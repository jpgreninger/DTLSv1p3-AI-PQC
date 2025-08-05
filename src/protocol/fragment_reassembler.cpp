#include <dtls/protocol/fragment_reassembler.h>
#include <dtls/error.h>
#include <algorithm>
#include <cstring>

namespace dtls::v13::protocol {

// ============================================================================
// FragmentReassembler Implementation
// ============================================================================

FragmentReassembler::FragmentReassembler(const FragmentReassemblyConfig& config)
    : config_(config) {
}

FragmentReassembler::~FragmentReassembler() {
    clear_all_reassemblies();
}

Result<bool> FragmentReassembler::add_fragment(
    uint16_t message_seq,
    uint32_t fragment_offset,
    uint32_t fragment_length,
    uint32_t total_message_length,
    const memory::ZeroCopyBuffer& fragment_data) {
    
    // Validate fragment parameters
    if (!validate_fragment(message_seq, fragment_offset, fragment_length, 
                          total_message_length, fragment_data)) {
        stats_.fragments_invalid.fetch_add(1);
        return make_error<bool>(DTLSError::INVALID_MESSAGE_FRAGMENT, "Fragment validation failed");
    }
    
    stats_.fragments_received.fetch_add(1);
    
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    // Check memory and concurrency limits
    if (!check_memory_limits(fragment_length)) {
        return make_error<bool>(DTLSError::RESOURCE_EXHAUSTED, "Memory limit exceeded");
    }
    
    if (!check_concurrency_limits()) {
        return make_error<bool>(DTLSError::RESOURCE_EXHAUSTED, "Too many concurrent reassemblies");
    }
    
    // Find or create reassembly state
    auto it = active_reassemblies_.find(message_seq);
    if (it == active_reassemblies_.end()) {
        // New message reassembly
        auto state = std::make_unique<MessageReassemblyState>(total_message_length);
        
        auto [new_it, inserted] = active_reassemblies_.emplace(message_seq, std::move(state));
        it = new_it;
        
        stats_.messages_started.fetch_add(1);
        stats_.active_reassemblies.fetch_add(1);
        
        // Update peak concurrent reassemblies
        uint32_t current_active = stats_.active_reassemblies.load();
        uint32_t current_peak = stats_.peak_concurrent_reassemblies.load();
        while (current_active > current_peak && 
               !stats_.peak_concurrent_reassemblies.compare_exchange_weak(current_peak, current_active)) {
            current_peak = stats_.peak_concurrent_reassemblies.load();
        }
    }
    
    MessageReassemblyState& state = *it->second;
    
    // Validate total length consistency
    if (state.total_length != total_message_length) {
        return make_error<bool>(DTLSError::FRAGMENT_LENGTH_MISMATCH, 
                               "Total length mismatch in fragment");
    }
    
    // Check for duplicate fragments
    if (config_.detect_duplicates && is_duplicate_fragment(state, fragment_offset, fragment_length)) {
        stats_.fragments_duplicate.fetch_add(1);
        return make_result(state.is_complete); // Not an error, just ignore duplicate
    }
    
    // Check for out-of-order fragments
    if (!state.fragments.empty()) {
        bool is_out_of_order = false;
        if (!state.fragments.empty()) {
            const auto& last_fragment = state.fragments.back();
            if (fragment_offset < last_fragment.offset) {
                is_out_of_order = true;
            }
        }
        
        if (is_out_of_order) {
            if (!config_.handle_out_of_order) {
                return make_error<bool>(DTLSError::OUT_OF_ORDER_FRAGMENT, 
                                       "Out-of-order fragment not allowed");
            }
            stats_.fragments_out_of_order.fetch_add(1);
        }
    }
    
    // Add fragment to state
    auto add_result = add_fragment_to_state(state, fragment_offset, fragment_length, fragment_data);
    if (!add_result.is_success()) {
        return make_error<bool>(add_result.error(), "Failed to add fragment to state");
    }
    
    // Update memory usage
    update_memory_usage(static_cast<int64_t>(fragment_length));
    
    // Update state timing
    state.last_fragment_time = std::chrono::steady_clock::now();
    
    // Check if message is now complete
    bool was_complete = state.is_complete;
    bool is_now_complete = check_message_complete(state);
    
    if (!was_complete && is_now_complete) {
        record_reassembly_completion(state, true);
    }
    
    return make_result(is_now_complete);
}

bool FragmentReassembler::is_message_complete(uint16_t message_seq) const {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    auto it = active_reassemblies_.find(message_seq);
    return it != active_reassemblies_.end() && it->second->is_complete;
}

Result<memory::ZeroCopyBuffer> FragmentReassembler::get_complete_message(uint16_t message_seq) {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    auto it = active_reassemblies_.find(message_seq);
    if (it == active_reassemblies_.end()) {
        return make_error<memory::ZeroCopyBuffer>(DTLSError::MESSAGE_NOT_FOUND, 
                                                 "Message not found");
    }
    
    MessageReassemblyState& state = *it->second;
    if (!state.is_complete) {
        return make_error<memory::ZeroCopyBuffer>(DTLSError::MESSAGE_NOT_COMPLETE, 
                                                 "Message not complete");
    }
    
    // Assemble the complete message
    auto message_result = assemble_complete_message(state);
    if (!message_result.is_success()) {
        return make_error<memory::ZeroCopyBuffer>(message_result.error(), 
                                                 "Failed to assemble message");
    }
    
    // Clean up the reassembly state
    update_memory_usage(-static_cast<int64_t>(state.received_bytes));
    active_reassemblies_.erase(it);
    stats_.active_reassemblies.fetch_sub(1);
    
    return message_result;
}

void FragmentReassembler::remove_message(uint16_t message_seq) {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    auto it = active_reassemblies_.find(message_seq);
    if (it != active_reassemblies_.end()) {
        update_memory_usage(-static_cast<int64_t>(it->second->received_bytes));
        active_reassemblies_.erase(it);
        stats_.active_reassemblies.fetch_sub(1);
    }
}

void FragmentReassembler::cleanup_timed_out_reassemblies() {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = active_reassemblies_.begin();
    
    while (it != active_reassemblies_.end()) {
        const auto& state = *it->second;
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - state.start_time);
        
        if (elapsed > config_.reassembly_timeout) {
            update_memory_usage(-static_cast<int64_t>(state.received_bytes));
            record_reassembly_completion(state, false);
            stats_.messages_timed_out.fetch_add(1);
            it = active_reassemblies_.erase(it);
            stats_.active_reassemblies.fetch_sub(1);
        } else {
            ++it;
        }
    }
}

void FragmentReassembler::clear_all_reassemblies() {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    for (const auto& [seq, state] : active_reassemblies_) {
        update_memory_usage(-static_cast<int64_t>(state->received_bytes));
    }
    
    active_reassemblies_.clear();
    stats_.active_reassemblies.store(0);
}

const FragmentReassemblyStats& FragmentReassembler::get_stats() const {
    return stats_;
}

void FragmentReassembler::reset_stats() {
    stats_.messages_started.store(0);
    stats_.messages_completed.store(0);
    stats_.messages_timed_out.store(0);
    stats_.messages_failed.store(0);
    
    stats_.fragments_received.store(0);
    stats_.fragments_duplicate.store(0);
    stats_.fragments_out_of_order.store(0);
    stats_.fragments_invalid.store(0);
    
    stats_.total_reassembly_time_ns.store(0);
    stats_.peak_memory_usage.store(0);
    stats_.peak_concurrent_reassemblies.store(0);
    
    stats_.active_reassemblies.store(0);
    stats_.current_memory_usage.store(0);
}

void FragmentReassembler::update_config(const FragmentReassemblyConfig& new_config) {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    config_ = new_config;
}

// Private Helper Methods
bool FragmentReassembler::validate_fragment(
    uint16_t message_seq,
    uint32_t fragment_offset,
    uint32_t fragment_length,
    uint32_t total_message_length,
    const memory::ZeroCopyBuffer& fragment_data) const {
    
    // Basic parameter validation
    if (fragment_length == 0) {
        return false;
    }
    
    if (fragment_offset >= total_message_length) {
        return false;
    }
    
    if (fragment_offset + fragment_length > total_message_length) {
        return false;
    }
    
    if (fragment_data.size() != fragment_length) {
        return false;
    }
    
    // Configuration-based validation
    if (config_.strict_validation) {
        if (total_message_length > config_.max_message_size) {
            return false;
        }
        
        // Estimate number of fragments needed
        uint32_t estimated_fragments = (total_message_length + fragment_length - 1) / fragment_length;
        if (estimated_fragments > config_.max_fragments_per_message) {
            return false;
        }
    }
    
    return true;
}

bool FragmentReassembler::check_memory_limits(uint32_t additional_bytes) const {
    uint64_t current_usage = stats_.current_memory_usage.load();
    return (current_usage + additional_bytes) <= config_.max_reassembly_memory;
}

bool FragmentReassembler::check_concurrency_limits() const {
    uint32_t current_active = stats_.active_reassemblies.load();
    return current_active < config_.max_concurrent_reassemblies;
}

Result<void> FragmentReassembler::add_fragment_to_state(
    MessageReassemblyState& state,
    uint32_t fragment_offset,
    uint32_t fragment_length,
    const memory::ZeroCopyBuffer& fragment_data) {
    
    // Create fragment buffer copy
    memory::ZeroCopyBuffer fragment_copy(fragment_length);
    auto resize_result = fragment_copy.resize(fragment_length);
    if (!resize_result.is_success()) {
        return make_error<void>(resize_result.error(), "Failed to allocate fragment buffer");
    }
    
    std::memcpy(fragment_copy.mutable_data(), fragment_data.data(), fragment_length);
    
    // Add fragment to state
    state.fragments.emplace_back(fragment_offset, fragment_length, std::move(fragment_copy));
    state.received_bytes += fragment_length;
    
    // Sort fragments by offset for efficient gap checking
    sort_fragments(state.fragments);
    
    return make_result();
}

bool FragmentReassembler::check_message_complete(MessageReassemblyState& state) {
    if (state.fragments.empty()) {
        return false;
    }
    
    // Check if we have received all bytes
    if (state.received_bytes != state.total_length) {
        return false;
    }
    
    // Check for gaps in coverage
    if (has_fragment_gaps(state.fragments, state.total_length)) {
        return false;
    }
    
    state.is_complete = true;
    return true;
}

Result<memory::ZeroCopyBuffer> FragmentReassembler::assemble_complete_message(
    MessageReassemblyState& state) {
    
    if (!state.is_complete) {
        return make_error<memory::ZeroCopyBuffer>(DTLSError::MESSAGE_NOT_COMPLETE, 
                                                 "Message not complete");
    }
    
    // Create output buffer
    memory::ZeroCopyBuffer complete_message(state.total_length);
    auto resize_result = complete_message.resize(state.total_length);
    if (!resize_result.is_success()) {
        return make_error<memory::ZeroCopyBuffer>(resize_result.error(), 
                                                 "Failed to allocate message buffer");
    }
    
    // Sort fragments by offset
    sort_fragments(state.fragments);
    
    // Copy fragment data to complete message buffer
    uint8_t* output_ptr = reinterpret_cast<uint8_t*>(complete_message.mutable_data());
    
    for (const auto& fragment : state.fragments) {
        std::memcpy(output_ptr + fragment.offset, 
                   fragment.data.data(), 
                   fragment.length);
    }
    
    return make_result(std::move(complete_message));
}

void FragmentReassembler::update_memory_usage(int64_t delta) {
    uint64_t current = stats_.current_memory_usage.load();
    uint64_t new_usage = static_cast<uint64_t>(static_cast<int64_t>(current) + delta);
    stats_.current_memory_usage.store(new_usage);
    
    // Update peak memory usage
    uint64_t current_peak = stats_.peak_memory_usage.load();
    while (new_usage > current_peak && 
           !stats_.peak_memory_usage.compare_exchange_weak(current_peak, new_usage)) {
        current_peak = stats_.peak_memory_usage.load();
    }
}

void FragmentReassembler::record_reassembly_completion(const MessageReassemblyState& state, bool success) {
    if (success) {
        stats_.messages_completed.fetch_add(1);
        
        // Record reassembly time
        auto reassembly_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
            state.last_fragment_time - state.start_time);
        stats_.total_reassembly_time_ns.fetch_add(reassembly_time.count());
    } else {
        stats_.messages_failed.fetch_add(1);
    }
}

bool FragmentReassembler::is_duplicate_fragment(
    const MessageReassemblyState& state,
    uint32_t fragment_offset,
    uint32_t fragment_length) const {
    
    for (const auto& existing : state.fragments) {
        if (existing.offset == fragment_offset && existing.length == fragment_length) {
            return true;
        }
    }
    return false;
}

void FragmentReassembler::sort_fragments(std::vector<FragmentInfo>& fragments) const {
    std::sort(fragments.begin(), fragments.end(),
              [](const FragmentInfo& a, const FragmentInfo& b) {
                  return a.offset < b.offset;
              });
}

bool FragmentReassembler::has_fragment_gaps(const std::vector<FragmentInfo>& fragments, 
                                           uint32_t total_length) const {
    if (fragments.empty()) {
        return total_length > 0;
    }
    
    // Check if first fragment doesn't start at offset 0
    if (fragments[0].offset != 0) {
        return true;
    }
    
    // Check for gaps between consecutive fragments
    uint32_t expected_next_offset = fragments[0].offset + fragments[0].length;
    
    for (size_t i = 1; i < fragments.size(); ++i) {
        if (fragments[i].offset != expected_next_offset) {
            return true; // Gap found
        }
        expected_next_offset = fragments[i].offset + fragments[i].length;
    }
    
    // Check if last fragment reaches the end
    return expected_next_offset != total_length;
}

// ============================================================================
// ConnectionFragmentManager Implementation
// ============================================================================

ConnectionFragmentManager::ConnectionFragmentManager(const FragmentReassemblyConfig& config)
    : reassembler_(std::make_unique<FragmentReassembler>(config)) {
}

Result<bool> ConnectionFragmentManager::process_handshake_fragment(
    const HandshakeHeader& header, 
    const memory::ZeroCopyBuffer& fragment_data) {
    
    // Add fragment to reassembler
    auto add_result = reassembler_->add_fragment(
        header.message_seq,
        header.fragment_offset,
        header.fragment_length,
        header.length,
        fragment_data
    );
    
    if (!add_result.is_success()) {
        return add_result;
    }
    
    bool is_complete = add_result.value();
    
    // If message is complete, deserialize it and cache
    if (is_complete) {
        auto message_buffer_result = reassembler_->get_complete_message(header.message_seq);
        if (!message_buffer_result.is_success()) {
            return make_error<bool>(message_buffer_result.error(), 
                                   "Failed to get complete message");
        }
        
        // Deserialize the handshake message
        auto message_result = deserialize_handshake_message(header.msg_type, 
                                                           message_buffer_result.value());
        if (!message_result.is_success()) {
            return make_error<bool>(message_result.error(), 
                                   "Failed to deserialize handshake message");
        }
        
        // Cache the complete message
        std::lock_guard<std::mutex> lock(completed_messages_mutex_);
        completed_messages_[header.message_seq] = std::move(message_result.value());
    }
    
    return make_result(is_complete);
}

Result<HandshakeMessage> ConnectionFragmentManager::get_complete_handshake_message(uint16_t message_seq) {
    std::lock_guard<std::mutex> lock(completed_messages_mutex_);
    
    auto it = completed_messages_.find(message_seq);
    if (it == completed_messages_.end()) {
        return make_error<HandshakeMessage>(DTLSError::MESSAGE_NOT_FOUND, 
                                           "Complete message not found");
    }
    
    HandshakeMessage message = std::move(it->second);
    completed_messages_.erase(it);
    
    return make_result(std::move(message));
}

void ConnectionFragmentManager::cleanup() {
    reassembler_->clear_all_reassemblies();
    
    std::lock_guard<std::mutex> lock(completed_messages_mutex_);
    completed_messages_.clear();
}

const FragmentReassemblyStats& ConnectionFragmentManager::get_stats() const {
    return reassembler_->get_stats();
}

void ConnectionFragmentManager::perform_maintenance() {
    reassembler_->cleanup_timed_out_reassemblies();
}

Result<HandshakeMessage> ConnectionFragmentManager::deserialize_handshake_message(
    HandshakeType msg_type, 
    const memory::ZeroCopyBuffer& message_data) {
    
    HandshakeMessage message;
    
    // Set header information (simplified - would need complete header parsing)
    message.header().msg_type = msg_type;
    message.header().length = static_cast<uint32_t>(message_data.size());
    message.header().fragment_offset = 0;
    message.header().fragment_length = static_cast<uint32_t>(message_data.size());
    
    // Deserialize message payload based on type
    switch (msg_type) {
        case HandshakeType::CLIENT_HELLO: {
            auto result = ClientHello::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize ClientHello");
        }
        
        case HandshakeType::SERVER_HELLO: {
            auto result = ServerHello::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize ServerHello");
        }
        
        case HandshakeType::HELLO_RETRY_REQUEST: {
            auto result = HelloRetryRequest::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize HelloRetryRequest");
        }
        
        case HandshakeType::ENCRYPTED_EXTENSIONS: {
            // EncryptedExtensions not fully implemented yet - return error for now
            return make_error<HandshakeMessage>(DTLSError::UNSUPPORTED_MESSAGE_TYPE, 
                                               "EncryptedExtensions deserialization not implemented");
        }
        
        case HandshakeType::CERTIFICATE: {
            auto result = Certificate::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize Certificate");
        }
        
        case HandshakeType::CERTIFICATE_VERIFY: {
            auto result = CertificateVerify::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize CertificateVerify");
        }
        
        case HandshakeType::FINISHED: {
            auto result = Finished::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize Finished");
        }
        
        case HandshakeType::NEW_SESSION_TICKET: {
            auto result = NewSessionTicket::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize NewSessionTicket");
        }
        
        case HandshakeType::KEY_UPDATE: {
            auto result = KeyUpdate::deserialize(message_data, 0);
            if (result.is_success()) {
                message.message() = std::move(result.value());
                return make_result(std::move(message));
            }
            return make_error<HandshakeMessage>(result.error(), "Failed to deserialize KeyUpdate");
        }
        
        default:
            return make_error<HandshakeMessage>(DTLSError::UNSUPPORTED_MESSAGE_TYPE, 
                                               "Unsupported handshake message type");
    }
}

} // namespace dtls::v13::protocol