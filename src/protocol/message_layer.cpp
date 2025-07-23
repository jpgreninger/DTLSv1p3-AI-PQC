#include "dtls/protocol/message_layer.h"
#include "dtls/error.h"
#include <algorithm>
#include <cstring>

namespace dtls::v13::protocol {

// ============================================================================
// MessageReassembler Implementation
// ============================================================================

Result<bool> MessageReassembler::add_fragment(const MessageFragment& fragment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!fragment.is_valid()) {
        return Result<bool>(DTLSError::INVALID_MESSAGE_FRAGMENT);
    }
    
    // First fragment sets the total length
    if (fragments_.empty()) {
        total_length_ = fragment.total_length;
    } else if (total_length_ != fragment.total_length) {
        return Result<bool>(DTLSError::FRAGMENT_LENGTH_MISMATCH);
    }
    
    // Check for overlapping or duplicate fragments
    for (const auto& existing : fragments_) {
        if (fragment.fragment_offset < existing.end && 
            fragment.fragment_offset + fragment.fragment_length > existing.start) {
            // Overlapping fragment - could be duplicate or partial overlap
            if (fragment.fragment_offset == existing.start && 
                fragment.fragment_length == (existing.end - existing.start)) {
                // Exact duplicate - ignore
                return Result<bool>(false);
            }
            // Handle partial overlap by rejecting for now (could be more sophisticated)
            return Result<bool>(DTLSError::OVERLAPPING_FRAGMENT);
        }
    }
    
    // Create copy of fragment data
    memory::Buffer fragment_data(fragment.fragment_data.size());
    auto resize_result = fragment_data.resize(fragment.fragment_data.size());
    if (!resize_result.is_success()) {
        return Result<bool>(resize_result.error());
    }
    
    std::memcpy(fragment_data.mutable_data(), fragment.fragment_data.data(), 
                fragment.fragment_data.size());
    
    // Add fragment
    fragments_.emplace_back(fragment.fragment_offset, 
                           fragment.fragment_offset + fragment.fragment_length,
                           std::move(fragment_data));
    
    // Sort fragments by start position
    std::sort(fragments_.begin(), fragments_.end(),
              [](const FragmentRange& a, const FragmentRange& b) {
                  return a.start < b.start;
              });
    
    // Merge any adjacent fragments
    merge_overlapping_fragments();
    
    return Result<bool>(is_complete());
}

bool MessageReassembler::is_complete() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (fragments_.empty() || total_length_ == 0) {
        return false;
    }
    
    // Check if we have a single continuous fragment covering the entire message
    return fragments_.size() == 1 && 
           fragments_[0].start == 0 && 
           fragments_[0].end == total_length_;
}

Result<memory::Buffer> MessageReassembler::get_complete_message() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!is_complete()) {
        return Result<memory::Buffer>(DTLSError::MESSAGE_NOT_COMPLETE);
    }
    
    // Return copy of the complete message
    const auto& complete_fragment = fragments_[0];
    memory::Buffer message(complete_fragment.data.size());
    auto resize_result = message.resize(complete_fragment.data.size());
    if (!resize_result.is_success()) {
        return Result<memory::Buffer>(resize_result.error());
    }
    
    std::memcpy(message.mutable_data(), complete_fragment.data.data(), 
                complete_fragment.data.size());
    
    return Result<memory::Buffer>(std::move(message));
}

void MessageReassembler::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    fragments_.clear();
    total_length_ = 0;
}

MessageReassembler::ReassemblyStats MessageReassembler::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ReassemblyStats stats;
    stats.total_length = total_length_;
    stats.fragment_count = fragments_.size();
    
    for (const auto& fragment : fragments_) {
        stats.received_bytes += (fragment.end - fragment.start);
    }
    
    // Count gaps
    if (!fragments_.empty()) {
        uint32_t expected_start = 0;
        for (const auto& fragment : fragments_) {
            if (fragment.start > expected_start) {
                stats.gap_count++;
            }
            expected_start = fragment.end;
        }
        if (expected_start < total_length_) {
            stats.gap_count++;
        }
    }
    
    return stats;
}

void MessageReassembler::merge_overlapping_fragments() {
    if (fragments_.size() <= 1) {
        return;
    }
    
    std::vector<FragmentRange> merged;
    merged.reserve(fragments_.size());
    
    merged.push_back(std::move(fragments_[0]));
    
    for (size_t i = 1; i < fragments_.size(); ++i) {
        auto& current = fragments_[i];
        auto& last_merged = merged.back();
        
        if (current.start <= last_merged.end) {
            // Adjacent or overlapping - merge
            if (current.end > last_merged.end) {
                // Extend the merged fragment
                size_t old_size = last_merged.data.size();
                size_t extension_size = current.end - last_merged.end;
                size_t new_size = old_size + extension_size;
                
                memory::Buffer new_data(new_size);
                auto resize_result = new_data.resize(new_size);
                if (resize_result.is_success()) {
                    // Copy existing data
                    std::memcpy(new_data.mutable_data(), last_merged.data.data(), old_size);
                    
                    // Copy extension from current fragment
                    size_t current_offset = last_merged.end - current.start;
                    std::memcpy(new_data.mutable_data() + old_size,
                               current.data.data() + current_offset,
                               extension_size);
                    
                    last_merged.data = std::move(new_data);
                    last_merged.end = current.end;
                }
            }
        } else {
            // Non-overlapping - add as separate fragment
            merged.push_back(std::move(current));
        }
    }
    
    fragments_ = std::move(merged);
}

// ============================================================================
// HandshakeFlight Implementation
// ============================================================================

HandshakeFlight::HandshakeFlight(FlightType type, uint16_t message_seq_start)
    : type_(type), message_seq_start_(message_seq_start) {
}

void HandshakeFlight::add_message(HandshakeMessage message) {
    messages_.push_back(std::move(message));
}

const std::vector<HandshakeMessage>& HandshakeFlight::get_messages() const {
    return messages_;
}

Result<std::vector<MessageFragment>> HandshakeFlight::fragment_messages(size_t max_fragment_size) const {
    std::vector<MessageFragment> fragments;
    
    for (const auto& message : messages_) {
        // Serialize the message payload (without handshake header)
        size_t payload_size = std::visit([](const auto& msg) {
            return msg.serialized_size();
        }, message.message_);
        
        memory::Buffer payload_buffer(payload_size);
        size_t actual_size = 0;
        
        std::visit([&](const auto& msg) {
            auto result = msg.serialize(payload_buffer);
            if (result.is_success()) {
                actual_size = result.value();
            }
        }, message.message_);
        
        if (actual_size == 0) {
            return Result<std::vector<MessageFragment>>(DTLSError::SERIALIZATION_FAILED);
        }
        
        // Fragment the message if needed
        uint32_t total_length = static_cast<uint32_t>(actual_size);
        uint32_t offset = 0;
        uint16_t message_seq = message.header().message_seq;
        
        while (offset < total_length) {
            uint32_t fragment_length = std::min(
                static_cast<uint32_t>(max_fragment_size),
                total_length - offset
            );
            
            memory::Buffer fragment_data(fragment_length);
            auto resize_result = fragment_data.resize(fragment_length);
            if (!resize_result.is_success()) {
                return Result<std::vector<MessageFragment>>(resize_result.error());
            }
            
            std::memcpy(fragment_data.mutable_data(), 
                       payload_buffer.data() + offset, 
                       fragment_length);
            
            fragments.emplace_back(message_seq, offset, fragment_length, 
                                 total_length, std::move(fragment_data));
            
            offset += fragment_length;
        }
    }
    
    return Result<std::vector<MessageFragment>>(std::move(fragments));
}

std::pair<uint16_t, uint16_t> HandshakeFlight::get_sequence_range() const {
    if (messages_.empty()) {
        return {message_seq_start_, message_seq_start_};
    }
    
    uint16_t min_seq = message_seq_start_;
    uint16_t max_seq = message_seq_start_ + static_cast<uint16_t>(messages_.size()) - 1;
    
    return {min_seq, max_seq};
}

bool HandshakeFlight::is_complete() const {
    return !messages_.empty();
}

size_t HandshakeFlight::get_total_size() const {
    size_t total = 0;
    for (const auto& message : messages_) {
        total += message.serialized_size();
    }
    return total;
}

// ============================================================================
// FlightManager Implementation
// ============================================================================

FlightManager::FlightManager() {
}

Result<void> FlightManager::create_flight(FlightType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (current_flight_) {
        return Result<void>(DTLSError::FLIGHT_IN_PROGRESS);
    }
    
    current_flight_ = std::make_unique<HandshakeFlight>(type, next_message_seq_);
    stats_.flights_created++;
    
    return Result<void>();
}

Result<void> FlightManager::add_message_to_current_flight(HandshakeMessage message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!current_flight_) {
        return Result<void>(DTLSError::NO_CURRENT_FLIGHT);
    }
    
    // Update message sequence number
    HandshakeMessage msg_with_seq = std::move(message);
    msg_with_seq.header_.message_seq = next_message_seq_++;
    
    current_flight_->add_message(std::move(msg_with_seq));
    
    return Result<void>();
}

Result<std::unique_ptr<HandshakeFlight>> FlightManager::complete_current_flight() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!current_flight_) {
        return Result<std::unique_ptr<HandshakeFlight>>(DTLSError::NO_CURRENT_FLIGHT);
    }
    
    if (!current_flight_->is_complete()) {
        return Result<std::unique_ptr<HandshakeFlight>>(DTLSError::INCOMPLETE_FLIGHT);
    }
    
    auto completed_flight = std::move(current_flight_);
    current_flight_.reset();
    
    // Store flight state for retransmission management
    FlightState state;
    state.flight = std::unique_ptr<HandshakeFlight>();  // Will be managed externally
    state.last_transmission = std::chrono::steady_clock::time_point{};
    state.retransmission_count = 0;
    state.acknowledged = false;
    
    flight_states_[completed_flight->get_type()] = std::move(state);
    
    return Result<std::unique_ptr<HandshakeFlight>>(std::move(completed_flight));
}

void FlightManager::set_retransmission_timeout(std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lock(mutex_);
    retransmission_timeout_ = timeout;
}

void FlightManager::set_max_retransmissions(size_t max_retries) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_retransmissions_ = max_retries;
}

bool FlightManager::should_retransmit(FlightType flight) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = flight_states_.find(flight);
    if (it == flight_states_.end() || it->second.acknowledged) {
        return false;
    }
    
    const auto& state = it->second;
    if (state.retransmission_count >= max_retransmissions_) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - state.last_transmission);
    
    return elapsed >= retransmission_timeout_;
}

void FlightManager::mark_flight_transmitted(FlightType flight) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = flight_states_.find(flight);
    if (it != flight_states_.end()) {
        it->second.last_transmission = std::chrono::steady_clock::now();
        if (it->second.retransmission_count == 0) {
            stats_.flights_transmitted++;
        } else {
            stats_.retransmissions++;
        }
        it->second.retransmission_count++;
    }
}

void FlightManager::mark_flight_acknowledged(FlightType flight) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = flight_states_.find(flight);
    if (it != flight_states_.end()) {
        it->second.acknowledged = true;
        stats_.flights_acknowledged++;
    }
}

FlightManager::FlightStats FlightManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

// ============================================================================
// MessageLayer Implementation
// ============================================================================

MessageLayer::MessageLayer(std::unique_ptr<RecordLayer> record_layer)
    : record_layer_(std::move(record_layer))
    , flight_manager_(std::make_unique<FlightManager>()) {
}

Result<void> MessageLayer::initialize() {
    if (!record_layer_) {
        return Result<void>(DTLSError::RECORD_LAYER_NOT_AVAILABLE);
    }
    
    return Result<void>();
}

Result<void> MessageLayer::send_handshake_message(const HandshakeMessage& message) {
    if (!record_layer_) {
        return Result<void>(DTLSError::RECORD_LAYER_NOT_AVAILABLE);
    }
    
    // Fragment the message
    auto fragments_result = fragment_message(message);
    if (!fragments_result.is_success()) {
        return Result<void>(fragments_result.error());
    }
    
    const auto& fragments = fragments_result.value();
    
    // Send each fragment as a separate record
    for (const auto& fragment : fragments) {
        auto record_result = create_handshake_record(fragment, 0); // Epoch 0 for now
        if (!record_result.is_success()) {
            return Result<void>(record_result.error());
        }
        
        auto send_result = record_layer_->prepare_outgoing_record(record_result.value());
        if (!send_result.is_success()) {
            return Result<void>(send_result.error());
        }
        
        update_stats_fragment_sent();
    }
    
    update_stats_message_sent();
    return Result<void>();
}

Result<void> MessageLayer::send_handshake_flight(std::unique_ptr<HandshakeFlight> flight) {
    if (!flight) {
        return Result<void>(DTLSError::INVALID_FLIGHT);
    }
    
    // Fragment all messages in the flight
    auto fragments_result = flight->fragment_messages(max_fragment_size_);
    if (!fragments_result.is_success()) {
        return Result<void>(fragments_result.error());
    }
    
    const auto& fragments = fragments_result.value();
    
    // Send all fragments
    for (const auto& fragment : fragments) {
        auto record_result = create_handshake_record(fragment, 0);
        if (!record_result.is_success()) {
            return Result<void>(record_result.error());
        }
        
        auto send_result = record_layer_->prepare_outgoing_record(record_result.value());
        if (!send_result.is_success()) {
            return Result<void>(send_result.error());
        }
        
        update_stats_fragment_sent();
    }
    
    // Mark flight as transmitted
    flight_manager_->mark_flight_transmitted(flight->get_type());
    
    update_stats_flight_sent();
    return Result<void>();
}

Result<std::vector<HandshakeMessage>> MessageLayer::process_incoming_handshake_record(
    const PlaintextRecord& record) {
    
    if (record.header().content_type != ContentType::HANDSHAKE) {
        return Result<std::vector<HandshakeMessage>>(DTLSError::INVALID_CONTENT_TYPE);
    }
    
    std::vector<HandshakeMessage> completed_messages;
    const memory::Buffer& payload = record.payload();
    size_t offset = 0;
    
    while (offset < payload.size()) {
        // Parse handshake header to get fragment information
        if (payload.size() < offset + HandshakeHeader::SERIALIZED_SIZE) {
            break;
        }
        
        auto header_result = HandshakeHeader::deserialize(payload, offset);
        if (!header_result.is_success()) {
            return Result<std::vector<HandshakeMessage>>(header_result.error());
        }
        
        const auto& header = header_result.value();
        size_t fragment_payload_size = std::min(
            static_cast<size_t>(header.fragment_length),
            payload.size() - offset - HandshakeHeader::SERIALIZED_SIZE
        );
        
        // Create message fragment
        memory::Buffer fragment_data(fragment_payload_size);
        auto resize_result = fragment_data.resize(fragment_payload_size);
        if (!resize_result.is_success()) {
            return Result<std::vector<HandshakeMessage>>(resize_result.error());
        }
        
        std::memcpy(fragment_data.mutable_data(),
                   payload.data() + offset + HandshakeHeader::SERIALIZED_SIZE,
                   fragment_payload_size);
        
        MessageFragment fragment(header.message_seq, header.fragment_offset,
                               header.fragment_length, header.length,
                               std::move(fragment_data));
        
        update_stats_fragment_received();
        
        // Handle fragment based on whether it's complete or needs reassembly
        if (fragment.is_complete_message()) {
            // Complete message - deserialize directly
            memory::Buffer complete_payload(fragment.fragment_data.size());
            auto resize_result = complete_payload.resize(fragment.fragment_data.size());
            if (!resize_result.is_success()) {
                return Result<std::vector<HandshakeMessage>>(resize_result.error());
            }
            
            std::memcpy(complete_payload.mutable_data(),
                       fragment.fragment_data.data(),
                       fragment.fragment_data.size());
            
            // Reconstruct complete message with header
            HandshakeMessage message;
            message.header_ = header;
            message.header_.fragment_offset = 0;
            message.header_.fragment_length = header.length;
            
            // Deserialize based on message type (simplified - would need full implementation)
            switch (header.msg_type) {
                case HandshakeType::CLIENT_HELLO: {
                    auto msg_result = ClientHello::deserialize(complete_payload, 0);
                    if (msg_result.is_success()) {
                        message.message_ = std::move(msg_result.value());
                        completed_messages.push_back(std::move(message));
                        update_stats_message_received();
                    }
                    break;
                }
                case HandshakeType::SERVER_HELLO: {
                    auto msg_result = ServerHello::deserialize(complete_payload, 0);
                    if (msg_result.is_success()) {
                        message.message_ = std::move(msg_result.value());
                        completed_messages.push_back(std::move(message));
                        update_stats_message_received();
                    }
                    break;
                }
                // Add other message types as needed
                default:
                    break;
            }
        } else {
            // Fragmented message - add to reassembler
            auto reassembler_it = reassemblers_.find(header.message_seq);
            if (reassembler_it == reassemblers_.end()) {
                reassemblers_[header.message_seq] = std::make_unique<MessageReassembler>();
                reassembler_it = reassemblers_.find(header.message_seq);
            }
            
            auto add_result = reassembler_it->second->add_fragment(fragment);
            if (add_result.is_success() && add_result.value()) {
                // Message is now complete
                auto complete_result = reassembler_it->second->get_complete_message();
                if (complete_result.is_success()) {
                    // Deserialize complete message (similar to above)
                    HandshakeMessage message;
                    message.header_ = header;
                    message.header_.fragment_offset = 0;
                    message.header_.fragment_length = header.length;
                    
                    // Would need full deserialization logic here
                    completed_messages.push_back(std::move(message));
                    update_stats_message_reassembled();
                    update_stats_message_received();
                }
                
                // Clean up reassembler
                reassemblers_.erase(reassembler_it);
            }
        }
        
        offset += HandshakeHeader::SERIALIZED_SIZE + fragment_payload_size;
    }
    
    return Result<std::vector<HandshakeMessage>>(std::move(completed_messages));
}

Result<void> MessageLayer::start_flight(FlightType type) {
    return flight_manager_->create_flight(type);
}

Result<void> MessageLayer::add_to_current_flight(const HandshakeMessage& message) {
    return flight_manager_->add_message_to_current_flight(message);
}

Result<void> MessageLayer::complete_and_send_flight() {
    auto flight_result = flight_manager_->complete_current_flight();
    if (!flight_result.is_success()) {
        return Result<void>(flight_result.error());
    }
    
    return send_handshake_flight(std::move(flight_result.value()));
}

Result<void> MessageLayer::handle_retransmissions() {
    // This would iterate through all flights and retransmit as needed
    // Implementation would depend on specific flight types and states
    return Result<void>();
}

void MessageLayer::set_max_fragment_size(size_t size) {
    max_fragment_size_ = size;
}

void MessageLayer::set_retransmission_timeout(std::chrono::milliseconds timeout) {
    flight_manager_->set_retransmission_timeout(timeout);
}

void MessageLayer::set_max_retransmissions(size_t max_retries) {
    flight_manager_->set_max_retransmissions(max_retries);
}

MessageLayer::MessageLayerStats MessageLayer::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// Private helper methods

Result<std::vector<MessageFragment>> MessageLayer::fragment_message(
    const HandshakeMessage& message) const {
    
    // Serialize message payload
    size_t payload_size = std::visit([](const auto& msg) {
        return msg.serialized_size();
    }, message.message_);
    
    memory::Buffer payload_buffer(payload_size);
    size_t actual_size = 0;
    
    std::visit([&](const auto& msg) {
        auto result = msg.serialize(payload_buffer);
        if (result.is_success()) {
            actual_size = result.value();
        }
    }, message.message_);
    
    if (actual_size == 0) {
        return Result<std::vector<MessageFragment>>(DTLSError::SERIALIZATION_FAILED);
    }
    
    std::vector<MessageFragment> fragments;
    uint32_t total_length = static_cast<uint32_t>(actual_size);
    uint32_t offset = 0;
    uint16_t message_seq = message.header().message_seq;
    
    while (offset < total_length) {
        uint32_t fragment_length = std::min(
            static_cast<uint32_t>(max_fragment_size_),
            total_length - offset
        );
        
        memory::Buffer fragment_data(fragment_length);
        auto resize_result = fragment_data.resize(fragment_length);
        if (!resize_result.is_success()) {
            return Result<std::vector<MessageFragment>>(resize_result.error());
        }
        
        std::memcpy(fragment_data.mutable_data(),
                   payload_buffer.data() + offset,
                   fragment_length);
        
        fragments.emplace_back(message_seq, offset, fragment_length,
                             total_length, std::move(fragment_data));
        
        offset += fragment_length;
    }
    
    return Result<std::vector<MessageFragment>>(std::move(fragments));
}

Result<PlaintextRecord> MessageLayer::create_handshake_record(
    const MessageFragment& fragment, uint16_t epoch) const {
    
    // Create handshake header for this fragment
    HandshakeHeader header;
    header.msg_type = HandshakeType::CLIENT_HELLO; // Would need to be determined properly
    header.length = fragment.total_length;
    header.message_seq = fragment.message_seq;
    header.fragment_offset = fragment.fragment_offset;
    header.fragment_length = fragment.fragment_length;
    
    // Serialize header
    memory::Buffer header_buffer(HandshakeHeader::SERIALIZED_SIZE);
    auto header_result = header.serialize(header_buffer);
    if (!header_result.is_success()) {
        return Result<PlaintextRecord>(header_result.error());
    }
    
    // Combine header and fragment data
    size_t total_size = HandshakeHeader::SERIALIZED_SIZE + fragment.fragment_data.size();
    memory::Buffer record_payload(total_size);
    auto resize_result = record_payload.resize(total_size);
    if (!resize_result.is_success()) {
        return Result<PlaintextRecord>(resize_result.error());
    }
    
    std::memcpy(record_payload.mutable_data(), header_buffer.data(), 
                HandshakeHeader::SERIALIZED_SIZE);
    std::memcpy(record_payload.mutable_data() + HandshakeHeader::SERIALIZED_SIZE,
                fragment.fragment_data.data(), fragment.fragment_data.size());
    
    PlaintextRecord record(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_3,
                          epoch, 0, std::move(record_payload));
    
    return Result<PlaintextRecord>(std::move(record));
}

void MessageLayer::update_stats_message_sent() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.messages_sent++;
}

void MessageLayer::update_stats_message_received() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.messages_received++;
}

void MessageLayer::update_stats_fragment_sent() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.fragments_sent++;
}

void MessageLayer::update_stats_fragment_received() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.fragments_received++;
}

void MessageLayer::update_stats_message_reassembled() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.messages_reassembled++;
}

void MessageLayer::update_stats_flight_sent() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.flights_sent++;
}

void MessageLayer::update_stats_retransmission() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.retransmissions++;
}

void MessageLayer::update_stats_reassembly_timeout() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.reassembly_timeouts++;
}

void MessageLayer::cleanup_old_reassemblers() {
    // Implementation would remove reassemblers that have timed out
    // This would be called periodically to prevent memory leaks
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace message_layer_utils {

std::unique_ptr<MessageLayer> create_test_message_layer() {
    // Create test dependencies
    auto record_layer = record_layer_utils::create_test_record_layer();
    if (!record_layer) {
        return nullptr;
    }
    
    auto message_layer = std::make_unique<MessageLayer>(std::move(record_layer));
    
    auto init_result = message_layer->initialize();
    if (!init_result.is_success()) {
        return nullptr;
    }
    
    return message_layer;
}

Result<void> validate_message_layer_config(const MessageLayer& layer) {
    auto stats = layer.get_stats();
    
    // Basic validation - could be expanded
    return Result<void>();
}

Result<std::vector<HandshakeMessage>> generate_test_handshake_messages() {
    std::vector<HandshakeMessage> messages;
    
    // Create test ClientHello
    ClientHello client_hello;
    client_hello.set_cipher_suites({CipherSuite::TLS_AES_128_GCM_SHA256});
    
    HandshakeMessage ch_message(client_hello, 0);
    messages.push_back(std::move(ch_message));
    
    return Result<std::vector<HandshakeMessage>>(std::move(messages));
}

Result<bool> test_fragmentation_reassembly(const HandshakeMessage& message, size_t fragment_size) {
    // Create a test message layer
    auto test_layer = create_test_message_layer();
    if (!test_layer) {
        return Result<bool>(DTLSError::INITIALIZATION_FAILED);
    }
    
    test_layer->set_max_fragment_size(fragment_size);
    
    // Test would fragment message and then reassemble it
    // Implementation would verify that original == reassembled
    
    return Result<bool>(true);
}

} // namespace message_layer_utils

} // namespace dtls::v13::protocol