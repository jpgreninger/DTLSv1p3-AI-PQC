#include "dtls/protocol/handshake_manager.h"
#include "dtls/error.h"
#include <algorithm>
#include <cmath>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

namespace dtls::v13::protocol {

// =============================================================================
// HandshakeManager Implementation
// =============================================================================

HandshakeManager::HandshakeManager()
    : config_(), reliability_manager_(std::make_unique<ReliabilityManager>()) {
    
    // Initialize RTO values
    rto_ = config_.initial_timeout;
    srtt_ = config_.initial_timeout;
    rttvar_ = config_.initial_timeout / 2;
}

HandshakeManager::HandshakeManager(const Config& config)
    : config_(config) {
    
    // Create reliability manager config
    ReliabilityManager::Config rel_config;
    rel_config.initial_rto = config.initial_timeout;
    rel_config.max_rto = config.max_timeout;
    rel_config.max_retransmissions = config.max_retransmissions;
    
    reliability_manager_ = std::make_unique<ReliabilityManager>(rel_config);
    
    // Initialize RTO values
    rto_ = config_.initial_timeout;
    srtt_ = config_.initial_timeout;
    rttvar_ = config_.initial_timeout / 2;
}

HandshakeManager::~HandshakeManager() = default;

Result<void> HandshakeManager::initialize(SendMessageCallback send_callback,
                                         HandshakeEventCallback event_callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!send_callback) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    send_callback_ = std::move(send_callback);
    event_callback_ = std::move(event_callback);
    initialized_ = true;
    
    return Result<void>();
}

Result<void> HandshakeManager::process_message(const HandshakeMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return Result<void>(DTLSError::INVALID_STATE);
    }
    
    stats_.messages_received++;
    
    uint32_t message_seq = message.header().message_seq;
    
    // Handle ACK messages specially
    if (message.message_type() == HandshakeType::ACK) {
        if (message.holds<ACK>()) {
            const ACK& ack_message = message.get<ACK>();
            auto ack_result = handle_ack_message(ack_message);
            if (!ack_result.is_success()) {
                return ack_result;
            }
            
            stats_.acks_received++;
            fire_event(HandshakeEvent::ACK_RECEIVED, {});
        }
        return Result<void>();
    }
    
    // Track received sequence numbers
    received_sequences_.push_back(message_seq);
    
    // Check for out-of-order delivery
    if (message_seq != expected_receive_sequence_) {
        out_of_order_sequences_.push_back(message_seq);
    } else {
        // Update expected sequence for in-order message
        expected_receive_sequence_ = message_seq + 1;
        
        // Check if we can advance expected sequence with out-of-order messages
        std::sort(out_of_order_sequences_.begin(), out_of_order_sequences_.end());
        while (!out_of_order_sequences_.empty() && 
               out_of_order_sequences_[0] == expected_receive_sequence_) {
            expected_receive_sequence_++;
            out_of_order_sequences_.erase(out_of_order_sequences_.begin());
        }
    }
    
    fire_event(HandshakeEvent::MESSAGE_RECEIVED, {});
    
    // Generate ACK if configured and appropriate
    if (config_.enable_ack_processing) {
        auto ack_result = generate_ack_for_received_messages();
        if (!ack_result.is_success()) {
            return ack_result;
        }
    }
    
    return Result<void>();
}

Result<void> HandshakeManager::send_message(const HandshakeMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return Result<void>(DTLSError::INVALID_STATE);
    }
    
    // Check flight size limit
    if (outbound_messages_.size() >= config_.max_flight_size) {
        return Result<void>(DTLSError::RESOURCE_EXHAUSTED);
    }
    
    // We need to create a copy of the message for tracking since messages are move-only
    // For now, we'll work with the original message directly
    
    // For now, assume the message will get the sequence number internally
    // TODO: Add proper sequence number setting method to HandshakeMessage
    
    // Send the message
    auto send_result = send_callback_(message);
    if (!send_result.is_success()) {
        return send_result;
    }
    
    // Track message for reliability (unless it's an ACK)
    if (message.message_type() != HandshakeType::ACK) {
        // Note: We can't easily copy the message due to non-copyable variant
        // For now we'll track basic info and rely on retransmission callback
        // TODO: Implement proper message copying or reconstruction
        
        // Create a minimal tracked message entry
        TrackedMessage tracked(message.message_type(), rto_);
        
        outbound_messages_[next_send_sequence_] = std::move(tracked);
        
        // Track in reliability manager
        reliability_manager_->add_outbound_message(next_send_sequence_, message.message_type(), rto_);
    }
    
    next_send_sequence_++;
    stats_.messages_sent++;
    
    fire_event(HandshakeEvent::MESSAGE_SENT, {});
    
    return Result<void>();
}

Result<void> HandshakeManager::process_timeouts() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return Result<void>(DTLSError::INVALID_STATE);
    }
    
    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> timed_out_messages;
    
    // Check for timed out messages
    for (auto& [seq, tracked_msg] : outbound_messages_) {
        if (tracked_msg.acknowledged) {
            continue;
        }
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - tracked_msg.send_time);
        
        if (elapsed >= tracked_msg.timeout) {
            timed_out_messages.push_back(seq);
        }
    }
    
    // Handle retransmissions
    for (uint32_t seq : timed_out_messages) {
        auto retrans_result = handle_retransmission(seq);
        if (!retrans_result.is_success()) {
            return retrans_result;
        }
    }
    
    // Use reliability manager timeout checking as well
    auto reliability_timeouts = reliability_manager_->check_timeouts();
    for (uint32_t seq : reliability_timeouts) {
        if (outbound_messages_.find(seq) != outbound_messages_.end()) {
            auto retrans_result = handle_retransmission(seq);
            if (!retrans_result.is_success()) {
                return retrans_result;
            }
        }
    }
    
    return Result<void>();
}

Result<void> HandshakeManager::handle_ack_message(const ACK& ack_message) {
    // Process ACK with reliability manager
    auto reliability_result = reliability_manager_->process_ack_message(ack_message);
    if (!reliability_result.is_success()) {
        return reliability_result;
    }
    
    // Update local tracking based on ACK ranges
    for (const auto& range : ack_message.ack_ranges()) {
        for (uint32_t seq = range.start_sequence; seq <= range.end_sequence; ++seq) {
            auto it = outbound_messages_.find(seq);
            if (it != outbound_messages_.end()) {
                if (!it->second.acknowledged) {
                    // Calculate RTT for this message
                    auto now = std::chrono::steady_clock::now();
                    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - it->second.send_time);
                    
                    // Update RTO statistics
                    update_rto_statistics(rtt);
                    reliability_manager_->update_rtt(seq, rtt);
                    
                    it->second.acknowledged = true;
                }
            }
        }
    }
    
    // Clean up acknowledged messages
    auto it = outbound_messages_.begin();
    while (it != outbound_messages_.end()) {
        if (it->second.acknowledged) {
            it = outbound_messages_.erase(it);
        } else {
            ++it;
        }
    }
    
    return Result<void>();
}

Result<void> HandshakeManager::generate_ack_for_received_messages() {
    if (received_sequences_.empty()) {
        return Result<void>();
    }
    
    // Check if we should send an ACK
    if (!should_send_ack(received_sequences_, last_ack_sent_)) {
        return Result<void>();
    }
    
    // Create ACK message from received sequences
    auto ack_result = create_ack_message(received_sequences_);
    if (!ack_result.is_success()) {
        return Result<void>(ack_result.error());
    }
    
    ACK ack_message = std::move(ack_result.value());
    
    // Send the ACK
    auto send_result = send_ack_message(ack_message);
    if (!send_result.is_success()) {
        return send_result;
    }
    
    // Update last ACK sent
    last_ack_sent_ = ack_message;
    last_ack_time_ = std::chrono::steady_clock::now();
    
    return Result<void>();
}

Result<void> HandshakeManager::send_ack_message(const ACK& ack_message) {
    // Create handshake message with ACK
    HandshakeMessage ack_handshake(ack_message, next_send_sequence_);
    
    // Send directly without reliability tracking (ACKs are not retransmitted)
    auto send_result = send_callback_(ack_handshake);
    if (!send_result.is_success()) {
        return send_result;
    }
    
    next_send_sequence_++;
    stats_.acks_sent++;
    
    fire_event(HandshakeEvent::ACK_SENT, {});
    
    return Result<void>();
}

Result<void> HandshakeManager::handle_retransmission(uint32_t message_sequence) {
    auto it = outbound_messages_.find(message_sequence);
    if (it == outbound_messages_.end() || it->second.acknowledged) {
        return Result<void>(); // Message already acknowledged or not found
    }
    
    TrackedMessage& tracked_msg = it->second;
    
    // Check retransmission limit
    if (tracked_msg.retransmission_count >= config_.max_retransmissions) {
        // Max retransmissions reached - handshake failure
        handshake_complete_ = false;
        fire_event(HandshakeEvent::HANDSHAKE_FAILED, {});
        return Result<void>(DTLSError::HANDSHAKE_TIMEOUT);
    }
    
    // Exponential backoff
    tracked_msg.timeout = std::min(
        std::chrono::milliseconds(static_cast<long long>(tracked_msg.timeout.count() * 2.0)),
        config_.max_timeout
    );
    
    // For now, we can't retransmit since we don't store the message
    // This is a limitation that needs to be addressed with proper message storage
    // TODO: Implement message storage/reconstruction for retransmission
    
    // Return success for now to avoid blocking the handshake
    // In a real implementation, this would need proper message reconstruction
    
    // Update tracking
    tracked_msg.send_time = std::chrono::steady_clock::now();
    tracked_msg.retransmission_count++;
    
    stats_.retransmissions++;
    
    fire_event(HandshakeEvent::RETRANSMISSION_NEEDED, {});
    
    return Result<void>();
}

void HandshakeManager::update_rto_statistics(std::chrono::milliseconds rtt) {
    // RFC 6298 RTO calculation
    const double alpha = 0.125; // SRTT gain
    const double beta = 0.25;   // RTTVAR gain
    const int k = 4;            // RTTVAR multiplier
    
    if (srtt_.count() == 0) {
        // First measurement
        srtt_ = rtt;
        rttvar_ = rtt / 2;
    } else {
        // Subsequent measurements
        auto rttvar_new = std::chrono::milliseconds(static_cast<long long>(
            (1.0 - beta) * rttvar_.count() + beta * std::abs(srtt_.count() - rtt.count())
        ));
        
        auto srtt_new = std::chrono::milliseconds(static_cast<long long>(
            (1.0 - alpha) * srtt_.count() + alpha * rtt.count()
        ));
        
        srtt_ = srtt_new;
        rttvar_ = rttvar_new;
    }
    
    // Calculate new RTO
    rto_ = std::max(
        std::chrono::milliseconds(srtt_.count() + k * rttvar_.count()),
        std::chrono::milliseconds(1000) // Minimum 1 second
    );
    
    rto_ = std::min(rto_, config_.max_timeout);
    
    stats_.current_rto = rto_;
}

void HandshakeManager::fire_event(HandshakeEvent event, const std::vector<uint8_t>& data) {
    if (event_callback_) {
        event_callback_(event, data);
    }
}

HandshakeManager::Statistics HandshakeManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.messages_in_flight = static_cast<uint32_t>(outbound_messages_.size());
    stats_.current_rto = rto_;
    return stats_;
}

void HandshakeManager::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    outbound_messages_.clear();
    received_sequences_.clear();
    out_of_order_sequences_.clear();
    
    next_send_sequence_ = 0;
    expected_receive_sequence_ = 0;
    
    last_ack_sent_.clear();
    
    // Reset RTO calculation
    srtt_ = config_.initial_timeout;
    rttvar_ = config_.initial_timeout / 2;
    rto_ = config_.initial_timeout;
    
    // Reset statistics
    stats_ = Statistics{};
    
    // Reset reliability manager
    reliability_manager_->reset();
    
    handshake_complete_ = false;
}

bool HandshakeManager::is_handshake_complete() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return handshake_complete_;
}

void HandshakeManager::set_next_send_sequence(uint32_t sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    next_send_sequence_ = sequence;
}

uint32_t HandshakeManager::get_expected_receive_sequence() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return expected_receive_sequence_;
}

// =============================================================================
// ReliabilityManager Implementation
// =============================================================================

ReliabilityManager::ReliabilityManager()
    : config_(), rto_(config_.initial_rto) {
}

ReliabilityManager::ReliabilityManager(const Config& config)
    : config_(config), rto_(config.initial_rto) {
}

void ReliabilityManager::add_outbound_message(uint32_t sequence, HandshakeType type, std::chrono::milliseconds rto) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    MessageEntry entry(type, rto);
    tracked_messages_[sequence] = std::move(entry);
}

Result<void> ReliabilityManager::process_ack_message(const ACK& ack_message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Process each ACK range
    for (const auto& range : ack_message.ack_ranges()) {
        for (uint32_t seq = range.start_sequence; seq <= range.end_sequence; ++seq) {
            auto it = tracked_messages_.find(seq);
            if (it != tracked_messages_.end() && !it->second.acknowledged) {
                // Calculate RTT
                auto now = std::chrono::steady_clock::now();
                auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - it->second.send_time);
                
                // Only update RTO with original transmission RTT
                if (it->second.retransmit_count == 0) {
                    update_rto_stats(rtt);
                }
                
                it->second.acknowledged = true;
            }
        }
    }
    
    return Result<void>();
}

std::vector<uint32_t> ReliabilityManager::check_timeouts() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<uint32_t> timed_out;
    auto now = std::chrono::steady_clock::now();
    
    for (auto& [seq, entry] : tracked_messages_) {
        if (entry.acknowledged) {
            continue;
        }
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - entry.last_retransmit_time);
        
        if (elapsed >= entry.current_rto) {
            timed_out.push_back(seq);
            
            // Update entry for next potential retransmission
            entry.retransmit_count++;
            entry.last_retransmit_time = now;
            entry.current_rto = std::min(
                std::chrono::milliseconds(static_cast<long long>(entry.current_rto.count() * config_.rto_multiplier)),
                config_.max_rto
            );
        }
    }
    
    return timed_out;
}

void ReliabilityManager::update_rtt(uint32_t message_sequence, std::chrono::milliseconds rtt) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = tracked_messages_.find(message_sequence);
    if (it != tracked_messages_.end() && it->second.retransmit_count == 0) {
        // Only use RTT from original transmission
        update_rto_stats(rtt);
    }
}

std::chrono::milliseconds ReliabilityManager::get_current_rto() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rto_;
}

void ReliabilityManager::acknowledge_message(uint32_t message_sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = tracked_messages_.find(message_sequence);
    if (it != tracked_messages_.end()) {
        it->second.acknowledged = true;
    }
}

void ReliabilityManager::acknowledge_message_range(uint32_t start_sequence, uint32_t end_sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (uint32_t seq = start_sequence; seq <= end_sequence; ++seq) {
        acknowledge_message(seq);
    }
}

std::vector<uint32_t> ReliabilityManager::get_unacknowledged_messages() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<uint32_t> unacked;
    for (const auto& [seq, entry] : tracked_messages_) {
        if (!entry.acknowledged) {
            unacked.push_back(seq);
        }
    }
    
    std::sort(unacked.begin(), unacked.end());
    return unacked;
}

void ReliabilityManager::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    tracked_messages_.clear();
    rto_ = config_.initial_rto;
    srtt_ = std::chrono::milliseconds(0);
    rttvar_ = std::chrono::milliseconds(0);
    first_measurement_ = true;
}

void ReliabilityManager::update_rto_stats(std::chrono::milliseconds rtt) {
    // RFC 6298 algorithm
    if (first_measurement_) {
        srtt_ = rtt;
        rttvar_ = rtt / 2;
        first_measurement_ = false;
    } else {
        rttvar_ = std::chrono::milliseconds(static_cast<long long>(
            0.75 * rttvar_.count() + 0.25 * std::abs(srtt_.count() - rtt.count())
        ));
        
        srtt_ = std::chrono::milliseconds(static_cast<long long>(
            0.875 * srtt_.count() + 0.125 * rtt.count()
        ));
    }
    
    rto_ = std::max(
        std::chrono::milliseconds(srtt_.count() + 4 * rttvar_.count()),
        config_.initial_rto
    );
    
    rto_ = std::min(rto_, config_.max_rto);
}

std::chrono::milliseconds ReliabilityManager::calculate_rto() const {
    return rto_;
}

} // namespace dtls::v13::protocol