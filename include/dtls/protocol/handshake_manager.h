#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/protocol/handshake.h"
#include "dtls/memory.h"
#include <memory>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <vector>
#include <queue>
#include <mutex>

namespace dtls::v13::protocol {

// Forward declarations
class ReliabilityManager;

/**
 * Callback function type for sending handshake messages
 */
using SendMessageCallback = std::function<Result<void>(const HandshakeMessage& message)>;

/**
 * Callback function type for handshake events
 */
enum class HandshakeEvent {
    MESSAGE_RECEIVED,
    MESSAGE_SENT,
    ACK_RECEIVED,
    ACK_SENT,
    RETRANSMISSION_NEEDED,
    TIMEOUT_OCCURRED,
    HANDSHAKE_COMPLETE,
    HANDSHAKE_FAILED
};

using HandshakeEventCallback = std::function<void(HandshakeEvent event, 
                                                 const std::vector<uint8_t>& data)>;

/**
 * Handshake Manager
 * 
 * Manages the DTLS v1.3 handshake process including message ordering,
 * ACK processing, and reliability mechanisms.
 */
class DTLS_API HandshakeManager {
public:
    /**
     * Configuration for handshake manager
     */
    struct Config {
        std::chrono::milliseconds initial_timeout{1000};  // 1 second
        std::chrono::milliseconds max_timeout{60000};     // 60 seconds
        uint32_t max_retransmissions{10};
        bool enable_ack_processing{true};
        size_t max_flight_size{10};  // Maximum messages in flight
        
        Config() = default;
    };
    
    /**
     * Constructor
     */
    HandshakeManager();
    explicit HandshakeManager(const Config& config);
    
    /**
     * Destructor
     */
    ~HandshakeManager();
    
    // Non-copyable, movable
    HandshakeManager(const HandshakeManager&) = delete;
    HandshakeManager& operator=(const HandshakeManager&) = delete;
    HandshakeManager(HandshakeManager&&) noexcept = default;
    HandshakeManager& operator=(HandshakeManager&&) noexcept = default;
    
    /**
     * Initialize the handshake manager
     */
    Result<void> initialize(SendMessageCallback send_callback,
                           HandshakeEventCallback event_callback = nullptr);
    
    /**
     * Process incoming handshake message
     */
    Result<void> process_message(const HandshakeMessage& message);
    
    /**
     * Send handshake message with reliability tracking
     */
    Result<void> send_message(const HandshakeMessage& message);
    
    /**
     * Process timeout events (call periodically)
     */
    Result<void> process_timeouts();
    
    /**
     * Get statistics
     */
    struct Statistics {
        uint32_t messages_sent{0};
        uint32_t messages_received{0};
        uint32_t acks_sent{0};
        uint32_t acks_received{0};
        uint32_t retransmissions{0};
        uint32_t timeouts{0};
        uint32_t messages_in_flight{0};
        std::chrono::milliseconds current_rto{0};
    };
    
    Statistics get_statistics() const;
    
    /**
     * Reset the handshake manager state
     */
    void reset();
    
    /**
     * Check if handshake is complete
     */
    bool is_handshake_complete() const;
    
    /**
     * Set sequence number for next outgoing message
     */
    void set_next_send_sequence(uint32_t sequence);
    
    /**
     * Get expected receive sequence number
     */
    uint32_t get_expected_receive_sequence() const;

private:
    // Internal message tracking
    struct TrackedMessage {
        std::chrono::steady_clock::time_point send_time;
        std::chrono::milliseconds timeout{1000};
        uint32_t retransmission_count{0};
        bool acknowledged{false};
        HandshakeType message_type{HandshakeType::CLIENT_HELLO};
        
        TrackedMessage() = default;
        
        TrackedMessage(HandshakeType type, std::chrono::milliseconds to)
            : send_time(std::chrono::steady_clock::now()), timeout(to), message_type(type) {}
    };
    
    // Internal methods
    Result<void> handle_ack_message(const ACK& ack_message);
    Result<void> generate_ack_for_received_messages();
    Result<void> send_ack_message(const ACK& ack_message);
    Result<void> handle_retransmission(uint32_t message_sequence);
    std::chrono::milliseconds calculate_rto() const;
    void update_rto_statistics(std::chrono::milliseconds rtt);
    void fire_event(HandshakeEvent event, const std::vector<uint8_t>& data = {});
    
    // Configuration and callbacks
    Config config_;
    SendMessageCallback send_callback_;
    HandshakeEventCallback event_callback_;
    
    // Reliability manager
    std::unique_ptr<ReliabilityManager> reliability_manager_;
    
    // Sequence number tracking
    uint32_t next_send_sequence_{0};
    uint32_t expected_receive_sequence_{0};
    std::vector<uint32_t> received_sequences_;
    std::vector<uint32_t> out_of_order_sequences_;
    
    // Message tracking
    std::unordered_map<uint32_t, TrackedMessage> outbound_messages_;
    std::queue<uint32_t> retransmission_queue_;
    
    // ACK management
    ACK last_ack_sent_;
    std::chrono::steady_clock::time_point last_ack_time_;
    std::chrono::milliseconds ack_delay_{50}; // 50ms ACK delay
    
    // RTO (Retransmission Timeout) calculation
    std::chrono::milliseconds srtt_{1000};  // Smoothed RTT
    std::chrono::milliseconds rttvar_{500}; // RTT variance
    std::chrono::milliseconds rto_{1000};   // Current RTO
    
    // Statistics
    mutable Statistics stats_;
    
    // Thread safety
    mutable std::mutex mutex_;
    
    // State
    bool initialized_{false};
    bool handshake_complete_{false};
};

/**
 * Reliability Manager
 * 
 * Handles retransmission logic, timeout calculation, and ACK processing
 * for DTLS handshake reliability.
 */
class DTLS_API ReliabilityManager {
public:
    /**
     * Configuration for reliability manager
     */
    struct Config {
        std::chrono::milliseconds initial_rto{1000};
        std::chrono::milliseconds max_rto{60000};
        uint32_t max_retransmissions{10};
        double rto_multiplier{2.0};
        std::chrono::milliseconds ack_timeout{200};
        
        Config() = default;
    };
    
    /**
     * Constructor
     */
    ReliabilityManager();
    explicit ReliabilityManager(const Config& config);
    
    /**
     * Add outbound message for tracking
     */
    void add_outbound_message(uint32_t sequence, HandshakeType type, std::chrono::milliseconds rto);
    
    /**
     * Process ACK message and update acknowledgments
     */
    Result<void> process_ack_message(const ACK& ack_message);
    
    /**
     * Check for timeout and retransmission needs
     */
    std::vector<uint32_t> check_timeouts();
    
    /**
     * Update RTT measurements
     */
    void update_rtt(uint32_t message_sequence, std::chrono::milliseconds rtt);
    
    /**
     * Get current RTO value
     */
    std::chrono::milliseconds get_current_rto() const;
    
    /**
     * Mark message as acknowledged
     */
    void acknowledge_message(uint32_t message_sequence);
    
    /**
     * Mark message range as acknowledged
     */
    void acknowledge_message_range(uint32_t start_sequence, uint32_t end_sequence);
    
    /**
     * Get unacknowledged messages
     */
    std::vector<uint32_t> get_unacknowledged_messages() const;
    
    /**
     * Reset reliability state
     */
    void reset();

private:
    // Message tracking entry
    struct MessageEntry {
        std::chrono::steady_clock::time_point send_time;
        std::chrono::steady_clock::time_point last_retransmit_time;
        uint32_t retransmit_count{0};
        bool acknowledged{false};
        std::chrono::milliseconds current_rto{1000};
        HandshakeType message_type{HandshakeType::CLIENT_HELLO};
        
        MessageEntry() = default;
        
        MessageEntry(HandshakeType type, std::chrono::milliseconds rto)
            : send_time(std::chrono::steady_clock::now()),
              last_retransmit_time(send_time),
              current_rto(rto),
              message_type(type) {}
    };
    
    // Internal methods
    void update_rto_stats(std::chrono::milliseconds rtt);
    std::chrono::milliseconds calculate_rto() const;
    
    // Configuration
    Config config_;
    
    // Message tracking
    std::unordered_map<uint32_t, MessageEntry> tracked_messages_;
    
    // RTO calculation (RFC 6298)
    std::chrono::milliseconds srtt_{0};      // Smoothed RTT
    std::chrono::milliseconds rttvar_{0};    // RTT variance
    std::chrono::milliseconds rto_;          // Current RTO
    bool first_measurement_{true};
    
    // Thread safety
    mutable std::mutex mutex_;
};

} // namespace dtls::v13::protocol