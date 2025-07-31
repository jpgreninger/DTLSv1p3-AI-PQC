#ifndef DTLS_PROTOCOL_MESSAGE_LAYER_H
#define DTLS_PROTOCOL_MESSAGE_LAYER_H

#include <dtls/config.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/record_layer.h>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <functional>

namespace dtls {
namespace v13 {
namespace protocol {

/**
 * Message fragment for DTLS handshake message fragmentation
 */
struct MessageFragment {
    uint16_t message_seq;
    uint32_t fragment_offset;
    uint32_t fragment_length;
    uint32_t total_length;
    memory::Buffer fragment_data;
    
    MessageFragment() = default;
    MessageFragment(uint16_t seq, uint32_t offset, uint32_t frag_len, 
                   uint32_t total_len, memory::Buffer data)
        : message_seq(seq), fragment_offset(offset), fragment_length(frag_len)
        , total_length(total_len), fragment_data(std::move(data)) {}
    
    bool is_complete_message() const {
        return fragment_offset == 0 && fragment_length == total_length;
    }
    
    bool is_valid() const {
        return fragment_offset + fragment_length <= total_length &&
               fragment_data.size() == fragment_length;
    }
};

/**
 * Message reassembly buffer for collecting fragments
 */
class DTLS_API MessageReassembler {
public:
    MessageReassembler() = default;
    ~MessageReassembler() = default;
    
    // Non-copyable, movable
    MessageReassembler(const MessageReassembler&) = delete;
    MessageReassembler& operator=(const MessageReassembler&) = delete;
    MessageReassembler(MessageReassembler&&) noexcept = default;
    MessageReassembler& operator=(MessageReassembler&&) noexcept = default;
    
    /**
     * Add a fragment to the reassembly buffer
     */
    Result<bool> add_fragment(const MessageFragment& fragment);
    
    /**
     * Check if message is complete
     */
    bool is_complete() const;
    
    /**
     * Get the complete message (only if is_complete() returns true)
     */
    Result<memory::Buffer> get_complete_message();
    
    /**
     * Clear the reassembly buffer
     */
    void clear();
    
    /**
     * Get reassembly statistics
     */
    struct ReassemblyStats {
        uint32_t total_length{0};
        uint32_t received_bytes{0};
        size_t fragment_count{0};
        size_t gap_count{0};
    };
    
    ReassemblyStats get_stats() const;

private:
    struct FragmentRange {
        uint32_t start;
        uint32_t end;
        memory::Buffer data;
        
        FragmentRange(uint32_t s, uint32_t e, memory::Buffer d)
            : start(s), end(e), data(std::move(d)) {}
    };
    
    uint32_t total_length_{0};
    std::vector<FragmentRange> fragments_;
    mutable std::mutex mutex_;
    
    void merge_overlapping_fragments();
    bool has_gap() const;
};

/**
 * DTLS Flight for reliable handshake message delivery
 */
enum class FlightType {
    CLIENT_HELLO_FLIGHT = 1,
    SERVER_HELLO_FLIGHT = 2,
    CLIENT_CERTIFICATE_FLIGHT = 3,
    SERVER_CERTIFICATE_FLIGHT = 4,
    CLIENT_FINISHED_FLIGHT = 5,
    SERVER_FINISHED_FLIGHT = 6
};

class DTLS_API HandshakeFlight {
public:
    HandshakeFlight(FlightType type, uint16_t message_seq_start);
    ~HandshakeFlight() = default;
    
    // Non-copyable, movable
    HandshakeFlight(const HandshakeFlight&) = delete;
    HandshakeFlight& operator=(const HandshakeFlight&) = delete;
    HandshakeFlight(HandshakeFlight&&) noexcept = default;
    HandshakeFlight& operator=(HandshakeFlight&&) noexcept = default;
    
    /**
     * Add a handshake message to the flight
     */
    void add_message(HandshakeMessage&& message);
    
    /**
     * Get all messages in the flight
     */
    const std::vector<HandshakeMessage>& get_messages() const;
    
    /**
     * Fragment all messages in the flight for transmission
     */
    Result<std::vector<MessageFragment>> fragment_messages(size_t max_fragment_size = 1200) const;
    
    /**
     * Get flight type
     */
    FlightType get_type() const { return type_; }
    
    /**
     * Get message sequence number range
     */
    std::pair<uint16_t, uint16_t> get_sequence_range() const;
    
    /**
     * Check if flight is complete
     */
    bool is_complete() const;
    
    /**
     * Get flight size in bytes
     */
    size_t get_total_size() const;

private:
    FlightType type_;
    uint16_t message_seq_start_;
    std::vector<HandshakeMessage> messages_;
};

/**
 * Flight manager for handling DTLS handshake flights
 */
class DTLS_API FlightManager {
public:
    FlightManager();
    ~FlightManager() = default;
    
    // Non-copyable, movable
    FlightManager(const FlightManager&) = delete;
    FlightManager& operator=(const FlightManager&) = delete;
    FlightManager(FlightManager&&) noexcept = default;
    FlightManager& operator=(FlightManager&&) noexcept = default;
    
    /**
     * Create a new flight
     */
    Result<void> create_flight(FlightType type);
    
    /**
     * Add message to current flight
     */
    Result<void> add_message_to_current_flight(HandshakeMessage&& message);
    
    /**
     * Complete current flight and prepare for transmission
     */
    Result<std::unique_ptr<HandshakeFlight>> complete_current_flight();
    
    /**
     * Set retransmission parameters
     */
    void set_retransmission_timeout(std::chrono::milliseconds timeout);
    void set_max_retransmissions(size_t max_retries);
    
    /**
     * Handle flight retransmission
     */
    bool should_retransmit(FlightType flight) const;
    void mark_flight_transmitted(FlightType flight);
    void mark_flight_acknowledged(FlightType flight);
    
    /**
     * Get flight statistics
     */
    struct FlightStats {
        size_t flights_created{0};
        size_t flights_transmitted{0};
        size_t flights_acknowledged{0};
        size_t retransmissions{0};
        std::chrono::milliseconds average_rtt{0};
    };
    
    FlightStats get_stats() const;

private:
    struct FlightState {
        std::unique_ptr<HandshakeFlight> flight;
        std::chrono::steady_clock::time_point last_transmission;
        size_t retransmission_count{0};
        bool acknowledged{false};
    };
    
    uint16_t next_message_seq_{0};
    std::unique_ptr<HandshakeFlight> current_flight_;
    std::map<FlightType, FlightState> flight_states_;
    
    std::chrono::milliseconds retransmission_timeout_{1000};
    size_t max_retransmissions_{3};
    
    mutable FlightStats stats_;
    mutable std::mutex mutex_;
};

/**
 * Main DTLS Message Layer
 * 
 * Handles message fragmentation, reassembly, flight management,
 * and reliable delivery for DTLS handshake messages.
 */
class DTLS_API MessageLayer {
public:
    MessageLayer(std::unique_ptr<RecordLayer> record_layer);
    ~MessageLayer() = default;
    
    // Non-copyable, movable
    MessageLayer(const MessageLayer&) = delete;
    MessageLayer& operator=(const MessageLayer&) = delete;
    MessageLayer(MessageLayer&&) noexcept = default;
    MessageLayer& operator=(MessageLayer&&) noexcept = default;
    
    /**
     * Initialize the message layer
     */
    Result<void> initialize();
    
    /**
     * Send a handshake message (handles fragmentation automatically)
     */
    Result<void> send_handshake_message(const HandshakeMessage& message);
    
    /**
     * Send a complete flight of handshake messages
     */
    Result<void> send_handshake_flight(std::unique_ptr<HandshakeFlight> flight);
    
    /**
     * Process incoming handshake record (handles reassembly)
     */
    Result<std::vector<HandshakeMessage>> process_incoming_handshake_record(
        const PlaintextRecord& record);
    
    /**
     * Start a new handshake flight
     */
    Result<void> start_flight(FlightType type);
    
    /**
     * Add message to current flight
     */
    Result<void> add_to_current_flight(HandshakeMessage&& message);
    
    /**
     * Complete and send current flight
     */
    Result<void> complete_and_send_flight();
    
    /**
     * Handle retransmissions (should be called periodically)
     */
    Result<void> handle_retransmissions();
    
    /**
     * Set message layer parameters
     */
    void set_max_fragment_size(size_t size);
    void set_retransmission_timeout(std::chrono::milliseconds timeout);
    void set_max_retransmissions(size_t max_retries);
    
    /**
     * Get message layer statistics
     */
    struct MessageLayerStats {
        size_t messages_sent{0};
        size_t messages_received{0};
        size_t fragments_sent{0};
        size_t fragments_received{0};
        size_t messages_reassembled{0};
        size_t flights_sent{0};
        size_t retransmissions{0};
        size_t reassembly_timeouts{0};
    };
    
    MessageLayerStats get_stats() const;

private:
    std::unique_ptr<RecordLayer> record_layer_;
    std::unique_ptr<FlightManager> flight_manager_;
    
    // Message reassembly
    std::map<uint16_t, std::unique_ptr<MessageReassembler>> reassemblers_;
    
    // Configuration
    size_t max_fragment_size_{1200}; // Conservative size for most networks
    std::chrono::milliseconds reassembly_timeout_{30000}; // 30 seconds
    
    // Statistics
    mutable MessageLayerStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Internal methods
    Result<std::vector<MessageFragment>> fragment_message(
        const HandshakeMessage& message) const;
    
    Result<PlaintextRecord> create_handshake_record(
        const MessageFragment& fragment, uint16_t epoch) const;
    
    void update_stats_message_sent();
    void update_stats_message_received();
    void update_stats_fragment_sent();
    void update_stats_fragment_received();
    void update_stats_message_reassembled();
    void update_stats_flight_sent();
    void update_stats_retransmission();
    void update_stats_reassembly_timeout();
    
    void cleanup_old_reassemblers();
};

// Utility functions for message layer testing and debugging
namespace message_layer_utils {

/**
 * Create test message layer with mock dependencies
 */
DTLS_API std::unique_ptr<MessageLayer> create_test_message_layer();

/**
 * Validate message layer configuration
 */
DTLS_API Result<void> validate_message_layer_config(const MessageLayer& layer);

/**
 * Generate test handshake messages
 */
DTLS_API Result<std::vector<HandshakeMessage>> generate_test_handshake_messages();

/**
 * Test message fragmentation and reassembly
 */
DTLS_API Result<bool> test_fragmentation_reassembly(const HandshakeMessage& message,
                                                   size_t fragment_size);

} // namespace message_layer_utils
} // namespace protocol
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_MESSAGE_LAYER_H