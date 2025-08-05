#pragma once

#include <dtls/error.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/protocol/handshake.h>

#include <memory>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <vector>

namespace dtls {
namespace v13 {
namespace protocol {

/**
 * Configuration for fragment reassembly behavior
 */
struct FragmentReassemblyConfig {
    // Timeout for incomplete fragment reassembly
    std::chrono::milliseconds reassembly_timeout{30000}; // 30 seconds
    
    // Maximum number of concurrent reassembly operations
    size_t max_concurrent_reassemblies{100};
    
    // Maximum total memory used for fragment reassembly (bytes)
    size_t max_reassembly_memory{1048576}; // 1MB
    
    // Maximum message size for reassembly
    size_t max_message_size{65536}; // 64KB
    
    // Maximum number of fragments per message
    size_t max_fragments_per_message{64};
    
    // Enable strict fragment validation
    bool strict_validation{true};
    
    // Enable duplicate fragment detection
    bool detect_duplicates{true};
    
    // Enable out-of-order fragment handling
    bool handle_out_of_order{true};
    
    FragmentReassemblyConfig() = default;
};

/**
 * Statistics for fragment reassembly operations
 */
struct FragmentReassemblyStats {
    // Message reassembly statistics
    std::atomic<uint64_t> messages_started{0};
    std::atomic<uint64_t> messages_completed{0};
    std::atomic<uint64_t> messages_timed_out{0};
    std::atomic<uint64_t> messages_failed{0};
    
    // Fragment statistics
    std::atomic<uint64_t> fragments_received{0};
    std::atomic<uint64_t> fragments_duplicate{0};
    std::atomic<uint64_t> fragments_out_of_order{0};
    std::atomic<uint64_t> fragments_invalid{0};
    
    // Performance statistics
    std::atomic<uint64_t> total_reassembly_time_ns{0};
    std::atomic<uint64_t> peak_memory_usage{0};
    std::atomic<uint32_t> peak_concurrent_reassemblies{0};
    
    // Current state
    std::atomic<uint32_t> active_reassemblies{0};
    std::atomic<uint64_t> current_memory_usage{0};
    
    FragmentReassemblyStats() = default;
    
    // Delete copy and move constructors/assignments due to atomic members
    FragmentReassemblyStats(const FragmentReassemblyStats&) = delete;
    FragmentReassemblyStats& operator=(const FragmentReassemblyStats&) = delete;
    FragmentReassemblyStats(FragmentReassemblyStats&&) = delete;
    FragmentReassemblyStats& operator=(FragmentReassemblyStats&&) = delete;
    
    // Calculate average reassembly time in microseconds
    double get_average_reassembly_time_us() const {
        uint64_t completed = messages_completed.load();
        if (completed == 0) return 0.0;
        return static_cast<double>(total_reassembly_time_ns.load()) / (completed * 1000.0);
    }
    
    // Calculate success rate (0.0 to 1.0)
    double get_success_rate() const {
        uint64_t total = messages_started.load();
        if (total == 0) return 0.0;
        return static_cast<double>(messages_completed.load()) / total;
    }
};

/**
 * Enhanced Fragment Reassembler with timeout management and security validation
 * 
 * This class provides a robust fragment reassembly system with the following features:
 * - Automatic timeout and cleanup of incomplete reassemblies
 * - Memory usage tracking and limits
 * - Security validation against malicious fragments
 * - Performance optimization for large messages
 * - Thread-safe operation with minimal lock contention
 */
class DTLS_API FragmentReassembler {
public:
    /**
     * Create a new fragment reassembler with the given configuration
     */
    explicit FragmentReassembler(const FragmentReassemblyConfig& config = FragmentReassemblyConfig{});
    
    ~FragmentReassembler();
    
    // Non-copyable, movable
    FragmentReassembler(const FragmentReassembler&) = delete;
    FragmentReassembler& operator=(const FragmentReassembler&) = delete;
    FragmentReassembler(FragmentReassembler&&) noexcept = default;
    FragmentReassembler& operator=(FragmentReassembler&&) noexcept = default;
    
    /**
     * Add a handshake message fragment for reassembly
     * 
     * @param message_seq Message sequence number (identifies the message)
     * @param fragment_offset Offset of this fragment within the complete message
     * @param fragment_length Length of this fragment
     * @param total_message_length Total length of the complete message
     * @param fragment_data The fragment payload data
     * @return Result indicating success and whether message is now complete
     */
    Result<bool> add_fragment(
        uint16_t message_seq,
        uint32_t fragment_offset,
        uint32_t fragment_length,
        uint32_t total_message_length,
        const memory::ZeroCopyBuffer& fragment_data
    );
    
    /**
     * Check if a message is completely reassembled
     */
    bool is_message_complete(uint16_t message_seq) const;
    
    /**
     * Get the complete reassembled message
     * 
     * @param message_seq Message sequence number
     * @return Complete message buffer, or error if not complete
     */
    Result<memory::ZeroCopyBuffer> get_complete_message(uint16_t message_seq);
    
    /**
     * Remove and cleanup a specific message reassembly
     */
    void remove_message(uint16_t message_seq);
    
    /**
     * Clean up timed-out reassembly operations
     * This should be called periodically to prevent memory leaks
     */
    void cleanup_timed_out_reassemblies();
    
    /**
     * Force cleanup of all reassembly operations
     */
    void clear_all_reassemblies();
    
    /**
     * Get current reassembly statistics
     */
    const FragmentReassemblyStats& get_stats() const;
    
    /**
     * Reset statistics counters
     */
    void reset_stats();
    
    /**
     * Get current configuration
     */
    const FragmentReassemblyConfig& get_config() const { return config_; }
    
    /**
     * Update configuration (thread-safe)
     */
    void update_config(const FragmentReassemblyConfig& new_config);

private:
    struct FragmentInfo {
        uint32_t offset;
        uint32_t length;
        memory::ZeroCopyBuffer data;
        std::chrono::steady_clock::time_point arrival_time;
        
        FragmentInfo(uint32_t off, uint32_t len, memory::ZeroCopyBuffer d)
            : offset(off), length(len), data(std::move(d))
            , arrival_time(std::chrono::steady_clock::now()) {}
    };
    
    struct MessageReassemblyState {
        uint32_t total_length;
        uint32_t received_bytes;
        std::vector<FragmentInfo> fragments;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point last_fragment_time;
        uint32_t expected_fragments;
        bool is_complete;
        
        MessageReassemblyState(uint32_t total_len)
            : total_length(total_len), received_bytes(0)
            , start_time(std::chrono::steady_clock::now())
            , last_fragment_time(start_time)
            , expected_fragments(0), is_complete(false) {}
    };
    
    // Configuration
    FragmentReassemblyConfig config_;
    
    // Active reassembly operations
    std::unordered_map<uint16_t, std::unique_ptr<MessageReassemblyState>> active_reassemblies_;
    mutable std::mutex reassembly_mutex_;
    
    // Statistics
    mutable FragmentReassemblyStats stats_;
    
    // Helper methods
    bool validate_fragment(
        uint16_t message_seq,
        uint32_t fragment_offset,
        uint32_t fragment_length,
        uint32_t total_message_length,
        const memory::ZeroCopyBuffer& fragment_data
    ) const;
    
    bool check_memory_limits(uint32_t additional_bytes) const;
    bool check_concurrency_limits() const;
    
    Result<void> add_fragment_to_state(
        MessageReassemblyState& state,
        uint32_t fragment_offset,
        uint32_t fragment_length,
        const memory::ZeroCopyBuffer& fragment_data
    );
    
    bool check_message_complete(MessageReassemblyState& state);
    Result<memory::ZeroCopyBuffer> assemble_complete_message(MessageReassemblyState& state);
    
    void update_memory_usage(int64_t delta);
    void record_reassembly_completion(const MessageReassemblyState& state, bool success);
    
    bool is_duplicate_fragment(
        const MessageReassemblyState& state,
        uint32_t fragment_offset,
        uint32_t fragment_length
    ) const;
    
    void sort_fragments(std::vector<FragmentInfo>& fragments) const;
    bool has_fragment_gaps(const std::vector<FragmentInfo>& fragments, uint32_t total_length) const;
};

/**
 * Connection-level fragment reassembly manager
 * 
 * Manages fragment reassembly for a specific DTLS connection with:
 * - Per-connection reassembly isolation
 * - Automatic cleanup on connection close
 * - Integration with connection statistics
 */
class DTLS_API ConnectionFragmentManager {
public:
    explicit ConnectionFragmentManager(const FragmentReassemblyConfig& config = FragmentReassemblyConfig{});
    ~ConnectionFragmentManager() = default;
    
    // Non-copyable, movable
    ConnectionFragmentManager(const ConnectionFragmentManager&) = delete;
    ConnectionFragmentManager& operator=(const ConnectionFragmentManager&) = delete;
    ConnectionFragmentManager(ConnectionFragmentManager&&) noexcept = default;
    ConnectionFragmentManager& operator=(ConnectionFragmentManager&&) noexcept = default;
    
    /**
     * Process an incoming handshake fragment
     */
    Result<bool> process_handshake_fragment(const HandshakeHeader& header, 
                                           const memory::ZeroCopyBuffer& fragment_data);
    
    /**
     * Get a complete handshake message if available
     */
    Result<HandshakeMessage> get_complete_handshake_message(uint16_t message_seq);
    
    /**
     * Clean up resources (called on connection close)
     */
    void cleanup();
    
    /**
     * Get reassembly statistics
     */
    const FragmentReassemblyStats& get_stats() const;
    
    /**
     * Perform periodic maintenance (cleanup timeouts)
     */
    void perform_maintenance();

private:
    std::unique_ptr<FragmentReassembler> reassembler_;
    
    // Cache for complete messages awaiting retrieval
    std::unordered_map<uint16_t, HandshakeMessage> completed_messages_;
    mutable std::mutex completed_messages_mutex_;
    
    Result<HandshakeMessage> deserialize_handshake_message(
        HandshakeType msg_type, 
        const memory::ZeroCopyBuffer& message_data
    );
};

} // namespace protocol
} // namespace v13
} // namespace dtls