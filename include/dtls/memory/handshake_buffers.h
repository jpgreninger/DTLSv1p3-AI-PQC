#ifndef DTLS_MEMORY_HANDSHAKE_BUFFERS_H
#define DTLS_MEMORY_HANDSHAKE_BUFFERS_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/memory/connection_pools.h>
#include <dtls/memory/dos_protection.h>
#include <dtls/protocol/handshake.h>
#include <memory>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>
#include <atomic>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * Optimized Handshake Message Buffering for DTLS v1.3
 * 
 * This system provides specialized memory management for DTLS handshake
 * messages, including efficient fragmentation handling, message reassembly,
 * and DoS-resistant buffering strategies.
 */

// Forward declarations
namespace protocol = dtls::v13::protocol;

// Handshake fragment information
struct HandshakeFragment {
    uint8_t message_type{0};
    uint32_t message_length{0};
    uint32_t fragment_offset{0};
    uint32_t fragment_length{0};
    uint16_t message_sequence{0};
    std::shared_ptr<ZeroCopyBuffer> fragment_data;
    std::chrono::steady_clock::time_point received_time;
    
    bool is_complete() const {
        return fragment_offset == 0 && fragment_length == message_length;
    }
    
    bool is_valid() const {
        return fragment_data && fragment_data->size() == fragment_length &&
               fragment_offset + fragment_length <= message_length;
    }
};

// Handshake message reassembly state
struct HandshakeReassembly {
    uint8_t message_type{0};
    uint32_t message_length{0};
    uint16_t message_sequence{0};
    std::shared_ptr<ZeroCopyBuffer> complete_message;
    
    // Fragment tracking
    std::vector<HandshakeFragment> fragments;
    std::vector<bool> received_ranges; // Bitmap for received byte ranges
    size_t total_fragments_received{0};
    size_t bytes_received{0};
    
    // Timing and DoS protection
    std::chrono::steady_clock::time_point first_fragment_time;
    std::chrono::steady_clock::time_point last_fragment_time;
    std::string source_ip;
    bool is_complete{false};
    bool has_duplicate_fragments{false};
    
    // Memory usage tracking
    size_t memory_usage{0};
    
    void update_memory_usage() {
        memory_usage = 0;
        for (const auto& fragment : fragments) {
            if (fragment.fragment_data) {
                memory_usage += fragment.fragment_data->size();
            }
        }
        memory_usage += received_ranges.size() / 8; // Bitmap overhead
    }
};

// Optimized handshake buffer manager
class DTLS_API HandshakeBufferManager {
public:
    static HandshakeBufferManager& instance();
    
    // Fragment handling
    Result<void> store_handshake_fragment(void* connection_id, 
                                         const std::string& source_ip,
                                         const HandshakeFragment& fragment);
    
    Result<std::shared_ptr<ZeroCopyBuffer>> try_assemble_message(
        void* connection_id, uint16_t message_sequence);
    
    // Buffer management
    Result<std::shared_ptr<ZeroCopyBuffer>> allocate_handshake_buffer(
        void* connection_id, const std::string& source_ip, size_t size);
    
    Result<std::shared_ptr<ZeroCopyBuffer>> allocate_fragment_buffer(
        void* connection_id, const std::string& source_ip, size_t size);
    
    // Specialized allocators for different handshake message types
    Result<std::shared_ptr<ZeroCopyBuffer>> allocate_certificate_buffer(
        void* connection_id, const std::string& source_ip);
    
    Result<std::shared_ptr<ZeroCopyBuffer>> allocate_key_exchange_buffer(
        void* connection_id, const std::string& source_ip);
    
    Result<std::shared_ptr<ZeroCopyBuffer>> allocate_finished_buffer(
        void* connection_id, const std::string& source_ip);
    
    // Connection lifecycle
    void on_handshake_start(void* connection_id, const std::string& source_ip);
    void on_handshake_complete(void* connection_id);
    void on_handshake_failed(void* connection_id);
    void cleanup_connection(void* connection_id);
    
    // DoS protection integration
    bool is_fragmentation_attack(void* connection_id, const std::string& source_ip) const;
    Result<void> validate_fragment(const HandshakeFragment& fragment, 
                                  const std::string& source_ip) const;
    
    // Memory management
    size_t cleanup_expired_fragments();
    size_t cleanup_abandoned_reassemblies();
    size_t get_total_memory_usage() const;
    size_t get_connection_memory_usage(void* connection_id) const;
    
    // Configuration
    struct HandshakeBufferConfig {
        size_t max_message_size{32 * 1024};           // 32KB max handshake message
        size_t max_fragment_size{16 * 1024};          // 16KB max fragment
        size_t max_fragments_per_message{64};         // Max fragments per message
        size_t max_concurrent_reassemblies{100};      // Max reassemblies per connection
        size_t max_reassembly_memory_per_connection{1024 * 1024}; // 1MB per connection
        std::chrono::seconds fragment_timeout{30};    // Fragment expiry time
        std::chrono::seconds reassembly_timeout{60};  // Reassembly expiry time
        bool enable_duplicate_detection{true};        // Detect duplicate fragments
        bool enable_dos_protection{true};             // Enable DoS protection
    };
    
    void set_config(const HandshakeBufferConfig& config);
    HandshakeBufferConfig get_config() const;
    
    // Statistics and monitoring
    struct HandshakeBufferStats {
        size_t total_fragments_stored{0};
        size_t total_messages_assembled{0};
        size_t total_reassembly_failures{0};
        size_t duplicate_fragments_detected{0};
        size_t fragmentation_attacks_detected{0};
        size_t memory_usage{0};
        size_t active_reassemblies{0};
        double average_reassembly_time_ms{0.0};
        std::chrono::steady_clock::time_point last_cleanup;
    };
    
    HandshakeBufferStats get_statistics() const;
    void reset_statistics();

private:
    HandshakeBufferManager() = default;
    ~HandshakeBufferManager() = default;
    
    // Connection state tracking
    struct ConnectionHandshakeState {
        void* connection_id{nullptr};
        std::string source_ip;
        std::chrono::steady_clock::time_point handshake_start_time;
        
        // Reassembly state for each message sequence
        std::unordered_map<uint16_t, HandshakeReassembly> reassemblies;
        
        // DoS protection counters
        size_t total_fragments_received{0};
        size_t total_bytes_received{0};
        size_t duplicate_fragments_received{0};
        size_t malformed_fragments_received{0};
        
        // Memory usage
        size_t current_memory_usage{0};
        size_t peak_memory_usage{0};
        
        bool is_active{true};
    };
    
    mutable std::mutex state_mutex_;
    std::unordered_map<void*, ConnectionHandshakeState> connection_states_;
    
    mutable std::mutex config_mutex_;
    HandshakeBufferConfig config_;
    
    mutable std::mutex stats_mutex_;
    HandshakeBufferStats stats_;
    
    // Internal methods
    Result<void> store_fragment_in_reassembly(HandshakeReassembly& reassembly, 
                                             const HandshakeFragment& fragment);
    bool is_message_complete(const HandshakeReassembly& reassembly) const;
    Result<std::shared_ptr<ZeroCopyBuffer>> assemble_complete_message(
        HandshakeReassembly& reassembly);
    
    void mark_byte_range_received(HandshakeReassembly& reassembly, 
                                 uint32_t offset, uint32_t length);
    bool is_byte_range_received(const HandshakeReassembly& reassembly,
                               uint32_t offset, uint32_t length) const;
    
    void update_connection_memory_usage(ConnectionHandshakeState& state);
    bool enforce_memory_limits(const ConnectionHandshakeState& state, 
                              size_t additional_memory) const;
    
    void detect_and_handle_dos_attack(ConnectionHandshakeState& state);
    bool is_fragment_duplicate(const HandshakeReassembly& reassembly,
                              const HandshakeFragment& fragment) const;
    
    void cleanup_connection_state(ConnectionHandshakeState& state);
    void update_statistics(const ConnectionHandshakeState& state);
};

// Fragment-aware buffer pools
class DTLS_API FragmentBufferPool {
public:
    static FragmentBufferPool& instance();
    
    // Optimized pools for common fragment sizes
    std::shared_ptr<ZeroCopyBuffer> acquire_small_fragment_buffer();   // < 1KB
    std::shared_ptr<ZeroCopyBuffer> acquire_medium_fragment_buffer();  // 1KB - 4KB
    std::shared_ptr<ZeroCopyBuffer> acquire_large_fragment_buffer();   // 4KB - 16KB
    
    void release_fragment_buffer(std::shared_ptr<ZeroCopyBuffer> buffer);
    
    // Message-specific pools
    std::shared_ptr<ZeroCopyBuffer> acquire_certificate_buffer();
    std::shared_ptr<ZeroCopyBuffer> acquire_key_exchange_buffer();
    std::shared_ptr<ZeroCopyBuffer> acquire_finished_buffer();
    
    // Pool statistics
    struct FragmentPoolStats {
        size_t small_fragments_allocated{0};
        size_t medium_fragments_allocated{0};
        size_t large_fragments_allocated{0};
        size_t certificate_buffers_allocated{0};
        size_t key_exchange_buffers_allocated{0};
        size_t finished_buffers_allocated{0};
        double hit_rate{0.0};
        size_t total_memory_usage{0};
    };
    
    FragmentPoolStats get_statistics() const;
    void optimize_pool_sizes();

private:
    FragmentBufferPool() = default;
    ~FragmentBufferPool() = default;
    
    // Specialized pools
    std::unique_ptr<AdaptiveBufferPool> small_fragment_pool_;
    std::unique_ptr<AdaptiveBufferPool> medium_fragment_pool_;
    std::unique_ptr<AdaptiveBufferPool> large_fragment_pool_;
    
    std::unique_ptr<AdaptiveBufferPool> certificate_pool_;
    std::unique_ptr<AdaptiveBufferPool> key_exchange_pool_;
    std::unique_ptr<AdaptiveBufferPool> finished_pool_;
    
    mutable std::mutex stats_mutex_;
    FragmentPoolStats stats_;
    
    void initialize_pools();
    size_t calculate_optimal_pool_size(const std::string& pool_type) const;
};

// Zero-copy message assembly
class DTLS_API ZeroCopyMessageAssembler {
public:
    // Assemble message from fragments using zero-copy techniques
    static Result<std::shared_ptr<ZeroCopyBuffer>> assemble_from_fragments(
        const std::vector<HandshakeFragment>& fragments, size_t total_size);
    
    // Validate fragment ordering and consistency
    static Result<void> validate_fragment_sequence(
        const std::vector<HandshakeFragment>& fragments);
    
    // Optimize fragment layout for cache efficiency
    static void optimize_fragment_layout(std::vector<HandshakeFragment>& fragments);
    
    // Create shared buffer for efficient fragment storage
    static Result<std::shared_ptr<ZeroCopyBuffer>> create_shared_assembly_buffer(
        size_t total_size);

private:
    // Internal assembly helpers
    static bool fragments_are_contiguous(const std::vector<HandshakeFragment>& fragments);
    static void sort_fragments_by_offset(std::vector<HandshakeFragment>& fragments);
    static Result<void> copy_fragments_to_buffer(
        const std::vector<HandshakeFragment>& fragments,
        ZeroCopyBuffer& target_buffer);
};

// Fragmentation attack detection
class DTLS_API FragmentationAttackDetector {
public:
    static FragmentationAttackDetector& instance();
    
    // Attack detection
    bool detect_fragmentation_attack(void* connection_id, const std::string& source_ip);
    
    // Pattern analysis
    bool is_excessive_fragmentation(const std::vector<HandshakeFragment>& fragments,
                                   size_t message_size) const;
    
    bool is_overlapping_fragments_attack(const std::vector<HandshakeFragment>& fragments) const;
    
    bool is_tiny_fragments_attack(const std::vector<HandshakeFragment>& fragments) const;
    
    bool is_fragment_flood_attack(const std::string& source_ip) const;
    
    // Attack mitigation
    void report_fragmentation_attack(const std::string& source_ip, 
                                   const std::string& attack_type);
    
    void apply_fragmentation_limits(const std::string& source_ip);
    
    // Configuration
    struct AttackDetectionConfig {
        size_t max_fragments_per_message{32};
        size_t min_fragment_size{64};
        double max_fragmentation_ratio{0.5};  // Max fragment overhead ratio
        size_t max_fragments_per_second{100};
        std::chrono::seconds detection_window{60};
    };
    
    void set_config(const AttackDetectionConfig& config);
    AttackDetectionConfig get_config() const;

private:
    FragmentationAttackDetector() = default;
    ~FragmentationAttackDetector() = default;
    
    AttackDetectionConfig config_;
    mutable std::mutex config_mutex_;
    
    // Per-IP fragment tracking
    struct IPFragmentStats {
        size_t fragments_received{0};
        size_t messages_fragmented{0};
        size_t tiny_fragments{0};
        size_t overlapping_fragments{0};
        std::vector<std::chrono::steady_clock::time_point> recent_fragments;
        bool is_suspicious{false};
    };
    
    std::unordered_map<std::string, IPFragmentStats> ip_fragment_stats_;
    mutable std::mutex stats_mutex_;
    
    void update_ip_fragment_stats(const std::string& source_ip,
                                 const HandshakeFragment& fragment);
    void cleanup_old_fragment_stats();
};

// Factory functions for handshake buffers
DTLS_API Result<std::shared_ptr<ZeroCopyBuffer>> make_handshake_buffer(
    void* connection_id, const std::string& source_ip, size_t size);

DTLS_API Result<std::shared_ptr<ZeroCopyBuffer>> make_fragment_buffer(
    void* connection_id, const std::string& source_ip, size_t size);

DTLS_API Result<std::shared_ptr<ZeroCopyBuffer>> make_certificate_buffer(
    void* connection_id, const std::string& source_ip);

// Handshake-specific optimizations
DTLS_API void optimize_handshake_memory_layout();
DTLS_API void enable_handshake_buffer_pooling(bool enabled = true);
DTLS_API void configure_handshake_dos_protection(bool enabled = true);
DTLS_API void cleanup_expired_handshake_fragments();

// Integration functions
DTLS_API void integrate_handshake_buffers_with_dos_protection();
DTLS_API void integrate_handshake_buffers_with_connection_pools();

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_HANDSHAKE_BUFFERS_H