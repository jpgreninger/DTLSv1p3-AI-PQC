#ifndef DTLS_PROTOCOL_RECORD_LAYER_H
#define DTLS_PROTOCOL_RECORD_LAYER_H

#include <dtls/config.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <dtls/protocol/record.h>
#include <dtls/protocol/dtls_records.h>
#include <dtls/crypto.h>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <chrono>

namespace dtls {
namespace v13 {
namespace protocol {

/**
 * Anti-Replay Window for detecting duplicate packets
 * 
 * Implements sliding window algorithm as specified in RFC 9147
 * to protect against replay attacks by tracking received sequence numbers.
 */
class DTLS_API AntiReplayWindow {
public:
    static constexpr size_t DEFAULT_WINDOW_SIZE = 64;
    
    explicit AntiReplayWindow(size_t window_size = DEFAULT_WINDOW_SIZE);
    ~AntiReplayWindow() = default;
    
    // Non-copyable, movable
    AntiReplayWindow(const AntiReplayWindow&) = delete;
    AntiReplayWindow& operator=(const AntiReplayWindow&) = delete;
    AntiReplayWindow(AntiReplayWindow&&) noexcept = default;
    AntiReplayWindow& operator=(AntiReplayWindow&&) noexcept = default;
    
    /**
     * Check if sequence number is valid (not a replay)
     * @param sequence_number The sequence number to check
     * @return true if valid, false if replay detected
     */
    bool is_valid_sequence_number(uint64_t sequence_number);
    
    /**
     * Mark sequence number as received
     * @param sequence_number The sequence number to mark
     */
    void mark_received(uint64_t sequence_number);
    
    /**
     * Reset the window (for epoch changes)
     */
    void reset();
    
    /**
     * Get current window statistics
     */
    struct WindowStats {
        uint64_t highest_sequence_number{0};
        uint64_t lowest_sequence_number{0};
        size_t window_size{0};
        size_t received_count{0};
        size_t replay_count{0};
    };
    
    WindowStats get_stats() const;

private:
    size_t window_size_;
    uint64_t highest_sequence_number_{0};
    std::vector<bool> window_;
    size_t received_count_{0};
    size_t replay_count_{0};
    mutable std::mutex mutex_;
    
    void slide_window(uint64_t new_highest);
};

/**
 * Sequence Number Manager for tracking and generating sequence numbers
 */
class DTLS_API SequenceNumberManager {
public:
    SequenceNumberManager() = default;
    ~SequenceNumberManager() = default;
    
    // Non-copyable, movable
    SequenceNumberManager(const SequenceNumberManager&) = delete;
    SequenceNumberManager& operator=(const SequenceNumberManager&) = delete;
    SequenceNumberManager(SequenceNumberManager&&) noexcept = default;
    SequenceNumberManager& operator=(SequenceNumberManager&&) noexcept = default;
    
    /**
     * Get next sequence number for sending
     */
    uint64_t get_next_sequence_number();
    
    /**
     * Get current sequence number (last generated)
     */
    uint64_t get_current_sequence_number() const;
    
    /**
     * Reset sequence numbers (for epoch change)
     */
    void reset();
    
    /**
     * Check if sequence number would overflow
     */
    bool would_overflow() const;

private:
    uint64_t current_sequence_number_{0};
    mutable std::mutex mutex_;
    
    static constexpr uint64_t MAX_SEQUENCE_NUMBER = (1ULL << 48) - 1; // 48-bit sequence numbers
};

/**
 * Epoch Manager for handling DTLS epochs
 */
class DTLS_API EpochManager {
public:
    EpochManager() = default;
    ~EpochManager() = default;
    
    // Non-copyable, movable
    EpochManager(const EpochManager&) = delete;
    EpochManager& operator=(const EpochManager&) = delete;
    EpochManager(EpochManager&&) noexcept = default;
    EpochManager& operator=(EpochManager&&) noexcept = default;
    
    /**
     * Get current epoch
     */
    uint16_t get_current_epoch() const;
    
    /**
     * Get current epoch (alias for get_current_epoch)
     */
    uint16_t current_epoch() const { return get_current_epoch(); }
    
    /**
     * Advance to next epoch
     */
    Result<uint16_t> advance_epoch();
    
    /**
     * Check if epoch is valid for receiving
     */
    bool is_valid_epoch(uint16_t epoch) const;
    
    /**
     * Set crypto keys for an epoch
     */
    Result<void> set_epoch_keys(uint16_t epoch, 
                               const std::vector<uint8_t>& read_key,
                               const std::vector<uint8_t>& write_key,
                               const std::vector<uint8_t>& read_iv,
                               const std::vector<uint8_t>& write_iv);
    
    /**
     * Get crypto parameters for an epoch
     */
    struct EpochCryptoParams {
        std::vector<uint8_t> read_key;
        std::vector<uint8_t> write_key;
        std::vector<uint8_t> read_iv;
        std::vector<uint8_t> write_iv;
        CipherSuite cipher_suite;
    };
    
    Result<EpochCryptoParams> get_epoch_crypto_params(uint16_t epoch) const;

private:
    uint16_t current_epoch_{0};
    std::unordered_map<uint16_t, EpochCryptoParams> epoch_keys_;
    mutable std::mutex mutex_;
    
    static constexpr uint16_t MAX_EPOCH = 65535;
};

/**
 * Connection ID Manager for handling DTLS Connection IDs (RFC 9146)
 */
class DTLS_API ConnectionIDManager {
public:
    ConnectionIDManager() = default;
    ~ConnectionIDManager() = default;
    
    // Non-copyable, movable
    ConnectionIDManager(const ConnectionIDManager&) = delete;
    ConnectionIDManager& operator=(const ConnectionIDManager&) = delete;
    ConnectionIDManager(ConnectionIDManager&&) noexcept = default;
    ConnectionIDManager& operator=(ConnectionIDManager&&) noexcept = default;
    
    /**
     * Set local connection ID
     */
    void set_local_connection_id(const ConnectionID& cid);
    
    /**
     * Set peer connection ID
     */
    void set_peer_connection_id(const ConnectionID& cid);
    
    /**
     * Get local connection ID
     */
    const ConnectionID& get_local_connection_id() const;
    
    /**
     * Get peer connection ID
     */
    const ConnectionID& get_peer_connection_id() const;
    
    /**
     * Check if connection ID is enabled
     */
    bool is_connection_id_enabled() const;
    
    /**
     * Validate incoming connection ID
     */
    bool is_valid_connection_id(const ConnectionID& cid) const;

private:
    ConnectionID local_connection_id_;
    ConnectionID peer_connection_id_;
    bool connection_id_enabled_{false};
    mutable std::mutex mutex_;
};

/**
 * Main Record Layer implementation
 * 
 * Handles record protection/unprotection, sequence number management,
 * epoch handling, and anti-replay protection for DTLS v1.3.
 */
class DTLS_API RecordLayer {
public:
    RecordLayer(std::unique_ptr<crypto::CryptoProvider> crypto_provider);
    ~RecordLayer() = default;
    
    // Non-copyable, movable
    RecordLayer(const RecordLayer&) = delete;
    RecordLayer& operator=(const RecordLayer&) = delete;
    RecordLayer(RecordLayer&&) noexcept = default;
    RecordLayer& operator=(RecordLayer&&) noexcept = default;
    
    /**
     * Initialize the record layer
     */
    Result<void> initialize();
    
    /**
     * Set cipher suite for current epoch
     */
    Result<void> set_cipher_suite(CipherSuite suite);
    
    /**
     * Protect a plaintext record (encrypt) - RFC 9147 compliance
     */
    Result<DTLSCiphertext> protect_record(const DTLSPlaintext& plaintext);
    
    /**
     * Unprotect a ciphertext record (decrypt) - RFC 9147 compliance
     */
    Result<DTLSPlaintext> unprotect_record(const DTLSCiphertext& ciphertext);
    
    /**
     * Process incoming record (includes anti-replay check)
     */
    Result<DTLSPlaintext> process_incoming_record(const DTLSCiphertext& ciphertext);
    
    /**
     * Prepare outgoing record (includes sequence number assignment)
     */
    Result<DTLSCiphertext> prepare_outgoing_record(const DTLSPlaintext& plaintext);
    
    // Legacy support for backward compatibility
    Result<CiphertextRecord> protect_record_legacy(const PlaintextRecord& plaintext);
    Result<PlaintextRecord> unprotect_record_legacy(const CiphertextRecord& ciphertext);
    
    /**
     * Advance to next epoch with new keys
     */
    Result<void> advance_epoch(const std::vector<uint8_t>& read_key,
                              const std::vector<uint8_t>& write_key,
                              const std::vector<uint8_t>& read_iv,
                              const std::vector<uint8_t>& write_iv);
    
    /**
     * Update traffic keys (RFC 9147 Section 4.6.3)
     * Generates new read/write keys from current keys using HKDF-Expand-Label
     */
    Result<void> update_traffic_keys();
    
    /**
     * Update traffic keys with provided key schedule
     * Used for coordinated key updates across multiple layers
     */
    Result<void> update_traffic_keys(const crypto::KeySchedule& new_keys);
    
    /**
     * Check if key update is needed based on record count or time
     */
    bool needs_key_update(uint64_t max_records = (1ULL << 24), 
                         std::chrono::seconds max_time = std::chrono::hours(24)) const;
    
    /**
     * Get current key update statistics
     */
    struct KeyUpdateStats {
        uint64_t updates_performed{0};
        uint64_t records_since_last_update{0};
        std::chrono::steady_clock::time_point last_update_time;
        uint64_t peer_updates_received{0};
        uint64_t peer_updates_requested{0};
    };
    KeyUpdateStats get_key_update_stats() const;
    
    /**
     * Enable connection ID support
     */
    Result<void> enable_connection_id(const ConnectionID& local_cid, 
                                     const ConnectionID& peer_cid);
    
    /**
     * Get current record layer statistics
     */
    struct RecordLayerStats {
        uint64_t records_sent{0};
        uint64_t records_received{0};
        uint64_t records_protected{0};
        uint64_t records_unprotected{0};
        uint64_t replay_attacks_detected{0};
        uint64_t decryption_failures{0};
        uint16_t current_epoch{0};
        uint64_t current_sequence_number{0};
    };
    
    RecordLayerStats get_stats() const;

private:
    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
    CipherSuite current_cipher_suite_{CipherSuite::TLS_AES_128_GCM_SHA256};
    
    // Managers
    std::unique_ptr<SequenceNumberManager> send_sequence_manager_;
    std::unordered_map<uint16_t, std::unique_ptr<AntiReplayWindow>> receive_windows_;
    std::unique_ptr<EpochManager> epoch_manager_;
    std::unique_ptr<ConnectionIDManager> connection_id_manager_;
    
    // Statistics
    mutable RecordLayerStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Key update state
    mutable KeyUpdateStats key_update_stats_;
    std::chrono::steady_clock::time_point connection_start_time_;
    mutable std::mutex key_update_mutex_;
    
    // Internal methods
    Result<std::vector<uint8_t>> construct_aead_nonce(uint16_t epoch, 
                                                     uint64_t sequence_number,
                                                     const std::vector<uint8_t>& base_iv) const;
    
    Result<std::vector<uint8_t>> construct_additional_data(const RecordHeader& header,
                                                          const ConnectionID& cid) const;
    
    // Helper for DTLSCiphertext additional data construction
    template<typename HeaderType>
    Result<std::vector<uint8_t>> construct_additional_data_dtls(const HeaderType& header,
                                                               const ConnectionID& cid) const;
    
    void update_stats_sent();
    void update_stats_received();
    void update_stats_protected();
    void update_stats_unprotected();
    void update_stats_replay_detected();
    void update_stats_decryption_failed();
};

// Utility functions for record layer testing and debugging
namespace record_layer_utils {

/**
 * Create test record layer with mock crypto provider
 */
DTLS_API std::unique_ptr<RecordLayer> create_test_record_layer();

/**
 * Validate record layer configuration
 */
DTLS_API Result<void> validate_record_layer_config(const RecordLayer& layer);

/**
 * Generate test vectors for record protection - RFC 9147 compliance
 */
DTLS_API Result<std::vector<std::pair<DTLSPlaintext, DTLSCiphertext>>> 
    generate_test_vectors(CipherSuite suite);

/**
 * Legacy test vector generation
 */
DTLS_API Result<std::vector<std::pair<PlaintextRecord, CiphertextRecord>>> 
    generate_legacy_test_vectors(CipherSuite suite);

} // namespace record_layer_utils
} // namespace protocol
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_RECORD_LAYER_H