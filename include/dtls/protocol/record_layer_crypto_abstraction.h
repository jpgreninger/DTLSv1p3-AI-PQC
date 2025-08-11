#ifndef DTLS_PROTOCOL_RECORD_LAYER_CRYPTO_ABSTRACTION_H
#define DTLS_PROTOCOL_RECORD_LAYER_CRYPTO_ABSTRACTION_H

#include <dtls/protocol/record_layer_interface.h>
#include <dtls/crypto/operations.h>
#include <memory>
#include <set>

namespace dtls {
namespace v13 {
namespace protocol {

/**
 * Record Layer Implementation with Crypto Operations Abstraction
 * 
 * This class demonstrates the crypto dependency reduction by using
 * the ICryptoOperations interface instead of direct CryptoProvider
 * dependency. This provides better testability and modularity.
 */
class DTLS_API RecordLayerWithCryptoAbstraction : public IRecordLayerInterface {
public:
    /**
     * Constructor with crypto operations interface
     * 
     * @param crypto_ops Crypto operations implementation
     */
    explicit RecordLayerWithCryptoAbstraction(
        std::unique_ptr<crypto::ICryptoOperations> crypto_ops);
    
    /**
     * Constructor with crypto operations manager
     * 
     * @param crypto_manager Crypto operations manager for failover support
     */
    explicit RecordLayerWithCryptoAbstraction(
        std::unique_ptr<crypto::CryptoOperationsManager> crypto_manager);
    
    ~RecordLayerWithCryptoAbstraction() override;
    
    // Non-copyable, movable
    RecordLayerWithCryptoAbstraction(const RecordLayerWithCryptoAbstraction&) = delete;
    RecordLayerWithCryptoAbstraction& operator=(const RecordLayerWithCryptoAbstraction&) = delete;
    RecordLayerWithCryptoAbstraction(RecordLayerWithCryptoAbstraction&&) noexcept;
    RecordLayerWithCryptoAbstraction& operator=(RecordLayerWithCryptoAbstraction&&) noexcept;
    
    // === IRecordLayerInterface Implementation ===
    
    Result<void> initialize() override;
    Result<void> set_cipher_suite(CipherSuite suite) override;
    
    Result<DTLSCiphertext> protect_record(const DTLSPlaintext& plaintext) override;
    Result<DTLSPlaintext> unprotect_record(const DTLSCiphertext& ciphertext) override;
    
    Result<DTLSPlaintext> process_incoming_record(const DTLSCiphertext& ciphertext) override;
    Result<DTLSCiphertext> prepare_outgoing_record(const DTLSPlaintext& plaintext) override;
    
    Result<CiphertextRecord> protect_record_legacy(const PlaintextRecord& plaintext) override;
    Result<PlaintextRecord> unprotect_record_legacy(const CiphertextRecord& ciphertext) override;
    
    Result<void> advance_epoch(const std::vector<uint8_t>& read_key,
                              const std::vector<uint8_t>& write_key,
                              const std::vector<uint8_t>& read_iv,
                              const std::vector<uint8_t>& write_iv) override;
    
    Result<void> update_traffic_keys() override;
    Result<void> update_traffic_keys(const crypto::KeySchedule& new_keys) override;
    
    bool needs_key_update(uint64_t max_records = (1ULL << 24), 
                         std::chrono::seconds max_time = std::chrono::hours(24)) const override;
    
    Result<void> enable_connection_id(const ConnectionID& local_cid, 
                                     const ConnectionID& peer_cid) override;
    
    RecordLayerStats get_stats() const override;
    KeyUpdateStats get_key_update_stats() const override;
    
    // === Additional Methods for Crypto Abstraction ===
    
    /**
     * Get current crypto operations interface
     * 
     * @return Pointer to current crypto operations (for testing/debugging)
     */
    crypto::ICryptoOperations* crypto_operations() const;
    
    /**
     * Switch to different crypto operations implementation
     * 
     * @param new_crypto_ops New crypto operations implementation
     * @return Success or error result
     */
    Result<void> switch_crypto_operations(
        std::unique_ptr<crypto::ICryptoOperations> new_crypto_ops);
    
    /**
     * Get crypto provider capabilities
     * 
     * @return Current crypto provider capabilities
     */
    crypto::ProviderCapabilities crypto_capabilities() const;
    
    /**
     * Check if crypto operation is supported
     * 
     * @param cipher_suite Cipher suite to check
     * @return true if supported
     */
    bool supports_cipher_suite(CipherSuite cipher_suite) const;

private:
    // Internal state management
    void reset_internal_state();
    Result<void> initialize_crypto_state();
    Result<void> validate_current_configuration() const;
    
    // Record protection helpers using crypto operations abstraction
    Result<std::vector<uint8_t>> encrypt_record_content(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& additional_data);
    
    Result<std::vector<uint8_t>> decrypt_record_content(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& additional_data);
    
    Result<std::vector<uint8_t>> compute_record_aad(
        const DTLSPlaintext& plaintext) const;
    
    Result<std::vector<uint8_t>> compute_record_aad(
        const DTLSCiphertext& ciphertext) const;
    
    // Sequence number management using crypto operations
    Result<void> encrypt_and_assign_sequence_number(DTLSCiphertext& ciphertext);
    Result<uint64_t> decrypt_sequence_number(const DTLSCiphertext& ciphertext);
    
    // Key management using crypto operations
    Result<void> derive_current_keys_from_schedule(const crypto::KeySchedule& schedule);
    Result<crypto::KeySchedule> update_keys_with_hkdf();
    
    // Anti-replay window management
    bool is_sequence_number_valid(uint64_t sequence_number) const;
    void update_replay_window(uint64_t sequence_number);
    
    // Statistics and monitoring
    void update_protection_stats(bool success, bool is_encryption);
    void update_key_update_stats();
    
    // Member variables
    std::unique_ptr<crypto::ICryptoOperations> crypto_ops_;
    std::unique_ptr<crypto::CryptoOperationsManager> crypto_manager_;
    
    // Current cryptographic state
    CipherSuite current_cipher_suite_{CipherSuite::TLS_AES_128_GCM_SHA256};
    crypto::CipherSpec current_cipher_spec_;
    crypto::KeySchedule current_keys_;
    
    // Epoch and sequence number tracking
    Epoch current_read_epoch_{0};
    Epoch current_write_epoch_{0};
    SequenceNumber next_sequence_number_{0};
    
    // Anti-replay window (RFC 4347 Section 4.1.2.6)
    static constexpr size_t REPLAY_WINDOW_SIZE = 64;
    uint64_t replay_window_base_{0};
    uint64_t replay_window_mask_{0};
    
    // Connection ID support
    bool connection_id_enabled_{false};
    ConnectionID local_connection_id_;
    ConnectionID peer_connection_id_;
    
    // Statistics
    RecordLayerStats stats_;
    KeyUpdateStats key_update_stats_;
    
    // Internal state
    bool initialized_{false};
    std::chrono::steady_clock::time_point creation_time_;
    std::chrono::steady_clock::time_point last_key_update_time_;
    
    mutable std::mutex state_mutex_;
};

/**
 * Factory for creating record layers with crypto abstraction
 */
class DTLS_API RecordLayerCryptoAbstractionFactory : public IRecordLayerFactory {
public:
    /**
     * Create record layer with specific crypto operations
     * 
     * @param crypto_ops Crypto operations implementation to use
     * @return Record layer instance or error
     */
    Result<std::unique_ptr<IRecordLayerInterface>> 
        create_record_layer_with_crypto_ops(
            std::unique_ptr<crypto::ICryptoOperations> crypto_ops);
    
    /**
     * Create record layer with crypto operations manager
     * 
     * @param criteria Provider selection criteria
     * @return Record layer instance or error
     */
    Result<std::unique_ptr<IRecordLayerInterface>>
        create_record_layer_with_manager(
            const crypto::ProviderSelection& criteria = {});
    
    // IRecordLayerFactory implementation
    Result<std::unique_ptr<IRecordLayerInterface>> 
        create_record_layer(std::unique_ptr<crypto::CryptoProvider> crypto_provider) override;
    
    std::unique_ptr<IRecordLayerInterface> create_mock_record_layer() override;
    
    // Static factory methods
    static RecordLayerCryptoAbstractionFactory& instance();
    
private:
    RecordLayerCryptoAbstractionFactory() = default;
    ~RecordLayerCryptoAbstractionFactory() = default;
    RecordLayerCryptoAbstractionFactory(const RecordLayerCryptoAbstractionFactory&) = delete;
    RecordLayerCryptoAbstractionFactory& operator=(const RecordLayerCryptoAbstractionFactory&) = delete;
};

/**
 * Mock Record Layer for testing with crypto operations abstraction
 * 
 * This class provides a mock record layer that uses mock crypto operations
 * for unit testing without requiring actual cryptographic computations.
 */
class DTLS_API MockRecordLayerWithCryptoAbstraction : public IRecordLayerInterface {
public:
    MockRecordLayerWithCryptoAbstraction();
    ~MockRecordLayerWithCryptoAbstraction() override = default;
    
    // Configuration methods for testing
    void set_protection_result(bool success);
    void set_unprotection_result(bool success);
    void set_key_update_result(bool success);
    void configure_supported_cipher_suite(CipherSuite suite, bool supported = true);
    
    // Call tracking for test verification
    size_t protect_call_count() const { return protect_call_count_; }
    size_t unprotect_call_count() const { return unprotect_call_count_; }
    size_t key_update_call_count() const { return key_update_call_count_; }
    size_t advance_epoch_call_count() const { return advance_epoch_call_count_; }
    
    void reset_call_counts();
    
    // Access to mock crypto operations for test configuration
    crypto::MockCryptoOperations* mock_crypto_operations() const;
    
    // IRecordLayerInterface implementation (returns mocked results)
    Result<void> initialize() override;
    Result<void> set_cipher_suite(CipherSuite suite) override;
    
    Result<DTLSCiphertext> protect_record(const DTLSPlaintext& plaintext) override;
    Result<DTLSPlaintext> unprotect_record(const DTLSCiphertext& ciphertext) override;
    
    Result<DTLSPlaintext> process_incoming_record(const DTLSCiphertext& ciphertext) override;
    Result<DTLSCiphertext> prepare_outgoing_record(const DTLSPlaintext& plaintext) override;
    
    Result<CiphertextRecord> protect_record_legacy(const PlaintextRecord& plaintext) override;
    Result<PlaintextRecord> unprotect_record_legacy(const CiphertextRecord& ciphertext) override;
    
    Result<void> advance_epoch(const std::vector<uint8_t>& read_key,
                              const std::vector<uint8_t>& write_key,
                              const std::vector<uint8_t>& read_iv,
                              const std::vector<uint8_t>& write_iv) override;
    
    Result<void> update_traffic_keys() override;
    Result<void> update_traffic_keys(const crypto::KeySchedule& new_keys) override;
    
    bool needs_key_update(uint64_t max_records = (1ULL << 24), 
                         std::chrono::seconds max_time = std::chrono::hours(24)) const override;
    
    Result<void> enable_connection_id(const ConnectionID& local_cid, 
                                     const ConnectionID& peer_cid) override;
    
    RecordLayerStats get_stats() const override;
    KeyUpdateStats get_key_update_stats() const override;

private:
    // Mock crypto operations instance
    std::unique_ptr<crypto::MockCryptoOperations> mock_crypto_;
    
    // Mock configuration
    bool protection_result_{true};
    bool unprotection_result_{true};
    bool key_update_result_{true};
    std::set<CipherSuite> supported_cipher_suites_;
    
    // Call counters
    mutable size_t protect_call_count_{0};
    mutable size_t unprotect_call_count_{0};
    mutable size_t key_update_call_count_{0};
    mutable size_t advance_epoch_call_count_{0};
    
    // Mock state
    RecordLayerStats mock_stats_;
    KeyUpdateStats mock_key_update_stats_;
    bool initialized_{false};
    CipherSuite current_cipher_suite_{CipherSuite::TLS_AES_128_GCM_SHA256};
};

// === Utility Functions ===

/**
 * Create record layer with default crypto operations
 * 
 * @param provider_name Crypto provider to use (empty for default)
 * @return Record layer instance or error
 */
DTLS_API Result<std::unique_ptr<IRecordLayerInterface>>
    create_record_layer_with_crypto_abstraction(const std::string& provider_name = "");

/**
 * Create record layer with crypto operations selection criteria
 * 
 * @param criteria Provider selection criteria
 * @return Record layer instance or error
 */
DTLS_API Result<std::unique_ptr<IRecordLayerInterface>>
    create_record_layer_with_crypto_selection(const crypto::ProviderSelection& criteria);

/**
 * Create mock record layer with crypto abstraction for testing
 * 
 * @return Mock record layer instance
 */
DTLS_API std::unique_ptr<IRecordLayerInterface>
    create_mock_record_layer_with_crypto_abstraction();

} // namespace protocol
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_RECORD_LAYER_CRYPTO_ABSTRACTION_H