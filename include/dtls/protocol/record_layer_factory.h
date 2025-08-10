#ifndef DTLS_PROTOCOL_RECORD_LAYER_FACTORY_H
#define DTLS_PROTOCOL_RECORD_LAYER_FACTORY_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/protocol/record_layer_interface.h>
#include <dtls/protocol/record_layer.h>
#include <dtls/crypto.h>
#include <memory>

namespace dtls {
namespace v13 {
namespace protocol {

/**
 * Standard Record Layer Factory Implementation
 * 
 * Creates record layer instances with proper dependency injection
 * and configuration management. Supports both production implementations
 * and mock implementations for testing.
 */
class DTLS_API RecordLayerFactory : public IRecordLayerFactory {
public:
    RecordLayerFactory() = default;
    ~RecordLayerFactory() override = default;
    
    // Non-copyable, movable
    RecordLayerFactory(const RecordLayerFactory&) = delete;
    RecordLayerFactory& operator=(const RecordLayerFactory&) = delete;
    RecordLayerFactory(RecordLayerFactory&&) noexcept = default;
    RecordLayerFactory& operator=(RecordLayerFactory&&) noexcept = default;
    
    /**
     * Create a production record layer implementation
     * 
     * Creates a fully functional RecordLayer instance with the provided
     * crypto provider. The crypto provider is moved into the record layer.
     * 
     * @param crypto_provider The crypto provider to use for operations
     * @return Record layer implementation or error details
     */
    Result<std::unique_ptr<IRecordLayerInterface>> 
        create_record_layer(std::unique_ptr<crypto::CryptoProvider> crypto_provider) override;
    
    /**
     * Create a mock record layer for testing
     * 
     * Creates a mock implementation suitable for unit testing connection
     * layer logic without actual crypto operations.
     * 
     * @return Mock record layer implementation
     */
    std::unique_ptr<IRecordLayerInterface> create_mock_record_layer() override;
    
    /**
     * Get singleton factory instance
     * 
     * @return Reference to singleton factory
     */
    static RecordLayerFactory& instance();
    
private:
    static std::unique_ptr<RecordLayerFactory> instance_;
    static std::mutex instance_mutex_;
};

/**
 * Mock Record Layer Implementation for Testing
 * 
 * Provides a lightweight mock implementation of IRecordLayerInterface
 * for use in unit tests. Does not perform actual crypto operations.
 */
class DTLS_API MockRecordLayer : public IRecordLayerInterface {
public:
    MockRecordLayer();
    ~MockRecordLayer() override = default;
    
    // Non-copyable, movable
    MockRecordLayer(const MockRecordLayer&) = delete;
    MockRecordLayer& operator=(const MockRecordLayer&) = delete;
    MockRecordLayer(MockRecordLayer&&) noexcept = default;
    MockRecordLayer& operator=(MockRecordLayer&&) noexcept = default;
    
    // Mock implementations of interface methods
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
    
    // Mock control methods for testing
    void set_should_fail(bool fail) { should_fail_ = fail; }
    void set_simulate_replay_attack(bool replay) { simulate_replay_attack_ = replay; }
    void set_simulate_decryption_failure(bool fail) { simulate_decryption_failure_ = fail; }
    void reset_mock_state();
    
    // Access to internal state for test verification
    size_t get_call_count(const std::string& method) const;
    void clear_call_counts();

private:
    bool initialized_{false};
    CipherSuite current_cipher_suite_{CipherSuite::TLS_AES_128_GCM_SHA256};
    uint16_t current_epoch_{0};
    uint64_t current_sequence_number_{0};
    
    // Mock control flags
    bool should_fail_{false};
    bool simulate_replay_attack_{false};
    bool simulate_decryption_failure_{false};
    
    // Statistics tracking
    mutable RecordLayerStats stats_;
    mutable KeyUpdateStats key_update_stats_;
    
    // Method call tracking for test verification
    mutable std::unordered_map<std::string, size_t> method_call_counts_;
    mutable std::mutex mock_mutex_;
    
    void increment_call_count(const std::string& method) const;
    
    // Helper methods for mock record generation
    DTLSCiphertext create_mock_ciphertext(const DTLSPlaintext& plaintext);
    DTLSPlaintext create_mock_plaintext(const DTLSCiphertext& ciphertext);
};

} // namespace protocol
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_RECORD_LAYER_FACTORY_H