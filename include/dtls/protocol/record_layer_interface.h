#ifndef DTLS_PROTOCOL_RECORD_LAYER_INTERFACE_H
#define DTLS_PROTOCOL_RECORD_LAYER_INTERFACE_H

#include <dtls/config.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <dtls/protocol/record.h>
#include <dtls/protocol/dtls_records.h>
#include <dtls/crypto.h>
#include <memory>
#include <vector>
#include <chrono>

namespace dtls {
namespace v13 {

// Forward declarations
namespace crypto {
    class KeySchedule;
}

namespace protocol {

/**
 * Record Layer Statistics Structure
 * 
 * Contains comprehensive statistics for record layer operations,
 * including performance metrics and security indicators.
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

/**
 * Key Update Statistics Structure
 * 
 * Tracks key update operations and timing for security monitoring.
 */
struct KeyUpdateStats {
    uint64_t updates_performed{0};
    uint64_t records_since_last_update{0};
    std::chrono::steady_clock::time_point last_update_time;
    uint64_t peer_updates_received{0};
    uint64_t peer_updates_requested{0};
};

/**
 * Abstract Record Layer Interface
 * 
 * Defines the contract for DTLS v1.3 record layer operations.
 * This interface provides complete decoupling between the connection layer
 * and record processing, enabling modular design and improved testability.
 * 
 * All methods maintain RFC 9147 compliance and provide thread-safe operations.
 */
class DTLS_API IRecordLayerInterface {
public:
    virtual ~IRecordLayerInterface() = default;
    
    // Core Initialization and Configuration
    
    /**
     * Initialize the record layer
     * 
     * Prepares the record layer for operation, including crypto provider
     * initialization and internal state setup.
     * 
     * @return Success result or error details
     */
    virtual Result<void> initialize() = 0;
    
    /**
     * Set cipher suite for current epoch
     * 
     * Configures the cryptographic algorithms used for record protection.
     * Must be called before processing any protected records.
     * 
     * @param suite The cipher suite to use (RFC 9147 compliant)
     * @return Success result or error details
     */
    virtual Result<void> set_cipher_suite(CipherSuite suite) = 0;
    
    // Core Record Processing Operations
    
    /**
     * Protect a plaintext record (encrypt)
     * 
     * Encrypts and authenticates a plaintext record according to RFC 9147
     * specifications. Handles sequence number assignment and AEAD encryption.
     * 
     * @param plaintext The plaintext record to protect
     * @return Protected ciphertext record or error details
     */
    virtual Result<DTLSCiphertext> protect_record(const DTLSPlaintext& plaintext) = 0;
    
    /**
     * Unprotect a ciphertext record (decrypt)
     * 
     * Decrypts and verifies a ciphertext record according to RFC 9147
     * specifications. Performs AEAD decryption and authenticity verification.
     * 
     * @param ciphertext The ciphertext record to unprotect
     * @return Plaintext record or error details
     */
    virtual Result<DTLSPlaintext> unprotect_record(const DTLSCiphertext& ciphertext) = 0;
    
    /**
     * Process incoming record (includes anti-replay check)
     * 
     * Complete processing pipeline for incoming records including:
     * - Anti-replay window validation
     * - Sequence number verification  
     * - Record decryption and verification
     * - Statistics updates
     * 
     * @param ciphertext The incoming ciphertext record
     * @return Processed plaintext record or error details
     */
    virtual Result<DTLSPlaintext> process_incoming_record(const DTLSCiphertext& ciphertext) = 0;
    
    /**
     * Prepare outgoing record (includes sequence number assignment)
     * 
     * Complete processing pipeline for outgoing records including:
     * - Sequence number assignment
     * - Record encryption and authentication
     * - Statistics updates
     * 
     * @param plaintext The plaintext record to prepare
     * @return Prepared ciphertext record or error details
     */
    virtual Result<DTLSCiphertext> prepare_outgoing_record(const DTLSPlaintext& plaintext) = 0;
    
    // Legacy Support (for backward compatibility)
    
    /**
     * Protect record using legacy format
     * 
     * @param plaintext Legacy plaintext record
     * @return Legacy ciphertext record or error details
     */
    virtual Result<CiphertextRecord> protect_record_legacy(const PlaintextRecord& plaintext) = 0;
    
    /**
     * Unprotect record using legacy format
     * 
     * @param ciphertext Legacy ciphertext record
     * @return Legacy plaintext record or error details
     */
    virtual Result<PlaintextRecord> unprotect_record_legacy(const CiphertextRecord& ciphertext) = 0;
    
    // Epoch and Key Management
    
    /**
     * Advance to next epoch with new keys
     * 
     * Transitions to a new cryptographic epoch with updated keying material.
     * Resets sequence numbers and anti-replay windows as required by RFC 9147.
     * 
     * @param read_key New key for reading/decryption
     * @param write_key New key for writing/encryption  
     * @param read_iv New IV for reading operations
     * @param write_iv New IV for writing operations
     * @return Success result or error details
     */
    virtual Result<void> advance_epoch(const std::vector<uint8_t>& read_key,
                                      const std::vector<uint8_t>& write_key,
                                      const std::vector<uint8_t>& read_iv,
                                      const std::vector<uint8_t>& write_iv) = 0;
    
    /**
     * Update traffic keys (RFC 9147 Section 4.6.3)
     * 
     * Generates new read/write keys from current keys using HKDF-Expand-Label
     * to provide forward secrecy without full handshake.
     * 
     * @return Success result or error details
     */
    virtual Result<void> update_traffic_keys() = 0;
    
    /**
     * Update traffic keys with provided key schedule
     * 
     * Used for coordinated key updates across multiple layers with
     * externally derived keying material.
     * 
     * @param new_keys The new key schedule to use
     * @return Success result or error details
     */
    virtual Result<void> update_traffic_keys(const crypto::KeySchedule& new_keys) = 0;
    
    /**
     * Check if key update is needed
     * 
     * Evaluates whether a key update should be performed based on
     * record count, time elapsed, or other security criteria.
     * 
     * @param max_records Maximum records before requiring key update
     * @param max_time Maximum time before requiring key update
     * @return true if key update is recommended
     */
    virtual bool needs_key_update(uint64_t max_records = (1ULL << 24), 
                                 std::chrono::seconds max_time = std::chrono::hours(24)) const = 0;
    
    // Connection ID Support (RFC 9146)
    
    /**
     * Enable connection ID support
     * 
     * Configures the record layer to use Connection IDs for NAT traversal
     * and connection migration as specified in RFC 9146.
     * 
     * @param local_cid Local connection identifier
     * @param peer_cid Peer connection identifier  
     * @return Success result or error details
     */
    virtual Result<void> enable_connection_id(const ConnectionID& local_cid, 
                                             const ConnectionID& peer_cid) = 0;
    
    // Statistics and Monitoring
    
    /**
     * Get current record layer statistics
     * 
     * Returns comprehensive statistics for monitoring record layer
     * performance, security events, and operational status.
     * 
     * @return Current statistics snapshot
     */
    virtual RecordLayerStats get_stats() const = 0;
    
    /**
     * Get current key update statistics
     * 
     * Returns statistics specific to key update operations for
     * security monitoring and compliance verification.
     * 
     * @return Current key update statistics
     */
    virtual KeyUpdateStats get_key_update_stats() const = 0;
};

/**
 * Record Layer Factory Interface
 * 
 * Provides factory methods for creating record layer implementations
 * with proper dependency injection and configuration.
 */
class DTLS_API IRecordLayerFactory {
public:
    virtual ~IRecordLayerFactory() = default;
    
    /**
     * Create a record layer implementation
     * 
     * @param crypto_provider The crypto provider to use
     * @return Record layer implementation or error details
     */
    virtual Result<std::unique_ptr<IRecordLayerInterface>> 
        create_record_layer(std::unique_ptr<crypto::CryptoProvider> crypto_provider) = 0;
    
    /**
     * Create a mock record layer for testing
     * 
     * @return Mock record layer implementation
     */
    virtual std::unique_ptr<IRecordLayerInterface> create_mock_record_layer() = 0;
};

} // namespace protocol
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_RECORD_LAYER_INTERFACE_H