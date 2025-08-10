#include <dtls/protocol/record_layer_factory.h>
#include <dtls/error.h>
#include <chrono>
#include <cstring>

namespace dtls::v13::protocol {

// Static member initialization
std::unique_ptr<RecordLayerFactory> RecordLayerFactory::instance_;
std::mutex RecordLayerFactory::instance_mutex_;

// ============================================================================
// RecordLayerFactory Implementation
// ============================================================================

Result<std::unique_ptr<IRecordLayerInterface>> 
RecordLayerFactory::create_record_layer(std::unique_ptr<crypto::CryptoProvider> crypto_provider) {
    if (!crypto_provider) {
        return make_error<std::unique_ptr<IRecordLayerInterface>>(
            DTLSError::INVALID_PARAMETER, "Crypto provider cannot be null");
    }
    
    try {
        auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider));
        return make_result<std::unique_ptr<IRecordLayerInterface>>(std::move(record_layer));
    } catch (const std::exception& e) {
        return make_error<std::unique_ptr<IRecordLayerInterface>>(
            DTLSError::OUT_OF_MEMORY, e.what());
    }
}

std::unique_ptr<IRecordLayerInterface> RecordLayerFactory::create_mock_record_layer() {
    try {
        return std::make_unique<MockRecordLayer>();
    } catch (const std::exception&) {
        // Return nullptr if allocation fails
        return nullptr;
    }
}

RecordLayerFactory& RecordLayerFactory::instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = std::make_unique<RecordLayerFactory>();
    }
    return *instance_;
}

// ============================================================================
// MockRecordLayer Implementation
// ============================================================================

MockRecordLayer::MockRecordLayer() {
    key_update_stats_.last_update_time = std::chrono::steady_clock::now();
}

Result<void> MockRecordLayer::initialize() {
    increment_call_count("initialize");
    
    if (should_fail_) {
        return make_error<void>(DTLSError::INITIALIZATION_FAILED, "Mock initialization failure");
    }
    
    initialized_ = true;
    return Result<void>();
}

Result<void> MockRecordLayer::set_cipher_suite(CipherSuite suite) {
    increment_call_count("set_cipher_suite");
    
    if (should_fail_) {
        return make_error<void>(DTLSError::CIPHER_SUITE_NOT_SUPPORTED, "Mock cipher suite failure");
    }
    
    current_cipher_suite_ = suite;
    return Result<void>();
}

Result<DTLSCiphertext> MockRecordLayer::protect_record(const DTLSPlaintext& plaintext) {
    increment_call_count("protect_record");
    
    if (should_fail_) {
        return make_error<DTLSCiphertext>(DTLSError::CRYPTO_PROVIDER_ERROR, "Mock encryption failure");
    }
    
    if (!initialized_) {
        return make_error<DTLSCiphertext>(DTLSError::NOT_INITIALIZED, "Record layer not initialized");
    }
    
    stats_.records_protected++;
    return make_result<DTLSCiphertext>(create_mock_ciphertext(plaintext));
}

Result<DTLSPlaintext> MockRecordLayer::unprotect_record(const DTLSCiphertext& ciphertext) {
    increment_call_count("unprotect_record");
    
    if (should_fail_ || simulate_decryption_failure_) {
        stats_.decryption_failures++;
        return make_error<DTLSPlaintext>(DTLSError::DECRYPT_ERROR, "Mock decryption failure");
    }
    
    if (!initialized_) {
        return make_error<DTLSPlaintext>(DTLSError::NOT_INITIALIZED, "Record layer not initialized");
    }
    
    stats_.records_unprotected++;
    return make_result<DTLSPlaintext>(create_mock_plaintext(ciphertext));
}

Result<DTLSPlaintext> MockRecordLayer::process_incoming_record(const DTLSCiphertext& ciphertext) {
    increment_call_count("process_incoming_record");
    
    if (simulate_replay_attack_) {
        stats_.replay_attacks_detected++;
        return make_error<DTLSPlaintext>(DTLSError::REPLAY_ATTACK_DETECTED, "Mock replay attack");
    }
    
    if (should_fail_ || simulate_decryption_failure_) {
        stats_.decryption_failures++;
        return make_error<DTLSPlaintext>(DTLSError::DECRYPT_ERROR, "Mock processing failure");
    }
    
    if (!initialized_) {
        return make_error<DTLSPlaintext>(DTLSError::NOT_INITIALIZED, "Record layer not initialized");
    }
    
    stats_.records_received++;
    stats_.records_unprotected++;
    return make_result<DTLSPlaintext>(create_mock_plaintext(ciphertext));
}

Result<DTLSCiphertext> MockRecordLayer::prepare_outgoing_record(const DTLSPlaintext& plaintext) {
    increment_call_count("prepare_outgoing_record");
    
    if (should_fail_) {
        return make_error<DTLSCiphertext>(DTLSError::CRYPTO_PROVIDER_ERROR, "Mock preparation failure");
    }
    
    if (!initialized_) {
        return make_error<DTLSCiphertext>(DTLSError::NOT_INITIALIZED, "Record layer not initialized");
    }
    
    current_sequence_number_++;
    stats_.current_sequence_number = current_sequence_number_;
    stats_.records_sent++;
    stats_.records_protected++;
    
    return make_result<DTLSCiphertext>(create_mock_ciphertext(plaintext));
}

Result<CiphertextRecord> MockRecordLayer::protect_record_legacy(const PlaintextRecord& plaintext) {
    increment_call_count("protect_record_legacy");
    
    if (should_fail_) {
        return make_error<CiphertextRecord>(DTLSError::CRYPTO_PROVIDER_ERROR, "Mock legacy protection failure");
    }
    
    // Create mock legacy ciphertext record - simplified implementation
    CiphertextRecord ciphertext;
    // Note: Legacy record types may have different field names
    // This is a simplified mock implementation
    
    return make_result<CiphertextRecord>(std::move(ciphertext));
}

Result<PlaintextRecord> MockRecordLayer::unprotect_record_legacy(const CiphertextRecord& ciphertext) {
    increment_call_count("unprotect_record_legacy");
    
    if (should_fail_ || simulate_decryption_failure_) {
        return make_error<PlaintextRecord>(DTLSError::DECRYPT_ERROR, "Mock legacy unprotection failure");
    }
    
    // Create mock legacy plaintext record - simplified implementation
    PlaintextRecord plaintext;
    // Note: Legacy record types may have different field names
    // This is a simplified mock implementation
    
    return make_result<PlaintextRecord>(std::move(plaintext));
}

Result<void> MockRecordLayer::advance_epoch(const std::vector<uint8_t>& read_key,
                                           const std::vector<uint8_t>& write_key,
                                           const std::vector<uint8_t>& read_iv,
                                           const std::vector<uint8_t>& write_iv) {
    increment_call_count("advance_epoch");
    
    if (should_fail_) {
        return make_error<void>(DTLSError::KEY_DERIVATION_FAILED, "Mock epoch advance failure");
    }
    
    current_epoch_++;
    current_sequence_number_ = 0;
    stats_.current_epoch = current_epoch_;
    stats_.current_sequence_number = current_sequence_number_;
    
    return Result<void>();
}

Result<void> MockRecordLayer::update_traffic_keys() {
    increment_call_count("update_traffic_keys");
    
    if (should_fail_) {
        return make_error<void>(DTLSError::KEY_DERIVATION_FAILED, "Mock key update failure");
    }
    
    key_update_stats_.updates_performed++;
    key_update_stats_.records_since_last_update = 0;
    key_update_stats_.last_update_time = std::chrono::steady_clock::now();
    
    return Result<void>();
}

Result<void> MockRecordLayer::update_traffic_keys(const crypto::KeySchedule& new_keys) {
    increment_call_count("update_traffic_keys_with_schedule");
    
    if (should_fail_) {
        return make_error<void>(DTLSError::KEY_DERIVATION_FAILED, "Mock key update with schedule failure");
    }
    
    key_update_stats_.updates_performed++;
    key_update_stats_.records_since_last_update = 0;
    key_update_stats_.last_update_time = std::chrono::steady_clock::now();
    
    return Result<void>();
}

bool MockRecordLayer::needs_key_update(uint64_t max_records, 
                                       std::chrono::seconds max_time) const {
    increment_call_count("needs_key_update");
    
    // Simple mock logic: need update if too many records or too much time
    if (key_update_stats_.records_since_last_update >= max_records) {
        return true;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto time_since_update = std::chrono::duration_cast<std::chrono::seconds>(
        now - key_update_stats_.last_update_time
    );
    
    return time_since_update >= max_time;
}

Result<void> MockRecordLayer::enable_connection_id(const ConnectionID& local_cid, 
                                                   const ConnectionID& peer_cid) {
    increment_call_count("enable_connection_id");
    
    if (should_fail_) {
        return make_error<void>(DTLSError::INVALID_PARAMETER, "Mock connection ID failure");
    }
    
    return Result<void>();
}

RecordLayerStats MockRecordLayer::get_stats() const {
    increment_call_count("get_stats");
    return stats_;
}

KeyUpdateStats MockRecordLayer::get_key_update_stats() const {
    increment_call_count("get_key_update_stats");
    return key_update_stats_;
}

// Mock control methods

void MockRecordLayer::reset_mock_state() {
    std::lock_guard<std::mutex> lock(mock_mutex_);
    initialized_ = false;
    current_epoch_ = 0;
    current_sequence_number_ = 0;
    should_fail_ = false;
    simulate_replay_attack_ = false;
    simulate_decryption_failure_ = false;
    
    stats_ = RecordLayerStats{};
    key_update_stats_ = KeyUpdateStats{};
    key_update_stats_.last_update_time = std::chrono::steady_clock::now();
    
    method_call_counts_.clear();
}

size_t MockRecordLayer::get_call_count(const std::string& method) const {
    std::lock_guard<std::mutex> lock(mock_mutex_);
    auto it = method_call_counts_.find(method);
    return it != method_call_counts_.end() ? it->second : 0;
}

void MockRecordLayer::clear_call_counts() {
    std::lock_guard<std::mutex> lock(mock_mutex_);
    method_call_counts_.clear();
}

// Private helper methods

void MockRecordLayer::increment_call_count(const std::string& method) const {
    std::lock_guard<std::mutex> lock(mock_mutex_);
    method_call_counts_[method]++;
}

DTLSCiphertext MockRecordLayer::create_mock_ciphertext(const DTLSPlaintext& plaintext) {
    DTLSCiphertext ciphertext;
    ciphertext.type = ContentType::APPLICATION_DATA; // Hide actual content type
    ciphertext.version = ProtocolVersion::DTLS_1_2;
    ciphertext.epoch = current_epoch_;
    ciphertext.encrypted_sequence_number = SequenceNumber48(current_sequence_number_);
    ciphertext.length = plaintext.fragment.size() + 16; // Add mock auth tag
    
    // Mock encrypted content - create a new buffer with plaintext + mock tag
    memory::ZeroCopyBuffer encrypted_buffer(plaintext.fragment.size() + 16);
    if (plaintext.fragment.size() > 0) {
        std::memcpy(encrypted_buffer.mutable_data(), plaintext.fragment.data(), plaintext.fragment.size());
    }
    // Add mock auth tag (16 bytes of 0xAA)
    std::memset(encrypted_buffer.mutable_data() + plaintext.fragment.size(), 0xAA, 16);
    encrypted_buffer.resize(plaintext.fragment.size() + 16);
    
    ciphertext.encrypted_record = memory::Buffer(std::move(encrypted_buffer));
    
    return ciphertext;
}

DTLSPlaintext MockRecordLayer::create_mock_plaintext(const DTLSCiphertext& ciphertext) {
    DTLSPlaintext plaintext;
    plaintext.type = ContentType::HANDSHAKE; // Mock content type
    plaintext.version = ProtocolVersion::DTLS_1_3;
    plaintext.epoch = ciphertext.epoch;
    plaintext.sequence_number = ciphertext.encrypted_sequence_number;
    plaintext.length = ciphertext.length > 16 ? ciphertext.length - 16 : 0;
    
    // Mock decrypted content - remove last 16 bytes (mock auth tag)
    if (ciphertext.encrypted_record.size() > 16) {
        size_t plaintext_size = ciphertext.encrypted_record.size() - 16;
        memory::ZeroCopyBuffer plaintext_buffer(plaintext_size);
        std::memcpy(plaintext_buffer.mutable_data(), ciphertext.encrypted_record.data(), plaintext_size);
        plaintext_buffer.resize(plaintext_size);
        plaintext.fragment = memory::Buffer(std::move(plaintext_buffer));
    }
    
    return plaintext;
}

} // namespace dtls::v13::protocol