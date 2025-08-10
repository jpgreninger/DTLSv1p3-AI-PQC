#include "dtls/protocol/record_layer.h"
#include "dtls/protocol/dtls_records.h"
#include "dtls/crypto/crypto_utils.h"
#include "dtls/error.h"
#include "dtls/crypto/provider_factory.h"
#include <algorithm>
#include <cstring>
#include <random>

#ifdef _WIN32
    #include <winsock2.h>
    #define htobe64(x) _byteswap_uint64(x)
    #define be64toh(x) _byteswap_uint64(x)
#else
    #include <arpa/inet.h>
    #if defined(__APPLE__)
        #include <libkern/OSByteOrder.h>
        #define htobe64(x) OSSwapHostToBigInt64(x)
        #define be64toh(x) OSSwapBigToHostInt64(x)
    #elif defined(__linux__)
        #include <endian.h>
    #else
        // Fallback implementation
        #define htobe64(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
        #define be64toh(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
    #endif
#endif

namespace dtls::v13::protocol {

// ============================================================================
// AntiReplayWindow Implementation
// ============================================================================

AntiReplayWindow::AntiReplayWindow(size_t window_size)
    : window_size_(window_size), window_(window_size, false) {
    if (window_size == 0) {
        window_size_ = DEFAULT_WINDOW_SIZE;
        window_.resize(DEFAULT_WINDOW_SIZE, false);
    }
}

bool AntiReplayWindow::is_valid_sequence_number(uint64_t sequence_number) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // First packet is always valid
    if (highest_sequence_number_ == 0) {
        return true;
    }
    
    // Packet too old (outside window)
    if (sequence_number <= highest_sequence_number_ && 
        (highest_sequence_number_ - sequence_number) >= window_size_) {
        return false;
    }
    
    // Future packet (always valid, will slide window)
    if (sequence_number > highest_sequence_number_) {
        return true;
    }
    
    // Within current window - check if already received
    size_t window_index = static_cast<size_t>(highest_sequence_number_ - sequence_number);
    return !window_[window_index];
}

void AntiReplayWindow::mark_received(uint64_t sequence_number) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // First packet
    if (highest_sequence_number_ == 0) {
        highest_sequence_number_ = sequence_number;
        window_[0] = true;
        received_count_++;
        return;
    }
    
    // Future packet - slide window
    if (sequence_number > highest_sequence_number_) {
        slide_window(sequence_number);
        window_[0] = true;
        received_count_++;
        return;
    }
    
    // Within current window
    if (sequence_number <= highest_sequence_number_ && 
        (highest_sequence_number_ - sequence_number) < window_size_) {
        size_t window_index = static_cast<size_t>(highest_sequence_number_ - sequence_number);
        if (!window_[window_index]) {
            window_[window_index] = true;
            received_count_++;
        } else {
            // Duplicate packet
            replay_count_++;
        }
    }
}

void AntiReplayWindow::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    highest_sequence_number_ = 0;
    std::fill(window_.begin(), window_.end(), false);
    received_count_ = 0;
    replay_count_ = 0;
}

AntiReplayWindow::WindowStats AntiReplayWindow::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    WindowStats stats;
    stats.highest_sequence_number = highest_sequence_number_;
    stats.lowest_sequence_number = (highest_sequence_number_ >= window_size_) ? 
        (highest_sequence_number_ - window_size_ + 1) : 0;
    stats.window_size = window_size_;
    stats.received_count = received_count_;
    stats.replay_count = replay_count_;
    return stats;
}

void AntiReplayWindow::slide_window(uint64_t new_highest) {
    uint64_t slide_amount = new_highest - highest_sequence_number_;
    
    if (slide_amount >= window_size_) {
        // Complete window shift
        std::fill(window_.begin(), window_.end(), false);
    } else {
        // Partial window shift
        std::rotate(window_.rbegin(), window_.rbegin() + slide_amount, window_.rend());
        std::fill(window_.begin(), window_.begin() + slide_amount, false);
    }
    
    highest_sequence_number_ = new_highest;
}

// ============================================================================
// SequenceNumberManager Implementation
// ============================================================================

uint64_t SequenceNumberManager::get_next_sequence_number() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (current_sequence_number_ >= MAX_SEQUENCE_NUMBER) {
        // Sequence number overflow - should trigger key update
        return MAX_SEQUENCE_NUMBER;
    }
    
    return ++current_sequence_number_;
}

uint64_t SequenceNumberManager::get_current_sequence_number() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_sequence_number_;
}

void SequenceNumberManager::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    current_sequence_number_ = 0;
}

bool SequenceNumberManager::would_overflow() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_sequence_number_ >= MAX_SEQUENCE_NUMBER;
}

// ============================================================================
// EpochManager Implementation
// ============================================================================

uint16_t EpochManager::get_current_epoch() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_epoch_;
}

Result<uint16_t> EpochManager::advance_epoch() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (current_epoch_ >= MAX_EPOCH) {
        return Result<uint16_t>(DTLSError::EPOCH_OVERFLOW);
    }
    
    return Result<uint16_t>(++current_epoch_);
}

bool EpochManager::is_valid_epoch(uint16_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Current epoch is always valid
    if (epoch == current_epoch_) {
        return true;
    }
    
    // Previous epoch may be valid during transition
    if (epoch == current_epoch_ - 1 && current_epoch_ > 0) {
        return epoch_keys_.find(epoch) != epoch_keys_.end();
    }
    
    return false;
}

Result<void> EpochManager::set_epoch_keys(uint16_t epoch, 
                                        const std::vector<uint8_t>& read_key,
                                        const std::vector<uint8_t>& write_key,
                                        const std::vector<uint8_t>& read_iv,
                                        const std::vector<uint8_t>& write_iv) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Epoch 0 uses null protection (empty keys are valid)
    // For other epochs, keys must be non-empty
    if (epoch != 0 && (read_key.empty() || write_key.empty() || read_iv.empty() || write_iv.empty())) {
        return Result<void>(DTLSError::INVALID_KEY_MATERIAL);
    }
    
    EpochCryptoParams params;
    params.read_key = read_key;
    params.write_key = write_key;
    params.read_iv = read_iv;
    params.write_iv = write_iv;
    params.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256; // Default
    
    epoch_keys_[epoch] = std::move(params);
    return Result<void>();
}

Result<EpochManager::EpochCryptoParams> EpochManager::get_epoch_crypto_params(uint16_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = epoch_keys_.find(epoch);
    if (it == epoch_keys_.end()) {
        return Result<EpochCryptoParams>(DTLSError::EPOCH_NOT_FOUND);
    }
    
    return Result<EpochCryptoParams>(it->second);
}

// ============================================================================
// ConnectionIDManager Implementation
// ============================================================================

void ConnectionIDManager::set_local_connection_id(const ConnectionID& cid) {
    std::lock_guard<std::mutex> lock(mutex_);
    local_connection_id_ = cid;
    connection_id_enabled_ = !cid.empty();
}

void ConnectionIDManager::set_peer_connection_id(const ConnectionID& cid) {
    std::lock_guard<std::mutex> lock(mutex_);
    peer_connection_id_ = cid;
    connection_id_enabled_ = connection_id_enabled_ || !cid.empty();
}

const ConnectionID& ConnectionIDManager::get_local_connection_id() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return local_connection_id_;
}

const ConnectionID& ConnectionIDManager::get_peer_connection_id() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peer_connection_id_;
}

bool ConnectionIDManager::is_connection_id_enabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connection_id_enabled_;
}

bool ConnectionIDManager::is_valid_connection_id(const ConnectionID& cid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!connection_id_enabled_) {
        return cid.empty();
    }
    
    // Check against local CID (for incoming packets)
    if (!local_connection_id_.empty() && cid == local_connection_id_) {
        return true;
    }
    
    // Empty CID is valid if not explicitly required
    return cid.empty();
}

// ============================================================================
// RecordLayer Implementation
// ============================================================================

RecordLayer::RecordLayer(std::unique_ptr<crypto::CryptoProvider> crypto_provider)
    : crypto_provider_(std::move(crypto_provider)),
      send_sequence_manager_(std::make_unique<SequenceNumberManager>()),
      epoch_manager_(std::make_unique<EpochManager>()),
      connection_id_manager_(std::make_unique<ConnectionIDManager>()),
      connection_start_time_(std::chrono::steady_clock::now()) {
    
    // Initialize key update stats
    key_update_stats_.last_update_time = connection_start_time_;
}

Result<void> RecordLayer::initialize() {
    if (!crypto_provider_) {
        return Result<void>(DTLSError::CRYPTO_PROVIDER_NOT_AVAILABLE);
    }
    
    // Initialize epoch 0 with null protection (no encryption)
    std::vector<uint8_t> null_key;
    auto result = epoch_manager_->set_epoch_keys(0, null_key, null_key, null_key, null_key);
    if (!result.is_success()) {
        return result;
    }
    
    // Create initial receive window for epoch 0
    receive_windows_[0] = std::make_unique<AntiReplayWindow>();
    
    return Result<void>();
}

Result<void> RecordLayer::set_cipher_suite(CipherSuite suite) {
    current_cipher_suite_ = suite;
    return Result<void>();
}

Result<DTLSCiphertext> RecordLayer::protect_record(const DTLSPlaintext& plaintext) {
    if (!plaintext.is_valid()) {
        return Result<DTLSCiphertext>(DTLSError::INVALID_PLAINTEXT_RECORD);
    }
    
    uint16_t current_epoch = epoch_manager_->get_current_epoch();
    
    // Get crypto parameters for current epoch
    auto crypto_params_result = epoch_manager_->get_epoch_crypto_params(current_epoch);
    if (!crypto_params_result.is_success()) {
        return Result<DTLSCiphertext>(crypto_params_result.error());
    }
    
    const auto& crypto_params = crypto_params_result.value();
    
    // Initially use unencrypted sequence number - will encrypt after AEAD operation
    SequenceNumber48 sequence_number = plaintext.get_sequence_number();
    
    // Epoch 0 uses null protection (no encryption)
    if (current_epoch == 0 || crypto_params.write_key.empty()) {
        // Create DTLSCiphertext with no encryption
        memory::Buffer encrypted_payload(plaintext.get_fragment().size());
        std::memcpy(encrypted_payload.mutable_data(), 
                   plaintext.get_fragment().data(), 
                   plaintext.get_fragment().size());
        
        DTLSCiphertext ciphertext(ContentType::APPLICATION_DATA,
                                 plaintext.get_version(),
                                 plaintext.get_epoch(),
                                 sequence_number,
                                 std::move(encrypted_payload));
        
        update_stats_protected();
        return Result<DTLSCiphertext>(std::move(ciphertext));
    }
    
    // Construct AEAD nonce with original (unencrypted) sequence number
    auto nonce_result = construct_aead_nonce(current_epoch, 
                                           plaintext.get_sequence_number(),
                                           crypto_params.write_iv);
    if (!nonce_result.is_success()) {
        return Result<DTLSCiphertext>(nonce_result.error());
    }
    
    // Construct additional authenticated data using encrypted sequence number
    ConnectionID cid = connection_id_manager_->is_connection_id_enabled() ?
        connection_id_manager_->get_peer_connection_id() : ConnectionID{};
    
    // Create temporary header with encrypted sequence number for AAD
    struct TempHeader {
        ContentType content_type;
        ProtocolVersion version;
        uint16_t epoch;
        uint64_t sequence_number;
        uint16_t length;
    } temp_header = {
        plaintext.get_type(),
        plaintext.get_version(),
        plaintext.get_epoch(),
        static_cast<uint64_t>(sequence_number),
        plaintext.get_length()
    };
    
    auto aad_result = construct_additional_data_dtls(temp_header, cid);
    if (!aad_result.is_success()) {
        return Result<DTLSCiphertext>(aad_result.error());
    }
    
    // Perform AEAD encryption
    crypto::AEADEncryptionParams encrypt_params;
    encrypt_params.key = crypto_params.write_key;
    encrypt_params.nonce = nonce_result.value();
    encrypt_params.additional_data = aad_result.value();
    encrypt_params.plaintext = std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(plaintext.get_fragment().data()),
        reinterpret_cast<const uint8_t*>(plaintext.get_fragment().data()) + plaintext.get_fragment().size());
    
    auto encrypt_result = crypto_provider_->encrypt_aead(encrypt_params);
    if (!encrypt_result.is_success()) {
        update_stats_decryption_failed();
        return Result<DTLSCiphertext>(encrypt_result.error());
    }
    
    const auto& encrypt_output = encrypt_result.value();
    
    // Create encrypted payload buffer including authentication tag
    memory::Buffer encrypted_record(encrypt_output.ciphertext.size() + encrypt_output.tag.size());
    std::memcpy(encrypted_record.mutable_data(), 
                encrypt_output.ciphertext.data(), 
                encrypt_output.ciphertext.size());
    std::memcpy(encrypted_record.mutable_data() + encrypt_output.ciphertext.size(),
                encrypt_output.tag.data(),
                encrypt_output.tag.size());
    
    // Now encrypt sequence number using first 16 bytes of ciphertext (RFC 9147 Section 4.2.3)
    SequenceNumber48 encrypted_sequence_number = sequence_number;
    if (encrypted_record.size() >= 16) {
        // Derive sequence number encryption key
        auto seq_key_result = crypto::utils::derive_sequence_number_mask(
            *crypto_provider_, crypto_params.write_key, "sn", 
            crypto::utils::get_cipher_suite_hash(current_cipher_suite_));
        if (seq_key_result.is_success()) {
            // Get cipher type from current cipher suite
            AEADCipher cipher_type = AEADCipher::AES_128_GCM; // Default
            switch (current_cipher_suite_) {
                case CipherSuite::TLS_AES_128_GCM_SHA256:
                    cipher_type = AEADCipher::AES_128_GCM;
                    break;
                case CipherSuite::TLS_AES_256_GCM_SHA384:
                    cipher_type = AEADCipher::AES_256_GCM;
                    break;
                case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
                    cipher_type = AEADCipher::CHACHA20_POLY1305;
                    break;
                case CipherSuite::TLS_AES_128_CCM_SHA256:
                    cipher_type = AEADCipher::AES_128_CCM;
                    break;
                case CipherSuite::TLS_AES_128_CCM_8_SHA256:
                    cipher_type = AEADCipher::AES_128_CCM_8;
                    break;
                default:
                    cipher_type = AEADCipher::AES_128_GCM;
                    break;
            }
            
            // Encrypt sequence number using first 16 bytes of ciphertext
            std::vector<uint8_t> ciphertext_prefix(16);
            std::memcpy(ciphertext_prefix.data(), encrypted_record.data(), 16);
            auto encrypted_seq_result = crypto::utils::encrypt_sequence_number(
                *crypto_provider_, 
                static_cast<uint64_t>(sequence_number), 
                seq_key_result.value(),
                ciphertext_prefix,
                cipher_type);
            if (encrypted_seq_result.is_success()) {
                encrypted_sequence_number = SequenceNumber48(encrypted_seq_result.value());
            }
        }
    }

    DTLSCiphertext ciphertext(ContentType::APPLICATION_DATA,
                             plaintext.get_version(),
                             plaintext.get_epoch(),
                             encrypted_sequence_number,
                             std::move(encrypted_record));
    
    // Add connection ID if enabled
    if (connection_id_manager_->is_connection_id_enabled() && !cid.empty()) {
        ciphertext.set_connection_id(cid);
    }
    
    update_stats_protected();
    
    // Update key update record counter
    {
        std::lock_guard<std::mutex> lock(key_update_mutex_);
        key_update_stats_.records_since_last_update++;
    }
    
    return Result<DTLSCiphertext>(std::move(ciphertext));
}

Result<DTLSPlaintext> RecordLayer::unprotect_record(const DTLSCiphertext& ciphertext) {
    if (!ciphertext.is_valid()) {
        return Result<DTLSPlaintext>(DTLSError::INVALID_CIPHERTEXT_RECORD);
    }
    
    uint16_t record_epoch = ciphertext.get_epoch();
    
    // Validate epoch
    if (!epoch_manager_->is_valid_epoch(record_epoch)) {
        return Result<DTLSPlaintext>(DTLSError::INVALID_EPOCH);
    }
    
    // Get crypto parameters for record epoch
    auto crypto_params_result = epoch_manager_->get_epoch_crypto_params(record_epoch);
    if (!crypto_params_result.is_success()) {
        return Result<DTLSPlaintext>(crypto_params_result.error());
    }
    
    const auto& crypto_params = crypto_params_result.value();
    
    // Decrypt sequence number using RFC 9147 Section 4.1.3
    uint64_t decrypted_seq_num = ciphertext.get_encrypted_sequence_number();
    if (record_epoch > 0 && !crypto_params.read_key.empty()) {
        // Derive sequence number decryption key
        auto seq_key_result = crypto::utils::derive_sequence_number_mask(
            *crypto_provider_, crypto_params.read_key, "sn",
            crypto::utils::get_cipher_suite_hash(current_cipher_suite_));
        if (!seq_key_result.is_success()) {
            return Result<DTLSPlaintext>(seq_key_result.error());
        }
        
        // Decrypt the sequence number
        // Get cipher type from current cipher suite
        AEADCipher cipher_type = AEADCipher::AES_128_GCM; // Default
        switch (current_cipher_suite_) {
            case CipherSuite::TLS_AES_128_GCM_SHA256:
                cipher_type = AEADCipher::AES_128_GCM;
                break;
            case CipherSuite::TLS_AES_256_GCM_SHA384:
                cipher_type = AEADCipher::AES_256_GCM;
                break;
            case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
                cipher_type = AEADCipher::CHACHA20_POLY1305;
                break;
            case CipherSuite::TLS_AES_128_CCM_SHA256:
                cipher_type = AEADCipher::AES_128_CCM;
                break;
            case CipherSuite::TLS_AES_128_CCM_8_SHA256:
                cipher_type = AEADCipher::AES_128_CCM_8;
                break;
            default:
                cipher_type = AEADCipher::AES_128_GCM;
                break;
        }
        
        // Extract first 16 bytes of encrypted record for sequence number decryption
        const auto& encrypted_record = ciphertext.get_encrypted_record();
        std::vector<uint8_t> ciphertext_prefix(16, 0);
        if (encrypted_record.size() >= 16) {
            std::memcpy(ciphertext_prefix.data(), encrypted_record.data(), 16);
        } else {
            // Fallback: pad to 16 bytes if ciphertext is shorter
            std::memcpy(ciphertext_prefix.data(), encrypted_record.data(), encrypted_record.size());
        }
        
        auto decrypted_seq_result = crypto::utils::decrypt_sequence_number(
            *crypto_provider_, ciphertext.get_encrypted_sequence_number(), seq_key_result.value(),
            ciphertext_prefix, cipher_type);
        if (!decrypted_seq_result.is_success()) {
            return Result<DTLSPlaintext>(decrypted_seq_result.error());
        }
        
        decrypted_seq_num = decrypted_seq_result.value();
    }
    
    // Epoch 0 uses null protection (no decryption)
    if (record_epoch == 0 || crypto_params.read_key.empty()) {
        // Create DTLSPlaintext with no decryption
        memory::Buffer payload(ciphertext.get_encrypted_record().size());
        std::memcpy(payload.mutable_data(), 
                   ciphertext.get_encrypted_record().data(), 
                   ciphertext.get_encrypted_record().size());
        
        DTLSPlaintext plaintext(ciphertext.get_type(),
                               ciphertext.get_version(),
                               ciphertext.get_epoch(),
                               SequenceNumber48(decrypted_seq_num),
                               std::move(payload));
        
        update_stats_unprotected();
        return Result<DTLSPlaintext>(std::move(plaintext));
    }
    
    // Construct AEAD nonce with original (decrypted) sequence number
    auto nonce_result = construct_aead_nonce(record_epoch, 
                                           decrypted_seq_num,
                                           crypto_params.read_iv);
    if (!nonce_result.is_success()) {
        return Result<DTLSPlaintext>(nonce_result.error());
    }
    
    // Construct additional authenticated data using encrypted sequence number (as sent)
    ConnectionID cid;
    if (ciphertext.has_cid()) {
        cid = ciphertext.get_connection_id_vector();
    }
    
    // Create temporary header with encrypted sequence number for AAD verification
    struct TempHeader {
        ContentType content_type;
        ProtocolVersion version;
        uint16_t epoch;
        uint64_t sequence_number;
        uint16_t length;
    } temp_header = {
        ciphertext.get_type(),
        ciphertext.get_version(),
        ciphertext.get_epoch(),
        static_cast<uint64_t>(ciphertext.get_encrypted_sequence_number()),
        ciphertext.get_length()
    };
    
    auto aad_result = construct_additional_data_dtls(temp_header, cid);
    if (!aad_result.is_success()) {
        return Result<DTLSPlaintext>(aad_result.error());
    }
    
    // Extract ciphertext and authentication tag from encrypted record
    const auto& encrypted_record = ciphertext.get_encrypted_record();
    if (encrypted_record.size() < 16) { // Minimum auth tag size
        return Result<DTLSPlaintext>(DTLSError::INVALID_CIPHERTEXT_RECORD);
    }
    
    // Assume GCM tag size of 16 bytes for now (should be determined by cipher suite)
    size_t tag_size = 16;
    size_t ciphertext_size = encrypted_record.size() - tag_size;
    
    // Perform AEAD decryption
    crypto::AEADDecryptionParams decrypt_params;
    decrypt_params.key = crypto_params.read_key;
    decrypt_params.nonce = nonce_result.value();
    decrypt_params.additional_data = aad_result.value();
    decrypt_params.ciphertext = std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(encrypted_record.data()),
        reinterpret_cast<const uint8_t*>(encrypted_record.data()) + ciphertext_size);
    decrypt_params.tag = std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(encrypted_record.data()) + ciphertext_size,
        reinterpret_cast<const uint8_t*>(encrypted_record.data()) + encrypted_record.size());
    
    auto decrypt_result = crypto_provider_->decrypt_aead(decrypt_params);
    if (!decrypt_result.is_success()) {
        update_stats_decryption_failed();
        return Result<DTLSPlaintext>(decrypt_result.error());
    }
    
    const auto& plaintext_data = decrypt_result.value();
    
    // Create DTLSPlaintext with decrypted sequence number
    memory::Buffer payload(plaintext_data.size());
    std::memcpy(payload.mutable_data(), plaintext_data.data(), plaintext_data.size());
    
    DTLSPlaintext plaintext(ciphertext.get_type(),
                           ciphertext.get_version(),
                           ciphertext.get_epoch(),
                           SequenceNumber48(decrypted_seq_num),
                           std::move(payload));
    
    update_stats_unprotected();
    return Result<DTLSPlaintext>(std::move(plaintext));
}

Result<DTLSCiphertext> RecordLayer::prepare_outgoing_record(const DTLSPlaintext& plaintext) {
    // Get next sequence number
    uint64_t sequence_number = send_sequence_manager_->get_next_sequence_number();
    
    // Check for sequence number overflow
    if (send_sequence_manager_->would_overflow()) {
        return Result<DTLSCiphertext>(DTLSError::SEQUENCE_NUMBER_OVERFLOW);
    }
    
    // Create record with assigned sequence number
    DTLSPlaintext outgoing_record = plaintext;
    outgoing_record.set_sequence_number(SequenceNumber48(sequence_number));
    outgoing_record.set_epoch(epoch_manager_->get_current_epoch());
    
    // Protect the record
    auto ciphertext_result = protect_record(outgoing_record);
    if (!ciphertext_result.is_success()) {
        return ciphertext_result;
    }
    
    update_stats_sent();
    return ciphertext_result;
}

Result<DTLSPlaintext> RecordLayer::process_incoming_record(const DTLSCiphertext& ciphertext) {
    uint16_t record_epoch = ciphertext.get_epoch();
    
    // Decrypt sequence number for anti-replay checking
    uint64_t decrypted_seq_num = ciphertext.get_encrypted_sequence_number();
    if (record_epoch > 0) {
        // Get crypto parameters for sequence number decryption
        auto crypto_params_result = epoch_manager_->get_epoch_crypto_params(record_epoch);
        if (crypto_params_result.is_success() && !crypto_params_result.value().read_key.empty()) {
            // Derive sequence number decryption key
            auto seq_key_result = crypto::utils::derive_sequence_number_mask(
                *crypto_provider_, crypto_params_result.value().read_key, "sn",
                crypto::utils::get_cipher_suite_hash(current_cipher_suite_));
            if (seq_key_result.is_success()) {
                // Decrypt the sequence number for anti-replay check
                // Get cipher type from current cipher suite
                AEADCipher cipher_type = AEADCipher::AES_128_GCM; // Default
                switch (current_cipher_suite_) {
                    case CipherSuite::TLS_AES_128_GCM_SHA256:
                        cipher_type = AEADCipher::AES_128_GCM;
                        break;
                    case CipherSuite::TLS_AES_256_GCM_SHA384:
                        cipher_type = AEADCipher::AES_256_GCM;
                        break;
                    case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
                        cipher_type = AEADCipher::CHACHA20_POLY1305;
                        break;
                    case CipherSuite::TLS_AES_128_CCM_SHA256:
                        cipher_type = AEADCipher::AES_128_CCM;
                        break;
                    case CipherSuite::TLS_AES_128_CCM_8_SHA256:
                        cipher_type = AEADCipher::AES_128_CCM_8;
                        break;
                    default:
                        cipher_type = AEADCipher::AES_128_GCM;
                        break;
                }
                
                // Extract first 16 bytes of encrypted record for sequence number decryption
        const auto& encrypted_record = ciphertext.get_encrypted_record();
        std::vector<uint8_t> ciphertext_prefix(16, 0);
        if (encrypted_record.size() >= 16) {
            std::memcpy(ciphertext_prefix.data(), encrypted_record.data(), 16);
        } else {
            // Fallback: pad to 16 bytes if ciphertext is shorter
            std::memcpy(ciphertext_prefix.data(), encrypted_record.data(), encrypted_record.size());
        }
                
                auto decrypted_seq_result = crypto::utils::decrypt_sequence_number(
                    *crypto_provider_, ciphertext.get_encrypted_sequence_number(), seq_key_result.value(),
                    ciphertext_prefix, cipher_type);
                if (decrypted_seq_result.is_success()) {
                    decrypted_seq_num = decrypted_seq_result.value();
                }
            }
        }
    }
    
    // Get or create anti-replay window for this epoch
    auto window_it = receive_windows_.find(record_epoch);
    if (window_it == receive_windows_.end()) {
        receive_windows_[record_epoch] = std::make_unique<AntiReplayWindow>();
        window_it = receive_windows_.find(record_epoch);
    }
    
    // Check for replay attack using decrypted sequence number
    if (!window_it->second->is_valid_sequence_number(decrypted_seq_num)) {
        update_stats_replay_detected();
        return Result<DTLSPlaintext>(DTLSError::REPLAY_ATTACK_DETECTED);
    }
    
    // Validate connection ID if present
    if (ciphertext.has_cid()) {
        auto cid = ciphertext.get_connection_id_vector();
        if (!connection_id_manager_->is_valid_connection_id(cid)) {
            return Result<DTLSPlaintext>(DTLSError::INVALID_CONNECTION_ID);
        }
    }
    
    // Unprotect the record
    auto plaintext_result = unprotect_record(ciphertext);
    if (!plaintext_result.is_success()) {
        return plaintext_result;
    }
    
    // Mark sequence number as received (prevents replays) using decrypted sequence number
    window_it->second->mark_received(decrypted_seq_num);
    
    update_stats_received();
    return plaintext_result;
}

Result<void> RecordLayer::advance_epoch(const std::vector<uint8_t>& read_key,
                                      const std::vector<uint8_t>& write_key,
                                      const std::vector<uint8_t>& read_iv,
                                      const std::vector<uint8_t>& write_iv) {
    // Advance epoch
    auto new_epoch_result = epoch_manager_->advance_epoch();
    if (!new_epoch_result.is_success()) {
        return Result<void>(new_epoch_result.error());
    }
    
    uint16_t new_epoch = new_epoch_result.value();
    
    // Set new epoch keys
    auto set_keys_result = epoch_manager_->set_epoch_keys(new_epoch, read_key, write_key, read_iv, write_iv);
    if (!set_keys_result.is_success()) {
        return set_keys_result;
    }
    
    // Reset sequence numbers for new epoch
    send_sequence_manager_->reset();
    
    // Create new anti-replay window for new epoch
    receive_windows_[new_epoch] = std::make_unique<AntiReplayWindow>();
    
    return Result<void>();
}

Result<void> RecordLayer::enable_connection_id(const ConnectionID& local_cid, 
                                              const ConnectionID& peer_cid) {
    if (local_cid.size() > MAX_CONNECTION_ID_LENGTH || peer_cid.size() > MAX_CONNECTION_ID_LENGTH) {
        return Result<void>(DTLSError::INVALID_CONNECTION_ID);
    }
    
    connection_id_manager_->set_local_connection_id(local_cid);
    connection_id_manager_->set_peer_connection_id(peer_cid);
    
    return Result<void>();
}

RecordLayerStats RecordLayer::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    RecordLayerStats current_stats = stats_;
    current_stats.current_epoch = epoch_manager_->get_current_epoch();
    current_stats.current_sequence_number = send_sequence_manager_->get_current_sequence_number();
    return current_stats;
}

// Private helper methods

Result<std::vector<uint8_t>> RecordLayer::construct_aead_nonce(uint16_t epoch, 
                                                             uint64_t sequence_number,
                                                             const std::vector<uint8_t>& base_iv) const {
    if (base_iv.size() != 12) { // Standard AEAD nonce size
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_IV_SIZE);
    }
    
    std::vector<uint8_t> nonce = base_iv;
    
    // XOR sequence number into the nonce (RFC 9147)
    uint64_t seq_net = htobe64(sequence_number);
    uint8_t* seq_bytes = reinterpret_cast<uint8_t*>(&seq_net);
    
    // XOR the last 8 bytes of nonce with sequence number
    for (size_t i = 0; i < 8; ++i) {
        nonce[4 + i] ^= seq_bytes[i];
    }
    
    return Result<std::vector<uint8_t>>(std::move(nonce));
}

Result<std::vector<uint8_t>> RecordLayer::construct_additional_data(const RecordHeader& header,
                                                                  const ConnectionID& cid) const {
    std::vector<uint8_t> aad;
    
    // Connection ID (if present)
    if (!cid.empty()) {
        aad.insert(aad.end(), cid.begin(), cid.end());
    }
    
    // Record header without length
    aad.push_back(static_cast<uint8_t>(header.content_type));
    
    // Protocol version (2 bytes, network order)
    uint16_t version_net = htons(static_cast<uint16_t>(header.version));
    uint8_t* version_bytes = reinterpret_cast<uint8_t*>(&version_net);
    aad.push_back(version_bytes[0]);
    aad.push_back(version_bytes[1]);
    
    // Epoch (2 bytes, network order)
    uint16_t epoch_net = htons(header.epoch);
    uint8_t* epoch_bytes = reinterpret_cast<uint8_t*>(&epoch_net);
    aad.push_back(epoch_bytes[0]);
    aad.push_back(epoch_bytes[1]);
    
    // Sequence number (6 bytes, network order)
    uint64_t seq_net = htobe64(header.sequence_number);
    uint8_t* seq_bytes = reinterpret_cast<uint8_t*>(&seq_net);
    for (int i = 2; i < 8; ++i) { // Only 6 bytes (48-bit sequence number)
        aad.push_back(seq_bytes[i]);
    }
    
    // Length (2 bytes, network order)
    uint16_t length_net = htons(header.length);
    uint8_t* length_bytes = reinterpret_cast<uint8_t*>(&length_net);
    aad.push_back(length_bytes[0]);
    aad.push_back(length_bytes[1]);
    
    return Result<std::vector<uint8_t>>(std::move(aad));
}

template<typename HeaderType>
Result<std::vector<uint8_t>> RecordLayer::construct_additional_data_dtls(const HeaderType& header,
                                                                        const ConnectionID& cid) const {
    std::vector<uint8_t> aad;
    
    // Connection ID (if present)
    if (!cid.empty()) {
        aad.insert(aad.end(), cid.begin(), cid.end());
    }
    
    // Record header without length
    aad.push_back(static_cast<uint8_t>(header.content_type));
    
    // Protocol version (2 bytes, network order)
    uint16_t version_net = htons(static_cast<uint16_t>(header.version));
    uint8_t* version_bytes = reinterpret_cast<uint8_t*>(&version_net);
    aad.push_back(version_bytes[0]);
    aad.push_back(version_bytes[1]);
    
    // Epoch (2 bytes, network order)
    uint16_t epoch_net = htons(header.epoch);
    uint8_t* epoch_bytes = reinterpret_cast<uint8_t*>(&epoch_net);
    aad.push_back(epoch_bytes[0]);
    aad.push_back(epoch_bytes[1]);
    
    // Sequence number (6 bytes, network order) - using encrypted sequence number for AAD
    uint64_t seq_net = htobe64(header.sequence_number);
    uint8_t* seq_bytes = reinterpret_cast<uint8_t*>(&seq_net);
    for (int i = 2; i < 8; ++i) { // Only 6 bytes (48-bit sequence number)
        aad.push_back(seq_bytes[i]);
    }
    
    // Length (2 bytes, network order)
    uint16_t length_net = htons(header.length);
    uint8_t* length_bytes = reinterpret_cast<uint8_t*>(&length_net);
    aad.push_back(length_bytes[0]);
    aad.push_back(length_bytes[1]);
    
    return Result<std::vector<uint8_t>>(std::move(aad));
}

void RecordLayer::update_stats_sent() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.records_sent++;
}

void RecordLayer::update_stats_received() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.records_received++;
}

void RecordLayer::update_stats_protected() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.records_protected++;
}

void RecordLayer::update_stats_unprotected() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.records_unprotected++;
}

void RecordLayer::update_stats_replay_detected() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.replay_attacks_detected++;
}

void RecordLayer::update_stats_decryption_failed() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.decryption_failures++;
}

// ============================================================================
// Legacy Support Methods
// ============================================================================

Result<CiphertextRecord> RecordLayer::protect_record_legacy(const PlaintextRecord& plaintext) {
    // Convert PlaintextRecord to DTLSPlaintext
    memory::Buffer fragment_copy(plaintext.payload().size());
    std::memcpy(fragment_copy.mutable_data(), plaintext.payload().data(), plaintext.payload().size());
    
    DTLSPlaintext dtls_plaintext(
        plaintext.header().content_type,
        plaintext.header().version,
        plaintext.header().epoch,
        SequenceNumber48(plaintext.header().sequence_number),
        std::move(fragment_copy)
    );
    
    // Protect using new method
    auto dtls_ciphertext_result = protect_record(dtls_plaintext);
    if (!dtls_ciphertext_result.is_success()) {
        return Result<CiphertextRecord>(dtls_ciphertext_result.error());
    }
    
    const auto& dtls_ciphertext = dtls_ciphertext_result.value();
    
    // Convert DTLSCiphertext back to CiphertextRecord for legacy compatibility
    // Extract ciphertext and tag from encrypted_record
    const auto& encrypted_record = dtls_ciphertext.get_encrypted_record();
    size_t tag_size = 16; // Assume GCM
    size_t ciphertext_size = encrypted_record.size() - tag_size;
    
    memory::Buffer ciphertext_payload(ciphertext_size);
    memory::Buffer auth_tag(tag_size);
    
    std::memcpy(ciphertext_payload.mutable_data(), encrypted_record.data(), ciphertext_size);
    std::memcpy(auth_tag.mutable_data(), encrypted_record.data() + ciphertext_size, tag_size);
    
    CiphertextRecord legacy_ciphertext(
        dtls_ciphertext.get_type(),
        dtls_ciphertext.get_version(),
        dtls_ciphertext.get_epoch(),
        static_cast<uint64_t>(dtls_ciphertext.get_encrypted_sequence_number()),
        std::move(ciphertext_payload),
        std::move(auth_tag)
    );
    
    // Add connection ID if present
    if (dtls_ciphertext.has_cid()) {
        auto cid_vector = dtls_ciphertext.get_connection_id_vector();
        legacy_ciphertext.set_connection_id(cid_vector);
    }
    
    return Result<CiphertextRecord>(std::move(legacy_ciphertext));
}

Result<PlaintextRecord> RecordLayer::unprotect_record_legacy(const CiphertextRecord& ciphertext) {
    // Convert CiphertextRecord to DTLSCiphertext
    memory::Buffer encrypted_record(ciphertext.encrypted_payload().size() + ciphertext.authentication_tag().size());
    std::memcpy(encrypted_record.mutable_data(), 
                ciphertext.encrypted_payload().data(), 
                ciphertext.encrypted_payload().size());
    std::memcpy(encrypted_record.mutable_data() + ciphertext.encrypted_payload().size(),
                ciphertext.authentication_tag().data(),
                ciphertext.authentication_tag().size());
    
    DTLSCiphertext dtls_ciphertext(
        ciphertext.header().content_type,
        ciphertext.header().version,
        ciphertext.header().epoch,
        SequenceNumber48(ciphertext.header().sequence_number),
        std::move(encrypted_record)
    );
    
    // Add connection ID if present
    if (ciphertext.has_connection_id()) {
        const auto& cid_array = ciphertext.connection_id();
        std::vector<uint8_t> cid_vector(cid_array.begin(), cid_array.end());
        dtls_ciphertext.set_connection_id(cid_vector);
    }
    
    // Unprotect using new method
    auto dtls_plaintext_result = unprotect_record(dtls_ciphertext);
    if (!dtls_plaintext_result.is_success()) {
        return Result<PlaintextRecord>(dtls_plaintext_result.error());
    }
    
    const auto& dtls_plaintext = dtls_plaintext_result.value();
    
    // Convert DTLSPlaintext back to PlaintextRecord
    memory::Buffer payload_copy(dtls_plaintext.get_fragment().size());
    std::memcpy(payload_copy.mutable_data(), 
                dtls_plaintext.get_fragment().data(), 
                dtls_plaintext.get_fragment().size());
    
    PlaintextRecord legacy_plaintext(
        dtls_plaintext.get_type(),
        dtls_plaintext.get_version(),
        dtls_plaintext.get_epoch(),
        static_cast<uint64_t>(dtls_plaintext.get_sequence_number()),
        std::move(payload_copy)
    );
    
    return Result<PlaintextRecord>(std::move(legacy_plaintext));
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace record_layer_utils {

std::unique_ptr<RecordLayer> create_test_record_layer() {
    // Create a mock crypto provider for testing
    auto crypto_provider_result = crypto::ProviderFactory::instance().create_provider("mock");
    if (!crypto_provider_result.is_success()) {
        return nullptr;
    }
    auto crypto_provider = std::move(crypto_provider_result.value());
    
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider));
    
    // Initialize with default settings
    auto init_result = record_layer->initialize();
    if (!init_result.is_success()) {
        return nullptr;
    }
    
    return record_layer;
}

Result<void> validate_record_layer_config(const RecordLayer& layer) {
    auto stats = layer.get_stats();
    
    // Basic validation checks
    if (stats.current_epoch > 65535) {
        return Result<void>(DTLSError::INVALID_EPOCH);
    }
    
    if (stats.current_sequence_number > ((1ULL << 48) - 1)) {
        return Result<void>(DTLSError::SEQUENCE_NUMBER_OVERFLOW);
    }
    
    return Result<void>();
}

Result<std::vector<std::pair<DTLSPlaintext, DTLSCiphertext>>> 
generate_test_vectors(CipherSuite suite) {
    std::vector<std::pair<DTLSPlaintext, DTLSCiphertext>> test_vectors;
    
    // Create test DTLSPlaintext record
    std::string test_data = "Hello, DTLS v1.3!";
    memory::Buffer payload(test_data.size());
    std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
    
    DTLSPlaintext plaintext(ContentType::APPLICATION_DATA,
                           ProtocolVersion::DTLS_1_3,
                           1, // epoch
                           SequenceNumber48(1), // sequence number
                           std::move(payload));
    
    // Create corresponding DTLSCiphertext (for testing, use mock encrypted data)
    memory::Buffer encrypted_record(test_data.size() + 16); // data + auth tag
    std::memcpy(encrypted_record.mutable_data(), test_data.data(), test_data.size());
    
    // Mock authentication tag at the end
    std::fill(encrypted_record.mutable_data() + test_data.size(), 
              encrypted_record.mutable_data() + encrypted_record.size(), 
              static_cast<std::byte>(0xAA));
    
    DTLSCiphertext ciphertext(ContentType::APPLICATION_DATA,
                             ProtocolVersion::DTLS_1_3,
                             1, // epoch
                             SequenceNumber48(0x123456789ABCULL), // encrypted sequence number
                             std::move(encrypted_record));
    
    test_vectors.emplace_back(std::move(plaintext), std::move(ciphertext));
    
    return Result<std::vector<std::pair<DTLSPlaintext, DTLSCiphertext>>>(std::move(test_vectors));
}

Result<std::vector<std::pair<PlaintextRecord, CiphertextRecord>>> 
generate_legacy_test_vectors(CipherSuite suite) {
    std::vector<std::pair<PlaintextRecord, CiphertextRecord>> test_vectors;
    
    // Create test plaintext record
    std::string test_data = "Hello, DTLS v1.3!";
    memory::Buffer payload(test_data.size());
    std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
    
    PlaintextRecord plaintext(ContentType::APPLICATION_DATA,
                            ProtocolVersion::DTLS_1_3,
                            1, // epoch
                            1, // sequence number
                            std::move(payload));
    
    // Create corresponding ciphertext (for testing, we'll use the same data)
    memory::Buffer encrypted_payload(test_data.size());
    std::memcpy(encrypted_payload.mutable_data(), test_data.data(), test_data.size());
    
    // Mock authentication tag
    memory::Buffer auth_tag(16); // 16 bytes for GCM
    std::fill(auth_tag.mutable_data(), auth_tag.mutable_data() + 16, static_cast<std::byte>(0xAA));
    
    CiphertextRecord ciphertext(ContentType::APPLICATION_DATA,
                              ProtocolVersion::DTLS_1_3,
                              1, // epoch
                              1, // sequence number
                              std::move(encrypted_payload),
                              std::move(auth_tag));
    
    test_vectors.emplace_back(std::move(plaintext), std::move(ciphertext));
    
    return Result<std::vector<std::pair<PlaintextRecord, CiphertextRecord>>>(std::move(test_vectors));
}

} // namespace record_layer_utils

// ============================================================================
// RecordLayer Key Update Implementation
// ============================================================================

Result<void> RecordLayer::update_traffic_keys() {
    std::lock_guard<std::mutex> lock(key_update_mutex_);
    
    // Get current cipher spec
    auto cipher_spec_result = crypto::CipherSpec::from_cipher_suite(current_cipher_suite_);
    if (!cipher_spec_result.is_success()) {
        return Result<void>(cipher_spec_result.error());
    }
    auto cipher_spec = cipher_spec_result.value();
    
    // Get current epoch crypto parameters
    auto current_epoch_result = epoch_manager_->get_epoch_crypto_params(epoch_manager_->current_epoch());
    if (!current_epoch_result.is_success()) {
        return Result<void>(current_epoch_result.error());
    }
    auto current_params = current_epoch_result.value();
    
    // Create current key schedule from epoch parameters
    crypto::KeySchedule current_keys;
    current_keys.client_write_key = current_params.read_key;  // In DTLS, read_key is peer's write_key
    current_keys.server_write_key = current_params.write_key;
    current_keys.client_write_iv = current_params.read_iv;
    current_keys.server_write_iv = current_params.write_iv;
    current_keys.epoch = epoch_manager_->current_epoch();
    
    // Perform key update using crypto utils
    auto updated_keys_result = crypto::utils::update_traffic_keys(
        *crypto_provider_, cipher_spec, current_keys);
    
    if (!updated_keys_result.is_success()) {
        return Result<void>(updated_keys_result.error());
    }
    
    auto updated_keys = updated_keys_result.value();
    
    // Update epoch with new keys
    auto advance_result = advance_epoch(
        updated_keys.client_write_key,  // read_key (peer's write key)
        updated_keys.server_write_key,  // write_key (our write key)  
        updated_keys.client_write_iv,   // read_iv
        updated_keys.server_write_iv    // write_iv
    );
    
    if (!advance_result.is_success()) {
        return advance_result;
    }
    
    // Update statistics
    key_update_stats_.updates_performed++;
    key_update_stats_.records_since_last_update = 0;
    key_update_stats_.last_update_time = std::chrono::steady_clock::now();
    
    return Result<void>();
}

Result<void> RecordLayer::update_traffic_keys(const crypto::KeySchedule& new_keys) {
    std::lock_guard<std::mutex> lock(key_update_mutex_);
    
    // Update epoch with provided keys
    auto advance_result = advance_epoch(
        new_keys.client_write_key,  // read_key (peer's write key)
        new_keys.server_write_key,  // write_key (our write key)
        new_keys.client_write_iv,   // read_iv
        new_keys.server_write_iv    // write_iv
    );
    
    if (!advance_result.is_success()) {
        return advance_result;
    }
    
    // Update statistics
    key_update_stats_.updates_performed++;
    key_update_stats_.records_since_last_update = 0;
    key_update_stats_.last_update_time = std::chrono::steady_clock::now();
    
    return Result<void>();
}

bool RecordLayer::needs_key_update(uint64_t max_records, std::chrono::seconds max_time) const {
    std::lock_guard<std::mutex> lock(key_update_mutex_);
    
    // Check record count limit
    if (key_update_stats_.records_since_last_update >= max_records) {
        return true;
    }
    
    // Check time limit
    auto current_time = std::chrono::steady_clock::now();
    auto time_since_last_update = current_time - key_update_stats_.last_update_time;
    
    if (time_since_last_update >= max_time) {
        return true;
    }
    
    return false;
}

KeyUpdateStats RecordLayer::get_key_update_stats() const {
    std::lock_guard<std::mutex> lock(key_update_mutex_);
    return key_update_stats_;
}


} // namespace dtls::v13::protocol