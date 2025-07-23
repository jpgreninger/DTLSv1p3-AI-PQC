#include "dtls/protocol/record_layer.h"
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
    
    if (read_key.empty() || write_key.empty() || read_iv.empty() || write_iv.empty()) {
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
      connection_id_manager_(std::make_unique<ConnectionIDManager>()) {
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

Result<CiphertextRecord> RecordLayer::protect_record(const PlaintextRecord& plaintext) {
    if (!plaintext.is_valid()) {
        return Result<CiphertextRecord>(DTLSError::INVALID_PLAINTEXT_RECORD);
    }
    
    uint16_t current_epoch = epoch_manager_->get_current_epoch();
    
    // Get crypto parameters for current epoch
    auto crypto_params_result = epoch_manager_->get_epoch_crypto_params(current_epoch);
    if (!crypto_params_result.is_success()) {
        return Result<CiphertextRecord>(crypto_params_result.error());
    }
    
    const auto& crypto_params = crypto_params_result.value();
    
    // Epoch 0 uses null protection (no encryption)
    if (current_epoch == 0 || crypto_params.write_key.empty()) {
        // Create ciphertext record with no encryption
        memory::Buffer encrypted_payload(plaintext.payload().size());
        std::memcpy(encrypted_payload.mutable_data(), plaintext.payload().data(), plaintext.payload().size());
        
        memory::Buffer empty_tag(0);
        CiphertextRecord ciphertext(plaintext.header().content_type,
                                  plaintext.header().version,
                                  plaintext.header().epoch,
                                  plaintext.header().sequence_number,
                                  std::move(encrypted_payload),
                                  std::move(empty_tag));
        update_stats_protected();
        return Result<CiphertextRecord>(std::move(ciphertext));
    }
    
    // Construct AEAD nonce
    auto nonce_result = construct_aead_nonce(current_epoch, 
                                           plaintext.header().sequence_number,
                                           crypto_params.write_iv);
    if (!nonce_result.is_success()) {
        return Result<CiphertextRecord>(nonce_result.error());
    }
    
    // Construct additional authenticated data
    ConnectionID cid = connection_id_manager_->is_connection_id_enabled() ?
        connection_id_manager_->get_peer_connection_id() : ConnectionID{};
    
    auto aad_result = construct_additional_data(plaintext.header(), cid);
    if (!aad_result.is_success()) {
        return Result<CiphertextRecord>(aad_result.error());
    }
    
    // Perform AEAD encryption
    crypto::AEADEncryptionParams encrypt_params;
    encrypt_params.key = crypto_params.write_key;
    encrypt_params.nonce = nonce_result.value();
    encrypt_params.additional_data = aad_result.value();
    encrypt_params.plaintext = std::vector<uint8_t>(plaintext.payload().data(),
                                                   plaintext.payload().data() + plaintext.payload().size());
    
    auto encrypt_result = crypto_provider_->encrypt_aead(encrypt_params);
    if (!encrypt_result.is_success()) {
        update_stats_decryption_failed();
        return Result<CiphertextRecord>(encrypt_result.error());
    }
    
    const auto& encrypt_output = encrypt_result.value();
    
    // Create ciphertext record
    memory::Buffer encrypted_payload(encrypt_output.ciphertext.size());
    std::memcpy(encrypted_payload.mutable_data(), encrypt_output.ciphertext.data(), 
                encrypt_output.ciphertext.size());
    
    memory::Buffer auth_tag(encrypt_output.tag.size());
    std::memcpy(auth_tag.mutable_data(), encrypt_output.tag.data(), encrypt_output.tag.size());
    
    CiphertextRecord ciphertext(plaintext.header().content_type,
                              plaintext.header().version,
                              plaintext.header().epoch,
                              plaintext.header().sequence_number,
                              std::move(encrypted_payload),
                              std::move(auth_tag));
    
    // Add connection ID if enabled
    if (connection_id_manager_->is_connection_id_enabled() && !cid.empty()) {
        std::array<uint8_t, 16> cid_array{};
        size_t copy_size = std::min(cid.size(), cid_array.size());
        std::memcpy(cid_array.data(), cid.data(), copy_size);
        ciphertext.set_connection_id(cid_array);
    }
    
    update_stats_protected();
    return Result<CiphertextRecord>(std::move(ciphertext));
}

Result<PlaintextRecord> RecordLayer::unprotect_record(const CiphertextRecord& ciphertext) {
    if (!ciphertext.is_valid()) {
        return Result<PlaintextRecord>(DTLSError::INVALID_CIPHERTEXT_RECORD);
    }
    
    uint16_t record_epoch = ciphertext.header().epoch;
    
    // Validate epoch
    if (!epoch_manager_->is_valid_epoch(record_epoch)) {
        return Result<PlaintextRecord>(DTLSError::INVALID_EPOCH);
    }
    
    // Get crypto parameters for record epoch
    auto crypto_params_result = epoch_manager_->get_epoch_crypto_params(record_epoch);
    if (!crypto_params_result.is_success()) {
        return Result<PlaintextRecord>(crypto_params_result.error());
    }
    
    const auto& crypto_params = crypto_params_result.value();
    
    // Epoch 0 uses null protection (no decryption)
    if (record_epoch == 0 || crypto_params.read_key.empty()) {
        // Create plaintext record with no decryption
        memory::Buffer payload(ciphertext.encrypted_payload().size());
        std::memcpy(payload.mutable_data(), ciphertext.encrypted_payload().data(), 
                   ciphertext.encrypted_payload().size());
        
        PlaintextRecord plaintext(ciphertext.header().content_type,
                                ciphertext.header().version,
                                ciphertext.header().epoch,
                                ciphertext.header().sequence_number,
                                std::move(payload));
        update_stats_unprotected();
        return Result<PlaintextRecord>(std::move(plaintext));
    }
    
    // Construct AEAD nonce
    auto nonce_result = construct_aead_nonce(record_epoch, 
                                           ciphertext.header().sequence_number,
                                           crypto_params.read_iv);
    if (!nonce_result.is_success()) {
        return Result<PlaintextRecord>(nonce_result.error());
    }
    
    // Construct additional authenticated data
    ConnectionID cid;
    if (ciphertext.has_connection_id()) {
        const auto& cid_array = ciphertext.connection_id();
        cid.assign(cid_array.begin(), cid_array.end());
    }
    
    auto aad_result = construct_additional_data(ciphertext.header(), cid);
    if (!aad_result.is_success()) {
        return Result<PlaintextRecord>(aad_result.error());
    }
    
    // Perform AEAD decryption
    crypto::AEADDecryptionParams decrypt_params;
    decrypt_params.key = crypto_params.read_key;
    decrypt_params.nonce = nonce_result.value();
    decrypt_params.additional_data = aad_result.value();
    decrypt_params.ciphertext = std::vector<uint8_t>(ciphertext.encrypted_payload().data(),
                                                    ciphertext.encrypted_payload().data() + 
                                                    ciphertext.encrypted_payload().size());
    decrypt_params.tag = std::vector<uint8_t>(ciphertext.authentication_tag().data(),
                                             ciphertext.authentication_tag().data() + 
                                             ciphertext.authentication_tag().size());
    
    auto decrypt_result = crypto_provider_->decrypt_aead(decrypt_params);
    if (!decrypt_result.is_success()) {
        update_stats_decryption_failed();
        return Result<PlaintextRecord>(decrypt_result.error());
    }
    
    const auto& plaintext_data = decrypt_result.value();
    
    // Create plaintext record
    memory::Buffer payload(plaintext_data.size());
    std::memcpy(payload.mutable_data(), plaintext_data.data(), plaintext_data.size());
    
    PlaintextRecord plaintext(ciphertext.header().content_type,
                            ciphertext.header().version,
                            ciphertext.header().epoch,
                            ciphertext.header().sequence_number,
                            std::move(payload));
    
    update_stats_unprotected();
    return Result<PlaintextRecord>(std::move(plaintext));
}

Result<PlaintextRecord> RecordLayer::process_incoming_record(const CiphertextRecord& ciphertext) {
    uint16_t record_epoch = ciphertext.header().epoch;
    uint64_t sequence_number = ciphertext.header().sequence_number;
    
    // Get or create anti-replay window for this epoch
    auto window_it = receive_windows_.find(record_epoch);
    if (window_it == receive_windows_.end()) {
        receive_windows_[record_epoch] = std::make_unique<AntiReplayWindow>();
        window_it = receive_windows_.find(record_epoch);
    }
    
    // Check for replay attack
    if (!window_it->second->is_valid_sequence_number(sequence_number)) {
        update_stats_replay_detected();
        return Result<PlaintextRecord>(DTLSError::REPLAY_ATTACK_DETECTED);
    }
    
    // Validate connection ID if present
    if (ciphertext.has_connection_id()) {
        const auto& cid_array = ciphertext.connection_id();
        ConnectionID cid(cid_array.begin(), cid_array.end());
        if (!connection_id_manager_->is_valid_connection_id(cid)) {
            return Result<PlaintextRecord>(DTLSError::INVALID_CONNECTION_ID);
        }
    }
    
    // Unprotect the record
    auto plaintext_result = unprotect_record(ciphertext);
    if (!plaintext_result.is_success()) {
        return plaintext_result;
    }
    
    // Mark sequence number as received (prevents replays)
    window_it->second->mark_received(sequence_number);
    
    update_stats_received();
    return plaintext_result;
}

Result<CiphertextRecord> RecordLayer::prepare_outgoing_record(const PlaintextRecord& plaintext) {
    // Get next sequence number
    uint64_t sequence_number = send_sequence_manager_->get_next_sequence_number();
    
    // Check for sequence number overflow
    if (send_sequence_manager_->would_overflow()) {
        return Result<CiphertextRecord>(DTLSError::SEQUENCE_NUMBER_OVERFLOW);
    }
    
    // Create record with assigned sequence number
    PlaintextRecord outgoing_record = plaintext;
    outgoing_record.set_sequence_number(sequence_number);
    outgoing_record.set_epoch(epoch_manager_->get_current_epoch());
    
    // Protect the record
    auto ciphertext_result = protect_record(outgoing_record);
    if (!ciphertext_result.is_success()) {
        return ciphertext_result;
    }
    
    update_stats_sent();
    return ciphertext_result;
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

RecordLayer::RecordLayerStats RecordLayer::get_stats() const {
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
// Utility Functions
// ============================================================================

namespace record_layer_utils {

std::unique_ptr<RecordLayer> create_test_record_layer() {
    // Create a mock crypto provider for testing
    auto crypto_provider = crypto::CryptoProviderFactory::create_provider("mock");
    if (!crypto_provider) {
        return nullptr;
    }
    
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

Result<std::vector<std::pair<PlaintextRecord, CiphertextRecord>>> 
generate_test_vectors(CipherSuite suite) {
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
    std::fill(auth_tag.mutable_data(), auth_tag.mutable_data() + 16, 0xAA);
    
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

} // namespace dtls::v13::protocol