#include <dtls/crypto/operations_impl.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/error.h>
#include <algorithm>
#include <chrono>
#include <unordered_set>
#include <iostream>

namespace dtls {
namespace v13 {
namespace crypto {

// === CryptoOperationsImpl Implementation ===

CryptoOperationsImpl::CryptoOperationsImpl(std::unique_ptr<CryptoProvider> provider)
    : provider_(std::move(provider))
    , provider_name_(provider_ ? provider_->name() : "")
    , initialized_(false) {
    if (provider_) {
        auto init_result = initialize_provider();
        if (init_result.is_success()) {
            initialized_ = true;
        }
    }
}

CryptoOperationsImpl::CryptoOperationsImpl(const std::string& provider_name)
    : provider_name_(provider_name.empty() ? "default" : provider_name)
    , initialized_(false) {
    
    auto& factory = ProviderFactory::instance();
    auto provider_result = provider_name.empty() ? 
        factory.create_default_provider() :
        factory.create_provider(provider_name);
    
    if (provider_result.is_success()) {
        provider_ = std::move(provider_result.value());
        provider_name_ = provider_->name();
        auto init_result = initialize_provider();
        if (init_result.is_success()) {
            initialized_ = true;
        }
    }
}

CryptoOperationsImpl::CryptoOperationsImpl(const ProviderSelection& criteria)
    : initialized_(false) {
    
    auto& factory = ProviderFactory::instance();
    
    // First try with specific provider if preferred_provider is set
    if (!criteria.preferred_provider.empty()) {
        auto provider_result = factory.create_provider(criteria.preferred_provider);
        if (provider_result.is_success()) {
            provider_ = std::move(provider_result.value());
            provider_name_ = provider_->name();
            auto init_result = initialize_provider();
            if (init_result.is_success()) {
                initialized_ = true;
                return;
            }
        }
    }
    
    // Fall back to trying available providers directly rather than best provider selection
    auto available_providers = factory.available_providers();
    for (const auto& provider_name : available_providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (provider_result.is_success()) {
            provider_ = std::move(provider_result.value());
            provider_name_ = provider_->name();
            auto init_result = initialize_provider();
            if (init_result.is_success()) {
                initialized_ = true;
                return;
            }
        }
    }
}

CryptoOperationsImpl::~CryptoOperationsImpl() {
    if (provider_ && initialized_) {
        provider_->cleanup();
    }
}

CryptoOperationsImpl::CryptoOperationsImpl(CryptoOperationsImpl&& other) noexcept
    : provider_(std::move(other.provider_))
    , provider_name_(std::move(other.provider_name_))
    , initialized_(other.initialized_) {
    other.initialized_ = false;
}

CryptoOperationsImpl& CryptoOperationsImpl::operator=(CryptoOperationsImpl&& other) noexcept {
    if (this != &other) {
        if (provider_ && initialized_) {
            provider_->cleanup();
        }
        
        provider_ = std::move(other.provider_);
        provider_name_ = std::move(other.provider_name_);
        initialized_ = other.initialized_;
        other.initialized_ = false;
    }
    return *this;
}

Result<void> CryptoOperationsImpl::initialize_provider() {
    if (!provider_) {
        return Result<void>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto init_result = provider_->initialize();
    if (!init_result.is_success()) {
        return init_result;
    }
    
    return Result<void>(/* success */);
}

// === Random Number Generation Operations ===

Result<std::vector<uint8_t>> CryptoOperationsImpl::generate_random(
    size_t length,
    const std::vector<uint8_t>& additional_entropy) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_random_params(length, additional_entropy);
    return provider_->generate_random(params);
}

Result<Random> CryptoOperationsImpl::generate_dtls_random() {
    auto random_bytes_result = generate_random(32);
    if (!random_bytes_result.is_success()) {
        return Result<Random>(random_bytes_result.error());
    }
    
    Random dtls_random;
    const auto& bytes = random_bytes_result.value();
    if (bytes.size() != 32) {
        return Result<Random>(DTLSError::INVALID_PARAMETER);
    }
    
    std::copy(bytes.begin(), bytes.end(), dtls_random.data());
    return Result<Random>(dtls_random);
}

Result<std::vector<uint8_t>> CryptoOperationsImpl::generate_session_id(size_t length) {
    return generate_random(length);
}

Result<ConnectionID> CryptoOperationsImpl::generate_connection_id(size_t length) {
    if (length == 0 || length > 255) {
        return Result<ConnectionID>(DTLSError::INVALID_PARAMETER);
    }
    
    auto random_result = generate_random(length);
    if (!random_result.is_success()) {
        return Result<ConnectionID>(random_result.error());
    }
    
    ConnectionID cid;
    cid = std::move(random_result.value());
    
    return Result<ConnectionID>(cid);
}

// === Key Derivation Operations ===

Result<std::vector<uint8_t>> CryptoOperationsImpl::hkdf_expand_label(
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& context,
    size_t length,
    HashAlgorithm hash_algo) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_key_derivation_params(secret, label, context, length, hash_algo);
    return provider_->derive_key_hkdf(params);
}

Result<KeySchedule> CryptoOperationsImpl::derive_traffic_keys(
    const std::vector<uint8_t>& master_secret,
    CipherSuite cipher_suite,
    const std::vector<uint8_t>& context) {
    
    if (!provider_ || !initialized_) {
        return Result<KeySchedule>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto cipher_spec_result = CipherSpec::from_cipher_suite(cipher_suite);
    if (!cipher_spec_result.is_success()) {
        return Result<KeySchedule>(cipher_spec_result.error());
    }
    
    const auto& spec = cipher_spec_result.value();
    KeySchedule schedule;
    
    // Derive client write key
    auto client_write_key_result = hkdf_expand_label(
        master_secret, "c ap traffic", context, spec.key_length, spec.hash_algorithm);
    if (!client_write_key_result.is_success()) {
        return Result<KeySchedule>(client_write_key_result.error());
    }
    schedule.client_write_key = std::move(client_write_key_result.value());
    
    // Derive server write key
    auto server_write_key_result = hkdf_expand_label(
        master_secret, "s ap traffic", context, spec.key_length, spec.hash_algorithm);
    if (!server_write_key_result.is_success()) {
        return Result<KeySchedule>(server_write_key_result.error());
    }
    schedule.server_write_key = std::move(server_write_key_result.value());
    
    // Derive client write IV
    auto client_write_iv_result = hkdf_expand_label(
        master_secret, "c ap iv", context, spec.iv_length, spec.hash_algorithm);
    if (!client_write_iv_result.is_success()) {
        return Result<KeySchedule>(client_write_iv_result.error());
    }
    schedule.client_write_iv = std::move(client_write_iv_result.value());
    
    // Derive server write IV
    auto server_write_iv_result = hkdf_expand_label(
        master_secret, "s ap iv", context, spec.iv_length, spec.hash_algorithm);
    if (!server_write_iv_result.is_success()) {
        return Result<KeySchedule>(server_write_iv_result.error());
    }
    schedule.server_write_iv = std::move(server_write_iv_result.value());
    
    // Derive sequence number keys
    auto client_sn_key_result = hkdf_expand_label(
        master_secret, "c sn", context, 16, spec.hash_algorithm);
    if (!client_sn_key_result.is_success()) {
        return Result<KeySchedule>(client_sn_key_result.error());
    }
    schedule.client_sequence_number_key = std::move(client_sn_key_result.value());
    
    auto server_sn_key_result = hkdf_expand_label(
        master_secret, "s sn", context, 16, spec.hash_algorithm);
    if (!server_sn_key_result.is_success()) {
        return Result<KeySchedule>(server_sn_key_result.error());
    }
    schedule.server_sequence_number_key = std::move(server_sn_key_result.value());
    
    return Result<KeySchedule>(schedule);
}

// === AEAD Encryption/Decryption Operations ===

Result<AEADEncryptionOutput> CryptoOperationsImpl::aead_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& additional_data,
    AEADCipher cipher) {
    
    if (!provider_ || !initialized_) {
        return Result<AEADEncryptionOutput>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_aead_encryption_params(plaintext, key, nonce, additional_data, cipher);
    return provider_->encrypt_aead(params);
}

Result<std::vector<uint8_t>> CryptoOperationsImpl::aead_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& additional_data,
    AEADCipher cipher) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_aead_decryption_params(ciphertext, tag, key, nonce, additional_data, cipher);
    return provider_->decrypt_aead(params);
}

// === Hash and HMAC Operations ===

Result<std::vector<uint8_t>> CryptoOperationsImpl::compute_hash(
    const std::vector<uint8_t>& data,
    HashAlgorithm algorithm) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_hash_params(data, algorithm);
    return provider_->compute_hash(params);
}

Result<std::vector<uint8_t>> CryptoOperationsImpl::compute_hmac(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    HashAlgorithm algorithm) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_hmac_params(key, data, algorithm);
    return provider_->compute_hmac(params);
}

Result<bool> CryptoOperationsImpl::verify_hmac(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& expected_mac,
    HashAlgorithm algorithm) {
    
    if (!provider_ || !initialized_) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_mac_validation_params(key, data, expected_mac, algorithm);
    return provider_->verify_hmac(params);
}

// === Digital Signature Operations ===

Result<std::vector<uint8_t>> CryptoOperationsImpl::sign_data(
    const std::vector<uint8_t>& data,
    const PrivateKey& private_key,
    SignatureScheme scheme) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_signature_params(data, scheme, &private_key);
    return provider_->sign_data(params);
}

Result<bool> CryptoOperationsImpl::verify_signature(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature,
    const PublicKey& public_key,
    SignatureScheme scheme) {
    
    if (!provider_ || !initialized_) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_signature_params(data, scheme, nullptr, &public_key);
    return provider_->verify_signature(params, signature);
}

Result<bool> CryptoOperationsImpl::verify_certificate_signature(
    const std::vector<uint8_t>& transcript_hash,
    const std::vector<uint8_t>& signature,
    const PublicKey& public_key,
    SignatureScheme scheme,
    bool is_server_context) {
    
    if (!provider_ || !initialized_) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_certificate_verify_params(transcript_hash, scheme, &public_key, is_server_context);
    return provider_->verify_dtls_certificate_signature(params, signature);
}

// === Key Exchange Operations ===

Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>
CryptoOperationsImpl::generate_key_pair(NamedGroup group) {
    
    if (!provider_ || !initialized_) {
        return Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return provider_->generate_key_pair(group);
}

Result<std::vector<uint8_t>> CryptoOperationsImpl::key_exchange(
    const PrivateKey& private_key,
    const std::vector<uint8_t>& peer_public_key,
    NamedGroup group) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_key_exchange_params(group, peer_public_key, &private_key);
    return provider_->perform_key_exchange(params);
}

// === Certificate Operations ===

Result<bool> CryptoOperationsImpl::validate_certificate_chain(
    const CertificateChain& chain,
    const std::vector<uint8_t>& root_ca_store,
    const std::string& hostname,
    bool check_revocation) {
    
    if (!provider_ || !initialized_) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    CertValidationParams params;
    params.chain = &chain;
    params.root_ca_store = root_ca_store;
    params.hostname = hostname;
    params.check_revocation = check_revocation;
    params.validation_time = std::chrono::system_clock::now();
    
    return provider_->validate_certificate_chain(params);
}

Result<std::unique_ptr<PublicKey>> CryptoOperationsImpl::extract_public_key(
    const std::vector<uint8_t>& certificate_der) {
    
    if (!provider_ || !initialized_) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return provider_->extract_public_key(certificate_der);
}

// === DTLS v1.3 Specific Operations ===

Result<std::vector<uint8_t>> CryptoOperationsImpl::encrypt_sequence_number(
    uint64_t sequence_number,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& sample) {
    
    if (!provider_ || !initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Use the crypto utilities for sequence number encryption
    // Stub implementation - RFC 9147 sequence number encryption
    // This would need proper implementation for production use
    std::vector<uint8_t> result(6, 0); // 48-bit sequence number = 6 bytes
    
    // Simple XOR with key for mock implementation
    if (!key.empty()) {
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] = static_cast<uint8_t>((sequence_number >> (i * 8)) & 0xFF) ^ 
                       (key[i % key.size()]);
        }
    }
    
    return Result<std::vector<uint8_t>>(result);
}

Result<uint64_t> CryptoOperationsImpl::decrypt_sequence_number(
    const std::vector<uint8_t>& encrypted_sequence_number,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& sample) {
    
    if (!provider_ || !initialized_) {
        return Result<uint64_t>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Use the crypto utilities for sequence number decryption
    // Stub implementation - RFC 9147 sequence number decryption
    // This would need proper implementation for production use
    if (encrypted_sequence_number.size() != 6) {
        return Result<uint64_t>(DTLSError::INVALID_PARAMETER);
    }
    
    uint64_t result = 0;
    
    // Simple XOR with key for mock implementation (reverse of encryption)
    if (!key.empty()) {
        for (size_t i = 0; i < encrypted_sequence_number.size(); ++i) {
            uint8_t decrypted_byte = encrypted_sequence_number[i] ^ (key[i % key.size()]);
            result |= (static_cast<uint64_t>(decrypted_byte) << (i * 8));
        }
    }
    
    return Result<uint64_t>(result & 0xFFFFFFFFFFFFULL); // Mask to 48 bits
}

Result<bool> CryptoOperationsImpl::validate_record_mac(
    const std::vector<uint8_t>& mac_key,
    const std::vector<uint8_t>& sequence_number_key,
    const std::vector<uint8_t>& record_header,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& expected_mac,
    ContentType content_type,
    Epoch epoch,
    SequenceNumber sequence_number) {
    
    if (!provider_ || !initialized_) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto params = create_record_mac_params(
        mac_key, sequence_number_key, record_header, plaintext, 
        expected_mac, content_type, epoch, sequence_number);
    
    return provider_->validate_record_mac(params);
}

// === Provider Information ===

std::string CryptoOperationsImpl::provider_name() const {
    return provider_name_;
}

ProviderCapabilities CryptoOperationsImpl::capabilities() const {
    if (!provider_ || !initialized_) {
        return ProviderCapabilities{};
    }
    return provider_->capabilities();
}

bool CryptoOperationsImpl::supports_cipher_suite(CipherSuite cipher_suite) const {
    if (!provider_ || !initialized_) {
        return false;
    }
    return provider_->supports_cipher_suite(cipher_suite);
}

bool CryptoOperationsImpl::supports_named_group(NamedGroup group) const {
    if (!provider_ || !initialized_) {
        return false;
    }
    return provider_->supports_named_group(group);
}

bool CryptoOperationsImpl::supports_signature_scheme(SignatureScheme scheme) const {
    if (!provider_ || !initialized_) {
        return false;
    }
    return provider_->supports_signature_scheme(scheme);
}

// === Helper Methods ===

RandomParams CryptoOperationsImpl::create_random_params(size_t length, const std::vector<uint8_t>& entropy) {
    RandomParams params;
    params.length = length;
    params.cryptographically_secure = true;
    params.additional_entropy = entropy;
    return params;
}

KeyDerivationParams CryptoOperationsImpl::create_key_derivation_params(
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& context,
    size_t length,
    HashAlgorithm hash_algo) {
    
    KeyDerivationParams params;
    params.secret = secret;
    params.output_length = length;
    params.hash_algorithm = hash_algo;
    
    // Create HKDF-Expand-Label info structure
    std::vector<uint8_t> info;
    
    // Length (2 bytes, big-endian)
    info.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    info.push_back(static_cast<uint8_t>(length & 0xFF));
    
    // Label length + "tls13 " + label
    std::string full_label = "tls13 " + label;
    info.push_back(static_cast<uint8_t>(full_label.length()));
    info.insert(info.end(), full_label.begin(), full_label.end());
    
    // Context length + context
    info.push_back(static_cast<uint8_t>(context.size()));
    info.insert(info.end(), context.begin(), context.end());
    
    params.info = std::move(info);
    return params;
}

AEADEncryptionParams CryptoOperationsImpl::create_aead_encryption_params(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& additional_data,
    AEADCipher cipher) {
    
    AEADEncryptionParams params;
    params.plaintext = plaintext;
    params.key = key;
    params.nonce = nonce;
    params.additional_data = additional_data;
    params.cipher = cipher;
    return params;
}

AEADDecryptionParams CryptoOperationsImpl::create_aead_decryption_params(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& additional_data,
    AEADCipher cipher) {
    
    AEADDecryptionParams params;
    params.ciphertext = ciphertext;
    params.tag = tag;
    params.key = key;
    params.nonce = nonce;
    params.additional_data = additional_data;
    params.cipher = cipher;
    return params;
}

HashParams CryptoOperationsImpl::create_hash_params(const std::vector<uint8_t>& data, HashAlgorithm algorithm) {
    HashParams params;
    params.data = data;
    params.algorithm = algorithm;
    return params;
}

HMACParams CryptoOperationsImpl::create_hmac_params(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    HashAlgorithm algorithm) {
    
    HMACParams params;
    params.key = key;
    params.data = data;
    params.algorithm = algorithm;
    return params;
}

MACValidationParams CryptoOperationsImpl::create_mac_validation_params(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& expected_mac,
    HashAlgorithm algorithm) {
    
    MACValidationParams params;
    params.key = key;
    params.data = data;
    params.expected_mac = expected_mac;
    params.algorithm = algorithm;
    params.constant_time_required = true;
    return params;
}

SignatureParams CryptoOperationsImpl::create_signature_params(
    const std::vector<uint8_t>& data,
    SignatureScheme scheme,
    const PrivateKey* private_key,
    const PublicKey* public_key) {
    
    SignatureParams params;
    params.data = data;
    params.scheme = scheme;
    params.private_key = private_key;
    params.public_key = public_key;
    return params;
}

KeyExchangeParams CryptoOperationsImpl::create_key_exchange_params(
    NamedGroup group,
    const std::vector<uint8_t>& peer_public_key,
    const PrivateKey* private_key) {
    
    KeyExchangeParams params;
    params.group = group;
    params.peer_public_key = peer_public_key;
    params.private_key = private_key;
    return params;
}

DTLSCertificateVerifyParams CryptoOperationsImpl::create_certificate_verify_params(
    const std::vector<uint8_t>& transcript_hash,
    SignatureScheme scheme,
    const PublicKey* public_key,
    bool is_server_context) {
    
    DTLSCertificateVerifyParams params;
    params.transcript_hash = transcript_hash;
    params.scheme = scheme;
    params.public_key = public_key;
    params.is_server_context = is_server_context;
    return params;
}

RecordMACParams CryptoOperationsImpl::create_record_mac_params(
    const std::vector<uint8_t>& mac_key,
    const std::vector<uint8_t>& sequence_number_key,
    const std::vector<uint8_t>& record_header,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& expected_mac,
    ContentType content_type,
    Epoch epoch,
    SequenceNumber sequence_number) {
    
    RecordMACParams params;
    params.mac_key = mac_key;
    params.sequence_number_key = sequence_number_key;
    params.record_header = record_header;
    params.plaintext = plaintext;
    params.expected_mac = expected_mac;
    params.mac_algorithm = HashAlgorithm::SHA256;
    params.content_type = content_type;
    params.epoch = epoch;
    params.sequence_number = sequence_number;
    return params;
}

// === MockCryptoOperations Implementation ===

MockCryptoOperations::MockCryptoOperations()
    : mock_random_bytes_(32, 0x42)  // Default 32 bytes of 0x42
    , mock_hash_result_(32, 0xAB)   // Default hash result
    , mock_hmac_result_(32, 0xCD)   // Default HMAC result
    , mock_signature_result_(64, 0xEF) // Default signature
    , mock_key_exchange_result_(32, 0x12) // Default shared secret
    , mock_aead_ciphertext_(32, 0x34) // Default ciphertext
    , mock_aead_tag_(16, 0x56)      // Default authentication tag
    , mock_aead_plaintext_(32, 0x78) // Default plaintext
    , mock_verification_result_(true) {
}

void MockCryptoOperations::set_random_bytes(const std::vector<uint8_t>& bytes) {
    mock_random_bytes_ = bytes;
}

void MockCryptoOperations::set_hash_result(const std::vector<uint8_t>& hash) {
    mock_hash_result_ = hash;
}

void MockCryptoOperations::set_hmac_result(const std::vector<uint8_t>& hmac) {
    mock_hmac_result_ = hmac;
}

void MockCryptoOperations::set_signature_result(const std::vector<uint8_t>& signature) {
    mock_signature_result_ = signature;
}

void MockCryptoOperations::set_key_exchange_result(const std::vector<uint8_t>& shared_secret) {
    mock_key_exchange_result_ = shared_secret;
}

void MockCryptoOperations::set_verification_result(bool result) {
    mock_verification_result_ = result;
}

void MockCryptoOperations::set_aead_encryption_result(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag) {
    mock_aead_ciphertext_ = ciphertext;
    mock_aead_tag_ = tag;
}

void MockCryptoOperations::set_aead_decryption_result(const std::vector<uint8_t>& plaintext) {
    mock_aead_plaintext_ = plaintext;
}

void MockCryptoOperations::reset_call_counts() {
    random_call_count_ = 0;
    hash_call_count_ = 0;
    hmac_call_count_ = 0;
    signature_call_count_ = 0;
    verification_call_count_ = 0;
    aead_encrypt_call_count_ = 0;
    aead_decrypt_call_count_ = 0;
}

// Mock implementations (abbreviated for brevity - each method increments counters and returns mocked results)
Result<std::vector<uint8_t>> MockCryptoOperations::generate_random(size_t length, const std::vector<uint8_t>&) {
    ++random_call_count_;
    std::vector<uint8_t> result(length);
    for (size_t i = 0; i < length && i < mock_random_bytes_.size(); ++i) {
        result[i] = mock_random_bytes_[i % mock_random_bytes_.size()];
    }
    return Result<std::vector<uint8_t>>(result);
}

Result<Random> MockCryptoOperations::generate_dtls_random() {
    ++random_call_count_;
    Random dtls_random;
    for (size_t i = 0; i < 32; ++i) {
        dtls_random.data()[i] = mock_random_bytes_[i % mock_random_bytes_.size()];
    }
    return Result<Random>(dtls_random);
}

Result<std::vector<uint8_t>> MockCryptoOperations::generate_session_id(size_t length) {
    return generate_random(length);
}

Result<ConnectionID> MockCryptoOperations::generate_connection_id(size_t length) {
    auto random_result = generate_random(length);
    if (!random_result.is_success()) {
        return Result<ConnectionID>(random_result.error());
    }
    
    ConnectionID cid;
    cid = std::move(random_result.value());
    return Result<ConnectionID>(cid);
}

// Continue with other mock implementations...
// (For brevity, I'll implement key methods and indicate where others follow the same pattern)

Result<std::vector<uint8_t>> MockCryptoOperations::compute_hash(const std::vector<uint8_t>&, HashAlgorithm) {
    ++hash_call_count_;
    return Result<std::vector<uint8_t>>(mock_hash_result_);
}

Result<std::vector<uint8_t>> MockCryptoOperations::compute_hmac(const std::vector<uint8_t>&, const std::vector<uint8_t>&, HashAlgorithm) {
    ++hmac_call_count_;
    return Result<std::vector<uint8_t>>(mock_hmac_result_);
}

Result<bool> MockCryptoOperations::verify_hmac(const std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&, HashAlgorithm) {
    ++verification_call_count_;
    return Result<bool>(mock_verification_result_);
}

Result<AEADEncryptionOutput> MockCryptoOperations::aead_encrypt(const std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&, AEADCipher) {
    ++aead_encrypt_call_count_;
    AEADEncryptionOutput output;
    output.ciphertext = mock_aead_ciphertext_;
    output.tag = mock_aead_tag_;
    return Result<AEADEncryptionOutput>(output);
}

Result<std::vector<uint8_t>> MockCryptoOperations::aead_decrypt(const std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&, AEADCipher) {
    ++aead_decrypt_call_count_;
    return Result<std::vector<uint8_t>>(mock_aead_plaintext_);
}

ProviderCapabilities MockCryptoOperations::capabilities() const {
    ProviderCapabilities caps;
    caps.provider_name = "Mock";
    caps.provider_version = "1.0.0";
    caps.hardware_acceleration = false;
    caps.fips_mode = false;
    
    // Add all supported cipher suites, groups, signatures, hashes
    caps.supported_cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    caps.supported_groups = {
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::X25519
    };
    caps.supported_signatures = {
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ED25519
    };
    caps.supported_hashes = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512
    };
    
    return caps;
}

// Additional mock method implementations

Result<std::vector<uint8_t>> MockCryptoOperations::hkdf_expand_label(
    const std::vector<uint8_t>& secret, const std::string& label, 
    const std::vector<uint8_t>& context, size_t length, HashAlgorithm) {
    return generate_random(length);
}

Result<KeySchedule> MockCryptoOperations::derive_traffic_keys(
    const std::vector<uint8_t>& master_secret, CipherSuite cipher_suite, 
    const std::vector<uint8_t>& context) {
    KeySchedule schedule;
    schedule.client_write_key = std::vector<uint8_t>(16, 0xAA);
    schedule.server_write_key = std::vector<uint8_t>(16, 0xBB);
    schedule.client_write_iv = std::vector<uint8_t>(12, 0xCC);
    schedule.server_write_iv = std::vector<uint8_t>(12, 0xDD);
    schedule.client_sequence_number_key = std::vector<uint8_t>(16, 0xEE);
    schedule.server_sequence_number_key = std::vector<uint8_t>(16, 0xFF);
    return Result<KeySchedule>(schedule);
}

Result<std::vector<uint8_t>> MockCryptoOperations::sign_data(
    const std::vector<uint8_t>&, const PrivateKey&, SignatureScheme) {
    ++signature_call_count_;
    return Result<std::vector<uint8_t>>(mock_signature_result_);
}

Result<bool> MockCryptoOperations::verify_signature(
    const std::vector<uint8_t>&, const std::vector<uint8_t>&,
    const PublicKey&, SignatureScheme) {
    ++verification_call_count_;
    return Result<bool>(mock_verification_result_);
}

Result<bool> MockCryptoOperations::verify_certificate_signature(
    const std::vector<uint8_t>&, const std::vector<uint8_t>&,
    const PublicKey&, SignatureScheme, bool) {
    ++verification_call_count_;
    return Result<bool>(mock_verification_result_);
}

Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>
MockCryptoOperations::generate_key_pair(NamedGroup) {
    // Return null pointers for mock - would need mock key classes for full implementation
    return Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>(
        DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<std::vector<uint8_t>> MockCryptoOperations::key_exchange(
    const PrivateKey&, const std::vector<uint8_t>&, NamedGroup) {
    return Result<std::vector<uint8_t>>(mock_key_exchange_result_);
}

Result<bool> MockCryptoOperations::validate_certificate_chain(
    const CertificateChain&, const std::vector<uint8_t>&, 
    const std::string&, bool) {
    return Result<bool>(mock_verification_result_);
}

Result<std::unique_ptr<PublicKey>> MockCryptoOperations::extract_public_key(
    const std::vector<uint8_t>&) {
    // Return null pointer for mock - would need mock key classes for full implementation
    return Result<std::unique_ptr<PublicKey>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<std::vector<uint8_t>> MockCryptoOperations::encrypt_sequence_number(
    uint64_t sequence_number, const std::vector<uint8_t>&, const std::vector<uint8_t>&) {
    // Return the sequence number as bytes for mock
    std::vector<uint8_t> result(8);
    for (int i = 7; i >= 0; --i) {
        result[7 - i] = static_cast<uint8_t>((sequence_number >> (i * 8)) & 0xFF);
    }
    return Result<std::vector<uint8_t>>(result);
}

Result<uint64_t> MockCryptoOperations::decrypt_sequence_number(
    const std::vector<uint8_t>& encrypted_sequence_number, 
    const std::vector<uint8_t>&, const std::vector<uint8_t>&) {
    // Convert bytes back to sequence number for mock
    if (encrypted_sequence_number.size() < 8) {
        return Result<uint64_t>(DTLSError::INVALID_PARAMETER);
    }
    
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= (static_cast<uint64_t>(encrypted_sequence_number[i]) << ((7 - i) * 8));
    }
    return Result<uint64_t>(result);
}

Result<bool> MockCryptoOperations::validate_record_mac(
    const std::vector<uint8_t>&, const std::vector<uint8_t>&,
    const std::vector<uint8_t>&, const std::vector<uint8_t>&,
    const std::vector<uint8_t>&, ContentType, Epoch, SequenceNumber) {
    ++verification_call_count_;
    return Result<bool>(mock_verification_result_);
}

// === Factory Implementation ===

CryptoOperationsFactory& CryptoOperationsFactory::instance() {
    static CryptoOperationsFactory factory;
    return factory;
}

Result<std::unique_ptr<ICryptoOperations>> 
CryptoOperationsFactory::create_operations(const std::string& provider_name) {
    
    auto impl = std::make_unique<CryptoOperationsImpl>(provider_name);
    if (impl && !impl->provider_name().empty()) {
        factory_stats_.total_created++;
        return Result<std::unique_ptr<ICryptoOperations>>(std::move(impl));
    }
    
    return Result<std::unique_ptr<ICryptoOperations>>(DTLSError::CRYPTO_PROVIDER_ERROR);
}

Result<std::unique_ptr<ICryptoOperations>>
CryptoOperationsFactory::create_operations(const ProviderSelection& criteria) {
    
    auto impl = std::make_unique<CryptoOperationsImpl>(criteria);
    if (impl && !impl->provider_name().empty()) {
        factory_stats_.total_created++;
        return Result<std::unique_ptr<ICryptoOperations>>(std::move(impl));
    }
    
    return Result<std::unique_ptr<ICryptoOperations>>(DTLSError::CRYPTO_PROVIDER_ERROR);
}

std::unique_ptr<ICryptoOperations> CryptoOperationsFactory::create_mock_operations() {
    factory_stats_.mock_created++;
    factory_stats_.total_created++;
    return std::make_unique<MockCryptoOperations>();
}

// === CryptoOperationsManager Implementation ===

CryptoOperationsManager::CryptoOperationsManager(const ProviderSelection& criteria)
    : selection_criteria_(criteria)
    , creation_time_(std::chrono::steady_clock::now()) {
    initialize_best_operations(criteria);
}

CryptoOperationsManager::CryptoOperationsManager(const std::string& provider_name)
    : current_provider_name_(provider_name)
    , creation_time_(std::chrono::steady_clock::now()) {
    initialize_operations(provider_name);
}

CryptoOperationsManager::~CryptoOperationsManager() {
    cleanup_current_operations();
}

CryptoOperationsManager::CryptoOperationsManager(CryptoOperationsManager&& other) noexcept
    : current_operations_(std::move(other.current_operations_))
    , current_provider_name_(std::move(other.current_provider_name_))
    , fallback_providers_(std::move(other.fallback_providers_))
    , selection_criteria_(std::move(other.selection_criteria_))
    , creation_time_(other.creation_time_) {
}

CryptoOperationsManager& CryptoOperationsManager::operator=(CryptoOperationsManager&& other) noexcept {
    if (this != &other) {
        cleanup_current_operations();
        current_operations_ = std::move(other.current_operations_);
        current_provider_name_ = std::move(other.current_provider_name_);
        fallback_providers_ = std::move(other.fallback_providers_);
        selection_criteria_ = std::move(other.selection_criteria_);
        creation_time_ = other.creation_time_;
    }
    return *this;
}

void CryptoOperationsManager::initialize_operations(const std::string& name) {
    auto& factory = CryptoOperationsFactory::instance();
    auto result = factory.create_operations(name);
    if (result.is_success()) {
        current_operations_ = std::move(result.value());
        current_provider_name_ = current_operations_->provider_name();
    }
}

void CryptoOperationsManager::initialize_best_operations(const ProviderSelection& criteria) {
    auto& factory = CryptoOperationsFactory::instance();
    
    // Try to create operations with criteria - but fallback to default if it fails
    auto result = factory.create_operations(criteria);
    if (!result.is_success()) {
        // Fallback to creating default operations if criteria-based creation fails
        result = factory.create_operations("");
    }
    
    if (result.is_success()) {
        current_operations_ = std::move(result.value());
        current_provider_name_ = current_operations_->provider_name();
    }
}

void CryptoOperationsManager::cleanup_current_operations() {
    current_operations_.reset();
}

std::string CryptoOperationsManager::current_provider_name() const {
    return current_provider_name_;
}

ProviderCapabilities CryptoOperationsManager::current_capabilities() const {
    if (current_operations_) {
        return current_operations_->capabilities();
    }
    return ProviderCapabilities{};
}

ICryptoOperations* CryptoOperationsManager::get() const {
    return current_operations_.get();
}

ICryptoOperations* CryptoOperationsManager::operator->() const {
    return current_operations_.get();
}

ICryptoOperations& CryptoOperationsManager::operator*() const {
    return *current_operations_;
}

// === Utility Functions ===

Result<std::unique_ptr<ICryptoOperations>> create_crypto_operations(const std::string& provider_name) {
    return CryptoOperationsFactory::instance().create_operations(provider_name);
}

Result<std::unique_ptr<ICryptoOperations>> create_best_crypto_operations(const ProviderSelection& criteria) {
    return CryptoOperationsFactory::instance().create_operations(criteria);
}

std::unique_ptr<ICryptoOperations> create_mock_crypto_operations() {
    return CryptoOperationsFactory::instance().create_mock_operations();
}

ICryptoOperationsFactory& get_crypto_current_operations_factory() {
    return CryptoOperationsFactory::instance();
}

// ===== Enhanced CryptoOperationsFactory Implementation =====

CryptoOperationsFactory::CryptoOperationsFactory() {
    factory_stats_.creation_start_time = std::chrono::steady_clock::now();
    
    // Start cache cleanup thread
    cache_cleanup_thread_ = std::thread([this] {
        while (!cleanup_shutdown_requested_) {
            std::unique_lock<std::mutex> lock(cleanup_mutex_);
            cleanup_cv_.wait_for(lock, std::chrono::minutes(5), 
                [this] { return cleanup_shutdown_requested_.load(); });
            if (!cleanup_shutdown_requested_) {
                cleanup_expired_cache_entries();
            }
        }
    });
}

CryptoOperationsFactory::~CryptoOperationsFactory() {
    cleanup_shutdown_requested_ = true;
    cleanup_cv_.notify_all();
    if (cache_cleanup_thread_.joinable()) {
        cache_cleanup_thread_.join();
    }
}

Result<std::unique_ptr<ICryptoOperations>>
CryptoOperationsFactory::create_cached_operations(const std::string& provider_name) {
    if (!caching_enabled_) {
        return create_operations(provider_name);
    }
    
    ProviderSelection criteria;
    criteria.preferred_provider = provider_name;
    std::string cache_key = generate_cache_key(provider_name, criteria);
    
    {
        std::shared_lock<std::shared_mutex> lock(factory_mutex_);
        auto it = operation_cache_.find(cache_key);
        if (it != operation_cache_.end()) {
            it->second.last_used = std::chrono::steady_clock::now();
            it->second.use_count++;
            cache_hit_count_++;
            
            // Create a new instance based on the cached one
            return create_operations(provider_name);
        }
    }
    
    cache_miss_count_++;
    auto result = create_operations(provider_name);
    if (result.is_success()) {
        std::unique_lock<std::shared_mutex> lock(factory_mutex_);
        if (operation_cache_.size() >= cache_size_limit_) {
            cleanup_expired_cache_entries();
        }
        
        factory_stats_.cached_created++;
        
        // Note: We don't actually cache the operations themselves due to
        // thread safety concerns. Instead, we cache the fact that this
        // configuration works and can be quickly recreated.
        CachedOperations cached;
        cached.created_time = std::chrono::steady_clock::now();
        cached.last_used = cached.created_time;
        cached.use_count = 1;
        operation_cache_[cache_key] = std::move(cached);
    }
    
    return result;
}

std::unique_ptr<AgnosticCryptoOperations>
CryptoOperationsFactory::create_agnostic_operations(
    const ProviderSelection& default_criteria,
    bool enable_per_operation_selection) {
    
    factory_stats_.agnostic_created++;
    factory_stats_.total_created++;
    
    return std::make_unique<AgnosticCryptoOperations>(
        default_criteria, enable_per_operation_selection);
}

Result<std::unique_ptr<ICryptoOperations>>
CryptoOperationsFactory::create_pooled_operations(const ProviderPoolConfig& pool_config) {
    factory_stats_.pooled_created++;
    factory_stats_.total_created++;
    
    // For now, create a simple implementation - in production this would create
    // a pool-managed operations instance
    return create_operations("");
}

Result<std::unique_ptr<ICryptoOperations>>
CryptoOperationsFactory::create_resilient_operations(
    const ProviderSelection& criteria,
    const std::vector<std::string>& fallback_providers) {
    
    factory_stats_.resilient_created++;
    factory_stats_.total_created++;
    
    // For now, create a simple implementation - in production this would create
    // a resilient operations instance with automatic failover
    return create_operations(criteria);
}

void CryptoOperationsFactory::clear_operation_cache() {
    std::unique_lock<std::shared_mutex> lock(factory_mutex_);
    operation_cache_.clear();
    cache_hit_count_ = 0;
    cache_miss_count_ = 0;
}

double CryptoOperationsFactory::get_cache_hit_rate() const {
    auto hits = cache_hit_count_.load();
    auto misses = cache_miss_count_.load();
    if (hits + misses == 0) return 0.0;
    return static_cast<double>(hits) / (hits + misses);
}

void CryptoOperationsFactory::reset_factory_stats() {
    factory_stats_ = FactoryStats{};
    factory_stats_.creation_start_time = std::chrono::steady_clock::now();
}

std::string CryptoOperationsFactory::generate_cache_key(
    const std::string& provider_name, 
    const ProviderSelection& criteria) const {
    
    std::string key = provider_name + "|";
    key += std::to_string(static_cast<int>(criteria.minimum_security_level)) + "|";
    key += (criteria.require_hardware_acceleration ? "1" : "0");
    key += "|";
    key += (criteria.require_fips_compliance ? "1" : "0");
    key += "|";
    
    // Add cipher suites
    for (auto suite : criteria.required_cipher_suites) {
        key += std::to_string(static_cast<int>(suite)) + ",";
    }
    key += "|";
    
    // Add named groups
    for (auto group : criteria.required_groups) {
        key += std::to_string(static_cast<int>(group)) + ",";
    }
    key += "|";
    
    // Add signature schemes
    for (auto scheme : criteria.required_signatures) {
        key += std::to_string(static_cast<int>(scheme)) + ",";
    }
    
    return key;
}

void CryptoOperationsFactory::cleanup_expired_cache_entries() {
    std::unique_lock<std::shared_mutex> lock(factory_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = operation_cache_.begin();
    
    while (it != operation_cache_.end()) {
        if (now - it->second.last_used > cache_expiry_time_) {
            it = operation_cache_.erase(it);
        } else {
            ++it;
        }
    }
}

// ===== ProviderCapabilityMatcher Implementation =====

Result<std::string> ProviderCapabilityMatcher::find_best_provider(
    const ProviderSelection& criteria) {
    
    auto& factory = ProviderFactory::instance();
    auto available_providers = factory.available_providers();
    
    if (available_providers.empty()) {
        return Result<std::string>(DTLSError::CRYPTO_PROVIDER_NOT_AVAILABLE);
    }
    
    std::string best_provider;
    double best_score = -1.0;
    
    for (const auto& provider_name : available_providers) {
        auto capabilities_result = factory.get_capabilities(provider_name);
        if (!capabilities_result.is_success()) {
            continue;
        }
        
        auto capabilities = capabilities_result.value();
        if (!meets_basic_requirements(capabilities, criteria)) {
            continue;
        }
        
        double score = calculate_compatibility_score(capabilities, criteria);
        if (score > best_score) {
            best_score = score;
            best_provider = provider_name;
        }
    }
    
    if (best_provider.empty()) {
        return Result<std::string>(DTLSError::CRYPTO_PROVIDER_NOT_AVAILABLE);
    }
    
    return Result<std::string>(best_provider);
}

double ProviderCapabilityMatcher::calculate_compatibility_score(
    const ProviderCapabilities& capabilities,
    const ProviderSelection& criteria) {
    
    if (!meets_basic_requirements(capabilities, criteria)) {
        return 0.0;
    }
    
    double score = 0.5; // Base score for meeting basic requirements
    
    // Add feature score
    score += 0.3 * calculate_feature_score(capabilities, criteria);
    
    // Add performance score
    score += 0.2 * calculate_performance_score(capabilities, criteria);
    
    return std::min(1.0, score);
}

bool ProviderCapabilityMatcher::meets_basic_requirements(
    const ProviderCapabilities& capabilities,
    const ProviderSelection& criteria) {
    
    // Check hardware acceleration requirement
    if (criteria.require_hardware_acceleration && !capabilities.hardware_acceleration) {
        return false;
    }
    
    // Check FIPS compliance requirement
    if (criteria.require_fips_compliance && !capabilities.fips_mode) {
        return false;
    }
    
    // Check cipher suite support
    for (auto required_suite : criteria.required_cipher_suites) {
        auto it = std::find(capabilities.supported_cipher_suites.begin(),
                           capabilities.supported_cipher_suites.end(), required_suite);
        if (it == capabilities.supported_cipher_suites.end()) {
            return false;
        }
    }
    
    // Check named group support
    for (auto required_group : criteria.required_groups) {
        auto it = std::find(capabilities.supported_groups.begin(),
                           capabilities.supported_groups.end(), required_group);
        if (it == capabilities.supported_groups.end()) {
            return false;
        }
    }
    
    // Check signature scheme support
    for (auto required_signature : criteria.required_signatures) {
        auto it = std::find(capabilities.supported_signatures.begin(),
                           capabilities.supported_signatures.end(), required_signature);
        if (it == capabilities.supported_signatures.end()) {
            return false;
        }
    }
    
    return true;
}

double ProviderCapabilityMatcher::calculate_feature_score(
    const ProviderCapabilities& capabilities,
    const ProviderSelection& criteria) {
    
    double feature_score = 0.0;
    
    // Bonus for hardware acceleration
    if (capabilities.hardware_acceleration) {
        feature_score += 0.3;
    }
    
    // Bonus for FIPS compliance
    if (capabilities.fips_mode) {
        feature_score += 0.2;
    }
    
    // Bonus for supporting more cipher suites than required
    if (!criteria.required_cipher_suites.empty()) {
        double support_ratio = static_cast<double>(capabilities.supported_cipher_suites.size()) / 
                              criteria.required_cipher_suites.size();
        feature_score += 0.25 * std::min(1.0, support_ratio);
    }
    
    // Bonus for provider maturity (based on provider name)
    if (capabilities.provider_name == "OpenSSL" || capabilities.provider_name == "Botan") {
        feature_score += 0.25;
    }
    
    return std::min(1.0, feature_score);
}

double ProviderCapabilityMatcher::calculate_performance_score(
    const ProviderCapabilities& capabilities,
    const ProviderSelection& criteria) {
    
    // This is a simplified performance score
    // In a real implementation, this would consider actual benchmark data
    
    double performance_score = 0.5; // Default score
    
    // Hardware acceleration provides significant performance boost
    if (capabilities.hardware_acceleration) {
        performance_score += 0.4;
    }
    
    // Well-known providers typically have better performance
    if (capabilities.provider_name == "OpenSSL") {
        performance_score += 0.1;
    }
    
    return std::min(1.0, performance_score);
}

Result<ProviderCompatibilityResult> ProviderCapabilityMatcher::check_compatibility(
    const std::string& provider_name,
    const ProviderSelection& criteria) {
    
    auto& factory = ProviderFactory::instance();
    auto capabilities_result = factory.get_capabilities(provider_name);
    if (!capabilities_result.is_success()) {
        return Result<ProviderCompatibilityResult>(capabilities_result.error());
    }
    
    auto capabilities = capabilities_result.value();
    ProviderCompatibilityResult result;
    
    result.is_compatible = meets_basic_requirements(capabilities, criteria);
    result.compatibility_score = calculate_compatibility_score(capabilities, criteria);
    
    // Check missing features
    for (auto suite : criteria.required_cipher_suites) {
        auto it = std::find(capabilities.supported_cipher_suites.begin(),
                           capabilities.supported_cipher_suites.end(), suite);
        if (it == capabilities.supported_cipher_suites.end()) {
            result.missing_features.push_back("Cipher suite: " + std::to_string(static_cast<int>(suite)));
        }
    }
    
    for (auto group : criteria.required_groups) {
        auto it = std::find(capabilities.supported_groups.begin(),
                           capabilities.supported_groups.end(), group);
        if (it == capabilities.supported_groups.end()) {
            result.missing_features.push_back("Named group: " + std::to_string(static_cast<int>(group)));
        }
    }
    
    for (auto sig : criteria.required_signatures) {
        auto it = std::find(capabilities.supported_signatures.begin(),
                           capabilities.supported_signatures.end(), sig);
        if (it == capabilities.supported_signatures.end()) {
            result.missing_features.push_back("Signature scheme: " + std::to_string(static_cast<int>(sig)));
        }
    }
    
    // Add warnings and recommendations based on compatibility
    if (result.compatibility_score < 0.7) {
        result.warnings.push_back("Low compatibility score");
    }
    
    if (!capabilities.hardware_acceleration && criteria.require_hardware_acceleration) {
        result.warnings.push_back("Hardware acceleration not available");
    }
    
    if (!capabilities.fips_mode && criteria.require_fips_compliance) {
        result.warnings.push_back("FIPS compliance not available");
    }
    
    if (result.compatibility_score > 0.8) {
        result.recommendations.push_back("Excellent compatibility - recommended for use");
    } else if (result.compatibility_score > 0.6) {
        result.recommendations.push_back("Good compatibility - suitable for most use cases");
    } else {
        result.recommendations.push_back("Limited compatibility - consider alternative provider");
    }
    
    return Result<ProviderCompatibilityResult>(std::move(result));
}

std::vector<std::pair<std::string, double>> ProviderCapabilityMatcher::rank_providers(
    const ProviderSelection& criteria) {
    
    auto& factory = ProviderFactory::instance();
    auto available_providers = factory.available_providers();
    
    std::vector<std::pair<std::string, double>> ranked_providers;
    
    for (const auto& provider_name : available_providers) {
        auto capabilities_result = factory.get_capabilities(provider_name);
        if (!capabilities_result.is_success()) {
            continue;
        }
        
        auto capabilities = capabilities_result.value();
        double score = calculate_compatibility_score(capabilities, criteria);
        ranked_providers.emplace_back(provider_name, score);
    }
    
    // Sort by score (descending)
    std::sort(ranked_providers.begin(), ranked_providers.end(),
              [](const auto& a, const auto& b) {
                  return a.second > b.second;
              });
    
    return ranked_providers;
}

// ===== AgnosticCryptoOperations Implementation =====

AgnosticCryptoOperations::AgnosticCryptoOperations(
    const ProviderSelection& default_criteria,
    bool enable_per_operation_selection)
    : default_criteria_(default_criteria),
      enable_per_operation_selection_(enable_per_operation_selection),
      last_cache_refresh_(std::chrono::steady_clock::now()) {
    
    refresh_provider_cache();
}

AgnosticCryptoOperations::~AgnosticCryptoOperations() {
    // Cleanup will be handled by unique_ptr destructors
}

Result<ICryptoOperations*> AgnosticCryptoOperations::get_best_provider_for_operation(
    const std::string& operation_category,
    const std::function<bool(const ProviderCapabilities&)>& capability_checker) {
    
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    
    ProviderSelection criteria = default_criteria_;
    
    // Check for operation-specific criteria
    auto it = operation_criteria_.find(operation_category);
    if (it != operation_criteria_.end()) {
        criteria = it->second;
    }
    
    // Find the best provider for this operation
    auto current_provider_name_result = ProviderCapabilityMatcher::find_best_provider(criteria);
    if (!current_provider_name_result.is_success()) {
        return Result<ICryptoOperations*>(current_provider_name_result.error());
    }
    
    std::string provider_name = current_provider_name_result.value();
    
    // Check if we already have this provider cached
    auto cache_it = provider_cache_.find(provider_name);
    if (cache_it != provider_cache_.end()) {
        provider_usage_count_[provider_name]++;
        return Result<ICryptoOperations*>(cache_it->second.get());
    }
    
    // Create new provider (this requires upgrading to exclusive lock)
    lock.unlock();
    std::unique_lock<std::shared_mutex> exclusive_lock(cache_mutex_);
    
    // Double-check after acquiring exclusive lock
    cache_it = provider_cache_.find(provider_name);
    if (cache_it != provider_cache_.end()) {
        provider_usage_count_[provider_name]++;
        return Result<ICryptoOperations*>(cache_it->second.get());
    }
    
    // Create new crypto operations for this provider
    auto& factory = CryptoOperationsFactory::instance();
    auto ops_result = factory.create_operations(provider_name);
    if (!ops_result.is_success()) {
        return Result<ICryptoOperations*>(ops_result.error());
    }
    
    auto ops = std::move(ops_result.value());
    ICryptoOperations* ops_ptr = ops.get();
    provider_cache_[provider_name] = std::move(ops);
    provider_usage_count_[provider_name] = 1;
    
    return Result<ICryptoOperations*>(ops_ptr);
}

void AgnosticCryptoOperations::refresh_provider_cache() {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    
    auto& factory = ProviderFactory::instance();
    auto available_providers = factory.available_providers();
    
    // Update capability cache
    capability_cache_.clear();
    for (const auto& provider_name : available_providers) {
        auto capabilities_result = factory.get_capabilities(provider_name);
        if (capabilities_result.is_success()) {
            capability_cache_[provider_name] = capabilities_result.value();
        }
    }
    
    last_cache_refresh_ = std::chrono::steady_clock::now();
}

std::string AgnosticCryptoOperations::provider_name() const {
    return "Agnostic (Multi-Provider)";
}

ProviderCapabilities AgnosticCryptoOperations::capabilities() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    
    // Aggregate capabilities from all cached providers
    ProviderCapabilities aggregated;
    aggregated.provider_name = "Agnostic";
    aggregated.provider_version = "1.0";
    
    std::unordered_set<CipherSuite> all_cipher_suites;
    std::unordered_set<NamedGroup> all_groups;
    std::unordered_set<SignatureScheme> all_signatures;
    std::unordered_set<HashAlgorithm> all_hashes;
    
    bool any_hardware_accel = false;
    bool any_fips_mode = false;
    
    for (const auto& [provider_name, capabilities] : capability_cache_) {
        // Aggregate cipher suites
        for (auto suite : capabilities.supported_cipher_suites) {
            all_cipher_suites.insert(suite);
        }
        
        // Aggregate named groups
        for (auto group : capabilities.supported_groups) {
            all_groups.insert(group);
        }
        
        // Aggregate signature schemes
        for (auto signature : capabilities.supported_signatures) {
            all_signatures.insert(signature);
        }
        
        // Aggregate hash algorithms
        for (auto hash : capabilities.supported_hashes) {
            all_hashes.insert(hash);
        }
        
        // Aggregate boolean capabilities
        if (capabilities.hardware_acceleration) {
            any_hardware_accel = true;
        }
        if (capabilities.fips_mode) {
            any_fips_mode = true;
        }
    }
    
    // Convert sets to vectors
    aggregated.supported_cipher_suites.assign(all_cipher_suites.begin(), all_cipher_suites.end());
    aggregated.supported_groups.assign(all_groups.begin(), all_groups.end());
    aggregated.supported_signatures.assign(all_signatures.begin(), all_signatures.end());
    aggregated.supported_hashes.assign(all_hashes.begin(), all_hashes.end());
    
    aggregated.hardware_acceleration = any_hardware_accel;
    aggregated.fips_mode = any_fips_mode;
    
    return aggregated;
}

// Implementation of specific operations for AgnosticCryptoOperations
// (For brevity, showing only a few representative methods)

Result<std::vector<uint8_t>> AgnosticCryptoOperations::generate_random(
    size_t length,
    const std::vector<uint8_t>& additional_entropy) {
    
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_RANDOM);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    
    return provider_result.value()->generate_random(length, additional_entropy);
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::compute_hash(
    const std::vector<uint8_t>& data,
    HashAlgorithm algorithm) {
    
    // Fast path: use cached default provider for common operations
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    if (!provider_cache_.empty()) {
        // Use the first available provider for hash operations (very common)
        // Most providers support basic hashing, so skip capability checking
        auto& first_provider = provider_cache_.begin()->second;
        if (first_provider) {
            provider_usage_count_[provider_cache_.begin()->first]++;
            lock.unlock();
            return first_provider->compute_hash(data, algorithm);
        }
    }
    lock.unlock();
    
    // Fallback to full provider selection if no cached provider available
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_HASH);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    
    return provider_result.value()->compute_hash(data, algorithm);
}

Result<AEADEncryptionOutput> AgnosticCryptoOperations::aead_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& additional_data,
    AEADCipher cipher) {
    
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_AEAD);
    if (!provider_result.is_success()) {
        return Result<AEADEncryptionOutput>(provider_result.error());
    }
    
    return provider_result.value()->aead_encrypt(plaintext, key, nonce, additional_data, cipher);
}

// Implement stubs for other AgnosticCryptoOperations methods
Result<Random> AgnosticCryptoOperations::generate_dtls_random() {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_RANDOM);
    if (!provider_result.is_success()) {
        return Result<Random>(provider_result.error());
    }
    return provider_result.value()->generate_dtls_random();
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::generate_session_id(size_t length) {
    return generate_random(length);
}

Result<ConnectionID> AgnosticCryptoOperations::generate_connection_id(size_t length) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_RANDOM);
    if (!provider_result.is_success()) {
        return Result<ConnectionID>(provider_result.error());
    }
    return provider_result.value()->generate_connection_id(length);
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::hkdf_expand_label(
    const std::vector<uint8_t>& secret, const std::string& label,
    const std::vector<uint8_t>& context, size_t length, HashAlgorithm hash_algo) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_HASH);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    return provider_result.value()->hkdf_expand_label(secret, label, context, length, hash_algo);
}

Result<KeySchedule> AgnosticCryptoOperations::derive_traffic_keys(
    const std::vector<uint8_t>& master_secret, CipherSuite cipher_suite, const std::vector<uint8_t>& context) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_HASH);
    if (!provider_result.is_success()) {
        return Result<KeySchedule>(provider_result.error());
    }
    return provider_result.value()->derive_traffic_keys(master_secret, cipher_suite, context);
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::aead_decrypt(
    const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& additional_data, AEADCipher cipher) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_AEAD);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    return provider_result.value()->aead_decrypt(ciphertext, tag, key, nonce, additional_data, cipher);
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::compute_hmac(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& data, HashAlgorithm algorithm) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_HASH);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    return provider_result.value()->compute_hmac(key, data, algorithm);
}

Result<bool> AgnosticCryptoOperations::verify_hmac(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& expected_mac, HashAlgorithm algorithm) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_HASH);
    if (!provider_result.is_success()) {
        return Result<bool>(provider_result.error());
    }
    return provider_result.value()->verify_hmac(key, data, expected_mac, algorithm);
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::sign_data(
    const std::vector<uint8_t>& data, const PrivateKey& private_key, SignatureScheme scheme) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_SIGNATURE);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    return provider_result.value()->sign_data(data, private_key, scheme);
}

Result<bool> AgnosticCryptoOperations::verify_signature(
    const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature,
    const PublicKey& public_key, SignatureScheme scheme) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_SIGNATURE);
    if (!provider_result.is_success()) {
        return Result<bool>(provider_result.error());
    }
    return provider_result.value()->verify_signature(data, signature, public_key, scheme);
}

Result<bool> AgnosticCryptoOperations::verify_certificate_signature(
    const std::vector<uint8_t>& transcript_hash, const std::vector<uint8_t>& signature,
    const PublicKey& public_key, SignatureScheme scheme, bool is_server_context) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_CERTIFICATE);
    if (!provider_result.is_success()) {
        return Result<bool>(provider_result.error());
    }
    return provider_result.value()->verify_certificate_signature(transcript_hash, signature, public_key, scheme, is_server_context);
}

Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>
AgnosticCryptoOperations::generate_key_pair(NamedGroup group) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_KEY_EXCHANGE);
    if (!provider_result.is_success()) {
        return Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>(provider_result.error());
    }
    return provider_result.value()->generate_key_pair(group);
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::key_exchange(
    const PrivateKey& private_key, const std::vector<uint8_t>& peer_public_key, NamedGroup group) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_KEY_EXCHANGE);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    return provider_result.value()->key_exchange(private_key, peer_public_key, group);
}

Result<bool> AgnosticCryptoOperations::validate_certificate_chain(
    const CertificateChain& chain, const std::vector<uint8_t>& root_ca_store,
    const std::string& hostname, bool check_revocation) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_CERTIFICATE);
    if (!provider_result.is_success()) {
        return Result<bool>(provider_result.error());
    }
    return provider_result.value()->validate_certificate_chain(chain, root_ca_store, hostname, check_revocation);
}

Result<std::unique_ptr<PublicKey>> AgnosticCryptoOperations::extract_public_key(
    const std::vector<uint8_t>& certificate_der) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_CERTIFICATE);
    if (!provider_result.is_success()) {
        return Result<std::unique_ptr<PublicKey>>(provider_result.error());
    }
    return provider_result.value()->extract_public_key(certificate_der);
}

Result<std::vector<uint8_t>> AgnosticCryptoOperations::encrypt_sequence_number(
    uint64_t sequence_number, const std::vector<uint8_t>& key, const std::vector<uint8_t>& sample) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_DTLS_SPECIFIC);
    if (!provider_result.is_success()) {
        return Result<std::vector<uint8_t>>(provider_result.error());
    }
    return provider_result.value()->encrypt_sequence_number(sequence_number, key, sample);
}

Result<uint64_t> AgnosticCryptoOperations::decrypt_sequence_number(
    const std::vector<uint8_t>& encrypted_sequence_number, const std::vector<uint8_t>& key, const std::vector<uint8_t>& sample) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_DTLS_SPECIFIC);
    if (!provider_result.is_success()) {
        return Result<uint64_t>(provider_result.error());
    }
    return provider_result.value()->decrypt_sequence_number(encrypted_sequence_number, key, sample);
}

Result<bool> AgnosticCryptoOperations::validate_record_mac(
    const std::vector<uint8_t>& mac_key, const std::vector<uint8_t>& sequence_number_key,
    const std::vector<uint8_t>& record_header, const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& expected_mac, ContentType content_type, Epoch epoch, SequenceNumber sequence_number) {
    auto provider_result = get_best_provider_for_operation(OP_CATEGORY_DTLS_SPECIFIC);
    if (!provider_result.is_success()) {
        return Result<bool>(provider_result.error());
    }
    return provider_result.value()->validate_record_mac(mac_key, sequence_number_key, record_header, plaintext, expected_mac, content_type, epoch, sequence_number);
}

bool AgnosticCryptoOperations::supports_cipher_suite(CipherSuite cipher_suite) const {
    auto caps = capabilities();
    return std::find(caps.supported_cipher_suites.begin(), caps.supported_cipher_suites.end(), cipher_suite) 
           != caps.supported_cipher_suites.end();
}

bool AgnosticCryptoOperations::supports_named_group(NamedGroup group) const {
    auto caps = capabilities();
    return std::find(caps.supported_groups.begin(), caps.supported_groups.end(), group) 
           != caps.supported_groups.end();
}

bool AgnosticCryptoOperations::supports_signature_scheme(SignatureScheme scheme) const {
    auto caps = capabilities();
    return std::find(caps.supported_signatures.begin(), caps.supported_signatures.end(), scheme) 
           != caps.supported_signatures.end();
}

std::vector<std::string> AgnosticCryptoOperations::get_active_providers() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    std::vector<std::string> providers;
    for (const auto& [provider_name, ops] : provider_cache_) {
        providers.push_back(provider_name);
    }
    return providers;
}

Result<void> AgnosticCryptoOperations::refresh_provider_capabilities() {
    refresh_provider_cache();
    return Result<void>();
}

} // namespace crypto
} // namespace v13
} // namespace dtls