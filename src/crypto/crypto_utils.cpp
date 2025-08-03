#include <dtls/crypto/crypto_utils.h>
#include <dtls/crypto/provider.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace dtls {
namespace v13 {
namespace crypto {

// CipherSpec implementation
Result<CipherSpec> CipherSpec::from_cipher_suite(CipherSuite suite) {
    CipherSpec spec;
    spec.suite = suite;
    
    switch (suite) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
            spec.aead_cipher = AEADCipher::AES_128_GCM;
            spec.hash_algorithm = HashAlgorithm::SHA256;
            spec.key_length = 16;
            spec.iv_length = 12;
            spec.tag_length = 16;
            spec.hash_length = 32;
            break;
            
        case CipherSuite::TLS_AES_256_GCM_SHA384:
            spec.aead_cipher = AEADCipher::AES_256_GCM;
            spec.hash_algorithm = HashAlgorithm::SHA384;
            spec.key_length = 32;
            spec.iv_length = 12;
            spec.tag_length = 16;
            spec.hash_length = 48;
            break;
            
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            spec.aead_cipher = AEADCipher::CHACHA20_POLY1305;
            spec.hash_algorithm = HashAlgorithm::SHA256;
            spec.key_length = 32;
            spec.iv_length = 12;
            spec.tag_length = 16;
            spec.hash_length = 32;
            break;
            
        case CipherSuite::TLS_AES_128_CCM_SHA256:
            spec.aead_cipher = AEADCipher::AES_128_CCM;
            spec.hash_algorithm = HashAlgorithm::SHA256;
            spec.key_length = 16;
            spec.iv_length = 12;
            spec.tag_length = 16;
            spec.hash_length = 32;
            break;
            
        case CipherSuite::TLS_AES_128_CCM_8_SHA256:
            spec.aead_cipher = AEADCipher::AES_128_CCM_8;
            spec.hash_algorithm = HashAlgorithm::SHA256;
            spec.key_length = 16;
            spec.iv_length = 12;
            spec.tag_length = 8;
            spec.hash_length = 32;
            break;
            
        default:
            return Result<CipherSpec>(DTLSError::CIPHER_SUITE_NOT_SUPPORTED);
    }
    
    return Result<CipherSpec>(spec);
}

namespace utils {

// HKDF utility functions
Result<std::vector<uint8_t>> hkdf_extract(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& input_key_material) {
    
    DTLS_CRYPTO_TIMER("hkdf_extract");
    
    // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
    HMACParams params;
    params.key = salt.empty() ? std::vector<uint8_t>(get_hash_output_length(hash), 0) : salt;
    params.data = input_key_material;
    params.algorithm = hash;
    
    return provider.compute_hmac(params);
}

Result<std::vector<uint8_t>> hkdf_expand(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& pseudo_random_key,
    const std::vector<uint8_t>& info,
    size_t output_length) {
    
    DTLS_CRYPTO_TIMER("hkdf_expand");
    
    size_t hash_len = get_hash_output_length(hash);
    size_t n = (output_length + hash_len - 1) / hash_len; // Ceiling division
    
    if (n > 255) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    std::vector<uint8_t> output;
    output.reserve(output_length);
    
    std::vector<uint8_t> t_prev;
    
    for (size_t i = 1; i <= n; ++i) {
        HMACParams params;
        params.key = pseudo_random_key;
        params.algorithm = hash;
        
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        params.data = t_prev;
        params.data.insert(params.data.end(), info.begin(), info.end());
        params.data.push_back(static_cast<uint8_t>(i));
        
        auto t_result = provider.compute_hmac(params);
        if (!t_result) {
            return t_result;
        }
        
        t_prev = *t_result;
        output.insert(output.end(), t_prev.begin(), t_prev.end());
    }
    
    // Truncate to desired length
    output.resize(output_length);
    return Result<std::vector<uint8_t>>(std::move(output));
}

Result<std::vector<uint8_t>> hkdf_expand_label(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& context,
    size_t length) {
    
    DTLS_CRYPTO_TIMER("hkdf_expand_label");
    
    // HkdfLabel {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // }
    
    std::vector<uint8_t> hkdf_label;
    
    // Length (2 bytes, big-endian)
    hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    hkdf_label.push_back(static_cast<uint8_t>(length & 0xFF));
    
    // Label with "tls13 " prefix
    std::string prefixed_label = "tls13 " + label;
    if (prefixed_label.length() > 255) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    hkdf_label.push_back(static_cast<uint8_t>(prefixed_label.length()));
    hkdf_label.insert(hkdf_label.end(), prefixed_label.begin(), prefixed_label.end());
    
    // Context
    if (context.size() > 255) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    hkdf_label.push_back(static_cast<uint8_t>(context.size()));
    hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());
    
    return hkdf_expand(provider, hash, secret, hkdf_label, length);
}

// Traffic key derivation
Result<KeySchedule> derive_handshake_keys(
    CryptoProvider& provider,
    const CipherSpec& cipher_spec,
    const std::vector<uint8_t>& handshake_secret,
    const std::vector<uint8_t>& client_random,
    const std::vector<uint8_t>& server_random) {
    
    DTLS_CRYPTO_TIMER("derive_handshake_keys");
    
    KeySchedule keys;
    
    // Derive client handshake traffic secret
    auto client_hs_secret = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, handshake_secret,
        constants::HKDF_LABEL_CLIENT_HANDSHAKE_TRAFFIC, {}, cipher_spec.hash_length);
    
    if (!client_hs_secret) {
        return Result<KeySchedule>(client_hs_secret.error());
    }
    
    // Derive server handshake traffic secret
    auto server_hs_secret = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, handshake_secret,
        constants::HKDF_LABEL_SERVER_HANDSHAKE_TRAFFIC, {}, cipher_spec.hash_length);
    
    if (!server_hs_secret) {
        return Result<KeySchedule>(server_hs_secret.error());
    }
    
    // Derive client keys
    auto client_key = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *client_hs_secret,
        constants::HKDF_LABEL_KEY, {}, cipher_spec.key_length);
    
    if (!client_key) {
        return Result<KeySchedule>(client_key.error());
    }
    
    auto client_iv = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *client_hs_secret,
        constants::HKDF_LABEL_IV, {}, cipher_spec.iv_length);
    
    if (!client_iv) {
        return Result<KeySchedule>(client_iv.error());
    }
    
    // Derive server keys
    auto server_key = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *server_hs_secret,
        constants::HKDF_LABEL_KEY, {}, cipher_spec.key_length);
    
    if (!server_key) {
        return Result<KeySchedule>(server_key.error());
    }
    
    auto server_iv = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *server_hs_secret,
        constants::HKDF_LABEL_IV, {}, cipher_spec.iv_length);
    
    if (!server_iv) {
        return Result<KeySchedule>(server_iv.error());
    }
    
    keys.client_write_key = std::move(*client_key);
    keys.server_write_key = std::move(*server_key);
    keys.client_write_iv = std::move(*client_iv);
    keys.server_write_iv = std::move(*server_iv);
    keys.epoch = 1; // Handshake epoch
    
    return Result<KeySchedule>(std::move(keys));
}

Result<KeySchedule> derive_application_keys(
    CryptoProvider& provider,
    const CipherSpec& cipher_spec,
    const std::vector<uint8_t>& master_secret,
    const std::vector<uint8_t>& handshake_hash) {
    
    DTLS_CRYPTO_TIMER("derive_application_keys");
    
    KeySchedule keys;
    
    // Derive client application traffic secret
    auto client_app_secret = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, master_secret,
        constants::HKDF_LABEL_CLIENT_APPLICATION_TRAFFIC, handshake_hash, cipher_spec.hash_length);
    
    if (!client_app_secret) {
        return Result<KeySchedule>(client_app_secret.error());
    }
    
    // Derive server application traffic secret
    auto server_app_secret = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, master_secret,
        constants::HKDF_LABEL_SERVER_APPLICATION_TRAFFIC, handshake_hash, cipher_spec.hash_length);
    
    if (!server_app_secret) {
        return Result<KeySchedule>(server_app_secret.error());
    }
    
    // Derive client keys
    auto client_key = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *client_app_secret,
        constants::HKDF_LABEL_KEY, {}, cipher_spec.key_length);
    
    if (!client_key) {
        return Result<KeySchedule>(client_key.error());
    }
    
    auto client_iv = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *client_app_secret,
        constants::HKDF_LABEL_IV, {}, cipher_spec.iv_length);
    
    if (!client_iv) {
        return Result<KeySchedule>(client_iv.error());
    }
    
    // Derive server keys
    auto server_key = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *server_app_secret,
        constants::HKDF_LABEL_KEY, {}, cipher_spec.key_length);
    
    if (!server_key) {
        return Result<KeySchedule>(server_key.error());
    }
    
    auto server_iv = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *server_app_secret,
        constants::HKDF_LABEL_IV, {}, cipher_spec.iv_length);
    
    if (!server_iv) {
        return Result<KeySchedule>(server_iv.error());
    }
    
    keys.client_write_key = std::move(*client_key);
    keys.server_write_key = std::move(*server_key);
    keys.client_write_iv = std::move(*client_iv);
    keys.server_write_iv = std::move(*server_iv);
    keys.epoch = 2; // Application epoch
    
    return Result<KeySchedule>(std::move(keys));
}

Result<KeySchedule> update_traffic_keys(
    CryptoProvider& provider,
    const CipherSpec& cipher_spec,
    const KeySchedule& current_keys) {
    
    DTLS_CRYPTO_TIMER("update_traffic_keys");
    
    KeySchedule updated_keys = current_keys;
    
    // RFC 9147 Section 4.6.3: Key Update
    // application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
    
    // Update client write key using current client write key as the base secret
    auto updated_client_secret = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, current_keys.client_write_key,
        "traffic upd", {}, cipher_spec.hash_length);
    
    if (!updated_client_secret) {
        return Result<KeySchedule>(updated_client_secret.error());
    }
    
    // Update server write key using current server write key as the base secret
    auto updated_server_secret = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, current_keys.server_write_key,
        "traffic upd", {}, cipher_spec.hash_length);
    
    if (!updated_server_secret) {
        return Result<KeySchedule>(updated_server_secret.error());
    }
    
    // Derive new client write key from updated secret
    auto new_client_key = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *updated_client_secret,
        constants::HKDF_LABEL_KEY, {}, cipher_spec.key_length);
    
    if (!new_client_key) {
        return Result<KeySchedule>(new_client_key.error());
    }
    
    // Derive new client IV from updated secret
    auto new_client_iv = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *updated_client_secret,
        constants::HKDF_LABEL_IV, {}, cipher_spec.iv_length);
    
    if (!new_client_iv) {
        return Result<KeySchedule>(new_client_iv.error());
    }
    
    // Derive new server write key from updated secret
    auto new_server_key = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *updated_server_secret,
        constants::HKDF_LABEL_KEY, {}, cipher_spec.key_length);
    
    if (!new_server_key) {
        return Result<KeySchedule>(new_server_key.error());
    }
    
    // Derive new server IV from updated secret
    auto new_server_iv = hkdf_expand_label(
        provider, cipher_spec.hash_algorithm, *updated_server_secret,
        constants::HKDF_LABEL_IV, {}, cipher_spec.iv_length);
    
    if (!new_server_iv) {
        return Result<KeySchedule>(new_server_iv.error());
    }
    
    // Update sequence number keys
    auto new_client_sn_key = derive_sequence_number_key(
        provider, *updated_client_secret, cipher_spec.hash_algorithm);
    
    if (!new_client_sn_key) {
        return Result<KeySchedule>(new_client_sn_key.error());
    }
    
    auto new_server_sn_key = derive_sequence_number_key(
        provider, *updated_server_secret, cipher_spec.hash_algorithm);
    
    if (!new_server_sn_key) {
        return Result<KeySchedule>(new_server_sn_key.error());
    }
    
    // Update the key schedule with new keys
    updated_keys.client_write_key = std::move(*new_client_key);
    updated_keys.server_write_key = std::move(*new_server_key);
    updated_keys.client_write_iv = std::move(*new_client_iv);
    updated_keys.server_write_iv = std::move(*new_server_iv);
    updated_keys.client_sequence_number_key = std::move(*new_client_sn_key);
    updated_keys.server_sequence_number_key = std::move(*new_server_sn_key);
    
    // Increment epoch for key update
    updated_keys.epoch++;
    
    return Result<KeySchedule>(std::move(updated_keys));
}

// TranscriptHash implementation
TranscriptHash::TranscriptHash(HashAlgorithm algorithm) 
    : algorithm_(algorithm) {}

TranscriptHash::~TranscriptHash() {
    secure_zero(data_);
}

Result<void> TranscriptHash::update(const std::vector<uint8_t>& data) {
    data_.insert(data_.end(), data.begin(), data.end());
    return Result<void>();
}

Result<std::vector<uint8_t>> TranscriptHash::finalize(CryptoProvider& provider) {
    HashParams params;
    params.data = data_;
    params.algorithm = algorithm_;
    
    return provider.compute_hash(params);
}

Result<std::vector<uint8_t>> TranscriptHash::current_hash(CryptoProvider& provider) const {
    HashParams params;
    params.data = data_;
    params.algorithm = algorithm_;
    
    return provider.compute_hash(params);
}

void TranscriptHash::reset() {
    secure_zero(data_);
    data_.clear();
}

// Record protection utilities
Result<std::vector<uint8_t>> protect_record(
    CryptoProvider& provider,
    const AEADParams& params,
    ContentType content_type,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& additional_data) {
    
    DTLS_CRYPTO_TIMER("protect_record");
    
    // Add content type to plaintext for TLS 1.3 inner plaintext
    std::vector<uint8_t> inner_plaintext = plaintext;
    inner_plaintext.push_back(static_cast<uint8_t>(content_type));
    
    return provider.aead_encrypt(params, inner_plaintext);
}

Result<std::pair<ContentType, std::vector<uint8_t>>> unprotect_record(
    CryptoProvider& provider,
    const AEADParams& params,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& additional_data) {
    
    DTLS_CRYPTO_TIMER("unprotect_record");
    
    auto plaintext_result = provider.aead_decrypt(params, ciphertext);
    if (!plaintext_result) {
        return Result<std::pair<ContentType, std::vector<uint8_t>>>(plaintext_result.error());
    }
    
    auto plaintext = std::move(*plaintext_result);
    
    // Extract content type from end of plaintext
    if (plaintext.empty()) {
        return Result<std::pair<ContentType, std::vector<uint8_t>>>(DTLSError::DECODE_ERROR);
    }
    
    ContentType content_type = static_cast<ContentType>(plaintext.back());
    plaintext.pop_back();
    
    return Result<std::pair<ContentType, std::vector<uint8_t>>>(
        std::make_pair(content_type, std::move(plaintext)));
}

// Nonce construction
std::vector<uint8_t> construct_aead_nonce(
    const std::vector<uint8_t>& write_iv,
    SequenceNumber sequence_number) {
    
    std::vector<uint8_t> nonce = write_iv;
    
    // XOR sequence number with the last 8 bytes of the IV
    size_t offset = nonce.size() - 8;
    for (size_t i = 0; i < 8; ++i) {
        nonce[offset + i] ^= static_cast<uint8_t>((sequence_number >> (8 * (7 - i))) & 0xFF);
    }
    
    return nonce;
}

std::vector<uint8_t> construct_aead_additional_data(
    const ConnectionID& connection_id,
    Epoch epoch,
    SequenceNumber sequence_number,
    ContentType content_type,
    ProtocolVersion version,
    uint16_t length) {
    
    std::vector<uint8_t> aad;
    
    // Connection ID (variable length)
    aad.insert(aad.end(), connection_id.begin(), connection_id.end());
    
    // Epoch (2 bytes)
    aad.push_back(static_cast<uint8_t>((epoch >> 8) & 0xFF));
    aad.push_back(static_cast<uint8_t>(epoch & 0xFF));
    
    // Sequence number (6 bytes, 48-bit)
    for (int i = 5; i >= 0; --i) {
        aad.push_back(static_cast<uint8_t>((sequence_number >> (8 * i)) & 0xFF));
    }
    
    // Content type (1 byte)
    aad.push_back(static_cast<uint8_t>(content_type));
    
    // Version (2 bytes)
    aad.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    aad.push_back(static_cast<uint8_t>(version & 0xFF));
    
    // Length (2 bytes)
    aad.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    aad.push_back(static_cast<uint8_t>(length & 0xFF));
    
    return aad;
}

// Key exchange utilities
Result<std::vector<uint8_t>> compute_ecdh_shared_secret(
    CryptoProvider& provider,
    const PrivateKey& private_key,
    const std::vector<uint8_t>& peer_public_key,
    NamedGroup group) {
    
    DTLS_CRYPTO_TIMER("compute_ecdh_shared_secret");
    
    KeyExchangeParams params;
    params.group = group;
    params.peer_public_key = peer_public_key;
    params.private_key = &private_key;
    
    return provider.perform_key_exchange(params);
}

Result<std::vector<uint8_t>> compute_dh_shared_secret(
    CryptoProvider& provider,
    const PrivateKey& private_key,
    const std::vector<uint8_t>& peer_public_key,
    NamedGroup group) {
    
    DTLS_CRYPTO_TIMER("compute_dh_shared_secret");
    
    KeyExchangeParams params;
    params.group = group;
    params.peer_public_key = peer_public_key;
    params.private_key = &private_key;
    
    return provider.perform_key_exchange(params);
}

// Signature utilities
Result<std::vector<uint8_t>> create_certificate_verify_data(
    const TranscriptHash& transcript,
    bool is_server) {
    
    std::vector<uint8_t> verify_data;
    
    // Add 64 0x20 (space) bytes
    verify_data.resize(64, 0x20);
    
    // Add context string
    const char* context = is_server ? constants::CERT_VERIFY_CONTEXT_SERVER : 
                                     constants::CERT_VERIFY_CONTEXT_CLIENT;
    
    verify_data.insert(verify_data.end(), context, context + std::strlen(context));
    
    // Add single 0 byte separator
    verify_data.push_back(0x00);
    
    // Add transcript hash (this would need to be computed)
    // For now, return the prepared context
    return Result<std::vector<uint8_t>>(std::move(verify_data));
}

Result<std::vector<uint8_t>> create_finished_verify_data(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& base_key,
    const std::vector<uint8_t>& transcript_hash) {
    
    DTLS_CRYPTO_TIMER("create_finished_verify_data");
    
    // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    auto finished_key = hkdf_expand_label(
        provider, hash, base_key, "finished", {}, get_hash_output_length(hash));
    
    if (!finished_key) {
        return finished_key;
    }
    
    // verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
    HMACParams params;
    params.key = *finished_key;
    params.data = transcript_hash;
    params.algorithm = hash;
    
    return provider.compute_hmac(params);
}

// PSK utilities
Result<std::vector<uint8_t>> compute_psk_binder(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& psk,
    const std::vector<uint8_t>& transcript_hash) {
    
    DTLS_CRYPTO_TIMER("compute_psk_binder");
    
    // This is a simplified version - full implementation requires
    // proper PSK binder key derivation
    HMACParams params;
    params.key = psk;
    params.data = transcript_hash;
    params.algorithm = hash;
    
    return provider.compute_hmac(params);
}

Result<bool> verify_psk_binder(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& psk,
    const std::vector<uint8_t>& transcript_hash,
    const std::vector<uint8_t>& binder) {
    
    auto computed_binder = compute_psk_binder(provider, hash, psk, transcript_hash);
    if (!computed_binder) {
        return Result<bool>(computed_binder.error());
    }
    
    bool equal = constant_time_compare(*computed_binder, binder);
    return Result<bool>(equal);
}

// Random utilities
Result<Random> generate_random(CryptoProvider& provider) {
    RandomParams params;
    params.length = RANDOM_LENGTH;
    params.cryptographically_secure = true;
    
    auto random_bytes = provider.generate_random(params);
    if (!random_bytes) {
        return Result<Random>(random_bytes.error());
    }
    
    if (random_bytes->size() != RANDOM_LENGTH) {
        return Result<Random>(DTLSError::INTERNAL_ERROR);
    }
    
    Random random;
    std::copy(random_bytes->begin(), random_bytes->end(), random.begin());
    
    return Result<Random>(random);
}

Result<std::vector<uint8_t>> generate_session_id(CryptoProvider& provider) {
    RandomParams params;
    params.length = 32; // Maximum session ID length
    params.cryptographically_secure = true;
    
    return provider.generate_random(params);
}

Result<ConnectionID> generate_connection_id(CryptoProvider& provider, size_t length) {
    if (length > MAX_CONNECTION_ID_LENGTH) {
        return Result<ConnectionID>(DTLSError::INVALID_PARAMETER);
    }
    
    RandomParams params;
    params.length = length;
    params.cryptographically_secure = true;
    
    return provider.generate_random(params);
}

// Timing-safe comparison
bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    
    uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= (a[i] ^ b[i]);
    }
    
    return result == 0;
}

// Secure memory utilities
void secure_zero(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        secure_zero(data.data(), data.size());
        data.clear();
    }
}

void secure_zero(uint8_t* data, size_t length) {
    if (data && length > 0) {
        // Use volatile to prevent compiler optimization
        volatile uint8_t* volatile_ptr = data;
        for (size_t i = 0; i < length; ++i) {
            volatile_ptr[i] = 0;
        }
    }
}

// Enhanced MAC validation utilities for DTLS v1.3
Result<bool> verify_record_mac(
    CryptoProvider& provider,
    const std::vector<uint8_t>& mac_key,
    const std::vector<uint8_t>& record_data,
    const std::vector<uint8_t>& expected_mac,
    HashAlgorithm algorithm) {
    
    DTLS_CRYPTO_TIMER("verify_record_mac");
    
    MACValidationParams params;
    params.key = mac_key;
    params.data = record_data;
    params.expected_mac = expected_mac;
    params.algorithm = algorithm;
    params.constant_time_required = true;
    
    return provider.verify_hmac(params);
}

Result<bool> verify_handshake_mac(
    CryptoProvider& provider,
    const std::vector<uint8_t>& mac_key,
    const std::vector<uint8_t>& transcript_hash,
    const std::vector<uint8_t>& expected_mac,
    HashAlgorithm algorithm) {
    
    DTLS_CRYPTO_TIMER("verify_handshake_mac");
    
    MACValidationParams params;
    params.key = mac_key;
    params.data = transcript_hash;
    params.expected_mac = expected_mac;
    params.algorithm = algorithm;
    params.constant_time_required = true;
    params.dtls_context.content_type = ContentType::HANDSHAKE;
    
    return provider.verify_hmac(params);
}

Result<bool> verify_cookie_mac(
    CryptoProvider& provider,
    const std::vector<uint8_t>& cookie_secret,
    const std::vector<uint8_t>& client_info,
    const std::vector<uint8_t>& expected_mac,
    HashAlgorithm algorithm) {
    
    DTLS_CRYPTO_TIMER("verify_cookie_mac");
    
    MACValidationParams params;
    params.key = cookie_secret;
    params.data = client_info;
    params.expected_mac = expected_mac;
    params.algorithm = algorithm;
    params.constant_time_required = true;
    params.max_data_length = 1024; // Reasonable limit for client info
    
    return provider.verify_hmac(params);
}

// Cipher suite utility functions
bool is_aead_cipher_suite(CipherSuite suite) {
    // All DTLS 1.3 cipher suites are AEAD
    return true;
}

bool is_psk_cipher_suite(CipherSuite suite) {
    // Basic cipher suites are not PSK-only
    return false;
}

size_t get_cipher_suite_key_length(CipherSuite suite) {
    auto spec = CipherSpec::from_cipher_suite(suite);
    return spec ? spec->key_length : 0;
}

size_t get_cipher_suite_iv_length(CipherSuite suite) {
    auto spec = CipherSpec::from_cipher_suite(suite);
    return spec ? spec->iv_length : 0;
}

size_t get_cipher_suite_tag_length(CipherSuite suite) {
    auto spec = CipherSpec::from_cipher_suite(suite);
    return spec ? spec->tag_length : 0;
}

HashAlgorithm get_cipher_suite_hash(CipherSuite suite) {
    auto spec = CipherSpec::from_cipher_suite(suite);
    return spec ? spec->hash_algorithm : HashAlgorithm::SHA256;
}

// Named group utilities
bool is_ecdh_group(NamedGroup group) {
    switch (group) {
        case NamedGroup::SECP256R1:
        case NamedGroup::SECP384R1:
        case NamedGroup::SECP521R1:
        case NamedGroup::X25519:
        case NamedGroup::X448:
            return true;
        default:
            return false;
    }
}

bool is_ffdh_group(NamedGroup group) {
    switch (group) {
        case NamedGroup::FFDHE2048:
        case NamedGroup::FFDHE3072:
        case NamedGroup::FFDHE4096:
        case NamedGroup::FFDHE6144:
        case NamedGroup::FFDHE8192:
            return true;
        default:
            return false;
    }
}

size_t get_named_group_key_length(NamedGroup group) {
    switch (group) {
        case NamedGroup::SECP256R1: return 32;
        case NamedGroup::SECP384R1: return 48;
        case NamedGroup::SECP521R1: return 66;
        case NamedGroup::X25519: return 32;
        case NamedGroup::X448: return 56;
        case NamedGroup::FFDHE2048: return 256;
        case NamedGroup::FFDHE3072: return 384;
        case NamedGroup::FFDHE4096: return 512;
        case NamedGroup::FFDHE6144: return 768;
        case NamedGroup::FFDHE8192: return 1024;
        default: return 0;
    }
}

size_t get_named_group_public_key_length(NamedGroup group) {
    switch (group) {
        case NamedGroup::SECP256R1: return 65; // Uncompressed point
        case NamedGroup::SECP384R1: return 97;
        case NamedGroup::SECP521R1: return 133;
        case NamedGroup::X25519: return 32;
        case NamedGroup::X448: return 56;
        default: return get_named_group_key_length(group); // For FFDHE
    }
}

// Hash algorithm utilities
size_t get_hash_output_length(HashAlgorithm hash) {
    switch (hash) {
        case HashAlgorithm::MD5: return 16;
        case HashAlgorithm::SHA1: return 20;
        case HashAlgorithm::SHA224: return 28;
        case HashAlgorithm::SHA256: return 32;
        case HashAlgorithm::SHA384: return 48;
        case HashAlgorithm::SHA512: return 64;
        case HashAlgorithm::SHA3_256: return 32;
        case HashAlgorithm::SHA3_384: return 48;
        case HashAlgorithm::SHA3_512: return 64;
        default: return 0;
    }
}

std::string get_hash_name(HashAlgorithm hash) {
    switch (hash) {
        case HashAlgorithm::MD5: return "MD5";
        case HashAlgorithm::SHA1: return "SHA1";
        case HashAlgorithm::SHA224: return "SHA224";
        case HashAlgorithm::SHA256: return "SHA256";
        case HashAlgorithm::SHA384: return "SHA384";
        case HashAlgorithm::SHA512: return "SHA512";
        case HashAlgorithm::SHA3_256: return "SHA3-256";
        case HashAlgorithm::SHA3_384: return "SHA3-384";
        case HashAlgorithm::SHA3_512: return "SHA3-512";
        default: return "UNKNOWN";
    }
}

// Signature scheme utilities
bool is_rsa_signature(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
        case SignatureScheme::RSA_PSS_PSS_SHA256:
        case SignatureScheme::RSA_PSS_PSS_SHA384:
        case SignatureScheme::RSA_PSS_PSS_SHA512:
            return true;
        default:
            return false;
    }
}

bool is_ecdsa_signature(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
            return true;
        default:
            return false;
    }
}

bool is_eddsa_signature(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::ED25519:
        case SignatureScheme::ED448:
            return true;
        default:
            return false;
    }
}

bool is_pss_signature(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
        case SignatureScheme::RSA_PSS_PSS_SHA256:
        case SignatureScheme::RSA_PSS_PSS_SHA384:
        case SignatureScheme::RSA_PSS_PSS_SHA512:
            return true;
        default:
            return false;
    }
}

HashAlgorithm get_signature_hash_algorithm(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_PSS_SHA256:
            return HashAlgorithm::SHA256;
            
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_PSS_SHA384:
            return HashAlgorithm::SHA384;
            
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
        case SignatureScheme::RSA_PSS_PSS_SHA512:
            return HashAlgorithm::SHA512;
            
        case SignatureScheme::ED25519:
        case SignatureScheme::ED448:
            return HashAlgorithm::NONE; // EdDSA doesn't use separate hash
            
        default:
            return HashAlgorithm::SHA256;
    }
}

// Performance monitoring
CryptoStatsCollector& CryptoStatsCollector::instance() {
    static CryptoStatsCollector instance;
    return instance;
}

void CryptoStatsCollector::record_operation(const std::string& operation, std::chrono::nanoseconds duration) {
    if (!collection_enabled_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto& stats = stats_[operation];
    
    stats.operation_name = operation;
    stats.call_count++;
    stats.total_time += duration;
    
    if (duration < stats.min_time) {
        stats.min_time = duration;
    }
    
    if (duration > stats.max_time) {
        stats.max_time = duration;
    }
}

CryptoOperationStats CryptoStatsCollector::get_stats(const std::string& operation) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(operation);
    return (it != stats_.end()) ? it->second : CryptoOperationStats{};
}

std::vector<CryptoOperationStats> CryptoStatsCollector::get_all_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CryptoOperationStats> all_stats;
    
    for (const auto& [name, stats] : stats_) {
        all_stats.push_back(stats);
    }
    
    return all_stats;
}

void CryptoStatsCollector::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.clear();
}

void CryptoStatsCollector::reset_operation_stats(const std::string& operation) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.erase(operation);
}

// RAII timer implementation
CryptoOperationTimer::CryptoOperationTimer(const std::string& operation_name)
    : operation_name_(operation_name)
    , start_time_(std::chrono::steady_clock::now()) {}

CryptoOperationTimer::~CryptoOperationTimer() {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time_);
    
    CryptoStatsCollector::instance().record_operation(operation_name_, duration);
}

} // namespace utils

// Constants definitions
namespace constants {

const std::vector<uint8_t> SHA256_EMPTY_HASH = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
    0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

const std::vector<uint8_t> SHA384_EMPTY_HASH = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
    0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
    0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};

const std::vector<uint8_t> SHA512_EMPTY_HASH = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50,
    0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c,
    0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
    0xf9, 0x27, 0xda, 0x3e
};

} // namespace constants

// Sequence number encryption utilities implementation
namespace utils {

Result<uint64_t> encrypt_sequence_number(
    CryptoProvider& provider,
    uint64_t sequence_number,
    const std::vector<uint8_t>& sequence_number_key) {
    
    DTLS_CRYPTO_TIMER("encrypt_sequence_number");
    
    if (sequence_number_key.size() < 16) {
        return make_error<uint64_t>(DTLSError::INVALID_PARAMETER);
    }
    
    // For DTLS v1.3, we use AES-128-ECB to encrypt the 48-bit sequence number
    // The sequence number is padded to 16 bytes with zeros
    std::vector<uint8_t> plaintext(16, 0);
    
    // Store sequence number in big-endian format, right-aligned
    for (int i = 0; i < 6; ++i) {
        plaintext[10 + i] = (sequence_number >> (8 * (5 - i))) & 0xFF;
    }
    
    // Use AEAD with empty nonce and AAD for ECB-like behavior
    AEADParams params;
    params.key = sequence_number_key;
    params.nonce = std::vector<uint8_t>(12, 0); // 12-byte nonce of zeros
    params.additional_data = {}; // No AAD
    params.cipher = AEADCipher::AES_128_GCM;
    
    auto encrypted_result = provider.aead_encrypt(params, plaintext);
    if (!encrypted_result.is_success()) {
        return make_error<uint64_t>(encrypted_result.error());
    }
    
    auto encrypted = encrypted_result.value();
    if (encrypted.size() < 16) {
        return make_error<uint64_t>(DTLSError::INTERNAL_ERROR);
    }
    
    // Extract the encrypted sequence number from the last 6 bytes (excluding auth tag)
    uint64_t encrypted_seq = 0;
    for (int i = 0; i < 6; ++i) {
        encrypted_seq |= (static_cast<uint64_t>(encrypted[10 + i]) << (8 * (5 - i)));
    }
    
    // Mask to 48 bits
    encrypted_seq &= 0xFFFFFFFFFFFFULL;
    
    return make_result(encrypted_seq);
}

Result<uint64_t> decrypt_sequence_number(
    CryptoProvider& provider,
    uint64_t encrypted_sequence_number,
    const std::vector<uint8_t>& sequence_number_key) {
    
    DTLS_CRYPTO_TIMER("decrypt_sequence_number");
    
    if (sequence_number_key.size() < 16) {
        return make_error<uint64_t>(DTLSError::INVALID_PARAMETER);
    }
    
    // Reconstruct the encrypted block
    std::vector<uint8_t> encrypted_block(16 + 16, 0); // 16 bytes plaintext + 16 bytes auth tag
    
    // Store encrypted sequence number in big-endian format, right-aligned
    for (int i = 0; i < 6; ++i) {
        encrypted_block[10 + i] = (encrypted_sequence_number >> (8 * (5 - i))) & 0xFF;
    }
    
    // Use AEAD decrypt with same parameters
    AEADParams params;
    params.key = sequence_number_key;
    params.nonce = std::vector<uint8_t>(12, 0); // 12-byte nonce of zeros
    params.additional_data = {}; // No AAD
    params.cipher = AEADCipher::AES_128_GCM;
    
    auto decrypted_result = provider.aead_decrypt(params, encrypted_block);
    if (!decrypted_result.is_success()) {
        return make_error<uint64_t>(decrypted_result.error());
    }
    
    auto decrypted = decrypted_result.value();
    if (decrypted.size() < 16) {
        return make_error<uint64_t>(DTLSError::INTERNAL_ERROR);
    }
    
    // Extract the decrypted sequence number from the last 6 bytes
    uint64_t sequence_number = 0;
    for (int i = 0; i < 6; ++i) {
        sequence_number |= (static_cast<uint64_t>(decrypted[10 + i]) << (8 * (5 - i)));
    }
    
    // Mask to 48 bits
    sequence_number &= 0xFFFFFFFFFFFFULL;
    
    return make_result(sequence_number);
}

Result<std::vector<uint8_t>> derive_sequence_number_mask(
    CryptoProvider& provider,
    const std::vector<uint8_t>& traffic_secret,
    const std::string& label,
    HashAlgorithm hash_algorithm) {
    
    DTLS_CRYPTO_TIMER("derive_sequence_number_mask");
    
    // Use HKDF-Expand-Label to derive the sequence number mask
    // mask = HKDF-Expand-Label(traffic_secret, label, "", 6)
    return hkdf_expand_label(provider, hash_algorithm, traffic_secret, label, {}, 6);
}

Result<std::vector<uint8_t>> derive_sequence_number_key(
    CryptoProvider& provider,
    const std::vector<uint8_t>& traffic_secret,
    HashAlgorithm hash_algorithm) {
    
    DTLS_CRYPTO_TIMER("derive_sequence_number_key");
    
    // Use HKDF-Expand-Label to derive the sequence number encryption key
    // seq_key = HKDF-Expand-Label(traffic_secret, "sn", "", 16)
    return hkdf_expand_label(provider, hash_algorithm, traffic_secret, "sn", {}, 16);
}

Result<void> update_key_schedule_with_sequence_keys(
    CryptoProvider& provider,
    KeySchedule& key_schedule,
    const std::vector<uint8_t>& client_traffic_secret,
    const std::vector<uint8_t>& server_traffic_secret,
    HashAlgorithm hash_algorithm) {
    
    DTLS_CRYPTO_TIMER("update_key_schedule_with_sequence_keys");
    
    // Derive client sequence number key
    auto client_seq_key_result = derive_sequence_number_key(
        provider, client_traffic_secret, hash_algorithm);
    if (!client_seq_key_result.is_success()) {
        return make_error<void>(client_seq_key_result.error());
    }
    
    // Derive server sequence number key
    auto server_seq_key_result = derive_sequence_number_key(
        provider, server_traffic_secret, hash_algorithm);
    if (!server_seq_key_result.is_success()) {
        return make_error<void>(server_seq_key_result.error());
    }
    
    // Update the key schedule
    key_schedule.client_sequence_number_key = client_seq_key_result.value();
    key_schedule.server_sequence_number_key = server_seq_key_result.value();
    
    return make_result();
}

// DTLS v1.3 signature verification utilities (RFC 9147 Section 4.2.3)
Result<std::vector<uint8_t>> construct_dtls_signature_context(
    const std::vector<uint8_t>& transcript_hash,
    bool is_server_context) {
    
    // Validate input parameters
    if (transcript_hash.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Maximum reasonable transcript hash size (SHA-512 = 64 bytes)
    if (transcript_hash.size() > 64) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Construct signature input according to TLS 1.3 Section 4.4.3:
    // - 64 bytes of 0x20 (space character)
    // - Context string
    // - Single 0x00 byte
    // - Transcript hash
    
    const char* context_string = is_server_context 
        ? "TLS 1.3, server CertificateVerify"
        : "TLS 1.3, client CertificateVerify";
    
    size_t context_string_len = std::strlen(context_string);
    size_t total_size = 64 + context_string_len + 1 + transcript_hash.size();
    
    std::vector<uint8_t> signature_input;
    signature_input.reserve(total_size);
    
    // Add 64 bytes of 0x20 (space character)
    signature_input.insert(signature_input.end(), 64, 0x20);
    
    // Add context string
    signature_input.insert(signature_input.end(), 
                          context_string, 
                          context_string + context_string_len);
    
    // Add separator byte
    signature_input.push_back(0x00);
    
    // Add transcript hash
    signature_input.insert(signature_input.end(), 
                          transcript_hash.begin(), 
                          transcript_hash.end());
    
    return Result<std::vector<uint8_t>>(std::move(signature_input));
}

// ASN.1 signature format validation for ECDSA
Result<bool> validate_ecdsa_asn1_signature(
    const std::vector<uint8_t>& signature,
    const PublicKey& public_key) {
    
    // Validate input
    if (signature.empty()) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // ECDSA signatures should be at least 8 bytes (minimal ASN.1 structure)
    // and no more than 150 bytes (P-521 with maximum ASN.1 overhead)
    if (signature.size() < 8 || signature.size() > 150) {
        return Result<bool>(false);
    }
    
    // Basic ASN.1 DER validation
    // ECDSA signature format: SEQUENCE { r INTEGER, s INTEGER }
    
    if (signature[0] != 0x30) { // SEQUENCE tag
        return Result<bool>(false);
    }
    
    // Check length encoding
    size_t seq_length_pos = 1;
    size_t seq_length;
    
    if (signature[1] & 0x80) {
        // Long form length
        size_t length_bytes = signature[1] & 0x7F;
        if (length_bytes == 0 || length_bytes > 4 || signature.size() < 2 + length_bytes) {
            return Result<bool>(false);
        }
        
        seq_length = 0;
        for (size_t i = 0; i < length_bytes; i++) {
            seq_length = (seq_length << 8) | signature[2 + i];
        }
        seq_length_pos = 2 + length_bytes;
    } else {
        // Short form length
        seq_length = signature[1];
        seq_length_pos = 2;
    }
    
    // Verify total length matches
    if (seq_length_pos + seq_length != signature.size()) {
        return Result<bool>(false);
    }
    
    // Parse r INTEGER
    if (seq_length_pos >= signature.size() || signature[seq_length_pos] != 0x02) {
        return Result<bool>(false);
    }
    
    size_t r_pos = seq_length_pos + 1;
    if (r_pos >= signature.size()) {
        return Result<bool>(false);
    }
    
    size_t r_length = signature[r_pos];
    if (r_length == 0 || r_pos + 1 + r_length > signature.size()) {
        return Result<bool>(false);
    }
    
    // Check r value (should not be zero, should not have unnecessary leading zeros)
    size_t r_value_pos = r_pos + 1;
    if (signature[r_value_pos] == 0x00 && r_length > 1 && 
        (signature[r_value_pos + 1] & 0x80) == 0) {
        return Result<bool>(false); // Unnecessary leading zero
    }
    
    // Parse s INTEGER
    size_t s_pos = r_value_pos + r_length;
    if (s_pos >= signature.size() || signature[s_pos] != 0x02) {
        return Result<bool>(false);
    }
    
    s_pos++;
    if (s_pos >= signature.size()) {
        return Result<bool>(false);
    }
    
    size_t s_length = signature[s_pos];
    if (s_length == 0 || s_pos + 1 + s_length > signature.size()) {
        return Result<bool>(false);
    }
    
    // Check s value (should not be zero, should not have unnecessary leading zeros)
    size_t s_value_pos = s_pos + 1;
    if (signature[s_value_pos] == 0x00 && s_length > 1 && 
        (signature[s_value_pos + 1] & 0x80) == 0) {
        return Result<bool>(false); // Unnecessary leading zero
    }
    
    // Verify we've consumed the entire signature
    if (s_value_pos + s_length != signature.size()) {
        return Result<bool>(false);
    }
    
    return Result<bool>(true);
}

// Enhanced certificate-signature scheme compatibility validation
Result<bool> validate_certificate_signature_compatibility(
    const std::vector<uint8_t>& certificate_der,
    SignatureScheme scheme) {
    
    if (certificate_der.empty()) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // For now, return true as this requires complex X.509 certificate parsing
    // This should be implemented using OpenSSL's X509 parsing functions
    // to extract the public key type and validate compatibility
    
    // Basic scheme validation
    switch (scheme) {
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
        case SignatureScheme::RSA_PSS_PSS_SHA256:
        case SignatureScheme::RSA_PSS_PSS_SHA384:
        case SignatureScheme::RSA_PSS_PSS_SHA512:
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
        case SignatureScheme::ED25519:
        case SignatureScheme::ED448:
            return Result<bool>(true);
        default:
            return Result<bool>(false);
    }
}

// Timing-attack resistant signature verification helpers
Result<bool> constant_time_signature_verify(
    const std::vector<uint8_t>& signature1,
    const std::vector<uint8_t>& signature2) {
    
    // Constant-time comparison to prevent timing attacks
    if (signature1.size() != signature2.size()) {
        return Result<bool>(false);
    }
    
    volatile uint8_t result = 0;
    for (size_t i = 0; i < signature1.size(); i++) {
        result |= signature1[i] ^ signature2[i];
    }
    
    return Result<bool>(result == 0);
}

} // namespace utils

} // namespace crypto
} // namespace v13
} // namespace dtls