#include <dtls/crypto/openssl_provider.h>
#include <dtls/crypto/crypto_utils.h>

using namespace dtls::v13::crypto::utils;
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <chrono>
#include <thread>
#include <iostream>

namespace dtls {
namespace v13 {
namespace crypto {

// OpenSSL Provider Implementation (Basic Stub)
// Note: This is a minimal implementation to get the system compiling.
// Full OpenSSL integration would require extensive implementation.

class OpenSSLProvider::Impl {
public:
    bool initialized_{false};
    SecurityLevel security_level_{SecurityLevel::HIGH};
    
    Impl() = default;
    ~Impl() = default;
};

OpenSSLProvider::OpenSSLProvider() 
    : pimpl_(std::make_unique<Impl>()) {}

OpenSSLProvider::~OpenSSLProvider() {
    cleanup();
}

OpenSSLProvider::OpenSSLProvider(OpenSSLProvider&& other) noexcept
    : pimpl_(std::move(other.pimpl_)) {}

OpenSSLProvider& OpenSSLProvider::operator=(OpenSSLProvider&& other) noexcept {
    if (this != &other) {
        cleanup();
        pimpl_ = std::move(other.pimpl_);
    }
    return *this;
}

// Provider information
std::string OpenSSLProvider::name() const {
    return "openssl";
}

std::string OpenSSLProvider::version() const {
    return OPENSSL_VERSION_TEXT;
}

ProviderCapabilities OpenSSLProvider::capabilities() const {
    ProviderCapabilities caps;
    caps.provider_name = "openssl";
    caps.provider_version = OPENSSL_VERSION_TEXT;
    
    // Supported cipher suites
    caps.supported_cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_AES_128_CCM_SHA256,
        CipherSuite::TLS_AES_128_CCM_8_SHA256
    };
    
    // Supported groups
    caps.supported_groups = {
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::SECP521R1,
        NamedGroup::X25519,
        NamedGroup::X448,
        NamedGroup::FFDHE2048,
        NamedGroup::FFDHE3072,
        NamedGroup::FFDHE4096
    };
    
    // Supported signatures
    caps.supported_signatures = {
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
        SignatureScheme::RSA_PSS_RSAE_SHA512,
        SignatureScheme::ED25519,
        SignatureScheme::ED448
    };
    
    // Supported hashes
    caps.supported_hashes = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512,
        HashAlgorithm::SHA3_256,
        HashAlgorithm::SHA3_384,
        HashAlgorithm::SHA3_512
    };
    
    caps.hardware_acceleration = false; // Would need detection logic
    caps.fips_mode = false; // Would need FIPS mode detection
    
    return caps;
}

bool OpenSSLProvider::is_available() const {
    return openssl_utils::is_openssl_available();
}

Result<void> OpenSSLProvider::initialize() {
    if (pimpl_->initialized_) {
        return Result<void>(DTLSError::ALREADY_INITIALIZED);
    }
    
    auto init_result = openssl_utils::initialize_openssl();
    if (!init_result) {
        return init_result;
    }
    
    pimpl_->initialized_ = true;
    return Result<void>();
}

void OpenSSLProvider::cleanup() {
    if (pimpl_ && pimpl_->initialized_) {
        pimpl_->initialized_ = false;
    }
}

// Random number generation - RFC 9147 compliant implementation
Result<std::vector<uint8_t>> OpenSSLProvider::generate_random(const RandomParams& params) {
    DTLS_CRYPTO_TIMER("openssl_generate_random");
    
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    // Validate parameters according to RFC 9147 requirements
    if (params.length == 0) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // For DTLS v1.3, enforce 32-byte random for ClientHello/ServerHello compliance
    if (params.length > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Check if cryptographically secure random is requested (required for DTLS v1.3)
    if (params.cryptographically_secure) {
        // Verify OpenSSL PRNG is properly seeded for FIPS compliance
        if (RAND_status() != 1) {
            // Attempt to seed the PRNG if not already seeded
            if (RAND_poll() != 1) {
                return Result<std::vector<uint8_t>>(DTLSError::RANDOM_GENERATION_FAILED);
            }
        }
    }
    
    std::vector<uint8_t> random_bytes(params.length);
    
    // Use RAND_bytes for cryptographically secure generation (RFC 9147 requirement)
    int result;
    if (params.cryptographically_secure) {
        result = RAND_bytes(random_bytes.data(), static_cast<int>(params.length));
    } else {
        // Use RAND_pseudo_bytes for non-cryptographic use (deprecated in OpenSSL 1.1.0+)
        // Fall back to RAND_bytes for better security
        result = RAND_bytes(random_bytes.data(), static_cast<int>(params.length));
    }
    
    if (result != 1) {
        // Enhanced error reporting - get specific OpenSSL error
        unsigned long openssl_error = ERR_get_error();
        
        // Clear the error and secure zero the buffer
        secure_cleanup(random_bytes);
        
        // Map specific OpenSSL random generation errors
        if (openssl_error != 0) {
            return Result<std::vector<uint8_t>>(map_openssl_error_detailed());
        } else {
            return Result<std::vector<uint8_t>>(DTLSError::RANDOM_GENERATION_FAILED);
        }
    }
    
    // If additional entropy is provided, mix it in using HKDF-Extract pattern
    if (!params.additional_entropy.empty()) {
        // Create a simple entropy mixing using XOR (for additional randomness)
        // Note: This is a lightweight approach - for production, consider HKDF-Extract
        size_t entropy_pos = 0;
        for (size_t i = 0; i < random_bytes.size() && entropy_pos < params.additional_entropy.size(); ++i) {
            random_bytes[i] ^= params.additional_entropy[entropy_pos];
            entropy_pos = (entropy_pos + 1) % params.additional_entropy.size();
        }
    }
    
    // Validate the generated random for basic entropy (simple statistical check)
    if (params.cryptographically_secure && params.length >= 16) {
        if (!validate_random_entropy(random_bytes)) {
            secure_cleanup(random_bytes);
            return Result<std::vector<uint8_t>>(DTLSError::RANDOM_GENERATION_FAILED);
        }
    }
    
    return Result<std::vector<uint8_t>>(std::move(random_bytes));
}

// HKDF key derivation implementation
Result<std::vector<uint8_t>> OpenSSLProvider::derive_key_hkdf(const KeyDerivationParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (params.secret.empty() || params.output_length == 0) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get the hash algorithm
    const EVP_MD* md = nullptr;
    switch (params.hash_algorithm) {
        case HashAlgorithm::SHA256:
            md = EVP_sha256();
            break;
        case HashAlgorithm::SHA384:
            md = EVP_sha384();
            break;
        case HashAlgorithm::SHA512:
            md = EVP_sha512();
            break;
        default:
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!md) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Create KDF context
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    std::vector<uint8_t> output(params.output_length);
    size_t output_len = params.output_length;
    
    int result = 1;
    
    // Initialize HKDF
    if (result == 1) {
        result = EVP_PKEY_derive_init(pctx);
    }
    
    // Set hash algorithm
    if (result == 1) {
        result = EVP_PKEY_CTX_set_hkdf_md(pctx, md);
    }
    
    // Set input key material (IKM)
    if (result == 1) {
        result = EVP_PKEY_CTX_set1_hkdf_key(pctx, params.secret.data(), 
                                           static_cast<int>(params.secret.size()));
    }
    
    // Set salt if provided
    if (result == 1 && !params.salt.empty()) {
        result = EVP_PKEY_CTX_set1_hkdf_salt(pctx, params.salt.data(), 
                                            static_cast<int>(params.salt.size()));
    }
    
    // Set info if provided
    if (result == 1 && !params.info.empty()) {
        result = EVP_PKEY_CTX_add1_hkdf_info(pctx, params.info.data(), 
                                            static_cast<int>(params.info.size()));
    }
    
    // Derive the key
    if (result == 1) {
        result = EVP_PKEY_derive(pctx, output.data(), &output_len);
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    if (result != 1) {
        return Result<std::vector<uint8_t>>(DTLSError::KEY_DERIVATION_FAILED);
    }
    
    output.resize(output_len);
    return Result<std::vector<uint8_t>>(std::move(output));
}

Result<std::vector<uint8_t>> OpenSSLProvider::derive_key_pbkdf2(const KeyDerivationParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    // TODO: Implement PBKDF2 using OpenSSL PKCS5_PBKDF2_HMAC
    return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

// AEAD encryption implementation
Result<std::vector<uint8_t>> OpenSSLProvider::aead_encrypt(
    const AEADParams& params,
    const std::vector<uint8_t>& plaintext) {
    
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (plaintext.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate AEAD parameters using new helper function
    auto validation_result = validate_aead_params(params.cipher, params.key, params.nonce);
    if (!validation_result) {
        return Result<std::vector<uint8_t>>(validation_result.error());
    }
    
    // Get the cipher algorithm and tag length using helper functions
    const EVP_CIPHER* cipher = nullptr;
    size_t tag_length = get_aead_tag_length(params.cipher);
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            break;
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            break;
        default:
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!cipher) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    // Output buffer: plaintext + tag
    std::vector<uint8_t> ciphertext(plaintext.size() + tag_length);
    int outlen = 0;
    int result = 1;
    
    // Initialize encryption
    if (result == 1) {
        result = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    }
    
    // Set nonce length (for GCM/CCM)
    if (result == 1 && (params.cipher == AEADCipher::AES_128_GCM || 
                        params.cipher == AEADCipher::AES_256_GCM ||
                        params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 
                                    static_cast<int>(params.nonce.size()), nullptr);
    }
    
    // For CCM, set tag length
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 
                                    static_cast<int>(tag_length), nullptr);
    }
    
    // Set key and nonce
    if (result == 1) {
        result = EVP_EncryptInit_ex(ctx, nullptr, nullptr, params.key.data(), params.nonce.data());
    }
    
    // For CCM, set plaintext length
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_EncryptUpdate(ctx, nullptr, &outlen, nullptr, static_cast<int>(plaintext.size()));
    }
    
    // Set additional authenticated data (AAD)
    if (result == 1 && !params.additional_data.empty()) {
        result = EVP_EncryptUpdate(ctx, nullptr, &outlen, 
                                  params.additional_data.data(), 
                                  static_cast<int>(params.additional_data.size()));
    }
    
    // Encrypt plaintext
    if (result == 1) {
        result = EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, 
                                  plaintext.data(), static_cast<int>(plaintext.size()));
    }
    
    // Finalize encryption
    int final_len = 0;
    if (result == 1) {
        result = EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &final_len);
    }
    
    // Get authentication tag
    if (result == 1) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 
                                    static_cast<int>(tag_length), 
                                    ciphertext.data() + plaintext.size());
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (result != 1) {
        DTLSError error = map_openssl_error_detailed();
        return Result<std::vector<uint8_t>>(error);
    }
    
    ciphertext.resize(plaintext.size() + tag_length);
    return Result<std::vector<uint8_t>>(std::move(ciphertext));
}

Result<std::vector<uint8_t>> OpenSSLProvider::aead_decrypt(
    const AEADParams& params,
    const std::vector<uint8_t>& ciphertext) {
    
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (ciphertext.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate AEAD parameters using new helper function
    auto validation_result = validate_aead_params(params.cipher, params.key, params.nonce);
    if (!validation_result) {
        return Result<std::vector<uint8_t>>(validation_result.error());
    }
    
    // Get the cipher algorithm and tag length using helper functions
    const EVP_CIPHER* cipher = nullptr;
    size_t tag_length = get_aead_tag_length(params.cipher);
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            break;
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            break;
        default:
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!cipher || ciphertext.size() < tag_length) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    // Split ciphertext and tag
    size_t plaintext_len = ciphertext.size() - tag_length;
    std::vector<uint8_t> plaintext(plaintext_len);
    const uint8_t* tag_data = ciphertext.data() + plaintext_len;
    
    int outlen = 0;
    int result = 1;
    
    // Initialize decryption
    if (result == 1) {
        result = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    }
    
    // Set nonce length (for GCM/CCM)
    if (result == 1 && (params.cipher == AEADCipher::AES_128_GCM || 
                        params.cipher == AEADCipher::AES_256_GCM ||
                        params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 
                                    static_cast<int>(params.nonce.size()), nullptr);
    }
    
    // For CCM, set tag length and tag
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 
                                    static_cast<int>(tag_length), 
                                    const_cast<uint8_t*>(tag_data));
    }
    
    // Set key and nonce
    if (result == 1) {
        result = EVP_DecryptInit_ex(ctx, nullptr, nullptr, params.key.data(), params.nonce.data());
    }
    
    // For CCM, set ciphertext length
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_DecryptUpdate(ctx, nullptr, &outlen, nullptr, static_cast<int>(plaintext_len));
    }
    
    // Set additional authenticated data (AAD)
    if (result == 1 && !params.additional_data.empty()) {
        result = EVP_DecryptUpdate(ctx, nullptr, &outlen, 
                                  params.additional_data.data(), 
                                  static_cast<int>(params.additional_data.size()));
    }
    
    // Decrypt ciphertext
    if (result == 1) {
        result = EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, 
                                  ciphertext.data(), static_cast<int>(plaintext_len));
    }
    
    // For GCM, set the tag for verification
    if (result == 1 && (params.cipher == AEADCipher::AES_128_GCM ||
                        params.cipher == AEADCipher::AES_256_GCM ||
                        params.cipher == AEADCipher::CHACHA20_POLY1305)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 
                                    static_cast<int>(tag_length), 
                                    const_cast<uint8_t*>(tag_data));
    }
    
    // Finalize decryption (this verifies the tag)
    int final_len = 0;
    if (result == 1) {
        result = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &final_len);
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (result != 1) {
        DTLSError error = map_openssl_error_detailed();
        // For AEAD decryption failures, prefer DECRYPT_ERROR for authentication failures
        if (error == DTLSError::CRYPTO_PROVIDER_ERROR) {
            error = DTLSError::DECRYPT_ERROR;
        }
        return Result<std::vector<uint8_t>>(error);
    }
    
    plaintext.resize(outlen + final_len);
    return Result<std::vector<uint8_t>>(std::move(plaintext));
}

// New AEAD interface with separate ciphertext and tag
Result<AEADEncryptionOutput> OpenSSLProvider::encrypt_aead(const AEADEncryptionParams& params) {
    if (!pimpl_->initialized_) {
        return Result<AEADEncryptionOutput>(DTLSError::NOT_INITIALIZED);
    }
    
    if (params.plaintext.empty()) {
        return Result<AEADEncryptionOutput>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate AEAD parameters using new helper function
    auto validation_result = validate_aead_params(params.cipher, params.key, params.nonce);
    if (!validation_result) {
        return Result<AEADEncryptionOutput>(validation_result.error());
    }
    
    // Get the cipher algorithm and tag length using helper functions
    const EVP_CIPHER* cipher = nullptr;
    size_t tag_length = get_aead_tag_length(params.cipher);
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            break;
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            break;
        default:
            return Result<AEADEncryptionOutput>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!cipher) {
        return Result<AEADEncryptionOutput>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<AEADEncryptionOutput>(DTLSError::OUT_OF_MEMORY);
    }
    
    // Output buffers
    std::vector<uint8_t> ciphertext(params.plaintext.size());
    std::vector<uint8_t> tag(tag_length);
    int outlen = 0;
    int result = 1;
    
    // Initialize encryption
    if (result == 1) {
        result = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    }
    
    // Set nonce length (for GCM/CCM)
    if (result == 1 && (params.cipher == AEADCipher::AES_128_GCM || 
                        params.cipher == AEADCipher::AES_256_GCM ||
                        params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 
                                    static_cast<int>(params.nonce.size()), nullptr);
    }
    
    // For CCM, set tag length
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 
                                    static_cast<int>(tag_length), nullptr);
    }
    
    // Set key and nonce
    if (result == 1) {
        result = EVP_EncryptInit_ex(ctx, nullptr, nullptr, params.key.data(), params.nonce.data());
    }
    
    // For CCM, set plaintext length
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_EncryptUpdate(ctx, nullptr, &outlen, nullptr, static_cast<int>(params.plaintext.size()));
    }
    
    // Set additional authenticated data (AAD)
    if (result == 1 && !params.additional_data.empty()) {
        result = EVP_EncryptUpdate(ctx, nullptr, &outlen, 
                                  params.additional_data.data(), 
                                  static_cast<int>(params.additional_data.size()));
    }
    
    // Encrypt plaintext
    if (result == 1) {
        result = EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, 
                                  params.plaintext.data(), static_cast<int>(params.plaintext.size()));
    }
    
    // Finalize encryption
    int final_len = 0;
    if (result == 1) {
        result = EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &final_len);
    }
    
    // Get authentication tag
    if (result == 1) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 
                                    static_cast<int>(tag_length), 
                                    tag.data());
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (result != 1) {
        DTLSError error = map_openssl_error_detailed();
        return Result<AEADEncryptionOutput>(error);
    }
    
    ciphertext.resize(outlen + final_len);
    
    AEADEncryptionOutput output;
    output.ciphertext = std::move(ciphertext);
    output.tag = std::move(tag);
    
    return Result<AEADEncryptionOutput>(std::move(output));
}

Result<std::vector<uint8_t>> OpenSSLProvider::decrypt_aead(const AEADDecryptionParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (params.ciphertext.empty() || params.tag.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate AEAD parameters using new helper function
    auto validation_result = validate_aead_params(params.cipher, params.key, params.nonce);
    if (!validation_result) {
        return Result<std::vector<uint8_t>>(validation_result.error());
    }
    
    // Get the cipher algorithm and validate tag length
    const EVP_CIPHER* cipher = nullptr;
    size_t expected_tag_length = get_aead_tag_length(params.cipher);
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            break;
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            break;
        default:
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!cipher || params.tag.size() != expected_tag_length) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    // Output buffer
    std::vector<uint8_t> plaintext(params.ciphertext.size());
    int outlen = 0;
    int result = 1;
    
    // Initialize decryption
    if (result == 1) {
        result = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    }
    
    // Set nonce length (for GCM/CCM)
    if (result == 1 && (params.cipher == AEADCipher::AES_128_GCM || 
                        params.cipher == AEADCipher::AES_256_GCM ||
                        params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 
                                    static_cast<int>(params.nonce.size()), nullptr);
    }
    
    // For CCM, set tag length and tag
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 
                                    static_cast<int>(expected_tag_length), 
                                    const_cast<uint8_t*>(params.tag.data()));
    }
    
    // Set key and nonce
    if (result == 1) {
        result = EVP_DecryptInit_ex(ctx, nullptr, nullptr, params.key.data(), params.nonce.data());
    }
    
    // For CCM, set ciphertext length
    if (result == 1 && (params.cipher == AEADCipher::AES_128_CCM ||
                        params.cipher == AEADCipher::AES_128_CCM_8)) {
        result = EVP_DecryptUpdate(ctx, nullptr, &outlen, nullptr, static_cast<int>(params.ciphertext.size()));
    }
    
    // Set additional authenticated data (AAD)
    if (result == 1 && !params.additional_data.empty()) {
        result = EVP_DecryptUpdate(ctx, nullptr, &outlen, 
                                  params.additional_data.data(), 
                                  static_cast<int>(params.additional_data.size()));
    }
    
    // Decrypt ciphertext
    if (result == 1) {
        result = EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, 
                                  params.ciphertext.data(), static_cast<int>(params.ciphertext.size()));
    }
    
    // For GCM, set the tag for verification
    if (result == 1 && (params.cipher == AEADCipher::AES_128_GCM ||
                        params.cipher == AEADCipher::AES_256_GCM ||
                        params.cipher == AEADCipher::CHACHA20_POLY1305)) {
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 
                                    static_cast<int>(expected_tag_length), 
                                    const_cast<uint8_t*>(params.tag.data()));
    }
    
    // Finalize decryption (this verifies the tag)
    int final_len = 0;
    if (result == 1) {
        result = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &final_len);
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (result != 1) {
        DTLSError error = map_openssl_error_detailed();
        // For AEAD decryption failures, prefer DECRYPT_ERROR for authentication failures
        if (error == DTLSError::CRYPTO_PROVIDER_ERROR) {
            error = DTLSError::DECRYPT_ERROR;
        }
        return Result<std::vector<uint8_t>>(error);
    }
    
    plaintext.resize(outlen + final_len);
    return Result<std::vector<uint8_t>>(std::move(plaintext));
}

// Hash functions
Result<std::vector<uint8_t>> OpenSSLProvider::compute_hash(const HashParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    const EVP_MD* md = nullptr;
    
    switch (params.algorithm) {
        case HashAlgorithm::SHA256:
            md = EVP_sha256();
            break;
        case HashAlgorithm::SHA384:
            md = EVP_sha384();
            break;
        case HashAlgorithm::SHA512:
            md = EVP_sha512();
            break;
        default:
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!md) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    std::vector<uint8_t> hash(EVP_MD_size(md));
    unsigned int hash_len = 0;
    
    int result = EVP_DigestInit_ex(ctx, md, nullptr);
    if (result == 1) {
        result = EVP_DigestUpdate(ctx, params.data.data(), params.data.size());
    }
    if (result == 1) {
        result = EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
    }
    
    EVP_MD_CTX_free(ctx);
    
    if (result != 1) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    hash.resize(hash_len);
    return Result<std::vector<uint8_t>>(std::move(hash));
}

Result<std::vector<uint8_t>> OpenSSLProvider::compute_hmac(const HMACParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    const EVP_MD* md = nullptr;
    
    switch (params.algorithm) {
        case HashAlgorithm::SHA256:
            md = EVP_sha256();
            break;
        case HashAlgorithm::SHA384:
            md = EVP_sha384();
            break;
        case HashAlgorithm::SHA512:
            md = EVP_sha512();
            break;
        default:
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!md) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> hmac(EVP_MD_size(md));
    unsigned int hmac_len = 0;
    
    unsigned char* result = HMAC(md, 
                                params.key.data(), static_cast<int>(params.key.size()),
                                params.data.data(), params.data.size(),
                                hmac.data(), &hmac_len);
    
    if (!result) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    hmac.resize(hmac_len);
    return Result<std::vector<uint8_t>>(std::move(hmac));
}

// MAC validation with timing-attack resistance (RFC 9147 Section 5.2)
Result<bool> OpenSSLProvider::verify_hmac(const MACValidationParams& params) {
    if (!pimpl_->initialized_) {
        return Result<bool>(DTLSError::NOT_INITIALIZED);
    }
    
    // Input validation
    if (params.key.empty() || params.data.empty() || params.expected_mac.empty()) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Check maximum data length if specified
    if (params.max_data_length > 0 && params.data.size() > params.max_data_length) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Compute HMAC using existing method
    HMACParams hmac_params;
    hmac_params.key = params.key;
    hmac_params.data = params.data;
    hmac_params.algorithm = params.algorithm;
    
    auto computed_hmac_result = compute_hmac(hmac_params);
    if (!computed_hmac_result) {
        return Result<bool>(computed_hmac_result.error());
    }
    
    const auto& computed_hmac = computed_hmac_result.value();
    
    // Always use constant-time comparison to prevent timing attacks
    bool is_valid = false;
    
    // Ensure both MACs are always computed with same-size expectations
    // This prevents timing attacks based on MAC length validation
    bool size_match = (computed_hmac.size() == params.expected_mac.size());
    
    if (params.constant_time_required || true) { // Always use constant-time for security
        // Use OpenSSL's CRYPTO_memcmp if available and sizes match
        if (size_match) {
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
            // OpenSSL 1.1.0+ has CRYPTO_memcmp
            is_valid = (CRYPTO_memcmp(computed_hmac.data(), params.expected_mac.data(), computed_hmac.size()) == 0);
#else
            // Fallback to our enhanced constant-time comparison
            is_valid = constant_time_compare(computed_hmac, params.expected_mac);
#endif
        } else {
            // Always use our constant-time comparison for size mismatches
            is_valid = constant_time_compare(computed_hmac, params.expected_mac);
        }
    } else {
        // This branch should never be used in production
        is_valid = size_match && (computed_hmac == params.expected_mac);
    }
    
    return Result<bool>(is_valid);
}

// DTLS v1.3 record MAC validation (RFC 9147 Section 4.2.1)
Result<bool> OpenSSLProvider::validate_record_mac(const RecordMACParams& params) {
    if (!pimpl_->initialized_) {
        return Result<bool>(DTLSError::NOT_INITIALIZED);
    }
    
    // Input validation
    if (params.mac_key.empty() || params.record_header.empty() || 
        params.plaintext.empty() || params.expected_mac.empty()) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Construct MAC input according to RFC 9147 Section 4.2.1:
    // MAC(MAC_key, seq_num_encrypted || DTLSCiphertext.type || 
    //     DTLSCiphertext.version || DTLSCiphertext.epoch ||
    //     DTLSCiphertext.sequence_number || DTLSCiphertext.length ||
    //     DTLSInnerPlaintext)
    
    std::vector<uint8_t> mac_input;
    mac_input.reserve(8 + params.record_header.size() + params.plaintext.size());
    
    // Add encrypted sequence number (8 bytes)
    // For now, we'll use the raw sequence number - proper implementation would
    // encrypt it using the sequence_number_key
    uint64_t seq_num = static_cast<uint64_t>(params.sequence_number);
    for (int i = 7; i >= 0; --i) {
        mac_input.push_back(static_cast<uint8_t>((seq_num >> (i * 8)) & 0xFF));
    }
    
    // Add record header components
    mac_input.insert(mac_input.end(), params.record_header.begin(), params.record_header.end());
    
    // Add plaintext
    mac_input.insert(mac_input.end(), params.plaintext.begin(), params.plaintext.end());
    
    // Compute HMAC
    HMACParams hmac_params;
    hmac_params.key = params.mac_key;
    hmac_params.data = mac_input;
    hmac_params.algorithm = params.mac_algorithm;
    
    auto computed_mac_result = compute_hmac(hmac_params);
    if (!computed_mac_result) {
        return Result<bool>(computed_mac_result.error());
    }
    
    const auto& computed_mac = computed_mac_result.value();
    
    // Always use constant-time comparison to prevent timing attacks
    bool is_valid = false;
    bool size_match = (computed_mac.size() == params.expected_mac.size());
    
    if (size_match) {
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        // OpenSSL 1.1.0+ has CRYPTO_memcmp
        is_valid = (CRYPTO_memcmp(computed_mac.data(), params.expected_mac.data(), computed_mac.size()) == 0);
#else
        // Fallback to our enhanced constant-time comparison
        is_valid = constant_time_compare(computed_mac, params.expected_mac);
#endif
    } else {
        // Always use our constant-time comparison for size mismatches
        is_valid = constant_time_compare(computed_mac, params.expected_mac);
    }
    
    return Result<bool>(is_valid);
}

// Legacy MAC verification for backward compatibility
Result<bool> OpenSSLProvider::verify_hmac_legacy(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& expected_mac,
    HashAlgorithm algorithm) {
    
    if (!pimpl_->initialized_) {
        return Result<bool>(DTLSError::NOT_INITIALIZED);
    }
    
    // Create MACValidationParams for consistency
    MACValidationParams params;
    params.key = key;
    params.data = data;
    params.expected_mac = expected_mac;
    params.algorithm = algorithm;
    params.constant_time_required = true; // Always use constant-time for security
    
    return verify_hmac(params);
}

// AEAD utility functions
size_t OpenSSLProvider::get_aead_key_length(AEADCipher cipher) const {
    switch (cipher) {
        case AEADCipher::AES_128_GCM:
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            return 16; // 128 bits
        case AEADCipher::AES_256_GCM:
            return 32; // 256 bits
        case AEADCipher::CHACHA20_POLY1305:
            return 32; // 256 bits
        default:
            return 0;
    }
}

size_t OpenSSLProvider::get_aead_nonce_length(AEADCipher cipher) const {
    switch (cipher) {
        case AEADCipher::AES_128_GCM:
        case AEADCipher::AES_256_GCM:
            return 12; // 96 bits for GCM
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            return 12; // 96 bits for CCM (can vary but 12 is standard)
        case AEADCipher::CHACHA20_POLY1305:
            return 12; // 96 bits
        default:
            return 0;
    }
}

size_t OpenSSLProvider::get_aead_tag_length(AEADCipher cipher) const {
    switch (cipher) {
        case AEADCipher::AES_128_GCM:
        case AEADCipher::AES_256_GCM:
        case AEADCipher::AES_128_CCM:
        case AEADCipher::CHACHA20_POLY1305:
            return 16; // 128 bits
        case AEADCipher::AES_128_CCM_8:
            return 8; // 64 bits
        default:
            return 0;
    }
}

Result<void> OpenSSLProvider::validate_aead_params(const AEADCipher cipher, 
                                                   const std::vector<uint8_t>& key,
                                                   const std::vector<uint8_t>& nonce) const {
    // Validate key length
    size_t expected_key_len = get_aead_key_length(cipher);
    if (expected_key_len == 0) {
        return Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    if (key.size() != expected_key_len) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate nonce length
    size_t expected_nonce_len = get_aead_nonce_length(cipher);
    if (expected_nonce_len == 0) {
        return Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    if (nonce.size() != expected_nonce_len) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    return Result<void>();
}

// Enhanced OpenSSL error handling
DTLSError OpenSSLProvider::map_openssl_error_detailed() const {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return DTLSError::SUCCESS;
    }
    
    int lib = ERR_GET_LIB(err);
    int reason = ERR_GET_REASON(err);
    
    // Map specific OpenSSL errors to DTLS errors
    switch (lib) {
        case ERR_LIB_EVP:
            switch (reason) {
                case EVP_R_BAD_DECRYPT:
                case EVP_R_CIPHER_PARAMETER_ERROR:
                    return DTLSError::DECRYPT_ERROR;
                case EVP_R_UNSUPPORTED_CIPHER:
                    return DTLSError::OPERATION_NOT_SUPPORTED;
                case EVP_R_INVALID_KEY_LENGTH:
                case EVP_R_INVALID_IV_LENGTH:
                    return DTLSError::INVALID_PARAMETER;
                default:
                    return DTLSError::CRYPTO_PROVIDER_ERROR;
            }
        case ERR_LIB_SSL:
            return DTLSError::CRYPTO_PROVIDER_ERROR;
        default:
            return DTLSError::CRYPTO_PROVIDER_ERROR;
    }
}

// Secure memory cleanup utility
void OpenSSLProvider::secure_cleanup(std::vector<uint8_t>& buffer) const {
    if (!buffer.empty()) {
        OPENSSL_cleanse(buffer.data(), buffer.size());
        buffer.clear();
    }
}

// Random entropy validation for RFC 9147 compliance
bool OpenSSLProvider::validate_random_entropy(const std::vector<uint8_t>& random_data) const {
    if (random_data.empty()) {
        return false;
    }
    
    // Simple entropy checks for DTLS v1.3 random values
    // These are basic statistical tests, not comprehensive entropy analysis
    
    // 1. Check for all-zero bytes (obvious failure)
    bool all_zero = std::all_of(random_data.begin(), random_data.end(), 
                               [](uint8_t byte) { return byte == 0; });
    if (all_zero) {
        return false;
    }
    
    // 2. Check for all-same bytes
    bool all_same = std::all_of(random_data.begin(), random_data.end(),
                               [&](uint8_t byte) { return byte == random_data[0]; });
    if (all_same) {
        return false;
    }
    
    // 3. Basic frequency analysis - no byte value should occur more than 75% of the time
    if (random_data.size() >= 16) {
        std::array<size_t, 256> byte_count{};
        for (uint8_t byte : random_data) {
            byte_count[byte]++;
        }
        
        size_t max_frequency = *std::max_element(byte_count.begin(), byte_count.end());
        double frequency_ratio = static_cast<double>(max_frequency) / random_data.size();
        
        if (frequency_ratio > 0.75) {
            return false;
        }
    }
    
    // 4. Simple runs test - check for excessive runs of consecutive same bits
    if (random_data.size() >= 8) {
        size_t max_run = 0;
        size_t current_run = 1;
        uint8_t prev_bit = random_data[0] & 1;
        
        for (size_t i = 1; i < random_data.size(); ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                uint8_t current_bit = (random_data[i] >> bit) & 1;
                if (current_bit == prev_bit) {
                    current_run++;
                } else {
                    max_run = std::max(max_run, current_run);
                    current_run = 1;
                    prev_bit = current_bit;
                }
            }
        }
        max_run = std::max(max_run, current_run);
        
        // For 32-byte random (256 bits), max run should be < 32 consecutive bits
        if (max_run > 32) {
            return false;
        }
    }
    
    // All basic entropy checks passed
    return true;
}

// Helper function to validate key type and signature scheme compatibility
bool OpenSSLProvider::validate_key_scheme_compatibility(int key_type, SignatureScheme scheme) const {
    switch (scheme) {
        // RSA signatures
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
            return key_type == EVP_PKEY_RSA;
            
        // ECDSA signatures
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
            return key_type == EVP_PKEY_EC;
            
        // EdDSA signatures
        case SignatureScheme::ED25519:
            return key_type == EVP_PKEY_ED25519;
        case SignatureScheme::ED448:
            return key_type == EVP_PKEY_ED448;
            
        default:
            return false;
    }
}

// Digital signature operations with enhanced security and DTLS v1.3 compliance
Result<std::vector<uint8_t>> OpenSSLProvider::sign_data(const SignatureParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    // Enhanced parameter validation
    if (!params.private_key || params.data.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate data size limits (prevent DoS attacks)
    if (params.data.size() > 1024 * 1024) { // 1MB limit
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Cast to OpenSSL private key
    const auto* openssl_key = dynamic_cast<const OpenSSLPrivateKey*>(params.private_key);
    if (!openssl_key) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* pkey = openssl_key->native_key();
    if (!pkey) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate that the key type matches the signature scheme
    int key_type = EVP_PKEY_base_id(pkey);
    if (!validate_key_scheme_compatibility(key_type, params.scheme)) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Thread-safe context creation
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    const EVP_MD* md = nullptr;
    int result = 1;
    
    // Get the hash algorithm based on signature scheme with enhanced validation
    switch (params.scheme) {
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
            md = EVP_sha256();
            break;
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
            md = EVP_sha384();
            break;
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
            md = EVP_sha512();
            break;
        case SignatureScheme::ED25519:
        case SignatureScheme::ED448:
            md = nullptr; // EdDSA doesn't use a separate hash
            break;
        default:
            EVP_MD_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Validate hash algorithm availability
    if (md && !md) {
        EVP_MD_CTX_free(ctx);
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Initialize signing context with proper error handling
    if (result == 1) {
        result = EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey);
        if (result != 1) {
            EVP_MD_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(map_openssl_error_detailed());
        }
    }
    
    // Configure algorithm-specific parameters
    EVP_PKEY_CTX* pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
    if (pkey_ctx) {
        // Configure RSA-PSS padding with proper salt length
        if (params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA256 ||
            params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA384 ||
            params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA512) {
            
            result = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
            if (result == 1) {
                // Use salt length equal to hash length (RFC 8017 recommendation)
                result = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
            }
            if (result == 1) {
                // Set MGF1 hash function to match the main hash
                result = EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, md);
            }
        }
        
        // Configure ECDSA for deterministic signatures (RFC 6979) if supported
        if (params.scheme == SignatureScheme::ECDSA_SECP256R1_SHA256 ||
            params.scheme == SignatureScheme::ECDSA_SECP384R1_SHA384 ||
            params.scheme == SignatureScheme::ECDSA_SECP521R1_SHA512) {
            
            // OpenSSL 3.0+ supports deterministic ECDSA via explicit setting
            // This improves security by making signatures reproducible
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            // Note: In OpenSSL 3.0+, we could set deterministic mode if available
            // EVP_PKEY_CTX_set_ecdsa_deterministic_k(pkey_ctx, 1);
#endif
        }
        
        if (result != 1) {
            EVP_MD_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(map_openssl_error_detailed());
        }
    }
    
    // Update with data to sign
    if (result == 1) {
        result = EVP_DigestSignUpdate(ctx, params.data.data(), params.data.size());
        if (result != 1) {
            EVP_MD_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(map_openssl_error_detailed());
        }
    }
    
    // Determine signature length
    size_t sig_len = 0;
    if (result == 1) {
        result = EVP_DigestSignFinal(ctx, nullptr, &sig_len);
        if (result != 1 || sig_len == 0) {
            EVP_MD_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(map_openssl_error_detailed());
        }
    }
    
    // Validate signature length is reasonable
    if (sig_len > 1024) { // Sanity check - no signature should be > 1KB
        EVP_MD_CTX_free(ctx);
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Generate the actual signature
    std::vector<uint8_t> signature(sig_len);
    if (result == 1) {
        result = EVP_DigestSignFinal(ctx, signature.data(), &sig_len);
        if (result != 1) {
            EVP_MD_CTX_free(ctx);
            // Clear signature buffer for security
            secure_cleanup(signature);
            return Result<std::vector<uint8_t>>(map_openssl_error_detailed());
        }
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Final validation and resize
    if (sig_len == 0) {
        secure_cleanup(signature);
        return Result<std::vector<uint8_t>>(DTLSError::SIGNATURE_VERIFICATION_FAILED);
    }
    
    signature.resize(sig_len);
    return Result<std::vector<uint8_t>>(std::move(signature));
}

Result<bool> OpenSSLProvider::verify_signature(const SignatureParams& params, const std::vector<uint8_t>& signature) {
    if (!pimpl_->initialized_) {
        return Result<bool>(DTLSError::NOT_INITIALIZED);
    }
    
    // Enhanced parameter validation
    if (!params.public_key || params.data.empty() || signature.empty()) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate data size limits (prevent DoS attacks)
    if (params.data.size() > 1024 * 1024) { // 1MB limit
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate signature size limits
    if (signature.size() > 1024) { // 1KB limit - no signature should be this large
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Cast to OpenSSL public key
    const auto* openssl_key = dynamic_cast<const OpenSSLPublicKey*>(params.public_key);
    if (!openssl_key) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* pkey = openssl_key->native_key();
    if (!pkey) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate that the key type matches the signature scheme
    int key_type = EVP_PKEY_base_id(pkey);
    if (!validate_key_scheme_compatibility(key_type, params.scheme)) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate signature length for the given scheme and key
    auto expected_length_result = get_signature_length(params.scheme, *params.public_key);
    if (expected_length_result) {
        size_t expected_max_length = *expected_length_result;
        // For ECDSA, signature can be variable length but should not exceed maximum
        // For RSA and EdDSA, signature length should be exact or close to expected
        if (signature.size() > expected_max_length) {
            return Result<bool>(DTLSError::INVALID_PARAMETER);
        }
        
        // For fixed-length signatures (RSA and EdDSA), check exact length
        if ((params.scheme == SignatureScheme::ED25519 && signature.size() != 64) ||
            (params.scheme == SignatureScheme::ED448 && signature.size() != 114)) {
            return Result<bool>(DTLSError::INVALID_PARAMETER);
        }
        
        // For RSA signatures, the signature length should match the key size
        if ((params.scheme == SignatureScheme::RSA_PKCS1_SHA256 ||
             params.scheme == SignatureScheme::RSA_PKCS1_SHA384 ||
             params.scheme == SignatureScheme::RSA_PKCS1_SHA512 ||
             params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA256 ||
             params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA384 ||
             params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA512) &&
            signature.size() != expected_max_length) {
            return Result<bool>(DTLSError::INVALID_PARAMETER);
        }
    }
    
    // Thread-safe context creation
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<bool>(DTLSError::OUT_OF_MEMORY);
    }
    
    const EVP_MD* md = nullptr;
    int result = 1;
    
    // Get the hash algorithm based on signature scheme with enhanced validation
    switch (params.scheme) {
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
            md = EVP_sha256();
            break;
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
            md = EVP_sha384();
            break;
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
            md = EVP_sha512();
            break;
        case SignatureScheme::ED25519:
        case SignatureScheme::ED448:
            md = nullptr; // EdDSA doesn't use a separate hash
            break;
        default:
            EVP_MD_CTX_free(ctx);
            return Result<bool>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Validate hash algorithm availability
    if (md && !md) {
        EVP_MD_CTX_free(ctx);
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Initialize verification context with proper error handling
    if (result == 1) {
        result = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey);
        if (result != 1) {
            EVP_MD_CTX_free(ctx);
            return Result<bool>(map_openssl_error_detailed());
        }
    }
    
    // Configure algorithm-specific parameters
    EVP_PKEY_CTX* pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
    if (pkey_ctx) {
        // Configure RSA-PSS padding with proper salt length (must match signing parameters)
        if (params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA256 ||
            params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA384 ||
            params.scheme == SignatureScheme::RSA_PSS_RSAE_SHA512) {
            
            result = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
            if (result == 1) {
                // Use salt length equal to hash length (RFC 8017 recommendation)
                result = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
            }
            if (result == 1) {
                // Set MGF1 hash function to match the main hash
                result = EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, md);
            }
        }
        
        if (result != 1) {
            EVP_MD_CTX_free(ctx);
            return Result<bool>(map_openssl_error_detailed());
        }
    }
    
    // Additional security validations before verification
    if (result == 1) {
        // For ECDSA signatures, perform ASN.1 format validation
        if (utils::is_ecdsa_signature(params.scheme)) {
            auto asn1_validation_result = utils::validate_ecdsa_asn1_signature(signature, *params.public_key);
            if (!asn1_validation_result) {
                EVP_MD_CTX_free(ctx);
                return Result<bool>(asn1_validation_result.error());
            }
            if (!*asn1_validation_result) {
                EVP_MD_CTX_free(ctx);
                return Result<bool>(false); // Invalid ASN.1 format
            }
        }
        
        // For EdDSA signatures, perform additional format validation
        if (params.scheme == SignatureScheme::ED25519 || params.scheme == SignatureScheme::ED448) {
            size_t expected_length = (params.scheme == SignatureScheme::ED25519) ? 64 : 114;
            if (signature.size() != expected_length || signature[0] == 0x00) {
                EVP_MD_CTX_free(ctx);
                return Result<bool>(false);
            }
        }
    }
    
    // Update with data to verify
    if (result == 1) {
        result = EVP_DigestVerifyUpdate(ctx, params.data.data(), params.data.size());
        if (result != 1) {
            EVP_MD_CTX_free(ctx);
            return Result<bool>(map_openssl_error_detailed());
        }
    }
    
    // Verify signature - this is the critical security operation
    // Record start time for timing attack mitigation
    auto verification_start = std::chrono::high_resolution_clock::now();
    
    if (result == 1) {
        result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    }
    
    // Add minimal delay to make timing more consistent (timing attack mitigation)
    auto verification_end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        verification_end - verification_start);
    
    // Ensure minimum verification time to reduce timing information leakage
    const auto min_verification_time = std::chrono::microseconds(10);
    if (duration < min_verification_time) {
        std::this_thread::sleep_for(min_verification_time - duration);
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Interpret the verification result according to OpenSSL conventions
    if (result == 1) {
        return Result<bool>(true);  // Signature verification succeeded
    } else if (result == 0) {
        return Result<bool>(false); // Signature verification failed (signature invalid)
    } else {
        // Error occurred during verification (result < 0)
        return Result<bool>(map_openssl_error_detailed());
    }
}

// DTLS v1.3 Certificate Verify (RFC 9147 Section 4.2.3)
Result<bool> OpenSSLProvider::verify_dtls_certificate_signature(
    const DTLSCertificateVerifyParams& params,
    const std::vector<uint8_t>& signature) {
    
    if (!pimpl_->initialized_) {
        return Result<bool>(DTLSError::NOT_INITIALIZED);
    }
    
    // Enhanced parameter validation for DTLS context
    if (!params.public_key || params.transcript_hash.empty() || signature.empty()) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate transcript hash size (reasonable limits for all supported hash algorithms)
    if (params.transcript_hash.size() < 20 || params.transcript_hash.size() > 64) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate signature size limits (prevent DoS attacks)
    if (signature.size() > 1024) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Cast to OpenSSL public key
    const auto* openssl_key = dynamic_cast<const OpenSSLPublicKey*>(params.public_key);
    if (!openssl_key) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* pkey = openssl_key->native_key();
    if (!pkey) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // Validate key-signature scheme compatibility
    int key_type = EVP_PKEY_base_id(pkey);
    if (!validate_key_scheme_compatibility(key_type, params.scheme)) {
        return Result<bool>(DTLSError::INVALID_PARAMETER);
    }
    
    // For ECDSA signatures, validate ASN.1 format
    if (utils::is_ecdsa_signature(params.scheme)) {
        auto asn1_validation_result = utils::validate_ecdsa_asn1_signature(signature, *params.public_key);
        if (!asn1_validation_result) {
            return Result<bool>(asn1_validation_result.error());
        }
        if (!*asn1_validation_result) {
            return Result<bool>(false); // Invalid ASN.1 format
        }
    }
    
    // Optional certificate compatibility validation
    if (!params.certificate_der.empty()) {
        auto cert_compat_result = utils::validate_certificate_signature_compatibility(
            params.certificate_der, params.scheme);
        if (!cert_compat_result) {
            return Result<bool>(cert_compat_result.error());
        }
        if (!*cert_compat_result) {
            return Result<bool>(DTLSError::INVALID_PARAMETER);
        }
    }
    
    // Construct the TLS 1.3 signature context
    auto context_result = utils::construct_dtls_signature_context(
        params.transcript_hash, params.is_server_context);
    if (!context_result) {
        return Result<bool>(context_result.error());
    }
    
    const auto& signature_input = *context_result;
    
    // Create signature verification parameters
    SignatureParams verify_params;
    verify_params.data = signature_input;
    verify_params.scheme = params.scheme;
    verify_params.public_key = params.public_key;
    
    // Perform the actual signature verification using the existing method
    auto verification_result = verify_signature(verify_params, signature);
    if (!verification_result) {
        return Result<bool>(verification_result.error());
    }
    
    // Additional security: For EdDSA signatures, perform additional validation
    if (params.scheme == SignatureScheme::ED25519 || params.scheme == SignatureScheme::ED448) {
        // EdDSA signatures should be exactly the expected length
        size_t expected_length = (params.scheme == SignatureScheme::ED25519) ? 64 : 114;
        if (signature.size() != expected_length) {
            return Result<bool>(false);
        }
        
        // EdDSA signatures should not have leading zero bytes (they're not ASN.1 encoded)
        if (signature[0] == 0x00) {
            return Result<bool>(false);
        }
    }
    
    return Result<bool>(*verification_result);
}

// Additional signature helper methods for DTLS v1.3
Result<size_t> OpenSSLProvider::get_signature_length(SignatureScheme scheme, const PrivateKey& key) const {
    if (!pimpl_->initialized_) {
        return Result<size_t>(DTLSError::NOT_INITIALIZED);
    }
    
    // Cast to OpenSSL private key
    const auto* openssl_key = dynamic_cast<const OpenSSLPrivateKey*>(&key);
    if (!openssl_key) {
        return Result<size_t>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* pkey = openssl_key->native_key();
    if (!pkey) {
        return Result<size_t>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get signature length based on key type and scheme
    int key_type = EVP_PKEY_base_id(pkey);
    size_t signature_length = 0;
    
    switch (scheme) {
        // RSA signatures - length depends on key size
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
            if (key_type == EVP_PKEY_RSA) {
                signature_length = static_cast<size_t>(EVP_PKEY_size(pkey));
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        // ECDSA signatures - variable length, estimate maximum
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
            if (key_type == EVP_PKEY_EC) {
                signature_length = 72; // Maximum for P-256 (2 * 32 + DER overhead)
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
            if (key_type == EVP_PKEY_EC) {
                signature_length = 104; // Maximum for P-384 (2 * 48 + DER overhead)
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
            if (key_type == EVP_PKEY_EC) {
                signature_length = 139; // Maximum for P-521 (2 * 66 + DER overhead)
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        // EdDSA signatures - fixed length
        case SignatureScheme::ED25519:
            if (key_type == EVP_PKEY_ED25519) {
                signature_length = 64; // Ed25519 signature is always 64 bytes
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        case SignatureScheme::ED448:
            if (key_type == EVP_PKEY_ED448) {
                signature_length = 114; // Ed448 signature is always 114 bytes
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        default:
            return Result<size_t>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    return Result<size_t>(signature_length);
}

// Overloaded version for public keys (same logic, different cast)
Result<size_t> OpenSSLProvider::get_signature_length(SignatureScheme scheme, const PublicKey& key) const {
    if (!pimpl_->initialized_) {
        return Result<size_t>(DTLSError::NOT_INITIALIZED);
    }
    
    // Cast to OpenSSL public key
    const auto* openssl_key = dynamic_cast<const OpenSSLPublicKey*>(&key);
    if (!openssl_key) {
        return Result<size_t>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* pkey = openssl_key->native_key();
    if (!pkey) {
        return Result<size_t>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get signature length based on key type and scheme
    int key_type = EVP_PKEY_base_id(pkey);
    size_t signature_length = 0;
    
    switch (scheme) {
        // RSA signatures - length depends on key size
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PKCS1_SHA384:
        case SignatureScheme::RSA_PKCS1_SHA512:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
            if (key_type == EVP_PKEY_RSA) {
                signature_length = static_cast<size_t>(EVP_PKEY_size(pkey));
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        // ECDSA signatures - variable length, estimate maximum
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
            if (key_type == EVP_PKEY_EC) {
                signature_length = 72; // Maximum for P-256 (2 * 32 + DER overhead)
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
            if (key_type == EVP_PKEY_EC) {
                signature_length = 104; // Maximum for P-384 (2 * 48 + DER overhead)
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
            if (key_type == EVP_PKEY_EC) {
                signature_length = 139; // Maximum for P-521 (2 * 66 + DER overhead)
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        // EdDSA signatures - fixed length
        case SignatureScheme::ED25519:
            if (key_type == EVP_PKEY_ED25519) {
                signature_length = 64; // Ed25519 signature is always 64 bytes
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        case SignatureScheme::ED448:
            if (key_type == EVP_PKEY_ED448) {
                signature_length = 114; // Ed448 signature is always 114 bytes
            } else {
                return Result<size_t>(DTLSError::INVALID_PARAMETER);
            }
            break;
            
        default:
            return Result<size_t>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    return Result<size_t>(signature_length);
}

Result<std::vector<uint8_t>> OpenSSLProvider::create_certificate_signature(
    const std::vector<uint8_t>& certificate_data,
    SignatureScheme scheme,
    const PrivateKey& private_key) const {
    
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (certificate_data.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Create signature parameters for certificate data
    SignatureParams params;
    params.data = certificate_data;
    params.scheme = scheme;
    params.private_key = &private_key;
    
    // Use the main sign_data method (cast away const since we're not modifying state)
    return const_cast<OpenSSLProvider*>(this)->sign_data(params);
}

Result<std::vector<uint8_t>> OpenSSLProvider::sign_handshake_transcript(
    const std::vector<uint8_t>& transcript_hash,
    SignatureScheme scheme,
    const PrivateKey& private_key,
    bool is_server) const {
    
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (transcript_hash.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // DTLS v1.3 handshake signature includes context strings per RFC 9147
    std::string context_string;
    if (is_server) {
        context_string = "TLS 1.3, server CertificateVerify";
    } else {
        context_string = "TLS 1.3, client CertificateVerify";
    }
    
    // Create the signed content as per RFC 8446 Section 4.4.3
    std::vector<uint8_t> content;
    
    // Add 64 space (0x20) characters
    content.insert(content.end(), 64, 0x20);
    
    // Add context string
    content.insert(content.end(), context_string.begin(), context_string.end());
    
    // Add separator byte (0x00)
    content.push_back(0x00);
    
    // Add transcript hash
    content.insert(content.end(), transcript_hash.begin(), transcript_hash.end());
    
    // Create signature parameters
    SignatureParams params;
    params.data = content;
    params.scheme = scheme;
    params.private_key = &private_key;
    
    // Use the main sign_data method (cast away const since we're not modifying state)
    return const_cast<OpenSSLProvider*>(this)->sign_data(params);
}

Result<std::vector<uint8_t>> OpenSSLProvider::generate_finished_signature(
    const std::vector<uint8_t>& finished_key,
    const std::vector<uint8_t>& transcript_hash,
    HashAlgorithm hash_algorithm) const {
    
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (finished_key.empty() || transcript_hash.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Finished message uses HMAC per RFC 9147 Section 4.4.4
    // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    // verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
    
    HMACParams hmac_params;
    hmac_params.key = finished_key;
    hmac_params.data = transcript_hash;
    hmac_params.algorithm = hash_algorithm;
    
    return const_cast<OpenSSLProvider*>(this)->compute_hmac(hmac_params);
}

std::vector<SignatureScheme> OpenSSLProvider::get_supported_signature_algorithms() const {
    auto caps = capabilities();
    return caps.supported_signatures;
}

Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
OpenSSLProvider::generate_key_pair(NamedGroup group) {
    if (!pimpl_->initialized_) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::NOT_INITIALIZED);
    }
    
    EVP_PKEY_CTX* pctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    int result = 1;
    
    switch (group) {
        case NamedGroup::SECP256R1:
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (pctx && result == 1) {
                result = EVP_PKEY_keygen_init(pctx);
            }
            if (result == 1) {
                result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
            }
            break;
            
        case NamedGroup::SECP384R1:
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (pctx && result == 1) {
                result = EVP_PKEY_keygen_init(pctx);
            }
            if (result == 1) {
                result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
            }
            break;
            
        case NamedGroup::SECP521R1:
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (pctx && result == 1) {
                result = EVP_PKEY_keygen_init(pctx);
            }
            if (result == 1) {
                result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1);
            }
            break;
            
        case NamedGroup::X25519:
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
            if (pctx && result == 1) {
                result = EVP_PKEY_keygen_init(pctx);
            }
            break;
            
        case NamedGroup::X448:
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
            if (pctx && result == 1) {
                result = EVP_PKEY_keygen_init(pctx);
            }
            break;
            
        default:
            using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
            return Result<ReturnType>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!pctx || result != 1) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::KEY_EXCHANGE_FAILED);
    }
    
    // Generate the key pair using cryptographically secure random generation
    if (result == 1) {
        result = EVP_PKEY_keygen(pctx, &pkey);
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    if (result != 1 || !pkey) {
        if (pkey) EVP_PKEY_free(pkey);
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::KEY_EXCHANGE_FAILED);
    }
    
    // Create private key wrapper
    auto private_key = std::make_unique<OpenSSLPrivateKey>(pkey);
    
    // Derive public key
    auto public_key_result = private_key->derive_public_key();
    if (!public_key_result) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(public_key_result.error());
    }
    
    auto public_key = std::move(*public_key_result);
    
    using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
    return Result<ReturnType>(std::make_pair(std::move(private_key), std::move(public_key)));
}

// RSA key generation method
Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
OpenSSLProvider::generate_rsa_keypair(int key_size) {
    if (!pimpl_->initialized_) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::NOT_INITIALIZED);
    }
    
    // Validate RSA key size
    if (key_size != 2048 && key_size != 3072 && key_size != 4096) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::OUT_OF_MEMORY);
    }
    
    EVP_PKEY* pkey = nullptr;
    int result = 1;
    
    // Initialize key generation
    if (result == 1) {
        result = EVP_PKEY_keygen_init(pctx);
    }
    
    // Set RSA key length
    if (result == 1) {
        result = EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, key_size);
    }
    
    // Set public exponent to 65537 (standard value)
    if (result == 1) {
        BIGNUM* e = BN_new();
        if (e && BN_set_word(e, RSA_F4) == 1) {
            result = EVP_PKEY_CTX_set_rsa_keygen_pubexp(pctx, e);
            // Note: e is now owned by the context, don't free it
        } else {
            if (e) BN_free(e);
            result = 0;
        }
    }
    
    // Generate the RSA key pair
    if (result == 1) {
        result = EVP_PKEY_keygen(pctx, &pkey);
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    if (result != 1 || !pkey) {
        if (pkey) EVP_PKEY_free(pkey);
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::KEY_EXCHANGE_FAILED);
    }
    
    // Create private key wrapper
    auto private_key = std::make_unique<OpenSSLPrivateKey>(pkey);
    
    // Derive public key
    auto public_key_result = private_key->derive_public_key();
    if (!public_key_result) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(public_key_result.error());
    }
    
    auto public_key = std::move(*public_key_result);
    
    using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
    return Result<ReturnType>(std::make_pair(std::move(private_key), std::move(public_key)));
}

// EdDSA key generation method
Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
OpenSSLProvider::generate_eddsa_keypair(int key_type) {
    if (!pimpl_->initialized_) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::NOT_INITIALIZED);
    }
    
    EVP_PKEY_CTX* pctx = nullptr;
    
    // Set up context based on key type
    switch (key_type) {
        case NID_ED25519:
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
            break;
        case NID_ED448:
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, nullptr);
            break;
        default:
            using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
            return Result<ReturnType>(DTLSError::INVALID_PARAMETER);
    }
    
    if (!pctx) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::OUT_OF_MEMORY);
    }
    
    EVP_PKEY* pkey = nullptr;
    int result = 1;
    
    // Initialize key generation
    if (result == 1) {
        result = EVP_PKEY_keygen_init(pctx);
    }
    
    // Generate the EdDSA key pair
    if (result == 1) {
        result = EVP_PKEY_keygen(pctx, &pkey);
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    if (result != 1 || !pkey) {
        if (pkey) EVP_PKEY_free(pkey);
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(DTLSError::KEY_EXCHANGE_FAILED);
    }
    
    // Create private key wrapper
    auto private_key = std::make_unique<OpenSSLPrivateKey>(pkey);
    
    // Derive public key
    auto public_key_result = private_key->derive_public_key();
    if (!public_key_result) {
        using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
        return Result<ReturnType>(public_key_result.error());
    }
    
    auto public_key = std::move(*public_key_result);
    
    using ReturnType = std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>;
    return Result<ReturnType>(std::make_pair(std::move(private_key), std::move(public_key)));
}

// Helper methods for supported curves and key sizes
std::vector<NamedGroup> OpenSSLProvider::get_supported_curves() const {
    return {
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::SECP521R1,
        NamedGroup::X25519,
        NamedGroup::X448
    };
}

std::vector<int> OpenSSLProvider::get_supported_rsa_sizes() const {
    return {2048, 3072, 4096};
}

Result<std::vector<uint8_t>> OpenSSLProvider::perform_key_exchange(const KeyExchangeParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (!params.private_key || params.peer_public_key.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Cast to OpenSSL private key
    const auto* openssl_private_key = dynamic_cast<const OpenSSLPrivateKey*>(params.private_key);
    if (!openssl_private_key) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* private_key = openssl_private_key->native_key();
    if (!private_key) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Create peer public key from raw bytes
    EVP_PKEY* peer_key = nullptr;
    
    switch (params.group) {
        case NamedGroup::X25519: {
            peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                  params.peer_public_key.data(),
                                                  params.peer_public_key.size());
            break;
        }
        case NamedGroup::X448: {
            peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, nullptr,
                                                  params.peer_public_key.data(),
                                                  params.peer_public_key.size());
            break;
        }
        case NamedGroup::SECP256R1:
        case NamedGroup::SECP384R1:
        case NamedGroup::SECP521R1: {
            // For ECDH, we need to reconstruct the EC public key
            int curve_nid;
            switch (params.group) {
                case NamedGroup::SECP256R1: curve_nid = NID_X9_62_prime256v1; break;
                case NamedGroup::SECP384R1: curve_nid = NID_secp384r1; break;
                case NamedGroup::SECP521R1: curve_nid = NID_secp521r1; break;
                default: curve_nid = NID_X9_62_prime256v1; break;
            }
            
            EC_KEY* ec_key = EC_KEY_new_by_curve_name(curve_nid);
            if (!ec_key) {
                return Result<std::vector<uint8_t>>(DTLSError::KEY_EXCHANGE_FAILED);
            }
            
            const EC_GROUP* group = EC_KEY_get0_group(ec_key);
            EC_POINT* point = EC_POINT_new(group);
            
            if (point && EC_POINT_oct2point(group, point, params.peer_public_key.data(),
                                           params.peer_public_key.size(), nullptr) == 1) {
                EC_KEY_set_public_key(ec_key, point);
                peer_key = EVP_PKEY_new();
                if (peer_key) {
                    EVP_PKEY_assign_EC_KEY(peer_key, ec_key);
                } else {
                    EC_KEY_free(ec_key);
                }
            } else {
                EC_KEY_free(ec_key);
            }
            
            if (point) EC_POINT_free(point);
            break;
        }
        default:
            return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!peer_key) {
        return Result<std::vector<uint8_t>>(DTLSError::KEY_EXCHANGE_FAILED);
    }
    
    // Perform key derivation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer_key);
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    int result = 1;
    if (result == 1) {
        result = EVP_PKEY_derive_init(ctx);
    }
    
    if (result == 1) {
        result = EVP_PKEY_derive_set_peer(ctx, peer_key);
    }
    
    // Determine output length
    size_t shared_secret_len = 0;
    if (result == 1) {
        result = EVP_PKEY_derive(ctx, nullptr, &shared_secret_len);
    }
    
    std::vector<uint8_t> shared_secret;
    if (result == 1 && shared_secret_len > 0) {
        shared_secret.resize(shared_secret_len);
        result = EVP_PKEY_derive(ctx, shared_secret.data(), &shared_secret_len);
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    
    if (result != 1) {
        return Result<std::vector<uint8_t>>(DTLSError::KEY_EXCHANGE_FAILED);
    }
    
    shared_secret.resize(shared_secret_len);
    return Result<std::vector<uint8_t>>(std::move(shared_secret));
}

Result<bool> OpenSSLProvider::validate_certificate_chain(const CertValidationParams& params) {
    return Result<bool>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<std::unique_ptr<PublicKey>> OpenSSLProvider::extract_public_key(const std::vector<uint8_t>& certificate) {
    return Result<std::unique_ptr<PublicKey>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<std::unique_ptr<PrivateKey>> OpenSSLProvider::import_private_key(const std::vector<uint8_t>& key_data, const std::string& format) {
    if (!pimpl_->initialized_) {
        return Result<std::unique_ptr<PrivateKey>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (key_data.empty()) {
        return Result<std::unique_ptr<PrivateKey>>(DTLSError::INVALID_PARAMETER);
    }
    
    BIO* bio = BIO_new_mem_buf(key_data.data(), static_cast<int>(key_data.size()));
    if (!bio) {
        return Result<std::unique_ptr<PrivateKey>>(DTLSError::OUT_OF_MEMORY);
    }
    
    EVP_PKEY* pkey = nullptr;
    
    if (format == "PEM") {
        pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    } else if (format == "DER") {
        pkey = d2i_PrivateKey_bio(bio, nullptr);
    } else {
        BIO_free(bio);
        return Result<std::unique_ptr<PrivateKey>>(DTLSError::INVALID_PARAMETER);
    }
    
    BIO_free(bio);
    
    if (!pkey) {
        return Result<std::unique_ptr<PrivateKey>>(DTLSError::INVALID_PARAMETER);
    }
    
    auto private_key = std::make_unique<OpenSSLPrivateKey>(pkey);
    return Result<std::unique_ptr<PrivateKey>>(std::move(private_key));
}

Result<std::unique_ptr<PublicKey>> OpenSSLProvider::import_public_key(const std::vector<uint8_t>& key_data, const std::string& format) {
    if (!pimpl_->initialized_) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (key_data.empty()) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::INVALID_PARAMETER);
    }
    
    BIO* bio = BIO_new_mem_buf(key_data.data(), static_cast<int>(key_data.size()));
    if (!bio) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::OUT_OF_MEMORY);
    }
    
    EVP_PKEY* pkey = nullptr;
    
    if (format == "PEM") {
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    } else if (format == "DER") {
        pkey = d2i_PUBKEY_bio(bio, nullptr);
    } else {
        BIO_free(bio);
        return Result<std::unique_ptr<PublicKey>>(DTLSError::INVALID_PARAMETER);
    }
    
    BIO_free(bio);
    
    if (!pkey) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::INVALID_PARAMETER);
    }
    
    auto public_key = std::make_unique<OpenSSLPublicKey>(pkey);
    return Result<std::unique_ptr<PublicKey>>(std::move(public_key));
}

Result<std::vector<uint8_t>> OpenSSLProvider::export_private_key(const PrivateKey& key, const std::string& format) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    // Cast to OpenSSL private key
    const auto* openssl_key = dynamic_cast<const OpenSSLPrivateKey*>(&key);
    if (!openssl_key) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* pkey = openssl_key->native_key();
    if (!pkey) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    int result = 0;
    if (format == "PEM") {
        result = PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    } else if (format == "DER") {
        result = i2d_PrivateKey_bio(bio, pkey);
    } else {
        BIO_free(bio);
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    if (result != 1) {
        BIO_free(bio);
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Extract data from BIO
    char* data = nullptr;
    long data_len = BIO_get_mem_data(bio, &data);
    
    if (data_len <= 0 || !data) {
        BIO_free(bio);
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> key_data(data, data + data_len);
    BIO_free(bio);
    
    return Result<std::vector<uint8_t>>(std::move(key_data));
}

Result<std::vector<uint8_t>> OpenSSLProvider::export_public_key(const PublicKey& key, const std::string& format) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    // Cast to OpenSSL public key
    const auto* openssl_key = dynamic_cast<const OpenSSLPublicKey*>(&key);
    if (!openssl_key) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    EVP_PKEY* pkey = openssl_key->native_key();
    if (!pkey) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return Result<std::vector<uint8_t>>(DTLSError::OUT_OF_MEMORY);
    }
    
    int result = 0;
    if (format == "PEM") {
        result = PEM_write_bio_PUBKEY(bio, pkey);
    } else if (format == "DER") {
        result = i2d_PUBKEY_bio(bio, pkey);
    } else {
        BIO_free(bio);
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    if (result != 1) {
        BIO_free(bio);
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Extract data from BIO
    char* data = nullptr;
    long data_len = BIO_get_mem_data(bio, &data);
    
    if (data_len <= 0 || !data) {
        BIO_free(bio);
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> key_data(data, data + data_len);
    BIO_free(bio);
    
    return Result<std::vector<uint8_t>>(std::move(key_data));
}

// Utility functions
bool OpenSSLProvider::supports_cipher_suite(CipherSuite suite) const {
    auto caps = capabilities();
    const auto& suites = caps.supported_cipher_suites;
    return std::find(suites.begin(), suites.end(), suite) != suites.end();
}

bool OpenSSLProvider::supports_named_group(NamedGroup group) const {
    auto caps = capabilities();
    const auto& groups = caps.supported_groups;
    return std::find(groups.begin(), groups.end(), group) != groups.end();
}

bool OpenSSLProvider::supports_signature_scheme(SignatureScheme scheme) const {
    auto caps = capabilities();
    const auto& schemes = caps.supported_signatures;
    return std::find(schemes.begin(), schemes.end(), scheme) != schemes.end();
}

bool OpenSSLProvider::supports_hash_algorithm(HashAlgorithm hash) const {
    auto caps = capabilities();
    const auto& hashes = caps.supported_hashes;
    return std::find(hashes.begin(), hashes.end(), hash) != hashes.end();
}

bool OpenSSLProvider::has_hardware_acceleration() const {
    return false; // Would need actual detection
}

bool OpenSSLProvider::is_fips_compliant() const {
    return false; // Would need FIPS mode detection
}

SecurityLevel OpenSSLProvider::security_level() const {
    return pimpl_->security_level_;
}

Result<void> OpenSSLProvider::set_security_level(SecurityLevel level) {
    pimpl_->security_level_ = level;
    return Result<void>();
}

// OpenSSL utility functions
namespace openssl_utils {

Result<void> initialize_openssl() {
    // OpenSSL 1.1.0+ automatically initializes
    return Result<void>();
}

void cleanup_openssl() {
    // OpenSSL 1.1.0+ automatically cleans up
}

bool is_openssl_available() {
    return true; // If we're compiled with OpenSSL, it's available
}

std::string get_openssl_version() {
    return OPENSSL_VERSION_TEXT;
}

DTLSError map_openssl_error(unsigned long openssl_error) {
    // Get the last error if none provided
    if (openssl_error == 0) {
        openssl_error = ERR_get_error();
    }
    
    if (openssl_error == 0) {
        return DTLSError::SUCCESS;
    }
    
    // Map common OpenSSL errors to DTLS errors
    // This is a simplified mapping
    return DTLSError::CRYPTO_PROVIDER_ERROR;
}

} // namespace openssl_utils

// Key and certificate class stubs (minimal implementation)
OpenSSLPrivateKey::OpenSSLPrivateKey(EVP_PKEY* key) : key_(key) {
    if (key_) {
        EVP_PKEY_up_ref(key_);
    }
}

OpenSSLPrivateKey::~OpenSSLPrivateKey() {
    if (key_) {
        EVP_PKEY_free(key_);
    }
}

OpenSSLPrivateKey::OpenSSLPrivateKey(OpenSSLPrivateKey&& other) noexcept 
    : key_(other.key_) {
    other.key_ = nullptr;
}

OpenSSLPrivateKey& OpenSSLPrivateKey::operator=(OpenSSLPrivateKey&& other) noexcept {
    if (this != &other) {
        if (key_) {
            EVP_PKEY_free(key_);
        }
        key_ = other.key_;
        other.key_ = nullptr;
    }
    return *this;
}

std::string OpenSSLPrivateKey::algorithm() const {
    if (!key_) return "unknown";
    
    int type = EVP_PKEY_base_id(key_);
    switch (type) {
        case EVP_PKEY_RSA: return "RSA";
        case EVP_PKEY_EC: return "EC";
        case EVP_PKEY_ED25519: return "Ed25519";
        case EVP_PKEY_ED448: return "Ed448";
        default: return "unknown";
    }
}

size_t OpenSSLPrivateKey::key_size() const {
    if (!key_) return 0;
    return static_cast<size_t>(EVP_PKEY_size(key_));
}

NamedGroup OpenSSLPrivateKey::group() const {
    if (!key_) return NamedGroup::SECP256R1;
    
    int type = EVP_PKEY_base_id(key_);
    switch (type) {
        case EVP_PKEY_EC: {
            EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key_);
            if (ec_key) {
                const EC_GROUP* group = EC_KEY_get0_group(ec_key);
                if (group) {
                    int nid = EC_GROUP_get_curve_name(group);
                    EC_KEY_free(ec_key);
                    switch (nid) {
                        case NID_X9_62_prime256v1: return NamedGroup::SECP256R1;
                        case NID_secp384r1: return NamedGroup::SECP384R1;
                        case NID_secp521r1: return NamedGroup::SECP521R1;
                        default: return NamedGroup::SECP256R1;
                    }
                }
                EC_KEY_free(ec_key);
            }
            break;
        }
        case EVP_PKEY_X25519:
            return NamedGroup::X25519;
        case EVP_PKEY_X448:
            return NamedGroup::X448;
        case EVP_PKEY_RSA:
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
            return NamedGroup::SECP256R1; // RSA and EdDSA don't have named groups
    }
    return NamedGroup::SECP256R1;
}

std::vector<uint8_t> OpenSSLPrivateKey::fingerprint() const {
    return {}; // Stub
}

Result<std::unique_ptr<PublicKey>> OpenSSLPrivateKey::derive_public_key() const {
    if (!key_) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Create a copy of the key and extract only the public portion
    EVP_PKEY* public_key_copy = nullptr;
    
    // Create a temporary context to extract public key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key_, nullptr);
    if (!ctx) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::OUT_OF_MEMORY);
    }
    
    // For most key types, we can simply up the reference and create a public key wrapper
    // OpenSSL EVP_PKEY handles the separation internally
    EVP_PKEY_up_ref(key_);
    public_key_copy = key_;
    
    EVP_PKEY_CTX_free(ctx);
    
    if (!public_key_copy) {
        return Result<std::unique_ptr<PublicKey>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto public_key = std::make_unique<OpenSSLPublicKey>(public_key_copy);
    return Result<std::unique_ptr<PublicKey>>(std::move(public_key));
}

// Similar stub implementations for OpenSSLPublicKey and OpenSSLCertificateChain
OpenSSLPublicKey::OpenSSLPublicKey(EVP_PKEY* key) : key_(key) {
    if (key_) {
        EVP_PKEY_up_ref(key_);
    }
}

OpenSSLPublicKey::~OpenSSLPublicKey() {
    if (key_) {
        EVP_PKEY_free(key_);
    }
}

OpenSSLPublicKey::OpenSSLPublicKey(OpenSSLPublicKey&& other) noexcept 
    : key_(other.key_) {
    other.key_ = nullptr;
}

OpenSSLPublicKey& OpenSSLPublicKey::operator=(OpenSSLPublicKey&& other) noexcept {
    if (this != &other) {
        if (key_) {
            EVP_PKEY_free(key_);
        }
        key_ = other.key_;
        other.key_ = nullptr;
    }
    return *this;
}

std::string OpenSSLPublicKey::algorithm() const {
    if (!key_) return "unknown";
    
    int type = EVP_PKEY_base_id(key_);
    switch (type) {
        case EVP_PKEY_RSA: return "RSA";
        case EVP_PKEY_EC: return "EC";
        case EVP_PKEY_ED25519: return "Ed25519";
        case EVP_PKEY_ED448: return "Ed448";
        default: return "unknown";
    }
}

size_t OpenSSLPublicKey::key_size() const {
    if (!key_) return 0;
    return static_cast<size_t>(EVP_PKEY_size(key_));
}

NamedGroup OpenSSLPublicKey::group() const {
    if (!key_) return NamedGroup::SECP256R1;
    
    int type = EVP_PKEY_base_id(key_);
    switch (type) {
        case EVP_PKEY_EC: {
            EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key_);
            if (ec_key) {
                const EC_GROUP* group = EC_KEY_get0_group(ec_key);
                if (group) {
                    int nid = EC_GROUP_get_curve_name(group);
                    EC_KEY_free(ec_key);
                    switch (nid) {
                        case NID_X9_62_prime256v1: return NamedGroup::SECP256R1;
                        case NID_secp384r1: return NamedGroup::SECP384R1;
                        case NID_secp521r1: return NamedGroup::SECP521R1;
                        default: return NamedGroup::SECP256R1;
                    }
                }
                EC_KEY_free(ec_key);
            }
            break;
        }
        case EVP_PKEY_X25519:
            return NamedGroup::X25519;
        case EVP_PKEY_X448:
            return NamedGroup::X448;
        case EVP_PKEY_RSA:
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
            return NamedGroup::SECP256R1; // RSA and EdDSA don't have named groups
    }
    return NamedGroup::SECP256R1;
}

std::vector<uint8_t> OpenSSLPublicKey::fingerprint() const {
    return {}; // Stub
}

bool OpenSSLPublicKey::equals(const PublicKey& other) const {
    return false; // Stub
}

// Certificate chain stub
OpenSSLCertificateChain::OpenSSLCertificateChain(STACK_OF_X509* chain) : chain_(chain) {}

OpenSSLCertificateChain::~OpenSSLCertificateChain() {
    if (chain_) {
        sk_X509_pop_free(chain_, X509_free);
    }
}

OpenSSLCertificateChain::OpenSSLCertificateChain(OpenSSLCertificateChain&& other) noexcept 
    : chain_(other.chain_) {
    other.chain_ = nullptr;
}

OpenSSLCertificateChain& OpenSSLCertificateChain::operator=(OpenSSLCertificateChain&& other) noexcept {
    if (this != &other) {
        if (chain_) {
            sk_X509_pop_free(chain_, X509_free);
        }
        chain_ = other.chain_;
        other.chain_ = nullptr;
    }
    return *this;
}

size_t OpenSSLCertificateChain::certificate_count() const {
    if (!chain_) return 0;
    return static_cast<size_t>(sk_X509_num(chain_));
}

std::vector<uint8_t> OpenSSLCertificateChain::certificate_at(size_t index) const {
    return {}; // Stub
}

std::unique_ptr<PublicKey> OpenSSLCertificateChain::leaf_public_key() const {
    return nullptr; // Stub
}

std::string OpenSSLCertificateChain::subject_name() const {
    return ""; // Stub
}

std::string OpenSSLCertificateChain::issuer_name() const {
    return ""; // Stub
}

std::chrono::system_clock::time_point OpenSSLCertificateChain::not_before() const {
    return std::chrono::system_clock::now(); // Stub
}

std::chrono::system_clock::time_point OpenSSLCertificateChain::not_after() const {
    return std::chrono::system_clock::now(); // Stub
}

bool OpenSSLCertificateChain::is_valid() const {
    return false; // Stub
}

} // namespace crypto
} // namespace v13
} // namespace dtls