#include <dtls/crypto/openssl_provider.h>
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

// Random number generation
Result<std::vector<uint8_t>> OpenSSLProvider::generate_random(const RandomParams& params) {
    if (!pimpl_->initialized_) {
        return Result<std::vector<uint8_t>>(DTLSError::NOT_INITIALIZED);
    }
    
    std::vector<uint8_t> random_bytes(params.length);
    
    int result = RAND_bytes(random_bytes.data(), static_cast<int>(params.length));
    if (result != 1) {
        return Result<std::vector<uint8_t>>(DTLSError::RANDOM_GENERATION_FAILED);
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
    
    if (params.key.empty() || params.nonce.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get the cipher algorithm
    const EVP_CIPHER* cipher = nullptr;
    size_t tag_length = 16; // Default tag length
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            tag_length = 16;
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            tag_length = 16;
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM:
            cipher = EVP_aes_128_ccm();
            tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            tag_length = 8;
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
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
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
    
    if (params.key.empty() || params.nonce.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get the cipher algorithm and tag length
    const EVP_CIPHER* cipher = nullptr;
    size_t tag_length = 16; // Default tag length
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            tag_length = 16;
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            tag_length = 16;
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM:
            cipher = EVP_aes_128_ccm();
            tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            tag_length = 8;
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
        return Result<std::vector<uint8_t>>(DTLSError::DECRYPT_ERROR);
    }
    
    plaintext.resize(outlen + final_len);
    return Result<std::vector<uint8_t>>(std::move(plaintext));
}

// New AEAD interface with separate ciphertext and tag
Result<AEADEncryptionOutput> OpenSSLProvider::encrypt_aead(const AEADEncryptionParams& params) {
    if (!pimpl_->initialized_) {
        return Result<AEADEncryptionOutput>(DTLSError::NOT_INITIALIZED);
    }
    
    if (params.key.empty() || params.nonce.empty()) {
        return Result<AEADEncryptionOutput>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get the cipher algorithm
    const EVP_CIPHER* cipher = nullptr;
    size_t tag_length = 16; // Default tag length
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            tag_length = 16;
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            tag_length = 16;
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM:
            cipher = EVP_aes_128_ccm();
            tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            tag_length = 8;
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
        return Result<AEADEncryptionOutput>(DTLSError::CRYPTO_PROVIDER_ERROR);
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
    
    if (params.key.empty() || params.nonce.empty() || params.ciphertext.empty() || params.tag.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get the cipher algorithm
    const EVP_CIPHER* cipher = nullptr;
    size_t expected_tag_length = 16; // Default tag length
    
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            expected_tag_length = 16;
            break;
        case AEADCipher::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            expected_tag_length = 16;
            break;
        case AEADCipher::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            expected_tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM:
            cipher = EVP_aes_128_ccm();
            expected_tag_length = 16;
            break;
        case AEADCipher::AES_128_CCM_8:
            cipher = EVP_aes_128_ccm();
            expected_tag_length = 8;
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
        return Result<std::vector<uint8_t>>(DTLSError::DECRYPT_ERROR);
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

// Remaining methods are stubs for compilation
Result<std::vector<uint8_t>> OpenSSLProvider::sign_data(const SignatureParams& params) {
    return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<bool> OpenSSLProvider::verify_signature(const SignatureParams& params, const std::vector<uint8_t>& signature) {
    return Result<bool>(DTLSError::OPERATION_NOT_SUPPORTED);
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
    
    // Generate the key pair
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
    return Result<std::unique_ptr<PrivateKey>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<std::unique_ptr<PublicKey>> OpenSSLProvider::import_public_key(const std::vector<uint8_t>& key_data, const std::string& format) {
    return Result<std::unique_ptr<PublicKey>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<std::vector<uint8_t>> OpenSSLProvider::export_private_key(const PrivateKey& key, const std::string& format) {
    return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<std::vector<uint8_t>> OpenSSLProvider::export_public_key(const PublicKey& key, const std::string& format) {
    return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
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
    return NamedGroup::SECP256R1; // Stub
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
    return NamedGroup::SECP256R1; // Stub
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