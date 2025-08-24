/**
 * @file openssl_pqc_signatures.cpp
 * @brief OpenSSL provider implementation for FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) post-quantum signatures
 * 
 * This file implements pure post-quantum digital signatures and hybrid classical+PQC signatures
 * using OpenSSL 3.0+ with the OQS (Open Quantum Safe) provider for quantum-resistant algorithms.
 */

#include "dtls/crypto/openssl_provider.h"
#include "dtls/error.h"
#include "dtls/result.h"

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <memory>
#include <unordered_map>
#include <algorithm>

namespace dtls {
namespace v13 {
namespace crypto {

// Helper function to convert SignatureScheme to ML-DSA parameters
Result<MLDSAParameterSet> OpenSSLProvider::signature_scheme_to_ml_dsa_params(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::ML_DSA_44:
            return Result<MLDSAParameterSet>(MLDSAParameterSet::ML_DSA_44);
        case SignatureScheme::ML_DSA_65:
            return Result<MLDSAParameterSet>(MLDSAParameterSet::ML_DSA_65);
        case SignatureScheme::ML_DSA_87:
            return Result<MLDSAParameterSet>(MLDSAParameterSet::ML_DSA_87);
        default:
            return Result<MLDSAParameterSet>(DTLSError::INVALID_PARAMETER);
    }
}

// Helper function to convert SignatureScheme to SLH-DSA parameters
Result<SLHDSAParameterSet> OpenSSLProvider::signature_scheme_to_slh_dsa_params(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::SLH_DSA_SHA2_128S:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHA2_128S);
        case SignatureScheme::SLH_DSA_SHA2_128F:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHA2_128F);
        case SignatureScheme::SLH_DSA_SHA2_192S:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHA2_192S);
        case SignatureScheme::SLH_DSA_SHA2_192F:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHA2_192F);
        case SignatureScheme::SLH_DSA_SHA2_256S:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHA2_256S);
        case SignatureScheme::SLH_DSA_SHA2_256F:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHA2_256F);
        case SignatureScheme::SLH_DSA_SHAKE_128S:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHAKE_128S);
        case SignatureScheme::SLH_DSA_SHAKE_128F:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHAKE_128F);
        case SignatureScheme::SLH_DSA_SHAKE_192S:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHAKE_192S);
        case SignatureScheme::SLH_DSA_SHAKE_192F:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHAKE_192F);
        case SignatureScheme::SLH_DSA_SHAKE_256S:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHAKE_256S);
        case SignatureScheme::SLH_DSA_SHAKE_256F:
            return Result<SLHDSAParameterSet>(SLHDSAParameterSet::SLH_DSA_SHAKE_256F);
        default:
            return Result<SLHDSAParameterSet>(DTLSError::INVALID_PARAMETER);
    }
}

// Convert ML-DSA parameter set to OpenSSL algorithm name
Result<std::string> OpenSSLProvider::ml_dsa_params_to_openssl_name(MLDSAParameterSet params) {
    switch (params) {
        case MLDSAParameterSet::ML_DSA_44:
            return Result<std::string>("ML-DSA-44");
        case MLDSAParameterSet::ML_DSA_65:
            return Result<std::string>("ML-DSA-65");
        case MLDSAParameterSet::ML_DSA_87:
            return Result<std::string>("ML-DSA-87");
        default:
            return Result<std::string>(DTLSError::INVALID_PARAMETER);
    }
}

// Convert SLH-DSA parameter set to OpenSSL algorithm name
Result<std::string> OpenSSLProvider::slh_dsa_params_to_openssl_name(SLHDSAParameterSet params) {
    switch (params) {
        case SLHDSAParameterSet::SLH_DSA_SHA2_128S:
            return Result<std::string>("SLH-DSA-SHA2-128s");
        case SLHDSAParameterSet::SLH_DSA_SHA2_128F:
            return Result<std::string>("SLH-DSA-SHA2-128f");
        case SLHDSAParameterSet::SLH_DSA_SHA2_192S:
            return Result<std::string>("SLH-DSA-SHA2-192s");
        case SLHDSAParameterSet::SLH_DSA_SHA2_192F:
            return Result<std::string>("SLH-DSA-SHA2-192f");
        case SLHDSAParameterSet::SLH_DSA_SHA2_256S:
            return Result<std::string>("SLH-DSA-SHA2-256s");
        case SLHDSAParameterSet::SLH_DSA_SHA2_256F:
            return Result<std::string>("SLH-DSA-SHA2-256f");
        case SLHDSAParameterSet::SLH_DSA_SHAKE_128S:
            return Result<std::string>("SLH-DSA-SHAKE-128s");
        case SLHDSAParameterSet::SLH_DSA_SHAKE_128F:
            return Result<std::string>("SLH-DSA-SHAKE-128f");
        case SLHDSAParameterSet::SLH_DSA_SHAKE_192S:
            return Result<std::string>("SLH-DSA-SHAKE-192s");
        case SLHDSAParameterSet::SLH_DSA_SHAKE_192F:
            return Result<std::string>("SLH-DSA-SHAKE-192f");
        case SLHDSAParameterSet::SLH_DSA_SHAKE_256S:
            return Result<std::string>("SLH-DSA-SHAKE-256s");
        case SLHDSAParameterSet::SLH_DSA_SHAKE_256F:
            return Result<std::string>("SLH-DSA-SHAKE-256f");
        default:
            return Result<std::string>(DTLSError::INVALID_PARAMETER);
    }
}

// Check if OQS provider is available
bool OpenSSLProvider::is_oqsprovider_available() const {
    OSSL_PROVIDER* oqs_provider = OSSL_PROVIDER_try_load(nullptr, "oqsprovider", 1);
    if (oqs_provider) {
        OSSL_PROVIDER_unload(oqs_provider);
        return true;
    }
    return false;
}

// Get supported PQC signatures
std::vector<SignatureScheme> OpenSSLProvider::get_supported_pqc_signatures() const {
    std::vector<SignatureScheme> supported;
    
    if (!is_oqsprovider_available()) {
        return supported; // Return empty vector if OQS provider not available
    }
    
    // Pure ML-DSA signatures
    supported.push_back(SignatureScheme::ML_DSA_44);
    supported.push_back(SignatureScheme::ML_DSA_65);
    supported.push_back(SignatureScheme::ML_DSA_87);
    
    // Pure SLH-DSA signatures
    supported.push_back(SignatureScheme::SLH_DSA_SHA2_128S);
    supported.push_back(SignatureScheme::SLH_DSA_SHA2_128F);
    supported.push_back(SignatureScheme::SLH_DSA_SHA2_192S);
    supported.push_back(SignatureScheme::SLH_DSA_SHA2_192F);
    supported.push_back(SignatureScheme::SLH_DSA_SHA2_256S);
    supported.push_back(SignatureScheme::SLH_DSA_SHA2_256F);
    supported.push_back(SignatureScheme::SLH_DSA_SHAKE_128S);
    supported.push_back(SignatureScheme::SLH_DSA_SHAKE_128F);
    supported.push_back(SignatureScheme::SLH_DSA_SHAKE_192S);
    supported.push_back(SignatureScheme::SLH_DSA_SHAKE_192F);
    supported.push_back(SignatureScheme::SLH_DSA_SHAKE_256S);
    supported.push_back(SignatureScheme::SLH_DSA_SHAKE_256F);
    
    // Hybrid signatures (if classical algorithms are also supported)
    supported.push_back(SignatureScheme::RSA3072_ML_DSA_44);
    supported.push_back(SignatureScheme::P256_ML_DSA_44);
    supported.push_back(SignatureScheme::RSA3072_ML_DSA_65);
    supported.push_back(SignatureScheme::P384_ML_DSA_65);
    supported.push_back(SignatureScheme::P521_ML_DSA_87);
    supported.push_back(SignatureScheme::RSA3072_SLH_DSA_128S);
    supported.push_back(SignatureScheme::P256_SLH_DSA_128S);
    supported.push_back(SignatureScheme::RSA3072_SLH_DSA_192S);
    supported.push_back(SignatureScheme::P384_SLH_DSA_192S);
    supported.push_back(SignatureScheme::P521_SLH_DSA_256S);
    
    return supported;
}

// ML-DSA key pair generation
Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
OpenSSLProvider::ml_dsa_generate_keypair(const MLDSAKeyGenParams& params) {
    if (!is_oqsprovider_available()) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto alg_name_result = ml_dsa_params_to_openssl_name(params.parameter_set);
    if (alg_name_result.is_error()) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            alg_name_result.error());
    }
    
    std::string alg_name = alg_name_result.value();
    
    // Create key generation context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), "provider=oqsprovider");
    if (!ctx) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctx_guard(ctx, EVP_PKEY_CTX_free);
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Set deterministic seed if provided
    if (!params.seed.empty()) {
        // Note: OpenSSL/OQS may not support deterministic key generation for ML-DSA
        // This would require custom parameter setting
    }
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_guard(pkey, EVP_PKEY_free);
    
    // Extract public key
    size_t pubkey_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> public_key(pubkey_len);
    if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &pubkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Extract private key
    size_t privkey_len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &privkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> private_key(privkey_len);
    if (EVP_PKEY_get_raw_private_key(pkey, private_key.data(), &privkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
        std::make_pair(std::move(private_key), std::move(public_key)));
}

// ML-DSA signing
Result<std::vector<uint8_t>> OpenSSLProvider::ml_dsa_sign(const MLDSASignatureParams& params) {
    if (!is_oqsprovider_available()) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto alg_name_result = ml_dsa_params_to_openssl_name(params.parameter_set);
    if (alg_name_result.is_error()) {
        return Result<std::vector<uint8_t>>(alg_name_result.error());
    }
    
    std::string alg_name = alg_name_result.value();
    
    // Create EVP_PKEY from raw private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key_ex(
        nullptr, alg_name.c_str(), "provider=oqsprovider",
        params.private_key.data(), params.private_key.size());
    
    if (!pkey) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_guard(pkey, EVP_PKEY_free);
    
    // Create signing context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md_ctx_guard(md_ctx, EVP_MD_CTX_free);
    
    if (EVP_DigestSignInit_ex(md_ctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Set context if provided
    if (!params.context.empty()) {
        // ML-DSA supports context strings - this would require parameter setting
        // Implementation depends on specific OpenSSL/OQS provider API
    }
    
    // Perform signing
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, nullptr, &sig_len, params.message.data(), params.message.size()) <= 0) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, 
                      params.message.data(), params.message.size()) <= 0) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    signature.resize(sig_len);
    return Result<std::vector<uint8_t>>(std::move(signature));
}

// ML-DSA verification
Result<bool> OpenSSLProvider::ml_dsa_verify(const MLDSAVerificationParams& params) {
    if (!is_oqsprovider_available()) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto alg_name_result = ml_dsa_params_to_openssl_name(params.parameter_set);
    if (alg_name_result.is_error()) {
        return Result<bool>(alg_name_result.error());
    }
    
    std::string alg_name = alg_name_result.value();
    
    // Create EVP_PKEY from raw public key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
        nullptr, alg_name.c_str(), "provider=oqsprovider",
        params.public_key.data(), params.public_key.size());
    
    if (!pkey) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_guard(pkey, EVP_PKEY_free);
    
    // Create verification context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md_ctx_guard(md_ctx, EVP_MD_CTX_free);
    
    if (EVP_DigestVerifyInit_ex(md_ctx, nullptr, nullptr, nullptr, nullptr, pkey, nullptr) <= 0) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Perform verification
    int verify_result = EVP_DigestVerify(md_ctx, params.signature.data(), params.signature.size(),
                                       params.message.data(), params.message.size());
    
    if (verify_result < 0) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return Result<bool>(verify_result == 1);
}

// SLH-DSA key pair generation
Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
OpenSSLProvider::slh_dsa_generate_keypair(const SLHDSAKeyGenParams& params) {
    if (!is_oqsprovider_available()) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto alg_name_result = slh_dsa_params_to_openssl_name(params.parameter_set);
    if (alg_name_result.is_error()) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            alg_name_result.error());
    }
    
    std::string alg_name = alg_name_result.value();
    
    // Create key generation context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), "provider=oqsprovider");
    if (!ctx) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctx_guard(ctx, EVP_PKEY_CTX_free);
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_guard(pkey, EVP_PKEY_free);
    
    // Extract public key
    size_t pubkey_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> public_key(pubkey_len);
    if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &pubkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Extract private key
    size_t privkey_len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &privkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> private_key(privkey_len);
    if (EVP_PKEY_get_raw_private_key(pkey, private_key.data(), &privkey_len) <= 0) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
            DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>(
        std::make_pair(std::move(private_key), std::move(public_key)));
}

// SLH-DSA signing
Result<std::vector<uint8_t>> OpenSSLProvider::slh_dsa_sign(const SLHDSASignatureParams& params) {
    if (!is_oqsprovider_available()) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto alg_name_result = slh_dsa_params_to_openssl_name(params.parameter_set);
    if (alg_name_result.is_error()) {
        return Result<std::vector<uint8_t>>(alg_name_result.error());
    }
    
    std::string alg_name = alg_name_result.value();
    
    // Create EVP_PKEY from raw private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key_ex(
        nullptr, alg_name.c_str(), "provider=oqsprovider",
        params.private_key.data(), params.private_key.size());
    
    if (!pkey) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_guard(pkey, EVP_PKEY_free);
    
    // Create signing context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md_ctx_guard(md_ctx, EVP_MD_CTX_free);
    
    // For SLH-DSA, we may need to specify hash algorithm if using pre-hash variant
    const EVP_MD* md = nullptr;
    if (params.use_prehash) {
        // Determine appropriate hash based on parameter set
        switch (params.parameter_set) {
            case SLHDSAParameterSet::SLH_DSA_SHA2_128S:
            case SLHDSAParameterSet::SLH_DSA_SHA2_128F:
                md = EVP_sha256();
                break;
            case SLHDSAParameterSet::SLH_DSA_SHA2_192S:
            case SLHDSAParameterSet::SLH_DSA_SHA2_192F:
                md = EVP_sha384();
                break;
            case SLHDSAParameterSet::SLH_DSA_SHA2_256S:
            case SLHDSAParameterSet::SLH_DSA_SHA2_256F:
                md = EVP_sha512();
                break;
            default:
                md = nullptr; // Pure signing
                break;
        }
    }
    
    if (EVP_DigestSignInit_ex(md_ctx, nullptr, md ? EVP_MD_get0_name(md) : nullptr, 
                             nullptr, nullptr, pkey, nullptr) <= 0) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Perform signing
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, nullptr, &sig_len, params.message.data(), params.message.size()) <= 0) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, 
                      params.message.data(), params.message.size()) <= 0) {
        return Result<std::vector<uint8_t>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    signature.resize(sig_len);
    return Result<std::vector<uint8_t>>(std::move(signature));
}

// SLH-DSA verification
Result<bool> OpenSSLProvider::slh_dsa_verify(const SLHDSAVerificationParams& params) {
    if (!is_oqsprovider_available()) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    auto alg_name_result = slh_dsa_params_to_openssl_name(params.parameter_set);
    if (alg_name_result.is_error()) {
        return Result<bool>(alg_name_result.error());
    }
    
    std::string alg_name = alg_name_result.value();
    
    // Create EVP_PKEY from raw public key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
        nullptr, alg_name.c_str(), "provider=oqsprovider",
        params.public_key.data(), params.public_key.size());
    
    if (!pkey) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_guard(pkey, EVP_PKEY_free);
    
    // Create verification context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> md_ctx_guard(md_ctx, EVP_MD_CTX_free);
    
    // Set hash algorithm if using pre-hash variant
    const EVP_MD* md = nullptr;
    if (params.use_prehash) {
        switch (params.parameter_set) {
            case SLHDSAParameterSet::SLH_DSA_SHA2_128S:
            case SLHDSAParameterSet::SLH_DSA_SHA2_128F:
                md = EVP_sha256();
                break;
            case SLHDSAParameterSet::SLH_DSA_SHA2_192S:
            case SLHDSAParameterSet::SLH_DSA_SHA2_192F:
                md = EVP_sha384();
                break;
            case SLHDSAParameterSet::SLH_DSA_SHA2_256S:
            case SLHDSAParameterSet::SLH_DSA_SHA2_256F:
                md = EVP_sha512();
                break;
            default:
                md = nullptr;
                break;
        }
    }
    
    if (EVP_DigestVerifyInit_ex(md_ctx, nullptr, md ? EVP_MD_get0_name(md) : nullptr, 
                               nullptr, nullptr, pkey, nullptr) <= 0) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Perform verification
    int verify_result = EVP_DigestVerify(md_ctx, params.signature.data(), params.signature.size(),
                                       params.message.data(), params.message.size());
    
    if (verify_result < 0) {
        return Result<bool>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return Result<bool>(verify_result == 1);
}

// Unified pure PQC signing interface
Result<std::vector<uint8_t>> OpenSSLProvider::pure_pqc_sign(const PurePQCSignatureParams& params) {
    if (is_ml_dsa_signature(params.scheme)) {
        MLDSASignatureParams ml_dsa_params;
        auto param_set_result = signature_scheme_to_ml_dsa_params(params.scheme);
        if (param_set_result.is_error()) {
            return Result<std::vector<uint8_t>>(param_set_result.error());
        }
        
        ml_dsa_params.parameter_set = param_set_result.value();
        ml_dsa_params.message = params.message;
        ml_dsa_params.private_key = params.private_key;
        ml_dsa_params.context = params.context;
        ml_dsa_params.deterministic = params.deterministic;
        
        return ml_dsa_sign(ml_dsa_params);
    }
    else if (is_slh_dsa_signature(params.scheme)) {
        SLHDSASignatureParams slh_dsa_params;
        auto param_set_result = signature_scheme_to_slh_dsa_params(params.scheme);
        if (param_set_result.is_error()) {
            return Result<std::vector<uint8_t>>(param_set_result.error());
        }
        
        slh_dsa_params.parameter_set = param_set_result.value();
        slh_dsa_params.message = params.message;
        slh_dsa_params.private_key = params.private_key;
        slh_dsa_params.context = params.context;
        slh_dsa_params.use_prehash = params.use_prehash;
        
        return slh_dsa_sign(slh_dsa_params);
    }
    
    return Result<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

// Unified pure PQC verification interface
Result<bool> OpenSSLProvider::pure_pqc_verify(const PurePQCVerificationParams& params) {
    if (is_ml_dsa_signature(params.scheme)) {
        MLDSAVerificationParams ml_dsa_params;
        auto param_set_result = signature_scheme_to_ml_dsa_params(params.scheme);
        if (param_set_result.is_error()) {
            return Result<bool>(param_set_result.error());
        }
        
        ml_dsa_params.parameter_set = param_set_result.value();
        ml_dsa_params.message = params.message;
        ml_dsa_params.signature = params.signature;
        ml_dsa_params.public_key = params.public_key;
        ml_dsa_params.context = params.context;
        
        return ml_dsa_verify(ml_dsa_params);
    }
    else if (is_slh_dsa_signature(params.scheme)) {
        SLHDSAVerificationParams slh_dsa_params;
        auto param_set_result = signature_scheme_to_slh_dsa_params(params.scheme);
        if (param_set_result.is_error()) {
            return Result<bool>(param_set_result.error());
        }
        
        slh_dsa_params.parameter_set = param_set_result.value();
        slh_dsa_params.message = params.message;
        slh_dsa_params.signature = params.signature;
        slh_dsa_params.public_key = params.public_key;
        slh_dsa_params.context = params.context;
        slh_dsa_params.use_prehash = params.use_prehash;
        
        return slh_dsa_verify(slh_dsa_params);
    }
    
    return Result<bool>(DTLSError::OPERATION_NOT_SUPPORTED);
}

// Hybrid PQC signature implementation
Result<HybridSignatureResult> OpenSSLProvider::hybrid_pqc_sign(const HybridPQCSignatureParams& params) {
    if (!supports_hybrid_pqc_signature(params.hybrid_scheme)) {
        return Result<HybridSignatureResult>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    HybridSignatureResult result;
    
    // Determine classical and PQC components
    SignatureScheme classical_scheme = SignatureScheme::RSA_PKCS1_SHA256; // default
    SignatureScheme pqc_scheme = SignatureScheme::ML_DSA_44; // default
    
    // Map hybrid scheme to component schemes
    switch (params.hybrid_scheme) {
        case SignatureScheme::RSA3072_ML_DSA_44:
            classical_scheme = SignatureScheme::RSA_PKCS1_SHA256;
            pqc_scheme = SignatureScheme::ML_DSA_44;
            break;
        case SignatureScheme::P256_ML_DSA_44:
            classical_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
            pqc_scheme = SignatureScheme::ML_DSA_44;
            break;
        case SignatureScheme::RSA3072_ML_DSA_65:
            classical_scheme = SignatureScheme::RSA_PKCS1_SHA384;
            pqc_scheme = SignatureScheme::ML_DSA_65;
            break;
        case SignatureScheme::P384_ML_DSA_65:
            classical_scheme = SignatureScheme::ECDSA_SECP384R1_SHA384;
            pqc_scheme = SignatureScheme::ML_DSA_65;
            break;
        case SignatureScheme::P521_ML_DSA_87:
            classical_scheme = SignatureScheme::ECDSA_SECP521R1_SHA512;
            pqc_scheme = SignatureScheme::ML_DSA_87;
            break;
        // SLH-DSA hybrid cases
        case SignatureScheme::RSA3072_SLH_DSA_128S:
            classical_scheme = SignatureScheme::RSA_PKCS1_SHA256;
            pqc_scheme = SignatureScheme::SLH_DSA_SHA2_128S;
            break;
        case SignatureScheme::P256_SLH_DSA_128S:
            classical_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
            pqc_scheme = SignatureScheme::SLH_DSA_SHA2_128S;
            break;
        default:
            return Result<HybridSignatureResult>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Sign with classical algorithm
    SignatureParams classical_params;
    classical_params.scheme = classical_scheme;
    classical_params.data = params.message;
    classical_params.private_key = params.classical_private_key;
    
    auto classical_result = sign_data(classical_params);
    if (classical_result.is_error()) {
        return Result<HybridSignatureResult>(classical_result.error());
    }
    result.classical_signature = classical_result.value();
    
    // Sign with PQC algorithm
    PurePQCSignatureParams pqc_params;
    pqc_params.scheme = pqc_scheme;
    pqc_params.message = params.message;
    pqc_params.private_key = params.pqc_private_key;
    pqc_params.context = params.context;
    pqc_params.additional_entropy = params.additional_entropy;
    
    auto pqc_result = pure_pqc_sign(pqc_params);
    if (pqc_result.is_error()) {
        return Result<HybridSignatureResult>(pqc_result.error());
    }
    result.pqc_signature = pqc_result.value();
    
    // Combine signatures (simple concatenation with length prefixes)
    size_t classical_len = result.classical_signature.size();
    size_t pqc_len = result.pqc_signature.size();
    
    result.combined_signature.reserve(8 + classical_len + pqc_len);
    
    // Add classical signature length (4 bytes)
    result.combined_signature.push_back((classical_len >> 24) & 0xFF);
    result.combined_signature.push_back((classical_len >> 16) & 0xFF);
    result.combined_signature.push_back((classical_len >> 8) & 0xFF);
    result.combined_signature.push_back(classical_len & 0xFF);
    
    // Add classical signature
    result.combined_signature.insert(result.combined_signature.end(),
                                   result.classical_signature.begin(),
                                   result.classical_signature.end());
    
    // Add PQC signature length (4 bytes)
    result.combined_signature.push_back((pqc_len >> 24) & 0xFF);
    result.combined_signature.push_back((pqc_len >> 16) & 0xFF);
    result.combined_signature.push_back((pqc_len >> 8) & 0xFF);
    result.combined_signature.push_back(pqc_len & 0xFF);
    
    // Add PQC signature
    result.combined_signature.insert(result.combined_signature.end(),
                                   result.pqc_signature.begin(),
                                   result.pqc_signature.end());
    
    return Result<HybridSignatureResult>(std::move(result));
}

// Hybrid PQC verification implementation
Result<bool> OpenSSLProvider::hybrid_pqc_verify(const HybridPQCVerificationParams& params) {
    if (!supports_hybrid_pqc_signature(params.hybrid_scheme)) {
        return Result<bool>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Parse combined signature
    if (params.hybrid_signature.size() < 8) {
        return Result<bool>(false); // Invalid signature format
    }
    
    const auto& sig_data = params.hybrid_signature;
    size_t offset = 0;
    
    // Extract classical signature length
    size_t classical_len = (static_cast<size_t>(sig_data[offset]) << 24) |
                          (static_cast<size_t>(sig_data[offset + 1]) << 16) |
                          (static_cast<size_t>(sig_data[offset + 2]) << 8) |
                          static_cast<size_t>(sig_data[offset + 3]);
    offset += 4;
    
    if (offset + classical_len + 4 > sig_data.size()) {
        return Result<bool>(false); // Invalid signature format
    }
    
    // Extract classical signature
    std::vector<uint8_t> classical_signature(sig_data.begin() + offset,
                                            sig_data.begin() + offset + classical_len);
    offset += classical_len;
    
    // Extract PQC signature length
    size_t pqc_len = (static_cast<size_t>(sig_data[offset]) << 24) |
                    (static_cast<size_t>(sig_data[offset + 1]) << 16) |
                    (static_cast<size_t>(sig_data[offset + 2]) << 8) |
                    static_cast<size_t>(sig_data[offset + 3]);
    offset += 4;
    
    if (offset + pqc_len != sig_data.size()) {
        return Result<bool>(false); // Invalid signature format
    }
    
    // Extract PQC signature
    std::vector<uint8_t> pqc_signature(sig_data.begin() + offset,
                                      sig_data.begin() + offset + pqc_len);
    
    // Determine component signature schemes
    SignatureScheme classical_scheme = SignatureScheme::RSA_PKCS1_SHA256; // default
    SignatureScheme pqc_scheme = SignatureScheme::ML_DSA_44; // default
    
    // Map hybrid scheme to component schemes (same mapping as in signing)
    switch (params.hybrid_scheme) {
        case SignatureScheme::RSA3072_ML_DSA_44:
            classical_scheme = SignatureScheme::RSA_PKCS1_SHA256;
            pqc_scheme = SignatureScheme::ML_DSA_44;
            break;
        case SignatureScheme::P256_ML_DSA_44:
            classical_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
            pqc_scheme = SignatureScheme::ML_DSA_44;
            break;
        // Add other cases...
        default:
            return Result<bool>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Verify classical signature
    SignatureParams classical_params;
    classical_params.scheme = classical_scheme;
    classical_params.data = params.message;
    classical_params.public_key = params.classical_public_key;
    
    auto classical_result = verify_signature(classical_params, classical_signature);
    if (classical_result.is_error() || !classical_result.value()) {
        return Result<bool>(false);
    }
    
    // Verify PQC signature
    PurePQCVerificationParams pqc_params;
    pqc_params.scheme = pqc_scheme;
    pqc_params.message = params.message;
    pqc_params.signature = pqc_signature;
    pqc_params.public_key = params.pqc_public_key;
    pqc_params.context = params.context;
    
    auto pqc_result = pure_pqc_verify(pqc_params);
    if (pqc_result.is_error() || !pqc_result.value()) {
        return Result<bool>(false);
    }
    
    // Both signatures must verify successfully
    return Result<bool>(true);
}

} // namespace crypto
} // namespace v13
} // namespace dtls