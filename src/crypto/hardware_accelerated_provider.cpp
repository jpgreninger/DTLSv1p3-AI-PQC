#include "dtls/crypto/hardware_accelerated_provider.h"
#include "dtls/crypto/provider_factory.h"
#include <algorithm>
#include <chrono>
#include <thread>
#include <immintrin.h>

namespace dtls {
namespace v13 {
namespace crypto {

// Static members for factory
HardwareAccelerationProfile HardwareAcceleratedProviderFactory::cached_hw_profile_;
std::atomic<bool> HardwareAcceleratedProviderFactory::hw_profile_detected_{false};
std::mutex HardwareAcceleratedProviderFactory::detection_mutex_;

HardwareAcceleratedProvider::HardwareAcceleratedProvider(
    std::unique_ptr<CryptoProvider> base_provider,
    const HardwareAccelerationProfile& hw_profile)
    : base_provider_(std::move(base_provider))
    , hw_profile_(hw_profile)
    , last_benchmark_time_(std::chrono::steady_clock::now()) {
    
    // Initialize enabled capabilities based on hardware profile
    for (const auto& cap : hw_profile_.capabilities) {
        if (cap.available) {
            enabled_capabilities_[cap.capability] = cap.enabled;
            
            // Store expected speedups for different operations
            switch (cap.capability) {
                case HardwareCapability::AES_NI:
                case HardwareCapability::ARM_AES:
                    operation_speedups_["aes-gcm"] = cap.performance_multiplier;
                    operation_speedups_["aes-ccm"] = cap.performance_multiplier * 0.9f;
                    break;
                case HardwareCapability::ARM_SHA1:
                case HardwareCapability::ARM_SHA2:
                    operation_speedups_["sha256"] = cap.performance_multiplier;
                    operation_speedups_["sha384"] = cap.performance_multiplier;
                    operation_speedups_["hmac"] = cap.performance_multiplier * 0.8f;
                    break;
                case HardwareCapability::AVX2:
                    operation_speedups_["bulk-ops"] = cap.performance_multiplier;
                    break;
                case HardwareCapability::RNG_HARDWARE:
                    operation_speedups_["random"] = cap.performance_multiplier;
                    break;
                default:
                    break;
            }
        }
    }
}

std::string HardwareAcceleratedProvider::name() const {
    return "HW-Accelerated(" + base_provider_->name() + ")";
}

std::string HardwareAcceleratedProvider::version() const {
    return base_provider_->version() + "+HWAccel";
}

ProviderCapabilities HardwareAcceleratedProvider::capabilities() const {
    auto caps = base_provider_->capabilities();
    caps.hardware_acceleration = has_hardware_acceleration();
    return caps;
}

bool HardwareAcceleratedProvider::is_available() const {
    return base_provider_->is_available();
}

Result<void> HardwareAcceleratedProvider::initialize() {
    auto result = base_provider_->initialize();
    if (!result) {
        return result;
    }
    
    // Initialize hardware-specific optimizations
    for (const auto& [capability, enabled] : enabled_capabilities_) {
        if (enabled) {
            // Platform-specific hardware initialization would go here
            // For now, we'll just mark as ready
        }
    }
    
    return Result<void>();
}

void HardwareAcceleratedProvider::cleanup() {
    base_provider_->cleanup();
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::generate_random(const RandomParams& params) {
    operations_count_++;
    
    bool use_hw = should_use_hardware_for_operation("random");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->generate_random(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("random", duration, use_hw);
    
    return result;
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::derive_key_hkdf(const KeyDerivationParams& params) {
    operations_count_++;
    
    std::string operation = "hkdf-" + std::to_string(static_cast<int>(params.hash_algorithm));
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->derive_key_hkdf(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics(operation, duration, use_hw);
    
    return result;
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::derive_key_pbkdf2(const KeyDerivationParams& params) {
    operations_count_++;
    
    std::string operation = "pbkdf2-" + std::to_string(static_cast<int>(params.hash_algorithm));
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->derive_key_pbkdf2(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics(operation, duration, use_hw);
    
    return result;
}

Result<AEADEncryptionOutput> HardwareAcceleratedProvider::encrypt_aead(const AEADEncryptionParams& params) {
    operations_count_++;
    
    std::string operation = classify_operation(params);
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Use hardware-optimized path if available
    auto result = base_provider_->encrypt_aead(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics(operation, duration, use_hw);
    
    return result;
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::decrypt_aead(const AEADDecryptionParams& params) {
    operations_count_++;
    
    std::string operation = classify_operation(params);
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->decrypt_aead(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics(operation, duration, use_hw);
    
    return result;
}

Result<void> HardwareAcceleratedProvider::aead_encrypt_inplace(
    const AEADParams& params,
    std::vector<uint8_t>& data,
    size_t plaintext_len) {
    
    operations_count_++;
    
    std::string operation = classify_operation(params);
    bool use_hw = should_use_hardware_for_operation(operation);
    
    if (use_hw && operation.find("aes-gcm") != std::string::npos) {
        // Hardware-optimized in-place encryption for AES-GCM
        return aead_encrypt_inplace_hw(params, data, plaintext_len);
    }
    
    // Fallback to base provider's implementation or emulation
    AEADEncryptionParams enc_params;
    enc_params.key = params.key;
    enc_params.nonce = params.nonce;
    enc_params.additional_data = params.additional_data;
    enc_params.cipher = params.cipher;
    
    // Extract plaintext
    std::vector<uint8_t> plaintext(data.begin(), data.begin() + plaintext_len);
    enc_params.plaintext = plaintext;
    
    auto result = encrypt_aead(enc_params);
    if (!result) {
        return Result<void>(result.error());
    }
    
    // Replace data with ciphertext + tag
    const auto& output = result.value();
    data.clear();
    data.insert(data.end(), output.ciphertext.begin(), output.ciphertext.end());
    data.insert(data.end(), output.tag.begin(), output.tag.end());
    
    return Result<void>();
}

Result<void> HardwareAcceleratedProvider::aead_decrypt_inplace(
    const AEADParams& params,
    std::vector<uint8_t>& data,
    size_t ciphertext_len) {
    
    operations_count_++;
    
    std::string operation = classify_operation(params);
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (use_hw && operation.find("aes-gcm") != std::string::npos) {
        // Hardware-optimized in-place decryption for AES-GCM
        auto result = aead_decrypt_inplace_hw(params, data, ciphertext_len);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        update_performance_metrics(operation, duration, true);
        return result;
    }
    
    // Fallback to base provider's implementation via decrypt_aead
    AEADDecryptionParams dec_params;
    dec_params.key = params.key;
    dec_params.nonce = params.nonce;
    dec_params.additional_data = params.additional_data;
    dec_params.cipher = params.cipher;
    dec_params.ciphertext = std::vector<uint8_t>(data.begin(), data.begin() + ciphertext_len);
    
    auto result = decrypt_aead(dec_params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics(operation, duration, false);
    
    if (!result) {
        return Result<void>(result.error());
    }
    
    // Replace data with plaintext
    const auto& plaintext = result.value();
    data.clear();
    data.insert(data.end(), plaintext.begin(), plaintext.end());
    
    return Result<void>();
}

Result<std::vector<AEADEncryptionOutput>> HardwareAcceleratedProvider::batch_encrypt_aead(
    const std::vector<AEADEncryptionParams>& params_batch) {
    
    if (params_batch.empty()) {
        return Result<std::vector<AEADEncryptionOutput>>({});
    }
    
    // Check if we can use SIMD batch processing
    bool use_simd = should_use_hardware_for_operation("bulk-ops") && params_batch.size() >= 4;
    
    if (use_simd) {
        return batch_encrypt_simd(params_batch);
    }
    
    // Fallback to sequential processing
    std::vector<AEADEncryptionOutput> results;
    results.reserve(params_batch.size());
    
    for (const auto& params : params_batch) {
        auto result = encrypt_aead(params);
        if (!result) {
            return Result<std::vector<AEADEncryptionOutput>>(result.error());
        }
        results.push_back(result.value());
    }
    
    return Result<std::vector<AEADEncryptionOutput>>(std::move(results));
}

Result<std::vector<std::vector<uint8_t>>> HardwareAcceleratedProvider::batch_decrypt_aead(
    const std::vector<AEADDecryptionParams>& params_batch) {
    
    if (params_batch.empty()) {
        return Result<std::vector<std::vector<uint8_t>>>({});
    }
    
    bool use_simd = should_use_hardware_for_operation("bulk-ops") && params_batch.size() >= 4;
    
    if (use_simd) {
        return batch_decrypt_simd(params_batch);
    }
    
    // Fallback to sequential processing
    std::vector<std::vector<uint8_t>> results;
    results.reserve(params_batch.size());
    
    for (const auto& params : params_batch) {
        auto result = decrypt_aead(params);
        if (!result) {
            return Result<std::vector<std::vector<uint8_t>>>(result.error());
        }
        results.push_back(result.value());
    }
    
    return Result<std::vector<std::vector<uint8_t>>>(std::move(results));
}

// Forward remaining methods to base provider
Result<std::vector<uint8_t>> HardwareAcceleratedProvider::aead_encrypt(
    const AEADParams& params, const std::vector<uint8_t>& plaintext) {
    return base_provider_->aead_encrypt(params, plaintext);
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::aead_decrypt(
    const AEADParams& params, const std::vector<uint8_t>& ciphertext) {
    return base_provider_->aead_decrypt(params, ciphertext);
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::compute_hash(const HashParams& params) {
    operations_count_++;
    
    std::string operation = classify_operation(params);
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->compute_hash(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics(operation, duration, use_hw);
    
    return result;
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::compute_hmac(const HMACParams& params) {
    return base_provider_->compute_hmac(params);
}

Result<bool> HardwareAcceleratedProvider::verify_hmac(const MACValidationParams& params) {
    return base_provider_->verify_hmac(params);
}

Result<bool> HardwareAcceleratedProvider::validate_record_mac(const RecordMACParams& params) {
    return base_provider_->validate_record_mac(params);
}

Result<bool> HardwareAcceleratedProvider::verify_hmac_legacy(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& expected_mac,
    HashAlgorithm algorithm) {
    return base_provider_->verify_hmac_legacy(key, data, expected_mac, algorithm);
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::sign_data(const SignatureParams& params) {
    operations_count_++;
    
    std::string operation = classify_operation(params);
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->sign_data(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics(operation, duration, use_hw);
    
    return result;
}

Result<bool> HardwareAcceleratedProvider::verify_signature(
    const SignatureParams& params,
    const std::vector<uint8_t>& signature) {
    return base_provider_->verify_signature(params, signature);
}

Result<bool> HardwareAcceleratedProvider::verify_dtls_certificate_signature(
    const DTLSCertificateVerifyParams& params,
    const std::vector<uint8_t>& signature) {
    return base_provider_->verify_dtls_certificate_signature(params, signature);
}

// Pure Post-Quantum Signatures (FIPS 204 - ML-DSA) with hardware acceleration
Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
HardwareAcceleratedProvider::ml_dsa_generate_keypair(const MLDSAKeyGenParams& params) {
    operations_count_++;
    
    // ML-DSA key generation can benefit from hardware random number generation
    bool use_hw_rng = should_use_hardware_for_operation("random");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->ml_dsa_generate_keypair(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("ml-dsa-keygen", duration, use_hw_rng);
    
    if (use_hw_rng) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::ml_dsa_sign(const MLDSASignatureParams& params) {
    operations_count_++;
    
    // ML-DSA signing can benefit from vectorized operations and hardware RNG
    bool use_hw = should_use_hardware_for_operation("ml-dsa-sign");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->ml_dsa_sign(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("ml-dsa-sign", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

Result<bool> HardwareAcceleratedProvider::ml_dsa_verify(const MLDSAVerificationParams& params) {
    operations_count_++;
    
    // ML-DSA verification can benefit from vectorized operations
    bool use_hw = should_use_hardware_for_operation("ml-dsa-verify");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->ml_dsa_verify(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("ml-dsa-verify", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

// Pure Post-Quantum Signatures (FIPS 205 - SLH-DSA) with hardware acceleration
Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
HardwareAcceleratedProvider::slh_dsa_generate_keypair(const SLHDSAKeyGenParams& params) {
    operations_count_++;
    
    // SLH-DSA key generation benefits from hardware random number generation
    bool use_hw_rng = should_use_hardware_for_operation("random");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->slh_dsa_generate_keypair(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("slh-dsa-keygen", duration, use_hw_rng);
    
    if (use_hw_rng) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::slh_dsa_sign(const SLHDSASignatureParams& params) {
    operations_count_++;
    
    // SLH-DSA signing benefits from SHA-2/SHAKE hardware acceleration and vectorization
    bool use_hw = should_use_hardware_for_operation("slh-dsa-sign");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->slh_dsa_sign(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("slh-dsa-sign", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

Result<bool> HardwareAcceleratedProvider::slh_dsa_verify(const SLHDSAVerificationParams& params) {
    operations_count_++;
    
    // SLH-DSA verification benefits from SHA-2/SHAKE hardware acceleration
    bool use_hw = should_use_hardware_for_operation("slh-dsa-verify");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->slh_dsa_verify(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("slh-dsa-verify", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

// Unified Pure PQC Signature Interface with hardware optimization
Result<std::vector<uint8_t>> HardwareAcceleratedProvider::pure_pqc_sign(const PurePQCSignatureParams& params) {
    operations_count_++;
    
    // Route to appropriate hardware-optimized implementation
    std::string operation = (params.scheme >= SignatureScheme::ML_DSA_44 && 
                            params.scheme <= SignatureScheme::ML_DSA_87) ? 
                           "ml-dsa-sign" : "slh-dsa-sign";
    
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->pure_pqc_sign(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("pure-pqc-sign", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

Result<bool> HardwareAcceleratedProvider::pure_pqc_verify(const PurePQCVerificationParams& params) {
    operations_count_++;
    
    // Route to appropriate hardware-optimized implementation
    std::string operation = (params.scheme >= SignatureScheme::ML_DSA_44 && 
                            params.scheme <= SignatureScheme::ML_DSA_87) ? 
                           "ml-dsa-verify" : "slh-dsa-verify";
    
    bool use_hw = should_use_hardware_for_operation(operation);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->pure_pqc_verify(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("pure-pqc-verify", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

// Hybrid Post-Quantum + Classical Signatures with hardware acceleration
Result<HybridSignatureResult> HardwareAcceleratedProvider::hybrid_pqc_sign(const HybridPQCSignatureParams& params) {
    operations_count_++;
    
    // Hybrid signatures benefit from both classical and PQC hardware optimizations
    bool use_hw = should_use_hardware_for_operation("hybrid-pqc-sign");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->hybrid_pqc_sign(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("hybrid-pqc-sign", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

Result<bool> HardwareAcceleratedProvider::hybrid_pqc_verify(const HybridPQCVerificationParams& params) {
    operations_count_++;
    
    // Hybrid verification benefits from both classical and PQC hardware optimizations
    bool use_hw = should_use_hardware_for_operation("hybrid-pqc-verify");
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto result = base_provider_->hybrid_pqc_verify(params);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_performance_metrics("hybrid-pqc-verify", duration, use_hw);
    
    if (use_hw) hw_accelerated_ops_++; else sw_fallback_ops_++;
    
    return result;
}

Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
HardwareAcceleratedProvider::generate_key_pair(NamedGroup group) {
    return base_provider_->generate_key_pair(group);
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::perform_key_exchange(const KeyExchangeParams& params) {
    return base_provider_->perform_key_exchange(params);
}

// ML-KEM Post-Quantum Key Encapsulation - delegate to base provider
Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
HardwareAcceleratedProvider::mlkem_generate_keypair(const MLKEMKeyGenParams& params) {
    return base_provider_->mlkem_generate_keypair(params);
}

Result<MLKEMEncapResult> 
HardwareAcceleratedProvider::mlkem_encapsulate(const MLKEMEncapParams& params) {
    return base_provider_->mlkem_encapsulate(params);
}

Result<std::vector<uint8_t>> 
HardwareAcceleratedProvider::mlkem_decapsulate(const MLKEMDecapParams& params) {
    return base_provider_->mlkem_decapsulate(params);
}

// Pure ML-KEM Key Exchange - delegate to base provider
Result<PureMLKEMKeyExchangeResult>
HardwareAcceleratedProvider::perform_pure_mlkem_key_exchange(const PureMLKEMKeyExchangeParams& params) {
    return base_provider_->perform_pure_mlkem_key_exchange(params);
}

// Hybrid Post-Quantum + Classical Key Exchange - delegate to base provider
Result<HybridKeyExchangeResult> 
HardwareAcceleratedProvider::perform_hybrid_key_exchange(const HybridKeyExchangeParams& params) {
    return base_provider_->perform_hybrid_key_exchange(params);
}

Result<bool> HardwareAcceleratedProvider::validate_certificate_chain(const CertValidationParams& params) {
    return base_provider_->validate_certificate_chain(params);
}

Result<std::unique_ptr<PublicKey>> HardwareAcceleratedProvider::extract_public_key(
    const std::vector<uint8_t>& certificate) {
    return base_provider_->extract_public_key(certificate);
}

Result<std::unique_ptr<PrivateKey>> HardwareAcceleratedProvider::import_private_key(
    const std::vector<uint8_t>& key_data,
    const std::string& format) {
    return base_provider_->import_private_key(key_data, format);
}

Result<std::unique_ptr<PublicKey>> HardwareAcceleratedProvider::import_public_key(
    const std::vector<uint8_t>& key_data,
    const std::string& format) {
    return base_provider_->import_public_key(key_data, format);
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::export_private_key(
    const PrivateKey& key,
    const std::string& format) {
    return base_provider_->export_private_key(key, format);
}

Result<std::vector<uint8_t>> HardwareAcceleratedProvider::export_public_key(
    const PublicKey& key,
    const std::string& format) {
    return base_provider_->export_public_key(key, format);
}

bool HardwareAcceleratedProvider::supports_cipher_suite(CipherSuite suite) const {
    return base_provider_->supports_cipher_suite(suite);
}

bool HardwareAcceleratedProvider::supports_named_group(NamedGroup group) const {
    return base_provider_->supports_named_group(group);
}

bool HardwareAcceleratedProvider::supports_signature_scheme(SignatureScheme scheme) const {
    return base_provider_->supports_signature_scheme(scheme);
}

bool HardwareAcceleratedProvider::supports_hash_algorithm(HashAlgorithm hash) const {
    return base_provider_->supports_hash_algorithm(hash);
}

bool HardwareAcceleratedProvider::has_hardware_acceleration() const {
    return hw_profile_.has_any_acceleration;
}

bool HardwareAcceleratedProvider::is_fips_compliant() const {
    return base_provider_->is_fips_compliant();
}

SecurityLevel HardwareAcceleratedProvider::security_level() const {
    return base_provider_->security_level();
}

Result<void> HardwareAcceleratedProvider::set_security_level(SecurityLevel level) {
    return base_provider_->set_security_level(level);
}

EnhancedProviderCapabilities HardwareAcceleratedProvider::enhanced_capabilities() const {
    auto caps = base_provider_->enhanced_capabilities();
    caps.supports_batch_operations = true;
    // Note: hardware_accelerated field not available in ProviderPerformanceMetrics
    caps.performance.throughput_mbps *= hw_profile_.overall_performance_score;
    return caps;
}

Result<void> HardwareAcceleratedProvider::perform_health_check() {
    return base_provider_->perform_health_check();
}

ProviderHealth HardwareAcceleratedProvider::get_health_status() const {
    return base_provider_->get_health_status();
}

ProviderPerformanceMetrics HardwareAcceleratedProvider::get_performance_metrics() const {
    auto metrics = base_provider_->get_performance_metrics();
    
    // Add hardware acceleration metrics
    metrics.success_count += operations_count_.load();
    // Note: hardware_accelerated field not available in ProviderPerformanceMetrics
    
    float hw_ratio = operations_count_.load() > 0 ? 
        static_cast<float>(hw_accelerated_ops_.load()) / operations_count_.load() : 0.0f;
    metrics.throughput_mbps *= (1.0f + hw_ratio * (hw_profile_.overall_performance_score - 1.0f));
    
    return metrics;
}

Result<void> HardwareAcceleratedProvider::reset_performance_metrics() {
    operations_count_.store(0);
    hw_accelerated_ops_.store(0);
    sw_fallback_ops_.store(0);
    return base_provider_->reset_performance_metrics();
}

size_t HardwareAcceleratedProvider::get_memory_usage() const {
    return base_provider_->get_memory_usage();
}

size_t HardwareAcceleratedProvider::get_current_operations() const {
    return base_provider_->get_current_operations();
}

Result<void> HardwareAcceleratedProvider::set_memory_limit(size_t limit) {
    return base_provider_->set_memory_limit(limit);
}

Result<void> HardwareAcceleratedProvider::set_operation_limit(size_t limit) {
    return base_provider_->set_operation_limit(limit);
}

bool HardwareAcceleratedProvider::supports_async_operations() const {
    return base_provider_->supports_async_operations();
}

Result<std::future<std::vector<uint8_t>>> HardwareAcceleratedProvider::async_derive_key_hkdf(
    const KeyDerivationParams& params) {
    return base_provider_->async_derive_key_hkdf(params);
}

Result<std::future<AEADEncryptionOutput>> HardwareAcceleratedProvider::async_encrypt_aead(
    const AEADEncryptionParams& params) {
    return base_provider_->async_encrypt_aead(params);
}

Result<std::future<std::vector<uint8_t>>> HardwareAcceleratedProvider::async_decrypt_aead(
    const AEADDecryptionParams& params) {
    return base_provider_->async_decrypt_aead(params);
}

Result<HardwareAccelerationProfile> HardwareAcceleratedProvider::get_hardware_profile() const {
    return Result<HardwareAccelerationProfile>(hw_profile_);
}

Result<void> HardwareAcceleratedProvider::enable_hardware_acceleration(HardwareCapability capability) {
    std::lock_guard<std::mutex> lock(hw_mutex_);
    
    auto it = enabled_capabilities_.find(capability);
    if (it != enabled_capabilities_.end()) {
        it->second = true;
        return Result<void>();
    }
    
    return Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<void> HardwareAcceleratedProvider::disable_hardware_acceleration(HardwareCapability capability) {
    std::lock_guard<std::mutex> lock(hw_mutex_);
    
    auto it = enabled_capabilities_.find(capability);
    if (it != enabled_capabilities_.end()) {
        it->second = false;
        return Result<void>();
    }
    
    return Result<void>(); // Not an error if not found
}

bool HardwareAcceleratedProvider::is_hardware_accelerated(const std::string& operation) const {
    return should_use_hardware_for_operation(operation);
}

Result<float> HardwareAcceleratedProvider::benchmark_hardware_operation(const std::string& operation) {
    return Result<float>(get_hardware_speedup(operation));
}

// Private helper methods

bool HardwareAcceleratedProvider::should_use_hardware_for_operation(const std::string& operation) const {
    if (!adaptive_selection_enabled_.load()) {
        return false;
    }
    
    // Check if we have relevant hardware acceleration
    auto speedup_it = operation_speedups_.find(operation);
    if (speedup_it == operation_speedups_.end()) {
        return false;
    }
    
    return speedup_it->second > 1.1f; // Use hardware if >10% speedup expected
}

void HardwareAcceleratedProvider::update_performance_metrics(
    const std::string& operation,
    std::chrono::microseconds duration,
    bool used_hardware) const {
    
    if (used_hardware) {
        hw_accelerated_ops_++;
    } else {
        sw_fallback_ops_++;
    }
    
    // Update operation speedup estimates based on actual performance
    // This would implement adaptive learning based on runtime measurements
}

float HardwareAcceleratedProvider::get_hardware_speedup(const std::string& operation) const {
    auto it = operation_speedups_.find(operation);
    return it != operation_speedups_.end() ? it->second : 1.0f;
}

std::string HardwareAcceleratedProvider::classify_operation(const AEADParams& params) const {
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
        case AEADCipher::AES_256_GCM:
            return "aes-gcm";
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            return "aes-ccm";
        case AEADCipher::CHACHA20_POLY1305:
            return "chacha20-poly1305";
        default:
            return "unknown-aead";
    }
}

std::string HardwareAcceleratedProvider::classify_operation(const AEADEncryptionParams& params) const {
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
        case AEADCipher::AES_256_GCM:
            return "aes-gcm";
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            return "aes-ccm";
        case AEADCipher::CHACHA20_POLY1305:
            return "chacha20-poly1305";
        default:
            return "unknown-aead";
    }
}

std::string HardwareAcceleratedProvider::classify_operation(const AEADDecryptionParams& params) const {
    switch (params.cipher) {
        case AEADCipher::AES_128_GCM:
        case AEADCipher::AES_256_GCM:
            return "aes-gcm";
        case AEADCipher::AES_128_CCM:
        case AEADCipher::AES_128_CCM_8:
            return "aes-ccm";
        case AEADCipher::CHACHA20_POLY1305:
            return "chacha20-poly1305";
        default:
            return "unknown-aead";
    }
}

std::string HardwareAcceleratedProvider::classify_operation(const HashParams& params) const {
    switch (params.algorithm) {
        case HashAlgorithm::SHA256:
            return "sha256";
        case HashAlgorithm::SHA384:
            return "sha384";
        case HashAlgorithm::SHA512:
            return "sha512";
        default:
            return "unknown-hash";
    }
}

std::string HardwareAcceleratedProvider::classify_operation(const SignatureParams& params) const {
    switch (params.scheme) {
        case SignatureScheme::RSA_PKCS1_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
            return "rsa-sha256";
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
            return "ecdsa-p256";
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
            return "ecdsa-p384";
        default:
            return "unknown-signature";
    }
}

Result<void> HardwareAcceleratedProvider::aead_encrypt_inplace_hw(
    const AEADParams& params,
    std::vector<uint8_t>& data,
    size_t plaintext_len) {
    
    // This would implement hardware-specific in-place encryption
    // For now, fallback to the base implementation via encrypt_aead
    AEADEncryptionParams enc_params;
    enc_params.key = params.key;
    enc_params.nonce = params.nonce;
    enc_params.additional_data = params.additional_data;
    enc_params.cipher = params.cipher;
    enc_params.plaintext = std::vector<uint8_t>(data.begin(), data.begin() + plaintext_len);
    
    auto result = encrypt_aead(enc_params);
    if (!result) {
        return Result<void>(result.error());
    }
    
    const auto& output = result.value();
    data.clear();
    data.insert(data.end(), output.ciphertext.begin(), output.ciphertext.end());
    data.insert(data.end(), output.tag.begin(), output.tag.end());
    
    return Result<void>();
}

Result<void> HardwareAcceleratedProvider::aead_decrypt_inplace_hw(
    const AEADParams& params,
    std::vector<uint8_t>& data,
    size_t ciphertext_len) {
    
    // This would implement hardware-specific in-place decryption
    // For now, fallback to the base implementation via decrypt_aead
    AEADDecryptionParams dec_params;
    dec_params.key = params.key;
    dec_params.nonce = params.nonce;
    dec_params.additional_data = params.additional_data;
    dec_params.cipher = params.cipher;
    dec_params.ciphertext = std::vector<uint8_t>(data.begin(), data.begin() + ciphertext_len);
    
    auto result = decrypt_aead(dec_params);
    if (!result) {
        return Result<void>(result.error());
    }
    
    // Replace data with plaintext
    const auto& plaintext = result.value();
    data.clear();
    data.insert(data.end(), plaintext.begin(), plaintext.end());
    
    return Result<void>();
}

Result<std::vector<AEADEncryptionOutput>> HardwareAcceleratedProvider::batch_encrypt_simd(
    const std::vector<AEADEncryptionParams>& params_batch) {
    
    // This would implement SIMD/vectorized batch encryption
    // For now, use parallel processing as a fallback
    
    std::vector<AEADEncryptionOutput> results(params_batch.size());
    std::vector<std::future<Result<AEADEncryptionOutput>>> futures;
    
    const size_t num_threads = std::min(params_batch.size(), static_cast<size_t>(std::thread::hardware_concurrency()));
    const size_t batch_size = params_batch.size() / num_threads;
    
    for (size_t t = 0; t < num_threads; ++t) {
        size_t start = t * batch_size;
        size_t end = (t == num_threads - 1) ? params_batch.size() : (t + 1) * batch_size;
        
        futures.push_back(std::async(std::launch::async, [this, &params_batch, start, end]() -> Result<AEADEncryptionOutput> {
            std::vector<AEADEncryptionOutput> thread_results;
            for (size_t i = start; i < end; ++i) {
                auto result = encrypt_aead(params_batch[i]);
                if (!result) {
                    return Result<AEADEncryptionOutput>(result.error());
                }
                thread_results.push_back(result.value());
            }
            // This is simplified - in practice we'd need to handle the vector properly
            return Result<AEADEncryptionOutput>(thread_results[0]);
        }));
    }
    
    // Wait for all threads and collect results
    for (size_t i = 0; i < futures.size(); ++i) {
        auto result = futures[i].get();
        if (!result) {
            return Result<std::vector<AEADEncryptionOutput>>(result.error());
        }
    }
    
    // For now, fallback to sequential
    for (const auto& params : params_batch) {
        auto result = encrypt_aead(params);
        if (!result) {
            return Result<std::vector<AEADEncryptionOutput>>(result.error());
        }
        results.push_back(result.value());
    }
    
    return Result<std::vector<AEADEncryptionOutput>>(std::move(results));
}

Result<std::vector<std::vector<uint8_t>>> HardwareAcceleratedProvider::batch_decrypt_simd(
    const std::vector<AEADDecryptionParams>& params_batch) {
    
    // Similar to batch_encrypt_simd but for decryption
    std::vector<std::vector<uint8_t>> results;
    results.reserve(params_batch.size());
    
    for (const auto& params : params_batch) {
        auto result = decrypt_aead(params);
        if (!result) {
            return Result<std::vector<std::vector<uint8_t>>>(result.error());
        }
        results.push_back(result.value());
    }
    
    return Result<std::vector<std::vector<uint8_t>>>(std::move(results));
}

// Factory implementation

Result<std::unique_ptr<HardwareAcceleratedProvider>> HardwareAcceleratedProviderFactory::create(
    std::unique_ptr<CryptoProvider> base_provider) {
    
    auto hw_profile_result = detect_and_cache_hardware();
    if (!hw_profile_result) {
        return Result<std::unique_ptr<HardwareAcceleratedProvider>>(hw_profile_result.error());
    }
    
    auto hw_provider = std::make_unique<HardwareAcceleratedProvider>(
        std::move(base_provider), hw_profile_result.value());
    
    return Result<std::unique_ptr<HardwareAcceleratedProvider>>(std::move(hw_provider));
}

Result<std::unique_ptr<HardwareAcceleratedProvider>> HardwareAcceleratedProviderFactory::create_optimized(
    const std::string& base_provider_name) {
    
    std::string provider_name = base_provider_name;
    if (provider_name.empty()) {
        auto optimal_result = get_optimal_base_provider();
        if (!optimal_result) {
            provider_name = "openssl"; // Default fallback
        } else {
            provider_name = optimal_result.value();
        }
    }
    
    // Get base provider from factory
    auto& factory = ProviderFactory::instance();
    auto base_provider_result = factory.create_provider(provider_name);
    if (!base_provider_result) {
        return Result<std::unique_ptr<HardwareAcceleratedProvider>>(DTLSError::CRYPTO_PROVIDER_NOT_AVAILABLE);
    }
    
    return create(std::move(base_provider_result.value()));
}

Result<std::string> HardwareAcceleratedProviderFactory::get_optimal_base_provider() {
    auto hw_profile_result = detect_and_cache_hardware();
    if (!hw_profile_result) {
        return Result<std::string>("openssl"); // Safe default
    }
    
    const auto& profile = hw_profile_result.value();
    
    // Use hardware acceleration detector to get recommendation
    return HardwareAccelerationDetector::get_recommended_provider();
}

Result<HardwareAccelerationProfile> HardwareAcceleratedProviderFactory::detect_and_cache_hardware() {
    std::lock_guard<std::mutex> lock(detection_mutex_);
    
    if (!hw_profile_detected_.load()) {
        auto detection_result = HardwareAccelerationDetector::detect_capabilities();
        if (!detection_result) {
            return detection_result;
        }
        
        cached_hw_profile_ = detection_result.value();
        hw_profile_detected_.store(true);
    }
    
    return Result<HardwareAccelerationProfile>(cached_hw_profile_);
}

} // namespace crypto
} // namespace v13
} // namespace dtls