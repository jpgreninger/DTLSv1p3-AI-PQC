#include "dtls/crypto/hardware_zero_copy.h"
#include "dtls/crypto/provider_factory.h"
#include <algorithm>
#include <cstring>
#include <immintrin.h>

#ifdef _WIN32
#include <malloc.h>
#else
#include <stdlib.h>
#endif

namespace dtls {
namespace v13 {
namespace crypto {

// HardwareAcceleratedCryptoBuffer implementation

HardwareAcceleratedCryptoBuffer::HardwareAcceleratedCryptoBuffer(size_t size, size_t alignment)
    : memory::CryptoBuffer(size), hardware_alignment_(alignment) {
    ensure_hardware_aligned();
}

HardwareAcceleratedCryptoBuffer::HardwareAcceleratedCryptoBuffer(std::vector<uint8_t>&& data)
    : memory::CryptoBuffer(std::move(data)) {
    ensure_hardware_aligned();
}

std::unique_ptr<HardwareAcceleratedCryptoBuffer> HardwareAcceleratedCryptoBuffer::create_aligned(
    size_t size, size_t alignment) {
    return std::unique_ptr<HardwareAcceleratedCryptoBuffer>(
        new HardwareAcceleratedCryptoBuffer(size, alignment));
}

std::unique_ptr<HardwareAcceleratedCryptoBuffer> HardwareAcceleratedCryptoBuffer::wrap(
    std::vector<uint8_t>&& data) {
    return std::unique_ptr<HardwareAcceleratedCryptoBuffer>(
        new HardwareAcceleratedCryptoBuffer(std::move(data)));
}

bool HardwareAcceleratedCryptoBuffer::is_hardware_aligned() const {
    return is_aligned_ && (reinterpret_cast<uintptr_t>(data()) % hardware_alignment_ == 0);
}

Result<void> HardwareAcceleratedCryptoBuffer::ensure_hardware_aligned() {
    if (is_hardware_aligned()) {
        return Result<void>::success();
    }
    
    // Reallocate with proper alignment
    size_t current_size = size();
    auto aligned_data = hardware_memory::allocate_aligned(current_size, hardware_alignment_);
    if (!aligned_data) {
        return Result<void>::error(DTLSError::OUT_OF_MEMORY);
    }
    
    if (current_size > 0) {
        std::memcpy(aligned_data.get(), data(), current_size);
    }
    
    // Replace internal data - this is a simplified approach
    // In practice, we'd need to properly handle the memory::CryptoBuffer internals
    clear();
    resize(current_size);
    std::memcpy(data(), aligned_data.get(), current_size);
    
    is_aligned_ = true;
    return Result<void>::success();
}

uint8_t* HardwareAcceleratedCryptoBuffer::get_hardware_pointer() {
    if (!is_hardware_aligned()) {
        ensure_hardware_aligned();
    }
    return data();
}

const uint8_t* HardwareAcceleratedCryptoBuffer::get_hardware_pointer() const {
    return const_cast<HardwareAcceleratedCryptoBuffer*>(this)->get_hardware_pointer();
}

Result<void> HardwareAcceleratedCryptoBuffer::reserve_for_encryption(size_t plaintext_size, size_t tag_size) {
    size_t required_size = plaintext_size + tag_size;
    if (required_size > capacity()) {
        resize(required_size);
        return ensure_hardware_aligned();
    }
    return Result<void>::success();
}

// HardwareZeroCopyCrypto implementation

HardwareZeroCopyCrypto::HardwareZeroCopyCrypto(
    std::shared_ptr<HardwareAcceleratedProvider> provider,
    const HardwareConfig& config)
    : provider_(std::move(provider)), config_(config) {
}

Result<size_t> HardwareZeroCopyCrypto::encrypt_in_place(
    const AEADParams& params,
    HardwareAcceleratedCryptoBuffer& buffer,
    size_t plaintext_len) {
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Check if we can use hardware-specific optimizations
    if (config_.enable_in_place_ops && params.cipher == AEADCipher::AES_128_GCM || 
        params.cipher == AEADCipher::AES_256_GCM) {
        auto result = encrypt_in_place_aes_gcm(params, buffer, plaintext_len);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        update_metrics("encrypt_in_place", duration, true, false);
        
        return result;
    }
    
    // Fallback to provider's in-place encryption
    auto result = provider_->aead_encrypt_inplace(params, buffer.get_data(), plaintext_len);
    if (!result) {
        return Result<size_t>(result.error());
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_metrics("encrypt_in_place", duration, false, false);
    
    // Return new size (plaintext + tag)
    return Result<size_t>::success(plaintext_len + 16); // Assuming 16-byte tag
}

Result<size_t> HardwareZeroCopyCrypto::decrypt_in_place(
    const AEADParams& params,
    HardwareAcceleratedCryptoBuffer& buffer,
    size_t ciphertext_len) {
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (config_.enable_in_place_ops && (params.cipher == AEADCipher::AES_128_GCM || 
        params.cipher == AEADCipher::AES_256_GCM)) {
        auto result = decrypt_in_place_aes_gcm(params, buffer, ciphertext_len);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        update_metrics("decrypt_in_place", duration, true, false);
        
        return result;
    }
    
    // Fallback to provider's in-place decryption
    auto result = provider_->aead_decrypt_inplace(params, buffer.get_data(), ciphertext_len);
    if (!result) {
        return Result<size_t>(result.error());
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_metrics("decrypt_in_place", duration, false, false);
    
    // Return plaintext size (ciphertext - tag)
    return Result<size_t>::success(ciphertext_len - 16); // Assuming 16-byte tag
}

Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>> 
HardwareZeroCopyCrypto::batch_encrypt_simd(
    const std::vector<AEADEncryptionParams>& params_batch,
    const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& plaintext_buffers) {
    
    if (params_batch.size() != plaintext_buffers.size()) {
        return Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>>(
            DTLSError::INVALID_PARAMETER);
    }
    
    if (!config_.enable_simd_batch_ops || !can_use_simd_batch(params_batch)) {
        // Fallback to sequential processing
        std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>> results;
        results.reserve(params_batch.size());
        
        for (size_t i = 0; i < params_batch.size(); ++i) {
            const auto& params = params_batch[i];
            auto& buffer = plaintext_buffers[i];
            
            auto result_buffer = HardwareAcceleratedCryptoBuffer::create_aligned(
                buffer->size() + 16); // Add space for tag
            
            std::memcpy(result_buffer->data(), buffer->data(), buffer->size());
            
            auto encrypt_result = encrypt_in_place(
                static_cast<const AEADParams&>(params), 
                *result_buffer, 
                buffer->size());
            
            if (!encrypt_result) {
                return Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>>(
                    encrypt_result.error());
            }
            
            result_buffer->resize(encrypt_result.value());
            results.push_back(std::move(result_buffer));
        }
        
        return Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>>::success(
            std::move(results));
    }
    
    // Use SIMD batch processing
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>> results;
    results.reserve(params_batch.size());
    
    // Initialize output buffers
    for (size_t i = 0; i < params_batch.size(); ++i) {
        auto result_buffer = HardwareAcceleratedCryptoBuffer::create_aligned(
            plaintext_buffers[i]->size() + 16);
        results.push_back(std::move(result_buffer));
    }
    
    auto simd_result = batch_process_aes_gcm_simd(params_batch, plaintext_buffers, results, true);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_metrics("batch_encrypt_simd", duration, true, true);
    
    if (!simd_result) {
        return Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>>(
            simd_result.error());
    }
    
    return Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>>::success(
        std::move(results));
}

Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>> 
HardwareZeroCopyCrypto::batch_decrypt_simd(
    const std::vector<AEADDecryptionParams>& params_batch,
    const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& ciphertext_buffers) {
    
    // Similar implementation to batch_encrypt_simd but for decryption
    std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>> results;
    results.reserve(params_batch.size());
    
    for (size_t i = 0; i < params_batch.size(); ++i) {
        const auto& params = params_batch[i];
        auto& buffer = ciphertext_buffers[i];
        
        auto result_buffer = HardwareAcceleratedCryptoBuffer::create_aligned(buffer->size());
        std::memcpy(result_buffer->data(), buffer->data(), buffer->size());
        
        auto decrypt_result = decrypt_in_place(
            static_cast<const AEADParams&>(params), 
            *result_buffer, 
            buffer->size());
        
        if (!decrypt_result) {
            return Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>>(
                decrypt_result.error());
        }
        
        result_buffer->resize(decrypt_result.value());
        results.push_back(std::move(result_buffer));
    }
    
    return Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>>::success(
        std::move(results));
}

Result<std::vector<std::vector<uint8_t>>> HardwareZeroCopyCrypto::compute_hash_batch(
    const std::vector<HashParams>& params_batch,
    const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& data_buffers) {
    
    std::vector<std::vector<uint8_t>> results;
    results.reserve(params_batch.size());
    
    for (size_t i = 0; i < params_batch.size(); ++i) {
        HashParams params = params_batch[i];
        params.data = std::vector<uint8_t>(
            data_buffers[i]->data(), 
            data_buffers[i]->data() + data_buffers[i]->size());
        
        auto result = provider_->compute_hash(params);
        if (!result) {
            return Result<std::vector<std::vector<uint8_t>>>(result.error());
        }
        
        results.push_back(result.value());
    }
    
    return Result<std::vector<std::vector<uint8_t>>>::success(std::move(results));
}

Result<void> HardwareZeroCopyCrypto::stream_encrypt(
    const AEADParams& params,
    const uint8_t* input,
    uint8_t* output,
    size_t length,
    size_t chunk_size) {
    
    if (chunk_size > length) {
        chunk_size = length;
    }
    
    size_t processed = 0;
    while (processed < length) {
        size_t current_chunk = std::min(chunk_size, length - processed);
        
        // Create temporary buffer for chunk processing
        auto chunk_buffer = HardwareAcceleratedCryptoBuffer::create_aligned(current_chunk + 16);
        std::memcpy(chunk_buffer->data(), input + processed, current_chunk);
        
        auto result = encrypt_in_place(params, *chunk_buffer, current_chunk);
        if (!result) {
            return Result<void>(result.error());
        }
        
        std::memcpy(output + processed, chunk_buffer->data(), result.value());
        processed += current_chunk;
    }
    
    return Result<void>::success();
}

Result<void> HardwareZeroCopyCrypto::stream_decrypt(
    const AEADParams& params,
    const uint8_t* input,
    uint8_t* output,
    size_t length,
    size_t chunk_size) {
    
    if (chunk_size > length) {
        chunk_size = length;
    }
    
    size_t processed = 0;
    while (processed < length) {
        size_t current_chunk = std::min(chunk_size, length - processed);
        
        auto chunk_buffer = HardwareAcceleratedCryptoBuffer::create_aligned(current_chunk);
        std::memcpy(chunk_buffer->data(), input + processed, current_chunk);
        
        auto result = decrypt_in_place(params, *chunk_buffer, current_chunk);
        if (!result) {
            return Result<void>(result.error());
        }
        
        std::memcpy(output + processed, chunk_buffer->data(), result.value());
        processed += current_chunk;
    }
    
    return Result<void>::success();
}

HardwareZeroCopyCrypto::HardwareMetrics HardwareZeroCopyCrypto::get_metrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return metrics_;
}

void HardwareZeroCopyCrypto::reset_metrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_ = HardwareMetrics{};
}

void HardwareZeroCopyCrypto::update_config(const HardwareConfig& config) {
    config_ = config;
}

bool HardwareZeroCopyCrypto::is_hardware_active() const {
    return provider_ && provider_->has_hardware_acceleration();
}

// Private helper methods

Result<size_t> HardwareZeroCopyCrypto::encrypt_in_place_aes_gcm(
    const AEADParams& params,
    HardwareAcceleratedCryptoBuffer& buffer,
    size_t plaintext_len) {
    
    // Ensure buffer has space for tag
    auto reserve_result = buffer.reserve_for_encryption(plaintext_len, 16);
    if (!reserve_result) {
        return Result<size_t>(reserve_result.error());
    }
    
    // Hardware-specific AES-GCM implementation would go here
    // For now, delegate to the provider
    auto result = provider_->aead_encrypt_inplace(params, buffer.get_data(), plaintext_len);
    if (!result) {
        return Result<size_t>(result.error());
    }
    
    return Result<size_t>::success(plaintext_len + 16); // + tag size
}

Result<size_t> HardwareZeroCopyCrypto::decrypt_in_place_aes_gcm(
    const AEADParams& params,
    HardwareAcceleratedCryptoBuffer& buffer,
    size_t ciphertext_len) {
    
    auto result = provider_->aead_decrypt_inplace(params, buffer.get_data(), ciphertext_len);
    if (!result) {
        return Result<size_t>(result.error());
    }
    
    return Result<size_t>::success(ciphertext_len - 16); // - tag size
}

Result<void> HardwareZeroCopyCrypto::batch_process_aes_gcm_simd(
    const std::vector<AEADEncryptionParams>& params_batch,
    const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& input_buffers,
    std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& output_buffers,
    bool encrypt) {
    
    // This would implement actual SIMD processing for AES-GCM
    // For now, process in groups using parallel execution
    
    const size_t batch_size = std::min(config_.simd_batch_size, params_batch.size());
    
    for (size_t start = 0; start < params_batch.size(); start += batch_size) {
        size_t end = std::min(start + batch_size, params_batch.size());
        
        // Process batch in parallel
        std::vector<std::future<Result<void>>> futures;
        
        for (size_t i = start; i < end; ++i) {
            futures.push_back(std::async(std::launch::async, [&, i]() -> Result<void> {
                if (encrypt) {
                    std::memcpy(output_buffers[i]->data(), 
                               input_buffers[i]->data(), 
                               input_buffers[i]->size());
                    
                    auto result = encrypt_in_place(
                        static_cast<const AEADParams&>(params_batch[i]),
                        *output_buffers[i],
                        input_buffers[i]->size());
                    
                    if (!result) {
                        return Result<void>(result.error());
                    }
                    
                    output_buffers[i]->resize(result.value());
                } else {
                    // Decryption logic would go here
                }
                
                return Result<void>::success();
            }));
        }
        
        // Wait for batch completion
        for (auto& future : futures) {
            auto result = future.get();
            if (!result) {
                return result;
            }
        }
    }
    
    return Result<void>::success();
}

bool HardwareZeroCopyCrypto::can_use_simd_batch(
    const std::vector<AEADEncryptionParams>& params_batch) const {
    
    if (params_batch.size() < config_.simd_batch_size) {
        return false;
    }
    
    // Check if all parameters use the same cipher
    if (params_batch.empty()) {
        return false;
    }
    
    AEADCipher first_cipher = params_batch[0].cipher;
    return std::all_of(params_batch.begin(), params_batch.end(),
                      [first_cipher](const auto& params) {
                          return params.cipher == first_cipher;
                      });
}

void HardwareZeroCopyCrypto::update_metrics(
    const std::string& operation, 
    std::chrono::microseconds duration,
    bool used_hardware, 
    bool used_simd) const {
    
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (used_hardware) {
        metrics_.hardware_accelerated_ops++;
        metrics_.total_hw_time += duration;
    } else {
        metrics_.software_fallback_ops++;
        metrics_.total_sw_time += duration;
    }
    
    if (used_simd) {
        metrics_.simd_operations++;
    }
    
    if (operation.find("in_place") != std::string::npos) {
        metrics_.in_place_operations++;
    }
    
    // Update average speedups
    if (metrics_.hardware_accelerated_ops > 0 && metrics_.software_fallback_ops > 0) {
        auto avg_hw_time = metrics_.total_hw_time.count() / static_cast<double>(metrics_.hardware_accelerated_ops);
        auto avg_sw_time = metrics_.total_sw_time.count() / static_cast<double>(metrics_.software_fallback_ops);
        metrics_.average_hw_speedup = static_cast<float>(avg_sw_time / avg_hw_time);
    }
}

// Factory implementation

HardwareZeroCryptoFactory& HardwareZeroCryptoFactory::instance() {
    static HardwareZeroCryptoFactory instance;
    return instance;
}

Result<std::unique_ptr<HardwareZeroCopyCrypto>> HardwareZeroCryptoFactory::create_optimal() {
    std::lock_guard<std::mutex> lock(factory_mutex_);
    
    if (!cached_provider_) {
        auto provider_result = HardwareAcceleratedProviderFactory::create_optimized();
        if (!provider_result) {
            return Result<std::unique_ptr<HardwareZeroCopyCrypto>>(provider_result.error());
        }
        cached_provider_ = std::move(provider_result.value());
    }
    
    auto config_result = get_optimal_config();
    if (!config_result) {
        // Use default config
        auto crypto = std::make_unique<HardwareZeroCopyCrypto>(cached_provider_);
        return Result<std::unique_ptr<HardwareZeroCopyCrypto>>::success(std::move(crypto));
    }
    
    auto crypto = std::make_unique<HardwareZeroCopyCrypto>(cached_provider_, config_result.value());
    return Result<std::unique_ptr<HardwareZeroCopyCrypto>>::success(std::move(crypto));
}

Result<std::unique_ptr<HardwareZeroCopyCrypto>> HardwareZeroCryptoFactory::create_with_provider(
    const std::string& provider_name,
    const HardwareZeroCopyCrypto::HardwareConfig& config) {
    
    auto provider_result = HardwareAcceleratedProviderFactory::create_optimized(provider_name);
    if (!provider_result) {
        return Result<std::unique_ptr<HardwareZeroCopyCrypto>>(provider_result.error());
    }
    
    auto crypto = std::make_unique<HardwareZeroCopyCrypto>(
        std::move(provider_result.value()), config);
    
    return Result<std::unique_ptr<HardwareZeroCopyCrypto>>::success(std::move(crypto));
}

Result<HardwareZeroCopyCrypto::HardwareConfig> HardwareZeroCryptoFactory::get_optimal_config() {
    auto hw_profile_result = HardwareAccelerationDetector::detect_capabilities();
    if (!hw_profile_result) {
        return Result<HardwareZeroCopyCrypto::HardwareConfig>(hw_profile_result.error());
    }
    
    const auto& profile = hw_profile_result.value();
    HardwareZeroCopyCrypto::HardwareConfig config;
    
    // Configure based on detected hardware
    bool has_aes = std::any_of(profile.capabilities.begin(), profile.capabilities.end(),
                              [](const auto& cap) {
                                  return (cap.capability == HardwareCapability::AES_NI ||
                                         cap.capability == HardwareCapability::ARM_AES) &&
                                         cap.available && cap.enabled;
                              });
    
    bool has_avx = std::any_of(profile.capabilities.begin(), profile.capabilities.end(),
                              [](const auto& cap) {
                                  return (cap.capability == HardwareCapability::AVX ||
                                         cap.capability == HardwareCapability::AVX2) &&
                                         cap.available && cap.enabled;
                              });
    
    config.enable_simd_batch_ops = has_avx;
    config.enable_in_place_ops = has_aes;
    config.simd_batch_size = has_avx ? 8 : 4;
    config.required_capabilities = has_aes ? HardwareCapability::AES_NI : HardwareCapability::AVX;
    
    return Result<HardwareZeroCopyCrypto::HardwareConfig>::success(config);
}

Result<std::vector<std::pair<HardwareZeroCopyCrypto::HardwareConfig, float>>> 
HardwareZeroCryptoFactory::benchmark_configurations() {
    
    std::vector<std::pair<HardwareZeroCopyCrypto::HardwareConfig, float>> results;
    
    // Test different configurations
    std::vector<HardwareZeroCopyCrypto::HardwareConfig> configs;
    
    // Default config
    configs.push_back(HardwareZeroCopyCrypto::HardwareConfig{});
    
    // SIMD-optimized config
    HardwareZeroCopyCrypto::HardwareConfig simd_config;
    simd_config.enable_simd_batch_ops = true;
    simd_config.simd_batch_size = 8;
    configs.push_back(simd_config);
    
    // In-place optimized config
    HardwareZeroCopyCrypto::HardwareConfig inplace_config;
    inplace_config.enable_in_place_ops = true;
    configs.push_back(inplace_config);
    
    // Benchmark each configuration
    for (const auto& config : configs) {
        auto crypto_result = create_with_provider("openssl", config);
        if (!crypto_result) {
            continue;
        }
        
        auto crypto = std::move(crypto_result.value());
        
        // Simple benchmark - encrypt 1000 small messages
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 1000; ++i) {
            AEADParams params;
            params.cipher = AEADCipher::AES_128_GCM;
            params.key = std::vector<uint8_t>(16, 0xAB);
            params.nonce = std::vector<uint8_t>(12, 0xCD);
            
            auto buffer = HardwareAcceleratedCryptoBuffer::create_aligned(64);
            std::fill(buffer->begin(), buffer->end(), 0xEF);
            
            crypto->encrypt_in_place(params, *buffer, 48);
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        float score = 1000000.0f / duration.count(); // Operations per second
        results.emplace_back(config, score);
    }
    
    // Sort by performance
    std::sort(results.begin(), results.end(),
             [](const auto& a, const auto& b) { return a.second > b.second; });
    
    return Result<std::vector<std::pair<HardwareZeroCopyCrypto::HardwareConfig, float>>>::success(
        std::move(results));
}

// Hardware memory utility functions

namespace hardware_memory {

std::unique_ptr<uint8_t[]> allocate_aligned(size_t size, size_t alignment) {
#ifdef _WIN32
    uint8_t* ptr = static_cast<uint8_t*>(_aligned_malloc(size, alignment));
    return std::unique_ptr<uint8_t[]>(ptr);
#else
    uint8_t* ptr = nullptr;
    if (posix_memalign(reinterpret_cast<void**>(&ptr), alignment, size) != 0) {
        return nullptr;
    }
    return std::unique_ptr<uint8_t[]>(ptr);
#endif
}

bool is_aligned(const void* ptr, size_t alignment) {
    return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

size_t get_optimal_alignment() {
    // Detect optimal alignment based on hardware
    auto hw_result = HardwareAccelerationDetector::detect_capabilities();
    if (!hw_result) {
        return 64; // Default cache line size
    }
    
    const auto& profile = hw_result.value();
    
    bool has_avx512 = false; // Would need to detect AVX-512
    bool has_avx2 = std::any_of(profile.capabilities.begin(), profile.capabilities.end(),
                               [](const auto& cap) {
                                   return cap.capability == HardwareCapability::AVX2 &&
                                          cap.available && cap.enabled;
                               });
    
    if (has_avx512) {
        return 64; // AVX-512 prefers 64-byte alignment
    } else if (has_avx2) {
        return 32; // AVX2 prefers 32-byte alignment
    } else {
        return 16; // SSE prefers 16-byte alignment
    }
}

void copy_optimized(const void* src, void* dest, size_t size) {
    // Use hardware-accelerated copy if available
#if defined(__AVX2__)
    if (size >= 32 && is_aligned(src, 32) && is_aligned(dest, 32)) {
        // AVX2-optimized copy
        const __m256i* src_vec = static_cast<const __m256i*>(src);
        __m256i* dest_vec = static_cast<__m256i*>(dest);
        size_t vec_count = size / 32;
        
        for (size_t i = 0; i < vec_count; ++i) {
            _mm256_store_si256(dest_vec + i, _mm256_load_si256(src_vec + i));
        }
        
        // Handle remaining bytes
        size_t remaining = size % 32;
        if (remaining > 0) {
            std::memcpy(static_cast<uint8_t*>(dest) + (vec_count * 32),
                       static_cast<const uint8_t*>(src) + (vec_count * 32),
                       remaining);
        }
        return;
    }
#endif
    
    // Fallback to standard copy
    std::memcpy(dest, src, size);
}

void secure_zero(void* ptr, size_t size) {
#if defined(__AVX2__)
    if (size >= 32 && is_aligned(ptr, 32)) {
        // AVX2-optimized zero
        __m256i* vec_ptr = static_cast<__m256i*>(ptr);
        __m256i zero = _mm256_setzero_si256();
        size_t vec_count = size / 32;
        
        for (size_t i = 0; i < vec_count; ++i) {
            _mm256_store_si256(vec_ptr + i, zero);
        }
        
        // Handle remaining bytes
        size_t remaining = size % 32;
        if (remaining > 0) {
            volatile uint8_t* byte_ptr = static_cast<volatile uint8_t*>(ptr) + (vec_count * 32);
            for (size_t i = 0; i < remaining; ++i) {
                byte_ptr[i] = 0;
            }
        }
        return;
    }
#endif
    
    // Fallback to volatile zero
    volatile uint8_t* byte_ptr = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        byte_ptr[i] = 0;
    }
}

} // namespace hardware_memory

} // namespace crypto
} // namespace v13
} // namespace dtls