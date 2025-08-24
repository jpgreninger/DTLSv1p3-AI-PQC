/**
 * @file test_performance_benchmarks_comprehensive.cpp
 * @brief Comprehensive performance benchmarks for crypto operations
 * 
 * This test suite provides detailed performance analysis of all crypto
 * operations to ensure they meet performance requirements.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <map>
#include <iomanip>
#include <sstream>

#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/crypto/openssl_provider.h"
#include "dtls/crypto/botan_provider.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class CryptoPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register all available providers
        auto register_result = builtin::register_all_providers();
        if (register_result.is_error()) {
            builtin::register_null_provider();
            builtin::register_openssl_provider();
            builtin::register_botan_provider();
        }
        
        // Get available providers
        providers_ = get_available_providers();
        
        
        // Setup test data of various sizes
        setup_test_data();
    }
    
    void TearDown() override {
        for (auto* provider : providers_) {
            delete provider;
        }
        ProviderFactory::instance().reset_all_stats();
    }
    
    void setup_test_data() {
        // Small data (typical for handshake messages)
        small_data_.resize(64);
        std::iota(small_data_.begin(), small_data_.end(), 0);
        
        // Medium data (typical for records)
        medium_data_.resize(1024);
        std::iota(medium_data_.begin(), medium_data_.end(), 0);
        
        // Large data (maximum record size)
        large_data_.resize(16384);
        std::iota(large_data_.begin(), large_data_.end(), 0);
        
        // Crypto keys
        key_128_.resize(16);
        std::iota(key_128_.begin(), key_128_.end(), 1);
        
        key_256_.resize(32);
        std::iota(key_256_.begin(), key_256_.end(), 1);
        
        // Salt and info for HKDF
        salt_ = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        info_ = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
        
        // AEAD nonce
        nonce_ = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
        aad_ = {0xAA, 0xBB, 0xCC, 0xDD};
    }
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        auto& factory = ProviderFactory::instance();
        
        for (const auto& name : {"openssl", "botan"}) {
            auto provider_result = factory.create_provider(name);
            if (provider_result.is_success()) {
                auto provider = provider_result.value().release();
                
                // Initialize the provider
                auto init_result = provider->initialize();
                if (init_result.is_success() && provider->is_available()) {
                    providers.push_back(provider);
                } else {
                    delete provider;  // Clean up if initialization failed
                }
            }
        }
        return providers;
    }
    
    struct BenchmarkResult {
        std::string operation;
        std::string provider;
        double ops_per_second;
        double avg_latency_us;
        double min_latency_us;
        double max_latency_us;
        double throughput_mbps;
        size_t data_size;
    };
    
    template<typename Func>
    BenchmarkResult benchmark_operation(
        const std::string& operation,
        const std::string& provider_name,
        Func operation_func,
        size_t iterations,
        size_t data_size = 0) {
        
        std::vector<double> latencies;
        latencies.reserve(iterations);
        
        auto start_total = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            bool success = operation_func();
            auto end = std::chrono::high_resolution_clock::now();
            
            if (success) {
                auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
                latencies.push_back(duration.count() / 1000.0);  // Convert to microseconds
            }
        }
        
        auto end_total = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_total - start_total);
        
        BenchmarkResult result;
        result.operation = operation;
        result.provider = provider_name;
        result.data_size = data_size;
        
        // Initialize all result fields to safe defaults
        result.avg_latency_us = 0.0;
        result.min_latency_us = 0.0;
        result.max_latency_us = 0.0;
        result.ops_per_second = 0.0;
        result.throughput_mbps = 0.0;
        
        if (!latencies.empty() && total_duration.count() > 0) {
            result.avg_latency_us = std::accumulate(latencies.begin(), latencies.end(), 0.0) / latencies.size();
            result.min_latency_us = *std::min_element(latencies.begin(), latencies.end());
            result.max_latency_us = *std::max_element(latencies.begin(), latencies.end());
            
            // Convert total duration to seconds and protect against division by zero
            double total_seconds = total_duration.count() / 1e9;
            if (total_seconds > 1e-9) {  // Minimum 1 nanosecond to avoid division by zero
                result.ops_per_second = latencies.size() / total_seconds;
                
                if (data_size > 0 && result.ops_per_second > 0) {
                    double bytes_per_second = result.ops_per_second * data_size;
                    result.throughput_mbps = bytes_per_second / (1024.0 * 1024.0);
                }
            } else {
                // If timing is too small, provide reasonable estimates
                if (result.avg_latency_us > 0) {
                    result.ops_per_second = 1e6 / result.avg_latency_us;  // Convert from μs to ops/sec
                    
                    if (data_size > 0) {
                        double bytes_per_second = result.ops_per_second * data_size;
                        result.throughput_mbps = bytes_per_second / (1024.0 * 1024.0);
                    }
                }
            }
        }
        
        return result;
    }
    
    void print_benchmark_result(const BenchmarkResult& result) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);
        oss << "BENCHMARK: " << result.operation << " [" << result.provider << "] ";
        
        if (result.ops_per_second > 0) {
            oss << "| " << result.ops_per_second << " ops/s ";
            oss << "| " << result.avg_latency_us << " μs avg ";
            oss << "| " << result.min_latency_us << "-" << result.max_latency_us << " μs range";
            
            if (result.throughput_mbps > 0) {
                oss << " | " << result.throughput_mbps << " MB/s";
            }
        } else {
            oss << "| FAILED - No successful operations recorded";
        }
        
        SCOPED_TRACE(oss.str());
    }
    
    std::vector<CryptoProvider*> providers_;
    std::vector<uint8_t> small_data_;
    std::vector<uint8_t> medium_data_;
    std::vector<uint8_t> large_data_;
    std::vector<uint8_t> key_128_;
    std::vector<uint8_t> key_256_;
    std::vector<uint8_t> salt_;
    std::vector<uint8_t> info_;
    std::vector<uint8_t> nonce_;
    std::vector<uint8_t> aad_;
};

// ============================================================================
// HASH PERFORMANCE BENCHMARKS
// ============================================================================

/**
 * Benchmark hash operations across different data sizes
 */
TEST_F(CryptoPerformanceTest, HashPerformance) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for performance testing";
    }
    
    
    std::vector<std::pair<std::string, std::vector<uint8_t>*>> test_cases = {
        {"small", &small_data_},
        {"medium", &medium_data_},
        {"large", &large_data_}
    };
    
    std::vector<HashAlgorithm> algorithms = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512
    };
    
    const size_t iterations = 1000;
    
    for (auto* provider : providers_) {
        for (auto algorithm : algorithms) {
            for (const auto& [size_name, data] : test_cases) {
                auto operation_func = [&]() -> bool {
                    HashParams params;
                    params.data = *data;
                    params.algorithm = algorithm;
                    
                    auto result = provider->compute_hash(params);
                    return result.is_success();
                };
                
                std::string operation_name = "Hash-" + std::to_string(static_cast<int>(algorithm)) + "-" + size_name;
                auto result = benchmark_operation(operation_name, provider->name(), operation_func, iterations, data->size());
                print_benchmark_result(result);
                
                // Performance expectations (very loose for testing environment)
                EXPECT_GT(result.ops_per_second, 1.0) 
                    << "Hash performance too slow for " << operation_name;
                EXPECT_LT(result.avg_latency_us, 100000.0) 
                    << "Hash latency too high for " << operation_name;
            }
        }
    }
}

// ============================================================================
// HMAC PERFORMANCE BENCHMARKS
// ============================================================================

/**
 * Benchmark HMAC operations
 */
TEST_F(CryptoPerformanceTest, HMACPerformance) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for performance testing";
    }
    
    std::vector<std::pair<std::string, std::vector<uint8_t>*>> test_cases = {
        {"small", &small_data_},
        {"medium", &medium_data_},
        {"large", &large_data_}
    };
    
    const size_t iterations = 1000;
    
    for (auto* provider : providers_) {
        for (const auto& [size_name, data] : test_cases) {
            auto operation_func = [&]() -> bool {
                HMACParams params;
                params.key = key_256_;
                params.data = *data;
                params.algorithm = HashAlgorithm::SHA256;
                
                auto result = provider->compute_hmac(params);
                return result.is_success();
            };
            
            std::string operation_name = "HMAC-SHA256-" + size_name;
            auto result = benchmark_operation(operation_name, provider->name(), operation_func, iterations, data->size());
            print_benchmark_result(result);
            
            // Performance expectations
            EXPECT_GT(result.ops_per_second, 1.0) 
                << "HMAC performance too slow for " << operation_name;
            EXPECT_LT(result.avg_latency_us, 100000.0) 
                << "HMAC latency too high for " << operation_name;
        }
    }
}

// ============================================================================
// KEY DERIVATION PERFORMANCE BENCHMARKS
// ============================================================================

/**
 * Benchmark HKDF operations
 */
TEST_F(CryptoPerformanceTest, HKDFPerformance) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for performance testing";
    }
    
    std::vector<size_t> output_lengths = {16, 32, 48, 64};
    const size_t iterations = 1000;
    
    for (auto* provider : providers_) {
        for (size_t length : output_lengths) {
            auto operation_func = [&]() -> bool {
                KeyDerivationParams params;
                params.secret = key_256_;
                params.salt = salt_;
                params.info = info_;
                params.output_length = length;
                params.hash_algorithm = HashAlgorithm::SHA256;
                
                auto result = provider->derive_key_hkdf(params);
                return result.is_success();
            };
            
            std::string operation_name = "HKDF-" + std::to_string(length) + "B";
            auto result = benchmark_operation(operation_name, provider->name(), operation_func, iterations);
            print_benchmark_result(result);
            
            // Performance expectations
            EXPECT_GT(result.ops_per_second, 1.0) 
                << "HKDF performance too slow for " << operation_name;
            EXPECT_LT(result.avg_latency_us, 100000.0) 
                << "HKDF latency too high for " << operation_name;
        }
    }
}

// ============================================================================
// AEAD PERFORMANCE BENCHMARKS
// ============================================================================

/**
 * Benchmark AEAD encryption operations
 */
TEST_F(CryptoPerformanceTest, AEADEncryptionPerformance) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for performance testing";
    }
    
    std::vector<std::pair<std::string, std::vector<uint8_t>*>> test_cases = {
        {"small", &small_data_},
        {"medium", &medium_data_},
        {"large", &large_data_}
    };
    
    std::vector<std::pair<AEADCipher, std::vector<uint8_t>*>> ciphers = {
        {AEADCipher::AES_128_GCM, &key_128_},
        {AEADCipher::AES_256_GCM, &key_256_},
        {AEADCipher::CHACHA20_POLY1305, &key_256_}
    };
    
    const size_t iterations = 500;  // Fewer iterations for expensive operations
    
    for (auto* provider : providers_) {
        for (const auto& [cipher, key] : ciphers) {
            for (const auto& [size_name, data] : test_cases) {
                auto operation_func = [&]() -> bool {
                    AEADEncryptionParams params;
                    params.key = *key;
                    params.nonce = nonce_;
                    params.additional_data = aad_;
                    params.plaintext = *data;
                    params.cipher = cipher;
                    
                    auto result = provider->encrypt_aead(params);
                    return result.is_success();
                };
                
                std::string cipher_name;
                switch (cipher) {
                    case AEADCipher::AES_128_GCM: cipher_name = "AES128-GCM"; break;
                    case AEADCipher::AES_256_GCM: cipher_name = "AES256-GCM"; break;
                    case AEADCipher::CHACHA20_POLY1305: cipher_name = "ChaCha20-Poly1305"; break;
                    default: cipher_name = "Unknown"; break;
                }
                
                std::string operation_name = "AEAD-Encrypt-" + cipher_name + "-" + size_name;
                auto result = benchmark_operation(operation_name, provider->name(), operation_func, iterations, data->size());
                print_benchmark_result(result);
                
                // Performance expectations (loose for test environment)
                EXPECT_GT(result.ops_per_second, 1.0) 
                    << "AEAD encryption performance too slow for " << operation_name;
                EXPECT_LT(result.avg_latency_us, 100000.0) 
                    << "AEAD encryption latency too high for " << operation_name;
                
                // For large data, expect reasonable throughput
                if (size_name == "large" && result.throughput_mbps > 0) {
                    EXPECT_GT(result.throughput_mbps, 0.1) 
                        << "AEAD encryption throughput too low for " << operation_name;
                }
            }
        }
    }
}

/**
 * Benchmark AEAD decryption operations
 */
TEST_F(CryptoPerformanceTest, AEADDecryptionPerformance) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for performance testing";
    }
    
    std::vector<std::pair<std::string, std::vector<uint8_t>*>> test_cases = {
        {"small", &small_data_},
        {"medium", &medium_data_},
        {"large", &large_data_}
    };
    
    std::vector<std::pair<AEADCipher, std::vector<uint8_t>*>> ciphers = {
        {AEADCipher::AES_128_GCM, &key_128_},
        {AEADCipher::AES_256_GCM, &key_256_},
        {AEADCipher::CHACHA20_POLY1305, &key_256_}
    };
    
    const size_t iterations = 500;
    
    for (auto* provider : providers_) {
        for (const auto& [cipher, key] : ciphers) {
            for (const auto& [size_name, data] : test_cases) {
                // First encrypt the data to have something to decrypt
                AEADEncryptionParams encrypt_params;
                encrypt_params.key = *key;
                encrypt_params.nonce = nonce_;
                encrypt_params.additional_data = aad_;
                encrypt_params.plaintext = *data;
                encrypt_params.cipher = cipher;
                
                auto encrypt_result = provider->encrypt_aead(encrypt_params);
                if (!encrypt_result.is_success()) {
                    continue;  // Skip if encryption fails
                }
                
                const auto& encrypted_output = encrypt_result.value();
                
                auto operation_func = [&]() -> bool {
                    AEADDecryptionParams params;
                    params.key = *key;
                    params.nonce = nonce_;
                    params.additional_data = aad_;
                    params.ciphertext = encrypted_output.ciphertext;
                    params.tag = encrypted_output.tag;
                    params.cipher = cipher;
                    
                    auto result = provider->decrypt_aead(params);
                    return result.is_success();
                };
                
                std::string cipher_name;
                switch (cipher) {
                    case AEADCipher::AES_128_GCM: cipher_name = "AES128-GCM"; break;
                    case AEADCipher::AES_256_GCM: cipher_name = "AES256-GCM"; break;
                    case AEADCipher::CHACHA20_POLY1305: cipher_name = "ChaCha20-Poly1305"; break;
                    default: cipher_name = "Unknown"; break;
                }
                
                std::string operation_name = "AEAD-Decrypt-" + cipher_name + "-" + size_name;
                auto result = benchmark_operation(operation_name, provider->name(), operation_func, iterations, data->size());
                print_benchmark_result(result);
                
                // Performance expectations
                EXPECT_GT(result.ops_per_second, 1.0) 
                    << "AEAD decryption performance too slow for " << operation_name;
                EXPECT_LT(result.avg_latency_us, 100000.0) 
                    << "AEAD decryption latency too high for " << operation_name;
            }
        }
    }
}

// ============================================================================
// RANDOM GENERATION PERFORMANCE BENCHMARKS
// ============================================================================

/**
 * Benchmark random generation operations
 */
TEST_F(CryptoPerformanceTest, RandomGenerationPerformance) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for performance testing";
    }
    
    std::vector<size_t> random_lengths = {16, 32, 64, 256, 1024};
    const size_t iterations = 1000;
    
    for (auto* provider : providers_) {
        for (size_t length : random_lengths) {
            auto operation_func = [&]() -> bool {
                RandomParams params;
                params.length = length;
                params.cryptographically_secure = true;
                
                auto result = provider->generate_random(params);
                return result.is_success();
            };
            
            std::string operation_name = "Random-" + std::to_string(length) + "B";
            auto result = benchmark_operation(operation_name, provider->name(), operation_func, iterations, length);
            print_benchmark_result(result);
            
            // Performance expectations
            EXPECT_GT(result.ops_per_second, 1.0) 
                << "Random generation performance too slow for " << operation_name;
            EXPECT_LT(result.avg_latency_us, 100000.0) 
                << "Random generation latency too high for " << operation_name;
        }
    }
}

// ============================================================================
// PROVIDER INITIALIZATION PERFORMANCE
// ============================================================================

/**
 * Benchmark provider initialization and cleanup
 */
TEST_F(CryptoPerformanceTest, ProviderInitializationPerformance) {
    auto& factory = ProviderFactory::instance();
    
    std::vector<std::string> provider_names = {"openssl", "botan"};
    const size_t iterations = 10;  // Fewer iterations for expensive initialization
    
    for (const auto& provider_name : provider_names) {
        
        auto operation_func = [&]() -> bool {
            auto provider_result = factory.create_provider(provider_name);
            if (provider_result.is_error()) {
                return false;
            }
            
            auto provider = std::move(provider_result.value());
            auto init_result = provider->initialize();
            if (init_result.is_error()) {
                return false;
            }
            
            provider->cleanup();
            return true;
        };
        
        std::string operation_name = "Provider-Init-" + provider_name;
        auto result = benchmark_operation(operation_name, provider_name, operation_func, iterations);
        print_benchmark_result(result);
        
        // Initialization should complete in reasonable time
        EXPECT_LT(result.avg_latency_us, 100000.0)  // 100ms
            << "Provider initialization too slow for " << provider_name;
    }
}

// ============================================================================
// MEMORY USAGE PERFORMANCE
// ============================================================================

/**
 * Test memory usage during intensive operations
 */
TEST_F(CryptoPerformanceTest, MemoryUsagePerformance) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for memory testing";
    }
    
    for (auto* provider : providers_) {
        size_t initial_memory = provider->get_memory_usage();
        
        // Perform a series of memory-intensive operations
        const size_t iterations = 100;
        for (size_t i = 0; i < iterations; ++i) {
            // Generate large random data
            RandomParams random_params;
            random_params.length = 4096;
            random_params.cryptographically_secure = true;
            auto random_result = provider->generate_random(random_params);
            
            // Hash large data
            HashParams hash_params;
            hash_params.data = large_data_;
            hash_params.algorithm = HashAlgorithm::SHA256;
            auto hash_result = provider->compute_hash(hash_params);
            
            // AEAD encryption
            AEADEncryptionParams aead_params;
            aead_params.key = key_256_;
            aead_params.nonce = nonce_;
            aead_params.additional_data = aad_;
            aead_params.plaintext = large_data_;
            aead_params.cipher = AEADCipher::AES_256_GCM;
            auto aead_result = provider->encrypt_aead(aead_params);
        }
        
        size_t final_memory = provider->get_memory_usage();
        
        // Memory usage should not grow unboundedly
        size_t memory_growth = final_memory > initial_memory ? final_memory - initial_memory : 0;
        
        SCOPED_TRACE("Provider " + provider->name() + " memory growth: " + 
                    std::to_string(memory_growth) + " bytes");
        
        // Allow some memory growth but not excessive
        EXPECT_LT(memory_growth, 10 * 1024 * 1024)  // 10MB
            << "Excessive memory growth for provider " << provider->name();
    }
}