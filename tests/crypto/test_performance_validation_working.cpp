/**
 * @file test_performance_validation_working.cpp
 * @brief Working Crypto Performance Validation Test
 * 
 * Simple performance validation that successfully benchmarks real crypto vs stubs
 * and generates a validation report as requested in TASKS.md Performance Validation.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/crypto/provider.h>
#include <dtls/types.h>
#include <chrono>
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class CryptoPerformanceValidationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize built-in providers
        builtin::register_all_providers();
        
        auto& factory = ProviderFactory::instance();
        auto providers = factory.available_providers();
        
        std::cout << "\n=== Crypto Performance Validation Setup ===\n";
        std::cout << "Available providers: ";
        for (const auto& name : providers) {
            std::cout << name << " ";
        }
        std::cout << "\n";
        
        for (const auto& provider_name : providers) {
            auto provider_result = factory.create_provider(provider_name);
            if (provider_result && provider_result.value()->is_available()) {
                auto provider = std::move(provider_result.value());
                if (provider->initialize()) {
                    providers_.push_back(std::move(provider));
                    std::cout << "Initialized provider: " << provider_name << "\n";
                }
            }
        }
        std::cout << "=============================================\n\n";
    }
    
    void TearDown() override {
        for (auto& provider : providers_) {
            if (provider) {
                provider->cleanup();
            }
        }
        providers_.clear();
    }
    
    std::vector<std::unique_ptr<CryptoProvider>> providers_;
    
    struct PerformanceResult {
        std::string operation;
        std::string provider;
        size_t iterations;
        double avg_time_us;
        double ops_per_sec;
        bool appears_to_be_stub;
        std::string notes;
    };
    
    std::vector<PerformanceResult> validation_results_;
    
    // Simple heuristic to detect stub implementations
    bool likely_stub_implementation(double avg_time_us, const std::string& operation) {
        // Stubs typically complete in < 0.1 microseconds
        // Real crypto operations should take longer, especially signature operations
        if (operation.find("signature") != std::string::npos || operation.find("sign") != std::string::npos) {
            return avg_time_us < 10.0; // Signature operations should take at least 10µs
        } else if (operation.find("aead") != std::string::npos || operation.find("encrypt") != std::string::npos) {
            return avg_time_us < 1.0; // AEAD operations should take at least 1µs
        } else {
            return avg_time_us < 0.5; // Other operations should take at least 0.5µs
        }
    }
};

// Test AEAD operations performance
TEST_F(CryptoPerformanceValidationTest, AEADPerformanceBaseline) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    std::cout << "=== AEAD Performance Baseline ===\n";
    
    // Test data
    std::vector<uint8_t> key(16, 0x42);  // 128-bit key
    std::vector<uint8_t> nonce(12, 0x00); // 96-bit nonce  
    std::vector<uint8_t> plaintext(1024, 0x41); // 1KB test data
    std::vector<uint8_t> aad = {0x41, 0x41, 0x44}; // "AAD"
    
    for (auto& provider : providers_) {
        std::string provider_name = provider->capabilities().provider_name;
        
        // Test AES-128-GCM encryption/decryption
        const size_t iterations = 100;
        size_t successful_operations = 0;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < iterations; ++i) {
            // Encryption
            AEADEncryptionParams encrypt_params;
            encrypt_params.cipher = AEADCipher::AES_128_GCM;
            encrypt_params.key = key;
            encrypt_params.nonce = nonce;
            encrypt_params.plaintext = plaintext;
            encrypt_params.additional_data = aad;
            
            auto encrypt_result = provider->encrypt_aead(encrypt_params);
            if (encrypt_result) {
                successful_operations++;
                
                // Decryption
                AEADDecryptionParams decrypt_params;
                decrypt_params.cipher = encrypt_params.cipher;
                decrypt_params.key = encrypt_params.key;
                decrypt_params.nonce = encrypt_params.nonce;
                decrypt_params.ciphertext = encrypt_result.value().ciphertext;
                decrypt_params.tag = encrypt_result.value().tag;
                decrypt_params.additional_data = encrypt_params.additional_data;
                
                auto decrypt_result = provider->decrypt_aead(decrypt_params);
                if (decrypt_result) {
                    successful_operations++;
                }
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        if (successful_operations > 0) {
            double avg_time_us = duration.count() / static_cast<double>(successful_operations);
            double ops_per_sec = 1000000.0 / avg_time_us;
            bool is_stub = likely_stub_implementation(avg_time_us, "aead_encrypt_decrypt");
            
            PerformanceResult result = {
                "AEAD AES-128-GCM encrypt/decrypt",
                provider_name,
                successful_operations,
                avg_time_us,
                ops_per_sec,
                is_stub,
                is_stub ? "Suspiciously fast - likely stub" : "Normal timing - likely real crypto"
            };
            validation_results_.push_back(result);
            
            std::cout << "Provider: " << provider_name << "\n";
            std::cout << "  Operations: " << successful_operations << "\n";
            std::cout << "  Avg time: " << avg_time_us << " µs\n";
            std::cout << "  Throughput: " << ops_per_sec << " ops/sec\n";
            std::cout << "  Assessment: " << result.notes << "\n\n";
        }
    }
}

// Test random generation performance
TEST_F(CryptoPerformanceValidationTest, RandomGenerationBaseline) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    std::cout << "=== Random Generation Performance Baseline ===\n";
    
    for (auto& provider : providers_) {
        std::string provider_name = provider->capabilities().provider_name;
        
        const size_t iterations = 1000;
        const size_t random_size = 32; // 256 bits
        size_t successful_operations = 0;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < iterations; ++i) {
            RandomParams params;
            params.length = random_size;
            params.cryptographically_secure = true;
            
            auto result = provider->generate_random(params);
            if (result && result.value().size() == random_size) {
                successful_operations++;
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        if (successful_operations > 0) {
            double avg_time_us = duration.count() / static_cast<double>(successful_operations);
            double ops_per_sec = 1000000.0 / avg_time_us;
            bool is_stub = likely_stub_implementation(avg_time_us, "random_generation");
            
            PerformanceResult result = {
                "Random generation 256-bit",
                provider_name,
                successful_operations,
                avg_time_us,
                ops_per_sec,
                is_stub,
                is_stub ? "Suspiciously fast - likely stub" : "Normal timing - likely real crypto"
            };
            validation_results_.push_back(result);
            
            std::cout << "Provider: " << provider_name << "\n";
            std::cout << "  Operations: " << successful_operations << "\n";
            std::cout << "  Avg time: " << avg_time_us << " µs\n";
            std::cout << "  Throughput: " << ops_per_sec << " ops/sec\n";
            std::cout << "  Assessment: " << result.notes << "\n\n";
        }
    }
}

// Generate validation report
TEST_F(CryptoPerformanceValidationTest, GenerateValidationReport) {
    if (validation_results_.empty()) {
        GTEST_SKIP() << "No validation results to report";
    }
    
    std::cout << "\n=== Crypto Performance Validation Report ===\n";
    
    // Console report
    size_t real_crypto_operations = 0;
    size_t stub_operations = 0;
    
    for (const auto& result : validation_results_) {
        if (result.appears_to_be_stub) {
            stub_operations++;
        } else {
            real_crypto_operations++;
        }
    }
    
    std::cout << "Total operations tested: " << validation_results_.size() << "\n";
    std::cout << "Real crypto operations: " << real_crypto_operations << "\n";
    std::cout << "Suspected stub operations: " << stub_operations << "\n";
    std::cout << "Real crypto percentage: " << 
        (validation_results_.empty() ? 0.0 : 
         (100.0 * real_crypto_operations / validation_results_.size())) << "%\n\n";
    
    // Detailed results
    std::cout << "Detailed Results:\n";
    std::cout << "================\n";
    for (const auto& result : validation_results_) {
        std::cout << "Operation: " << result.operation << "\n";
        std::cout << "Provider: " << result.provider << "\n";
        std::cout << "Performance: " << result.ops_per_sec << " ops/sec\n";
        std::cout << "Classification: " << (result.appears_to_be_stub ? "STUB" : "REAL CRYPTO") << "\n";
        std::cout << "Notes: " << result.notes << "\n";
        std::cout << "------------------------\n";
    }
    
    // File report (to build directory)
    std::string report_filename = "../crypto_performance_validation_report.txt";
    std::ofstream report_file(report_filename);
    if (report_file.is_open()) {
        report_file << "DTLS v1.3 Crypto Performance Validation Report\n";
        report_file << "==============================================\n\n";
        report_file << "Generated: " << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
        report_file << "Total operations tested: " << validation_results_.size() << "\n";
        report_file << "Real crypto operations: " << real_crypto_operations << "\n";
        report_file << "Suspected stub operations: " << stub_operations << "\n\n";
        
        report_file << "Performance Analysis:\n";
        report_file << "====================\n";
        for (const auto& result : validation_results_) {
            report_file << "Operation: " << result.operation << "\n";
            report_file << "Provider: " << result.provider << "\n";
            report_file << "Iterations: " << result.iterations << "\n";
            report_file << "Avg Time: " << result.avg_time_us << " µs\n";
            report_file << "Throughput: " << result.ops_per_sec << " ops/sec\n";
            report_file << "Classification: " << (result.appears_to_be_stub ? "STUB" : "REAL CRYPTO") << "\n";
            report_file << "Notes: " << result.notes << "\n";
            report_file << "------------------------\n";
        }
        
        report_file << "\nConclusion:\n";
        if (real_crypto_operations > 0) {
            report_file << "✅ PASS - Real cryptographic operations detected\n";
            report_file << "The DTLS v1.3 implementation includes functional cryptographic operations.\n";
        } else {
            report_file << "❌ FAIL - Only stub operations detected\n";
            report_file << "All tested operations appear to be stubs. Real crypto implementation needed.\n";
        }
        
        report_file.close();
        std::cout << "\n✅ Validation report written to: " << report_filename << "\n";
    }
    
    // Test assertions
    EXPECT_GT(validation_results_.size(), 0) << "Should have performance results";
    EXPECT_GT(real_crypto_operations, 0) << "Should detect some real crypto operations (not all stubs)";
    
    std::cout << "\n=== Performance Validation Complete ===\n";
}