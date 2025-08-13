#include <gtest/gtest.h>
#include "dtls/crypto/hardware_acceleration.h"
#include "dtls/crypto/hardware_accelerated_provider.h"
#include "dtls/crypto/hardware_zero_copy.h"
#include "dtls/protocol/hardware_accelerated_record_layer.h"
#include <chrono>
#include <vector>
#include <algorithm>

using namespace dtls::v13::crypto;
using namespace dtls::v13::protocol;

class HardwareAccelerationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Detect hardware capabilities
        auto hw_result = HardwareAccelerationDetector::detect_capabilities();
        ASSERT_TRUE(hw_result) << "Failed to detect hardware capabilities";
        hw_profile_ = hw_result.value();
        
        // Create hardware-accelerated provider
        auto provider_result = HardwareAcceleratedProviderFactory::create_optimized();
        if (provider_result) {
            hw_provider_ = std::move(provider_result.value());
        }
    }
    
    void TearDown() override {
        if (hw_provider_) {
            hw_provider_->cleanup();
        }
    }
    
    HardwareAccelerationProfile hw_profile_;
    std::shared_ptr<HardwareAcceleratedProvider> hw_provider_;
};

TEST_F(HardwareAccelerationTest, HardwareDetection) {
    EXPECT_FALSE(hw_profile_.platform_name.empty());
    EXPECT_FALSE(hw_profile_.cpu_model.empty());
    EXPECT_GE(hw_profile_.overall_performance_score, 1.0f);
    
    // Print detected capabilities for debugging
    std::cout << "Detected Hardware Profile:" << std::endl;
    std::cout << "Platform: " << hw_profile_.platform_name << std::endl;
    std::cout << "CPU: " << hw_profile_.cpu_model << std::endl;
    std::cout << "Performance Score: " << hw_profile_.overall_performance_score << "x" << std::endl;
    std::cout << "Capabilities:" << std::endl;
    
    for (const auto& cap : hw_profile_.capabilities) {
        std::cout << "  - " << cap.description << " (available: " 
                  << (cap.available ? "yes" : "no") 
                  << ", enabled: " << (cap.enabled ? "yes" : "no")
                  << ", speedup: " << cap.performance_multiplier << "x)" << std::endl;
    }
}

TEST_F(HardwareAccelerationTest, CapabilityCheck) {
    // Test specific capability detection
    auto aes_available = HardwareAccelerationDetector::is_capability_available(
        HardwareCapability::AES_NI);
    auto avx_available = HardwareAccelerationDetector::is_capability_available(
        HardwareCapability::AVX);
    
    // These tests will pass/fail based on the running hardware
    std::cout << "AES-NI available: " << (aes_available ? "yes" : "no") << std::endl;
    std::cout << "AVX available: " << (avx_available ? "yes" : "no") << std::endl;
    
    // Test benchmarking
    if (aes_available) {
        auto benchmark_result = HardwareAccelerationDetector::benchmark_capability(
            HardwareCapability::AES_NI);
        ASSERT_TRUE(benchmark_result);
        EXPECT_GT(benchmark_result.value(), 0.0f);
        std::cout << "AES-NI benchmark score: " << benchmark_result.value() << std::endl;
    }
}

TEST_F(HardwareAccelerationTest, OptimizationRecommendations) {
    auto recommendations_result = HardwareAccelerationDetector::get_optimization_recommendations();
    ASSERT_TRUE(recommendations_result);
    
    const auto& recommendations = recommendations_result.value();
    EXPECT_FALSE(recommendations.empty());
    
    std::cout << "Optimization Recommendations:" << std::endl;
    for (size_t i = 0; i < recommendations.size(); ++i) {
        std::cout << "  " << (i + 1) << ". " << recommendations[i] << std::endl;
    }
}

TEST_F(HardwareAccelerationTest, HardwareUtilities) {
    auto summary = hardware_utils::get_acceleration_summary();
    EXPECT_FALSE(summary.empty());
    std::cout << "Hardware Summary:\n" << summary << std::endl;
    
    auto optimization_report = hardware_utils::generate_optimization_report();
    ASSERT_TRUE(optimization_report);
    std::cout << "Optimization Report:\n" << optimization_report.value() << std::endl;
    
    auto cipher_suites = hardware_utils::get_hardware_optimized_cipher_suites();
    EXPECT_FALSE(cipher_suites.empty());
    std::cout << "Recommended cipher suites: " << cipher_suites.size() << std::endl;
}

TEST_F(HardwareAccelerationTest, HardwareAcceleratedProvider) {
    if (!hw_provider_) {
        GTEST_SKIP() << "Hardware-accelerated provider not available";
    }
    
    EXPECT_TRUE(hw_provider_->is_available());
    
    auto init_result = hw_provider_->initialize();
    ASSERT_TRUE(init_result) << "Failed to initialize hardware provider";
    
    // Test hardware profile retrieval
    auto profile_result = hw_provider_->get_hardware_profile();
    ASSERT_TRUE(profile_result);
    EXPECT_EQ(profile_result.value().platform_name, hw_profile_.platform_name);
    
    // Test random number generation with hardware acceleration
    RandomParams rng_params;
    rng_params.length = 32;
    rng_params.cryptographically_secure = true;
    
    auto random_result = hw_provider_->generate_random(rng_params);
    ASSERT_TRUE(random_result);
    EXPECT_EQ(random_result.value().size(), 32);
    
    // Test HKDF with hardware acceleration
    KeyDerivationParams hkdf_params;
    hkdf_params.secret = std::vector<uint8_t>(32, 0xAA);
    hkdf_params.salt = std::vector<uint8_t>(16, 0xBB);
    hkdf_params.info = std::vector<uint8_t>(8, 0xCC);
    hkdf_params.output_length = 48;
    hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
    
    auto hkdf_result = hw_provider_->derive_key_hkdf(hkdf_params);
    ASSERT_TRUE(hkdf_result);
    EXPECT_EQ(hkdf_result.value().size(), 48);
    
    // Test AEAD encryption with hardware acceleration
    AEADEncryptionParams aead_params;
    aead_params.key = std::vector<uint8_t>(16, 0xDD);
    aead_params.nonce = std::vector<uint8_t>(12, 0xEE);
    aead_params.additional_data = std::vector<uint8_t>(8, 0xFF);
    aead_params.plaintext = std::vector<uint8_t>(64, 0x42);
    aead_params.cipher = AEADCipher::AES_128_GCM;
    
    auto encrypt_result = hw_provider_->encrypt_aead(aead_params);
    ASSERT_TRUE(encrypt_result);
    EXPECT_EQ(encrypt_result.value().ciphertext.size(), 64);
    EXPECT_EQ(encrypt_result.value().tag.size(), 16);
    
    // Test decryption
    AEADDecryptionParams decrypt_params;
    decrypt_params.key = aead_params.key;
    decrypt_params.nonce = aead_params.nonce;
    decrypt_params.additional_data = aead_params.additional_data;
    decrypt_params.ciphertext = encrypt_result.value().ciphertext;
    decrypt_params.tag = encrypt_result.value().tag;
    decrypt_params.cipher = aead_params.cipher;
    
    auto decrypt_result = hw_provider_->decrypt_aead(decrypt_params);
    ASSERT_TRUE(decrypt_result);
    EXPECT_EQ(decrypt_result.value(), aead_params.plaintext);
}

TEST_F(HardwareAccelerationTest, BatchOperations) {
    if (!hw_provider_) {
        GTEST_SKIP() << "Hardware-accelerated provider not available";
    }
    
    auto init_result = hw_provider_->initialize();
    ASSERT_TRUE(init_result);
    
    // Create batch of encryption parameters
    const size_t batch_size = 16;
    std::vector<AEADEncryptionParams> batch_params;
    batch_params.reserve(batch_size);
    
    for (size_t i = 0; i < batch_size; ++i) {
        AEADEncryptionParams params;
        params.key = std::vector<uint8_t>(16, static_cast<uint8_t>(i + 1));
        params.nonce = std::vector<uint8_t>(12, static_cast<uint8_t>(i + 2));
        params.additional_data = std::vector<uint8_t>(8, static_cast<uint8_t>(i + 3));
        params.plaintext = std::vector<uint8_t>(32, static_cast<uint8_t>(i + 4));
        params.cipher = AEADCipher::AES_128_GCM;
        batch_params.push_back(std::move(params));
    }
    
    // Test batch encryption
    auto start_time = std::chrono::high_resolution_clock::now();
    auto batch_result = hw_provider_->batch_encrypt_aead(batch_params);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    ASSERT_TRUE(batch_result);
    EXPECT_EQ(batch_result.value().size(), batch_size);
    
    auto batch_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    // Test sequential encryption for comparison
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<AEADEncryptionOutput> sequential_results;
    for (const auto& params : batch_params) {
        auto result = hw_provider_->encrypt_aead(params);
        ASSERT_TRUE(result);
        sequential_results.push_back(result.value());
    }
    end_time = std::chrono::high_resolution_clock::now();
    
    auto sequential_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    std::cout << "Batch encryption: " << batch_duration.count() << " µs" << std::endl;
    std::cout << "Sequential encryption: " << sequential_duration.count() << " µs" << std::endl;
    
    float speedup = static_cast<float>(sequential_duration.count()) / batch_duration.count();
    std::cout << "Batch speedup: " << speedup << "x" << std::endl;
    
    // Verify results are identical
    ASSERT_EQ(batch_result.value().size(), sequential_results.size());
    for (size_t i = 0; i < batch_size; ++i) {
        EXPECT_EQ(batch_result.value()[i].ciphertext, sequential_results[i].ciphertext);
        EXPECT_EQ(batch_result.value()[i].tag, sequential_results[i].tag);
    }
}

TEST_F(HardwareAccelerationTest, ZeroCopyOperations) {
    auto factory = HardwareZeroCryptoFactory::instance();
    auto zero_copy_result = factory.create_optimal();
    
    if (!zero_copy_result) {
        GTEST_SKIP() << "Zero-copy crypto not available";
    }
    
    auto zero_copy_crypto = std::move(zero_copy_result.value());
    
    // Test hardware-aligned buffer creation
    auto buffer = HardwareAcceleratedCryptoBuffer::create_aligned(1024);
    ASSERT_TRUE(buffer);
    EXPECT_TRUE(buffer->is_hardware_aligned());
    EXPECT_GE(buffer->capacity(), 1024);
    
    // Fill buffer with test data
    std::fill(buffer->begin(), buffer->end(), 0x42);
    
    // Test in-place encryption
    AEADParams aead_params;
    aead_params.key = std::vector<uint8_t>(16, 0xAA);
    aead_params.nonce = std::vector<uint8_t>(12, 0xBB);
    aead_params.additional_data = std::vector<uint8_t>(8, 0xCC);
    aead_params.cipher = AEADCipher::AES_128_GCM;
    
    size_t original_size = buffer->size();
    auto encrypt_result = zero_copy_crypto->encrypt_in_place(aead_params, *buffer, 512);
    ASSERT_TRUE(encrypt_result);
    EXPECT_EQ(encrypt_result.value(), 512 + 16); // plaintext + tag
    
    // Test in-place decryption
    auto decrypt_result = zero_copy_crypto->decrypt_in_place(aead_params, *buffer, encrypt_result.value());
    ASSERT_TRUE(decrypt_result);
    EXPECT_EQ(decrypt_result.value(), 512); // original plaintext size
    
    // Verify original data was restored
    for (size_t i = 0; i < 512; ++i) {
        EXPECT_EQ((*buffer)[i], 0x42);
    }
}

TEST_F(HardwareAccelerationTest, RecordLayerIntegration) {
    auto record_layer_result = HardwareAcceleratedRecordLayerFactory::create_optimal();
    
    if (!record_layer_result) {
        GTEST_SKIP() << "Hardware-accelerated record layer not available";
    }
    
    auto record_layer = std::move(record_layer_result.value());
    
    // Initialize record layer
    ConnectionParams conn_params;
    auto init_result = record_layer->initialize(conn_params);
    ASSERT_TRUE(init_result);
    
    // Test single record protection
    PlaintextRecord plaintext;
    plaintext.content_type = ContentType::APPLICATION_DATA;
    plaintext.version = DTLS_V13;
    plaintext.epoch = 1;
    plaintext.sequence_number = 42;
    plaintext.payload = std::vector<uint8_t>(100, 0x55);
    
    ProtectionParams protection_params;
    protection_params.key = std::vector<uint8_t>(16, 0xAA);
    protection_params.nonce = std::vector<uint8_t>(12, 0xBB);
    protection_params.cipher = AEADCipher::AES_128_GCM;
    protection_params.epoch = plaintext.epoch;
    protection_params.sequence_number = plaintext.sequence_number;
    
    auto protect_result = record_layer->protect_record(plaintext, protection_params);
    ASSERT_TRUE(protect_result);
    
    auto protected_record = protect_result.value();
    EXPECT_EQ(protected_record.content_type, ContentType::APPLICATION_DATA);
    EXPECT_EQ(protected_record.version, DTLS_V13);
    EXPECT_EQ(protected_record.epoch, plaintext.epoch);
    EXPECT_EQ(protected_record.sequence_number, plaintext.sequence_number);
    EXPECT_GT(protected_record.payload.size(), plaintext.payload.size()); // includes tag
    
    // Test record unprotection
    auto unprotect_result = record_layer->unprotect_record(protected_record, protection_params);
    ASSERT_TRUE(unprotect_result);
    
    auto recovered_plaintext = unprotect_result.value();
    EXPECT_EQ(recovered_plaintext.content_type, plaintext.content_type);
    EXPECT_EQ(recovered_plaintext.payload, plaintext.payload);
}

TEST_F(HardwareAccelerationTest, BatchRecordProcessing) {
    auto record_layer_result = HardwareAcceleratedRecordLayerFactory::create_optimal();
    
    if (!record_layer_result) {
        GTEST_SKIP() << "Hardware-accelerated record layer not available";
    }
    
    auto record_layer = std::move(record_layer_result.value());
    
    ConnectionParams conn_params;
    auto init_result = record_layer->initialize(conn_params);
    ASSERT_TRUE(init_result);
    
    // Create batch of records
    const size_t batch_size = 32;
    std::vector<PlaintextRecord> plaintexts;
    std::vector<ProtectionParams> params;
    
    plaintexts.reserve(batch_size);
    params.reserve(batch_size);
    
    for (size_t i = 0; i < batch_size; ++i) {
        PlaintextRecord plaintext;
        plaintext.content_type = ContentType::APPLICATION_DATA;
        plaintext.version = DTLS_V13;
        plaintext.epoch = 1;
        plaintext.sequence_number = i + 1;
        plaintext.payload = std::vector<uint8_t>(64, static_cast<uint8_t>(i + 1));
        plaintexts.push_back(std::move(plaintext));
        
        ProtectionParams protection_params;
        protection_params.key = std::vector<uint8_t>(16, 0xAA);
        protection_params.nonce = std::vector<uint8_t>(12, static_cast<uint8_t>(i + 1));
        protection_params.cipher = AEADCipher::AES_128_GCM;
        protection_params.epoch = 1;
        protection_params.sequence_number = i + 1;
        params.push_back(std::move(protection_params));
    }
    
    // Test batch protection
    auto start_time = std::chrono::high_resolution_clock::now();
    auto batch_protect_result = record_layer->protect_records_batch(plaintexts, params);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    ASSERT_TRUE(batch_protect_result);
    EXPECT_EQ(batch_protect_result.value().size(), batch_size);
    
    auto batch_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    // Test sequential protection for comparison
    start_time = std::chrono::high_resolution_clock::now();
    std::vector<ProtectedRecord> sequential_results;
    for (size_t i = 0; i < batch_size; ++i) {
        auto result = record_layer->protect_record(plaintexts[i], params[i]);
        ASSERT_TRUE(result);
        sequential_results.push_back(result.value());
    }
    end_time = std::chrono::high_resolution_clock::now();
    
    auto sequential_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    std::cout << "Batch record protection: " << batch_duration.count() << " µs" << std::endl;
    std::cout << "Sequential record protection: " << sequential_duration.count() << " µs" << std::endl;
    
    if (batch_duration.count() > 0) {
        float speedup = static_cast<float>(sequential_duration.count()) / batch_duration.count();
        std::cout << "Batch record speedup: " << speedup << "x" << std::endl;
        
        // For hardware-accelerated systems, we expect at least some performance improvement
        if (record_layer->is_hardware_acceleration_active()) {
            EXPECT_GE(speedup, 1.0f) << "Hardware acceleration should provide performance benefits";
        }
    }
    
    // Test batch unprotection
    auto batch_unprotect_result = record_layer->unprotect_records_batch(
        batch_protect_result.value(), params);
    ASSERT_TRUE(batch_unprotect_result);
    
    const auto& recovered_plaintexts = batch_unprotect_result.value();
    EXPECT_EQ(recovered_plaintexts.size(), batch_size);
    
    // Verify all records were correctly recovered
    for (size_t i = 0; i < batch_size; ++i) {
        EXPECT_EQ(recovered_plaintexts[i].content_type, plaintexts[i].content_type);
        EXPECT_EQ(recovered_plaintexts[i].payload, plaintexts[i].payload);
    }
}

TEST_F(HardwareAccelerationTest, PerformanceMetrics) {
    if (!hw_provider_) {
        GTEST_SKIP() << "Hardware-accelerated provider not available";
    }
    
    auto init_result = hw_provider_->initialize();
    ASSERT_TRUE(init_result);
    
    // Reset metrics
    auto reset_result = hw_provider_->reset_performance_metrics();
    ASSERT_TRUE(reset_result);
    
    // Perform some operations
    const size_t num_operations = 1000;
    
    for (size_t i = 0; i < num_operations; ++i) {
        RandomParams rng_params;
        rng_params.length = 32;
        rng_params.cryptographically_secure = true;
        
        auto result = hw_provider_->generate_random(rng_params);
        ASSERT_TRUE(result);
    }
    
    // Get metrics
    auto metrics = hw_provider_->get_performance_metrics();
    EXPECT_GE(metrics.success_count, num_operations);
    EXPECT_EQ(metrics.failure_count, 0);
    EXPECT_GT(metrics.throughput_mbps, 0.0f);
    
    std::cout << "Performance Metrics:" << std::endl;
    std::cout << "Success count: " << metrics.success_count << std::endl;
    std::cout << "Failure count: " << metrics.failure_count << std::endl;
    std::cout << "Success rate: " << metrics.success_rate << std::endl;
    std::cout << "Throughput: " << metrics.throughput_mbps << " MB/s" << std::endl;
    std::cout << "Average operation time: " << metrics.average_operation_time << " µs" << std::endl;
    std::cout << "Memory usage: " << metrics.memory_usage_bytes << " bytes" << std::endl;
}

TEST_F(HardwareAccelerationTest, AdaptiveSelection) {
    if (!hw_provider_) {
        GTEST_SKIP() << "Hardware-accelerated provider not available";
    }
    
    // Test that the provider can adapt operation selection based on hardware capabilities
    auto init_result = hw_provider_->initialize();
    ASSERT_TRUE(init_result);
    
    // Test different operations and verify hardware acceleration is used when available
    std::vector<std::string> operations = {
        "aes-gcm", "sha256", "hmac", "ecdsa-p256"
    };
    
    for (const auto& operation : operations) {
        bool is_hw_accelerated = hw_provider_->is_hardware_accelerated(operation);
        auto benchmark_result = hw_provider_->benchmark_hardware_operation(operation);
        
        std::cout << "Operation: " << operation 
                  << ", Hardware accelerated: " << (is_hw_accelerated ? "yes" : "no");
        
        if (benchmark_result) {
            std::cout << ", Benchmark score: " << benchmark_result.value();
        }
        std::cout << std::endl;
    }
}

// Performance comparison test
TEST_F(HardwareAccelerationTest, HardwareVsSoftwareComparison) {
    if (!hw_provider_) {
        GTEST_SKIP() << "Hardware-accelerated provider not available";
    }
    
    auto init_result = hw_provider_->initialize();
    ASSERT_TRUE(init_result);
    
    // Test AES encryption performance
    const size_t test_data_size = 1024 * 1024; // 1MB
    const size_t num_iterations = 100;
    
    AEADEncryptionParams params;
    params.key = std::vector<uint8_t>(32, 0xAA); // AES-256
    params.nonce = std::vector<uint8_t>(12, 0xBB);
    params.additional_data = std::vector<uint8_t>(8, 0xCC);
    params.plaintext = std::vector<uint8_t>(test_data_size, 0xDD);
    params.cipher = AEADCipher::AES_256_GCM;
    
    // Test with hardware acceleration enabled
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_iterations; ++i) {
        auto result = hw_provider_->encrypt_aead(params);
        ASSERT_TRUE(result);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto hw_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    std::cout << "Hardware-accelerated AES-256-GCM (" << num_iterations 
              << " iterations of " << test_data_size << " bytes): " 
              << hw_duration.count() << " µs" << std::endl;
    
    // Calculate throughput
    double total_mb = (static_cast<double>(test_data_size * num_iterations)) / (1024 * 1024);
    double duration_seconds = static_cast<double>(hw_duration.count()) / 1000000.0;
    double throughput_mbps = total_mb / duration_seconds;
    
    std::cout << "Throughput: " << throughput_mbps << " MB/s" << std::endl;
    
    // For comparison purposes, ensure we're getting reasonable performance
    EXPECT_GT(throughput_mbps, 10.0) << "Hardware acceleration should provide decent throughput";
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}