/**
 * @file test_crypto_security_validation.cpp
 * @brief Security-focused validation tests for cryptographic operations
 * 
 * This test suite validates security properties of crypto operations including
 * timing attack resistance, key isolation, and cryptographic correctness.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/operations.h>
#include <dtls/crypto/operations_impl.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <chrono>
#include <algorithm>
#include <random>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class CryptoSecurityValidationTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto init_result = crypto::builtin::register_all_providers();
        ASSERT_TRUE(init_result.is_success()) << "Failed to register crypto providers";
        
        auto ops_result = create_crypto_operations();
        ASSERT_TRUE(ops_result.is_success()) << "Failed to create crypto operations";
        ops_ = std::move(ops_result.value());
        ASSERT_NE(ops_, nullptr) << "Crypto operations pointer is null";
    }
    
    void TearDown() override {
        ops_.reset();
    }
    
    std::unique_ptr<ICryptoOperations> ops_;
    
    // Helper function to measure operation timing
    template<typename F>
    std::chrono::microseconds measure_timing(F&& func, size_t iterations = 1000) {
        auto start = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < iterations; ++i) {
            func();
        }
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    }
};

// === Timing Attack Resistance Tests ===

TEST_F(CryptoSecurityValidationTest, TimingAttack_HMACVerification) {
    std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 
                                 0x72, 0x6c, 0x64}; // "Hello World"
    
    // Compute correct HMAC
    auto hmac_result = ops_->compute_hmac(key, data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hmac_result.is_success()) << "HMAC computation failed";
    auto correct_hmac = hmac_result.value();
    
    // Create HMACs with different numbers of correct leading bytes
    std::vector<std::vector<uint8_t>> test_hmacs;
    
    // Completely wrong HMAC
    auto wrong_hmac = correct_hmac;
    for (auto& byte : wrong_hmac) {
        byte ^= 0xFF;
    }
    test_hmacs.push_back(wrong_hmac);
    
    // HMACs with 1, 2, 4, 8, 16 correct leading bytes
    for (size_t correct_bytes : {1, 2, 4, 8, 16}) {
        auto partial_hmac = correct_hmac;
        for (size_t i = correct_bytes; i < partial_hmac.size(); ++i) {
            partial_hmac[i] ^= 0xFF;
        }
        test_hmacs.push_back(partial_hmac);
    }
    
    // Correct HMAC
    test_hmacs.push_back(correct_hmac);
    
    // Measure timing for each HMAC verification
    std::vector<std::chrono::microseconds> timings;
    const size_t iterations_per_test = 1000;
    
    for (const auto& test_hmac : test_hmacs) {
        auto timing = measure_timing([&]() {
            auto result = ops_->verify_hmac(key, data, test_hmac, HashAlgorithm::SHA256);
            // Force actual computation by accessing result
            volatile bool value = result.is_success() ? result.value() : false;
            (void)value; // Suppress unused variable warning
        }, iterations_per_test);
        
        timings.push_back(timing);
    }
    
    // Calculate timing statistics
    auto min_time = *std::min_element(timings.begin(), timings.end());
    auto max_time = *std::max_element(timings.begin(), timings.end());
    
    // Timing variance should be minimal for constant-time implementation
    double variance_ratio = static_cast<double>(max_time.count()) / min_time.count();
    
    EXPECT_LT(variance_ratio, 1.5) << "HMAC verification timing variance too high: " 
                                   << min_time.count() << " to " << max_time.count() << " microseconds";
    
    // Log timing results for analysis
    std::cout << "HMAC Verification Timing Analysis:\n";
    for (size_t i = 0; i < timings.size(); ++i) {
        std::cout << "  Test " << i << ": " << timings[i].count() << " μs\n";
    }
    std::cout << "  Variance ratio: " << std::fixed << std::setprecision(2) << variance_ratio << "\n";
}

TEST_F(CryptoSecurityValidationTest, TimingAttack_AEADDecryption) {
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> nonce(12, 0x33);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad = {0x01, 0x02, 0x03};
    
    // Create valid ciphertext
    auto encrypt_result = ops_->aead_encrypt(plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(encrypt_result.is_success()) << "AEAD encryption failed";
    auto valid_output = encrypt_result.value();
    
    // Create test cases with different types of corruption
    struct TestCase {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;
        std::string name;
    };
    
    std::vector<TestCase> test_cases;
    
    // Valid case
    test_cases.push_back({valid_output.ciphertext, valid_output.tag, "valid"});
    
    // Corrupted first byte of ciphertext
    auto corrupt_ct_first = valid_output;
    corrupt_ct_first.ciphertext[0] ^= 0xFF;
    test_cases.push_back({corrupt_ct_first.ciphertext, corrupt_ct_first.tag, "corrupt_ct_first"});
    
    // Corrupted last byte of ciphertext
    auto corrupt_ct_last = valid_output;
    corrupt_ct_last.ciphertext.back() ^= 0xFF;
    test_cases.push_back({corrupt_ct_last.ciphertext, corrupt_ct_last.tag, "corrupt_ct_last"});
    
    // Corrupted first byte of tag
    auto corrupt_tag_first = valid_output;
    corrupt_tag_first.tag[0] ^= 0xFF;
    test_cases.push_back({corrupt_tag_first.ciphertext, corrupt_tag_first.tag, "corrupt_tag_first"});
    
    // Corrupted last byte of tag
    auto corrupt_tag_last = valid_output;
    corrupt_tag_last.tag.back() ^= 0xFF;
    test_cases.push_back({corrupt_tag_last.ciphertext, corrupt_tag_last.tag, "corrupt_tag_last"});
    
    // Measure timing for each decryption attempt
    std::vector<std::chrono::microseconds> timings;
    const size_t iterations_per_test = 1000;
    
    for (const auto& test_case : test_cases) {
        auto timing = measure_timing([&]() {
            auto result = ops_->aead_decrypt(test_case.ciphertext, test_case.tag, 
                                             key, nonce, aad, AEADCipher::AES_128_GCM);
            // Force actual computation
            volatile bool success = result.is_success();
            (void)success;
        }, iterations_per_test);
        
        timings.push_back(timing);
    }
    
    // Analyze timing variance
    auto min_time = *std::min_element(timings.begin(), timings.end());
    auto max_time = *std::max_element(timings.begin(), timings.end());
    double variance_ratio = static_cast<double>(max_time.count()) / min_time.count();
    
    EXPECT_LT(variance_ratio, 2.0) << "AEAD decryption timing variance too high";
    
    std::cout << "AEAD Decryption Timing Analysis:\n";
    for (size_t i = 0; i < timings.size(); ++i) {
        std::cout << "  " << test_cases[i].name << ": " << timings[i].count() << " μs\n";
    }
}

// === Cryptographic Correctness Tests ===

TEST_F(CryptoSecurityValidationTest, CryptoCorrectness_KnownAnswerTests) {
    // Test vectors for SHA-256 (NIST test vectors)
    struct SHA256TestVector {
        std::vector<uint8_t> input;
        std::vector<uint8_t> expected_output;
        std::string name;
    };
    
    std::vector<SHA256TestVector> sha256_vectors = {
        // Empty string
        {{}, 
         {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 
          0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 
          0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
         "empty"},
        
        // "abc"
        {{0x61, 0x62, 0x63},
         {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 
          0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 
          0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad},
         "abc"}
    };
    
    for (const auto& vector : sha256_vectors) {
        auto result = ops_->compute_hash(vector.input, HashAlgorithm::SHA256);
        ASSERT_TRUE(result.is_success()) << "SHA-256 computation failed for " << vector.name;
        EXPECT_EQ(result.value(), vector.expected_output) 
            << "SHA-256 KAT failed for " << vector.name;
    }
}

TEST_F(CryptoSecurityValidationTest, CryptoCorrectness_HMACTestVectors) {
    // HMAC-SHA256 test vectors from RFC 4231
    struct HMACTestVector {
        std::vector<uint8_t> key;
        std::vector<uint8_t> data;
        std::vector<uint8_t> expected_hmac;
        std::string name;
    };
    
    std::vector<HMACTestVector> hmac_vectors = {
        // Test Case 1
        {{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
         {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65}, // "Hi There"
         {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 
          0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 
          0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7},
         "Test Case 1"}
    };
    
    for (const auto& vector : hmac_vectors) {
        auto result = ops_->compute_hmac(vector.key, vector.data, HashAlgorithm::SHA256);
        ASSERT_TRUE(result.is_success()) << "HMAC computation failed for " << vector.name;
        EXPECT_EQ(result.value(), vector.expected_hmac) 
            << "HMAC KAT failed for " << vector.name;
        
        // Verify the computed HMAC
        auto verify_result = ops_->verify_hmac(vector.key, vector.data, vector.expected_hmac, HashAlgorithm::SHA256);
        ASSERT_TRUE(verify_result.is_success()) << "HMAC verification failed for " << vector.name;
        EXPECT_TRUE(verify_result.value()) << "HMAC verification should succeed for " << vector.name;
    }
}

// === Key Isolation Tests ===

TEST_F(CryptoSecurityValidationTest, KeyIsolation_DifferentKeysProduceDifferentResults) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    // Test with similar keys
    std::vector<uint8_t> key1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    std::vector<uint8_t> key2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11}; // Last byte different
    
    auto hmac1_result = ops_->compute_hmac(key1, data, HashAlgorithm::SHA256);
    auto hmac2_result = ops_->compute_hmac(key2, data, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hmac1_result.is_success()) << "HMAC 1 computation failed";
    ASSERT_TRUE(hmac2_result.is_success()) << "HMAC 2 computation failed";
    
    EXPECT_NE(hmac1_result.value(), hmac2_result.value()) 
        << "Different keys should produce different HMACs";
}

TEST_F(CryptoSecurityValidationTest, KeyIsolation_AEADKeyIndependence) {
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> nonce(12, 0x33);
    std::vector<uint8_t> aad = {0x01, 0x02, 0x03};
    
    std::vector<uint8_t> key1(16, 0x42);
    std::vector<uint8_t> key2(16, 0x43);
    
    auto encrypt1_result = ops_->aead_encrypt(plaintext, key1, nonce, aad, AEADCipher::AES_128_GCM);
    auto encrypt2_result = ops_->aead_encrypt(plaintext, key2, nonce, aad, AEADCipher::AES_128_GCM);
    
    ASSERT_TRUE(encrypt1_result.is_success()) << "AEAD encryption 1 failed";
    ASSERT_TRUE(encrypt2_result.is_success()) << "AEAD encryption 2 failed";
    
    EXPECT_NE(encrypt1_result.value().ciphertext, encrypt2_result.value().ciphertext)
        << "Different keys should produce different ciphertexts";
    EXPECT_NE(encrypt1_result.value().tag, encrypt2_result.value().tag)
        << "Different keys should produce different authentication tags";
}

// === Randomness Quality Tests ===

TEST_F(CryptoSecurityValidationTest, RandomnessQuality_StatisticalTests) {
    const size_t sample_size = 100000;
    auto random_result = ops_->generate_random(sample_size);
    ASSERT_TRUE(random_result.is_success()) << "Random generation failed";
    
    const auto& random_data = random_result.value();
    ASSERT_EQ(random_data.size(), sample_size) << "Random data size mismatch";
    
    // Basic statistical tests
    
    // 1. Frequency test (should be roughly equal distribution)
    std::array<size_t, 256> byte_counts = {};
    for (uint8_t byte : random_data) {
        byte_counts[byte]++;
    }
    
    // Calculate chi-square statistic
    double expected_frequency = static_cast<double>(sample_size) / 256.0;
    double chi_square = 0.0;
    for (size_t count : byte_counts) {
        double diff = count - expected_frequency;
        chi_square += (diff * diff) / expected_frequency;
    }
    
    // With 255 degrees of freedom, critical value at 0.01 significance is ~310.46
    EXPECT_LT(chi_square, 350.0) << "Random data fails frequency test (chi-square: " << chi_square << ")";
    
    // 2. Runs test (alternating patterns)
    size_t runs = 1;
    for (size_t i = 1; i < random_data.size(); ++i) {
        if ((random_data[i] & 1) != (random_data[i-1] & 1)) {
            runs++;
        }
    }
    
    // Expected runs for random data is approximately n/2
    double expected_runs = static_cast<double>(sample_size) / 2.0;
    double runs_ratio = static_cast<double>(runs) / expected_runs;
    
    EXPECT_GT(runs_ratio, 0.8) << "Too few runs in random data: " << runs;
    EXPECT_LT(runs_ratio, 1.2) << "Too many runs in random data: " << runs;
    
    std::cout << "Random Quality Analysis:\n";
    std::cout << "  Chi-square: " << std::fixed << std::setprecision(2) << chi_square << "\n";
    std::cout << "  Runs: " << runs << " (expected ~" << static_cast<size_t>(expected_runs) << ")\n";
}

TEST_F(CryptoSecurityValidationTest, RandomnessQuality_NonRepeatability) {
    const size_t num_samples = 1000;
    const size_t sample_size = 32;
    
    std::set<std::vector<uint8_t>> unique_samples;
    
    for (size_t i = 0; i < num_samples; ++i) {
        auto result = ops_->generate_random(sample_size);
        ASSERT_TRUE(result.is_success()) << "Random generation " << i << " failed";
        
        bool inserted = unique_samples.insert(result.value()).second;
        EXPECT_TRUE(inserted) << "Duplicate random sample detected at iteration " << i;
    }
    
    EXPECT_EQ(unique_samples.size(), num_samples) << "All random samples should be unique";
}

// === Nonce Uniqueness Tests ===

TEST_F(CryptoSecurityValidationTest, NonceUniqueness_DTLSRandom) {
    const size_t num_randoms = 10000;
    std::set<std::vector<uint8_t>> unique_randoms;
    
    for (size_t i = 0; i < num_randoms; ++i) {
        auto result = ops_->generate_dtls_random();
        ASSERT_TRUE(result.is_success()) << "DTLS random generation " << i << " failed";
        
        std::vector<uint8_t> random_vec(result.value().begin(), result.value().end());
        bool inserted = unique_randoms.insert(random_vec).second;
        EXPECT_TRUE(inserted) << "Duplicate DTLS random detected at iteration " << i;
    }
    
    EXPECT_EQ(unique_randoms.size(), num_randoms) << "All DTLS randoms should be unique";
}

TEST_F(CryptoSecurityValidationTest, NonceUniqueness_ConnectionIDs) {
    const size_t num_connection_ids = 10000;
    std::set<std::vector<uint8_t>> unique_connection_ids;
    
    for (size_t i = 0; i < num_connection_ids; ++i) {
        auto result = ops_->generate_connection_id(8);
        ASSERT_TRUE(result.is_success()) << "Connection ID generation " << i << " failed";
        
        bool inserted = unique_connection_ids.insert(result.value()).second;
        EXPECT_TRUE(inserted) << "Duplicate connection ID detected at iteration " << i;
    }
    
    EXPECT_EQ(unique_connection_ids.size(), num_connection_ids) 
        << "All connection IDs should be unique";
}

// === Side-Channel Resistance Tests ===

TEST_F(CryptoSecurityValidationTest, SideChannelResistance_KeyDependentTiming) {
    const size_t num_keys = 100;
    const size_t iterations_per_key = 100;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    std::vector<std::chrono::microseconds> key_timings;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    
    for (size_t key_idx = 0; key_idx < num_keys; ++key_idx) {
        // Generate random key
        std::vector<uint8_t> key(16);
        for (auto& byte : key) {
            byte = byte_dist(gen);
        }
        
        // Measure timing for this key
        auto timing = measure_timing([&]() {
            auto result = ops_->compute_hmac(key, data, HashAlgorithm::SHA256);
            volatile bool success = result.is_success();
            (void)success;
        }, iterations_per_key);
        
        key_timings.push_back(timing);
    }
    
    // Analyze timing variance across different keys
    auto min_time = *std::min_element(key_timings.begin(), key_timings.end());
    auto max_time = *std::max_element(key_timings.begin(), key_timings.end());
    double variance_ratio = static_cast<double>(max_time.count()) / min_time.count();
    
    EXPECT_LT(variance_ratio, 1.3) << "Key-dependent timing variance too high: " 
                                   << min_time.count() << " to " << max_time.count() << " microseconds";
}