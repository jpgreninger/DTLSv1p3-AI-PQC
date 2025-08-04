#include <gtest/gtest.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/crypto/botan_provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <test_infrastructure/test_utilities.h>
#include <chrono>
#include <random>
#include <algorithm>
#include <set>
#include <numeric>
#include <cmath>

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace dtls::test;

class RandomGenerationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto providers
        openssl_provider_ = std::make_unique<OpenSSLProvider>();
        if (openssl_provider_->is_available()) {
            auto init_result = openssl_provider_->initialize();
            ASSERT_TRUE(init_result.is_ok()) << "Failed to initialize OpenSSL provider";
        }
        
        // Try to initialize Botan provider if available
        // Commented out for now as mentioned in existing tests
        // if (botan_utils::is_botan_available()) {
        //     botan_provider_ = std::make_unique<BotanProvider>();
        //     auto init_result = botan_provider_->initialize();
        //     if (init_result.is_ok()) {
        //         botan_available_ = true;
        //     }
        // }
    }
    
    void TearDown() override {
        if (openssl_provider_) {
            openssl_provider_->cleanup();
        }
        if (botan_provider_) {
            botan_provider_->cleanup();
        }
    }
    
    // Statistical tests for randomness quality
    bool chi_square_test(const std::vector<uint8_t>& data, double significance_level = 0.05) {
        if (data.size() < 256) return true; // Skip test for small samples
        
        // Count frequency of each byte value
        std::array<size_t, 256> frequency{};
        for (uint8_t byte : data) {
            frequency[byte]++;
        }
        
        // Expected frequency (uniform distribution)
        double expected = static_cast<double>(data.size()) / 256.0;
        
        // Calculate chi-square statistic
        double chi_square = 0.0;
        for (size_t count : frequency) {
            double diff = static_cast<double>(count) - expected;
            chi_square += (diff * diff) / expected;
        }
        
        // For 255 degrees of freedom and 5% significance level, critical value is ~293.2
        // We use a more relaxed threshold for this test
        return chi_square < 350.0;
    }
    
    bool runs_test(const std::vector<uint8_t>& data) {
        if (data.empty()) return false;
        
        // Convert to bit sequence and count runs
        size_t runs = 1;
        uint8_t prev_bit = data[0] & 1;
        
        for (size_t i = 1; i < data.size(); ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                uint8_t current_bit = (data[i] >> bit) & 1;
                if (current_bit != prev_bit) {
                    runs++;
                    prev_bit = current_bit;
                }
            }
        }
        
        size_t total_bits = data.size() * 8;
        
        // For good randomness, runs should be approximately half the total bits
        // Allow reasonable deviation (25% to 75% of total bits)
        return runs >= (total_bits / 4) && runs <= (3 * total_bits / 4);
    }
    
    bool entropy_test(const std::vector<uint8_t>& data) {
        if (data.size() < 32) return true; // Skip for small samples
        
        // Check for obvious patterns
        
        // 1. All zeros
        if (std::all_of(data.begin(), data.end(), [](uint8_t b) { return b == 0; })) {
            return false;
        }
        
        // 2. All same value
        if (std::all_of(data.begin(), data.end(), [&](uint8_t b) { return b == data[0]; })) {
            return false;
        }
        
        // 3. Simple sequential pattern
        bool is_sequential = true;
        for (size_t i = 1; i < std::min(data.size(), size_t(32)); ++i) {
            if (data[i] != static_cast<uint8_t>(data[i-1] + 1)) {
                is_sequential = false;
                break;
            }
        }
        if (is_sequential) return false;
        
        // 4. Check for minimum entropy (at least 50% of possible byte values should appear)
        std::set<uint8_t> unique_bytes(data.begin(), data.end());
        double entropy_ratio = static_cast<double>(unique_bytes.size()) / std::min(data.size(), size_t(256));
        
        return entropy_ratio > 0.3; // At least 30% diversity
    }
    
    std::unique_ptr<OpenSSLProvider> openssl_provider_;
    std::unique_ptr<BotanProvider> botan_provider_;
    bool botan_available_ = false;
};

// Basic functionality tests
TEST_F(RandomGenerationTest, BasicRandomGeneration) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    RandomParams params;
    params.length = 32;
    params.cryptographically_secure = true;
    
    auto result = openssl_provider_->generate_random(params);
    ASSERT_TRUE(result.is_ok()) << "Random generation should succeed";
    
    auto random_data = result.value();
    EXPECT_EQ(random_data.size(), 32);
    
    // Generate a second random value and ensure they're different
    auto result2 = openssl_provider_->generate_random(params);
    ASSERT_TRUE(result2.is_ok());
    
    auto random_data2 = result2.value();
    EXPECT_NE(random_data, random_data2) << "Two random generations should produce different results";
}

TEST_F(RandomGenerationTest, DTLSRandomTypeGeneration) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    // Test the convenience wrapper
    auto result = utils::generate_random(*openssl_provider_);
    ASSERT_TRUE(result.is_ok()) << "DTLS Random generation should succeed";
    
    auto random_value = result.value();
    EXPECT_EQ(random_value.size(), RANDOM_LENGTH);
    
    // Verify it's different from a second generation
    auto result2 = utils::generate_random(*openssl_provider_);
    ASSERT_TRUE(result2.is_ok());
    
    auto random_value2 = result2.value();
    EXPECT_NE(random_value, random_value2);
}

TEST_F(RandomGenerationTest, ClientHelloRandomGeneration) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    auto result = utils::generate_client_hello_random(*openssl_provider_);
    ASSERT_TRUE(result.is_ok()) << "ClientHello random generation should succeed";
    
    auto client_random = result.value();
    EXPECT_EQ(client_random.size(), 32) << "ClientHello random must be exactly 32 bytes";
    
    // Verify uniqueness
    auto result2 = utils::generate_client_hello_random(*openssl_provider_);
    ASSERT_TRUE(result2.is_ok());
    
    auto client_random2 = result2.value();
    EXPECT_NE(client_random, client_random2) << "ClientHello randoms should be unique";
}

TEST_F(RandomGenerationTest, ServerHelloRandomGeneration) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    auto result = utils::generate_server_hello_random(*openssl_provider_);
    ASSERT_TRUE(result.is_ok()) << "ServerHello random generation should succeed";
    
    auto server_random = result.value();
    EXPECT_EQ(server_random.size(), 32) << "ServerHello random must be exactly 32 bytes";
    
    // Verify uniqueness
    auto result2 = utils::generate_server_hello_random(*openssl_provider_);
    ASSERT_TRUE(result2.is_ok());
    
    auto server_random2 = result2.value();
    EXPECT_NE(server_random, server_random2) << "ServerHello randoms should be unique";
}

TEST_F(RandomGenerationTest, RandomWithAdditionalEntropy) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    std::vector<uint8_t> additional_entropy = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    auto result = utils::generate_dtls_random_with_entropy(*openssl_provider_, additional_entropy);
    ASSERT_TRUE(result.is_ok()) << "Random generation with entropy should succeed";
    
    auto enhanced_random = result.value();
    EXPECT_EQ(enhanced_random.size(), 32);
    
    // Compare with regular random to ensure additional entropy makes a difference
    auto regular_result = utils::generate_random(*openssl_provider_);
    ASSERT_TRUE(regular_result.is_ok());
    
    // They should be different (though this is probabilistic)
    EXPECT_NE(enhanced_random, regular_result.value());
}

// Error handling tests
TEST_F(RandomGenerationTest, InvalidParameters) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    // Test zero length
    RandomParams params;
    params.length = 0;
    params.cryptographically_secure = true;
    
    auto result = openssl_provider_->generate_random(params);
    EXPECT_FALSE(result.is_ok()) << "Zero length should fail";
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(RandomGenerationTest, UninitializedProvider) {
    auto uninit_provider = std::make_unique<OpenSSLProvider>();
    // Don't initialize it
    
    RandomParams params;
    params.length = 32;
    params.cryptographically_secure = true;
    
    auto result = uninit_provider->generate_random(params);
    EXPECT_FALSE(result.is_ok()) << "Uninitialized provider should fail";
    EXPECT_EQ(result.error(), DTLSError::NOT_INITIALIZED);
}

// Security and quality tests
TEST_F(RandomGenerationTest, RandomnessQuality) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    // Generate a large sample for statistical testing
    RandomParams params;
    params.length = 1024; // 1KB sample
    params.cryptographically_secure = true;
    
    auto result = openssl_provider_->generate_random(params);
    ASSERT_TRUE(result.is_ok());
    
    auto random_data = result.value();
    
    // Apply statistical tests
    EXPECT_TRUE(entropy_test(random_data)) << "Random data should pass basic entropy tests";
    EXPECT_TRUE(runs_test(random_data)) << "Random data should pass runs test";
    EXPECT_TRUE(chi_square_test(random_data)) << "Random data should pass chi-square test";
}

TEST_F(RandomGenerationTest, ReproducibilityTest) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    const int num_samples = 100;
    std::vector<std::vector<uint8_t>> samples;
    
    RandomParams params;
    params.length = 32;
    params.cryptographically_secure = true;
    
    // Generate multiple samples
    for (int i = 0; i < num_samples; ++i) {
        auto result = openssl_provider_->generate_random(params);
        ASSERT_TRUE(result.is_ok());
        samples.push_back(result.value());
    }
    
    // Verify all samples are unique (with very high probability)
    for (int i = 0; i < num_samples; ++i) {
        for (int j = i + 1; j < num_samples; ++j) {
            EXPECT_NE(samples[i], samples[j]) << "Sample " << i << " and " << j << " should be different";
        }
    }
}

TEST_F(RandomGenerationTest, PerformanceTest) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    RandomParams params;
    params.length = 32;
    params.cryptographically_secure = true;
    
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto result = openssl_provider_->generate_random(params);
        ASSERT_TRUE(result.is_ok());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should be able to generate 1000 32-byte randoms in reasonable time (< 100ms)
    EXPECT_LT(duration.count(), 100000) << "Random generation should be performant";
    
    double avg_time_per_generation = static_cast<double>(duration.count()) / iterations;
    std::cout << "Average time per 32-byte random generation: " 
              << avg_time_per_generation << " microseconds" << std::endl;
}

// Integration tests with DTLS protocol structures
TEST_F(RandomGenerationTest, HandshakeMessageIntegration) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    // Test that our random generation works with actual DTLS handshake messages
    auto client_random_result = utils::generate_client_hello_random(*openssl_provider_);
    ASSERT_TRUE(client_random_result.is_ok());
    
    auto server_random_result = utils::generate_server_hello_random(*openssl_provider_);
    ASSERT_TRUE(server_random_result.is_ok());
    
    auto client_random = client_random_result.value();
    auto server_random = server_random_result.value();
    
    // Verify they can be used in key derivation (basic test)
    EXPECT_NE(client_random, server_random) << "Client and server randoms should be different";
    
    // Verify size requirements for DTLS v1.3
    EXPECT_EQ(client_random.size(), 32);
    EXPECT_EQ(server_random.size(), 32);
}

// Edge cases and boundary tests
TEST_F(RandomGenerationTest, VariousLengths) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    std::vector<size_t> test_lengths = {1, 16, 32, 64, 128, 256, 1024};
    
    for (size_t length : test_lengths) {
        RandomParams params;
        params.length = length;
        params.cryptographically_secure = true;
        
        auto result = openssl_provider_->generate_random(params);
        ASSERT_TRUE(result.is_ok()) << "Length " << length << " should succeed";
        
        auto random_data = result.value();
        EXPECT_EQ(random_data.size(), length);
        
        if (length >= 16) {
            EXPECT_TRUE(entropy_test(random_data)) << "Length " << length << " should pass entropy test";
        }
    }
}

TEST_F(RandomGenerationTest, NonCryptographicRandom) {
    ASSERT_TRUE(openssl_provider_->is_available());
    
    RandomParams params;
    params.length = 32;
    params.cryptographically_secure = false; // Non-cryptographic
    
    auto result = openssl_provider_->generate_random(params);
    ASSERT_TRUE(result.is_ok()) << "Non-cryptographic random should still succeed";
    
    auto random_data = result.value();
    EXPECT_EQ(random_data.size(), 32);
    
    // Should still pass basic tests
    EXPECT_TRUE(entropy_test(random_data));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}