/*
 * Basic Timing Attack Resistance Test
 * Simplified standalone test for timing attack resistance validation
 */

#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>

namespace dtls::v13::test {

class BasicTimingResistanceTest : public ::testing::Test {
protected:
    std::vector<uint8_t> generate_random_data(size_t size) {
        std::vector<uint8_t> data(size);
        std::mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        std::generate(data.begin(), data.end(), [&]() { return dist(rng); });
        return data;
    }

    bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        
        uint8_t result = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            result |= (a[i] ^ b[i]);
        }
        
        return result == 0;
    }
    
    double calculate_coefficient_of_variation(const std::vector<std::chrono::nanoseconds>& times) {
        if (times.empty()) return 1.0;
        
        std::vector<double> durations;
        for (auto t : times) durations.push_back(t.count());
        
        double mean = std::accumulate(durations.begin(), durations.end(), 0.0) / durations.size();
        
        double variance = 0.0;
        for (double d : durations) {
            variance += (d - mean) * (d - mean);
        }
        variance /= durations.size();
        
        double std_dev = std::sqrt(variance);
        return std_dev / mean;
    }
};

/**
 * Test constant-time memory comparison
 */
TEST_F(BasicTimingResistanceTest, MemoryComparisonConstantTime) {
    const size_t iterations = 100;
    std::vector<std::chrono::nanoseconds> equal_times;
    std::vector<std::chrono::nanoseconds> unequal_times;
    
    // Test equal comparisons
    for (size_t i = 0; i < iterations; ++i) {
        auto data1 = generate_random_data(32);
        auto data2 = data1;
        
        auto start = std::chrono::high_resolution_clock::now();
        bool result = constant_time_compare(data1, data2);
        auto end = std::chrono::high_resolution_clock::now();
        
        EXPECT_TRUE(result);
        equal_times.push_back(end - start);
    }
    
    // Test unequal comparisons
    for (size_t i = 0; i < iterations; ++i) {
        auto data1 = generate_random_data(32);
        auto data2 = data1;
        data2[i % 32] ^= 0x01;
        
        auto start = std::chrono::high_resolution_clock::now();
        bool result = constant_time_compare(data1, data2);
        auto end = std::chrono::high_resolution_clock::now();
        
        EXPECT_FALSE(result);
        unequal_times.push_back(end - start);
    }
    
    // Check timing consistency
    double equal_cv = calculate_coefficient_of_variation(equal_times);
    double unequal_cv = calculate_coefficient_of_variation(unequal_times);
    
    // Both should have low coefficient of variation (< 10%)
    EXPECT_LT(equal_cv, 0.1) << "Equal comparison timing varies too much: " << equal_cv;
    EXPECT_LT(unequal_cv, 0.1) << "Unequal comparison timing varies too much: " << unequal_cv;
    
    std::cout << "Memory Comparison Timing Analysis:\n";
    std::cout << "  Equal comparisons CV: " << equal_cv << "\n";
    std::cout << "  Unequal comparisons CV: " << unequal_cv << "\n";
}

/**
 * Test XOR operation timing independence
 */
TEST_F(BasicTimingResistanceTest, XOROperationConstantTime) {
    const size_t iterations = 100;
    std::vector<std::chrono::nanoseconds> zero_xor_times;
    std::vector<std::chrono::nanoseconds> random_xor_times;
    
    auto zero_data = std::vector<uint8_t>(32, 0x00);
    
    // Test XOR with zero
    for (size_t i = 0; i < iterations; ++i) {
        auto data = generate_random_data(32);
        
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> result(32);
        for (size_t j = 0; j < 32; ++j) {
            result[j] = data[j] ^ zero_data[j];
        }
        volatile int sum = std::accumulate(result.begin(), result.end(), 0);
        (void)sum;
        auto end = std::chrono::high_resolution_clock::now();
        
        zero_xor_times.push_back(end - start);
    }
    
    // Test XOR with random data
    for (size_t i = 0; i < iterations; ++i) {
        auto data1 = generate_random_data(32);
        auto data2 = generate_random_data(32);
        
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> result(32);
        for (size_t j = 0; j < 32; ++j) {
            result[j] = data1[j] ^ data2[j];
        }
        volatile int sum = std::accumulate(result.begin(), result.end(), 0);
        (void)sum;
        auto end = std::chrono::high_resolution_clock::now();
        
        random_xor_times.push_back(end - start);
    }
    
    double zero_cv = calculate_coefficient_of_variation(zero_xor_times);
    double random_cv = calculate_coefficient_of_variation(random_xor_times);
    
    // Both should have similar timing patterns
    EXPECT_LT(zero_cv, 0.2) << "XOR with zero timing varies too much: " << zero_cv;
    EXPECT_LT(random_cv, 0.2) << "XOR with random timing varies too much: " << random_cv;
    
    std::cout << "XOR Operation Timing Analysis:\n";
    std::cout << "  XOR with zero CV: " << zero_cv << "\n";
    std::cout << "  XOR with random CV: " << random_cv << "\n";
}

/**
 * Test hash computation timing consistency
 */
TEST_F(BasicTimingResistanceTest, HashComputationTiming) {
    const size_t iterations = 50;
    std::vector<std::chrono::nanoseconds> pattern_times;
    std::vector<std::chrono::nanoseconds> random_times;
    
    // Test with pattern data
    for (size_t i = 0; i < iterations; ++i) {
        std::vector<uint8_t> pattern_data(128, static_cast<uint8_t>(i % 4));
        
        auto start = std::chrono::high_resolution_clock::now();
        std::hash<std::string> hasher;
        std::string data_str(pattern_data.begin(), pattern_data.end());
        volatile size_t hash_result = hasher(data_str);
        (void)hash_result;
        auto end = std::chrono::high_resolution_clock::now();
        
        pattern_times.push_back(end - start);
    }
    
    // Test with random data
    for (size_t i = 0; i < iterations; ++i) {
        auto random_data = generate_random_data(128);
        
        auto start = std::chrono::high_resolution_clock::now();
        std::hash<std::string> hasher;
        std::string data_str(random_data.begin(), random_data.end());
        volatile size_t hash_result = hasher(data_str);
        (void)hash_result;
        auto end = std::chrono::high_resolution_clock::now();
        
        random_times.push_back(end - start);
    }
    
    double pattern_cv = calculate_coefficient_of_variation(pattern_times);
    double random_cv = calculate_coefficient_of_variation(random_times);
    
    // Hash timing should be consistent regardless of input patterns
    EXPECT_LT(pattern_cv, 0.3) << "Pattern hash timing varies too much: " << pattern_cv;
    EXPECT_LT(random_cv, 0.3) << "Random hash timing varies too much: " << random_cv;
    
    std::cout << "Hash Computation Timing Analysis:\n";
    std::cout << "  Pattern data CV: " << pattern_cv << "\n";
    std::cout << "  Random data CV: " << random_cv << "\n";
}

} // namespace dtls::v13::test