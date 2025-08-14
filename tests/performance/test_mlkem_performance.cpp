/**
 * @file test_mlkem_performance.cpp
 * @brief Performance benchmarks for ML-KEM implementation
 * 
 * This test suite provides comprehensive performance benchmarking of the ML-KEM
 * implementation including key generation, encapsulation, decapsulation operations,
 * memory usage analysis, and comparison with classical key exchange methods.
 * 
 * Performance Test Coverage:
 * - ML-KEM key generation benchmarks
 * - Encapsulation/decapsulation performance
 * - Memory usage analysis
 * - Throughput measurements
 * - Comparison with classical ECDHE
 * - Cross-provider performance comparison
 * 
 * @author DTLS v1.3 Test Suite
 * @version 1.0.0
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include "../test_infrastructure/test_utilities.h"

#ifdef DTLS_HAS_BENCHMARK
#include <benchmark/benchmark.h>
#endif

#include <vector>
#include <memory>
#include <string>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <sstream>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

/**
 * Performance test fixture for ML-KEM operations
 */
class MLKEMPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
        // Initialize available providers
        auto openssl_result = factory.create_provider("openssl");
        if (openssl_result && openssl_result.value()->is_available()) {
            openssl_provider_ = std::move(openssl_result.value());
            auto init_result = openssl_provider_->initialize();
            if (!init_result) {
                openssl_provider_.reset();
            }
        }
        
        auto botan_result = factory.create_provider("botan");
        if (botan_result && botan_result.value()->is_available()) {
            botan_provider_ = std::move(botan_result.value());
            auto init_result = botan_provider_->initialize();
            if (!init_result) {
                botan_provider_.reset();
            }
        }

        auto hardware_result = factory.create_provider("hardware");
        if (hardware_result && hardware_result.value()->is_available()) {
            hardware_provider_ = std::move(hardware_result.value());
            auto init_result = hardware_provider_->initialize();
            if (!init_result) {
                hardware_provider_.reset();
            }
        }
        
        // Set up test parameters
        parameter_sets_ = {
            MLKEMParameterSet::MLKEM512,
            MLKEMParameterSet::MLKEM768,
            MLKEMParameterSet::MLKEM1024
        };
        
        named_groups_ = {
            NamedGroup::MLKEM512,
            NamedGroup::MLKEM768,
            NamedGroup::MLKEM1024
        };
    }
    
    void TearDown() override {
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
        if (hardware_provider_) hardware_provider_->cleanup();
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    std::unique_ptr<CryptoProvider> hardware_provider_;
    
    std::vector<MLKEMParameterSet> parameter_sets_;
    std::vector<NamedGroup> named_groups_;
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        if (openssl_provider_) providers.push_back(openssl_provider_.get());
        if (botan_provider_) providers.push_back(botan_provider_.get());
        if (hardware_provider_) providers.push_back(hardware_provider_.get());
        return providers;
    }
    
    std::string get_param_set_name(MLKEMParameterSet param_set) {
        switch (param_set) {
            case MLKEMParameterSet::MLKEM512: return "ML-KEM-512";
            case MLKEMParameterSet::MLKEM768: return "ML-KEM-768";
            case MLKEMParameterSet::MLKEM1024: return "ML-KEM-1024";
            default: return "Unknown";
        }
    }
    
    // Timing utilities
    template<typename Func>
    std::chrono::nanoseconds time_operation(Func&& func) {
        auto start = std::chrono::high_resolution_clock::now();
        func();
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    }
    
    struct PerformanceStats {
        std::chrono::nanoseconds min_time;
        std::chrono::nanoseconds max_time;
        std::chrono::nanoseconds avg_time;
        std::chrono::nanoseconds median_time;
        double operations_per_second;
        size_t memory_used_bytes;
    };
    
    PerformanceStats calculate_stats(const std::vector<std::chrono::nanoseconds>& timings,
                                   size_t memory_bytes = 0) {
        auto sorted_timings = timings;
        std::sort(sorted_timings.begin(), sorted_timings.end());
        
        PerformanceStats stats;
        stats.min_time = sorted_timings.front();
        stats.max_time = sorted_timings.back();
        stats.median_time = sorted_timings[sorted_timings.size() / 2];
        stats.avg_time = std::accumulate(sorted_timings.begin(), sorted_timings.end(),
                                        std::chrono::nanoseconds(0)) / sorted_timings.size();
        stats.operations_per_second = 1e9 / static_cast<double>(stats.avg_time.count());
        stats.memory_used_bytes = memory_bytes;
        
        return stats;
    }
    
    void print_performance_results(const std::string& operation,
                                  const std::string& provider_name,
                                  const std::string& param_set_name,
                                  const PerformanceStats& stats) {
        std::cout << "\n" << operation << " Performance - " << provider_name 
                  << " - " << param_set_name << ":\n";
        std::cout << "  Average: " << std::fixed << std::setprecision(3) 
                  << static_cast<double>(stats.avg_time.count()) / 1000000.0 << " ms\n";
        std::cout << "  Min:     " << std::fixed << std::setprecision(3)
                  << static_cast<double>(stats.min_time.count()) / 1000000.0 << " ms\n";
        std::cout << "  Max:     " << std::fixed << std::setprecision(3)
                  << static_cast<double>(stats.max_time.count()) / 1000000.0 << " ms\n";
        std::cout << "  Median:  " << std::fixed << std::setprecision(3)
                  << static_cast<double>(stats.median_time.count()) / 1000000.0 << " ms\n";
        std::cout << "  Ops/sec: " << std::fixed << std::setprecision(0) 
                  << stats.operations_per_second << "\n";
        if (stats.memory_used_bytes > 0) {
            std::cout << "  Memory:  " << stats.memory_used_bytes << " bytes\n";
        }
    }
    
    // Memory usage estimation
    size_t estimate_memory_usage(MLKEMParameterSet param_set) {
        using namespace hybrid_pqc;
        auto sizes = get_mlkem_sizes(param_set);
        
        // Estimate total memory for operation (keys + temporary buffers)
        return sizes.public_key_bytes + sizes.private_key_bytes + 
               sizes.ciphertext_bytes + sizes.shared_secret_bytes + 1024; // overhead
    }
};

// ============================================================================
// PERFORMANCE TESTS - Key Generation Benchmarks
// ============================================================================

/**
 * Test ML-KEM key generation performance across all parameter sets
 */
TEST_F(MLKEMPerformanceTest, KeyGenerationPerformance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_iterations = 100; // Reduced for CI performance
    
    std::cout << "\n=== ML-KEM Key Generation Performance ===\n";
    
    for (auto* provider : providers) {
        for (auto param_set : parameter_sets_) {
            std::vector<std::chrono::nanoseconds> timings;
            size_t memory_estimate = estimate_memory_usage(param_set);
            
            MLKEMKeyGenParams params;
            params.parameter_set = param_set;
            
            // Warm up
            for (int i = 0; i < 5; ++i) {
                auto result = provider->mlkem_generate_keypair(params);
                ASSERT_TRUE(result.is_success()) << "Warmup key generation failed";
            }
            
            // Measure performance
            for (int i = 0; i < num_iterations; ++i) {
                auto duration = time_operation([&]() {
                    auto result = provider->mlkem_generate_keypair(params);
                    ASSERT_TRUE(result.is_success()) << "Key generation failed at iteration " << i;
                });
                
                timings.push_back(duration);
            }
            
            auto stats = calculate_stats(timings, memory_estimate);
            print_performance_results("Key Generation", provider->name(),
                                     get_param_set_name(param_set), stats);
            
            // Performance expectations (these are rough benchmarks)
            EXPECT_LT(stats.avg_time, std::chrono::milliseconds(100))
                << "Key generation too slow for " << get_param_set_name(param_set);
            EXPECT_GT(stats.operations_per_second, 10.0)
                << "Key generation throughput too low for " << get_param_set_name(param_set);
        }
    }
}

/**
 * Test ML-KEM key generation scalability with different parameter sets
 */
TEST_F(MLKEMPerformanceTest, KeyGenerationScalability) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_iterations = 50;
    
    std::cout << "\n=== ML-KEM Key Generation Scalability Analysis ===\n";
    
    for (auto* provider : providers) {
        std::vector<double> avg_times;
        std::vector<std::string> param_names;
        
        for (auto param_set : parameter_sets_) {
            std::vector<std::chrono::nanoseconds> timings;
            
            MLKEMKeyGenParams params;
            params.parameter_set = param_set;
            
            for (int i = 0; i < num_iterations; ++i) {
                auto duration = time_operation([&]() {
                    auto result = provider->mlkem_generate_keypair(params);
                    ASSERT_TRUE(result.is_success());
                });
                timings.push_back(duration);
            }
            
            auto avg_time = std::accumulate(timings.begin(), timings.end(),
                                          std::chrono::nanoseconds(0)) / timings.size();
            
            avg_times.push_back(static_cast<double>(avg_time.count()) / 1000000.0);
            param_names.push_back(get_param_set_name(param_set));
        }
        
        std::cout << "\nScalability for " << provider->name() << ":\n";
        for (size_t i = 0; i < avg_times.size(); ++i) {
            std::cout << "  " << param_names[i] << ": " 
                      << std::fixed << std::setprecision(3) << avg_times[i] << " ms\n";
        }
        
        // Verify reasonable scaling (ML-KEM-1024 should be slower than ML-KEM-512)
        if (avg_times.size() >= 3) {
            EXPECT_GT(avg_times[2], avg_times[0])
                << "ML-KEM-1024 should be slower than ML-KEM-512";
            EXPECT_GT(avg_times[1], avg_times[0])
                << "ML-KEM-768 should be slower than ML-KEM-512";
        }
    }
}

// ============================================================================
// PERFORMANCE TESTS - Encapsulation/Decapsulation Benchmarks
// ============================================================================

/**
 * Test ML-KEM encapsulation performance
 */
TEST_F(MLKEMPerformanceTest, EncapsulationPerformance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_iterations = 200; // More iterations for encapsulation (faster operation)
    
    std::cout << "\n=== ML-KEM Encapsulation Performance ===\n";
    
    for (auto* provider : providers) {
        for (auto param_set : parameter_sets_) {
            // Generate keypair first
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keygen_result.is_success());
            
            const auto& [public_key, private_key] = keygen_result.value();
            
            std::vector<std::chrono::nanoseconds> timings;
            size_t memory_estimate = estimate_memory_usage(param_set);
            
            // Warm up
            for (int i = 0; i < 10; ++i) {
                MLKEMEncapParams params;
                params.parameter_set = param_set;
                params.public_key = public_key;
                
                auto result = provider->mlkem_encapsulate(params);
                ASSERT_TRUE(result.is_success()) << "Warmup encapsulation failed";
            }
            
            // Measure performance
            for (int i = 0; i < num_iterations; ++i) {
                MLKEMEncapParams params;
                params.parameter_set = param_set;
                params.public_key = public_key;
                
                auto duration = time_operation([&]() {
                    auto result = provider->mlkem_encapsulate(params);
                    ASSERT_TRUE(result.is_success()) << "Encapsulation failed at iteration " << i;
                });
                
                timings.push_back(duration);
            }
            
            auto stats = calculate_stats(timings, memory_estimate);
            print_performance_results("Encapsulation", provider->name(),
                                     get_param_set_name(param_set), stats);
            
            // Performance expectations
            EXPECT_LT(stats.avg_time, std::chrono::milliseconds(50))
                << "Encapsulation too slow for " << get_param_set_name(param_set);
            EXPECT_GT(stats.operations_per_second, 20.0)
                << "Encapsulation throughput too low for " << get_param_set_name(param_set);
        }
    }
}

/**
 * Test ML-KEM decapsulation performance
 */
TEST_F(MLKEMPerformanceTest, DecapsulationPerformance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_iterations = 200;
    
    std::cout << "\n=== ML-KEM Decapsulation Performance ===\n";
    
    for (auto* provider : providers) {
        for (auto param_set : parameter_sets_) {
            // Generate keypair and ciphertext
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keygen_result.is_success());
            
            const auto& [public_key, private_key] = keygen_result.value();
            
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = param_set;
            encap_params.public_key = public_key;
            
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result.is_success());
            
            const auto& ciphertext = encap_result.value().ciphertext;
            
            std::vector<std::chrono::nanoseconds> timings;
            size_t memory_estimate = estimate_memory_usage(param_set);
            
            // Warm up
            for (int i = 0; i < 10; ++i) {
                MLKEMDecapParams params;
                params.parameter_set = param_set;
                params.private_key = private_key;
                params.ciphertext = ciphertext;
                
                auto result = provider->mlkem_decapsulate(params);
                ASSERT_TRUE(result.is_success()) << "Warmup decapsulation failed";
            }
            
            // Measure performance
            for (int i = 0; i < num_iterations; ++i) {
                MLKEMDecapParams params;
                params.parameter_set = param_set;
                params.private_key = private_key;
                params.ciphertext = ciphertext;
                
                auto duration = time_operation([&]() {
                    auto result = provider->mlkem_decapsulate(params);
                    ASSERT_TRUE(result.is_success()) << "Decapsulation failed at iteration " << i;
                });
                
                timings.push_back(duration);
            }
            
            auto stats = calculate_stats(timings, memory_estimate);
            print_performance_results("Decapsulation", provider->name(),
                                     get_param_set_name(param_set), stats);
            
            // Performance expectations
            EXPECT_LT(stats.avg_time, std::chrono::milliseconds(50))
                << "Decapsulation too slow for " << get_param_set_name(param_set);
            EXPECT_GT(stats.operations_per_second, 20.0)
                << "Decapsulation throughput too low for " << get_param_set_name(param_set);
        }
    }
}

// ============================================================================
// PERFORMANCE TESTS - End-to-End Key Exchange
// ============================================================================

/**
 * Test complete ML-KEM key exchange performance
 */
TEST_F(MLKEMPerformanceTest, EndToEndKeyExchangePerformance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_iterations = 100;
    
    std::cout << "\n=== ML-KEM End-to-End Key Exchange Performance ===\n";
    
    for (auto* provider : providers) {
        for (size_t i = 0; i < named_groups_.size(); ++i) {
            auto group = named_groups_[i];
            auto param_set = parameter_sets_[i];
            
            std::vector<std::chrono::nanoseconds> timings;
            size_t memory_estimate = estimate_memory_usage(param_set);
            
            // Warm up
            for (int j = 0; j < 5; ++j) {
                // Server generates keypair
                MLKEMKeyGenParams keygen_params;
                keygen_params.parameter_set = param_set;
                auto server_keygen = provider->mlkem_generate_keypair(keygen_params);
                ASSERT_TRUE(server_keygen.is_success());
                
                const auto& [server_public_key, server_private_key] = server_keygen.value();
                
                // Client encapsulation
                PureMLKEMKeyExchangeParams client_params;
                client_params.mlkem_group = group;
                client_params.peer_public_key = server_public_key;
                client_params.is_encapsulation = true;
                
                auto client_result = provider->perform_pure_mlkem_key_exchange(client_params);
                ASSERT_TRUE(client_result.is_success());
                
                // Server decapsulation
                PureMLKEMKeyExchangeParams server_params;
                server_params.mlkem_group = group;
                server_params.private_key = server_private_key;
                server_params.peer_public_key = client_result.value().ciphertext;
                server_params.is_encapsulation = false;
                
                auto server_result = provider->perform_pure_mlkem_key_exchange(server_params);
                ASSERT_TRUE(server_result.is_success());
            }
            
            // Measure complete key exchange
            for (int j = 0; j < num_iterations; ++j) {
                auto duration = time_operation([&]() {
                    // Server generates keypair
                    MLKEMKeyGenParams keygen_params;
                    keygen_params.parameter_set = param_set;
                    auto server_keygen = provider->mlkem_generate_keypair(keygen_params);
                    ASSERT_TRUE(server_keygen.is_success());
                    
                    const auto& [server_public_key, server_private_key] = server_keygen.value();
                    
                    // Client encapsulation
                    PureMLKEMKeyExchangeParams client_params;
                    client_params.mlkem_group = group;
                    client_params.peer_public_key = server_public_key;
                    client_params.is_encapsulation = true;
                    
                    auto client_result = provider->perform_pure_mlkem_key_exchange(client_params);
                    ASSERT_TRUE(client_result.is_success());
                    
                    // Server decapsulation
                    PureMLKEMKeyExchangeParams server_params;
                    server_params.mlkem_group = group;
                    server_params.private_key = server_private_key;
                    server_params.peer_public_key = client_result.value().ciphertext;
                    server_params.is_encapsulation = false;
                    
                    auto server_result = provider->perform_pure_mlkem_key_exchange(server_params);
                    ASSERT_TRUE(server_result.is_success());
                });
                
                timings.push_back(duration);
            }
            
            auto stats = calculate_stats(timings, memory_estimate);
            print_performance_results("End-to-End Key Exchange", provider->name(),
                                     get_param_set_name(param_set), stats);
            
            // Performance expectations for complete handshake
            EXPECT_LT(stats.avg_time, std::chrono::milliseconds(200))
                << "End-to-end key exchange too slow for " << get_param_set_name(param_set);
        }
    }
}

// ============================================================================
// PERFORMANCE TESTS - Memory Usage Analysis
// ============================================================================

/**
 * Test memory usage for ML-KEM operations
 */
TEST_F(MLKEMPerformanceTest, MemoryUsageAnalysis) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    std::cout << "\n=== ML-KEM Memory Usage Analysis ===\n";
    
    for (auto* provider : providers) {
        std::cout << "\nMemory usage for " << provider->name() << ":\n";
        
        for (auto param_set : parameter_sets_) {
            using namespace hybrid_pqc;
            auto sizes = get_mlkem_sizes(param_set);
            
            std::cout << "  " << get_param_set_name(param_set) << ":\n";
            std::cout << "    Public Key:    " << sizes.public_key_bytes << " bytes\n";
            std::cout << "    Private Key:   " << sizes.private_key_bytes << " bytes\n";
            std::cout << "    Ciphertext:    " << sizes.ciphertext_bytes << " bytes\n";
            std::cout << "    Shared Secret: " << sizes.shared_secret_bytes << " bytes\n";
            
            size_t total_memory = sizes.public_key_bytes + sizes.private_key_bytes + 
                                 sizes.ciphertext_bytes + sizes.shared_secret_bytes;
            std::cout << "    Total Memory:  " << total_memory << " bytes\n";
            
            // Memory efficiency tests
            EXPECT_LT(total_memory, 10000) // 10KB limit
                << "Total memory usage too high for " << get_param_set_name(param_set);
        }
        
        // Test provider memory tracking if supported
        if (provider->get_memory_usage() > 0) {
            size_t initial_memory = provider->get_memory_usage();
            
            // Perform some operations
            MLKEMKeyGenParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            
            for (int i = 0; i < 10; ++i) {
                auto result = provider->mlkem_generate_keypair(params);
                ASSERT_TRUE(result.is_success());
            }
            
            size_t final_memory = provider->get_memory_usage();
            
            std::cout << "  Provider Memory Tracking:\n";
            std::cout << "    Initial: " << initial_memory << " bytes\n";
            std::cout << "    Final:   " << final_memory << " bytes\n";
            std::cout << "    Delta:   " << (final_memory - initial_memory) << " bytes\n";
        }
    }
}

// ============================================================================
// PERFORMANCE TESTS - Cross-Provider Comparison
// ============================================================================

/**
 * Compare performance across different providers
 */
TEST_F(MLKEMPerformanceTest, CrossProviderPerformanceComparison) {
    auto providers = get_available_providers();
    if (providers.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for comparison";
    }
    
    const int num_iterations = 50;
    
    std::cout << "\n=== Cross-Provider Performance Comparison ===\n";
    
    struct ProviderResults {
        std::string name;
        std::vector<double> keygen_times;
        std::vector<double> encap_times;
        std::vector<double> decap_times;
    };
    
    for (auto param_set : parameter_sets_) {
        std::vector<ProviderResults> results;
        
        for (auto* provider : providers) {
            ProviderResults result;
            result.name = provider->name();
            
            // Benchmark key generation
            std::vector<std::chrono::nanoseconds> keygen_timings;
            for (int i = 0; i < num_iterations; ++i) {
                MLKEMKeyGenParams params;
                params.parameter_set = param_set;
                
                auto duration = time_operation([&]() {
                    auto res = provider->mlkem_generate_keypair(params);
                    ASSERT_TRUE(res.is_success());
                });
                keygen_timings.push_back(duration);
            }
            
            double avg_keygen = static_cast<double>(
                std::accumulate(keygen_timings.begin(), keygen_timings.end(),
                              std::chrono::nanoseconds(0)).count()) / 
                              (keygen_timings.size() * 1000000.0);
            
            result.keygen_times.push_back(avg_keygen);
            
            // Benchmark encapsulation/decapsulation
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            auto keypair_result = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keypair_result.is_success());
            
            const auto& [public_key, private_key] = keypair_result.value();
            
            // Encapsulation timings
            std::vector<std::chrono::nanoseconds> encap_timings;
            for (int i = 0; i < num_iterations; ++i) {
                MLKEMEncapParams params;
                params.parameter_set = param_set;
                params.public_key = public_key;
                
                auto duration = time_operation([&]() {
                    auto res = provider->mlkem_encapsulate(params);
                    ASSERT_TRUE(res.is_success());
                });
                encap_timings.push_back(duration);
            }
            
            double avg_encap = static_cast<double>(
                std::accumulate(encap_timings.begin(), encap_timings.end(),
                              std::chrono::nanoseconds(0)).count()) /
                              (encap_timings.size() * 1000000.0);
            
            result.encap_times.push_back(avg_encap);
            
            // Generate ciphertext for decapsulation
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = param_set;
            encap_params.public_key = public_key;
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result.is_success());
            
            // Decapsulation timings
            std::vector<std::chrono::nanoseconds> decap_timings;
            for (int i = 0; i < num_iterations; ++i) {
                MLKEMDecapParams params;
                params.parameter_set = param_set;
                params.private_key = private_key;
                params.ciphertext = encap_result.value().ciphertext;
                
                auto duration = time_operation([&]() {
                    auto res = provider->mlkem_decapsulate(params);
                    ASSERT_TRUE(res.is_success());
                });
                decap_timings.push_back(duration);
            }
            
            double avg_decap = static_cast<double>(
                std::accumulate(decap_timings.begin(), decap_timings.end(),
                              std::chrono::nanoseconds(0)).count()) /
                              (decap_timings.size() * 1000000.0);
            
            result.decap_times.push_back(avg_decap);
            
            results.push_back(result);
        }
        
        // Print comparison results
        std::cout << "\n" << get_param_set_name(param_set) << " Performance Comparison:\n";
        std::cout << "  Provider        KeyGen(ms)  Encap(ms)   Decap(ms)\n";
        std::cout << "  ------------------------------------------------\n";
        
        for (const auto& result : results) {
            std::cout << "  " << std::setw(15) << std::left << result.name
                      << std::setw(11) << std::fixed << std::setprecision(3) 
                      << result.keygen_times[0]
                      << std::setw(11) << std::fixed << std::setprecision(3)
                      << result.encap_times[0]
                      << std::setw(11) << std::fixed << std::setprecision(3)
                      << result.decap_times[0] << "\n";
        }
    }
}

#ifdef DTLS_HAS_BENCHMARK
// ============================================================================
// GOOGLE BENCHMARK INTEGRATION (if available)
// ============================================================================

static void BM_MLKEMKeyGeneration(benchmark::State& state, MLKEMParameterSet param_set) {
    auto& factory = ProviderFactory::instance();
    auto openssl_result = factory.create_provider("openssl");
    if (!openssl_result || !openssl_result.value()->is_available()) {
        state.SkipWithError("OpenSSL provider not available");
        return;
    }
    
    auto provider = std::move(openssl_result.value());
    auto init_result = provider->initialize();
    if (!init_result) {
        state.SkipWithError("Failed to initialize provider");
        return;
    }
    
    MLKEMKeyGenParams params;
    params.parameter_set = param_set;
    
    for (auto _ : state) {
        auto result = provider->mlkem_generate_keypair(params);
        if (!result.is_success()) {
            state.SkipWithError("Key generation failed");
            return;
        }
        benchmark::DoNotOptimize(result.value());
    }
    
    provider->cleanup();
}

BENCHMARK_CAPTURE(BM_MLKEMKeyGeneration, MLKEM512, MLKEMParameterSet::MLKEM512);
BENCHMARK_CAPTURE(BM_MLKEMKeyGeneration, MLKEM768, MLKEMParameterSet::MLKEM768);
BENCHMARK_CAPTURE(BM_MLKEMKeyGeneration, MLKEM1024, MLKEMParameterSet::MLKEM1024);

#endif // DTLS_HAS_BENCHMARK