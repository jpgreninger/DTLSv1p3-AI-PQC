/**
 * @file test_hybrid_pqc_performance.cpp
 * @brief Performance benchmarks for hybrid PQC implementation
 * 
 * Comprehensive performance testing of ML-KEM operations vs classical ECDHE,
 * memory usage analysis, handshake latency measurements, and throughput analysis
 * for hybrid post-quantum cryptography in DTLS v1.3.
 */

#include <gtest/gtest.h>
#include "benchmark_framework.h"
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <vector>
#include <memory>
#include <string>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <numeric>

#ifdef DTLS_HAS_BENCHMARK
#include <benchmark/benchmark.h>
#endif

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class HybridPQCPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
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
    }
    
    void TearDown() override {
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
        if (hardware_provider_) hardware_provider_->cleanup();
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    std::unique_ptr<CryptoProvider> hardware_provider_;
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        if (openssl_provider_) providers.push_back(openssl_provider_.get());
        if (botan_provider_) providers.push_back(botan_provider_.get());
        if (hardware_provider_) providers.push_back(hardware_provider_.get());
        return providers;
    }
    
    // Performance measurement structure
    struct PerformanceMetrics {
        std::chrono::microseconds min_time{0};
        std::chrono::microseconds max_time{0};
        std::chrono::microseconds avg_time{0};
        std::chrono::microseconds median_time{0};
        double operations_per_second = 0.0;
        size_t memory_usage_bytes = 0;
        size_t iterations = 0;
    };
    
    // Measure operation performance with multiple iterations
    template<typename Operation>
    PerformanceMetrics measure_operation(Operation op, size_t iterations = 100) {
        std::vector<std::chrono::microseconds> times;
        times.reserve(iterations);
        
        size_t memory_before = get_memory_usage();
        
        for (size_t i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            bool success = op();
            auto end = std::chrono::high_resolution_clock::now();
            
            if (success) {
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                times.push_back(duration);
            }
        }
        
        size_t memory_after = get_memory_usage();
        
        if (times.empty()) {
            return PerformanceMetrics{};
        }
        
        std::sort(times.begin(), times.end());
        
        PerformanceMetrics metrics;
        metrics.iterations = times.size();
        metrics.min_time = times.front();
        metrics.max_time = times.back();
        metrics.median_time = times[times.size() / 2];
        
        auto total_time = std::accumulate(times.begin(), times.end(), std::chrono::microseconds(0));
        metrics.avg_time = total_time / times.size();
        
        if (metrics.avg_time.count() > 0) {
            metrics.operations_per_second = 1000000.0 / metrics.avg_time.count();
        }
        
        metrics.memory_usage_bytes = memory_after - memory_before;
        
        return metrics;
    }
    
    // Simple memory usage estimation (placeholder)
    size_t get_memory_usage() const {
        // In a real implementation, this would use platform-specific memory measurement
        return 0; // Placeholder
    }
    
    void print_performance_comparison(const std::string& operation,
                                    const std::string& classical_name,
                                    const PerformanceMetrics& classical,
                                    const std::string& hybrid_name,
                                    const PerformanceMetrics& hybrid) {
        std::cout << "\n=== " << operation << " Performance Comparison ===" << std::endl;
        std::cout << std::fixed << std::setprecision(2);
        
        std::cout << classical_name << ":" << std::endl;
        std::cout << "  Average: " << classical.avg_time.count() << " µs" << std::endl;
        std::cout << "  Range: " << classical.min_time.count() << " - " 
                  << classical.max_time.count() << " µs" << std::endl;
        std::cout << "  Throughput: " << classical.operations_per_second << " ops/sec" << std::endl;
        
        std::cout << hybrid_name << ":" << std::endl;
        std::cout << "  Average: " << hybrid.avg_time.count() << " µs" << std::endl;
        std::cout << "  Range: " << hybrid.min_time.count() << " - " 
                  << hybrid.max_time.count() << " µs" << std::endl;
        std::cout << "  Throughput: " << hybrid.operations_per_second << " ops/sec" << std::endl;
        
        if (classical.avg_time.count() > 0) {
            double overhead = (static_cast<double>(hybrid.avg_time.count()) / 
                             classical.avg_time.count() - 1.0) * 100.0;
            std::cout << "Hybrid overhead: " << overhead << "%" << std::endl;
        }
        
        std::cout << std::endl;
    }
};

// Benchmark ML-KEM key generation vs classical ECDHE
TEST_F(HybridPQCPerformanceTest, KeyGenerationPerformance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const size_t iterations = 50;
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Benchmark classical ECDHE key generation
        auto classical_metrics = measure_operation([provider]() {
            auto result = provider->generate_key_pair(NamedGroup::SECP256R1);
            return result.is_success();
        }, iterations);
        
        // Benchmark ML-KEM-512 key generation
        auto mlkem512_metrics = measure_operation([provider]() {
            MLKEMKeyGenParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            auto result = provider->mlkem_generate_keypair(params);
            return result.is_success();
        }, iterations);
        
        // Benchmark ML-KEM-768 key generation
        auto mlkem768_metrics = measure_operation([provider]() {
            MLKEMKeyGenParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM768;
            auto result = provider->mlkem_generate_keypair(params);
            return result.is_success();
        }, iterations);
        
        // Benchmark ML-KEM-1024 key generation
        auto mlkem1024_metrics = measure_operation([provider]() {
            MLKEMKeyGenParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM1024;
            auto result = provider->mlkem_generate_keypair(params);
            return result.is_success();
        }, iterations);
        
        // Print results
        print_performance_comparison("Key Generation", 
                                   "ECDHE P-256", classical_metrics,
                                   "ML-KEM-512", mlkem512_metrics);
        print_performance_comparison("Key Generation", 
                                   "ECDHE P-256", classical_metrics,
                                   "ML-KEM-768", mlkem768_metrics);
        print_performance_comparison("Key Generation", 
                                   "ECDHE P-256", classical_metrics,
                                   "ML-KEM-1024", mlkem1024_metrics);
    }
}

// Benchmark ML-KEM encapsulation vs classical ECDHE key exchange
TEST_F(HybridPQCPerformanceTest, EncapsulationPerformance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const size_t iterations = 50;
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Pre-generate keys for testing
        auto classical_keypair = provider->generate_key_pair(NamedGroup::SECP256R1);
        ASSERT_TRUE(classical_keypair);
        
        MLKEMKeyGenParams mlkem_params;
        mlkem_params.parameter_set = MLKEMParameterSet::MLKEM512;
        auto mlkem_keypair = provider->mlkem_generate_keypair(mlkem_params);
        ASSERT_TRUE(mlkem_keypair);
        auto [mlkem_pubkey, mlkem_privkey] = mlkem_keypair.value();
        
        // Benchmark classical ECDHE (simulate key exchange)
        auto classical_metrics = measure_operation([provider, &classical_keypair]() {
            KeyExchangeParams params;
            params.group = NamedGroup::SECP256R1;
            params.peer_public_key = std::vector<uint8_t>(65, 0x42); // Placeholder peer key
            params.private_key = classical_keypair.value().first.get();
            auto result = provider->perform_key_exchange(params);
            return result.is_success();
        }, iterations);
        
        // Benchmark ML-KEM encapsulation
        auto mlkem_metrics = measure_operation([provider, &mlkem_pubkey]() {
            MLKEMEncapParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            params.public_key = mlkem_pubkey;
            auto result = provider->mlkem_encapsulate(params);
            return result.is_success();
        }, iterations);
        
        print_performance_comparison("Key Exchange/Encapsulation",
                                   "ECDHE P-256", classical_metrics,
                                   "ML-KEM-512", mlkem_metrics);
    }
}

// Benchmark hybrid key exchange complete operation
TEST_F(HybridPQCPerformanceTest, HybridKeyExchangePerformance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const size_t iterations = 20; // Fewer iterations for complex operation
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Benchmark complete hybrid key exchange simulation
        auto hybrid_metrics = measure_operation([provider]() {
            try {
                // Generate server keypairs
                auto server_classical = provider->generate_key_pair(NamedGroup::SECP256R1);
                if (!server_classical) return false;
                
                MLKEMKeyGenParams mlkem_params;
                mlkem_params.parameter_set = MLKEMParameterSet::MLKEM512;
                auto server_mlkem = provider->mlkem_generate_keypair(mlkem_params);
                if (!server_mlkem) return false;
                auto [server_pq_pub, server_pq_priv] = server_mlkem.value();
                
                // Client generates keypair and performs encapsulation
                auto client_classical = provider->generate_key_pair(NamedGroup::SECP256R1);
                if (!client_classical) return false;
                
                MLKEMEncapParams encap_params;
                encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
                encap_params.public_key = server_pq_pub;
                auto encap_result = provider->mlkem_encapsulate(encap_params);
                if (!encap_result) return false;
                
                // Server performs decapsulation
                MLKEMDecapParams decap_params;
                decap_params.parameter_set = MLKEMParameterSet::MLKEM512;
                decap_params.private_key = server_pq_priv;
                decap_params.ciphertext = encap_result.value().ciphertext;
                auto decap_result = provider->mlkem_decapsulate(decap_params);
                if (!decap_result) return false;
                
                // Combine shared secrets using HKDF
                KeyDerivationParams hkdf_params;
                hkdf_params.secret.insert(hkdf_params.secret.end(),
                                         encap_result.value().shared_secret.begin(),
                                         encap_result.value().shared_secret.end());
                hkdf_params.secret.insert(hkdf_params.secret.end(),
                                         decap_result.value().begin(),
                                         decap_result.value().end());
                hkdf_params.salt.clear();
                hkdf_params.info = std::vector<uint8_t>{'h', 'y', 'b', 'r', 'i', 'd'};
                hkdf_params.output_length = 32;
                hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
                
                auto combined = provider->derive_key_hkdf(hkdf_params);
                return combined.is_success();
                
            } catch (...) {
                return false;
            }
        }, iterations);
        
        // Benchmark classical-only key exchange
        auto classical_metrics = measure_operation([provider]() {
            try {
                auto server_keypair = provider->generate_key_pair(NamedGroup::SECP256R1);
                if (!server_keypair) return false;
                
                auto client_keypair = provider->generate_key_pair(NamedGroup::SECP256R1);
                if (!client_keypair) return false;
                
                // Simulate key exchange (in real scenario, would use actual peer keys)
                KeyExchangeParams params;
                params.group = NamedGroup::SECP256R1;
                params.peer_public_key = std::vector<uint8_t>(65, 0x42);
                params.private_key = client_keypair.value().first.get();
                auto result = provider->perform_key_exchange(params);
                return result.is_success();
                
            } catch (...) {
                return false;
            }
        }, iterations);
        
        print_performance_comparison("Complete Key Exchange",
                                   "Classical ECDHE", classical_metrics,
                                   "Hybrid PQC", hybrid_metrics);
    }
}

// Benchmark memory usage and data sizes
TEST_F(HybridPQCPerformanceTest, MemoryUsageAnalysis) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        std::cout << "\n=== Memory Usage Analysis - " << provider->name() << " ===" << std::endl;
        
        // Classical ECDHE key sizes
        auto classical_keypair = provider->generate_key_pair(NamedGroup::SECP256R1);
        if (classical_keypair) {
            // Note: Actual key size measurement would require provider-specific APIs
            std::cout << "Classical ECDHE P-256:" << std::endl;
            std::cout << "  Public key: ~65 bytes (uncompressed)" << std::endl;
            std::cout << "  Private key: ~32 bytes" << std::endl;
            std::cout << "  Shared secret: ~32 bytes" << std::endl;
        }
        
        // ML-KEM key sizes
        std::vector<MLKEMParameterSet> param_sets = {
            MLKEMParameterSet::MLKEM512,
            MLKEMParameterSet::MLKEM768,
            MLKEMParameterSet::MLKEM1024
        };
        
        for (auto param_set : param_sets) {
            auto sizes = hybrid_pqc::get_mlkem_sizes(param_set);
            std::string name = (param_set == MLKEMParameterSet::MLKEM512) ? "ML-KEM-512" :
                              (param_set == MLKEMParameterSet::MLKEM768) ? "ML-KEM-768" : "ML-KEM-1024";
            
            std::cout << name << ":" << std::endl;
            std::cout << "  Public key: " << sizes.public_key_bytes << " bytes" << std::endl;
            std::cout << "  Private key: " << sizes.private_key_bytes << " bytes" << std::endl;
            std::cout << "  Ciphertext: " << sizes.ciphertext_bytes << " bytes" << std::endl;
            std::cout << "  Shared secret: " << sizes.shared_secret_bytes << " bytes" << std::endl;
        }
        
        // Hybrid group sizes
        std::vector<NamedGroup> hybrid_groups = {
            NamedGroup::ECDHE_P256_MLKEM512,
            NamedGroup::ECDHE_P384_MLKEM768,
            NamedGroup::ECDHE_P521_MLKEM1024
        };
        
        std::cout << "\nHybrid Key Share Sizes:" << std::endl;
        for (auto group : hybrid_groups) {
            std::string name = (group == NamedGroup::ECDHE_P256_MLKEM512) ? "ECDHE_P256_MLKEM512" :
                              (group == NamedGroup::ECDHE_P384_MLKEM768) ? "ECDHE_P384_MLKEM768" : 
                              "ECDHE_P521_MLKEM1024";
            
            auto client_size = hybrid_pqc::get_hybrid_client_keyshare_size(group);
            auto server_size = hybrid_pqc::get_hybrid_server_keyshare_size(group);
            
            std::cout << name << ":" << std::endl;
            std::cout << "  Client KeyShare: " << client_size << " bytes" << std::endl;
            std::cout << "  Server KeyShare: " << server_size << " bytes" << std::endl;
        }
    }
}

// Benchmark handshake latency impact
TEST_F(HybridPQCPerformanceTest, HandshakeLatencyImpact) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const size_t iterations = 10;
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        std::cout << "\n=== Handshake Latency Analysis - " << provider->name() << " ===" << std::endl;
        
        // Simulate handshake operations for different groups
        std::vector<std::pair<std::string, NamedGroup>> test_groups = {
            {"SECP256R1", NamedGroup::SECP256R1},
            {"SECP384R1", NamedGroup::SECP384R1},
            {"SECP521R1", NamedGroup::SECP521R1}
        };
        
        for (auto& [name, group] : test_groups) {
            auto metrics = measure_operation([provider, group]() {
                // Simulate full handshake key generation + exchange
                auto server_keypair = provider->generate_key_pair(group);
                if (!server_keypair) return false;
                
                auto client_keypair = provider->generate_key_pair(group);
                if (!client_keypair) return false;
                
                // Simulate key exchange
                KeyExchangeParams params;
                params.group = group;
                params.peer_public_key = std::vector<uint8_t>(65, 0x42); // Placeholder
                params.private_key = client_keypair.value().first.get();
                auto result = provider->perform_key_exchange(params);
                return result.is_success();
            }, iterations);
            
            std::cout << "Classical " << name << " handshake: " 
                     << metrics.avg_time.count() << " µs average" << std::endl;
        }
        
        // Test hybrid groups
        std::vector<std::pair<std::string, NamedGroup>> hybrid_groups = {
            {"ECDHE_P256_MLKEM512", NamedGroup::ECDHE_P256_MLKEM512},
            {"ECDHE_P384_MLKEM768", NamedGroup::ECDHE_P384_MLKEM768},
            {"ECDHE_P521_MLKEM1024", NamedGroup::ECDHE_P521_MLKEM1024}
        };
        
        for (auto& [name, group] : hybrid_groups) {
            auto classical_group = hybrid_pqc::get_classical_group(group);
            auto mlkem_param_set = hybrid_pqc::get_mlkem_parameter_set(group);
            
            auto metrics = measure_operation([provider, classical_group, mlkem_param_set]() {
                // Simulate hybrid handshake
                auto server_classical = provider->generate_key_pair(classical_group);
                if (!server_classical) return false;
                
                MLKEMKeyGenParams mlkem_params;
                mlkem_params.parameter_set = mlkem_param_set;
                auto server_mlkem = provider->mlkem_generate_keypair(mlkem_params);
                if (!server_mlkem) return false;
                auto [server_pq_pub, server_pq_priv] = server_mlkem.value();
                
                auto client_classical = provider->generate_key_pair(classical_group);
                if (!client_classical) return false;
                
                MLKEMEncapParams encap_params;
                encap_params.parameter_set = mlkem_param_set;
                encap_params.public_key = server_pq_pub;
                auto encap_result = provider->mlkem_encapsulate(encap_params);
                if (!encap_result) return false;
                
                MLKEMDecapParams decap_params;
                decap_params.parameter_set = mlkem_param_set;
                decap_params.private_key = server_pq_priv;
                decap_params.ciphertext = encap_result.value().ciphertext;
                auto decap_result = provider->mlkem_decapsulate(decap_params);
                return decap_result.is_success();
            }, iterations);
            
            std::cout << "Hybrid " << name << " handshake: " 
                     << metrics.avg_time.count() << " µs average" << std::endl;
        }
    }
}

// Performance regression test
TEST_F(HybridPQCPerformanceTest, PerformanceRegression) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    // Define performance thresholds (these would be based on baseline measurements)
    const auto MAX_KEYGEN_TIME = std::chrono::milliseconds(50);
    const auto MAX_ENCAP_TIME = std::chrono::milliseconds(20);
    const auto MAX_DECAP_TIME = std::chrono::milliseconds(20);
    const auto MAX_HYBRID_HANDSHAKE_TIME = std::chrono::milliseconds(200);
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test ML-KEM-512 key generation performance
        auto start = std::chrono::high_resolution_clock::now();
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        auto keygen_result = provider->mlkem_generate_keypair(params);
        auto end = std::chrono::high_resolution_clock::now();
        
        ASSERT_TRUE(keygen_result) << "Key generation failed";
        auto keygen_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        EXPECT_LT(keygen_time, MAX_KEYGEN_TIME) 
            << "Key generation took too long: " << keygen_time.count() << "ms";
        
        auto [pubkey, privkey] = keygen_result.value();
        
        // Test encapsulation performance
        start = std::chrono::high_resolution_clock::now();
        MLKEMEncapParams encap_params;
        encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        encap_params.public_key = pubkey;
        auto encap_result = provider->mlkem_encapsulate(encap_params);
        end = std::chrono::high_resolution_clock::now();
        
        ASSERT_TRUE(encap_result) << "Encapsulation failed";
        auto encap_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        EXPECT_LT(encap_time, MAX_ENCAP_TIME) 
            << "Encapsulation took too long: " << encap_time.count() << "ms";
        
        // Test decapsulation performance
        start = std::chrono::high_resolution_clock::now();
        MLKEMDecapParams decap_params;
        decap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        decap_params.private_key = privkey;
        decap_params.ciphertext = encap_result.value().ciphertext;
        auto decap_result = provider->mlkem_decapsulate(decap_params);
        end = std::chrono::high_resolution_clock::now();
        
        ASSERT_TRUE(decap_result) << "Decapsulation failed";
        auto decap_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        EXPECT_LT(decap_time, MAX_DECAP_TIME) 
            << "Decapsulation took too long: " << decap_time.count() << "ms";
        
        std::cout << provider->name() << " performance results:" << std::endl;
        std::cout << "  Key generation: " << keygen_time.count() << "ms" << std::endl;
        std::cout << "  Encapsulation: " << encap_time.count() << "ms" << std::endl;
        std::cout << "  Decapsulation: " << decap_time.count() << "ms" << std::endl;
    }
}

#ifdef DTLS_HAS_BENCHMARK
// Google Benchmark integration for precise measurements
static void BM_MLKEMKeyGen512(benchmark::State& state) {
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_provider("openssl");
    if (!provider_result || !provider_result.value()->is_available()) {
        state.SkipWithError("OpenSSL provider not available");
        return;
    }
    auto provider = std::move(provider_result.value());
    provider->initialize();
    
    for (auto _ : state) {
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        auto result = provider->mlkem_generate_keypair(params);
        if (!result) {
            state.SkipWithError("Key generation failed");
        }
    }
    
    provider->cleanup();
}
BENCHMARK(BM_MLKEMKeyGen512);

static void BM_MLKEMEncap512(benchmark::State& state) {
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_provider("openssl");
    if (!provider_result || !provider_result.value()->is_available()) {
        state.SkipWithError("OpenSSL provider not available");
        return;
    }
    auto provider = std::move(provider_result.value());
    provider->initialize();
    
    // Pre-generate keypair
    MLKEMKeyGenParams keygen_params;
    keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
    auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
    if (!keygen_result) {
        state.SkipWithError("Key generation failed");
        return;
    }
    auto [pubkey, privkey] = keygen_result.value();
    
    for (auto _ : state) {
        MLKEMEncapParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        params.public_key = pubkey;
        auto result = provider->mlkem_encapsulate(params);
        if (!result) {
            state.SkipWithError("Encapsulation failed");
        }
    }
    
    provider->cleanup();
}
BENCHMARK(BM_MLKEMEncap512);

static void BM_ECDHEKeyGen256(benchmark::State& state) {
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_provider("openssl");
    if (!provider_result || !provider_result.value()->is_available()) {
        state.SkipWithError("OpenSSL provider not available");
        return;
    }
    auto provider = std::move(provider_result.value());
    provider->initialize();
    
    for (auto _ : state) {
        auto result = provider->generate_key_pair(NamedGroup::SECP256R1);
        if (!result) {
            state.SkipWithError("Key generation failed");
        }
    }
    
    provider->cleanup();
}
BENCHMARK(BM_ECDHEKeyGen256);
#endif // DTLS_HAS_BENCHMARK