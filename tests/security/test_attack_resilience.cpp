#include <gtest/gtest.h>
#include <dtls/security/dos_protection.h>
#include <dtls/security/rate_limiter.h>
#include <dtls/security/resource_manager.h>
#include <dtls/protocol/cookie.h>
#include <dtls/types.h>
#include <dtls/memory/buffer.h>
#include <chrono>
#include <thread>
#include <atomic>
#include <future>
#include <random>
#include <algorithm>
#include <numeric>

using namespace dtls::v13::security;
using namespace dtls::v13;
using dtls::v13::NetworkAddress;
using namespace dtls::v13::protocol;

/**
 * Comprehensive DoS Attack Resilience Test Suite
 * 
 * This test suite validates the DTLS v1.3 implementation against real-world
 * DoS attack patterns and ensures compliance with RFC 9147 security requirements.
 * 
 * Attack Categories Tested:
 * 1. Volumetric Attacks (SYN floods, UDP floods)
 * 2. Protocol-Based Attacks (malformed packets, state exhaustion)
 * 3. Resource Exhaustion Attacks (memory, connections, handshakes)
 * 4. Amplification Attacks (reflection, bandwidth amplification)
 * 5. Application Layer Attacks (slowloris, cookie poisoning)
 * 6. Distributed Attacks (multiple source simulation)
 */

class AttackResilienceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize random number generator for attack simulation
        rng_.seed(std::chrono::steady_clock::now().time_since_epoch().count());
        
        // Create production-level DoS protection
        dos_protection_ = DoSProtectionFactory::create_production();
        
        // Setup test network addresses
        setupTestAddresses();
        
        // Initialize performance metrics
        resetMetrics();
        
        // Start performance monitoring
        startPerformanceMonitoring();
    }
    
    void TearDown() override {
        stopPerformanceMonitoring();
        analyzeAttackResults();
    }
    
    void setupTestAddresses() {
        // Legitimate clients
        legitimate_clients_ = {
            NetworkAddress("192.168.1.10", 12345),
            NetworkAddress("192.168.1.11", 12346),
            NetworkAddress("192.168.1.12", 12347),
            NetworkAddress("10.0.0.10", 54321),
            NetworkAddress("172.16.1.10", 65432)
        };
        
        // Attack sources (simulating botnet)
        std::uniform_int_distribution<uint16_t> port_dist(10000, 65535);
        for (int i = 0; i < 1000; ++i) {
            std::string ip;
            if (i < 250) {
                ip = "185.220." + std::to_string(i % 256) + "." + std::to_string((i / 256) % 256);
            } else if (i < 500) {
                ip = "45.142." + std::to_string(i % 256) + "." + std::to_string((i / 256) % 256);
            } else if (i < 750) {
                ip = "104.244." + std::to_string(i % 256) + "." + std::to_string((i / 256) % 256);
            } else {
                ip = "198.98." + std::to_string(i % 256) + "." + std::to_string((i / 256) % 256);
            }
            attack_sources_.emplace_back(ip, port_dist(rng_));
        }
    }
    
    void resetMetrics() {
        attack_metrics_.total_attack_attempts = 0;
        attack_metrics_.blocked_attacks = 0;
        attack_metrics_.successful_attacks = 0;
        attack_metrics_.legitimate_attempts = 0;
        attack_metrics_.legitimate_success = 0;
        attack_metrics_.resource_exhaustion_attempts = 0;
        attack_metrics_.amplification_attempts = 0;
        attack_metrics_.cookie_attacks = 0;
        attack_metrics_.protocol_violations = 0;
        performance_samples_.clear();
        legitimate_client_success_rate_.clear();
        attack_start_time_ = std::chrono::steady_clock::now();
    }
    
    void startPerformanceMonitoring() {
        monitoring_active_ = true;
        performance_monitor_ = std::thread([this]() {
            while (monitoring_active_) {
                auto timestamp = std::chrono::steady_clock::now();
                auto health = dos_protection_->get_system_health();
                auto stats = dos_protection_->get_statistics();
                
                PerformanceSample sample{
                    timestamp,
                    health.cpu_usage,
                    health.memory_usage,
                    health.connection_usage,
                    static_cast<double>(stats.allowed_requests),
                    static_cast<double>(stats.blocked_requests)
                };
                
                {
                    std::lock_guard<std::mutex> lock(metrics_mutex_);
                    performance_samples_.push_back(sample);
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
    }
    
    void stopPerformanceMonitoring() {
        monitoring_active_ = false;
        if (performance_monitor_.joinable()) {
            performance_monitor_.join();
        }
    }
    
    void analyzeAttackResults() {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        auto attack_duration = std::chrono::steady_clock::now() - attack_start_time_;
        auto duration_seconds = std::chrono::duration_cast<std::chrono::seconds>(attack_duration).count();
        
        std::cout << "\n=== Attack Resilience Analysis ===" << std::endl;
        std::cout << "Attack Duration: " << duration_seconds << "s" << std::endl;
        std::cout << "Total Attack Attempts: " << attack_metrics_.total_attack_attempts << std::endl;
        std::cout << "Blocked Attacks: " << attack_metrics_.blocked_attacks << std::endl;
        std::cout << "Successful Attacks: " << attack_metrics_.successful_attacks << std::endl;
        
        if (attack_metrics_.total_attack_attempts > 0) {
            double block_rate = static_cast<double>(attack_metrics_.blocked_attacks) / 
                               attack_metrics_.total_attack_attempts;
            std::cout << "Attack Block Rate: " << (block_rate * 100.0) << "%" << std::endl;
        }
        
        std::cout << "Legitimate Client Attempts: " << attack_metrics_.legitimate_attempts << std::endl;
        std::cout << "Legitimate Client Success: " << attack_metrics_.legitimate_success << std::endl;
        
        if (attack_metrics_.legitimate_attempts > 0) {
            double success_rate = static_cast<double>(attack_metrics_.legitimate_success) / 
                                 attack_metrics_.legitimate_attempts;
            std::cout << "Legitimate Success Rate: " << (success_rate * 100.0) << "%" << std::endl;
        }
        
        if (!performance_samples_.empty()) {
            auto max_cpu = std::max_element(performance_samples_.begin(), performance_samples_.end(),
                [](const auto& a, const auto& b) { return a.cpu_usage < b.cpu_usage; });
            auto max_memory = std::max_element(performance_samples_.begin(), performance_samples_.end(),
                [](const auto& a, const auto& b) { return a.memory_usage < b.memory_usage; });
            
            std::cout << "Peak CPU Usage: " << (max_cpu->cpu_usage * 100.0) << "%" << std::endl;
            std::cout << "Peak Memory Usage: " << (max_memory->memory_usage * 100.0) << "%" << std::endl;
        }
        
        std::cout << "Resource Exhaustion Attempts: " << attack_metrics_.resource_exhaustion_attempts << std::endl;
        std::cout << "Amplification Attempts: " << attack_metrics_.amplification_attempts << std::endl;
        std::cout << "Cookie Poisoning Attempts: " << attack_metrics_.cookie_attacks << std::endl;
        std::cout << "Protocol Violation Attempts: " << attack_metrics_.protocol_violations << std::endl;
    }

    // Test infrastructure
    std::unique_ptr<DoSProtection> dos_protection_;
    std::vector<NetworkAddress> legitimate_clients_;
    std::vector<NetworkAddress> attack_sources_;
    std::mt19937 rng_;
    
    // Performance monitoring
    std::atomic<bool> monitoring_active_{false};
    std::thread performance_monitor_;
    std::mutex metrics_mutex_;
    
    // Metrics tracking
    struct AttackMetrics {
        std::atomic<size_t> total_attack_attempts{0};
        std::atomic<size_t> blocked_attacks{0};
        std::atomic<size_t> successful_attacks{0};
        std::atomic<size_t> legitimate_attempts{0};
        std::atomic<size_t> legitimate_success{0};
        std::atomic<size_t> resource_exhaustion_attempts{0};
        std::atomic<size_t> amplification_attempts{0};
        std::atomic<size_t> cookie_attacks{0};
        std::atomic<size_t> protocol_violations{0};
    } attack_metrics_;
    
    struct PerformanceSample {
        std::chrono::steady_clock::time_point timestamp;
        double cpu_usage;
        double memory_usage;
        double connection_usage;
        double requests_allowed;
        double requests_blocked;
    };
    
    std::vector<PerformanceSample> performance_samples_;
    std::vector<double> legitimate_client_success_rate_;
    std::chrono::steady_clock::time_point attack_start_time_;
};

/**
 * Test 1: Volumetric UDP Flood Attack
 * 
 * Simulates high-volume UDP packet floods from multiple sources
 * targeting server resources and network bandwidth.
 */
TEST_F(AttackResilienceTest, VolumetricUDPFloodAttack) {
    const size_t flood_threads = 100;
    const size_t packets_per_thread = 1000;
    const auto attack_duration = std::chrono::seconds(30);
    
    std::cout << "Starting Volumetric UDP Flood Attack..." << std::endl;
    std::cout << "Threads: " << flood_threads << ", Packets per thread: " << packets_per_thread << std::endl;
    
    std::vector<std::future<void>> attack_futures;
    std::atomic<bool> attack_active{true};
    
    // Launch flood attack threads
    for (size_t i = 0; i < flood_threads; ++i) {
        attack_futures.push_back(std::async(std::launch::async, [this, i, packets_per_thread, &attack_active]() {
            std::uniform_int_distribution<size_t> source_dist(0, attack_sources_.size() - 1);
            
            for (size_t j = 0; j < packets_per_thread && attack_active; ++j) {
                const auto& source = attack_sources_[source_dist(rng_)];
                
                attack_metrics_.total_attack_attempts++;
                
                auto result = dos_protection_->check_connection_attempt(source, 64);
                if (result == DoSProtectionResult::ALLOWED) {
                    attack_metrics_.successful_attacks++;
                } else {
                    attack_metrics_.blocked_attacks++;
                }
                
                // High-frequency attack pattern
                std::this_thread::sleep_for(std::chrono::microseconds(100 + (j % 1000)));
            }
        }));
    }
    
    // Monitor legitimate client access during attack
    std::future<void> client_monitor = std::async(std::launch::async, [this, &attack_active]() {
        while (attack_active) {
            for (const auto& client : legitimate_clients_) {
                attack_metrics_.legitimate_attempts++;
                
                auto result = dos_protection_->check_connection_attempt(client, 512);
                if (result == DoSProtectionResult::ALLOWED) {
                    attack_metrics_.legitimate_success++;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Let attack run for specified duration
    std::this_thread::sleep_for(attack_duration);
    attack_active = false;
    
    // Wait for all threads to complete
    for (auto& future : attack_futures) {
        future.wait();
    }
    client_monitor.wait();
    
    // Validate attack mitigation
    double block_rate = static_cast<double>(attack_metrics_.blocked_attacks) / 
                       attack_metrics_.total_attack_attempts;
    double legitimate_success_rate = static_cast<double>(attack_metrics_.legitimate_success) / 
                                   attack_metrics_.legitimate_attempts;
    
    // Attack should be >95% blocked while legitimate clients maintain >80% success
    EXPECT_GT(block_rate, 0.95) << "UDP flood attack not adequately blocked";
    EXPECT_GT(legitimate_success_rate, 0.80) << "Legitimate clients overly impacted by protection";
}

/**
 * Test 2: Protocol-Based State Exhaustion Attack
 * 
 * Attempts to exhaust server state by sending malformed handshake messages
 * that consume resources without completing connections.
 */
TEST_F(AttackResilienceTest, ProtocolStateExhaustionAttack) {
    const size_t attack_threads = 50;
    const size_t malformed_packets_per_thread = 500;
    
    std::cout << "Starting Protocol State Exhaustion Attack..." << std::endl;
    
    std::vector<std::future<void>> attack_futures;
    
    // Launch state exhaustion attack
    for (size_t i = 0; i < attack_threads; ++i) {
        attack_futures.push_back(std::async(std::launch::async, [this, i, malformed_packets_per_thread]() {
            std::uniform_int_distribution<size_t> source_dist(0, attack_sources_.size() - 1);
            
            for (size_t j = 0; j < malformed_packets_per_thread; ++j) {
                const auto& source = attack_sources_[source_dist(rng_)];
                
                attack_metrics_.total_attack_attempts++;
                attack_metrics_.protocol_violations++;
                
                // Simulate malformed handshake that consumes server state
                size_t handshake_size = 1024 + (j % 4096); // Variable size handshake
                
                auto result = dos_protection_->check_handshake_attempt(source, handshake_size);
                if (result == DoSProtectionResult::ALLOWED) {
                    // Attempt resource allocation without completion
                    auto alloc_result = dos_protection_->allocate_handshake_resources(source, handshake_size);
                    if (alloc_result.is_success()) {
                        attack_metrics_.successful_attacks++;
                        // Don't release resources (simulating incomplete handshake)
                    }
                } else {
                    attack_metrics_.blocked_attacks++;
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(10 + (j % 50)));
            }
        }));
    }
    
    // Simultaneously test legitimate handshakes
    std::future<void> legitimate_test = std::async(std::launch::async, [this]() {
        for (int round = 0; round < 100; ++round) {
            for (const auto& client : legitimate_clients_) {
                attack_metrics_.legitimate_attempts++;
                
                auto result = dos_protection_->check_handshake_attempt(client, 1024);
                if (result == DoSProtectionResult::ALLOWED) {
                    auto alloc_result = dos_protection_->allocate_handshake_resources(client, 1024);
                    if (alloc_result.is_success()) {
                        attack_metrics_.legitimate_success++;
                        // Properly release resources
                        dos_protection_->release_resources(alloc_result.value());
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Wait for attack completion
    for (auto& future : attack_futures) {
        future.wait();
    }
    legitimate_test.wait();
    
    // Force cleanup to test resource management
    dos_protection_->force_cleanup();
    
    // Validate system stability after attack
    auto health = dos_protection_->get_system_health();
    EXPECT_TRUE(health.is_healthy) << "System not healthy after protocol attack";
    
    double legitimate_success_rate = static_cast<double>(attack_metrics_.legitimate_success) / 
                                   attack_metrics_.legitimate_attempts;
    EXPECT_GT(legitimate_success_rate, 0.85) << "Legitimate handshakes overly impacted";
}

/**
 * Test 3: Resource Exhaustion Attack
 * 
 * Attempts to exhaust memory and connection resources through
 * rapid resource allocation without proper cleanup.
 */
TEST_F(AttackResilienceTest, ResourceExhaustionAttack) {
    const size_t exhaustion_threads = 25;
    const size_t allocations_per_thread = 200;
    
    std::cout << "Starting Resource Exhaustion Attack..." << std::endl;
    
    std::vector<std::future<void>> attack_futures;
    
    for (size_t i = 0; i < exhaustion_threads; ++i) {
        attack_futures.push_back(std::async(std::launch::async, [this, i, allocations_per_thread]() {
            std::uniform_int_distribution<size_t> source_dist(0, attack_sources_.size() - 1);
            std::uniform_int_distribution<size_t> memory_dist(1024, 65536); // 1KB to 64KB per allocation
            
            std::vector<uint64_t> leaked_allocations;
            
            for (size_t j = 0; j < allocations_per_thread; ++j) {
                const auto& source = attack_sources_[source_dist(rng_)];
                size_t memory_size = memory_dist(rng_);
                
                attack_metrics_.total_attack_attempts++;
                attack_metrics_.resource_exhaustion_attempts++;
                
                // Attempt massive resource allocation
                auto result = dos_protection_->allocate_connection_resources(source, memory_size);
                if (result.is_success()) {
                    attack_metrics_.successful_attacks++;
                    leaked_allocations.push_back(result.value());
                    
                    // Intentionally don't release some resources (resource leak attack)
                    if ((j % 10) != 0) { // Leak 90% of resources
                        // Don't call dos_protection_->release_resources(result.value());
                    } else {
                        dos_protection_->release_resources(result.value());
                    }
                } else {
                    attack_metrics_.blocked_attacks++;
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(20 + (j % 100)));
            }
        }));
    }
    
    // Monitor system health during resource exhaustion
    std::atomic<bool> health_monitoring{true};
    std::future<void> health_monitor = std::async(std::launch::async, [this, &health_monitoring]() {
        std::vector<double> memory_usage_samples;
        
        while (health_monitoring) {
            auto health = dos_protection_->get_system_health();
            memory_usage_samples.push_back(health.memory_usage);
            
            // System should never become completely unhealthy
            if (health.memory_usage > 0.95) {
                std::cout << "WARNING: Memory usage exceeded 95%" << std::endl;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        if (!memory_usage_samples.empty()) {
            auto max_memory = *std::max_element(memory_usage_samples.begin(), memory_usage_samples.end());
            std::cout << "Peak memory usage during attack: " << (max_memory * 100.0) << "%" << std::endl;
        }
    });
    
    // Wait for resource exhaustion attempts
    for (auto& future : attack_futures) {
        future.wait();
    }
    
    health_monitoring = false;
    health_monitor.wait();
    
    // Test legitimate client access during resource pressure
    for (const auto& client : legitimate_clients_) {
        attack_metrics_.legitimate_attempts++;
        
        auto result = dos_protection_->allocate_connection_resources(client, 2048);
        if (result.is_success()) {
            attack_metrics_.legitimate_success++;
            dos_protection_->release_resources(result.value());
        }
    }
    
    // Force cleanup and verify recovery
    dos_protection_->force_cleanup();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    auto final_health = dos_protection_->get_system_health();
    EXPECT_TRUE(final_health.is_healthy) << "System failed to recover after resource exhaustion";
    
    // System should limit resource allocation to prevent complete exhaustion
    auto stats = dos_protection_->get_resource_stats();
    EXPECT_LT(stats.total_allocated_memory, 1000000UL) // Less than 1MB allocated 
        << "Resource limits not properly enforced";
}

/**
 * Test 4: Amplification Attack
 * 
 * Tests reflection/amplification attack scenarios where attackers
 * use small requests to generate large responses.
 */
TEST_F(AttackResilienceTest, AmplificationAttack) {
    const size_t amplification_threads = 20;
    const size_t amplification_attempts = 100;
    
    std::cout << "Starting Amplification Attack..." << std::endl;
    
    std::vector<std::future<void>> attack_futures;
    
    for (size_t i = 0; i < amplification_threads; ++i) {
        attack_futures.push_back(std::async(std::launch::async, [this, i, amplification_attempts]() {
            std::uniform_int_distribution<size_t> source_dist(0, attack_sources_.size() - 1);
            
            for (size_t j = 0; j < amplification_attempts; ++j) {
                const auto& source = attack_sources_[source_dist(rng_)];
                
                attack_metrics_.total_attack_attempts++;
                attack_metrics_.amplification_attempts++;
                
                // Small request, large response (amplification attack)
                size_t request_size = 64;   // 64 bytes request
                size_t response_size = 8192; // 8KB response (128x amplification)
                
                bool amplification_allowed = dos_protection_->check_amplification_limits(
                    source, request_size, response_size);
                
                if (amplification_allowed) {
                    attack_metrics_.successful_attacks++;
                } else {
                    attack_metrics_.blocked_attacks++;
                }
                
                // Try various amplification ratios
                std::vector<size_t> response_sizes = {2048, 4096, 8192, 16384, 32768};
                for (auto resp_size : response_sizes) {
                    bool allowed = dos_protection_->check_amplification_limits(source, request_size, resp_size);
                    if (!allowed) break; // Stop at first blocked amplification
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(50 + (j % 200)));
            }
        }));
    }
    
    // Test legitimate traffic during amplification attack
    std::future<void> legitimate_test = std::async(std::launch::async, [this]() {
        for (int round = 0; round < 50; ++round) {
            for (const auto& client : legitimate_clients_) {
                attack_metrics_.legitimate_attempts++;
                
                // Normal request/response ratio
                size_t request_size = 512;
                size_t response_size = 1024; // 2x amplification (reasonable)
                
                bool allowed = dos_protection_->check_amplification_limits(client, request_size, response_size);
                if (allowed) {
                    attack_metrics_.legitimate_success++;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Wait for attack completion
    for (auto& future : attack_futures) {
        future.wait();
    }
    legitimate_test.wait();
    
    // Verify amplification protection effectiveness
    double block_rate = static_cast<double>(attack_metrics_.blocked_attacks) / 
                       attack_metrics_.total_attack_attempts;
    double legitimate_success_rate = static_cast<double>(attack_metrics_.legitimate_success) / 
                                   attack_metrics_.legitimate_attempts;
    
    EXPECT_GT(block_rate, 0.90) << "Amplification attacks not adequately blocked";
    EXPECT_GT(legitimate_success_rate, 0.95) << "Legitimate amplification requests blocked";
}

/**
 * Test 5: Cookie-Based Attack Patterns
 * 
 * Tests various cookie-related attack scenarios including
 * cookie flooding, replay, and poisoning attacks.
 */
TEST_F(AttackResilienceTest, CookieBasedAttacks) {
    // Enable cookie validation for this test
    dos_protection_->enable_cookie_validation(true);
    
    const size_t cookie_attack_threads = 30;
    const size_t cookie_attempts = 100;
    
    std::cout << "Starting Cookie-Based Attacks..." << std::endl;
    
    std::vector<std::future<void>> attack_futures;
    
    for (size_t i = 0; i < cookie_attack_threads; ++i) {
        attack_futures.push_back(std::async(std::launch::async, [this, i, cookie_attempts]() {
            std::uniform_int_distribution<size_t> source_dist(0, attack_sources_.size() - 1);
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            
            for (size_t j = 0; j < cookie_attempts; ++j) {
                const auto& source = attack_sources_[source_dist(rng_)];
                
                attack_metrics_.total_attack_attempts++;
                attack_metrics_.cookie_attacks++;
                
                // Test various cookie attack patterns
                if (j % 4 == 0) {
                    // Attack 1: Cookie flooding - generate excessive cookies
                    std::vector<uint8_t> client_hello(64);
                    std::generate(client_hello.begin(), client_hello.end(), [&]() { return byte_dist(rng_); });
                    
                    auto cookie_result = dos_protection_->generate_client_cookie(source, client_hello);
                    if (cookie_result.is_success()) {
                        attack_metrics_.successful_attacks++;
                    } else {
                        attack_metrics_.blocked_attacks++;
                    }
                } else if (j % 4 == 1) {
                    // Attack 2: Invalid cookie replay
                    std::vector<uint8_t> fake_cookie(32);
                    std::generate(fake_cookie.begin(), fake_cookie.end(), [&]() { return byte_dist(rng_); });
                    
                    std::vector<uint8_t> client_hello(64);
                    memory::Buffer cookie_buf(reinterpret_cast<const std::byte*>(fake_cookie.data()), fake_cookie.size());
                    auto result = dos_protection_->validate_client_cookie(cookie_buf, source, client_hello);
                    
                    if (result == DoSProtectionResult::ALLOWED) {
                        attack_metrics_.successful_attacks++;
                    } else {
                        attack_metrics_.blocked_attacks++;
                    }
                } else if (j % 4 == 2) {
                    // Attack 3: Cookie brute force - try to guess valid cookies
                    for (int attempt = 0; attempt < 10; ++attempt) {
                        std::vector<uint8_t> brute_cookie(24);
                        std::generate(brute_cookie.begin(), brute_cookie.end(), [&]() { return byte_dist(rng_); });
                        
                        std::vector<uint8_t> client_hello(32);
                        memory::Buffer cookie_buf(reinterpret_cast<const std::byte*>(brute_cookie.data()), brute_cookie.size());
                        auto result = dos_protection_->validate_client_cookie(cookie_buf, source, client_hello);
                        
                        if (result == DoSProtectionResult::ALLOWED) {
                            attack_metrics_.successful_attacks++;
                            break; // Found valid cookie (shouldn't happen)
                        }
                    }
                    attack_metrics_.blocked_attacks++;
                } else {
                    // Attack 4: Cookie requirement bypass attempt
                    std::vector<uint8_t> client_hello(128);
                    
                    // Check if cookie is required
                    bool cookie_required = dos_protection_->should_require_cookie(source, client_hello);
                    if (cookie_required) {
                        // Try to proceed without providing cookie
                        auto check_result = dos_protection_->check_connection_attempt(source);
                        if (check_result == DoSProtectionResult::ALLOWED) {
                            attack_metrics_.successful_attacks++;
                        } else {
                            attack_metrics_.blocked_attacks++;
                        }
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(30 + (j % 100)));
            }
        }));
    }
    
    // Test legitimate cookie workflow
    std::future<void> legitimate_test = std::async(std::launch::async, [this]() {
        for (int round = 0; round < 25; ++round) {
            for (const auto& client : legitimate_clients_) {
                attack_metrics_.legitimate_attempts++;
                
                std::vector<uint8_t> client_hello = {0x16, 0x03, 0x03, 0x01, 0x00}; // Valid ClientHello
                
                // Proper cookie workflow
                bool needs_cookie = dos_protection_->should_require_cookie(client, client_hello);
                if (needs_cookie) {
                    auto cookie_result = dos_protection_->generate_client_cookie(client, client_hello);
                    if (cookie_result.is_success()) {
                        auto validation_result = dos_protection_->validate_client_cookie(
                            cookie_result.value(), client, client_hello);
                        
                        if (validation_result == DoSProtectionResult::ALLOWED) {
                            dos_protection_->consume_client_cookie(cookie_result.value(), client);
                            attack_metrics_.legitimate_success++;
                        }
                    }
                } else {
                    attack_metrics_.legitimate_success++;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });
    
    // Wait for attack completion
    for (auto& future : attack_futures) {
        future.wait();
    }
    legitimate_test.wait();
    
    // Validate cookie protection effectiveness
    double block_rate = static_cast<double>(attack_metrics_.blocked_attacks) / 
                       attack_metrics_.total_attack_attempts;
    double legitimate_success_rate = static_cast<double>(attack_metrics_.legitimate_success) / 
                                   attack_metrics_.legitimate_attempts;
    
    EXPECT_GT(block_rate, 0.98) << "Cookie attacks not adequately blocked";
    EXPECT_GT(legitimate_success_rate, 0.90) << "Legitimate cookie workflow impacted";
}

/**
 * Test 6: Distributed Attack Simulation
 * 
 * Simulates large-scale distributed attacks from multiple
 * geographic regions with coordinated timing.
 */
TEST_F(AttackResilienceTest, DistributedAttackSimulation) {
    const size_t attack_waves = 5;
    const size_t attackers_per_wave = 200;
    const auto wave_interval = std::chrono::seconds(10);
    
    std::cout << "Starting Distributed Attack Simulation..." << std::endl;
    std::cout << "Attack waves: " << attack_waves << ", Attackers per wave: " << attackers_per_wave << std::endl;
    
    // Monitor system health throughout distributed attack
    std::atomic<bool> health_monitoring{true};
    std::future<void> health_monitor = std::async(std::launch::async, [this, &health_monitoring]() {
        std::vector<double> cpu_samples, memory_samples;
        
        while (health_monitoring) {
            auto health = dos_protection_->get_system_health();
            cpu_samples.push_back(health.cpu_usage);
            memory_samples.push_back(health.memory_usage);
            
            // Log critical system states
            if (health.cpu_usage > 0.90 || health.memory_usage > 0.90) {
                std::cout << "System under extreme load - CPU: " << (health.cpu_usage * 100.0) 
                         << "%, Memory: " << (health.memory_usage * 100.0) << "%" << std::endl;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        
        if (!cpu_samples.empty()) {
            auto max_cpu = *std::max_element(cpu_samples.begin(), cpu_samples.end());
            auto max_memory = *std::max_element(memory_samples.begin(), memory_samples.end());
            std::cout << "Distributed attack peak usage - CPU: " << (max_cpu * 100.0) 
                     << "%, Memory: " << (max_memory * 100.0) << "%" << std::endl;
        }
    });
    
    // Launch coordinated attack waves
    for (size_t wave = 0; wave < attack_waves; ++wave) {
        std::cout << "Launching attack wave " << (wave + 1) << "/" << attack_waves << std::endl;
        
        std::vector<std::future<void>> wave_futures;
        
        for (size_t attacker = 0; attacker < attackers_per_wave; ++attacker) {
            wave_futures.push_back(std::async(std::launch::async, [this, wave, attacker]() {
                std::uniform_int_distribution<size_t> source_dist(0, attack_sources_.size() - 1);
                const auto& source = attack_sources_[source_dist(rng_)];
                
                // Multiple attack types per attacker
                for (int attack_type = 0; attack_type < 5; ++attack_type) {
                    attack_metrics_.total_attack_attempts++;
                    
                    DoSProtectionResult result = DoSProtectionResult::ALLOWED;
                    
                    switch (attack_type) {
                        case 0: // Connection flood
                            result = dos_protection_->check_connection_attempt(source);
                            break;
                        case 1: // Handshake flood
                            result = dos_protection_->check_handshake_attempt(source, 1024);
                            break;
                        case 2: // Resource allocation
                            {
                                auto alloc_result = dos_protection_->allocate_connection_resources(source, 2048);
                                result = alloc_result.is_success() ? DoSProtectionResult::ALLOWED : 
                                                                    DoSProtectionResult::RESOURCE_EXHAUSTED;
                                if (alloc_result.is_success()) {
                                    dos_protection_->release_resources(alloc_result.value());
                                }
                            }
                            break;
                        case 3: // Amplification attempt
                            {
                                bool amp_allowed = dos_protection_->check_amplification_limits(source, 64, 4096);
                                result = amp_allowed ? DoSProtectionResult::ALLOWED : 
                                                     DoSProtectionResult::AMPLIFICATION_BLOCKED;
                            }
                            break;
                        case 4: // Security violation
                            dos_protection_->record_security_violation(source, "distributed_attack", "high");
                            result = dos_protection_->check_connection_attempt(source);
                            break;
                    }
                    
                    if (result == DoSProtectionResult::ALLOWED) {
                        attack_metrics_.successful_attacks++;
                    } else {
                        attack_metrics_.blocked_attacks++;
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(100 + (attacker % 500)));
                }
            }));
        }
        
        // Test legitimate client access during each wave
        std::future<void> legitimate_wave_test = std::async(std::launch::async, [this, wave]() {
            for (int test_round = 0; test_round < 10; ++test_round) {
                for (const auto& client : legitimate_clients_) {
                    attack_metrics_.legitimate_attempts++;
                    
                    auto result = dos_protection_->check_connection_attempt(client);
                    if (result == DoSProtectionResult::ALLOWED) {
                        attack_metrics_.legitimate_success++;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        });
        
        // Wait for current wave to complete
        for (auto& future : wave_futures) {
            future.wait();
        }
        legitimate_wave_test.wait();
        
        // Brief pause between waves (except for last wave)
        if (wave < attack_waves - 1) {
            std::this_thread::sleep_for(wave_interval);
        }
        
        // Force cleanup between waves
        dos_protection_->force_cleanup();
    }
    
    health_monitoring = false;
    health_monitor.wait();
    
    // Final system stability check
    std::this_thread::sleep_for(std::chrono::seconds(2));
    auto final_health = dos_protection_->get_system_health();
    
    // System should remain stable despite massive distributed attack
    EXPECT_TRUE(final_health.is_healthy) << "System failed to maintain stability under distributed attack";
    
    // Attack should be predominantly blocked while legitimate traffic flows
    double overall_block_rate = static_cast<double>(attack_metrics_.blocked_attacks) / 
                               attack_metrics_.total_attack_attempts;
    double legitimate_success_rate = static_cast<double>(attack_metrics_.legitimate_success) / 
                                   attack_metrics_.legitimate_attempts;
    
    EXPECT_GT(overall_block_rate, 0.85) << "Distributed attack not adequately blocked";
    EXPECT_GT(legitimate_success_rate, 0.70) << "Legitimate traffic severely impacted by distributed attack";
    
    // Performance should not degrade catastrophically
    EXPECT_LT(final_health.cpu_usage, 0.95) << "CPU usage excessive after distributed attack";
    EXPECT_LT(final_health.memory_usage, 0.95) << "Memory usage excessive after distributed attack";
}

/**
 * Test 7: Performance Degradation Under Attack
 * 
 * Measures and validates that system performance remains within
 * acceptable bounds even under sustained attack conditions.
 */
TEST_F(AttackResilienceTest, PerformanceDegradationUnderAttack) {
    const auto baseline_duration = std::chrono::seconds(10);
    const auto attack_duration = std::chrono::seconds(30);
    const auto recovery_duration = std::chrono::seconds(10);
    
    std::cout << "Measuring Performance Degradation Under Attack..." << std::endl;
    
    // Phase 1: Baseline performance measurement
    std::cout << "Phase 1: Baseline measurement..." << std::endl;
    
    std::atomic<bool> baseline_active{true};
    std::vector<std::chrono::microseconds> baseline_response_times;
    std::mutex baseline_mutex;
    
    std::future<void> baseline_test = std::async(std::launch::async, [this, &baseline_active, &baseline_response_times, &baseline_mutex]() {
        while (baseline_active) {
            for (const auto& client : legitimate_clients_) {
                auto start = std::chrono::high_resolution_clock::now();
                
                auto result = dos_protection_->check_connection_attempt(client);
                if (result == DoSProtectionResult::ALLOWED) {
                    attack_metrics_.legitimate_success++;
                }
                
                auto end = std::chrono::high_resolution_clock::now();
                auto response_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                
                {
                    std::lock_guard<std::mutex> lock(baseline_mutex);
                    baseline_response_times.push_back(response_time);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    
    std::this_thread::sleep_for(baseline_duration);
    baseline_active = false;
    baseline_test.wait();
    
    // Calculate baseline metrics
    auto baseline_avg = std::accumulate(baseline_response_times.begin(), baseline_response_times.end(),
                                       std::chrono::microseconds{0}) / baseline_response_times.size();
    auto baseline_max = *std::max_element(baseline_response_times.begin(), baseline_response_times.end());
    
    std::cout << "Baseline - Avg: " << baseline_avg.count() << "μs, Max: " << baseline_max.count() << "μs" << std::endl;
    
    // Phase 2: Performance under attack
    std::cout << "Phase 2: Performance under attack..." << std::endl;
    
    std::vector<std::chrono::microseconds> attack_response_times;
    std::mutex attack_mutex;
    std::atomic<bool> attack_active{true};
    
    // Launch sustained attack
    std::future<void> sustained_attack = std::async(std::launch::async, [this, &attack_active]() {
        const size_t attack_threads = 50;
        std::vector<std::future<void>> attack_futures;
        
        for (size_t i = 0; i < attack_threads; ++i) {
            attack_futures.push_back(std::async(std::launch::async, [this, i, &attack_active]() {
                std::uniform_int_distribution<size_t> source_dist(0, attack_sources_.size() - 1);
                
                while (attack_active) {
                    const auto& source = attack_sources_[source_dist(rng_)];
                    dos_protection_->check_connection_attempt(source);
                    dos_protection_->check_handshake_attempt(source, 1024);
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(5 + (i % 50)));
                }
            }));
        }
        
        for (auto& future : attack_futures) {
            future.wait();
        }
    });
    
    // Measure legitimate client performance during attack
    std::future<void> attack_perf_test = std::async(std::launch::async, [this, &attack_active, &attack_response_times, &attack_mutex]() {
        while (attack_active) {
            for (const auto& client : legitimate_clients_) {
                auto start = std::chrono::high_resolution_clock::now();
                
                auto result = dos_protection_->check_connection_attempt(client);
                if (result == DoSProtectionResult::ALLOWED) {
                    attack_metrics_.legitimate_success++;
                }
                
                auto end = std::chrono::high_resolution_clock::now();
                auto response_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                
                {
                    std::lock_guard<std::mutex> lock(attack_mutex);
                    attack_response_times.push_back(response_time);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    
    std::this_thread::sleep_for(attack_duration);
    attack_active = false;
    sustained_attack.wait();
    attack_perf_test.wait();
    
    // Calculate attack performance metrics
    if (!attack_response_times.empty()) {
        auto attack_avg = std::accumulate(attack_response_times.begin(), attack_response_times.end(),
                                         std::chrono::microseconds{0}) / attack_response_times.size();
        auto attack_max = *std::max_element(attack_response_times.begin(), attack_response_times.end());
        
        std::cout << "Under Attack - Avg: " << attack_avg.count() << "μs, Max: " << attack_max.count() << "μs" << std::endl;
        
        // Phase 3: Recovery performance
        std::cout << "Phase 3: Recovery measurement..." << std::endl;
        
        dos_protection_->force_cleanup();
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        std::vector<std::chrono::microseconds> recovery_response_times;
        for (int round = 0; round < 100; ++round) {
            for (const auto& client : legitimate_clients_) {
                auto start = std::chrono::high_resolution_clock::now();
                
                auto result = dos_protection_->check_connection_attempt(client);
                if (result == DoSProtectionResult::ALLOWED) {
                    attack_metrics_.legitimate_success++;
                }
                
                auto end = std::chrono::high_resolution_clock::now();
                auto response_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                recovery_response_times.push_back(response_time);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        auto recovery_avg = std::accumulate(recovery_response_times.begin(), recovery_response_times.end(),
                                           std::chrono::microseconds{0}) / recovery_response_times.size();
        auto recovery_max = *std::max_element(recovery_response_times.begin(), recovery_response_times.end());
        
        std::cout << "Recovery - Avg: " << recovery_avg.count() << "μs, Max: " << recovery_max.count() << "μs" << std::endl;
        
        // Validate performance requirements
        
        // Average response time should not increase by more than 500% under attack
        double perf_degradation = static_cast<double>(attack_avg.count()) / baseline_avg.count();
        EXPECT_LT(perf_degradation, 5.0) << "Performance degradation excessive under attack";
        
        // Max response time should not exceed 100ms even under attack
        EXPECT_LT(attack_max.count(), 100000) << "Maximum response time exceeded 100ms under attack";
        
        // System should recover to near-baseline performance after attack
        double recovery_ratio = static_cast<double>(recovery_avg.count()) / baseline_avg.count();
        EXPECT_LT(recovery_ratio, 2.0) << "System failed to recover to acceptable performance";
        
        std::cout << "Performance Analysis:" << std::endl;
        std::cout << "  Degradation under attack: " << (perf_degradation * 100.0) << "%" << std::endl;
        std::cout << "  Recovery ratio: " << (recovery_ratio * 100.0) << "%" << std::endl;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}