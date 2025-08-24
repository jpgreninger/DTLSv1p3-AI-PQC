/**
 * @file test_dos_protection_comprehensive.cpp
 * @brief Comprehensive tests for DTLS DoS protection system
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>

#include "dtls/security/dos_protection.h"
#include "dtls/security/rate_limiter.h"
#include "dtls/security/resource_manager.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::security;
using namespace std::chrono_literals;

class DoSProtectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up test addresses
        test_address1_ = NetworkAddress::from_string("192.168.1.100:8080").value();
        test_address2_ = NetworkAddress::from_string("192.168.1.101:8080").value();
        test_address3_ = NetworkAddress::from_string("10.0.0.1:443").value();
        blocked_address_ = NetworkAddress::from_string("203.0.113.1:9999").value();
        
        // Create test configuration
        test_config_ = DoSProtectionConfig{};
        
        // Configure rate limiting (permissive for most tests)
        test_config_.rate_limit_config.max_tokens = 100;
        test_config_.rate_limit_config.tokens_per_second = 20;
        test_config_.rate_limit_config.max_burst_count = 50;
        test_config_.rate_limit_config.max_concurrent_connections = 1000;
        test_config_.rate_limit_config.blacklist_duration = 5s;
        
        // Configure resource management (generous for testing)
        test_config_.resource_config.max_total_memory = 100 * 1024 * 1024; // 100MB
        test_config_.resource_config.max_total_connections = 5000;
        test_config_.resource_config.max_connections_per_source = 100;
        test_config_.resource_config.max_pending_handshakes = 500;
        
        // Configure DoS protection features
        test_config_.enable_cookie_validation = true;
        test_config_.enable_cpu_monitoring = false; // Disable for testing
        test_config_.enable_proof_of_work = false; // Enable only for specific tests
        test_config_.enable_source_validation = true;
        test_config_.enable_geoblocking = false; // Enable only for specific tests
        
        // Test data
        client_hello_data_ = {0x16, 0x03, 0x03, 0x00, 0x20}; // Simplified ClientHello
        large_request_data_.resize(4096, 0xAA);
        small_request_data_.resize(64, 0xBB);
    }
    
    NetworkAddress test_address1_, test_address2_, test_address3_, blocked_address_;
    DoSProtectionConfig test_config_;
    std::vector<uint8_t> client_hello_data_;
    std::vector<uint8_t> large_request_data_;
    std::vector<uint8_t> small_request_data_;
};

// Test basic DoS protection creation and configuration
TEST_F(DoSProtectionTest, BasicCreationAndConfiguration) {
    DoSProtection protection(test_config_);
    
    // Test initial state
    auto stats = protection.get_statistics();
    EXPECT_EQ(stats.total_requests, 0);
    EXPECT_EQ(stats.allowed_requests, 0);
    EXPECT_EQ(stats.blocked_requests, 0);
    
    // Test configuration access
    const auto& config = protection.get_config();
    EXPECT_EQ(config.rate_limit_config.max_tokens, test_config_.rate_limit_config.max_tokens);
    EXPECT_EQ(config.resource_config.max_total_memory, test_config_.resource_config.max_total_memory);
    EXPECT_EQ(config.enable_cookie_validation, test_config_.enable_cookie_validation);
    
    // Test system health
    auto health = protection.get_system_health();
    EXPECT_TRUE(health.is_healthy);
    EXPECT_EQ(health.resource_pressure, PressureLevel::NORMAL);
    EXPECT_GE(health.cpu_usage, 0.0);
    EXPECT_LE(health.cpu_usage, 1.0);
}

// Test basic connection attempt checking
TEST_F(DoSProtectionTest, BasicConnectionAttemptChecking) {
    DoSProtection protection(test_config_);
    
    // Normal connection attempts should be allowed
    for (int i = 0; i < 10; ++i) {
        auto result = protection.check_connection_attempt(test_address1_, small_request_data_.size());
        EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    }
    
    // Verify statistics
    auto stats = protection.get_statistics();
    EXPECT_EQ(stats.total_requests, 10);
    EXPECT_EQ(stats.allowed_requests, 10);
    EXPECT_EQ(stats.blocked_requests, 0);
    
    // Test from different source
    auto result = protection.check_connection_attempt(test_address2_, small_request_data_.size());
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
}

// Test handshake attempt checking
TEST_F(DoSProtectionTest, HandshakeAttemptChecking) {
    DoSProtection protection(test_config_);
    
    // Normal handshake attempts should be allowed
    for (int i = 0; i < 5; ++i) {
        auto result = protection.check_handshake_attempt(test_address1_, client_hello_data_.size());
        EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    }
    
    // Test large handshake attempt
    auto large_result = protection.check_handshake_attempt(test_address1_, large_request_data_.size());
    EXPECT_EQ(large_result, DoSProtectionResult::ALLOWED); // Should still be allowed unless amplification limits hit
}

// Test resource allocation and release
TEST_F(DoSProtectionTest, ResourceAllocationAndRelease) {
    DoSProtection protection(test_config_);
    
    // Allocate connection resources
    auto alloc_result = protection.allocate_connection_resources(test_address1_, 1024);
    ASSERT_TRUE(alloc_result.is_ok());
    
    uint64_t allocation_id = alloc_result.value();
    EXPECT_GT(allocation_id, 0);
    
    // Record connection established
    protection.record_connection_established(test_address1_);
    
    // Test system health after allocation
    auto health = protection.get_system_health();
    EXPECT_TRUE(health.is_healthy);
    EXPECT_GT(health.memory_usage, 0.0);
    
    // Allocate handshake resources
    auto handshake_alloc = protection.allocate_handshake_resources(test_address1_, 512);
    ASSERT_TRUE(handshake_alloc.is_ok());
    
    uint64_t handshake_id = handshake_alloc.value();
    EXPECT_NE(handshake_id, allocation_id); // Should be different IDs
    
    // Release resources
    auto release_result = protection.release_resources(allocation_id);
    EXPECT_TRUE(release_result.is_ok());
    
    release_result = protection.release_resources(handshake_id);
    EXPECT_TRUE(release_result.is_ok());
    
    // Record connection closed
    protection.record_connection_closed(test_address1_);
}

// Test rate limiting integration
TEST_F(DoSProtectionTest, RateLimitingIntegration) {
    // Configure strict rate limiting for this test
    DoSProtectionConfig strict_config = test_config_;
    strict_config.rate_limit_config.max_tokens = 5;
    strict_config.rate_limit_config.max_burst_count = 5;
    
    DoSProtection protection(strict_config);
    
    // Exhaust rate limits
    for (int i = 0; i < 5; ++i) {
        auto result = protection.check_connection_attempt(test_address1_);
        EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    }
    
    // Next attempt should be rate limited
    auto limited_result = protection.check_connection_attempt(test_address1_);
    EXPECT_EQ(limited_result, DoSProtectionResult::RATE_LIMITED);
    
    // Verify statistics
    auto stats = protection.get_statistics();
    EXPECT_EQ(stats.total_requests, 6);
    EXPECT_EQ(stats.allowed_requests, 5);
    EXPECT_EQ(stats.blocked_requests, 1);
    EXPECT_EQ(stats.rate_limited, 1);
}

// Test resource exhaustion protection
TEST_F(DoSProtectionTest, ResourceExhaustionProtection) {
    // Configure limited resources
    DoSProtectionConfig limited_config = test_config_;
    limited_config.resource_config.max_total_memory = 4096; // Very small
    limited_config.resource_config.max_total_connections = 3; // Very few connections
    
    DoSProtection protection(limited_config);
    
    std::vector<uint64_t> allocations;
    
    // Allocate resources up to limit
    for (int i = 0; i < 3; ++i) {
        auto alloc_result = protection.allocate_connection_resources(test_address1_, 1024);
        if (alloc_result.is_ok()) {
            allocations.push_back(alloc_result.value());
            protection.record_connection_established(test_address1_);
        }
    }
    
    // Next allocation should fail due to connection limit
    auto failed_alloc = protection.allocate_connection_resources(test_address1_, 1024);
    EXPECT_TRUE(failed_alloc.is_error());
    
    // Connection attempt should be blocked
    auto blocked_result = protection.check_connection_attempt(test_address1_);
    EXPECT_EQ(blocked_result, DoSProtectionResult::RESOURCE_EXHAUSTED);
    
    // Clean up
    for (auto id : allocations) {
        protection.release_resources(id);
        protection.record_connection_closed(test_address1_);
    }
}

// Test blacklisting functionality
TEST_F(DoSProtectionTest, BlacklistingFunctionality) {
    DoSProtection protection(test_config_);
    
    // Initially should be allowed
    auto result = protection.check_connection_attempt(blocked_address_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    
    // Blacklist the source
    auto blacklist_result = protection.blacklist_source(blocked_address_, 2s);
    EXPECT_TRUE(blacklist_result.is_ok());
    
    // Now should be blocked
    result = protection.check_connection_attempt(blocked_address_);
    EXPECT_EQ(result, DoSProtectionResult::BLACKLISTED);
    
    // Handshake attempts should also be blocked
    result = protection.check_handshake_attempt(blocked_address_);
    EXPECT_EQ(result, DoSProtectionResult::BLACKLISTED);
    
    // Remove from blacklist
    auto remove_result = protection.remove_from_blacklist(blocked_address_);
    EXPECT_TRUE(remove_result.is_ok());
    
    // Should be allowed again
    result = protection.check_connection_attempt(blocked_address_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
}

// Test whitelisting functionality
TEST_F(DoSProtectionTest, WhitelistingFunctionality) {
    DoSProtection protection(test_config_);
    
    // Add to whitelist
    auto whitelist_result = protection.add_to_whitelist(test_address1_);
    EXPECT_TRUE(whitelist_result.is_ok());
    
    // Should always be allowed even with rate limiting
    DoSProtectionConfig strict_config = test_config_;
    strict_config.rate_limit_config.max_tokens = 1;
    
    DoSProtection strict_protection(strict_config);
    strict_protection.add_to_whitelist(test_address1_);
    
    // Exhaust rate limits
    auto result = strict_protection.check_connection_attempt(test_address1_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    
    // Should still be allowed (whitelisted)
    result = strict_protection.check_connection_attempt(test_address1_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    
    // Non-whitelisted address should be rate limited
    result = strict_protection.check_connection_attempt(test_address2_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    result = strict_protection.check_connection_attempt(test_address2_);
    EXPECT_EQ(result, DoSProtectionResult::RATE_LIMITED);
    
    // Remove from whitelist
    auto remove_result = strict_protection.remove_from_whitelist(test_address1_);
    EXPECT_TRUE(remove_result.is_ok());
}

// Test amplification attack protection
TEST_F(DoSProtectionTest, AmplificationAttackProtection) {
    DoSProtection protection(test_config_);
    
    // Test normal request/response ratio
    bool normal_allowed = protection.check_amplification_limits(
        test_address1_, 100, 200); // 2x amplification
    EXPECT_TRUE(normal_allowed);
    
    // Test excessive amplification
    bool excessive_blocked = protection.check_amplification_limits(
        test_address1_, 100, 500); // 5x amplification
    EXPECT_FALSE(excessive_blocked); // Should be blocked due to high amplification ratio
    
    // Test very small request with normal response
    bool small_request_blocked = protection.check_amplification_limits(
        test_address1_, 10, 2000); // 200x amplification
    EXPECT_FALSE(small_request_blocked); // Should be blocked
}

// Test concurrent DoS protection access
TEST_F(DoSProtectionTest, ConcurrentDoSProtectionAccess) {
    DoSProtection protection(test_config_);
    
    const int num_threads = 4;
    const int requests_per_thread = 50;
    std::atomic<int> total_allowed{0};
    std::atomic<int> total_blocked{0};
    std::atomic<int> total_errors{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch threads that make concurrent requests
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> size_dis(50, 500);
            
            // Use different addresses per thread to avoid excessive conflicts
            auto thread_address = NetworkAddress::from_string(
                "192.168.1." + std::to_string(100 + t) + ":8080").value();
            
            for (int i = 0; i < requests_per_thread; ++i) {
                try {
                    size_t request_size = size_dis(gen);
                    
                    // Mix connection and handshake attempts
                    DoSProtectionResult result;
                    if (i % 2 == 0) {
                        result = protection.check_connection_attempt(thread_address, request_size);
                    } else {
                        result = protection.check_handshake_attempt(thread_address, request_size);
                    }
                    
                    if (result == DoSProtectionResult::ALLOWED) {
                        total_allowed.fetch_add(1);
                        
                        // Occasionally allocate resources
                        if (i % 10 == 0) {
                            auto alloc_result = protection.allocate_connection_resources(thread_address, 1024);
                            if (alloc_result.is_ok()) {
                                protection.record_connection_established(thread_address);
                                
                                // Release after a short time
                                std::this_thread::sleep_for(std::chrono::microseconds(100));
                                protection.release_resources(alloc_result.value());
                                protection.record_connection_closed(thread_address);
                            }
                        }
                    } else {
                        total_blocked.fetch_add(1);
                    }
                    
                } catch (...) {
                    total_errors.fetch_add(1);
                }
                
                // Small delay to avoid overwhelming the system
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify results
    int expected_total = num_threads * requests_per_thread;
    EXPECT_EQ(total_allowed.load() + total_blocked.load(), expected_total);
    EXPECT_EQ(total_errors.load(), 0); // Should not have errors
    
    // Verify statistics consistency
    auto stats = protection.get_statistics();
    EXPECT_EQ(stats.total_requests, expected_total);
    EXPECT_EQ(stats.allowed_requests, total_allowed.load());
    EXPECT_EQ(stats.blocked_requests, total_blocked.load());
}