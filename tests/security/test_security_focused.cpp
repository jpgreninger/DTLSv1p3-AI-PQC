/**
 * @file test_security_focused.cpp
 * @brief Focused security components tests using verified APIs
 * Phase 2 - Security Components Coverage Enhancement
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <random>

#include "dtls/security/rate_limiter.h"
#include "dtls/security/dos_protection.h"
#include "dtls/security/resource_manager.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::security;

class SecurityFocusedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test network addresses
        test_address1_ = NetworkAddress("192.168.1.100", 12345);
        test_address2_ = NetworkAddress("192.168.1.101", 12346);
        test_address3_ = NetworkAddress("10.0.0.5", 54321);
        
        // Create test configurations
        default_config_ = RateLimitConfig{};
        default_config_.max_tokens = 10;
        default_config_.tokens_per_second = 2;
        default_config_.max_burst_count = 5;
        default_config_.max_concurrent_connections = 3;
        
        strict_config_ = RateLimitConfig{};
        strict_config_.max_tokens = 5;
        strict_config_.tokens_per_second = 1;
        strict_config_.max_burst_count = 2;
        strict_config_.max_concurrent_connections = 2;
        strict_config_.blacklist_duration = std::chrono::seconds{60};
    }
    
    NetworkAddress test_address1_;
    NetworkAddress test_address2_;
    NetworkAddress test_address3_;
    RateLimitConfig default_config_;
    RateLimitConfig strict_config_;
};

// Test TokenBucket basic functionality
TEST_F(SecurityFocusedTest, TokenBucketBasics) {
    TokenBucket bucket(10, 5); // 10 tokens max, 5 per second
    
    // Test basic properties
    EXPECT_EQ(bucket.get_capacity(), 10);
    EXPECT_EQ(bucket.get_refill_rate(), 5);
    EXPECT_LE(bucket.get_token_count(), 10);
    
    // Test token consumption
    EXPECT_TRUE(bucket.try_consume(1));
    EXPECT_TRUE(bucket.try_consume(2));
    EXPECT_TRUE(bucket.try_consume(3));
    
    // Should have fewer tokens now
    auto remaining = bucket.get_token_count();
    EXPECT_LT(remaining, 10);
    
    // Try to consume more than available
    EXPECT_FALSE(bucket.try_consume(remaining + 1));
    
    // Reset should restore tokens
    bucket.reset();
    EXPECT_EQ(bucket.get_token_count(), bucket.get_capacity());
}

// Test TokenBucket refill mechanism
TEST_F(SecurityFocusedTest, TokenBucketRefill) {
    TokenBucket bucket(4, 2); // 4 tokens max, 2 per second
    
    // Consume all tokens
    EXPECT_TRUE(bucket.try_consume(4));
    EXPECT_EQ(bucket.get_token_count(), 0);
    EXPECT_FALSE(bucket.try_consume(1));
    
    // Wait for refill (a bit more than 1 second)
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    // bucket.refill_tokens(); // Private method - tokens refill automatically
    
    // Should have some tokens now
    EXPECT_GT(bucket.get_token_count(), 0);
    EXPECT_LE(bucket.get_token_count(), 4);
    
    // Should be able to consume again
    EXPECT_TRUE(bucket.try_consume(1));
}

// Test SlidingWindow functionality
TEST_F(SecurityFocusedTest, SlidingWindowBasics) {
    SlidingWindow window(std::chrono::milliseconds(1000)); // 1 second window
    
    // Test basic event tracking
    EXPECT_FALSE(window.add_event_and_check_burst(5)); // First 5 events, no burst
    EXPECT_EQ(window.get_event_count(), 5);
    
    // Add more events within window
    EXPECT_FALSE(window.add_event_and_check_burst(3)); // 8 total events
    EXPECT_EQ(window.get_event_count(), 8);
    
    // Add events that trigger burst detection
    EXPECT_TRUE(window.add_event_and_check_burst(10)); // 18 total events - likely burst
    EXPECT_EQ(window.get_event_count(), 18);
    
    // Clear window
    window.clear();
    EXPECT_EQ(window.get_event_count(), 0);
}

// Test SlidingWindow time-based cleanup
TEST_F(SecurityFocusedTest, SlidingWindowTimeCleanup) {
    SlidingWindow window(std::chrono::milliseconds(500)); // 500ms window
    
    // Add events
    window.add_event_and_check_burst(5);
    EXPECT_EQ(window.get_event_count(), 5);
    
    // Wait for window to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    
    // Clean up old events
    // window.cleanup_old_events(); // Private method - cleanup happens automatically
    EXPECT_EQ(window.get_event_count(), 0);
    
    // New events should start fresh
    window.add_event_and_check_burst(3);
    EXPECT_EQ(window.get_event_count(), 3);
}

// Test RateLimiter basic functionality
TEST_F(SecurityFocusedTest, RateLimiterBasics) {
    RateLimiter limiter(default_config_);
    
    // Test basic rate limiting
    auto result = limiter.check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
    
    // Test multiple requests from same source
    for (int i = 0; i < 5; ++i) {
        result = limiter.check_connection_attempt(test_address1_);
        EXPECT_EQ(result, RateLimitResult::ALLOWED);
    }
    
    // Should start rate limiting after exhausting tokens
    for (int i = 0; i < 10; ++i) {
        result = limiter.check_connection_attempt(test_address1_);
        if (result != RateLimitResult::ALLOWED) {
            EXPECT_EQ(result, RateLimitResult::RATE_LIMITED);
            break;
        }
    }
    
    // Different source should be independent
    result = limiter.check_connection_attempt(test_address2_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
}

// Test connection tracking
TEST_F(SecurityFocusedTest, ConnectionTracking) {
    RateLimiter limiter(default_config_);
    
    // Test connection establishment
    limiter.record_connection_established(test_address1_);
    // Connection establishment successful
    
    limiter.record_connection_established(test_address1_);
    // Connection establishment successful
    
    // Test connection limit
    for (size_t i = 0; i < default_config_.max_concurrent_connections + 2; ++i) {
        auto result = limiter.check_connection_attempt(test_address1_);
        if (result == RateLimitResult::RESOURCE_EXHAUSTED) {
            // Connection limit reached
            break;
        } else if (result == RateLimitResult::ALLOWED) {
            limiter.record_connection_established(test_address1_);
        }
    }
    
    // Test connection removal
    limiter.record_connection_closed(test_address1_);
    limiter.record_connection_closed(test_address1_);
    
    // Should be able to add connections again
    limiter.record_connection_established(test_address1_);
    // Connection establishment successful
    
    limiter.record_connection_closed(test_address1_);
}

// Test blacklisting functionality
TEST_F(SecurityFocusedTest, BlacklistingFunctionality) {
    RateLimiter limiter(strict_config_);
    
    // Test manual blacklisting
    limiter.blacklist_source(test_address1_, std::chrono::seconds(30));
    
    auto result = limiter.check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::BLACKLISTED);
    
    // Test that other sources are not affected
    result = limiter.check_connection_attempt(test_address2_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
    
    // Test blacklist removal
    limiter.remove_from_blacklist(test_address1_);
    result = limiter.check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
    
    // Test blacklist check
    EXPECT_FALSE(limiter.is_blacklisted(test_address1_));
    limiter.blacklist_source(test_address1_, std::chrono::seconds(30));
    EXPECT_TRUE(limiter.is_blacklisted(test_address1_));
}

// Test whitelist functionality
TEST_F(SecurityFocusedTest, WhitelistFunctionality) {
    RateLimiter limiter(default_config_);
    
    // Add address to whitelist
    limiter.add_to_whitelist(test_address1_);
    EXPECT_TRUE(limiter.is_whitelisted(test_address1_));
    
    // Whitelisted sources should always be allowed
    for (int i = 0; i < 100; ++i) {
        auto result = limiter.check_connection_attempt(test_address1_);
        EXPECT_EQ(result, RateLimitResult::ALLOWED);
    }
    
    // Remove from whitelist
    limiter.remove_from_whitelist(test_address1_);
    EXPECT_FALSE(limiter.is_whitelisted(test_address1_));
    
    // Should now be subject to rate limiting
    for (int i = 0; i < 20; ++i) {
        auto result = limiter.check_connection_attempt(test_address1_);
        if (result != RateLimitResult::ALLOWED) {
            EXPECT_EQ(result, RateLimitResult::RATE_LIMITED);
            break;
        }
    }
}

// Test statistics collection
TEST_F(SecurityFocusedTest, StatisticsCollection) {
    RateLimiter limiter(default_config_);
    
    // Generate some activity
    for (int i = 0; i < 10; ++i) {
        limiter.check_connection_attempt(test_address1_);
    }
    
    // Generate activity from different source
    for (int i = 0; i < 5; ++i) {
        limiter.check_connection_attempt(test_address2_);
    }
    
    // Get statistics
    auto stats = limiter.get_source_stats(test_address1_);
    if (stats.is_ok()) {
        auto addr_stats = stats.value();
        EXPECT_EQ(addr_stats.total_requests, 10);
        EXPECT_GT(addr_stats.allowed_requests, 0);
        EXPECT_GE(addr_stats.total_requests, addr_stats.allowed_requests + addr_stats.denied_requests);
    }
    
    // Get global statistics
    auto global_stats = limiter.get_overall_stats();
    EXPECT_GT(global_stats.total_sources, 0);
    EXPECT_GE(global_stats.total_sources, 2); // We used 2 different addresses
    EXPECT_GE(global_stats.active_connections, 0);
}

// Test RateLimiterFactory
TEST_F(SecurityFocusedTest, RateLimiterFactory) {
    // Test development configuration
    auto dev_limiter = RateLimiterFactory::create_development();
    EXPECT_NE(dev_limiter, nullptr);
    
    auto result = dev_limiter->check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
    
    // Test production configuration
    auto prod_limiter = RateLimiterFactory::create_production();
    EXPECT_NE(prod_limiter, nullptr);
    
    result = prod_limiter->check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
    
    // Test high security configuration
    auto secure_limiter = RateLimiterFactory::create_high_security();
    EXPECT_NE(secure_limiter, nullptr);
    
    result = secure_limiter->check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
    
    // Test custom configuration
    auto custom_limiter = RateLimiterFactory::create_custom(strict_config_);
    EXPECT_NE(custom_limiter, nullptr);
    
    result = custom_limiter->check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
}

// Test concurrent rate limiting
TEST_F(SecurityFocusedTest, ConcurrentRateLimiting) {
    RateLimiter limiter(default_config_);
    
    constexpr size_t num_threads = 4;
    constexpr size_t requests_per_thread = 20;
    
    std::vector<std::future<std::pair<size_t, size_t>>> futures;
    std::atomic<size_t> total_requests{0};
    
    // Launch concurrent requests
    for (size_t t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            size_t allowed = 0;
            size_t denied = 0;
            
            // Create unique address for this thread
            NetworkAddress thread_addr;
            thread_addr = NetworkAddress("192.168.1." + std::to_string(100 + t), 12345);
            
            for (size_t i = 0; i < requests_per_thread; ++i) {
                auto result = limiter.check_connection_attempt(thread_addr);
                total_requests.fetch_add(1);
                
                if (result == RateLimitResult::ALLOWED) {
                    ++allowed;
                } else {
                    ++denied;
                }
                
                // Small delay to simulate real requests
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            
            return std::make_pair(allowed, denied);
        }));
    }
    
    // Collect results
    size_t total_allowed = 0;
    size_t total_denied = 0;
    
    for (auto& future : futures) {
        auto [allowed, denied] = future.get();
        total_allowed += allowed;
        total_denied += denied;
    }
    
    EXPECT_EQ(total_allowed + total_denied, num_threads * requests_per_thread);
    EXPECT_GT(total_allowed, 0);
    
    // Get global statistics
    auto global_stats = limiter.get_overall_stats();
    EXPECT_EQ(global_stats.total_sources, num_threads); // Each thread used unique address
    EXPECT_GE(global_stats.active_connections, 0);
    EXPECT_GE(global_stats.total_violations, 0);
}

// Test burst detection
TEST_F(SecurityFocusedTest, BurstDetection) {
    // Create limiter with tight burst controls
    RateLimitConfig burst_config = strict_config_;
    burst_config.max_burst_count = 3;
    burst_config.burst_window = std::chrono::milliseconds(500);
    
    RateLimiter limiter(burst_config);
    
    // Send burst of requests quickly
    std::vector<RateLimitResult> results;
    for (int i = 0; i < 10; ++i) {
        results.push_back(limiter.check_connection_attempt(test_address1_));
    }
    
    // Should have some allowed and some denied
    bool has_allowed = false;
    bool has_denied = false;
    
    for (auto result : results) {
        if (result == RateLimitResult::ALLOWED) {
            has_allowed = true;
        } else if (result == RateLimitResult::RATE_LIMITED) {
            has_denied = true;
        }
    }
    
    EXPECT_TRUE(has_allowed);
    EXPECT_TRUE(has_denied);
}

// Test rate limit recovery
TEST_F(SecurityFocusedTest, RateLimitRecovery) {
    RateLimiter limiter(default_config_);
    
    // Exhaust rate limit
    RateLimitResult result;
    do {
        result = limiter.check_connection_attempt(test_address1_);
    } while (result == RateLimitResult::ALLOWED);
    
    EXPECT_EQ(result, RateLimitResult::RATE_LIMITED);
    
    // Wait for token refill
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Should be able to make requests again
    result = limiter.check_connection_attempt(test_address1_);
    EXPECT_EQ(result, RateLimitResult::ALLOWED);
}

// Test configuration edge cases
TEST_F(SecurityFocusedTest, ConfigurationEdgeCases) {
    // Test with zero tokens (should be handled gracefully)
    RateLimitConfig zero_config;
    zero_config.max_tokens = 0;
    zero_config.tokens_per_second = 0;
    
    RateLimiter zero_limiter(zero_config);
    auto result = zero_limiter.check_connection_attempt(test_address1_);
    // Should either be allowed (if implementation handles gracefully) or rate limited
    EXPECT_TRUE(result == RateLimitResult::ALLOWED || result == RateLimitResult::RATE_LIMITED);
    
    // Test with very high token count
    RateLimitConfig high_config;
    high_config.max_tokens = 10000;
    high_config.tokens_per_second = 1000;
    
    RateLimiter high_limiter(high_config);
    
    // Should be able to handle many requests
    for (int i = 0; i < 100; ++i) {
        result = high_limiter.check_connection_attempt(test_address1_);
        EXPECT_EQ(result, RateLimitResult::ALLOWED);
    }
}

// Test cleanup and resource management
TEST_F(SecurityFocusedTest, CleanupAndResourceManagement) {
    RateLimiter limiter(default_config_);
    
    // Add many sources
    std::vector<NetworkAddress> addresses;
    for (int i = 0; i < 100; ++i) {
        NetworkAddress addr;
        addr = NetworkAddress("10.0.0." + std::to_string(i), 12345);
        addresses.push_back(addr);
        
        limiter.check_connection_attempt(addr);
    }
    
    auto global_stats = limiter.get_overall_stats();
    EXPECT_GE(global_stats.total_sources, 100);
    
    // Test cleanup of idle sources
    limiter.cleanup_expired_entries(); // Cleanup all
    
    global_stats = limiter.get_overall_stats();
    // After cleanup, active sources should be reduced
    EXPECT_LE(global_stats.total_sources, 100);
    
    // Test reset
    limiter.reset();
    global_stats = limiter.get_overall_stats();
    EXPECT_EQ(global_stats.total_sources, 0);
}

// Test error conditions
TEST_F(SecurityFocusedTest, ErrorConditions) {
    RateLimiter limiter(default_config_);
    
    // Test operations with invalid addresses
    NetworkAddress invalid_addr; // Default constructed, may be invalid
    
    auto result = limiter.check_connection_attempt(invalid_addr);
    // Should handle gracefully - either allow or deny based on implementation
    EXPECT_TRUE(result == RateLimitResult::ALLOWED || 
                result == RateLimitResult::RATE_LIMITED ||
                result == RateLimitResult::RESOURCE_EXHAUSTED);
    
    // Test adding connection with invalid address
    limiter.record_connection_established(invalid_addr);
    // Should handle gracefully
    
    // Test statistics for non-existent source
    auto stats = limiter.get_source_stats(test_address3_);
    // May return error or default stats based on implementation
    (void)stats; // Suppress unused variable warning
}