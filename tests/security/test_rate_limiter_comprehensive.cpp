/**
 * @file test_rate_limiter_comprehensive.cpp
 * @brief Comprehensive tests for DTLS rate limiter
 */

#include <gtest/gtest.h>
#include <memory>
#include <chrono>
#include <thread>
#include <vector>
#include <future>
#include <random>
#include <atomic>

#include "dtls/security/rate_limiter.h"
#include "dtls/types.h"

using namespace dtls::v13;
using namespace dtls::v13::security;
using namespace std::chrono_literals;

class RateLimiterComprehensiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Basic configuration for most tests
        config_.max_tokens = 15;
        config_.tokens_per_second = 10;
        config_.burst_window = std::chrono::milliseconds{1000};
        config_.max_burst_count = 20;
        config_.blacklist_duration = std::chrono::seconds{60};
        config_.max_violations_per_hour = 5;
        config_.violation_window = std::chrono::seconds{3600};
        config_.max_concurrent_connections = 10;
        config_.max_handshakes_per_minute = 30;
        config_.enable_whitelist = true;
        
        rate_limiter_ = std::make_unique<RateLimiter>(config_);
        
        // Test IP addresses
        test_ip1_ = NetworkAddress::from_string("192.168.1.100:5000").value();
        test_ip2_ = NetworkAddress::from_string("192.168.1.101:5000").value();
        test_ip3_ = NetworkAddress::from_string("10.0.0.1:5000").value();
        local_ip_ = NetworkAddress::from_string("127.0.0.1:5000").value();
    }
    
    void TearDown() override {
        rate_limiter_.reset();
    }
    
    RateLimitConfig config_;
    std::unique_ptr<RateLimiter> rate_limiter_;
    NetworkAddress test_ip1_, test_ip2_, test_ip3_, local_ip_;
};

// Test basic rate limiting functionality
TEST_F(RateLimiterComprehensiveTest, BasicRateLimiting) {
    // Should allow initial requests up to token bucket capacity
    for (int i = 0; i < config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, rate_limiter_->check_connection_attempt(test_ip1_));
    }
    
    // Should block subsequent requests (token bucket exhausted)
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, rate_limiter_->check_connection_attempt(test_ip1_));
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, rate_limiter_->check_connection_attempt(test_ip1_));
    
    // Different IP should still be allowed (separate token bucket)
    EXPECT_EQ(RateLimitResult::ALLOWED, rate_limiter_->check_connection_attempt(test_ip2_));
}

// Test rate limiting with time windows
TEST_F(RateLimiterComprehensiveTest, TimeWindowBasedLimiting) {
    // Use up the token allowance
    for (int i = 0; i < config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, rate_limiter_->check_connection_attempt(test_ip1_));
    }
    
    // Should be blocked now
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, rate_limiter_->check_connection_attempt(test_ip1_));
    
    // Wait for token refresh (simulate time passing)
    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // Just over 1 second
    
    // Should have some tokens available now - consume what's available
    int allowed_after_refill = 0;
    for (int i = 0; i < config_.tokens_per_second + 5; ++i) {
        if (rate_limiter_->check_connection_attempt(test_ip1_) == RateLimitResult::ALLOWED) {
            allowed_after_refill++;
        } else {
            break; // Stop when we hit rate limiting
        }
    }
    
    // Should have gotten at least some tokens, but not unlimited
    EXPECT_GT(allowed_after_refill, 0);
    EXPECT_LE(allowed_after_refill, config_.tokens_per_second + 3); // Allow some tolerance
    
    // Should be limited again after consuming available tokens
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, rate_limiter_->check_connection_attempt(test_ip1_));
}

// Test per-IP rate limiting configuration
TEST_F(RateLimiterComprehensiveTest, PerIPRateLimiting) {
    RateLimitConfig per_ip_config;
    per_ip_config.max_tokens = 5;
    per_ip_config.tokens_per_second = 5;
    per_ip_config.max_burst_count = 10;
    per_ip_config.max_concurrent_connections = 10;
    per_ip_config.enable_whitelist = true;
    
    auto per_ip_limiter = std::make_unique<RateLimiter>(per_ip_config);
    
    // Each IP should get its own allowance
    for (int i = 0; i < per_ip_config.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, per_ip_limiter->check_connection_attempt(test_ip1_));
        EXPECT_EQ(RateLimitResult::ALLOWED, per_ip_limiter->check_connection_attempt(test_ip2_));
        EXPECT_EQ(RateLimitResult::ALLOWED, per_ip_limiter->check_connection_attempt(test_ip3_));
    }
    
    // All IPs should be limited now (tokens exhausted)
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, per_ip_limiter->check_connection_attempt(test_ip1_));
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, per_ip_limiter->check_connection_attempt(test_ip2_));
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, per_ip_limiter->check_connection_attempt(test_ip3_));
}

// Test concurrent connection limiting
TEST_F(RateLimiterComprehensiveTest, ConcurrentConnectionLimiting) {
    RateLimitConfig concurrent_config;
    concurrent_config.max_tokens = 50; // High to avoid token limiting
    concurrent_config.tokens_per_second = 50;
    concurrent_config.max_burst_count = 50; // High to avoid burst limiting
    concurrent_config.max_concurrent_connections = 5; // Low to test this limit
    concurrent_config.max_handshakes_per_minute = 100;
    
    auto concurrent_limiter = std::make_unique<RateLimiter>(concurrent_config);
    
    // Should allow connections up to limit
    for (int i = 0; i < concurrent_config.max_concurrent_connections; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, concurrent_limiter->check_connection_attempt(test_ip1_));
        concurrent_limiter->record_connection_established(test_ip1_);
    }
    
    // Next connection should be blocked (concurrent limit reached)
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, concurrent_limiter->check_connection_attempt(test_ip1_));
    
    // Close one connection
    concurrent_limiter->record_connection_closed(test_ip1_);
    
    // Should now be able to establish one more
    EXPECT_EQ(RateLimitResult::ALLOWED, concurrent_limiter->check_connection_attempt(test_ip1_));
}

// Test burst detection
TEST_F(RateLimiterComprehensiveTest, BurstDetection) {
    RateLimitConfig burst_config;
    burst_config.max_tokens = 50; // High to avoid token limiting
    burst_config.tokens_per_second = 50;
    burst_config.max_burst_count = 5; // Low to test burst detection
    burst_config.burst_window = std::chrono::milliseconds{1000};
    burst_config.max_concurrent_connections = 50;
    
    auto burst_limiter = std::make_unique<RateLimiter>(burst_config);
    
    // Should allow requests up to burst limit
    for (int i = 0; i < burst_config.max_burst_count; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, burst_limiter->check_connection_attempt(test_ip1_));
    }
    
    // Next request should trigger burst detection
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, burst_limiter->check_connection_attempt(test_ip1_));
    
    // Wait for burst window to pass
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    
    // Should be allowed again
    EXPECT_EQ(RateLimitResult::ALLOWED, burst_limiter->check_connection_attempt(test_ip1_));
}

// Test whitelist and blacklist functionality
TEST_F(RateLimiterComprehensiveTest, WhitelistAndBlacklist) {
    // Add IP to whitelist
    EXPECT_TRUE(rate_limiter_->add_to_whitelist(test_ip1_).is_ok());
    EXPECT_TRUE(rate_limiter_->is_whitelisted(test_ip1_));
    
    // Whitelisted IP should always be allowed
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, rate_limiter_->check_connection_attempt(test_ip1_));
    }
    
    // Add IP to blacklist
    EXPECT_TRUE(rate_limiter_->blacklist_source(test_ip2_, std::chrono::seconds{60}).is_ok());
    EXPECT_TRUE(rate_limiter_->is_blacklisted(test_ip2_));
    
    // Blacklisted IP should always be blocked
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(RateLimitResult::BLACKLISTED, rate_limiter_->check_connection_attempt(test_ip2_));
    }
    
    // Regular IP should follow normal rate limiting
    for (int i = 0; i < config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, rate_limiter_->check_connection_attempt(test_ip3_));
    }
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, rate_limiter_->check_connection_attempt(test_ip3_));
    
    // Test removal from lists
    EXPECT_TRUE(rate_limiter_->remove_from_whitelist(test_ip1_).is_ok());
    EXPECT_TRUE(rate_limiter_->remove_from_blacklist(test_ip2_).is_ok());
    EXPECT_FALSE(rate_limiter_->is_whitelisted(test_ip1_));
    EXPECT_FALSE(rate_limiter_->is_blacklisted(test_ip2_));
}

// Test rate limiter statistics
TEST_F(RateLimiterComprehensiveTest, Statistics) {
    // Generate some traffic
    int allowed_count = 0;
    int blocked_count = 0;
    
    for (int i = 0; i < 50; ++i) {
        auto result1 = rate_limiter_->check_connection_attempt(test_ip1_);
        if (result1 == RateLimitResult::ALLOWED) {
            allowed_count++;
        } else {
            blocked_count++;
        }
        
        auto result2 = rate_limiter_->check_connection_attempt(test_ip2_);
        if (result2 == RateLimitResult::ALLOWED) {
            allowed_count++;
        } else {
            blocked_count++;
        }
    }
    
    // Test source-specific statistics
    auto stats1_result = rate_limiter_->get_source_stats(test_ip1_);
    auto stats2_result = rate_limiter_->get_source_stats(test_ip2_);
    
    EXPECT_TRUE(stats1_result.is_ok());
    EXPECT_TRUE(stats2_result.is_ok());
    
    auto stats1 = stats1_result.value();
    auto stats2 = stats2_result.value();
    
    EXPECT_GT(stats1.total_requests, 0);
    EXPECT_GT(stats2.total_requests, 0);
    EXPECT_GE(stats1.allowed_requests, 0);
    EXPECT_GE(stats2.allowed_requests, 0);
    
    // Test overall statistics
    auto overall_stats = rate_limiter_->get_overall_stats();
    EXPECT_EQ(2, overall_stats.total_sources); // test_ip1_ and test_ip2_
}

// Test concurrent access and thread safety
TEST_F(RateLimiterComprehensiveTest, ConcurrentAccess) {
    constexpr int num_threads = 10;
    constexpr int requests_per_thread = 20;
    
    std::atomic<int> total_allowed{0};
    std::atomic<int> total_blocked{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch multiple threads making concurrent requests
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(1, 4);
            
            for (int i = 0; i < requests_per_thread; ++i) {
                // Use different IPs to test per-IP limiting
                NetworkAddress ip;
                switch (dis(gen)) {
                    case 1: ip = test_ip1_; break;
                    case 2: ip = test_ip2_; break;
                    case 3: ip = test_ip3_; break;
                    case 4: ip = local_ip_; break;
                }
                
                auto result = rate_limiter_->check_connection_attempt(ip);
                if (result == RateLimitResult::ALLOWED) {
                    total_allowed.fetch_add(1);
                } else {
                    total_blocked.fetch_add(1);
                }
                
                // Add small random delay
                std::this_thread::sleep_for(std::chrono::microseconds(dis(gen) * 100));
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    int expected_total = num_threads * requests_per_thread;
    EXPECT_EQ(total_allowed.load() + total_blocked.load(), expected_total);
    
    // Verify statistics consistency by checking individual source stats
    auto overall_stats = rate_limiter_->get_overall_stats();
    EXPECT_GT(overall_stats.total_sources, 0);
    EXPECT_LE(overall_stats.total_sources, 4); // At most 4 IPs used
}

// Test cleanup and memory management
TEST_F(RateLimiterComprehensiveTest, CleanupAndMemoryManagement) {
    RateLimitConfig cleanup_config;
    cleanup_config.max_tokens = 10;
    cleanup_config.tokens_per_second = 10;
    cleanup_config.max_burst_count = 15;
    cleanup_config.blacklist_duration = std::chrono::seconds{2}; // Short for testing
    cleanup_config.max_concurrent_connections = 10;
    
    auto cleanup_limiter = std::make_unique<RateLimiter>(cleanup_config);
    
    // Generate traffic from many different IPs
    std::vector<NetworkAddress> test_ips;
    for (int i = 1; i <= 50; ++i) {
        std::string ip = "192.168.1." + std::to_string(i) + ":5000";
        auto addr_result = NetworkAddress::from_string(ip);
        if (addr_result.is_ok()) {
            test_ips.push_back(addr_result.value());
        }
    }
    
    // Make requests from all IPs
    for (const auto& ip : test_ips) {
        cleanup_limiter->check_connection_attempt(ip);
    }
    
    auto stats_before = cleanup_limiter->get_overall_stats();
    EXPECT_GT(stats_before.total_sources, 25);
    
    // Blacklist some IPs temporarily
    for (int i = 0; i < 5; ++i) {
        cleanup_limiter->blacklist_source(test_ips[i], std::chrono::seconds{1});
    }
    
    // Wait for blacklists to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Force cleanup
    cleanup_limiter->cleanup_expired_entries();
    
    // Verify blacklists have been cleaned up
    for (int i = 0; i < 5; ++i) {
        EXPECT_FALSE(cleanup_limiter->is_blacklisted(test_ips[i]));
    }
}

// Test configuration updates
TEST_F(RateLimiterComprehensiveTest, ConfigurationUpdates) {
    // Initial configuration allows max_tokens requests
    for (int i = 0; i < config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, rate_limiter_->check_connection_attempt(test_ip1_));
    }
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, rate_limiter_->check_connection_attempt(test_ip1_));
    
    // Update configuration to be more restrictive
    RateLimitConfig new_config = config_;
    new_config.max_tokens = 5;
    new_config.tokens_per_second = 5;
    
    EXPECT_TRUE(rate_limiter_->update_config(new_config).is_ok());
    
    // Verify configuration was updated
    EXPECT_EQ(5, rate_limiter_->get_config().max_tokens);
    EXPECT_EQ(5, rate_limiter_->get_config().tokens_per_second);
    
    // Wait for some token refresh
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    
    // Should get new allowance based on updated configuration
    int allowed_after_update = 0;
    for (int i = 0; i < 20; ++i) {
        if (rate_limiter_->check_connection_attempt(test_ip2_) == RateLimitResult::ALLOWED) {
            allowed_after_update++;
        }
    }
    
    EXPECT_LE(allowed_after_update, new_config.tokens_per_second + 2); // Allow some tolerance
}

// Test burst handling and token bucket behavior
TEST_F(RateLimiterComprehensiveTest, BurstHandlingAndTokenBucket) {
    RateLimitConfig burst_config;
    burst_config.max_tokens = 10;        // Token bucket capacity
    burst_config.tokens_per_second = 2;  // Very low refill rate
    burst_config.max_burst_count = 20;   // Higher than token bucket to avoid burst detection
    burst_config.max_concurrent_connections = 20;
    
    auto burst_limiter = std::make_unique<RateLimiter>(burst_config);
    
    // Should allow initial burst up to token bucket capacity
    for (int i = 0; i < burst_config.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, burst_limiter->check_connection_attempt(test_ip1_));
    }
    
    // Should be limited after tokens are exhausted
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, burst_limiter->check_connection_attempt(test_ip1_));
    
    // Wait for token refresh
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    
    // Should get a small number of tokens back
    int tokens_after_wait = 0;
    for (int i = 0; i < 10; ++i) {
        if (burst_limiter->check_connection_attempt(test_ip1_) == RateLimitResult::ALLOWED) {
            tokens_after_wait++;
        }
    }
    
    EXPECT_LE(tokens_after_wait, burst_config.tokens_per_second + 1);
    EXPECT_GT(tokens_after_wait, 0);
}

// Test error handling and edge cases
TEST_F(RateLimiterComprehensiveTest, ErrorHandlingAndEdgeCases) {
    // Test with extremely high rates - should not crash
    RateLimitConfig high_rate_config;
    high_rate_config.max_tokens = 1000000;
    high_rate_config.tokens_per_second = 1000000;
    high_rate_config.max_burst_count = 2000000;
    high_rate_config.max_concurrent_connections = 1000000;
    
    auto high_rate_limiter = std::make_unique<RateLimiter>(high_rate_config);
    
    // Should handle high rates without issues
    for (int i = 0; i < 1000; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, high_rate_limiter->check_connection_attempt(test_ip1_));
    }
    
    // Test statistics overflow protection
    RateLimitConfig overflow_config;
    overflow_config.max_tokens = 1000;
    overflow_config.tokens_per_second = 1000;
    overflow_config.max_burst_count = 2000;
    overflow_config.max_concurrent_connections = 1000;
    
    auto overflow_limiter = std::make_unique<RateLimiter>(overflow_config);
    
    // Generate massive load
    for (int i = 0; i < 10000; ++i) {
        overflow_limiter->check_connection_attempt(test_ip1_);
    }
    
    auto stats = overflow_limiter->get_source_stats(test_ip1_);
    EXPECT_TRUE(stats.is_ok());
    EXPECT_GT(stats.value().total_requests, 0);
    
    // Test overall statistics
    auto overall_stats = overflow_limiter->get_overall_stats();
    EXPECT_GT(overall_stats.total_sources, 0);
}

// Test rate limiter with different attack patterns
TEST_F(RateLimiterComprehensiveTest, AttackPatternResistance) {
    // Test sustained attack pattern
    RateLimitConfig attack_config;
    attack_config.max_tokens = 10;
    attack_config.tokens_per_second = 5;
    attack_config.max_burst_count = 5; // Low burst threshold
    attack_config.burst_window = std::chrono::milliseconds{1000};
    attack_config.max_concurrent_connections = 5;
    attack_config.enable_whitelist = true;
    
    auto attack_limiter = std::make_unique<RateLimiter>(attack_config);
    
    // Rapid burst attack should be detected
    int burst_successful = 0;
    for (int i = 0; i < 20; ++i) {
        if (attack_limiter->check_connection_attempt(test_ip1_) == RateLimitResult::ALLOWED) {
            burst_successful++;
        }
    }
    
    // Should have blocked most requests due to burst detection
    EXPECT_LE(burst_successful, attack_config.max_burst_count + 2); // Allow some tolerance
    
    // Test distributed attack (many IPs)
    std::vector<NetworkAddress> attack_ips;
    for (int i = 1; i <= 20; ++i) {
        std::string ip = "10.0.0." + std::to_string(i) + ":5000";
        auto addr_result = NetworkAddress::from_string(ip);
        if (addr_result.is_ok()) {
            attack_ips.push_back(addr_result.value());
        }
    }
    
    int distributed_success = 0;
    for (int round = 0; round < 10; ++round) {
        for (const auto& ip : attack_ips) {
            if (attack_limiter->check_connection_attempt(ip) == RateLimitResult::ALLOWED) {
                distributed_success++;
            }
        }
    }
    
    // Each IP gets its own token bucket, so distributed attacks can partially succeed
    EXPECT_GT(distributed_success, 0);
    EXPECT_LT(distributed_success, attack_ips.size() * 10); // Should not all succeed
}

// Test performance under load
TEST_F(RateLimiterComprehensiveTest, PerformanceUnderLoad) {
    RateLimitConfig perf_config;
    perf_config.max_tokens = 2000;
    perf_config.tokens_per_second = 1000;
    perf_config.max_burst_count = 2000;
    perf_config.max_concurrent_connections = 2000;
    
    auto perf_limiter = std::make_unique<RateLimiter>(perf_config);
    
    constexpr int total_requests = 10000;
    std::vector<NetworkAddress> perf_ips;
    
    // Create multiple IPs for testing
    for (int i = 1; i <= 10; ++i) {
        std::string ip = "172.16.0." + std::to_string(i) + ":5000";
        auto addr_result = NetworkAddress::from_string(ip);
        if (addr_result.is_ok()) {
            perf_ips.push_back(addr_result.value());
        }
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> ip_dis(0, perf_ips.size() - 1);
    
    for (int i = 0; i < total_requests; ++i) {
        const auto& ip = perf_ips[ip_dis(gen)];
        perf_limiter->check_connection_attempt(ip);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should be able to process requests quickly
    double requests_per_second = (total_requests * 1000000.0) / duration.count();
    EXPECT_GT(requests_per_second, 10000); // Should handle at least 10k requests/second
    
    // Print performance metrics for informational purposes
    std::cout << "Performance: " << requests_per_second << " requests/second" << std::endl;
    std::cout << "Average latency: " << (duration.count() / total_requests) << " μs per request" << std::endl;
    
    // Verify that the rate limiter is still functioning correctly
    auto overall_stats = perf_limiter->get_overall_stats();
    EXPECT_EQ(10, overall_stats.total_sources);
}

// Test handshake rate limiting
TEST_F(RateLimiterComprehensiveTest, HandshakeRateLimiting) {
    RateLimitConfig handshake_config;
    handshake_config.max_tokens = 100; // High to avoid token limiting
    handshake_config.tokens_per_second = 100;
    handshake_config.max_burst_count = 100; // High to avoid burst limiting  
    handshake_config.max_concurrent_connections = 100;
    handshake_config.max_handshakes_per_minute = 5; // Low to test handshake limiting
    
    auto handshake_limiter = std::make_unique<RateLimiter>(handshake_config);
    
    // Should allow handshakes up to limit
    for (int i = 0; i < handshake_config.max_handshakes_per_minute; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, handshake_limiter->check_handshake_attempt(test_ip1_));
    }
    
    // Next handshake should be rate limited
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, handshake_limiter->check_handshake_attempt(test_ip1_));
    
    // Different IP should still be allowed
    EXPECT_EQ(RateLimitResult::ALLOWED, handshake_limiter->check_handshake_attempt(test_ip2_));
}

// Test violation tracking and automatic blacklisting
TEST_F(RateLimiterComprehensiveTest, ViolationTrackingAndBlacklisting) {
    RateLimitConfig violation_config;
    violation_config.max_tokens = 10;
    violation_config.tokens_per_second = 10;
    violation_config.max_burst_count = 10;
    violation_config.max_concurrent_connections = 10;
    violation_config.max_violations_per_hour = 3; // Low threshold for testing
    violation_config.violation_window = std::chrono::seconds{3600};
    violation_config.blacklist_duration = std::chrono::seconds{5};
    
    auto violation_limiter = std::make_unique<RateLimiter>(violation_config);
    
    // Initially should not be blacklisted
    EXPECT_FALSE(violation_limiter->is_blacklisted(test_ip1_));
    
    // Record violations
    for (int i = 0; i < violation_config.max_violations_per_hour; ++i) {
        violation_limiter->record_violation(test_ip1_, "test_violation_" + std::to_string(i));
    }
    
    // Should now be automatically blacklisted
    EXPECT_TRUE(violation_limiter->is_blacklisted(test_ip1_));
    
    // Connection attempts should be blocked
    EXPECT_EQ(RateLimitResult::BLACKLISTED, violation_limiter->check_connection_attempt(test_ip1_));
    
    // Wait for blacklist to expire
    std::this_thread::sleep_for(std::chrono::seconds(6));
    
    // Should no longer be blacklisted
    EXPECT_FALSE(violation_limiter->is_blacklisted(test_ip1_));
}

// Test factory methods
TEST_F(RateLimiterComprehensiveTest, FactoryMethods) {
    auto dev_limiter = RateLimiterFactory::create_development();
    auto prod_limiter = RateLimiterFactory::create_production();
    auto secure_limiter = RateLimiterFactory::create_high_security();
    auto custom_limiter = RateLimiterFactory::create_custom(config_);
    
    EXPECT_NE(nullptr, dev_limiter);
    EXPECT_NE(nullptr, prod_limiter);
    EXPECT_NE(nullptr, secure_limiter);
    EXPECT_NE(nullptr, custom_limiter);
    
    // Development should have higher limits than production
    EXPECT_GT(dev_limiter->get_config().max_tokens, prod_limiter->get_config().max_tokens);
    EXPECT_GT(dev_limiter->get_config().max_concurrent_connections, 
              prod_limiter->get_config().max_concurrent_connections);
    
    // High security should have lowest limits
    EXPECT_LE(secure_limiter->get_config().max_tokens, prod_limiter->get_config().max_tokens);
    EXPECT_LE(secure_limiter->get_config().max_concurrent_connections,
              prod_limiter->get_config().max_concurrent_connections);
    
    // Custom should match our config
    EXPECT_EQ(config_.max_tokens, custom_limiter->get_config().max_tokens);
}

// Test reset functionality
TEST_F(RateLimiterComprehensiveTest, ResetFunctionality) {
    // Create some state
    rate_limiter_->check_connection_attempt(test_ip1_);
    rate_limiter_->add_to_whitelist(test_ip2_);
    rate_limiter_->blacklist_source(test_ip3_);
    
    EXPECT_TRUE(rate_limiter_->get_source_stats(test_ip1_).is_ok());
    EXPECT_TRUE(rate_limiter_->is_whitelisted(test_ip2_));
    EXPECT_TRUE(rate_limiter_->is_blacklisted(test_ip3_));
    
    // Reset should clear all state
    rate_limiter_->reset();
    
    EXPECT_FALSE(rate_limiter_->get_source_stats(test_ip1_).is_ok());
    EXPECT_FALSE(rate_limiter_->is_whitelisted(test_ip2_));
    EXPECT_FALSE(rate_limiter_->is_blacklisted(test_ip3_));
    
    auto overall_stats = rate_limiter_->get_overall_stats();
    EXPECT_EQ(0, overall_stats.total_sources);
    EXPECT_EQ(0, overall_stats.whitelisted_sources);
    EXPECT_EQ(0, overall_stats.blacklisted_sources);
}