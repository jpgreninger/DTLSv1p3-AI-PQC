#include <gtest/gtest.h>
#include <dtls/security/rate_limiter.h>
#include <dtls/types.h>
#include <thread>
#include <chrono>
#include <vector>

using namespace dtls::v13::security;
using namespace dtls::v13;

class RateLimiterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default test configuration
        test_config_ = RateLimitConfig{};
        test_config_.max_tokens = 10;
        test_config_.tokens_per_second = 2;
        test_config_.max_concurrent_connections = 5;
        test_config_.max_handshakes_per_minute = 10;
        test_config_.max_burst_count = 5;
        test_config_.burst_window = std::chrono::milliseconds{1000};
        test_config_.blacklist_duration = std::chrono::seconds{5};
        test_config_.max_violations_per_hour = 3;
        
        test_address1_ = NetworkAddress::from_string("192.168.1.100:8080").value();
        test_address2_ = NetworkAddress::from_string("192.168.1.101:8080").value();
        test_address3_ = NetworkAddress::from_string("10.0.0.1:443").value();
    }

    RateLimitConfig test_config_;
    NetworkAddress test_address1_;
    NetworkAddress test_address2_;
    NetworkAddress test_address3_;
};

// Basic functionality tests
TEST_F(RateLimiterTest, BasicConnectionAttempts) {
    RateLimiter limiter(test_config_);
    
    // First few attempts should be allowed
    for (int i = 0; i < test_config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_connection_attempt(test_address1_));
    }
    
    // Next attempt should be rate limited (token bucket exhausted)
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_connection_attempt(test_address1_));
}

TEST_F(RateLimiterTest, TokenBucketRefill) {
    RateLimiter limiter(test_config_);
    
    // Exhaust tokens
    for (int i = 0; i < test_config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_connection_attempt(test_address1_));
    }
    
    // Should be rate limited
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_connection_attempt(test_address1_));
    
    // Wait for token refill (2 tokens per second)
    std::this_thread::sleep_for(std::chrono::milliseconds{1500});
    
    // Should have ~3 tokens refilled
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
    
    // Next should be rate limited again
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_connection_attempt(test_address1_));
}

TEST_F(RateLimiterTest, BurstDetection) {
    RateLimiter limiter(test_config_);
    
    // Make burst attempts
    std::vector<RateLimitResult> results;
    for (int i = 0; i < test_config_.max_burst_count + 2; ++i) {
        results.push_back(limiter.check_connection_attempt(test_address1_));
    }
    
    // First max_burst_count should be allowed, then rate limited due to burst
    for (size_t i = 0; i < test_config_.max_burst_count; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, results[i]) 
            << "Request " << i << " should be allowed";
    }
    
    // Additional requests should be rate limited due to burst detection
    for (size_t i = test_config_.max_burst_count; i < results.size(); ++i) {
        EXPECT_EQ(RateLimitResult::RATE_LIMITED, results[i]) 
            << "Request " << i << " should be rate limited";
    }
}

TEST_F(RateLimiterTest, ConcurrentConnectionLimits) {
    RateLimiter limiter(test_config_);
    
    // Establish connections up to limit
    for (int i = 0; i < test_config_.max_concurrent_connections; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_connection_attempt(test_address1_));
        limiter.record_connection_established(test_address1_);
    }
    
    // Next connection attempt should be rate limited
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_connection_attempt(test_address1_));
    
    // Close one connection
    limiter.record_connection_closed(test_address1_);
    
    // Should now be able to establish one more
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
}

TEST_F(RateLimiterTest, HandshakeRateLimiting) {
    RateLimiter limiter(test_config_);
    
    // Handshake attempts should be allowed initially
    for (int i = 0; i < test_config_.max_handshakes_per_minute; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_handshake_attempt(test_address1_));
    }
    
    // Next handshake should be rate limited
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_handshake_attempt(test_address1_));
}

// Whitelist and blacklist tests
TEST_F(RateLimiterTest, WhitelistFunctionality) {
    RateLimiter limiter(test_config_);
    
    // Add to whitelist
    EXPECT_TRUE(limiter.add_to_whitelist(test_address1_).is_ok());
    EXPECT_TRUE(limiter.is_whitelisted(test_address1_));
    EXPECT_FALSE(limiter.is_whitelisted(test_address2_));
    
    // Whitelisted source should always be allowed
    for (int i = 0; i < test_config_.max_tokens * 2; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_connection_attempt(test_address1_));
    }
    
    // Remove from whitelist
    EXPECT_TRUE(limiter.remove_from_whitelist(test_address1_).is_ok());
    EXPECT_FALSE(limiter.is_whitelisted(test_address1_));
    
    // Should now be subject to rate limiting
    for (int i = 0; i < test_config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_connection_attempt(test_address1_));
    }
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_connection_attempt(test_address1_));
}

TEST_F(RateLimiterTest, ManualBlacklisting) {
    RateLimiter limiter(test_config_);
    
    // Initially allowed
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
    
    // Manually blacklist
    EXPECT_TRUE(limiter.blacklist_source(test_address1_, std::chrono::seconds{2}).is_ok());
    EXPECT_TRUE(limiter.is_blacklisted(test_address1_));
    
    // Should be blacklisted
    EXPECT_EQ(RateLimitResult::BLACKLISTED, 
              limiter.check_connection_attempt(test_address1_));
    
    // Wait for blacklist to expire
    std::this_thread::sleep_for(std::chrono::milliseconds{2100});
    
    // Should no longer be blacklisted
    EXPECT_FALSE(limiter.is_blacklisted(test_address1_));
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
}

TEST_F(RateLimiterTest, AutomaticBlacklisting) {
    RateLimiter limiter(test_config_);
    
    // Generate violations to trigger automatic blacklisting
    for (int i = 0; i < test_config_.max_violations_per_hour; ++i) {
        limiter.record_violation(test_address1_, "test_violation");
    }
    
    // Should be automatically blacklisted
    EXPECT_TRUE(limiter.is_blacklisted(test_address1_));
    EXPECT_EQ(RateLimitResult::BLACKLISTED, 
              limiter.check_connection_attempt(test_address1_));
    
    // Remove from blacklist
    EXPECT_TRUE(limiter.remove_from_blacklist(test_address1_).is_ok());
    EXPECT_FALSE(limiter.is_blacklisted(test_address1_));
}

// Statistics tests
TEST_F(RateLimiterTest, SourceStatistics) {
    RateLimiter limiter(test_config_);
    
    // Initial stats should not exist
    auto stats_result = limiter.get_source_stats(test_address1_);
    EXPECT_FALSE(stats_result.is_ok());
    
    // Make some requests
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
    EXPECT_EQ(RateLimitResult::ALLOWED, 
              limiter.check_connection_attempt(test_address1_));
    
    // Exhaust tokens to trigger rate limiting
    for (int i = 0; i < test_config_.max_tokens; ++i) {
        limiter.check_connection_attempt(test_address1_);
    }
    
    // Get stats
    stats_result = limiter.get_source_stats(test_address1_);
    EXPECT_TRUE(stats_result.is_ok());
    
    auto stats = stats_result.value();
    EXPECT_GT(stats.total_requests, 0);
    EXPECT_GT(stats.allowed_requests, 0);
    EXPECT_GE(stats.denied_requests, 0);
}

TEST_F(RateLimiterTest, OverallStatistics) {
    RateLimiter limiter(test_config_);
    
    // Make requests from multiple sources
    limiter.check_connection_attempt(test_address1_);
    limiter.check_connection_attempt(test_address2_);
    limiter.check_connection_attempt(test_address3_);
    
    limiter.add_to_whitelist(test_address1_);
    limiter.blacklist_source(test_address2_);
    
    auto overall_stats = limiter.get_overall_stats();
    EXPECT_EQ(3, overall_stats.total_sources);
    EXPECT_EQ(1, overall_stats.whitelisted_sources);
    EXPECT_EQ(1, overall_stats.blacklisted_sources);
}

// Edge case and performance tests
TEST_F(RateLimiterTest, MultipleSourcesIsolation) {
    RateLimiter limiter(test_config_);
    
    // Exhaust tokens for address1
    for (int i = 0; i < test_config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_connection_attempt(test_address1_));
    }
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_connection_attempt(test_address1_));
    
    // address2 should still be allowed (independent token buckets)
    for (int i = 0; i < test_config_.max_tokens; ++i) {
        EXPECT_EQ(RateLimitResult::ALLOWED, 
                  limiter.check_connection_attempt(test_address2_));
    }
    EXPECT_EQ(RateLimitResult::RATE_LIMITED, 
              limiter.check_connection_attempt(test_address2_));
}

TEST_F(RateLimiterTest, ConfigurationUpdate) {
    RateLimiter limiter(test_config_);
    
    // Use initial config
    EXPECT_EQ(test_config_.max_tokens, limiter.get_config().max_tokens);
    
    // Update configuration
    RateLimitConfig new_config = test_config_;
    new_config.max_tokens = 20;
    new_config.tokens_per_second = 5;
    
    EXPECT_TRUE(limiter.update_config(new_config).is_ok());
    EXPECT_EQ(20, limiter.get_config().max_tokens);
    EXPECT_EQ(5, limiter.get_config().tokens_per_second);
}

TEST_F(RateLimiterTest, CleanupExpiredEntries) {
    RateLimiter limiter(test_config_);
    
    // Create some activity
    limiter.check_connection_attempt(test_address1_);
    limiter.blacklist_source(test_address1_, std::chrono::seconds{1});
    
    EXPECT_TRUE(limiter.is_blacklisted(test_address1_));
    
    // Wait for blacklist to expire
    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    
    // Cleanup should remove expired blacklist
    limiter.cleanup_expired_entries();
    EXPECT_FALSE(limiter.is_blacklisted(test_address1_));
}

TEST_F(RateLimiterTest, ResetFunctionality) {
    RateLimiter limiter(test_config_);
    
    // Create state
    limiter.check_connection_attempt(test_address1_);
    limiter.add_to_whitelist(test_address2_);
    limiter.blacklist_source(test_address3_);
    
    EXPECT_TRUE(limiter.get_source_stats(test_address1_).is_ok());
    EXPECT_TRUE(limiter.is_whitelisted(test_address2_));
    EXPECT_TRUE(limiter.is_blacklisted(test_address3_));
    
    // Reset should clear all state
    limiter.reset();
    
    EXPECT_FALSE(limiter.get_source_stats(test_address1_).is_ok());
    EXPECT_FALSE(limiter.is_whitelisted(test_address2_));
    EXPECT_FALSE(limiter.is_blacklisted(test_address3_));
}

// Factory tests
TEST_F(RateLimiterTest, FactoryMethods) {
    auto dev_limiter = RateLimiterFactory::create_development();
    auto prod_limiter = RateLimiterFactory::create_production();
    auto secure_limiter = RateLimiterFactory::create_high_security();
    
    EXPECT_NE(nullptr, dev_limiter);
    EXPECT_NE(nullptr, prod_limiter);
    EXPECT_NE(nullptr, secure_limiter);
    
    // Development should have higher limits than production
    EXPECT_GT(dev_limiter->get_config().max_tokens, 
              prod_limiter->get_config().max_tokens);
    EXPECT_GT(dev_limiter->get_config().max_concurrent_connections, 
              prod_limiter->get_config().max_concurrent_connections);
    
    // High security should have lowest limits
    EXPECT_LE(secure_limiter->get_config().max_tokens, 
              prod_limiter->get_config().max_tokens);
    EXPECT_LE(secure_limiter->get_config().max_concurrent_connections, 
              prod_limiter->get_config().max_concurrent_connections);
    
    // Test custom factory
    auto custom_limiter = RateLimiterFactory::create_custom(test_config_);
    EXPECT_NE(nullptr, custom_limiter);
    EXPECT_EQ(test_config_.max_tokens, custom_limiter->get_config().max_tokens);
}

// Concurrent access tests
TEST_F(RateLimiterTest, ConcurrentAccess) {
    RateLimiter limiter(test_config_);
    const int num_threads = 4;
    const int requests_per_thread = 10;
    std::vector<std::thread> threads;
    std::vector<int> allowed_counts(num_threads, 0);
    
    // Launch concurrent threads
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&limiter, &allowed_counts, t, requests_per_thread, this]() {
            for (int i = 0; i < requests_per_thread; ++i) {
                if (limiter.check_connection_attempt(test_address1_) == RateLimitResult::ALLOWED) {
                    allowed_counts[t]++;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Calculate total allowed requests
    int total_allowed = 0;
    for (int count : allowed_counts) {
        total_allowed += count;
    }
    
    // Should not exceed token bucket capacity significantly
    // (allowing some variance due to token refill during test)
    EXPECT_LE(total_allowed, test_config_.max_tokens + 5);
}

// Token bucket specific tests
class TokenBucketTest : public ::testing::Test {
protected:
    void SetUp() override {
        bucket_ = std::make_unique<TokenBucket>(10, 2); // 10 tokens max, 2 per second
    }
    
    std::unique_ptr<TokenBucket> bucket_;
};

TEST_F(TokenBucketTest, BasicConsumption) {
    EXPECT_TRUE(bucket_->try_consume(1));
    EXPECT_TRUE(bucket_->try_consume(5));
    EXPECT_TRUE(bucket_->try_consume(4));
    
    // Should have no tokens left
    EXPECT_FALSE(bucket_->try_consume(1));
    EXPECT_EQ(0, bucket_->get_token_count());
}

TEST_F(TokenBucketTest, Refill) {
    // Consume all tokens
    EXPECT_TRUE(bucket_->try_consume(10));
    EXPECT_FALSE(bucket_->try_consume(1));
    
    // Wait for refill
    std::this_thread::sleep_for(std::chrono::milliseconds{1500});
    
    // Should have ~3 tokens
    EXPECT_GE(bucket_->get_token_count(), 2);
    EXPECT_LE(bucket_->get_token_count(), 4);
}

TEST_F(TokenBucketTest, Reset) {
    bucket_->try_consume(8);
    EXPECT_EQ(2, bucket_->get_token_count());
    
    bucket_->reset();
    EXPECT_EQ(10, bucket_->get_token_count());
}

// Sliding window tests
class SlidingWindowTest : public ::testing::Test {
protected:
    void SetUp() override {
        window_ = std::make_unique<SlidingWindow>(std::chrono::milliseconds{1000});
    }
    
    std::unique_ptr<SlidingWindow> window_;
};

TEST_F(SlidingWindowTest, EventCounting) {
    EXPECT_FALSE(window_->add_event_and_check_burst(5));
    EXPECT_FALSE(window_->add_event_and_check_burst(5));
    EXPECT_FALSE(window_->add_event_and_check_burst(5));
    EXPECT_FALSE(window_->add_event_and_check_burst(5));
    EXPECT_FALSE(window_->add_event_and_check_burst(5));
    
    // 6th event should trigger burst detection
    EXPECT_TRUE(window_->add_event_and_check_burst(5));
    
    EXPECT_EQ(6, window_->get_event_count());
}

TEST_F(SlidingWindowTest, WindowSliding) {
    // Add events
    window_->add_event_and_check_burst(10);
    window_->add_event_and_check_burst(10);
    EXPECT_EQ(2, window_->get_event_count());
    
    // Wait for window to slide
    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    
    // Events should be cleaned up
    EXPECT_EQ(0, window_->get_event_count());
}

TEST_F(SlidingWindowTest, Clear) {
    window_->add_event_and_check_burst(10);
    window_->add_event_and_check_burst(10);
    EXPECT_EQ(2, window_->get_event_count());
    
    window_->clear();
    EXPECT_EQ(0, window_->get_event_count());
}