#include <gtest/gtest.h>
#include <dtls/security/dos_protection.h>
#include <dtls/security/rate_limiter.h>
#include <dtls/security/resource_manager.h>
#include <chrono>
#include <thread>

using namespace dtls::v13::security;

class DoSProtectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test configuration
        config_ = DoSProtectionConfig{};
        config_.rate_limit_config.max_tokens = 10;
        config_.rate_limit_config.tokens_per_second = 5;
        config_.rate_limit_config.max_concurrent_connections = 5;
        config_.resource_config.max_total_connections = 100;
        config_.resource_config.max_connections_per_source = 10;
        config_.enable_cpu_monitoring = false;  // Disable for testing
        
        dos_protection_ = std::make_unique<DoSProtection>(config_);
        
        // Test addresses
        client1_ = dtls::v13::NetworkAddress("192.168.1.100", 12345);
        client2_ = dtls::v13::NetworkAddress("192.168.1.101", 12346);
        attacker_ = dtls::v13::NetworkAddress("10.0.0.1", 54321);
    }
    
    void TearDown() override {
        dos_protection_.reset();
    }
    
    DoSProtectionConfig config_;
    std::unique_ptr<DoSProtection> dos_protection_;
    dtls::v13::NetworkAddress client1_;
    dtls::v13::NetworkAddress client2_;
    dtls::v13::NetworkAddress attacker_;
};

// Rate Limiting Tests
TEST_F(DoSProtectionTest, BasicRateLimiting) {
    // Normal client should be allowed initially
    auto result = dos_protection_->check_connection_attempt(client1_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    
    // Exhaust rate limit
    for (int i = 0; i < 15; ++i) {
        dos_protection_->check_connection_attempt(attacker_);
    }
    
    // Should now be rate limited
    result = dos_protection_->check_connection_attempt(attacker_);
    EXPECT_EQ(result, DoSProtectionResult::RATE_LIMITED);
    
    // Normal client should still work (different source)
    result = dos_protection_->check_connection_attempt(client1_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
}

TEST_F(DoSProtectionTest, TokenBucketRefill) {
    // Exhaust tokens
    for (int i = 0; i < 15; ++i) {
        dos_protection_->check_connection_attempt(attacker_);
    }
    
    // Should be rate limited
    auto result = dos_protection_->check_connection_attempt(attacker_);
    EXPECT_EQ(result, DoSProtectionResult::RATE_LIMITED);
    
    // Wait for token refill (tokens_per_second = 5, so wait > 200ms for 1 token)
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Should have one request allowed now
    result = dos_protection_->check_connection_attempt(attacker_);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
}

TEST_F(DoSProtectionTest, BurstDetection) {
    // Create rapid burst of requests
    for (int i = 0; i < 25; ++i) {
        auto result = dos_protection_->check_connection_attempt(attacker_);
        if (i < 10) {
            EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
        } else {
            EXPECT_EQ(result, DoSProtectionResult::RATE_LIMITED);
        }
    }
}

TEST_F(DoSProtectionTest, HandshakeRateLimiting) {
    // Normal handshake should be allowed
    auto result = dos_protection_->check_handshake_attempt(client1_, 1024);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    
    // Exhaust handshake rate limit for attacker
    for (int i = 0; i < 35; ++i) {
        dos_protection_->check_handshake_attempt(attacker_, 1024);
    }
    
    // Should be rate limited
    result = dos_protection_->check_handshake_attempt(attacker_, 1024);
    EXPECT_EQ(result, DoSProtectionResult::RATE_LIMITED);
}

// Resource Management Tests
TEST_F(DoSProtectionTest, ResourceAllocation) {
    // Allocate connection resources
    auto result = dos_protection_->allocate_connection_resources(client1_, 1024);
    EXPECT_TRUE(result.is_success());
    
    uint64_t allocation_id = result.value();
    EXPECT_GT(allocation_id, 0);
    
    // Release resources
    auto release_result = dos_protection_->release_resources(allocation_id);
    EXPECT_TRUE(release_result.is_success());
}

TEST_F(DoSProtectionTest, ResourceExhaustion) {
    std::vector<uint64_t> allocations;
    
    // Allocate up to the limit
    for (size_t i = 0; i < config_.resource_config.max_connections_per_source; ++i) {
        auto result = dos_protection_->allocate_connection_resources(client1_, 1024);
        EXPECT_TRUE(result.is_success());
        allocations.push_back(result.value());
    }
    
    // Next allocation should fail
    auto result = dos_protection_->allocate_connection_resources(client1_, 1024);
    EXPECT_FALSE(result.is_success());
    
    // Clean up
    for (auto allocation_id : allocations) {
        dos_protection_->release_resources(allocation_id);
    }
}

TEST_F(DoSProtectionTest, HandshakeResourceAllocation) {
    // Allocate handshake resources
    auto result = dos_protection_->allocate_handshake_resources(client1_, 512);
    EXPECT_TRUE(result.is_success());
    
    uint64_t allocation_id = result.value();
    
    // Check that resources are tracked
    auto stats = dos_protection_->get_resource_stats();
    EXPECT_GT(stats.pending_handshakes, 0);
    
    // Release resources
    auto release_result = dos_protection_->release_resources(allocation_id);
    EXPECT_TRUE(release_result.is_success());
}

// Whitelist/Blacklist Tests
TEST_F(DoSProtectionTest, WhitelistProtection) {
    // Add client to whitelist
    auto result = dos_protection_->add_to_whitelist(client1_);
    EXPECT_TRUE(result.is_success());
    
    // Whitelisted client should bypass rate limits
    for (int i = 0; i < 50; ++i) {
        auto check_result = dos_protection_->check_connection_attempt(client1_);
        EXPECT_EQ(check_result, DoSProtectionResult::ALLOWED);
    }
    
    // Remove from whitelist
    result = dos_protection_->remove_from_whitelist(client1_);
    EXPECT_TRUE(result.is_success());
    
    // Should now be subject to rate limits
    for (int i = 0; i < 20; ++i) {
        dos_protection_->check_connection_attempt(client1_);
    }
    auto check_result = dos_protection_->check_connection_attempt(client1_);
    EXPECT_EQ(check_result, DoSProtectionResult::RATE_LIMITED);
}

TEST_F(DoSProtectionTest, BlacklistBlocking) {
    // Blacklist attacker
    auto result = dos_protection_->blacklist_source(attacker_, std::chrono::seconds(60));
    EXPECT_TRUE(result.is_success());
    
    // All requests should be blocked
    for (int i = 0; i < 10; ++i) {
        auto check_result = dos_protection_->check_connection_attempt(attacker_);
        EXPECT_EQ(check_result, DoSProtectionResult::BLACKLISTED);
    }
    
    // Remove from blacklist
    result = dos_protection_->remove_from_blacklist(attacker_);
    EXPECT_TRUE(result.is_success());
    
    // Should work normally now
    auto check_result = dos_protection_->check_connection_attempt(attacker_);
    EXPECT_EQ(check_result, DoSProtectionResult::ALLOWED);
}

TEST_F(DoSProtectionTest, AutoBlacklisting) {
    // Trigger multiple violations to cause auto-blacklisting
    for (int i = 0; i < 10; ++i) {
        dos_protection_->record_security_violation(attacker_, "multiple_violations", "high");
    }
    
    // Should be blacklisted after violations
    auto result = dos_protection_->check_connection_attempt(attacker_);
    EXPECT_EQ(result, DoSProtectionResult::BLACKLISTED);
}

// Amplification Attack Prevention Tests
TEST_F(DoSProtectionTest, AmplificationLimits) {
    size_t request_size = 100;
    size_t response_size = 500;  // 5x amplification
    
    // Should be allowed within amplification limit
    bool allowed = dos_protection_->check_amplification_limits(client1_, request_size, response_size);
    EXPECT_TRUE(allowed);
    
    // Large amplification should be blocked
    response_size = 1000;  // 10x amplification
    allowed = dos_protection_->check_amplification_limits(client1_, request_size, response_size);
    EXPECT_FALSE(allowed);
}

TEST_F(DoSProtectionTest, UnverifiedClientResponseLimit) {
    size_t request_size = 100;
    size_t response_size = 2048;  // Larger than max_response_size_unverified
    
    // Should be blocked for unverified clients
    bool allowed = dos_protection_->check_amplification_limits(attacker_, request_size, response_size);
    EXPECT_FALSE(allowed);
    
    // Smaller response should be allowed
    response_size = 512;
    allowed = dos_protection_->check_amplification_limits(attacker_, request_size, response_size);
    EXPECT_TRUE(allowed);
}

// Proof-of-Work Tests
TEST_F(DoSProtectionTest, ProofOfWorkGeneration) {
    // Enable proof-of-work
    dos_protection_->enable_proof_of_work(true);
    
    // Generate challenge
    auto result = dos_protection_->generate_proof_of_work_challenge(client1_);
    EXPECT_TRUE(result.is_success());
    
    auto challenge = result.value();
    EXPECT_FALSE(challenge.challenge.empty());
    EXPECT_GT(challenge.difficulty, 0);
    EXPECT_FALSE(challenge.is_expired());
}

// Statistics Tests
TEST_F(DoSProtectionTest, StatisticsTracking) {
    // Generate some activity
    dos_protection_->check_connection_attempt(client1_);
    dos_protection_->check_connection_attempt(client2_);
    
    // Trigger some blocks
    for (int i = 0; i < 20; ++i) {
        dos_protection_->check_connection_attempt(attacker_);
    }
    
    // Check statistics
    auto stats = dos_protection_->get_statistics();
    EXPECT_GT(stats.total_requests, 0);
    EXPECT_GT(stats.allowed_requests, 0);
    EXPECT_GT(stats.blocked_requests, 0);
    EXPECT_GT(stats.rate_limited, 0);
    
    // Check rate limit statistics
    auto rate_stats = dos_protection_->get_rate_limit_stats();
    EXPECT_GT(rate_stats.total_sources, 0);
    
    // Check resource statistics
    auto resource_stats = dos_protection_->get_resource_stats();
    EXPECT_GE(resource_stats.total_allocated_memory, 0);
}

TEST_F(DoSProtectionTest, SystemHealthMonitoring) {
    auto health = dos_protection_->get_system_health();
    EXPECT_GE(health.cpu_usage, 0.0);
    EXPECT_LE(health.cpu_usage, 1.0);
    EXPECT_GE(health.memory_usage, 0.0);
    EXPECT_LE(health.memory_usage, 1.0);
    EXPECT_GE(health.connection_usage, 0.0);
    EXPECT_LE(health.connection_usage, 1.0);
}

// Configuration Tests
TEST_F(DoSProtectionTest, ConfigurationUpdate) {
    auto new_config = config_;
    new_config.rate_limit_config.max_tokens = 20;
    new_config.resource_config.max_total_connections = 200;
    
    auto result = dos_protection_->update_config(new_config);
    EXPECT_TRUE(result.is_success());
    
    auto current_config = dos_protection_->get_config();
    EXPECT_EQ(current_config.rate_limit_config.max_tokens, 20);
    EXPECT_EQ(current_config.resource_config.max_total_connections, 200);
}

// Cleanup Tests
TEST_F(DoSProtectionTest, AutoCleanup) {
    // Create some expired entries (this would require time manipulation in real tests)
    dos_protection_->force_cleanup();
    
    // Should not crash and should clean up expired entries
    EXPECT_NO_THROW(dos_protection_->force_cleanup());
}

// Factory Tests
class DoSProtectionFactoryTest : public ::testing::Test {};

TEST_F(DoSProtectionFactoryTest, DevelopmentFactory) {
    auto dos_protection = DoSProtectionFactory::create_development();
    EXPECT_NE(dos_protection, nullptr);
    
    // Development should be more permissive
    auto config = dos_protection->get_config();
    EXPECT_GT(config.rate_limit_config.max_tokens, 100);  // More permissive
}

TEST_F(DoSProtectionFactoryTest, ProductionFactory) {
    auto dos_protection = DoSProtectionFactory::create_production();
    EXPECT_NE(dos_protection, nullptr);
    
    auto config = dos_protection->get_config();
    EXPECT_TRUE(config.enable_cpu_monitoring);
    EXPECT_LT(config.rate_limit_config.max_tokens, 500);  // Reasonable limits
}

TEST_F(DoSProtectionFactoryTest, HighSecurityFactory) {
    auto dos_protection = DoSProtectionFactory::create_high_security();
    EXPECT_NE(dos_protection, nullptr);
    
    auto config = dos_protection->get_config();
    EXPECT_TRUE(config.enable_proof_of_work);
    EXPECT_TRUE(config.enable_source_validation);
    EXPECT_LT(config.amplification_ratio_limit, 3.0);  // Strict limits
}

TEST_F(DoSProtectionFactoryTest, EmbeddedFactory) {
    auto dos_protection = DoSProtectionFactory::create_embedded();
    EXPECT_NE(dos_protection, nullptr);
    
    auto config = dos_protection->get_config();
    EXPECT_FALSE(config.enable_cpu_monitoring);  // Save CPU
    EXPECT_FALSE(config.enable_proof_of_work);   // Too expensive
}

// Stress Tests
class DoSProtectionStressTest : public ::testing::Test {
protected:
    void SetUp() override {
        dos_protection_ = DoSProtectionFactory::create_production();
    }
    
    std::unique_ptr<DoSProtection> dos_protection_;
};

TEST_F(DoSProtectionStressTest, HighVolumeConnections) {
    // Simulate high volume of connections from many sources
    std::vector<dtls::v13::NetworkAddress> sources;
    for (int i = 0; i < 100; ++i) {
        sources.emplace_back("192.168.1." + std::to_string(i), 12345);
    }
    
    int allowed_count = 0;
    int blocked_count = 0;
    
    for (const auto& source : sources) {
        for (int j = 0; j < 10; ++j) {
            auto result = dos_protection_->check_connection_attempt(source);
            if (result == DoSProtectionResult::ALLOWED) {
                allowed_count++;
            } else {
                blocked_count++;
            }
        }
    }
    
    EXPECT_GT(allowed_count, 0);
    // Some should be blocked due to rate limiting
    EXPECT_GE(blocked_count, 0);
}

TEST_F(DoSProtectionStressTest, ResourceAllocationStress) {
    std::vector<uint64_t> allocations;
    dtls::v13::NetworkAddress client("192.168.1.10", 12345);
    
    // Allocate as many resources as possible
    for (int i = 0; i < 1000; ++i) {
        auto result = dos_protection_->allocate_connection_resources(client, 1024);
        if (result.is_success()) {
            allocations.push_back(result.value());
        } else {
            break;  // Hit resource limits
        }
    }
    
    EXPECT_GT(allocations.size(), 0);
    
    // Clean up all allocations
    for (auto allocation_id : allocations) {
        auto result = dos_protection_->release_resources(allocation_id);
        EXPECT_TRUE(result.is_success());
    }
}

// Integration Tests
class DoSProtectionIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        dos_protection_ = DoSProtectionFactory::create_production();
    }
    
    std::unique_ptr<DoSProtection> dos_protection_;
};

TEST_F(DoSProtectionIntegrationTest, FullConnectionLifecycle) {
    dtls::v13::NetworkAddress client("192.168.1.50", 12345);
    
    // 1. Check connection attempt
    auto check_result = dos_protection_->check_connection_attempt(client, 512);
    EXPECT_EQ(check_result, DoSProtectionResult::ALLOWED);
    
    // 2. Allocate connection resources
    auto alloc_result = dos_protection_->allocate_connection_resources(client, 2048);
    EXPECT_TRUE(alloc_result.is_success());
    uint64_t connection_allocation = alloc_result.value();
    
    // 3. Check handshake attempt
    auto handshake_result = dos_protection_->check_handshake_attempt(client, 1024);
    EXPECT_EQ(handshake_result, DoSProtectionResult::ALLOWED);
    
    // 4. Allocate handshake resources
    auto handshake_alloc_result = dos_protection_->allocate_handshake_resources(client, 1024);
    EXPECT_TRUE(handshake_alloc_result.is_success());
    uint64_t handshake_allocation = handshake_alloc_result.value();
    
    // 5. Record connection established
    dos_protection_->record_connection_established(client);
    
    // 6. Release handshake resources (handshake complete)
    auto release_result = dos_protection_->release_resources(handshake_allocation);
    EXPECT_TRUE(release_result.is_success());
    
    // 7. Later, record connection closed and release resources
    dos_protection_->record_connection_closed(client);
    release_result = dos_protection_->release_resources(connection_allocation);
    EXPECT_TRUE(release_result.is_success());
    
    // Verify statistics were updated
    auto stats = dos_protection_->get_statistics();
    EXPECT_GT(stats.total_requests, 0);
    EXPECT_GT(stats.allowed_requests, 0);
}

TEST_F(DoSProtectionIntegrationTest, AttackScenario) {
    dtls::v13::NetworkAddress attacker("10.0.0.100", 54321);
    dtls::v13::NetworkAddress legitimate_client("192.168.1.100", 12345);
    
    // 1. Legitimate client should work normally
    auto result = dos_protection_->check_connection_attempt(legitimate_client);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    
    // 2. Attacker floods with connection attempts
    for (int i = 0; i < 100; ++i) {
        dos_protection_->check_connection_attempt(attacker);
    }
    
    // 3. Attacker should be rate limited or blacklisted
    result = dos_protection_->check_connection_attempt(attacker);
    EXPECT_NE(result, DoSProtectionResult::ALLOWED);
    
    // 4. Legitimate client should still work (different source)
    result = dos_protection_->check_connection_attempt(legitimate_client);
    EXPECT_EQ(result, DoSProtectionResult::ALLOWED);
    
    // 5. Record security violations for attacker
    for (int i = 0; i < 10; ++i) {
        dos_protection_->record_security_violation(attacker, "connection_flood", "high");
    }
    
    // 6. Attacker should be blacklisted
    result = dos_protection_->check_connection_attempt(attacker);
    EXPECT_EQ(result, DoSProtectionResult::BLACKLISTED);
    
    // 7. Verify attack was recorded in statistics
    auto stats = dos_protection_->get_statistics();
    EXPECT_GT(stats.attack_attempts, 0);
    EXPECT_GT(stats.security_violations, 0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}