#include <dtls/security/rate_limiter.h>
#include <dtls/types.h>
#include <dtls/error.h>
#include <iostream>

using namespace dtls::v13::security;
using namespace dtls::v13;

int main() {
    try {
        std::cout << "Testing Rate Limiter Implementation..." << std::endl;
        
        // Create test configuration
        RateLimitConfig config;
        config.max_tokens = 5;
        config.tokens_per_second = 2;
        config.max_concurrent_connections = 3;
        config.max_handshakes_per_minute = 10;
        config.max_burst_count = 3;
        
        std::cout << "✓ Rate limit configuration created" << std::endl;
        
        // Create rate limiter
        RateLimiter limiter(config);
        std::cout << "✓ Rate limiter created" << std::endl;
        
        // Create test address
        NetworkAddress test_address("192.168.1.100", 8080);
        std::cout << "✓ Test address created: " << test_address.get_ip() << ":" << test_address.get_port() << std::endl;
        
        // Test basic connection attempts
        std::cout << "\nTesting basic connection attempts:" << std::endl;
        int allowed_count = 0;
        for (int i = 0; i < config.max_tokens; ++i) {
            auto result = limiter.check_connection_attempt(test_address);
            if (result == RateLimitResult::ALLOWED) {
                allowed_count++;
                std::cout << "  Attempt " << (i+1) << ": ALLOWED" << std::endl;
            } else {
                std::cout << "  Attempt " << (i+1) << ": DENIED" << std::endl;
            }
        }
        
        // Next attempt should be rate limited
        auto result = limiter.check_connection_attempt(test_address);
        if (result == RateLimitResult::RATE_LIMITED) {
            std::cout << "✓ Rate limiting working: " << allowed_count << " attempts allowed, then rate limited" << std::endl;
        } else {
            std::cerr << "✗ Rate limiting failed: Expected RATE_LIMITED, got " << static_cast<int>(result) << std::endl;
            return 1;
        }
        
        // Test whitelist functionality
        std::cout << "\nTesting whitelist functionality:" << std::endl;
        auto whitelist_result = limiter.add_to_whitelist(test_address);
        if (whitelist_result.is_ok()) {
            std::cout << "✓ Address added to whitelist" << std::endl;
            
            if (limiter.is_whitelisted(test_address)) {
                std::cout << "✓ Address confirmed whitelisted" << std::endl;
                
                // Should now be allowed despite being rate limited before
                auto whitelisted_result = limiter.check_connection_attempt(test_address);
                if (whitelisted_result == RateLimitResult::ALLOWED) {
                    std::cout << "✓ Whitelisted address allowed despite rate limits" << std::endl;
                } else {
                    std::cerr << "✗ Whitelisted address was denied" << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "✗ Address not showing as whitelisted" << std::endl;
                return 1;
            }
        } else {
            std::cerr << "✗ Failed to add to whitelist: " << error_message(whitelist_result.error()) << std::endl;
            return 1;
        }
        
        // Test factory methods
        std::cout << "\nTesting factory methods:" << std::endl;
        auto dev_limiter = RateLimiterFactory::create_development();
        auto prod_limiter = RateLimiterFactory::create_production();  
        auto secure_limiter = RateLimiterFactory::create_high_security();
        
        if (dev_limiter && prod_limiter && secure_limiter) {
            std::cout << "✓ All factory methods working" << std::endl;
            std::cout << "  Development: " << dev_limiter->get_config().max_tokens << " tokens" << std::endl;
            std::cout << "  Production: " << prod_limiter->get_config().max_tokens << " tokens" << std::endl;
            std::cout << "  High Security: " << secure_limiter->get_config().max_tokens << " tokens" << std::endl;
        } else {
            std::cerr << "✗ Factory methods failed" << std::endl;
            return 1;
        }
        
        // Test statistics
        std::cout << "\nTesting statistics:" << std::endl;
        auto stats_result = limiter.get_source_stats(test_address);
        if (stats_result.is_ok()) {
            auto stats = stats_result.value();
            std::cout << "✓ Source statistics retrieved:" << std::endl;
            std::cout << "  Total requests: " << stats.total_requests << std::endl;
            std::cout << "  Allowed requests: " << stats.allowed_requests << std::endl;
            std::cout << "  Denied requests: " << stats.denied_requests << std::endl;
        } else {
            std::cerr << "✗ Failed to get statistics: " << error_message(stats_result.error()) << std::endl;
            return 1;
        }
        
        auto overall_stats = limiter.get_overall_stats();
        std::cout << "✓ Overall statistics retrieved:" << std::endl;
        std::cout << "  Total sources: " << overall_stats.total_sources << std::endl;
        std::cout << "  Whitelisted sources: " << overall_stats.whitelisted_sources << std::endl;
        std::cout << "  Blacklisted sources: " << overall_stats.blacklisted_sources << std::endl;
        
        std::cout << "\n🎉 All rate limiter tests passed successfully!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "✗ Exception caught: " << e.what() << std::endl;
        return 1;
    }
}