#include <gtest/gtest.h>
#include <dtls/protocol/cookie.h>
#include <dtls/protocol/handshake.h>
#include <dtls/memory/buffer.h>
#include <dtls/error.h>
#include <vector>
#include <chrono>
#include <thread>

using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;
using namespace dtls::v13;

class CookieTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test secret key
        test_secret_key = Buffer(32);
        test_secret_key.resize(32);
        uint8_t* key_data = reinterpret_cast<uint8_t*>(test_secret_key.mutable_data());
        for (size_t i = 0; i < 32; ++i) {
            key_data[i] = static_cast<uint8_t>(i);
        }
        
        // Create test client info
        std::vector<uint8_t> hello_data = {
            0x16, 0x03, 0x03, 0x00, 0x2a, 0x01, 0x00, 0x00,
            0x26, 0x03, 0x03, 0x12, 0x34, 0x56, 0x78
        };
        test_client_info = CookieManager::ClientInfo("192.168.1.100", 443, hello_data);
        
        // Initialize cookie manager
        cookie_manager = std::make_unique<CookieManager>();
        auto init_result = cookie_manager->initialize(test_secret_key);
        ASSERT_TRUE(init_result.is_success());
    }
    
    void TearDown() override {
        cookie_manager.reset();
    }
    
    Buffer test_secret_key;
    CookieManager::ClientInfo test_client_info;
    std::unique_ptr<CookieManager> cookie_manager;
};

// Basic Cookie Manager Tests
TEST_F(CookieTest, ManagerInitialization) {
    CookieManager manager;
    
    // Should fail without initialization
    auto cookie_result = manager.generate_cookie(test_client_info);
    EXPECT_FALSE(cookie_result.is_success());
    EXPECT_EQ(cookie_result.error(), DTLSError::NOT_INITIALIZED);
    
    // Should succeed after initialization
    auto init_result = manager.initialize(test_secret_key);
    EXPECT_TRUE(init_result.is_success());
    
    cookie_result = manager.generate_cookie(test_client_info);
    EXPECT_TRUE(cookie_result.is_success());
}

TEST_F(CookieTest, InvalidSecretKey) {
    CookieManager manager;
    
    // Too short secret key should fail
    Buffer short_key(8);
    short_key.resize(8);
    
    auto init_result = manager.initialize(short_key);
    EXPECT_FALSE(init_result.is_success());
    EXPECT_EQ(init_result.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(CookieTest, CookieGeneration) {
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    
    Buffer cookie = std::move(cookie_result.value());
    EXPECT_GT(cookie.size(), 16); // Should be reasonably sized
    EXPECT_LE(cookie.size(), 255); // Should not exceed maximum
    
    // Cookie should be valid format
    EXPECT_TRUE(dtls::v13::protocol::is_valid_cookie_format(cookie));
}

TEST_F(CookieTest, CookieValidation) {
    // Generate cookie
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    Buffer cookie = std::move(cookie_result.value());
    
    // Validate with correct client info
    auto validation_result = cookie_manager->validate_cookie(cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::VALID);
    
    // Validate with wrong client info
    CookieManager::ClientInfo wrong_client("192.168.1.101", 443, test_client_info.client_hello_data);
    validation_result = cookie_manager->validate_cookie(cookie, wrong_client);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::CLIENT_MISMATCH);
}

TEST_F(CookieTest, CookieConsumption) {
    // Generate and validate cookie
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    Buffer cookie = std::move(cookie_result.value());
    
    // First validation should succeed
    auto validation_result = cookie_manager->validate_cookie(cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::VALID);
    
    // Consume the cookie
    cookie_manager->consume_cookie(cookie, test_client_info);
    
    // Second validation should detect replay
    validation_result = cookie_manager->validate_cookie(cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::REPLAY_DETECTED);
}

TEST_F(CookieTest, CookieExpiration) {
    // Create manager with short expiration time
    CookieConfig config;
    config.cookie_lifetime = std::chrono::seconds(1);
    CookieManager short_expire_manager(config);
    auto init_result = short_expire_manager.initialize(test_secret_key);
    ASSERT_TRUE(init_result.is_success());
    
    // Generate cookie
    auto cookie_result = short_expire_manager.generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    Buffer cookie = std::move(cookie_result.value());
    
    // Should be valid immediately
    auto validation_result = short_expire_manager.validate_cookie(cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::VALID);
    
    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Should be expired
    validation_result = short_expire_manager.validate_cookie(cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::EXPIRED);
}

TEST_F(CookieTest, ClientNeedsCookie) {
    // New client should need cookie
    EXPECT_TRUE(cookie_manager->client_needs_cookie(test_client_info));
    
    // After generating cookie, client should still need cookie (not consumed yet)
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    
    // Client still needs cookie until it's validated
    EXPECT_TRUE(cookie_manager->client_needs_cookie(test_client_info));
    
    // After validation, client should not need cookie
    Buffer cookie = std::move(cookie_result.value());
    auto validation_result = cookie_manager->validate_cookie(cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::VALID);
    
    // Client should not need cookie now
    EXPECT_FALSE(cookie_manager->client_needs_cookie(test_client_info));
}

TEST_F(CookieTest, MaxCookiesPerClient) {
    CookieConfig config;
    config.max_cookies_per_client = 3;
    CookieManager limited_manager(config);
    auto init_result = limited_manager.initialize(test_secret_key);
    ASSERT_TRUE(init_result.is_success());
    
    std::vector<Buffer> cookies;
    
    // Generate maximum allowed cookies
    for (int i = 0; i < 3; ++i) {
        auto cookie_result = limited_manager.generate_cookie(test_client_info);
        ASSERT_TRUE(cookie_result.is_success());
        cookies.push_back(std::move(cookie_result.value()));
    }
    
    // Generating another cookie should succeed (oldest removed)
    auto cookie_result = limited_manager.generate_cookie(test_client_info);
    EXPECT_TRUE(cookie_result.is_success());
    
    // First cookie should no longer be valid (removed)
    auto validation_result = limited_manager.validate_cookie(cookies[0], test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::NOT_FOUND);
    
    // Later cookies should still be valid
    validation_result = limited_manager.validate_cookie(cookies[2], test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::VALID);
}

TEST_F(CookieTest, CookieCleanup) {
    CookieConfig config;
    config.cookie_lifetime = std::chrono::seconds(1);
    config.cleanup_interval = std::chrono::seconds(1);
    CookieManager cleanup_manager(config);
    auto init_result = cleanup_manager.initialize(test_secret_key);
    ASSERT_TRUE(init_result.is_success());
    
    // Generate some cookies
    auto cookie1_result = cleanup_manager.generate_cookie(test_client_info);
    ASSERT_TRUE(cookie1_result.is_success());
    
    CookieManager::ClientInfo client2("192.168.1.101", 443, test_client_info.client_hello_data);
    auto cookie2_result = cleanup_manager.generate_cookie(client2);
    ASSERT_TRUE(cookie2_result.is_success());
    
    // Check initial statistics
    auto stats = cleanup_manager.get_statistics();
    EXPECT_EQ(stats.cookies_generated, 2);
    EXPECT_EQ(stats.active_cookies, 2);
    
    // Wait for cookies to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Run cleanup
    cleanup_manager.cleanup_expired_cookies();
    
    // Check that cookies were cleaned up
    stats = cleanup_manager.get_statistics();
    EXPECT_EQ(stats.active_cookies, 0);
}

TEST_F(CookieTest, Statistics) {
    auto initial_stats = cookie_manager->get_statistics();
    EXPECT_EQ(initial_stats.cookies_generated, 0);
    EXPECT_EQ(initial_stats.cookies_validated, 0);
    
    // Generate and validate cookie
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    Buffer cookie = std::move(cookie_result.value());
    
    auto validation_result = cookie_manager->validate_cookie(cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::VALID);
    
    // Check updated statistics
    auto stats = cookie_manager->get_statistics();
    EXPECT_EQ(stats.cookies_generated, 1);
    EXPECT_EQ(stats.cookies_validated, 1);
    EXPECT_EQ(stats.active_cookies, 1);
    EXPECT_EQ(stats.validation_failures, 0);
    
    // Try validation with wrong client
    CookieManager::ClientInfo wrong_client("192.168.1.101", 443, test_client_info.client_hello_data);
    validation_result = cookie_manager->validate_cookie(cookie, wrong_client);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::CLIENT_MISMATCH);
    
    // Check failure statistics
    stats = cookie_manager->get_statistics();
    EXPECT_EQ(stats.validation_failures, 1);
}

TEST_F(CookieTest, Reset) {
    // Generate some cookies
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    
    auto stats = cookie_manager->get_statistics();
    EXPECT_GT(stats.cookies_generated, 0);
    EXPECT_GT(stats.active_cookies, 0);
    
    // Reset manager
    cookie_manager->reset();
    
    // Check that everything is cleared
    stats = cookie_manager->get_statistics();
    EXPECT_EQ(stats.cookies_generated, 0);
    EXPECT_EQ(stats.cookies_validated, 0);
    EXPECT_EQ(stats.active_cookies, 0);
}

// Utility Function Tests
TEST_F(CookieTest, ExtractClientInfo) {
    std::vector<uint8_t> hello_data = {0x01, 0x02, 0x03, 0x04};
    
    // Valid address
    auto result = extract_client_info("192.168.1.100:443", hello_data);
    ASSERT_TRUE(result.is_success());
    
    auto client_info = result.value();
    EXPECT_EQ(client_info.client_address, "192.168.1.100");
    EXPECT_EQ(client_info.client_port, 443);
    EXPECT_EQ(client_info.client_hello_data, hello_data);
    
    // Invalid address format
    result = extract_client_info("192.168.1.100", hello_data);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
    
    // Invalid port
    result = extract_client_info("192.168.1.100:invalid", hello_data);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(CookieTest, CookieExtensionUtilities) {
    // Generate test cookie
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    Buffer cookie = std::move(cookie_result.value());
    
    // Create cookie extension
    auto ext_result = create_cookie_extension(cookie);
    ASSERT_TRUE(ext_result.is_success());
    
    Extension extension = ext_result.value();
    EXPECT_EQ(extension.type, dtls::v13::protocol::ExtensionType::COOKIE);
    EXPECT_EQ(extension.data.size(), 2 + cookie.size());
    
    // Extract cookie from extension
    auto extracted_result = dtls::v13::protocol::extract_cookie_from_extension(extension);
    ASSERT_TRUE(extracted_result.is_success());
    
    Buffer extracted_cookie = std::move(extracted_result.value());
    EXPECT_EQ(extracted_cookie.size(), cookie.size());
    EXPECT_EQ(std::memcmp(extracted_cookie.data(), cookie.data(), cookie.size()), 0);
}

TEST_F(CookieTest, InvalidCookieExtraction) {
    // Create non-cookie extension
    Extension wrong_extension;
    wrong_extension.type = dtls::v13::protocol::ExtensionType::SERVER_NAME;
    wrong_extension.data.resize(10);
    
    auto result = dtls::v13::protocol::extract_cookie_from_extension(wrong_extension);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
    
    // Create malformed cookie extension
    Extension malformed_extension;
    malformed_extension.type = dtls::v13::protocol::ExtensionType::COOKIE;
    malformed_extension.data.resize(1); // Too short
    
    result = dtls::v13::protocol::extract_cookie_from_extension(malformed_extension);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_MESSAGE_FORMAT);
}

TEST_F(CookieTest, CookieFormatValidation) {
    // Valid cookie
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    Buffer valid_cookie = std::move(cookie_result.value());
    
    EXPECT_TRUE(dtls::v13::protocol::is_valid_cookie_format(valid_cookie));
    
    // Too small cookie
    Buffer small_cookie(4);
    small_cookie.resize(4);
    EXPECT_FALSE(dtls::v13::protocol::is_valid_cookie_format(small_cookie));
    
    // Too large cookie
    Buffer large_cookie(300);
    large_cookie.resize(300);
    EXPECT_FALSE(dtls::v13::protocol::is_valid_cookie_format(large_cookie));
    
    // Wrong magic number
    Buffer wrong_magic(valid_cookie.size());
    wrong_magic.resize(valid_cookie.size());
    std::memcpy(wrong_magic.mutable_data(), valid_cookie.data(), valid_cookie.size());
    uint8_t* data = reinterpret_cast<uint8_t*>(wrong_magic.mutable_data());
    data[0] = 0xFF; // Change magic number
    EXPECT_FALSE(dtls::v13::protocol::is_valid_cookie_format(wrong_magic));
    
    // Wrong version
    Buffer wrong_version(valid_cookie.size());
    wrong_version.resize(valid_cookie.size());
    std::memcpy(wrong_version.mutable_data(), valid_cookie.data(), valid_cookie.size());
    data = reinterpret_cast<uint8_t*>(wrong_version.mutable_data());
    data[4] = 0xFF; // Change version
    EXPECT_FALSE(dtls::v13::protocol::is_valid_cookie_format(wrong_version));
}

TEST_F(CookieTest, TestCookieGeneration) {
    // Test with default size
    Buffer test_cookie = dtls::v13::protocol::generate_test_cookie();
    EXPECT_EQ(test_cookie.size(), 32);
    
    // Test with custom size
    test_cookie = dtls::v13::protocol::generate_test_cookie(16);
    EXPECT_EQ(test_cookie.size(), 16);
    
    // Test with too small size (should use minimum)
    test_cookie = dtls::v13::protocol::generate_test_cookie(4);
    EXPECT_EQ(test_cookie.size(), 8); // MIN_COOKIE_SIZE
    
    // Test with too large size (should use maximum)
    test_cookie = dtls::v13::protocol::generate_test_cookie(300);
    EXPECT_EQ(test_cookie.size(), 255); // MAX_COOKIE_SIZE
}

// Integration Tests
TEST_F(CookieTest, ClientInfoComparison) {
    CookieManager::ClientInfo client1("192.168.1.100", 443, {0x01, 0x02});
    CookieManager::ClientInfo client2("192.168.1.100", 443, {0x03, 0x04});
    CookieManager::ClientInfo client3("192.168.1.101", 443, {0x01, 0x02});
    
    // Same address and port should be equal regardless of hello data
    EXPECT_TRUE(client1 == client2);
    EXPECT_FALSE(client1 == client3);
    
    // Client ID should include address and port
    EXPECT_EQ(client1.get_client_id(), "192.168.1.100:443");
    EXPECT_EQ(client3.get_client_id(), "192.168.1.101:443");
}

TEST_F(CookieTest, ConfigurationUpdate) {
    CookieConfig new_config;
    new_config.cookie_lifetime = std::chrono::seconds(60);
    new_config.max_cookies_per_client = 5;
    new_config.strict_validation = false;
    
    cookie_manager->update_config(new_config);
    
    // With strict validation disabled, clients shouldn't need cookies
    EXPECT_FALSE(cookie_manager->client_needs_cookie(test_client_info));
}

// Performance Tests
TEST_F(CookieTest, CookieGenerationPerformance) {
    const int iterations = 1000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto cookie_result = cookie_manager->generate_cookie(test_client_info);
        EXPECT_TRUE(cookie_result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should be reasonably fast (less than 1ms per operation on average)
    EXPECT_LT(duration.count() / iterations, 1000);
    
    std::cout << "Average cookie generation time: " 
              << (duration.count() / iterations) << " microseconds" << std::endl;
}

TEST_F(CookieTest, CookieValidationPerformance) {
    const int iterations = 1000;
    
    // Generate cookie once
    auto cookie_result = cookie_manager->generate_cookie(test_client_info);
    ASSERT_TRUE(cookie_result.is_success());
    Buffer cookie = std::move(cookie_result.value());
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto validation_result = cookie_manager->validate_cookie(cookie, test_client_info);
        // First validation should succeed, subsequent ones should detect replay
        if (i == 0) {
            EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::VALID);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should be reasonably fast
    EXPECT_LT(duration.count() / iterations, 500);
    
    std::cout << "Average cookie validation time: " 
              << (duration.count() / iterations) << " microseconds" << std::endl;
}

// Edge Cases
TEST_F(CookieTest, EmptyCookieHandling) {
    Buffer empty_cookie;
    
    // Should fail validation
    auto validation_result = cookie_manager->validate_cookie(empty_cookie, test_client_info);
    EXPECT_EQ(validation_result, CookieManager::CookieValidationResult::INVALID);
    
    // Should fail format validation
    EXPECT_FALSE(dtls::v13::protocol::is_valid_cookie_format(empty_cookie));
    
    // Should fail extension creation
    auto ext_result = create_cookie_extension(empty_cookie);
    EXPECT_FALSE(ext_result.is_success());
}

TEST_F(CookieTest, ConcurrentAccess) {
    const int num_threads = 4;
    const int operations_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([this, &success_count, operations_per_thread, t]() {
            for (int i = 0; i < operations_per_thread; ++i) {
                // Create unique client info for each thread
                std::string address = "192.168.1." + std::to_string(100 + t);
                CookieManager::ClientInfo client_info(address, 443, test_client_info.client_hello_data);
                
                auto cookie_result = cookie_manager->generate_cookie(client_info);
                if (cookie_result.is_success()) {
                    auto validation_result = cookie_manager->validate_cookie(
                        cookie_result.value(), client_info);
                    if (validation_result == CookieManager::CookieValidationResult::VALID) {
                        success_count++;
                    }
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All operations should have succeeded
    EXPECT_EQ(success_count.load(), num_threads * operations_per_thread);
}