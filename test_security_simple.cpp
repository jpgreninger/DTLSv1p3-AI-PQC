#include <gtest/gtest.h>
#include <dtls/connection.h>
#include <dtls/crypto/openssl_provider.h>
#include <iostream>

using namespace dtls::v13;

// Simple test to verify the security framework builds and basic functionality works
TEST(SimpleSecurityTest, BasicCryptoProvider) {
    std::cout << "Testing basic crypto provider..." << std::endl;
    
    auto provider = std::make_unique<crypto::OpenSSLProvider>();
    auto init_result = provider->initialize();
    
    EXPECT_TRUE(init_result.is_ok()) << "OpenSSL provider should initialize successfully";
    
    if (init_result.is_ok()) {
        std::cout << "OpenSSL provider initialized successfully" << std::endl;
    } else {
        std::cout << "OpenSSL provider initialization failed: " << init_result.error() << std::endl;
    }
}

TEST(SimpleSecurityTest, ContextCreation) {
    std::cout << "Testing context creation..." << std::endl;
    
    auto client_context = Context::create_client();
    EXPECT_TRUE(client_context.is_ok()) << "Client context should be created successfully";
    
    auto server_context = Context::create_server();
    EXPECT_TRUE(server_context.is_ok()) << "Server context should be created successfully";
    
    if (client_context.is_ok() && server_context.is_ok()) {
        std::cout << "Both client and server contexts created successfully" << std::endl;
        
        // Test initialization
        auto client_init = client_context.value()->initialize();
        EXPECT_TRUE(client_init.is_ok()) << "Client context should initialize successfully";
        
        auto server_init = server_context.value()->initialize();
        EXPECT_TRUE(server_init.is_ok()) << "Server context should initialize successfully";
        
        if (client_init.is_ok() && server_init.is_ok()) {
            std::cout << "Both contexts initialized successfully" << std::endl;
        }
    }
}

TEST(SimpleSecurityTest, CipherSuiteSupport) {
    std::cout << "Testing cipher suite support..." << std::endl;
    
    auto provider = std::make_unique<crypto::OpenSSLProvider>();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    // Test required cipher suites
    std::vector<CipherSuite> required_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384
    };
    
    for (auto suite : required_suites) {
        bool supported = provider->supports_cipher_suite(suite);
        EXPECT_TRUE(supported) << "Required cipher suite should be supported: " << static_cast<int>(suite);
        std::cout << "Cipher suite " << static_cast<int>(suite) << " supported: " << (supported ? "Yes" : "No") << std::endl;
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}