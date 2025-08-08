#include <dtls/protocol/cookie.h>
#include <iostream>

using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

int main() {
    // Test generate_test_cookie with size 300
    auto test_cookie = generate_test_cookie(300);
    std::cout << "Test cookie size (expecting 255): " << test_cookie.size() << std::endl;
    
    // Test cookie manager functionality
    CookieConfig config;
    config.strict_validation = true;
    CookieManager manager(config);
    
    // Initialize
    Buffer secret_key(32);
    secret_key.resize(32);
    for (size_t i = 0; i < 32; ++i) {
        reinterpret_cast<uint8_t*>(secret_key.mutable_data())[i] = static_cast<uint8_t>(i);
    }
    
    auto init_result = manager.initialize(secret_key);
    if (!init_result.is_success()) {
        std::cout << "Failed to initialize" << std::endl;
        return 1;
    }
    
    // Test client needs cookie logic
    CookieManager::ClientInfo client_info("192.168.1.100", 443, {0x01, 0x02, 0x03});
    
    std::cout << "Client needs cookie initially: " << manager.client_needs_cookie(client_info) << std::endl;
    
    // Generate cookie
    auto cookie_result = manager.generate_cookie(client_info);
    if (!cookie_result.is_success()) {
        std::cout << "Failed to generate cookie" << std::endl;
        return 1;
    }
    
    std::cout << "Client needs cookie after generation: " << manager.client_needs_cookie(client_info) << std::endl;
    
    // Validate cookie
    Buffer cookie = std::move(cookie_result.value());
    auto validation_result = manager.validate_cookie(cookie, client_info);
    std::cout << "Validation result: " << static_cast<int>(validation_result) << std::endl;
    
    std::cout << "Client needs cookie after validation: " << manager.client_needs_cookie(client_info) << std::endl;
    
    return 0;
}