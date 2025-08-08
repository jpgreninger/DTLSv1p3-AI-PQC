#include <iostream>
#include <dtls/crypto/provider_factory.h>

using namespace dtls::v13::crypto;

int main() {
    // Initialize providers
    builtin::register_all_providers();
    
    auto& factory = ProviderFactory::instance();
    
    // Test basic functionality
    std::cout << "=== Provider Selection Test ===\n";
    
    // List available providers
    auto providers = factory.available_providers();
    std::cout << "Available providers: ";
    for (const auto& provider : providers) {
        std::cout << provider << " ";
    }
    std::cout << "\n";
    
    // Test cipher suite selection
    auto cipher_result = factory.select_provider_for_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    if (cipher_result.is_success()) {
        std::cout << "Provider for AES_256_GCM_SHA384: " << *cipher_result << "\n";
    } else {
        std::cout << "No provider found for AES_256_GCM_SHA384\n";
    }
    
    // Test key exchange selection
    auto ke_result = factory.select_provider_for_key_exchange(NamedGroup::SECP256R1);
    if (ke_result.is_success()) {
        std::cout << "Provider for SECP256R1: " << *ke_result << "\n";
    } else {
        std::cout << "No provider found for SECP256R1\n";
    }
    
    // Test signature scheme selection
    auto sig_result = factory.select_provider_for_signature(SignatureScheme::RSA_PSS_RSAE_SHA256);
    if (sig_result.is_success()) {
        std::cout << "Provider for RSA_PSS_RSAE_SHA256: " << *sig_result << "\n";
    } else {
        std::cout << "No provider found for RSA_PSS_RSAE_SHA256\n";
    }
    
    // Test preference order functionality
    std::cout << "\n=== Testing Preference Order ===\n";
    factory.set_provider_preference_order({"botan", "openssl"});
    std::cout << "Set preference order: botan, openssl\n";
    
    auto cipher_result2 = factory.select_provider_for_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    if (cipher_result2.is_success()) {
        std::cout << "Provider with preference (botan first): " << *cipher_result2 << "\n";
    }
    
    factory.set_provider_preference_order({"openssl", "botan"});
    std::cout << "Set preference order: openssl, botan\n";
    
    auto cipher_result3 = factory.select_provider_for_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    if (cipher_result3.is_success()) {
        std::cout << "Provider with preference (openssl first): " << *cipher_result3 << "\n";
    }
    
    std::cout << "\n=== Test Complete ===\n";
    return 0;
}