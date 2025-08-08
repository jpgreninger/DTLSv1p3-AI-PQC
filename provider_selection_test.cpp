#include <iostream>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

void test_provider_selection_basic() {
    std::cout << "=== Basic Provider Selection Test ===\n";
    
    // Initialize providers
    builtin::register_all_providers();
    
    auto& factory = ProviderFactory::instance();
    
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
        std::cout << "✓ Provider for AES_256_GCM_SHA384: " << *cipher_result << "\n";
    } else {
        std::cout << "✗ No provider found for AES_256_GCM_SHA384\n";
    }
    
    // Test key exchange selection
    auto ke_result = factory.select_provider_for_key_exchange(NamedGroup::SECP256R1);
    if (ke_result.is_success()) {
        std::cout << "✓ Provider for SECP256R1: " << *ke_result << "\n";
    } else {
        std::cout << "✗ No provider found for SECP256R1\n";
    }
    
    // Test signature scheme selection
    auto sig_result = factory.select_provider_for_signature(SignatureScheme::RSA_PSS_RSAE_SHA256);
    if (sig_result.is_success()) {
        std::cout << "✓ Provider for RSA_PSS_RSAE_SHA256: " << *sig_result << "\n";
    } else {
        std::cout << "✗ No provider found for RSA_PSS_RSAE_SHA256\n";
    }
}

void test_preference_order() {
    std::cout << "\n=== Preference Order Test ===\n";
    
    auto& factory = ProviderFactory::instance();
    
    // Test with different preference orders
    std::cout << "Setting preference order: [botan, openssl]\n";
    factory.set_provider_preference_order({"botan", "openssl"});
    
    auto cipher_result1 = factory.select_provider_for_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    if (cipher_result1.is_success()) {
        std::cout << "✓ Selected provider: " << *cipher_result1 << "\n";
    }
    
    std::cout << "Setting preference order: [openssl, botan]\n";
    factory.set_provider_preference_order({"openssl", "botan"});
    
    auto cipher_result2 = factory.select_provider_for_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    if (cipher_result2.is_success()) {
        std::cout << "✓ Selected provider: " << *cipher_result2 << "\n";
    }
    
    // Test with empty preference (should fall back to priority)
    std::cout << "Clearing preference order (fall back to priority)\n";
    factory.set_provider_preference_order({});
    
    auto cipher_result3 = factory.select_provider_for_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    if (cipher_result3.is_success()) {
        std::cout << "✓ Selected provider (by priority): " << *cipher_result3 << "\n";
    }
}

void test_provider_capabilities() {
    std::cout << "\n=== Provider Capabilities Test ===\n";
    
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    for (const auto& provider_name : providers) {
        std::cout << "\nProvider: " << provider_name << "\n";
        
        // Test cipher suite support
        bool supports_aes256 = factory.supports_cipher_suite(provider_name, CipherSuite::TLS_AES_256_GCM_SHA384);
        std::cout << "  AES_256_GCM_SHA384: " << (supports_aes256 ? "✓" : "✗") << "\n";
        
        bool supports_aes128 = factory.supports_cipher_suite(provider_name, CipherSuite::TLS_AES_128_GCM_SHA256);
        std::cout << "  AES_128_GCM_SHA256: " << (supports_aes128 ? "✓" : "✗") << "\n";
        
        // Test named group support
        bool supports_p256 = factory.supports_named_group(provider_name, NamedGroup::SECP256R1);
        std::cout << "  SECP256R1: " << (supports_p256 ? "✓" : "✗") << "\n";
        
        bool supports_p384 = factory.supports_named_group(provider_name, NamedGroup::SECP384R1);
        std::cout << "  SECP384R1: " << (supports_p384 ? "✓" : "✗") << "\n";
        
        // Test signature scheme support
        bool supports_rsa_pss = factory.supports_signature_scheme(provider_name, SignatureScheme::RSA_PSS_RSAE_SHA256);
        std::cout << "  RSA_PSS_RSAE_SHA256: " << (supports_rsa_pss ? "✓" : "✗") << "\n";
        
        bool supports_ecdsa = factory.supports_signature_scheme(provider_name, SignatureScheme::ECDSA_SECP256R1_SHA256);
        std::cout << "  ECDSA_SECP256R1_SHA256: " << (supports_ecdsa ? "✓" : "✗") << "\n";
    }
}

void test_error_cases() {
    std::cout << "\n=== Error Cases Test ===\n";
    
    auto& factory = ProviderFactory::instance();
    
    // Test unsupported cipher suite
    auto unsupported_cipher = factory.select_provider_for_cipher_suite(static_cast<CipherSuite>(0xFFFF));
    if (unsupported_cipher.is_error()) {
        std::cout << "✓ Correctly rejected unsupported cipher suite\n";
    } else {
        std::cout << "✗ Should have rejected unsupported cipher suite\n";
    }
    
    // Test unsupported named group
    auto unsupported_group = factory.select_provider_for_key_exchange(static_cast<NamedGroup>(0xFFFF));
    if (unsupported_group.is_error()) {
        std::cout << "✓ Correctly rejected unsupported named group\n";
    } else {
        std::cout << "✗ Should have rejected unsupported named group\n";
    }
    
    // Test unsupported signature scheme
    auto unsupported_sig = factory.select_provider_for_signature(static_cast<SignatureScheme>(0xFFFF));
    if (unsupported_sig.is_error()) {
        std::cout << "✓ Correctly rejected unsupported signature scheme\n";
    } else {
        std::cout << "✗ Should have rejected unsupported signature scheme\n";
    }
}

int main() {
    std::cout << "DTLS v1.3 Provider Selection Comprehensive Test\n";
    std::cout << "==============================================\n";
    
    try {
        test_provider_selection_basic();
        test_preference_order();
        test_provider_capabilities();
        test_error_cases();
        
        std::cout << "\n=== All Tests Completed ===\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << "\n";
        return 1;
    }
}