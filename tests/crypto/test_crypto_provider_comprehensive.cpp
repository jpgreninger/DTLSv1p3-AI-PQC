/**
 * @file test_crypto_provider_comprehensive.cpp
 * @brief Comprehensive tests for DTLS crypto provider system
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>
#include <algorithm>

#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class CryptoProviderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register built-in providers
        auto register_result = builtin::register_all_providers();
        if (register_result.is_error()) {
            // Fallback: register at least the null provider for testing
            builtin::register_null_provider();
        }
        
        // Set up test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<uint8_t>(i % 256);
        }
        
        small_data_ = {0xDE, 0xAD, 0xBE, 0xEF};
        large_data_.resize(4096, 0xAA);
        
        // Test messages for signatures
        test_message_ = "DTLS v1.3 test message for cryptographic operations";
        
        // Test selection criteria
        basic_criteria_.require_hardware_acceleration = false;
        basic_criteria_.require_fips_compliance = false;
        basic_criteria_.allow_software_fallback = true;
        basic_criteria_.minimum_security_level = SecurityLevel::MEDIUM;
        basic_criteria_.require_thread_safety = true;
        
        // Advanced criteria
        advanced_criteria_ = basic_criteria_;
        advanced_criteria_.required_cipher_suites = {
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384
        };
        advanced_criteria_.required_groups = {
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1
        };
        advanced_criteria_.required_signatures = {
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_SECP256R1_SHA256
        };
    }
    
    void TearDown() override {
        // Clean up factory state
        ProviderFactory::instance().reset_all_stats();
    }
    
    std::vector<uint8_t> test_data_;
    std::vector<uint8_t> small_data_;
    std::vector<uint8_t> large_data_;
    std::string test_message_;
    ProviderSelection basic_criteria_;
    ProviderSelection advanced_criteria_;
};

// Test provider factory registration and discovery
TEST_F(CryptoProviderTest, ProviderFactoryRegistrationAndDiscovery) {
    auto& factory = ProviderFactory::instance();
    
    // Test singleton behavior
    auto& factory2 = ProviderFactory::instance();
    EXPECT_EQ(&factory, &factory2);
    
    // Get available providers
    auto providers = factory.available_providers();
    EXPECT_GT(providers.size(), 0); // Should have at least one provider
    
    // Test provider information
    for (const auto& provider_name : providers) {
        auto registration = factory.get_registration(provider_name);
        EXPECT_TRUE(registration.is_ok());
        
        if (registration.is_ok()) {
            auto& reg = registration.value();
            EXPECT_FALSE(reg.name.empty());
            EXPECT_FALSE(reg.description.empty());
            EXPECT_NE(reg.factory, nullptr);
        }
        
        // Test provider availability
        EXPECT_TRUE(factory.is_provider_available(provider_name));
        
        // Test capabilities query
        auto capabilities = factory.get_capabilities(provider_name);
        EXPECT_TRUE(capabilities.is_ok());
        
        if (capabilities.is_ok()) {
            auto& caps = capabilities.value();
            EXPECT_FALSE(caps.provider_name.empty());
            EXPECT_FALSE(caps.provider_version.empty());
        }
    }
    
    // Test all registrations
    auto all_registrations = factory.get_all_registrations();
    EXPECT_EQ(all_registrations.size(), providers.size());
}

// Test provider creation and basic functionality
TEST_F(CryptoProviderTest, ProviderCreationAndBasicFunctionality) {
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    for (const auto& provider_name : providers) {
        // Create provider
        auto provider_result = factory.create_provider(provider_name);
        ASSERT_TRUE(provider_result.is_ok()) << "Failed to create provider: " << provider_name;
        
        auto provider = provider_result.value();
        ASSERT_NE(provider, nullptr);
        
        // Test basic provider information
        EXPECT_FALSE(provider->name().empty());
        EXPECT_FALSE(provider->version().empty());
        EXPECT_TRUE(provider->is_available());
        
        // Test initialization
        auto init_result = provider->initialize();
        EXPECT_TRUE(init_result.is_ok()) << "Failed to initialize provider: " << provider_name;
        
        if (init_result.is_ok()) {
            // Test capabilities
            auto capabilities = provider->capabilities();
            EXPECT_FALSE(capabilities.provider_name.empty());
            EXPECT_FALSE(capabilities.provider_version.empty());
            
            // Test enhanced capabilities
            auto enhanced_caps = provider->enhanced_capabilities();
            EXPECT_EQ(enhanced_caps.provider_name, capabilities.provider_name);
            
            // Test health check
            auto health_result = provider->perform_health_check();
            EXPECT_TRUE(health_result.is_ok());
            
            auto health_status = provider->get_health_status();
            EXPECT_TRUE(health_status == ProviderHealth::HEALTHY || 
                       health_status == ProviderHealth::DEGRADED ||
                       health_status == ProviderHealth::FAILING ||
                       health_status == ProviderHealth::UNAVAILABLE);
            
            // Test performance metrics
            auto metrics = provider->get_performance_metrics();
            EXPECT_GE(metrics.success_count, 0);
            EXPECT_GE(metrics.failure_count, 0);
            
            // Test resource usage
            auto memory_usage = provider->get_memory_usage();
            EXPECT_GE(memory_usage, 0);
            
            auto current_ops = provider->get_current_operations();
            EXPECT_GE(current_ops, 0);
            
            // Test cleanup
            provider->cleanup();
        }
    }
}

// Test random number generation
TEST_F(CryptoProviderTest, RandomNumberGeneration) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    // Test various random generation sizes
    std::vector<size_t> test_sizes = {1, 16, 32, 64, 128, 256, 1024};
    
    for (size_t size : test_sizes) {
        RandomParams params;
        params.length = size;
        params.cryptographically_secure = true;
        
        auto random_result = provider->generate_random(params);
        ASSERT_TRUE(random_result.is_ok()) << "Failed to generate " << size << " random bytes";
        
        auto random_data = random_result.value();
        EXPECT_EQ(random_data.size(), size);
        
        // Test that we get different results on subsequent calls
        if (size >= 16) {
            auto random_result2 = provider->generate_random(params);
            ASSERT_TRUE(random_result2.is_ok());
            
            auto random_data2 = random_result2.value();
            EXPECT_NE(random_data, random_data2); // Should be different (extremely high probability)
        }
    }
    
    // Test with additional entropy
    RandomParams entropy_params;
    entropy_params.length = 32;
    entropy_params.additional_entropy = test_data_;
    
    auto entropy_result = provider->generate_random(entropy_params);
    EXPECT_TRUE(entropy_result.is_ok());
    
    // Test edge cases
    RandomParams zero_params;
    zero_params.length = 0;
    
    auto zero_result = provider->generate_random(zero_params);
    if (zero_result.is_ok()) {
        EXPECT_EQ(zero_result.value().size(), 0);
    }
    
    provider->cleanup();
}

// Test key derivation functions
TEST_F(CryptoProviderTest, KeyDerivationFunctions) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    // Test HKDF
    KeyDerivationParams hkdf_params;
    hkdf_params.secret = test_data_;
    hkdf_params.salt = small_data_;
    hkdf_params.info = std::vector<uint8_t>(test_message_.begin(), test_message_.end());
    hkdf_params.output_length = 32;
    hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
    
    auto hkdf_result = provider->derive_key_hkdf(hkdf_params);
    ASSERT_TRUE(hkdf_result.is_ok());
    
    auto derived_key = hkdf_result.value();
    EXPECT_EQ(derived_key.size(), 32);
    
    // Test reproducibility
    auto hkdf_result2 = provider->derive_key_hkdf(hkdf_params);
    ASSERT_TRUE(hkdf_result2.is_ok());
    EXPECT_EQ(derived_key, hkdf_result2.value());
    
    // Test different output lengths
    for (size_t length : {16, 32, 48, 64}) {
        hkdf_params.output_length = length;
        auto length_result = provider->derive_key_hkdf(hkdf_params);
        EXPECT_TRUE(length_result.is_ok());
        
        if (length_result.is_ok()) {
            EXPECT_EQ(length_result.value().size(), length);
        }
    }
    
    // Test different hash algorithms
    for (auto hash : {HashAlgorithm::SHA256, HashAlgorithm::SHA384, HashAlgorithm::SHA512}) {
        if (provider->supports_hash_algorithm(hash)) {
            hkdf_params.hash_algorithm = hash;
            hkdf_params.output_length = 32;
            
            auto hash_result = provider->derive_key_hkdf(hkdf_params);
            EXPECT_TRUE(hash_result.is_ok());
        }
    }
    
    // Test PBKDF2 if supported
    KeyDerivationParams pbkdf2_params;
    pbkdf2_params.secret = std::vector<uint8_t>(test_message_.begin(), test_message_.end());
    pbkdf2_params.salt = small_data_;
    pbkdf2_params.output_length = 32;
    pbkdf2_params.hash_algorithm = HashAlgorithm::SHA256;
    
    auto pbkdf2_result = provider->derive_key_pbkdf2(pbkdf2_params);
    // PBKDF2 may not be supported by all providers
    if (pbkdf2_result.is_ok()) {
        EXPECT_EQ(pbkdf2_result.value().size(), 32);
    }
    
    provider->cleanup();
}

// Test hash and HMAC functions
TEST_F(CryptoProviderTest, HashAndHMACFunctions) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    // Test hash functions
    std::vector<HashAlgorithm> test_hashes = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512
    };
    
    for (auto hash_algo : test_hashes) {
        if (provider->supports_hash_algorithm(hash_algo)) {
            HashParams hash_params;
            hash_params.data = test_data_;
            hash_params.algorithm = hash_algo;
            
            auto hash_result = provider->compute_hash(hash_params);
            ASSERT_TRUE(hash_result.is_ok()) << "Failed to compute hash for algorithm";
            
            auto hash_value = hash_result.value();
            
            // Verify expected hash sizes
            size_t expected_size = 0;
            switch (hash_algo) {
                case HashAlgorithm::SHA256: expected_size = 32; break;
                case HashAlgorithm::SHA384: expected_size = 48; break;
                case HashAlgorithm::SHA512: expected_size = 64; break;
                default: break;
            }
            
            if (expected_size > 0) {
                EXPECT_EQ(hash_value.size(), expected_size);
            }
            
            // Test reproducibility
            auto hash_result2 = provider->compute_hash(hash_params);
            ASSERT_TRUE(hash_result2.is_ok());
            EXPECT_EQ(hash_value, hash_result2.value());
            
            // Test HMAC with this hash
            HMACParams hmac_params;
            hmac_params.key = small_data_;
            hmac_params.data = test_data_;
            hmac_params.algorithm = hash_algo;
            
            auto hmac_result = provider->compute_hmac(hmac_params);
            ASSERT_TRUE(hmac_result.is_ok());
            
            auto hmac_value = hmac_result.value();
            EXPECT_EQ(hmac_value.size(), expected_size);
            
            // Test HMAC verification
            auto verify_result = provider->verify_hmac_legacy(
                hmac_params.key, hmac_params.data, hmac_value, hash_algo);
            EXPECT_TRUE(verify_result.is_ok());
            EXPECT_TRUE(verify_result.value());
            
            // Test HMAC verification with wrong MAC
            std::vector<uint8_t> wrong_mac = hmac_value;
            if (!wrong_mac.empty()) {
                wrong_mac[0] ^= 0x01; // Flip a bit
                
                auto wrong_verify = provider->verify_hmac_legacy(
                    hmac_params.key, hmac_params.data, wrong_mac, hash_algo);
                EXPECT_TRUE(wrong_verify.is_ok());
                EXPECT_FALSE(wrong_verify.value());
            }
        }
    }
    
    provider->cleanup();
}

// Test AEAD encryption and decryption
TEST_F(CryptoProviderTest, AEADEncryptionAndDecryption) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    // Test different AEAD ciphers
    std::vector<AEADCipher> test_ciphers = {
        AEADCipher::AES_128_GCM,
        AEADCipher::AES_256_GCM,
        AEADCipher::CHACHA20_POLY1305
    };
    
    for (auto cipher : test_ciphers) {
        // Generate appropriate key size
        size_t key_size = 0;
        switch (cipher) {
            case AEADCipher::AES_128_GCM: key_size = 16; break;
            case AEADCipher::AES_256_GCM: key_size = 32; break;
            case AEADCipher::CHACHA20_POLY1305: key_size = 32; break;
            default: continue;
        }
        
        RandomParams key_params;
        key_params.length = key_size;
        auto key_result = provider->generate_random(key_params);
        ASSERT_TRUE(key_result.is_ok());
        auto key = key_result.value();
        
        // Generate nonce
        RandomParams nonce_params;
        nonce_params.length = 12; // 96-bit nonce
        auto nonce_result = provider->generate_random(nonce_params);
        ASSERT_TRUE(nonce_result.is_ok());
        auto nonce = nonce_result.value();
        
        // Test new AEAD interface
        AEADEncryptionParams enc_params;
        enc_params.key = key;
        enc_params.nonce = nonce;
        enc_params.additional_data = small_data_;
        enc_params.plaintext = test_data_;
        enc_params.cipher = cipher;
        
        auto encrypt_result = provider->encrypt_aead(enc_params);
        if (encrypt_result.is_ok()) {
            auto encryption_output = encrypt_result.value();
            EXPECT_FALSE(encryption_output.ciphertext.empty());
            EXPECT_FALSE(encryption_output.tag.empty());
            EXPECT_NE(encryption_output.ciphertext, test_data_); // Should be different
            
            // Test decryption
            AEADDecryptionParams dec_params;
            dec_params.key = key;
            dec_params.nonce = nonce;
            dec_params.additional_data = small_data_;
            dec_params.ciphertext = encryption_output.ciphertext;
            dec_params.tag = encryption_output.tag;
            dec_params.cipher = cipher;
            
            auto decrypt_result = provider->decrypt_aead(dec_params);
            ASSERT_TRUE(decrypt_result.is_ok());
            
            auto decrypted = decrypt_result.value();
            EXPECT_EQ(decrypted, test_data_);
            
            // Test decryption with wrong tag
            std::vector<uint8_t> wrong_tag = encryption_output.tag;
            if (!wrong_tag.empty()) {
                wrong_tag[0] ^= 0x01;
                dec_params.tag = wrong_tag;
                
                auto wrong_decrypt = provider->decrypt_aead(dec_params);
                EXPECT_TRUE(wrong_decrypt.is_error()); // Should fail
            }
            
            // Test decryption with wrong additional data
            dec_params.tag = encryption_output.tag; // Restore correct tag
            dec_params.additional_data = large_data_;
            
            auto wrong_ad_decrypt = provider->decrypt_aead(dec_params);
            EXPECT_TRUE(wrong_ad_decrypt.is_error()); // Should fail
        }
        
        // Test legacy AEAD interface if supported
        AEADParams legacy_params;
        legacy_params.key = key;
        legacy_params.nonce = nonce;
        legacy_params.additional_data = small_data_;
        legacy_params.cipher = cipher;
        
        auto legacy_encrypt = provider->aead_encrypt(legacy_params, test_data_);
        if (legacy_encrypt.is_ok()) {
            auto legacy_ciphertext = legacy_encrypt.value();
            EXPECT_FALSE(legacy_ciphertext.empty());
            
            auto legacy_decrypt = provider->aead_decrypt(legacy_params, legacy_ciphertext);
            EXPECT_TRUE(legacy_decrypt.is_ok());
            
            if (legacy_decrypt.is_ok()) {
                EXPECT_EQ(legacy_decrypt.value(), test_data_);
            }
        }
    }
    
    provider->cleanup();
}

// Test key generation and exchange
TEST_F(CryptoProviderTest, KeyGenerationAndExchange) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    // Test classical ECDHE key generation
    std::vector<NamedGroup> test_groups = {
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::SECP521R1
    };
    
    for (auto group : test_groups) {
        if (provider->supports_named_group(group)) {
            // Generate key pair
            auto keypair_result = provider->generate_key_pair(group);
            ASSERT_TRUE(keypair_result.is_ok()) << "Failed to generate key pair for group";
            
            auto [private_key, public_key] = keypair_result.value();
            ASSERT_NE(private_key, nullptr);
            ASSERT_NE(public_key, nullptr);
            
            EXPECT_TRUE(private_key->is_private());
            EXPECT_FALSE(public_key->is_private());
            EXPECT_EQ(private_key->group(), group);
            EXPECT_EQ(public_key->group(), group);
            
            // Test public key derivation
            auto derived_public = private_key->derive_public_key();
            ASSERT_TRUE(derived_public.is_ok());
            
            auto derived_pub = derived_public.value();
            EXPECT_TRUE(derived_pub->equals(*public_key));
            
            // Generate second key pair for key exchange
            auto keypair2_result = provider->generate_key_pair(group);
            ASSERT_TRUE(keypair2_result.is_ok());
            
            auto [private_key2, public_key2] = keypair2_result.value();
            
            // Test key exchange (Alice computes with her private, Bob's public)
            auto pub2_exported = provider->export_public_key(*public_key2);
            ASSERT_TRUE(pub2_exported.is_ok());
            
            auto pub2_imported = provider->import_public_key(pub2_exported.value());
            ASSERT_TRUE(pub2_imported.is_ok());
            
            KeyExchangeParams kx_params;
            kx_params.group = group;
            kx_params.private_key = private_key.get();
            // Would need peer public key in real scenario
            
            // Note: Full key exchange test would require proper public key serialization
            // which depends on the specific provider implementation
        }
    }
    
    provider->cleanup();
}

// Test ML-KEM post-quantum cryptography
TEST_F(CryptoProviderTest, MLKEMPostQuantumCryptography) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    // Test ML-KEM parameter sets
    std::vector<MLKEMParameterSet> test_param_sets = {
        MLKEMParameterSet::MLKEM512,
        MLKEMParameterSet::MLKEM768,
        MLKEMParameterSet::MLKEM1024
    };
    
    for (auto param_set : test_param_sets) {
        // Test ML-KEM key generation
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = param_set;
        
        auto keypair_result = provider->mlkem_generate_keypair(keygen_params);
        if (keypair_result.is_ok()) {
            auto [public_key, private_key] = keypair_result.value();
            EXPECT_FALSE(public_key.empty());
            EXPECT_FALSE(private_key.empty());
            
            // Test encapsulation
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = param_set;
            encap_params.public_key = public_key;
            
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result.is_ok());
            
            auto encap_output = encap_result.value();
            EXPECT_FALSE(encap_output.ciphertext.empty());
            EXPECT_FALSE(encap_output.shared_secret.empty());
            EXPECT_EQ(encap_output.shared_secret.size(), 32); // ML-KEM always produces 32-byte secrets
            
            // Test decapsulation
            MLKEMDecapParams decap_params;
            decap_params.parameter_set = param_set;
            decap_params.private_key = private_key;
            decap_params.ciphertext = encap_output.ciphertext;
            
            auto decap_result = provider->mlkem_decapsulate(decap_params);
            ASSERT_TRUE(decap_result.is_ok());
            
            auto decapsulated_secret = decap_result.value();
            EXPECT_EQ(decapsulated_secret, encap_output.shared_secret);
            
            // Test pure ML-KEM key exchange if supported
            std::vector<NamedGroup> pure_mlkem_groups = {
                NamedGroup::MLKEM512,
                NamedGroup::MLKEM768,
                NamedGroup::MLKEM1024
            };
            
            for (auto group : pure_mlkem_groups) {
                if (provider->supports_pure_mlkem_group(group)) {
                    PureMLKEMKeyExchangeParams pure_params;
                    pure_params.mlkem_group = group;
                    pure_params.is_encapsulation = true;
                    pure_params.peer_public_key = public_key;
                    
                    auto pure_result = provider->perform_pure_mlkem_key_exchange(pure_params);
                    if (pure_result.is_ok()) {
                        auto pure_output = pure_result.value();
                        EXPECT_FALSE(pure_output.ciphertext.empty());
                        EXPECT_FALSE(pure_output.shared_secret.empty());
                        EXPECT_EQ(pure_output.shared_secret.size(), 32);
                    }
                }
            }
        }
    }
    
    provider->cleanup();
}

// Test hybrid post-quantum key exchange
TEST_F(CryptoProviderTest, HybridPostQuantumKeyExchange) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    std::vector<NamedGroup> hybrid_groups = {
        NamedGroup::ECDHE_P256_MLKEM512,
        NamedGroup::ECDHE_P384_MLKEM768,
        NamedGroup::ECDHE_P521_MLKEM1024
    };
    
    for (auto hybrid_group : hybrid_groups) {
        if (provider->supports_hybrid_group(hybrid_group)) {
            // Get the classical and PQ components
            auto classical_group = crypto::hybrid_pqc::get_classical_group(hybrid_group);
            auto mlkem_param_set = crypto::hybrid_pqc::get_mlkem_parameter_set(hybrid_group);
            
            // Generate classical key pair
            auto classical_keypair = provider->generate_key_pair(classical_group);
            if (classical_keypair.is_error()) continue;
            
            auto [classical_private, classical_public] = classical_keypair.value();
            
            // Generate ML-KEM key pair
            MLKEMKeyGenParams mlkem_keygen;
            mlkem_keygen.parameter_set = mlkem_param_set;
            
            auto mlkem_keypair = provider->mlkem_generate_keypair(mlkem_keygen);
            if (mlkem_keypair.is_error()) continue;
            
            auto [mlkem_public, mlkem_private] = mlkem_keypair.value();
            
            // Test hybrid key exchange
            HybridKeyExchangeParams hybrid_params;
            hybrid_params.hybrid_group = hybrid_group;
            hybrid_params.is_encapsulation = true;
            hybrid_params.classical_peer_public_key = {}; // Would need serialized public key
            hybrid_params.pq_peer_public_key = mlkem_public;
            hybrid_params.classical_private_key = classical_private.get();
            hybrid_params.pq_private_key = mlkem_private;
            
            // Note: This test is simplified - full hybrid key exchange would require
            // proper public key serialization and more complex setup
            auto hybrid_result = provider->perform_hybrid_key_exchange(hybrid_params);
            if (hybrid_result.is_ok()) {
                auto hybrid_output = hybrid_result.value();
                EXPECT_FALSE(hybrid_output.classical_shared_secret.empty());
                EXPECT_FALSE(hybrid_output.pq_shared_secret.empty());
                EXPECT_FALSE(hybrid_output.combined_shared_secret.empty());
                EXPECT_EQ(hybrid_output.pq_shared_secret.size(), 32);
            }
        }
    }
    
    provider->cleanup();
}

// Test provider selection and compatibility
TEST_F(CryptoProviderTest, ProviderSelectionAndCompatibility) {
    auto& factory = ProviderFactory::instance();
    
    // Test default provider creation
    auto default_result = factory.create_default_provider();
    EXPECT_TRUE(default_result.is_ok());
    
    // Test best provider selection with basic criteria
    auto best_result = factory.create_best_provider(basic_criteria_);
    EXPECT_TRUE(best_result.is_ok());
    
    // Test best provider selection with advanced criteria
    auto advanced_result = factory.create_best_provider(advanced_criteria_);
    EXPECT_TRUE(advanced_result.is_ok());
    
    // Test provider compatibility checking
    auto providers = factory.available_providers();
    for (const auto& provider_name : providers) {
        auto compat_result = factory.check_compatibility(provider_name, basic_criteria_);
        EXPECT_TRUE(compat_result.is_ok());
        
        if (compat_result.is_ok()) {
            auto compat = compat_result.value();
            EXPECT_GE(compat.compatibility_score, 0.0);
            EXPECT_LE(compat.compatibility_score, 1.0);
        }
        
        // Test cipher suite support
        for (auto suite : {CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite::TLS_AES_256_GCM_SHA384}) {
            bool supports = factory.supports_cipher_suite(provider_name, suite);
            // Result varies by provider
        }
        
        // Test named group support
        for (auto group : {NamedGroup::SECP256R1, NamedGroup::SECP384R1}) {
            bool supports = factory.supports_named_group(provider_name, group);
            // Result varies by provider
        }
    }
    
    // Test finding compatible providers
    auto compatible_providers = factory.find_compatible_providers(basic_criteria_);
    EXPECT_GT(compatible_providers.size(), 0);
    
    // Test selecting best compatible provider
    auto best_compatible = factory.select_best_compatible_provider(basic_criteria_);
    EXPECT_TRUE(best_compatible.is_ok());
    
    if (best_compatible.is_ok()) {
        EXPECT_FALSE(best_compatible.value().empty());
    }
}

// Test provider health monitoring
TEST_F(CryptoProviderTest, ProviderHealthMonitoring) {
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    // Test individual health checks
    for (const auto& provider_name : providers) {
        auto health_result = factory.perform_health_check(provider_name);
        EXPECT_TRUE(health_result.is_ok());
    }
    
    // Test global health checks
    auto global_health = factory.perform_health_checks();
    EXPECT_TRUE(global_health.is_ok());
    
    // Test healthy/unhealthy provider lists
    auto healthy_providers = factory.get_healthy_providers();
    auto unhealthy_providers = factory.get_unhealthy_providers();
    
    EXPECT_GE(healthy_providers.size(), 0);
    EXPECT_GE(unhealthy_providers.size(), 0);
    EXPECT_EQ(healthy_providers.size() + unhealthy_providers.size(), providers.size());
    
    // Test that healthy and unhealthy lists don't overlap
    for (const auto& healthy : healthy_providers) {
        EXPECT_TRUE(std::find(unhealthy_providers.begin(), unhealthy_providers.end(), healthy) 
                   == unhealthy_providers.end());
    }
}

// Test provider statistics
TEST_F(CryptoProviderTest, ProviderStatistics) {
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    for (const auto& provider_name : providers) {
        // Get initial stats
        auto initial_stats = factory.get_provider_stats(provider_name);
        
        // Create provider to generate some stats
        auto provider_result = factory.create_provider(provider_name);
        if (provider_result.is_ok()) {
            auto provider = provider_result.value();
            
            // Initialize provider
            auto init_result = provider->initialize();
            if (init_result.is_ok()) {
                // Perform some operations to generate stats
                RandomParams rand_params;
                rand_params.length = 32;
                
                for (int i = 0; i < 5; ++i) {
                    auto rand_result = provider->generate_random(rand_params);
                    // Don't care about success/failure, just generating stats
                }
                
                provider->cleanup();
            }
        }
        
        // Get updated stats
        auto updated_stats = factory.get_provider_stats(provider_name);
        EXPECT_GE(updated_stats.creation_count, initial_stats.creation_count);
        
        // Test stats reset
        factory.reset_provider_stats(provider_name);
        auto reset_stats = factory.get_provider_stats(provider_name);
        EXPECT_EQ(reset_stats.creation_count, 0);
        EXPECT_EQ(reset_stats.success_count, 0);
        EXPECT_EQ(reset_stats.failure_count, 0);
    }
    
    // Test reset all stats
    factory.reset_all_stats();
    for (const auto& provider_name : providers) {
        auto stats = factory.get_provider_stats(provider_name);
        EXPECT_EQ(stats.creation_count, 0);
    }
}

// Test ProviderManager RAII wrapper
TEST_F(CryptoProviderTest, ProviderManagerRAII) {
    // Test creation with criteria
    {
        ProviderManager manager(basic_criteria_);
        EXPECT_TRUE(manager.is_initialized());
        EXPECT_NE(manager.get(), nullptr);
        EXPECT_FALSE(manager.current_provider_name().empty());
        
        // Test provider access
        auto* provider = manager.get();
        EXPECT_NE(provider, nullptr);
        
        // Test capabilities access
        auto capabilities = manager.current_capabilities();
        EXPECT_FALSE(capabilities.provider_name.empty());
        
        // Test uptime
        auto uptime = manager.uptime();
        EXPECT_GE(uptime.count(), 0);
        
        // Test provider operations through manager
        EXPECT_FALSE(provider->name().empty());
        EXPECT_TRUE(provider->is_available());
    } // Manager should cleanup automatically
    
    // Test creation with specific provider name
    auto providers = ProviderFactory::instance().available_providers();
    if (!providers.empty()) {
        ProviderManager named_manager(providers[0]);
        EXPECT_TRUE(named_manager.is_initialized());
        EXPECT_EQ(named_manager.current_provider_name(), providers[0]);
    }
    
    // Test move semantics
    {
        ProviderManager manager1(basic_criteria_);
        EXPECT_TRUE(manager1.is_initialized());
        
        ProviderManager manager2 = std::move(manager1);
        EXPECT_FALSE(manager1.is_initialized());
        EXPECT_TRUE(manager2.is_initialized());
        
        ProviderManager manager3(basic_criteria_);
        manager3 = std::move(manager2);
        EXPECT_FALSE(manager2.is_initialized());
        EXPECT_TRUE(manager3.is_initialized());
    }
}

// Test concurrent provider access
TEST_F(CryptoProviderTest, ConcurrentProviderAccess) {
    auto provider_result = ProviderFactory::instance().create_best_provider(basic_criteria_);
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = provider_result.value();
    ASSERT_TRUE(provider->initialize().is_ok());
    
    const int num_threads = 4;
    const int operations_per_thread = 25;
    std::atomic<int> successful_operations{0};
    std::atomic<int> failed_operations{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch threads that perform concurrent crypto operations
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> op_dis(0, 2);
            
            for (int i = 0; i < operations_per_thread; ++i) {
                try {
                    bool success = false;
                    int operation = op_dis(gen);
                    
                    switch (operation) {
                        case 0: {
                            // Random generation
                            RandomParams params;
                            params.length = 32;
                            auto result = provider->generate_random(params);
                            success = result.is_ok();
                            break;
                        }
                        case 1: {
                            // Hash computation
                            HashParams params;
                            params.data = test_data_;
                            params.algorithm = HashAlgorithm::SHA256;
                            auto result = provider->compute_hash(params);
                            success = result.is_ok();
                            break;
                        }
                        case 2: {
                            // HMAC computation
                            HMACParams params;
                            params.key = small_data_;
                            params.data = test_data_;
                            params.algorithm = HashAlgorithm::SHA256;
                            auto result = provider->compute_hmac(params);
                            success = result.is_ok();
                            break;
                        }
                    }
                    
                    if (success) {
                        successful_operations.fetch_add(1);
                    } else {
                        failed_operations.fetch_add(1);
                    }
                    
                } catch (...) {
                    failed_operations.fetch_add(1);
                }
                
                // Small delay
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify results
    int expected_total = num_threads * operations_per_thread;
    EXPECT_EQ(successful_operations.load() + failed_operations.load(), expected_total);
    
    // Most operations should succeed
    EXPECT_GT(successful_operations.load(), expected_total / 2);
    
    provider->cleanup();
}

// Test convenience functions
TEST_F(CryptoProviderTest, ConvenienceFunctions) {
    // Test list available providers
    auto providers = list_available_providers();
    EXPECT_GT(providers.size(), 0);
    
    auto factory_providers = ProviderFactory::instance().available_providers();
    EXPECT_EQ(providers, factory_providers);
    
    // Test is provider available
    for (const auto& provider_name : providers) {
        EXPECT_TRUE(is_provider_available(provider_name));
    }
    
    EXPECT_FALSE(is_provider_available("nonexistent_provider"));
    
    // Test get default provider name
    auto default_name = get_default_provider_name();
    EXPECT_FALSE(default_name.empty());
    
    // Test create crypto provider convenience functions
    auto provider1 = create_crypto_provider();
    EXPECT_TRUE(provider1.is_ok());
    
    auto provider2 = create_crypto_provider(providers[0]);
    EXPECT_TRUE(provider2.is_ok());
    
    auto provider3 = create_best_crypto_provider(basic_criteria_);
    EXPECT_TRUE(provider3.is_ok());
}