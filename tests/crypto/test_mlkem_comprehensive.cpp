/**
 * @file test_mlkem_comprehensive.cpp
 * @brief Comprehensive ML-KEM test suite for DTLS v1.3 Pure ML-KEM support
 * 
 * This test suite provides comprehensive validation of the ML-KEM implementation
 * according to draft-connolly-tls-mlkem-key-agreement-05 and FIPS 203.
 * 
 * Test Coverage:
 * - ML-KEM named group detection and validation
 * - Parameter set mapping and key size calculations  
 * - Key generation, encapsulation, decapsulation operations
 * - Error handling for invalid inputs
 * - FIPS 203 compliance validation
 * - Performance benchmarking
 * - Security property validation
 * 
 * @author DTLS v1.3 Test Suite
 * @version 1.0.0
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include "../test_infrastructure/test_utilities.h"
#include <vector>
#include <memory>
#include <string>
#include <chrono>
#include <random>
#include <algorithm>
#include <cmath>
#include <set>
#include <bitset>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

/**
 * Comprehensive test fixture for ML-KEM operations
 */
class MLKEMComprehensiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
        // Initialize all available providers
        auto openssl_result = factory.create_provider("openssl");
        if (openssl_result && openssl_result.value()->is_available()) {
            openssl_provider_ = std::move(openssl_result.value());
            auto init_result = openssl_provider_->initialize();
            if (!init_result) {
                openssl_provider_.reset();
            }
        }
        
        auto botan_result = factory.create_provider("botan");
        if (botan_result && botan_result.value()->is_available()) {
            botan_provider_ = std::move(botan_result.value());
            auto init_result = botan_provider_->initialize();
            if (!init_result) {
                botan_provider_.reset();
            }
        }

        auto hardware_result = factory.create_provider("hardware");
        if (hardware_result && hardware_result.value()->is_available()) {
            hardware_provider_ = std::move(hardware_result.value());
            auto init_result = hardware_provider_->initialize();
            if (!init_result) {
                hardware_provider_.reset();
            }
        }
        
        // Set up test parameters
        ml_kem_groups_ = {
            NamedGroup::MLKEM512,
            NamedGroup::MLKEM768,
            NamedGroup::MLKEM1024
        };
        
        ml_kem_parameter_sets_ = {
            MLKEMParameterSet::MLKEM512,
            MLKEMParameterSet::MLKEM768,
            MLKEMParameterSet::MLKEM1024
        };
        
        // Initialize random engine for tests
        random_engine_.seed(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }
    
    void TearDown() override {
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
        if (hardware_provider_) hardware_provider_->cleanup();
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    std::unique_ptr<CryptoProvider> hardware_provider_;
    
    std::vector<NamedGroup> ml_kem_groups_;
    std::vector<MLKEMParameterSet> ml_kem_parameter_sets_;
    std::mt19937 random_engine_;
    
    // Helper function to get all available providers
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        if (openssl_provider_) providers.push_back(openssl_provider_.get());
        if (botan_provider_) providers.push_back(botan_provider_.get());
        if (hardware_provider_) providers.push_back(hardware_provider_.get());
        return providers;
    }
    
    // Helper function to get parameter set name for logging
    std::string get_param_set_name(MLKEMParameterSet param_set) {
        switch (param_set) {
            case MLKEMParameterSet::MLKEM512: return "ML-KEM-512";
            case MLKEMParameterSet::MLKEM768: return "ML-KEM-768";
            case MLKEMParameterSet::MLKEM1024: return "ML-KEM-1024";
            default: return "Unknown";
        }
    }
    
    // Helper function to get named group name for logging
    std::string get_named_group_name(NamedGroup group) {
        switch (group) {
            case NamedGroup::MLKEM512: return "MLKEM512";
            case NamedGroup::MLKEM768: return "MLKEM768";
            case NamedGroup::MLKEM1024: return "MLKEM1024";
            default: return "Unknown";
        }
    }
    
    // Statistical entropy calculation for randomness testing
    double calculate_shannon_entropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0;
        
        std::array<size_t, 256> freq = {0};
        for (uint8_t byte : data) {
            freq[byte]++;
        }
        
        double entropy = 0.0;
        double data_size = static_cast<double>(data.size());
        
        for (size_t count : freq) {
            if (count > 0) {
                double p = static_cast<double>(count) / data_size;
                entropy -= p * std::log2(p);
            }
        }
        
        return entropy;
    }
    
    // Generate random bytes for testing
    std::vector<uint8_t> generate_random_bytes(size_t length) {
        std::vector<uint8_t> bytes(length);
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (auto& byte : bytes) {
            byte = dist(random_engine_);
        }
        return bytes;
    }
    
    // Validate key sizes match FIPS 203 specification
    void validate_mlkem_key_sizes(MLKEMParameterSet param_set,
                                  const std::vector<uint8_t>& public_key,
                                  const std::vector<uint8_t>& private_key) {
        using namespace hybrid_pqc;
        auto sizes = get_mlkem_sizes(param_set);
        
        EXPECT_EQ(public_key.size(), sizes.public_key_bytes)
            << "Public key size mismatch for " << get_param_set_name(param_set);
            
        EXPECT_EQ(private_key.size(), sizes.private_key_bytes)
            << "Private key size mismatch for " << get_param_set_name(param_set);
    }
    
    // Validate ciphertext and shared secret sizes
    void validate_mlkem_encap_sizes(MLKEMParameterSet param_set,
                                    const std::vector<uint8_t>& ciphertext,
                                    const std::vector<uint8_t>& shared_secret) {
        using namespace hybrid_pqc;
        auto sizes = get_mlkem_sizes(param_set);
        
        EXPECT_EQ(ciphertext.size(), sizes.ciphertext_bytes)
            << "Ciphertext size mismatch for " << get_param_set_name(param_set);
            
        EXPECT_EQ(shared_secret.size(), sizes.shared_secret_bytes)
            << "Shared secret size mismatch for " << get_param_set_name(param_set);
    }
};

// ============================================================================
// UNIT TESTS - Named Group Detection and Validation
// ============================================================================

/**
 * Test ML-KEM named group constants match IANA registry values
 * From draft-connolly-tls-mlkem-key-agreement-05
 */
TEST_F(MLKEMComprehensiveTest, NamedGroupConstants) {
    // Verify IANA registry values
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::MLKEM512), 0x0200)
        << "ML-KEM-512 named group must be 0x0200";
    
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::MLKEM768), 0x0201)
        << "ML-KEM-768 named group must be 0x0201";
    
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::MLKEM1024), 0x0202)
        << "ML-KEM-1024 named group must be 0x0202";
}

/**
 * Test ML-KEM group detection functions
 */
TEST_F(MLKEMComprehensiveTest, GroupDetection) {
    using namespace pqc_utils;
    
    // Test pure ML-KEM group detection
    for (auto group : ml_kem_groups_) {
        EXPECT_TRUE(is_pure_mlkem_group(group))
            << "Group " << get_named_group_name(group) << " should be detected as pure ML-KEM";
    }
    
    // Test classical groups are not detected as pure ML-KEM
    std::vector<NamedGroup> classical_groups = {
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::SECP521R1,
        NamedGroup::X25519,
        NamedGroup::X448
    };
    
    for (auto group : classical_groups) {
        EXPECT_FALSE(is_pure_mlkem_group(group))
            << "Classical group should not be detected as pure ML-KEM";
    }
    
    // Test hybrid groups are not detected as pure ML-KEM
    std::vector<NamedGroup> hybrid_groups = {
        NamedGroup::ECDHE_P256_MLKEM512,
        NamedGroup::ECDHE_P384_MLKEM768,
        NamedGroup::ECDHE_P521_MLKEM1024
    };
    
    for (auto group : hybrid_groups) {
        EXPECT_FALSE(is_pure_mlkem_group(group))
            << "Hybrid group should not be detected as pure ML-KEM";
    }
}

/**
 * Test ML-KEM parameter set mapping
 */
TEST_F(MLKEMComprehensiveTest, ParameterSetMapping) {
    using namespace pqc_utils;
    
    EXPECT_EQ(get_pure_mlkem_parameter_set(NamedGroup::MLKEM512), 
              MLKEMParameterSet::MLKEM512);
    EXPECT_EQ(get_pure_mlkem_parameter_set(NamedGroup::MLKEM768), 
              MLKEMParameterSet::MLKEM768);
    EXPECT_EQ(get_pure_mlkem_parameter_set(NamedGroup::MLKEM1024), 
              MLKEMParameterSet::MLKEM1024);
}

/**
 * Test provider ML-KEM support detection
 */
TEST_F(MLKEMComprehensiveTest, ProviderSupport) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        EXPECT_TRUE(provider->supports_pure_mlkem_group(NamedGroup::MLKEM512))
            << provider->name() << " should support ML-KEM-512";
        EXPECT_TRUE(provider->supports_pure_mlkem_group(NamedGroup::MLKEM768))
            << provider->name() << " should support ML-KEM-768";
        EXPECT_TRUE(provider->supports_pure_mlkem_group(NamedGroup::MLKEM1024))
            << provider->name() << " should support ML-KEM-1024";
            
        EXPECT_TRUE(provider->is_pure_mlkem_group(NamedGroup::MLKEM512))
            << provider->name() << " should detect ML-KEM-512 as pure ML-KEM";
        EXPECT_FALSE(provider->is_pure_mlkem_group(NamedGroup::SECP256R1))
            << provider->name() << " should not detect SECP256R1 as pure ML-KEM";
    }
}

// ============================================================================
// UNIT TESTS - Key Share Size Calculations
// ============================================================================

/**
 * Test ML-KEM key share sizes according to FIPS 203
 */
TEST_F(MLKEMComprehensiveTest, KeyShareSizes) {
    using namespace pqc_utils;
    
    // Test ML-KEM-512 sizes
    EXPECT_EQ(get_pure_mlkem_client_keyshare_size(NamedGroup::MLKEM512), 800)
        << "ML-KEM-512 client key share (public key) must be 800 bytes";
    EXPECT_EQ(get_pure_mlkem_server_keyshare_size(NamedGroup::MLKEM512), 768)
        << "ML-KEM-512 server key share (ciphertext) must be 768 bytes";
    
    // Test ML-KEM-768 sizes  
    EXPECT_EQ(get_pure_mlkem_client_keyshare_size(NamedGroup::MLKEM768), 1184)
        << "ML-KEM-768 client key share (public key) must be 1184 bytes";
    EXPECT_EQ(get_pure_mlkem_server_keyshare_size(NamedGroup::MLKEM768), 1088)
        << "ML-KEM-768 server key share (ciphertext) must be 1088 bytes";
    
    // Test ML-KEM-1024 sizes
    EXPECT_EQ(get_pure_mlkem_client_keyshare_size(NamedGroup::MLKEM1024), 1568)
        << "ML-KEM-1024 client key share (public key) must be 1568 bytes";
    EXPECT_EQ(get_pure_mlkem_server_keyshare_size(NamedGroup::MLKEM1024), 1568)
        << "ML-KEM-1024 server key share (ciphertext) must be 1568 bytes";
}

/**
 * Test shared secret size is consistent (always 32 bytes for ML-KEM)
 */
TEST_F(MLKEMComprehensiveTest, SharedSecretSizes) {
    using namespace hybrid_pqc;
    
    for (auto param_set : ml_kem_parameter_sets_) {
        auto sizes = get_mlkem_sizes(param_set);
        EXPECT_EQ(sizes.shared_secret_bytes, 32)
            << get_param_set_name(param_set) << " shared secret must be 32 bytes";
    }
}

/**
 * Test key size validation functions
 */
TEST_F(MLKEMComprehensiveTest, KeySizeValidation) {
    using namespace pqc_utils;
    
    // Test valid key sizes
    EXPECT_TRUE(validate_pure_mlkem_public_key_size(NamedGroup::MLKEM512, 800));
    EXPECT_TRUE(validate_pure_mlkem_public_key_size(NamedGroup::MLKEM768, 1184));
    EXPECT_TRUE(validate_pure_mlkem_public_key_size(NamedGroup::MLKEM1024, 1568));
    
    // Test valid ciphertext sizes
    EXPECT_TRUE(validate_pure_mlkem_ciphertext_size(NamedGroup::MLKEM512, 768));
    EXPECT_TRUE(validate_pure_mlkem_ciphertext_size(NamedGroup::MLKEM768, 1088));
    EXPECT_TRUE(validate_pure_mlkem_ciphertext_size(NamedGroup::MLKEM1024, 1568));
    
    // Test invalid sizes
    EXPECT_FALSE(validate_pure_mlkem_public_key_size(NamedGroup::MLKEM512, 1184));
    EXPECT_FALSE(validate_pure_mlkem_ciphertext_size(NamedGroup::MLKEM768, 768));
    
    // Test shared secret size
    EXPECT_TRUE(validate_pure_mlkem_shared_secret_size(32));
    EXPECT_FALSE(validate_pure_mlkem_shared_secret_size(31));
    EXPECT_FALSE(validate_pure_mlkem_shared_secret_size(33));
}

// ============================================================================
// INTEGRATION TESTS - Key Generation Operations
// ============================================================================

/**
 * Test ML-KEM key generation for all parameter sets
 */
TEST_F(MLKEMComprehensiveTest, KeyGeneration) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        for (auto param_set : ml_kem_parameter_sets_) {
            MLKEMKeyGenParams params;
            params.parameter_set = param_set;
            
            auto result = provider->mlkem_generate_keypair(params);
            ASSERT_TRUE(result.is_success())
                << "Key generation failed for " << get_param_set_name(param_set)
                << " with provider " << provider->name()
                << ": " << result.error();
            
            const auto& [public_key, private_key] = result.value();
            
            // Validate key sizes
            validate_mlkem_key_sizes(param_set, public_key, private_key);
            
            // Validate keys are non-empty and different
            EXPECT_FALSE(public_key.empty()) << "Public key should not be empty";
            EXPECT_FALSE(private_key.empty()) << "Private key should not be empty";
            EXPECT_NE(public_key, private_key) << "Public and private keys should differ";
        }
    }
}

/**
 * Test ML-KEM key generation with additional entropy
 */
TEST_F(MLKEMComprehensiveTest, KeyGenerationWithEntropy) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        params.additional_entropy = generate_random_bytes(32);
        
        auto result = provider->mlkem_generate_keypair(params);
        ASSERT_TRUE(result.is_success())
            << "Key generation with entropy failed: " << result.error();
        
        const auto& [public_key, private_key] = result.value();
        validate_mlkem_key_sizes(params.parameter_set, public_key, private_key);
    }
}

/**
 * Test ML-KEM key generation produces different keys on each call
 */
TEST_F(MLKEMComprehensiveTest, KeyGenerationRandomness) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_keys = 10;
    
    for (auto* provider : providers) {
        std::set<std::vector<uint8_t>> public_keys;
        std::set<std::vector<uint8_t>> private_keys;
        
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        for (int i = 0; i < num_keys; ++i) {
            auto result = provider->mlkem_generate_keypair(params);
            ASSERT_TRUE(result.is_success()) << "Key generation failed on iteration " << i;
            
            const auto& [public_key, private_key] = result.value();
            
            // Ensure keys are unique
            EXPECT_TRUE(public_keys.insert(public_key).second)
                << "Duplicate public key generated by " << provider->name();
            EXPECT_TRUE(private_keys.insert(private_key).second)
                << "Duplicate private key generated by " << provider->name();
        }
    }
}

// ============================================================================
// INTEGRATION TESTS - Encapsulation/Decapsulation Operations
// ============================================================================

/**
 * Test ML-KEM encapsulation operation
 */
TEST_F(MLKEMComprehensiveTest, Encapsulation) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        for (auto param_set : ml_kem_parameter_sets_) {
            // Generate keypair first
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keygen_result.is_success())
                << "Key generation failed for " << get_param_set_name(param_set);
            
            const auto& [public_key, private_key] = keygen_result.value();
            
            // Perform encapsulation
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = param_set;
            encap_params.public_key = public_key;
            
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result.is_success())
                << "Encapsulation failed for " << get_param_set_name(param_set)
                << " with provider " << provider->name()
                << ": " << encap_result.error();
            
            const auto& encap_output = encap_result.value();
            
            // Validate output sizes
            validate_mlkem_encap_sizes(param_set, encap_output.ciphertext, 
                                     encap_output.shared_secret);
        }
    }
}

/**
 * Test ML-KEM decapsulation operation
 */
TEST_F(MLKEMComprehensiveTest, Decapsulation) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        for (auto param_set : ml_kem_parameter_sets_) {
            // Generate keypair
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keygen_result.is_success());
            
            const auto& [public_key, private_key] = keygen_result.value();
            
            // Perform encapsulation
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = param_set;
            encap_params.public_key = public_key;
            
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result.is_success());
            
            const auto& encap_output = encap_result.value();
            
            // Perform decapsulation
            MLKEMDecapParams decap_params;
            decap_params.parameter_set = param_set;
            decap_params.private_key = private_key;
            decap_params.ciphertext = encap_output.ciphertext;
            
            auto decap_result = provider->mlkem_decapsulate(decap_params);
            ASSERT_TRUE(decap_result.is_success())
                << "Decapsulation failed for " << get_param_set_name(param_set)
                << " with provider " << provider->name()
                << ": " << decap_result.error();
            
            const auto& decap_shared_secret = decap_result.value();
            
            // Validate shared secret matches
            EXPECT_EQ(encap_output.shared_secret, decap_shared_secret)
                << "Shared secrets must match for " << get_param_set_name(param_set)
                << " with provider " << provider->name();
        }
    }
}

/**
 * Test complete ML-KEM key exchange end-to-end
 */
TEST_F(MLKEMComprehensiveTest, EndToEndKeyExchange) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        for (auto group : ml_kem_groups_) {
            // Step 1: Server generates keypair
            auto param_set = pqc_utils::get_pure_mlkem_parameter_set(group);
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto server_keygen = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(server_keygen.is_success())
                << "Server key generation failed for " << get_named_group_name(group);
            
            const auto& [server_public_key, server_private_key] = server_keygen.value();
            
            // Step 2: Client performs encapsulation using server's public key
            PureMLKEMKeyExchangeParams client_params;
            client_params.mlkem_group = group;
            client_params.is_encapsulation = true;
            client_params.peer_public_key = server_public_key;
            
            auto client_result = provider->perform_pure_mlkem_key_exchange(client_params);
            ASSERT_TRUE(client_result.is_success())
                << "Client key exchange failed for " << get_named_group_name(group)
                << " with provider " << provider->name();
            
            // Step 3: Server performs decapsulation using client's ciphertext
            PureMLKEMKeyExchangeParams server_params;
            server_params.mlkem_group = group;
            server_params.is_encapsulation = false;  // Server decapsulates
            server_params.private_key = server_private_key;
            server_params.ciphertext = client_result.value().ciphertext;
            
            auto server_result = provider->perform_pure_mlkem_key_exchange(server_params);
            ASSERT_TRUE(server_result.is_success())
                << "Server key exchange failed for " << get_named_group_name(group)
                << " with provider " << provider->name();
            
            // Step 4: Validate shared secrets match
            EXPECT_EQ(client_result.value().shared_secret, 
                     server_result.value().shared_secret)
                << "Shared secrets must match for end-to-end key exchange with "
                << get_named_group_name(group) << " using provider " << provider->name();
            
            // Step 5: Validate sizes are correct
            using namespace pqc_utils;
            auto expected_client_size = get_pure_mlkem_client_keyshare_size(group);
            auto expected_server_size = get_pure_mlkem_server_keyshare_size(group);
            
            EXPECT_EQ(server_public_key.size(), expected_client_size)
                << "Server public key size incorrect for " << get_named_group_name(group);
            EXPECT_EQ(client_result.value().ciphertext.size(), expected_server_size)
                << "Client ciphertext size incorrect for " << get_named_group_name(group);
            EXPECT_EQ(client_result.value().shared_secret.size(), 32)
                << "Client shared secret size must be 32 bytes";
            EXPECT_EQ(server_result.value().shared_secret.size(), 32)
                << "Server shared secret size must be 32 bytes";
        }
    }
}

/**
 * Test ML-KEM interface parameter validation
 */
TEST_F(MLKEMComprehensiveTest, InterfaceParameterValidation) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        // Test encapsulation with missing public key
        PureMLKEMKeyExchangeParams encap_params;
        encap_params.mlkem_group = NamedGroup::MLKEM512;
        encap_params.is_encapsulation = true;
        // peer_public_key intentionally left empty
        
        auto encap_result = provider->perform_pure_mlkem_key_exchange(encap_params);
        EXPECT_FALSE(encap_result.is_success())
            << "Encapsulation should fail with empty public key";
        EXPECT_EQ(encap_result.error(), DTLSError::INVALID_PARAMETER)
            << "Should return INVALID_PARAMETER error";
        
        // Test decapsulation with missing private key
        PureMLKEMKeyExchangeParams decap_params;
        decap_params.mlkem_group = NamedGroup::MLKEM512;
        decap_params.is_encapsulation = false;
        // private_key intentionally left empty
        decap_params.ciphertext = std::vector<uint8_t>(768, 0x42);  // dummy ciphertext
        
        auto decap_result = provider->perform_pure_mlkem_key_exchange(decap_params);
        EXPECT_FALSE(decap_result.is_success())
            << "Decapsulation should fail with empty private key";
        EXPECT_EQ(decap_result.error(), DTLSError::INVALID_PARAMETER)
            << "Should return INVALID_PARAMETER error";
        
        // Test decapsulation with missing ciphertext
        PureMLKEMKeyExchangeParams decap_params2;
        decap_params2.mlkem_group = NamedGroup::MLKEM512;
        decap_params2.is_encapsulation = false;
        decap_params2.private_key = std::vector<uint8_t>(1632, 0x42);  // dummy private key
        // ciphertext intentionally left empty
        
        auto decap_result2 = provider->perform_pure_mlkem_key_exchange(decap_params2);
        EXPECT_FALSE(decap_result2.is_success())
            << "Decapsulation should fail with empty ciphertext";
        EXPECT_EQ(decap_result2.error(), DTLSError::INVALID_PARAMETER)
            << "Should return INVALID_PARAMETER error";
    }
}

/**
 * Test ML-KEM client/server coordination with multiple rounds
 */
TEST_F(MLKEMComprehensiveTest, MultiRoundKeyExchangeCoordination) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_rounds = 5;
    
    for (auto* provider : providers) {
        for (auto group : ml_kem_groups_) {
            std::vector<std::vector<uint8_t>> shared_secrets;
            
            for (int round = 0; round < num_rounds; ++round) {
                // Generate fresh server keypair for each round
                auto param_set = pqc_utils::get_pure_mlkem_parameter_set(group);
                MLKEMKeyGenParams keygen_params;
                keygen_params.parameter_set = param_set;
                
                auto server_keygen = provider->mlkem_generate_keypair(keygen_params);
                ASSERT_TRUE(server_keygen.is_success())
                    << "Server key generation failed in round " << round;
                
                const auto& [server_public_key, server_private_key] = server_keygen.value();
                
                // Client encapsulation
                PureMLKEMKeyExchangeParams client_params;
                client_params.mlkem_group = group;
                client_params.is_encapsulation = true;
                client_params.peer_public_key = server_public_key;
                
                auto client_result = provider->perform_pure_mlkem_key_exchange(client_params);
                ASSERT_TRUE(client_result.is_success())
                    << "Client encapsulation failed in round " << round;
                
                // Server decapsulation
                PureMLKEMKeyExchangeParams server_params;
                server_params.mlkem_group = group;
                server_params.is_encapsulation = false;
                server_params.private_key = server_private_key;
                server_params.ciphertext = client_result.value().ciphertext;
                
                auto server_result = provider->perform_pure_mlkem_key_exchange(server_params);
                ASSERT_TRUE(server_result.is_success())
                    << "Server decapsulation failed in round " << round;
                
                // Validate shared secrets match
                EXPECT_EQ(client_result.value().shared_secret, 
                         server_result.value().shared_secret)
                    << "Shared secrets mismatch in round " << round;
                
                // Store shared secret for uniqueness test
                shared_secrets.push_back(client_result.value().shared_secret);
            }
            
            // Verify all shared secrets are unique (probabilistically)
            for (size_t i = 0; i < shared_secrets.size(); ++i) {
                for (size_t j = i + 1; j < shared_secrets.size(); ++j) {
                    EXPECT_NE(shared_secrets[i], shared_secrets[j])
                        << "Shared secrets should be unique across rounds";
                }
            }
        }
    }
}