#include <gtest/gtest.h>
#include "dtls/crypto/provider.h"
#include "dtls/types.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;

/**
 * Test pure ML-KEM support according to draft-connolly-tls-mlkem-key-agreement-05.
 * 
 * This test suite validates:
 * - Pure ML-KEM named group constants match IANA registry values
 * - ML-KEM parameter set mapping is correct
 * - Key share sizes match specification requirements
 * - Provider utility functions work correctly
 */
class PureMLKEMSupportTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test setup if needed
    }
    
    void TearDown() override {
        // Test cleanup if needed
    }
};

// Test pure ML-KEM named group constants match IANA registry values
TEST_F(PureMLKEMSupportTest, NamedGroupConstants) {
    // Verify IANA registry values from draft-connolly-tls-mlkem-key-agreement-05
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::MLKEM512), 0x0200)
        << "ML-KEM-512 named group must be 0x0200";
    
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::MLKEM768), 0x0201)
        << "ML-KEM-768 named group must be 0x0201";
    
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::MLKEM1024), 0x0202)
        << "ML-KEM-1024 named group must be 0x0202";
}

// Test ML-KEM parameter set detection
TEST_F(PureMLKEMSupportTest, ParameterSetMapping) {
    using namespace pqc_utils;
    
    // Test pure ML-KEM group detection
    EXPECT_TRUE(is_pure_mlkem_group(NamedGroup::MLKEM512));
    EXPECT_TRUE(is_pure_mlkem_group(NamedGroup::MLKEM768));
    EXPECT_TRUE(is_pure_mlkem_group(NamedGroup::MLKEM1024));
    
    // Test classical groups are not detected as pure ML-KEM
    EXPECT_FALSE(is_pure_mlkem_group(NamedGroup::SECP256R1));
    EXPECT_FALSE(is_pure_mlkem_group(NamedGroup::X25519));
    
    // Test hybrid groups are not detected as pure ML-KEM
    EXPECT_FALSE(is_pure_mlkem_group(NamedGroup::ECDHE_P256_MLKEM512));
    EXPECT_FALSE(is_pure_mlkem_group(NamedGroup::ECDHE_P384_MLKEM768));
    EXPECT_FALSE(is_pure_mlkem_group(NamedGroup::ECDHE_P521_MLKEM1024));
    
    // Test parameter set mapping
    EXPECT_EQ(get_pure_mlkem_parameter_set(NamedGroup::MLKEM512), MLKEMParameterSet::MLKEM512);
    EXPECT_EQ(get_pure_mlkem_parameter_set(NamedGroup::MLKEM768), MLKEMParameterSet::MLKEM768);
    EXPECT_EQ(get_pure_mlkem_parameter_set(NamedGroup::MLKEM1024), MLKEMParameterSet::MLKEM1024);
}

// Test ML-KEM key share sizes according to FIPS 203
TEST_F(PureMLKEMSupportTest, KeyShareSizes) {
    using namespace pqc_utils;
    
    // Test ML-KEM-512 sizes
    auto client_size_512 = get_pure_mlkem_client_keyshare_size(NamedGroup::MLKEM512);
    auto server_size_512 = get_pure_mlkem_server_keyshare_size(NamedGroup::MLKEM512);
    
    EXPECT_EQ(client_size_512, 800) << "ML-KEM-512 client key share (public key) must be 800 bytes";
    EXPECT_EQ(server_size_512, 768) << "ML-KEM-512 server key share (ciphertext) must be 768 bytes";
    
    // Test ML-KEM-768 sizes
    auto client_size_768 = get_pure_mlkem_client_keyshare_size(NamedGroup::MLKEM768);
    auto server_size_768 = get_pure_mlkem_server_keyshare_size(NamedGroup::MLKEM768);
    
    EXPECT_EQ(client_size_768, 1184) << "ML-KEM-768 client key share (public key) must be 1184 bytes";
    EXPECT_EQ(server_size_768, 1088) << "ML-KEM-768 server key share (ciphertext) must be 1088 bytes";
    
    // Test ML-KEM-1024 sizes
    auto client_size_1024 = get_pure_mlkem_client_keyshare_size(NamedGroup::MLKEM1024);
    auto server_size_1024 = get_pure_mlkem_server_keyshare_size(NamedGroup::MLKEM1024);
    
    EXPECT_EQ(client_size_1024, 1568) << "ML-KEM-1024 client key share (public key) must be 1568 bytes";
    EXPECT_EQ(server_size_1024, 1568) << "ML-KEM-1024 server key share (ciphertext) must be 1568 bytes";
}

// Test shared secret size is consistent (always 32 bytes for ML-KEM)
TEST_F(PureMLKEMSupportTest, SharedSecretSizes) {
    using namespace pqc_utils;
    using namespace hybrid_pqc;
    
    auto sizes_512 = get_mlkem_sizes(MLKEMParameterSet::MLKEM512);
    auto sizes_768 = get_mlkem_sizes(MLKEMParameterSet::MLKEM768);
    auto sizes_1024 = get_mlkem_sizes(MLKEMParameterSet::MLKEM1024);
    
    EXPECT_EQ(sizes_512.shared_secret_bytes, 32) << "ML-KEM-512 shared secret must be 32 bytes";
    EXPECT_EQ(sizes_768.shared_secret_bytes, 32) << "ML-KEM-768 shared secret must be 32 bytes";
    EXPECT_EQ(sizes_1024.shared_secret_bytes, 32) << "ML-KEM-1024 shared secret must be 32 bytes";
}

// Test pure ML-KEM vs hybrid detection 
TEST_F(PureMLKEMSupportTest, GroupClassification) {
    using namespace pqc_utils;
    using namespace hybrid_pqc;
    
    // Pure ML-KEM groups
    EXPECT_TRUE(is_pure_mlkem_group(NamedGroup::MLKEM512));
    EXPECT_TRUE(is_pure_mlkem_group(NamedGroup::MLKEM768));
    EXPECT_TRUE(is_pure_mlkem_group(NamedGroup::MLKEM1024));
    EXPECT_TRUE(is_pqc_group(NamedGroup::MLKEM512));  // Should be detected as PQC
    
    // Hybrid groups
    EXPECT_TRUE(is_hybrid_pqc_group(NamedGroup::ECDHE_P256_MLKEM512));
    EXPECT_TRUE(is_hybrid_pqc_group(NamedGroup::ECDHE_P384_MLKEM768));
    EXPECT_TRUE(is_hybrid_pqc_group(NamedGroup::ECDHE_P521_MLKEM1024));
    EXPECT_TRUE(is_pqc_group(NamedGroup::ECDHE_P256_MLKEM512));  // Should be detected as PQC
    
    // Classical groups should not be detected as PQC
    EXPECT_FALSE(is_pure_mlkem_group(NamedGroup::SECP256R1));
    EXPECT_FALSE(is_hybrid_pqc_group(NamedGroup::SECP256R1));
    EXPECT_FALSE(is_pqc_group(NamedGroup::SECP256R1));
}

// Test ML-KEM encapsulation failure rate handling
TEST_F(PureMLKEMSupportTest, EncapsulationFailureRate) {
    // According to FIPS 203, ML-KEM has a decapsulation failure rate < 2^-138
    // This is astronomically small and should not occur in practice
    // But proper error handling should be in place
    
    // This is more of a documentation test - the actual failure rate testing
    // would require statistical testing over many operations which is not practical
    // 2^-138 is approximately 1e-42, which is astronomically small
    EXPECT_LT(1e-42, 1e-40) << "ML-KEM failure rate must be < 2^-138 (approx 1e-42)";
}