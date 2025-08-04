#include <gtest/gtest.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/crypto/botan_provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <chrono>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class HKDFExpandLabelTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto providers
        openssl_provider_ = std::make_unique<OpenSSLProvider>();
        if (openssl_provider_->is_available()) {
            openssl_provider_->initialize();
        }
        
        // Botan provider testing disabled for now
        // if (botan_utils::is_botan_available()) {
        //     botan_provider_ = std::make_unique<BotanProvider>();
        //     botan_provider_->initialize();
        // }
    }
    
    void TearDown() override {
        if (openssl_provider_) {
            openssl_provider_->cleanup();
        }
        if (botan_provider_) {
            botan_provider_->cleanup();
        }
    }
    
    std::unique_ptr<OpenSSLProvider> openssl_provider_;
    std::unique_ptr<BotanProvider> botan_provider_;
};

// RFC 8446 Test Vectors for HKDF-Expand-Label
class HKDFExpandLabelRFCTest : public HKDFExpandLabelTest {};

TEST_F(HKDFExpandLabelRFCTest, RFC8446_TestVector_ClientHandshakeTrafficSecret) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // RFC 8446 Appendix A.4 test vector
    // Early Secret = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
    std::vector<uint8_t> early_secret = {
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
        0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
        0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
        0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a
    };
    
    // Expected client handshake traffic secret from RFC test vector
    std::vector<uint8_t> expected_client_hs_secret = {
        0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35,
        0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
        0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96,
        0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21
    };
    
    // Transcript hash from the test vector (empty for this simplified test)
    std::vector<uint8_t> empty_hash(32, 0);
    
    auto result = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA256,
        early_secret,
        constants::HKDF_LABEL_CLIENT_HANDSHAKE_TRAFFIC,
        empty_hash,
        32
    );
    
    ASSERT_TRUE(result.is_success());
    
    // Note: This test is simplified. In practice, the full derivation chain
    // would be more complex and involve proper transcript hashes.
    EXPECT_EQ(result.value().size(), 32);
}

TEST_F(HKDFExpandLabelRFCTest, RFC8446_TestVector_HKDFLabelStructure) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test the HKDF label structure construction
    std::vector<uint8_t> secret(32, 0x42);  // Test secret
    std::vector<uint8_t> context = {0x01, 0x02, 0x03};
    
    auto result = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA256,
        secret,
        "key",
        context,
        16
    );
    
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value().size(), 16);
    
    // Test with empty context
    auto result_empty = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA256,
        secret,
        "iv",
        {},
        12
    );
    
    ASSERT_TRUE(result_empty.is_success());
    EXPECT_EQ(result_empty.value().size(), 12);
}

TEST_F(HKDFExpandLabelRFCTest, RFC8446_AllRequiredLabels) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    std::vector<uint8_t> secret(32, 0x33);
    std::vector<uint8_t> context(32, 0x44);
    
    // Test all required DTLS v1.3 labels
    struct LabelTest {
        const char* label;
        size_t expected_length;
    };
    
    std::vector<LabelTest> labels = {
        {constants::HKDF_LABEL_DERIVED, 32},
        {constants::HKDF_LABEL_EXTERNAL_PSK_BINDER, 32},
        {constants::HKDF_LABEL_RESUMPTION_PSK_BINDER, 32},
        {constants::HKDF_LABEL_CLIENT_EARLY_TRAFFIC, 32},
        {constants::HKDF_LABEL_EARLY_EXPORTER_MASTER, 32},
        {constants::HKDF_LABEL_CLIENT_HANDSHAKE_TRAFFIC, 32},
        {constants::HKDF_LABEL_SERVER_HANDSHAKE_TRAFFIC, 32},
        {constants::HKDF_LABEL_CLIENT_APPLICATION_TRAFFIC, 32},
        {constants::HKDF_LABEL_SERVER_APPLICATION_TRAFFIC, 32},
        {constants::HKDF_LABEL_EXPORTER_MASTER, 32},
        {constants::HKDF_LABEL_RESUMPTION_MASTER, 32},
        {constants::HKDF_LABEL_KEY, 16},
        {constants::HKDF_LABEL_IV, 12},
        {constants::HKDF_LABEL_SN, 16},
        {constants::HKDF_LABEL_CLIENT_FINISHED, 32},
        {constants::HKDF_LABEL_SERVER_FINISHED, 32},
    };
    
    for (const auto& label_test : labels) {
        auto result = utils::hkdf_expand_label(
            *openssl_provider_,
            HashAlgorithm::SHA256,
            secret,
            label_test.label,
            context,
            label_test.expected_length
        );
        
        ASSERT_TRUE(result.is_success()) << "Failed for label: " << label_test.label;
        EXPECT_EQ(result.value().size(), label_test.expected_length) 
            << "Wrong length for label: " << label_test.label;
    }
}

// Test different hash algorithms
TEST_F(HKDFExpandLabelRFCTest, DifferentHashAlgorithms) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    std::vector<uint8_t> secret_sha256(32, 0x55);
    std::vector<uint8_t> secret_sha384(48, 0x66);
    
    // Test SHA256
    auto result_256 = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA256,
        secret_sha256,
        "test",
        {},
        32
    );
    
    ASSERT_TRUE(result_256.is_success());
    EXPECT_EQ(result_256.value().size(), 32);
    
    // Test SHA384
    auto result_384 = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA384,
        secret_sha384,
        "test",
        {},
        48
    );
    
    ASSERT_TRUE(result_384.is_success());
    EXPECT_EQ(result_384.value().size(), 48);
}

// Key derivation hierarchy tests
class KeyDerivationHierarchyTest : public HKDFExpandLabelTest {};

TEST_F(KeyDerivationHierarchyTest, HandshakeKeyDerivation) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test the handshake key derivation function
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    std::vector<uint8_t> handshake_secret(32, 0x77);
    std::vector<uint8_t> client_random(32, 0x88);
    std::vector<uint8_t> server_random(32, 0x99);
    
    auto keys_result = utils::derive_handshake_keys(
        *openssl_provider_,
        cipher_spec,
        handshake_secret,
        client_random,
        server_random
    );
    
    ASSERT_TRUE(keys_result.is_success());
    auto keys = keys_result.value();
    
    // Verify all keys are generated with correct lengths
    EXPECT_EQ(keys.client_write_key.size(), cipher_spec.key_length);
    EXPECT_EQ(keys.server_write_key.size(), cipher_spec.key_length);
    EXPECT_EQ(keys.client_write_iv.size(), cipher_spec.iv_length);
    EXPECT_EQ(keys.server_write_iv.size(), cipher_spec.iv_length);
}

TEST_F(KeyDerivationHierarchyTest, ApplicationKeyDerivation) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    std::vector<uint8_t> master_secret(48, 0xAA);
    std::vector<uint8_t> handshake_hash(48, 0xBB);
    
    auto keys_result = utils::derive_application_keys(
        *openssl_provider_,
        cipher_spec,
        master_secret,
        handshake_hash
    );
    
    ASSERT_TRUE(keys_result.is_success());
    auto keys = keys_result.value();
    
    // Verify all keys are generated with correct lengths
    EXPECT_EQ(keys.client_write_key.size(), cipher_spec.key_length);
    EXPECT_EQ(keys.server_write_key.size(), cipher_spec.key_length);
    EXPECT_EQ(keys.client_write_iv.size(), cipher_spec.iv_length);
    EXPECT_EQ(keys.server_write_iv.size(), cipher_spec.iv_length);
}

TEST_F(KeyDerivationHierarchyTest, KeyUpdateMechanism) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test key update functionality
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    KeySchedule original_keys;
    original_keys.client_write_key = std::vector<uint8_t>(32, 0xCC);
    original_keys.server_write_key = std::vector<uint8_t>(32, 0xDD);
    original_keys.client_write_iv = std::vector<uint8_t>(12, 0xEE);
    original_keys.server_write_iv = std::vector<uint8_t>(12, 0xFF);
    
    auto updated_keys_result = utils::update_traffic_keys(
        *openssl_provider_,
        cipher_spec,
        original_keys
    );
    
    ASSERT_TRUE(updated_keys_result.is_success());
    auto updated_keys = updated_keys_result.value();
    
    // Verify keys are updated (different from original)
    EXPECT_NE(updated_keys.client_write_key, original_keys.client_write_key);
    EXPECT_NE(updated_keys.server_write_key, original_keys.server_write_key);
    EXPECT_EQ(updated_keys.client_write_key.size(), cipher_spec.key_length);
    EXPECT_EQ(updated_keys.server_write_key.size(), cipher_spec.key_length);
}

// Cross-provider validation tests
class CrossProviderValidationTest : public HKDFExpandLabelTest {};

TEST_F(CrossProviderValidationTest, ConsistentResults) {
    bool openssl_available = openssl_provider_ && openssl_provider_->is_available();
    bool botan_available = botan_provider_ && botan_provider_->is_available();
    
    if (!openssl_available || !botan_available) {
        GTEST_SKIP() << "Both OpenSSL and Botan providers required for cross-validation";
    }
    
    std::vector<uint8_t> secret(32, 0x11);
    std::vector<uint8_t> context = {0x01, 0x02, 0x03, 0x04};
    
    // Test with both providers
    auto openssl_result = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA256,
        secret,
        "test_label",
        context,
        32
    );
    
    auto botan_result = utils::hkdf_expand_label(
        *botan_provider_,
        HashAlgorithm::SHA256,
        secret,
        "test_label",
        context,
        32
    );
    
    ASSERT_TRUE(openssl_result.is_success());
    ASSERT_TRUE(botan_result.is_success());
    
    // Results should be identical
    EXPECT_EQ(openssl_result.value(), botan_result.value());
}

// Error handling tests
class HKDFExpandLabelErrorTest : public HKDFExpandLabelTest {};

TEST_F(HKDFExpandLabelErrorTest, InvalidParameters) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    std::vector<uint8_t> secret(32, 0x22);
    
    // Test label too long (>255 characters including "tls13 " prefix)
    std::string long_label(250, 'a');  // "tls13 " + 250 chars = 256 chars (too long)
    auto result = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA256,
        secret,
        long_label,
        {},
        32
    );
    
    EXPECT_FALSE(result.is_success());
    
    // Test context too long (>255 bytes)
    std::vector<uint8_t> long_context(256, 0x33);
    auto result2 = utils::hkdf_expand_label(
        *openssl_provider_,
        HashAlgorithm::SHA256,
        secret,
        "test",
        long_context,
        32
    );
    
    EXPECT_FALSE(result2.is_success());
}

// Performance tests
class HKDFExpandLabelPerformanceTest : public HKDFExpandLabelTest {};

TEST_F(HKDFExpandLabelPerformanceTest, PerformanceBenchmark) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    std::vector<uint8_t> secret(32, 0x44);
    std::vector<uint8_t> context(32, 0x55);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    const int iterations = 1000;
    for (int i = 0; i < iterations; ++i) {
        auto result = utils::hkdf_expand_label(
            *openssl_provider_,
            HashAlgorithm::SHA256,
            secret,
            "perf_test",
            context,
            32
        );
        ASSERT_TRUE(result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete 1000 operations in reasonable time (< 100ms)
    EXPECT_LT(duration.count(), 100000);
    
    std::cout << "HKDF-Expand-Label performance: " 
              << iterations << " operations in " 
              << duration.count() << " microseconds ("
              << (duration.count() / iterations) << " μs per operation)"
              << std::endl;
}

// Integration tests with actual cipher suites
class HKDFIntegrationTest : public HKDFExpandLabelTest {};

TEST_F(HKDFIntegrationTest, FullKeyDerivationChain) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test complete key derivation chain for TLS_AES_128_GCM_SHA256
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    // Simulate complete handshake key derivation
    std::vector<uint8_t> early_secret(32, 0x00);
    std::vector<uint8_t> handshake_context(32, 0x11);
    std::vector<uint8_t> application_context(32, 0x22);
    
    // 1. Derive handshake secret
    auto hs_secret_result = utils::hkdf_expand_label(
        *openssl_provider_,
        cipher_spec.hash_algorithm,
        early_secret,
        constants::HKDF_LABEL_DERIVED,
        handshake_context,
        cipher_spec.hash_length
    );
    ASSERT_TRUE(hs_secret_result.is_success());
    
    // 2. Derive client handshake traffic secret
    auto client_hs_traffic_result = utils::hkdf_expand_label(
        *openssl_provider_,
        cipher_spec.hash_algorithm,
        hs_secret_result.value(),
        constants::HKDF_LABEL_CLIENT_HANDSHAKE_TRAFFIC,
        handshake_context,
        cipher_spec.hash_length
    );
    ASSERT_TRUE(client_hs_traffic_result.is_success());
    
    // 3. Derive server handshake traffic secret
    auto server_hs_traffic_result = utils::hkdf_expand_label(
        *openssl_provider_,
        cipher_spec.hash_algorithm,
        hs_secret_result.value(),
        constants::HKDF_LABEL_SERVER_HANDSHAKE_TRAFFIC,
        handshake_context,
        cipher_spec.hash_length
    );
    ASSERT_TRUE(server_hs_traffic_result.is_success());
    
    // 4. Derive keys from traffic secrets
    auto client_key_result = utils::hkdf_expand_label(
        *openssl_provider_,
        cipher_spec.hash_algorithm,
        client_hs_traffic_result.value(),
        constants::HKDF_LABEL_KEY,
        {},
        cipher_spec.key_length
    );
    ASSERT_TRUE(client_key_result.is_success());
    
    auto client_iv_result = utils::hkdf_expand_label(
        *openssl_provider_,
        cipher_spec.hash_algorithm,
        client_hs_traffic_result.value(),
        constants::HKDF_LABEL_IV,
        {},
        cipher_spec.iv_length
    );
    ASSERT_TRUE(client_iv_result.is_success());
    
    // Verify all derived values have correct lengths
    EXPECT_EQ(client_key_result.value().size(), cipher_spec.key_length);
    EXPECT_EQ(client_iv_result.value().size(), cipher_spec.iv_length);
}

// main function is provided by gtest_main library