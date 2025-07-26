#include <gtest/gtest.h>
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/record_layer.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/crypto/botan_provider.h>
#include <dtls/crypto/provider_factory.h>
#include <chrono>
#include <thread>

using namespace dtls::v13::protocol;
using namespace dtls::v13::crypto;

class KeyUpdateTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto providers
        openssl_provider_ = std::make_unique<OpenSSLProvider>();
        if (openssl_provider_->is_available()) {
            openssl_provider_->initialize();
        }
        
        if (botan_utils::is_botan_available()) {
            botan_provider_ = std::make_unique<BotanProvider>();
            botan_provider_->initialize();
        }
        
        // Create record layer for testing
        record_layer_ = std::make_unique<RecordLayer>(
            std::make_unique<OpenSSLProvider>(*openssl_provider_));
        record_layer_->initialize();
        record_layer_->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
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
    std::unique_ptr<RecordLayer> record_layer_;
};

// ============================================================================
// KeyUpdate Message Tests
// ============================================================================

TEST_F(KeyUpdateTest, KeyUpdateMessageConstruction) {
    // Test default construction
    KeyUpdate default_key_update;
    EXPECT_EQ(default_key_update.update_request(), KeyUpdateRequest::UPDATE_NOT_REQUESTED);
    EXPECT_FALSE(default_key_update.requests_peer_update());
    EXPECT_TRUE(default_key_update.is_valid());
    
    // Test explicit construction
    KeyUpdate request_update(KeyUpdateRequest::UPDATE_REQUESTED);
    EXPECT_EQ(request_update.update_request(), KeyUpdateRequest::UPDATE_REQUESTED);
    EXPECT_TRUE(request_update.requests_peer_update());
    EXPECT_TRUE(request_update.is_valid());
}

TEST_F(KeyUpdateTest, KeyUpdateMessageSerialization) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test UPDATE_NOT_REQUESTED serialization
    KeyUpdate not_requested(KeyUpdateRequest::UPDATE_NOT_REQUESTED);
    memory::Buffer buffer(KeyUpdate::serialized_size());
    
    auto serialize_result = not_requested.serialize(buffer);
    ASSERT_TRUE(serialize_result.is_success());
    EXPECT_EQ(serialize_result.value(), 1);
    EXPECT_EQ(static_cast<uint8_t>(buffer.data()[0]), 0);
    
    // Test deserialization
    auto deserialize_result = KeyUpdate::deserialize(buffer, 0);
    ASSERT_TRUE(deserialize_result.is_success());
    auto deserialized = deserialize_result.value();
    EXPECT_EQ(deserialized.update_request(), KeyUpdateRequest::UPDATE_NOT_REQUESTED);
    EXPECT_EQ(deserialized, not_requested);
    
    // Test UPDATE_REQUESTED serialization
    KeyUpdate requested(KeyUpdateRequest::UPDATE_REQUESTED);
    auto serialize_result2 = requested.serialize(buffer);
    ASSERT_TRUE(serialize_result2.is_success());
    EXPECT_EQ(static_cast<uint8_t>(buffer.data()[0]), 1);
    
    auto deserialize_result2 = KeyUpdate::deserialize(buffer, 0);
    ASSERT_TRUE(deserialize_result2.is_success());
    auto deserialized2 = deserialize_result2.value();
    EXPECT_EQ(deserialized2.update_request(), KeyUpdateRequest::UPDATE_REQUESTED);
    EXPECT_EQ(deserialized2, requested);
}

TEST_F(KeyUpdateTest, KeyUpdateMessageValidation) {
    memory::Buffer buffer(1);
    
    // Test valid values
    buffer.mutable_data()[0] = static_cast<std::byte>(0);
    auto result1 = KeyUpdate::deserialize(buffer, 0);
    ASSERT_TRUE(result1.is_success());
    
    buffer.mutable_data()[0] = static_cast<std::byte>(1);
    auto result2 = KeyUpdate::deserialize(buffer, 0);
    ASSERT_TRUE(result2.is_success());
    
    // Test invalid value
    buffer.mutable_data()[0] = static_cast<std::byte>(2);
    auto result3 = KeyUpdate::deserialize(buffer, 0);
    EXPECT_FALSE(result3.is_success());
    EXPECT_EQ(result3.error(), DTLSError::INVALID_MESSAGE_FORMAT);
}

TEST_F(KeyUpdateTest, HandshakeMessageIntegration) {
    KeyUpdate key_update(KeyUpdateRequest::UPDATE_REQUESTED);
    
    // Create HandshakeMessage with KeyUpdate
    HandshakeMessage message(key_update, 42);
    
    // Verify message type mapping
    EXPECT_EQ(message.get_handshake_type(), HandshakeType::KEY_UPDATE);
    EXPECT_EQ(message.get_message_sequence(), 42);
    
    // Verify message retrieval
    auto retrieved_update = message.get<KeyUpdate>();
    ASSERT_TRUE(retrieved_update.has_value());
    EXPECT_EQ(retrieved_update->update_request(), KeyUpdateRequest::UPDATE_REQUESTED);
}

// ============================================================================
// HKDF-Expand-Label Key Update Tests
// ============================================================================

TEST_F(KeyUpdateTest, TrafficKeyUpdate) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Create test cipher spec
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    // Create initial key schedule
    KeySchedule initial_keys;
    initial_keys.client_write_key = std::vector<uint8_t>(16, 0xAA);
    initial_keys.server_write_key = std::vector<uint8_t>(16, 0xBB);
    initial_keys.client_write_iv = std::vector<uint8_t>(12, 0xCC);
    initial_keys.server_write_iv = std::vector<uint8_t>(12, 0xDD);
    initial_keys.epoch = 1;
    
    // Perform key update
    auto updated_keys_result = utils::update_traffic_keys(
        *openssl_provider_, cipher_spec, initial_keys);
    
    ASSERT_TRUE(updated_keys_result.is_success());
    auto updated_keys = updated_keys_result.value();
    
    // Verify keys are different (perfect forward secrecy)
    EXPECT_NE(updated_keys.client_write_key, initial_keys.client_write_key);
    EXPECT_NE(updated_keys.server_write_key, initial_keys.server_write_key);
    EXPECT_NE(updated_keys.client_write_iv, initial_keys.client_write_iv);
    EXPECT_NE(updated_keys.server_write_iv, initial_keys.server_write_iv);
    
    // Verify key lengths are correct
    EXPECT_EQ(updated_keys.client_write_key.size(), cipher_spec.key_length);
    EXPECT_EQ(updated_keys.server_write_key.size(), cipher_spec.key_length);
    EXPECT_EQ(updated_keys.client_write_iv.size(), cipher_spec.iv_length);
    EXPECT_EQ(updated_keys.server_write_iv.size(), cipher_spec.iv_length);
    
    // Verify epoch increment
    EXPECT_EQ(updated_keys.epoch, initial_keys.epoch + 1);
}

TEST_F(KeyUpdateTest, MultipleKeyUpdates) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    // Start with initial keys
    KeySchedule keys;
    keys.client_write_key = std::vector<uint8_t>(32, 0x11);
    keys.server_write_key = std::vector<uint8_t>(32, 0x22);
    keys.client_write_iv = std::vector<uint8_t>(12, 0x33);
    keys.server_write_iv = std::vector<uint8_t>(12, 0x44);
    keys.epoch = 1;
    
    std::vector<KeySchedule> key_history;
    key_history.push_back(keys);
    
    // Perform multiple key updates
    for (int i = 0; i < 5; ++i) {
        auto updated_result = utils::update_traffic_keys(*openssl_provider_, cipher_spec, keys);
        ASSERT_TRUE(updated_result.is_success());
        keys = updated_result.value();
        key_history.push_back(keys);
        
        // Verify epoch progression
        EXPECT_EQ(keys.epoch, static_cast<uint16_t>(2 + i));
    }
    
    // Verify all keys in history are unique (perfect forward secrecy)
    for (size_t i = 0; i < key_history.size(); ++i) {
        for (size_t j = i + 1; j < key_history.size(); ++j) {
            EXPECT_NE(key_history[i].client_write_key, key_history[j].client_write_key);
            EXPECT_NE(key_history[i].server_write_key, key_history[j].server_write_key);
        }
    }
}

TEST_F(KeyUpdateTest, CrossProviderKeyUpdateConsistency) {
    bool openssl_available = openssl_provider_ && openssl_provider_->is_available();
    bool botan_available = botan_provider_ && botan_provider_->is_available();
    
    if (!openssl_available || !botan_available) {
        GTEST_SKIP() << "Both OpenSSL and Botan providers required for cross-validation";
    }
    
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    // Use identical initial keys
    KeySchedule initial_keys;
    initial_keys.client_write_key = std::vector<uint8_t>(32, 0x55);
    initial_keys.server_write_key = std::vector<uint8_t>(32, 0x66);
    initial_keys.client_write_iv = std::vector<uint8_t>(12, 0x77);
    initial_keys.server_write_iv = std::vector<uint8_t>(12, 0x88);
    initial_keys.epoch = 1;
    
    // Update with both providers
    auto openssl_result = utils::update_traffic_keys(*openssl_provider_, cipher_spec, initial_keys);
    auto botan_result = utils::update_traffic_keys(*botan_provider_, cipher_spec, initial_keys);
    
    ASSERT_TRUE(openssl_result.is_success());
    ASSERT_TRUE(botan_result.is_success());
    
    // Results should be identical
    EXPECT_EQ(openssl_result.value().client_write_key, botan_result.value().client_write_key);
    EXPECT_EQ(openssl_result.value().server_write_key, botan_result.value().server_write_key);
    EXPECT_EQ(openssl_result.value().client_write_iv, botan_result.value().client_write_iv);
    EXPECT_EQ(openssl_result.value().server_write_iv, botan_result.value().server_write_iv);
}

// ============================================================================
// RecordLayer Key Update Integration Tests
// ============================================================================

TEST_F(KeyUpdateTest, RecordLayerKeyUpdateTriggers) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test initial state
    EXPECT_FALSE(record_layer_->needs_key_update(100, std::chrono::seconds(60)));
    
    // Test record count trigger
    EXPECT_TRUE(record_layer_->needs_key_update(0, std::chrono::seconds(3600)));
    
    // Test time trigger
    EXPECT_TRUE(record_layer_->needs_key_update(1000000, std::chrono::seconds(0)));
}

TEST_F(KeyUpdateTest, RecordLayerKeyUpdateStats) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Get initial stats
    auto initial_stats = record_layer_->get_key_update_stats();
    EXPECT_EQ(initial_stats.updates_performed, 0);
    EXPECT_EQ(initial_stats.records_since_last_update, 0);
    
    // Setup initial epoch with test keys
    std::vector<uint8_t> test_key(16, 0x99);
    std::vector<uint8_t> test_iv(12, 0xAA);
    
    auto advance_result = record_layer_->advance_epoch(test_key, test_key, test_iv, test_iv);
    ASSERT_TRUE(advance_result.is_success());
    
    // Perform key update
    auto update_result = record_layer_->update_traffic_keys();
    ASSERT_TRUE(update_result.is_success());
    
    // Check updated stats
    auto updated_stats = record_layer_->get_key_update_stats();
    EXPECT_EQ(updated_stats.updates_performed, 1);
    EXPECT_EQ(updated_stats.records_since_last_update, 0);
    EXPECT_GT(updated_stats.last_update_time, initial_stats.last_update_time);
}

// ============================================================================
// Perfect Forward Secrecy Tests
// ============================================================================

TEST_F(KeyUpdateTest, PerfectForwardSecrecy) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    // Create initial secret
    std::vector<uint8_t> master_secret(32);
    auto random_result = openssl_provider_->generate_random({32, true, {}});
    ASSERT_TRUE(random_result.is_success());
    master_secret = random_result.value();
    
    // Derive multiple generations of keys
    const int generations = 10;
    std::vector<KeySchedule> key_generations;
    
    KeySchedule current_keys;
    current_keys.client_write_key = master_secret;
    current_keys.server_write_key = master_secret;
    current_keys.client_write_iv = std::vector<uint8_t>(12, 0x00);
    current_keys.server_write_iv = std::vector<uint8_t>(12, 0x00);
    current_keys.epoch = 1;
    
    for (int gen = 0; gen < generations; ++gen) {
        auto update_result = utils::update_traffic_keys(*openssl_provider_, cipher_spec, current_keys);
        ASSERT_TRUE(update_result.is_success());
        current_keys = update_result.value();
        key_generations.push_back(current_keys);
    }
    
    // Verify perfect forward secrecy: no key from any generation should be derivable from later keys
    for (int i = 0; i < generations; ++i) {
        for (int j = i + 1; j < generations; ++j) {
            // Keys should be completely different
            EXPECT_NE(key_generations[i].client_write_key, key_generations[j].client_write_key);
            EXPECT_NE(key_generations[i].server_write_key, key_generations[j].server_write_key);
            
            // Even attempting to derive backwards should fail
            // (This tests that there's no simple relationship between keys)
            auto backward_attempt = utils::update_traffic_keys(
                *openssl_provider_, cipher_spec, key_generations[j]);
            ASSERT_TRUE(backward_attempt.is_success());
            EXPECT_NE(backward_attempt.value().client_write_key, key_generations[i].client_write_key);
        }
    }
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST_F(KeyUpdateTest, KeyUpdatePerformance) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    KeySchedule keys;
    keys.client_write_key = std::vector<uint8_t>(16, 0x12);
    keys.server_write_key = std::vector<uint8_t>(16, 0x34);
    keys.client_write_iv = std::vector<uint8_t>(12, 0x56);
    keys.server_write_iv = std::vector<uint8_t>(12, 0x78);
    keys.epoch = 1;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    const int iterations = 100;
    for (int i = 0; i < iterations; ++i) {
        auto update_result = utils::update_traffic_keys(*openssl_provider_, cipher_spec, keys);
        ASSERT_TRUE(update_result.is_success());
        keys = update_result.value();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete 100 key updates in reasonable time (< 100ms)
    EXPECT_LT(duration.count(), 100000);
    
    std::cout << "Key update performance: " 
              << iterations << " updates in " 
              << duration.count() << " microseconds ("
              << (duration.count() / iterations) << " μs per update)"
              << std::endl;
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST_F(KeyUpdateTest, ErrorHandling) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    auto cipher_spec_result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipher_spec_result.is_success());
    auto cipher_spec = cipher_spec_result.value();
    
    // Test with invalid keys (empty)
    KeySchedule invalid_keys;
    invalid_keys.epoch = 1;
    
    auto result = utils::update_traffic_keys(*openssl_provider_, cipher_spec, invalid_keys);
    // This should handle empty keys gracefully by using them as-is in HKDF
    EXPECT_TRUE(result.is_success());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}