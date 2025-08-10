#include <gtest/gtest.h>
#include <dtls/protocol/record_layer_interface.h>
#include <dtls/protocol/record_layer_factory.h>
#include <dtls/crypto/provider_factory.h>

namespace dtls::v13::test {

/**
 * Test class for Record Layer Decoupling validation
 * 
 * Tests that the interface abstraction works correctly and that
 * different implementations can be used interchangeably.
 */
class RecordLayerDecouplingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup test environment
    }

    void TearDown() override {
        // Cleanup test environment  
    }
};

/**
 * Test that the factory can create record layer instances
 */
TEST_F(RecordLayerDecouplingTest, FactoryCanCreateRecordLayer) {
    auto crypto_result = crypto::ProviderFactory::instance().create_default_provider();
    ASSERT_TRUE(crypto_result.is_success()) << "Failed to create crypto provider";
    
    auto record_layer_result = protocol::RecordLayerFactory::instance().create_record_layer(
        std::move(crypto_result.value()));
    
    ASSERT_TRUE(record_layer_result.is_success()) << "Failed to create record layer";
    
    auto& record_layer = record_layer_result.value();
    ASSERT_NE(record_layer, nullptr) << "Record layer should not be null";
    
    // Test basic initialization
    auto init_result = record_layer->initialize();
    EXPECT_TRUE(init_result.is_success()) << "Record layer initialization should succeed";
}

/**
 * Test that the factory can create mock record layers
 */
TEST_F(RecordLayerDecouplingTest, FactoryCanCreateMockRecordLayer) {
    auto mock_record_layer = protocol::RecordLayerFactory::instance().create_mock_record_layer();
    
    ASSERT_NE(mock_record_layer, nullptr) << "Mock record layer should not be null";
    
    // Test basic initialization
    auto init_result = mock_record_layer->initialize();
    EXPECT_TRUE(init_result.is_success()) << "Mock record layer initialization should succeed";
    
    // Test that we can get statistics
    auto stats = mock_record_layer->get_stats();
    EXPECT_EQ(stats.records_sent, 0) << "Initial stats should be zero";
    EXPECT_EQ(stats.records_received, 0) << "Initial stats should be zero";
}

/**
 * Test that mock implementation provides controllable behavior
 */
TEST_F(RecordLayerDecouplingTest, MockRecordLayerControlBehavior) {
    auto mock_record_layer = protocol::RecordLayerFactory::instance().create_mock_record_layer();
    auto* mock_ptr = dynamic_cast<protocol::MockRecordLayer*>(mock_record_layer.get());
    ASSERT_NE(mock_ptr, nullptr) << "Should be able to cast to MockRecordLayer";
    
    // Test initialization success
    auto init_result = mock_record_layer->initialize();
    EXPECT_TRUE(init_result.is_success());
    
    // Test failure injection
    mock_ptr->set_should_fail(true);
    init_result = mock_record_layer->initialize();
    EXPECT_FALSE(init_result.is_success()) << "Should fail when configured to fail";
    
    // Reset and test success again
    mock_ptr->set_should_fail(false);
    init_result = mock_record_layer->initialize();
    EXPECT_TRUE(init_result.is_success()) << "Should succeed after reset";
}

/**
 * Test that interfaces can be used interchangeably
 */
TEST_F(RecordLayerDecouplingTest, InterfacesAreInterchangeable) {
    std::vector<std::unique_ptr<protocol::IRecordLayerInterface>> record_layers;
    
    // Add production implementation
    auto crypto_result = crypto::ProviderFactory::instance().create_default_provider();
    if (crypto_result.is_success()) {
        auto production_result = protocol::RecordLayerFactory::instance().create_record_layer(
            std::move(crypto_result.value()));
        if (production_result.is_success()) {
            record_layers.push_back(std::move(production_result.value()));
        }
    }
    
    // Add mock implementation
    auto mock_layer = protocol::RecordLayerFactory::instance().create_mock_record_layer();
    if (mock_layer) {
        record_layers.push_back(std::move(mock_layer));
    }
    
    ASSERT_GE(record_layers.size(), 1) << "Should have at least one record layer";
    
    // Test that all implementations provide the same interface
    for (auto& layer : record_layers) {
        ASSERT_NE(layer, nullptr);
        
        auto init_result = layer->initialize();
        EXPECT_TRUE(init_result.is_success()) << "All implementations should initialize";
        
        auto stats = layer->get_stats();
        // All implementations should provide valid statistics
        EXPECT_GE(stats.records_sent, 0);
        EXPECT_GE(stats.records_received, 0);
        
        auto key_stats = layer->get_key_update_stats();
        EXPECT_GE(key_stats.updates_performed, 0);
    }
}

/**
 * Test that cipher suite configuration works through interface
 */
TEST_F(RecordLayerDecouplingTest, CipherSuiteConfiguration) {
    auto mock_record_layer = protocol::RecordLayerFactory::instance().create_mock_record_layer();
    ASSERT_NE(mock_record_layer, nullptr);
    
    // Initialize first
    auto init_result = mock_record_layer->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Test cipher suite configuration
    auto cipher_result = mock_record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_TRUE(cipher_result.is_success()) << "Cipher suite configuration should succeed";
    
    cipher_result = mock_record_layer->set_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    EXPECT_TRUE(cipher_result.is_success()) << "Different cipher suite should also succeed";
}

/**
 * Test error handling through interface
 */
TEST_F(RecordLayerDecouplingTest, ErrorHandlingThroughInterface) {
    auto mock_record_layer = protocol::RecordLayerFactory::instance().create_mock_record_layer();
    auto* mock_ptr = dynamic_cast<protocol::MockRecordLayer*>(mock_record_layer.get());
    ASSERT_NE(mock_ptr, nullptr);
    
    // Configure to fail
    mock_ptr->set_should_fail(true);
    
    // Test various operations fail as expected
    auto init_result = mock_record_layer->initialize();
    EXPECT_FALSE(init_result.is_success()) << "Initialize should fail";
    
    auto cipher_result = mock_record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_FALSE(cipher_result.is_success()) << "Cipher suite should fail";
    
    auto key_update_result = mock_record_layer->update_traffic_keys();
    EXPECT_FALSE(key_update_result.is_success()) << "Key update should fail";
}

} // namespace dtls::v13::test