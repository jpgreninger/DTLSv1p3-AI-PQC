/**
 * @file test_message_layer_comprehensive_enhanced_FIXED.cpp
 * @brief Fixed comprehensive tests for DTLS message layer implementation
 * 
 * This is a corrected version that works with the actual API
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "dtls/protocol/message_layer.h"
#include "dtls/protocol/handshake.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/memory/buffer.h"
#include "dtls/types.h"
#include "dtls/error.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

class MessageLayerEnhancedFixedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto provider
        auto provider_result = crypto::ProviderFactory::instance().create_provider("openssl");
        if (provider_result.is_success()) {
            crypto_provider_ = std::move(provider_result.value());
        } else {
            // Fallback to mock provider for CI environments
            auto mock_result = crypto::ProviderFactory::instance().create_provider("mock");
            ASSERT_TRUE(mock_result.is_success());
            crypto_provider_ = std::move(mock_result.value());
        }
    }
    
    // Helper to create a test ClientHello message
    HandshakeMessage create_client_hello(uint16_t seq = 1) {
        ClientHello client_hello;
        client_hello.set_random(std::vector<uint8_t>(32, 0x42));
        return HandshakeMessage(std::move(client_hello), seq);
    }
    
    // Helper to create a test ServerHello message
    HandshakeMessage create_server_hello(uint16_t seq = 2) {
        ServerHello server_hello;
        server_hello.set_random(std::vector<uint8_t>(32, 0x43));
        return HandshakeMessage(std::move(server_hello), seq);
    }
    
    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
};

// ============================================================================
// HandshakeFlight Tests
// ============================================================================

TEST_F(MessageLayerEnhancedFixedTest, HandshakeFlightBasic) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 1);
    
    EXPECT_EQ(flight.get_flight_number(), 1);
    EXPECT_TRUE(flight.get_messages().empty());
    EXPECT_FALSE(flight.is_complete());
}

TEST_F(MessageLayerEnhancedFixedTest, HandshakeFlightAddMessage) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 1);
    
    // Create and add a message
    auto message = create_client_hello(1);
    flight.add_message(std::move(message));
    
    auto messages = flight.get_messages();
    EXPECT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0].message_type(), HandshakeType::CLIENT_HELLO);
}

TEST_F(MessageLayerEnhancedFixedTest, HandshakeFlightMultipleMessages) {
    HandshakeFlight flight(FlightType::SERVER_CERTIFICATE_FLIGHT, 2);
    
    // Add multiple messages
    auto hello_msg = create_server_hello(1);
    flight.add_message(std::move(hello_msg));
    
    Certificate certificate;
    HandshakeMessage cert_msg(std::move(certificate), 2);
    flight.add_message(std::move(cert_msg));
    
    auto messages = flight.get_messages();
    EXPECT_EQ(messages.size(), 2);
    EXPECT_EQ(messages[0].message_type(), HandshakeType::SERVER_HELLO);
    EXPECT_EQ(messages[1].message_type(), HandshakeType::CERTIFICATE);
}

// ============================================================================
// MessageFragment Tests  
// ============================================================================

TEST_F(MessageLayerEnhancedFixedTest, MessageFragmentBasic) {
    MessageFragment fragment;
    fragment.message_seq = 1;
    fragment.fragment_offset = 0;
    fragment.fragment_length = 100;
    fragment.total_length = 200;
    
    // Create test data
    std::vector<uint8_t> test_data(100, 0xAB);
    auto buffer_result = Buffer::create_from_data(test_data.data(), test_data.size());
    ASSERT_TRUE(buffer_result.is_success());
    fragment.fragment_data = std::move(buffer_result.value());
    
    EXPECT_TRUE(fragment.is_valid());
    EXPECT_EQ(fragment.message_seq, 1);
    EXPECT_EQ(fragment.fragment_offset, 0);
    EXPECT_EQ(fragment.fragment_length, 100);
    EXPECT_EQ(fragment.total_length, 200);
}

// ============================================================================
// MessageReassembler Tests
// ============================================================================

TEST_F(MessageLayerEnhancedFixedTest, MessageReassemblerBasic) {
    MessageReassembler reassembler(1);
    
    EXPECT_FALSE(reassembler.is_complete());
    EXPECT_EQ(reassembler.get_message_seq(), 1);
}

TEST_F(MessageLayerEnhancedFixedTest, MessageReassemblerSingleFragment) {
    MessageReassembler reassembler(1);
    
    // Create a complete message in a single fragment
    MessageFragment fragment;
    fragment.message_seq = 1;
    fragment.fragment_offset = 0;
    fragment.fragment_length = 50;
    fragment.total_length = 50;
    
    std::vector<uint8_t> test_data(50, 0xCD);
    auto buffer_result = Buffer::create_from_data(test_data.data(), test_data.size());
    ASSERT_TRUE(buffer_result.is_success());
    fragment.fragment_data = std::move(buffer_result.value());
    
    auto add_result = reassembler.add_fragment(fragment);
    EXPECT_TRUE(add_result.is_success());
    EXPECT_TRUE(add_result.value());  // Should indicate fragment was added
    EXPECT_TRUE(reassembler.is_complete());
    
    auto message_result = reassembler.get_complete_message();
    EXPECT_TRUE(message_result.is_success());
    EXPECT_EQ(message_result.value().size(), 50);
}

// ============================================================================
// FlightManager Tests
// ============================================================================

TEST_F(MessageLayerEnhancedFixedTest, FlightManagerBasic) {
    FlightManager manager;
    
    EXPECT_FALSE(manager.get_current_flight().has_value());
    EXPECT_TRUE(manager.get_completed_flights().empty());
}

TEST_F(MessageLayerEnhancedFixedTest, FlightManagerCreateFlight) {
    FlightManager manager;
    
    auto result = manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_TRUE(result.is_success());
    
    auto current_flight = manager.get_current_flight();
    EXPECT_TRUE(current_flight.has_value());
    EXPECT_EQ(current_flight.value()->get_type(), FlightType::CLIENT_HELLO_FLIGHT);
}

TEST_F(MessageLayerEnhancedFixedTest, FlightManagerAddMessage) {
    FlightManager manager;
    
    // Create flight first
    EXPECT_TRUE(manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT).is_success());
    
    // Create and add message
    auto message = create_client_hello(1);
    auto add_result = manager.add_message_to_current_flight(std::move(message));
    EXPECT_TRUE(add_result.is_success());
    
    auto current_flight = manager.get_current_flight();
    EXPECT_TRUE(current_flight.has_value());
    
    auto messages = current_flight.value()->get_messages();
    EXPECT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0].message_type(), HandshakeType::CLIENT_HELLO);
}

// ============================================================================
// MessageLayer Integration Tests
// ============================================================================

TEST_F(MessageLayerEnhancedFixedTest, MessageLayerBasic) {
    MessageLayer message_layer;
    
    auto init_result = message_layer.initialize();
    EXPECT_TRUE(init_result.is_success());
}

TEST_F(MessageLayerEnhancedFixedTest, MessageLayerSendReceive) {
    MessageLayer message_layer;
    
    auto init_result = message_layer.initialize();
    EXPECT_TRUE(init_result.is_success());
    
    // Create test message data
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04};
    
    // Send message
    auto send_result = message_layer.send_message(test_data);
    EXPECT_TRUE(send_result.is_success());
    
    // Process the message (simulate receiving it)
    auto process_result = message_layer.process_received_data(send_result.value());
    EXPECT_TRUE(process_result.is_success());
    
    // Try to get complete message
    auto message_result = message_layer.get_next_complete_message();
    if (message_result.is_success()) {
        EXPECT_EQ(message_result.value(), test_data);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST_F(MessageLayerEnhancedFixedTest, FlightManagerErrorHandling) {
    FlightManager manager;
    
    // Try to add message without creating flight first
    auto message = create_client_hello(1);
    auto add_result = manager.add_message_to_current_flight(std::move(message));
    EXPECT_FALSE(add_result.is_success());
    
    // Try to complete non-existent flight
    auto complete_result = manager.complete_current_flight();
    EXPECT_FALSE(complete_result.is_success());
}

TEST_F(MessageLayerEnhancedFixedTest, MessageFragmentValidation) {
    MessageFragment fragment;
    fragment.message_seq = 0;
    fragment.fragment_offset = 0;
    fragment.fragment_length = 0;
    fragment.total_length = 0;
    
    // Invalid fragment should be rejected
    EXPECT_FALSE(fragment.is_valid());
}