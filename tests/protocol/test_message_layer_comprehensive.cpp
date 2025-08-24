/**
 * @file test_message_layer_comprehensive.cpp
 * @brief Comprehensive tests for DTLS message layer implementation
 * 
 * Targets message_layer.cpp which currently has 0% coverage (0/509 lines)
 * Tests all major components: MessageReassembler, HandshakeFlight, 
 * FlightManager, MessageLayer functionality
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <cstddef>

#include "dtls/protocol/message_layer.h"
#include "dtls/protocol/record_layer.h"
#include "dtls/protocol/handshake.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/memory/buffer.h"
#include "dtls/types.h"
#include "dtls/error.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

class MessageLayerComprehensiveTest : public ::testing::Test {
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
        
        // Create test message data
        test_message_data_ = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };
        
        large_message_data_.resize(4096);
        for (size_t i = 0; i < large_message_data_.size(); ++i) {
            large_message_data_[i] = static_cast<uint8_t>(i % 256);
        }
    }
    
    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
    std::vector<uint8_t> test_message_data_;
    std::vector<uint8_t> large_message_data_;
};

// ============================================================================
// MessageFragment Tests
// ============================================================================

class MessageFragmentTest : public MessageLayerComprehensiveTest {};

TEST_F(MessageFragmentTest, BasicConstruction) {
    Buffer fragment_data(test_message_data_.size());
    auto resize_result = fragment_data.resize(test_message_data_.size());
    ASSERT_TRUE(resize_result.is_success());
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), test_message_data_.size());
    
    MessageFragment fragment(1, 0, 16, 16, std::move(fragment_data));
    
    EXPECT_EQ(fragment.message_seq, 1);
    EXPECT_EQ(fragment.fragment_offset, 0);
    EXPECT_EQ(fragment.fragment_length, 16);
    EXPECT_EQ(fragment.total_length, 16);
    EXPECT_TRUE(fragment.is_complete_message());
    EXPECT_TRUE(fragment.is_valid());
}

TEST_F(MessageFragmentTest, PartialFragment) {
    Buffer fragment_data(8);
    auto resize_result = fragment_data.resize(8);
    ASSERT_TRUE(resize_result.is_success());
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), 8);
    
    MessageFragment fragment(1, 0, 8, 16, std::move(fragment_data));
    
    EXPECT_FALSE(fragment.is_complete_message());
    EXPECT_TRUE(fragment.is_valid());
}

TEST_F(MessageFragmentTest, InvalidFragment) {
    Buffer fragment_data(16);
    auto resize_result = fragment_data.resize(16);
    ASSERT_TRUE(resize_result.is_success());
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), 16);
    
    // Offset + length > total_length (invalid)
    MessageFragment fragment(1, 10, 16, 20, std::move(fragment_data));
    
    EXPECT_FALSE(fragment.is_valid());
}

TEST_F(MessageFragmentTest, FragmentDataMismatch) {
    Buffer fragment_data(8); // Data size is 8
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), 8);
    
    // Fragment length says 16 but data is only 8 bytes
    MessageFragment fragment(1, 0, 16, 16, std::move(fragment_data));
    
    EXPECT_FALSE(fragment.is_valid());
}

// ============================================================================
// MessageReassembler Tests
// ============================================================================

class MessageReassemblerTest : public MessageLayerComprehensiveTest {};

TEST_F(MessageReassemblerTest, SingleCompleteFragment) {
    MessageReassembler reassembler;
    
    Buffer fragment_data(test_message_data_.size());
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), test_message_data_.size());
    
    MessageFragment fragment(1, 0, 16, 16, std::move(fragment_data));
    
    auto result = reassembler.add_fragment(fragment);
    ASSERT_TRUE(result.is_success());
    EXPECT_TRUE(result.value()); // Should be complete
    EXPECT_TRUE(reassembler.is_complete());
    
    auto message_result = reassembler.get_complete_message();
    ASSERT_TRUE(message_result.is_success());
    
    const auto& message = message_result.value();
    EXPECT_EQ(message.size(), test_message_data_.size());
    EXPECT_EQ(std::memcmp(message.data(), test_message_data_.data(), test_message_data_.size()), 0);
}

TEST_F(MessageReassemblerTest, MultipleFragments) {
    MessageReassembler reassembler;
    
    // Split test data into 4 fragments of 4 bytes each
    for (size_t i = 0; i < 4; ++i) {
        Buffer fragment_data(4);
        std::memcpy(fragment_data.mutable_data(), test_message_data_.data() + i * 4, 4);
        
        MessageFragment fragment(1, i * 4, 4, 16, std::move(fragment_data));
        
        auto result = reassembler.add_fragment(fragment);
        ASSERT_TRUE(result.is_success());
        
        if (i < 3) {
            EXPECT_FALSE(result.value()); // Not complete yet
            EXPECT_FALSE(reassembler.is_complete());
        } else {
            EXPECT_TRUE(result.value()); // Complete
            EXPECT_TRUE(reassembler.is_complete());
        }
    }
    
    auto message_result = reassembler.get_complete_message();
    ASSERT_TRUE(message_result.is_success());
    
    const auto& message = message_result.value();
    EXPECT_EQ(message.size(), test_message_data_.size());
    EXPECT_EQ(std::memcmp(message.data(), test_message_data_.data(), test_message_data_.size()), 0);
}

TEST_F(MessageReassemblerTest, OutOfOrderFragments) {
    MessageReassembler reassembler;
    
    // Add fragments in reverse order: 3, 2, 1, 0
    for (int i = 3; i >= 0; --i) {
        Buffer fragment_data(4);
        std::memcpy(fragment_data.mutable_data(), test_message_data_.data() + i * 4, 4);
        
        MessageFragment fragment(1, i * 4, 4, 16, std::move(fragment_data));
        
        auto result = reassembler.add_fragment(fragment);
        ASSERT_TRUE(result.is_success());
        
        if (i > 0) {
            EXPECT_FALSE(result.value()); // Not complete yet
        } else {
            EXPECT_TRUE(result.value()); // Complete when last fragment added
        }
    }
    
    EXPECT_TRUE(reassembler.is_complete());
    
    auto message_result = reassembler.get_complete_message();
    ASSERT_TRUE(message_result.is_success());
    
    const auto& message = message_result.value();
    EXPECT_EQ(std::memcmp(message.data(), test_message_data_.data(), test_message_data_.size()), 0);
}

TEST_F(MessageReassemblerTest, DuplicateFragments) {
    MessageReassembler reassembler;
    
    Buffer fragment_data(8);
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), 8);
    
    MessageFragment fragment(1, 0, 8, 16, std::move(fragment_data));
    
    // Add first time
    auto result1 = reassembler.add_fragment(fragment);
    ASSERT_TRUE(result1.is_success());
    EXPECT_FALSE(result1.value());
    
    // Add duplicate - should be ignored
    Buffer fragment_data2(8);
    std::memcpy(fragment_data2.mutable_data(), test_message_data_.data(), 8);
    MessageFragment duplicate_fragment(1, 0, 8, 16, std::move(fragment_data2));
    
    auto result2 = reassembler.add_fragment(duplicate_fragment);
    ASSERT_TRUE(result2.is_success());
    EXPECT_FALSE(result2.value()); // Should return false for duplicate
}

TEST_F(MessageReassemblerTest, OverlappingFragments) {
    MessageReassembler reassembler;
    
    // Add first fragment (0-8)
    Buffer fragment_data1(8);
    std::memcpy(fragment_data1.mutable_data(), test_message_data_.data(), 8);
    MessageFragment fragment1(1, 0, 8, 16, std::move(fragment_data1));
    
    auto result1 = reassembler.add_fragment(fragment1);
    ASSERT_TRUE(result1.is_success());
    
    // Add overlapping fragment (4-12) - should be rejected
    Buffer fragment_data2(8);
    std::memcpy(fragment_data2.mutable_data(), test_message_data_.data() + 4, 8);
    MessageFragment fragment2(1, 4, 8, 16, std::move(fragment_data2));
    
    auto result2 = reassembler.add_fragment(fragment2);
    EXPECT_FALSE(result2.is_success());
    EXPECT_EQ(result2.error(), DTLSError::OVERLAPPING_FRAGMENT);
}

TEST_F(MessageReassemblerTest, InvalidFragment) {
    MessageReassembler reassembler;
    
    Buffer fragment_data(16);
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), 16);
    
    // Invalid: offset + length > total_length
    MessageFragment invalid_fragment(1, 10, 16, 20, std::move(fragment_data));
    
    auto result = reassembler.add_fragment(invalid_fragment);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_MESSAGE_FRAGMENT);
}

TEST_F(MessageReassemblerTest, FragmentLengthMismatch) {
    MessageReassembler reassembler;
    
    // Add first fragment with total_length = 16
    Buffer fragment_data1(8);
    std::memcpy(fragment_data1.mutable_data(), test_message_data_.data(), 8);
    MessageFragment fragment1(1, 0, 8, 16, std::move(fragment_data1));
    
    auto result1 = reassembler.add_fragment(fragment1);
    ASSERT_TRUE(result1.is_success());
    
    // Add second fragment with different total_length = 20
    Buffer fragment_data2(8);
    std::memcpy(fragment_data2.mutable_data(), test_message_data_.data() + 8, 8);
    MessageFragment fragment2(1, 8, 8, 20, std::move(fragment_data2)); // Different total length
    
    auto result2 = reassembler.add_fragment(fragment2);
    EXPECT_FALSE(result2.is_success());
    EXPECT_EQ(result2.error(), DTLSError::FRAGMENT_LENGTH_MISMATCH);
}

TEST_F(MessageReassemblerTest, ReassemblerStats) {
    MessageReassembler reassembler;
    
    auto initial_stats = reassembler.get_stats();
    EXPECT_EQ(initial_stats.total_length, 0);
    EXPECT_EQ(initial_stats.fragment_count, 0);
    EXPECT_EQ(initial_stats.received_bytes, 0);
    EXPECT_EQ(initial_stats.gap_count, 0);
    
    // Add first fragment (0-8)
    Buffer fragment_data1(8);
    std::memcpy(fragment_data1.mutable_data(), test_message_data_.data(), 8);
    MessageFragment fragment1(1, 0, 8, 16, std::move(fragment_data1));
    reassembler.add_fragment(fragment1);
    
    auto partial_stats = reassembler.get_stats();
    EXPECT_EQ(partial_stats.total_length, 16);
    EXPECT_EQ(partial_stats.fragment_count, 1);
    EXPECT_EQ(partial_stats.received_bytes, 8);
    EXPECT_EQ(partial_stats.gap_count, 1); // Gap at end
    
    // Add second fragment (8-16)
    Buffer fragment_data2(8);
    std::memcpy(fragment_data2.mutable_data(), test_message_data_.data() + 8, 8);
    MessageFragment fragment2(1, 8, 8, 16, std::move(fragment_data2));
    reassembler.add_fragment(fragment2);
    
    auto complete_stats = reassembler.get_stats();
    EXPECT_EQ(complete_stats.total_length, 16);
    EXPECT_EQ(complete_stats.fragment_count, 1); // Merged into single fragment
    EXPECT_EQ(complete_stats.received_bytes, 16);
    EXPECT_EQ(complete_stats.gap_count, 0); // No gaps
}

TEST_F(MessageReassemblerTest, ClearReassembler) {
    MessageReassembler reassembler;
    
    // Add a fragment
    Buffer fragment_data(8);
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), 8);
    MessageFragment fragment(1, 0, 8, 16, std::move(fragment_data));
    reassembler.add_fragment(fragment);
    
    EXPECT_FALSE(reassembler.is_complete());
    
    // Clear the reassembler
    reassembler.clear();
    
    auto stats = reassembler.get_stats();
    EXPECT_EQ(stats.total_length, 0);
    EXPECT_EQ(stats.fragment_count, 0);
}

TEST_F(MessageReassemblerTest, GetIncompleteMessage) {
    MessageReassembler reassembler;
    
    // Add partial fragment
    Buffer fragment_data(8);
    std::memcpy(fragment_data.mutable_data(), test_message_data_.data(), 8);
    MessageFragment fragment(1, 0, 8, 16, std::move(fragment_data));
    reassembler.add_fragment(fragment);
    
    EXPECT_FALSE(reassembler.is_complete());
    
    auto result = reassembler.get_complete_message();
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::MESSAGE_NOT_COMPLETE);
}

// ============================================================================
// HandshakeFlight Tests
// ============================================================================

class HandshakeFlightTest : public MessageLayerComprehensiveTest {};

TEST_F(HandshakeFlightTest, BasicFlightCreation) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 1);
    
    EXPECT_EQ(flight.get_type(), FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_TRUE(flight.get_messages().empty());
    EXPECT_FALSE(flight.is_complete()); // No messages added yet
    EXPECT_EQ(flight.get_total_size(), 0);
    
    auto range = flight.get_sequence_range();
    EXPECT_EQ(range.first, 1);
    EXPECT_EQ(range.second, 1); // Empty flight
}

TEST_F(HandshakeFlightTest, AddMessages) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 1);
    
    // Create test ClientHello message
    ClientHello client_hello;
    client_hello.set_cipher_suites({CipherSuite::TLS_AES_128_GCM_SHA256});
    
    HandshakeMessage message(std::move(client_hello), 1);
    flight.add_message(std::move(message));
    
    EXPECT_EQ(flight.get_messages().size(), 1);
    EXPECT_TRUE(flight.is_complete()); // Has messages now
    EXPECT_GT(flight.get_total_size(), 0);
    
    auto range = flight.get_sequence_range();
    EXPECT_EQ(range.first, 1);
    EXPECT_EQ(range.second, 1); // One message
}

TEST_F(HandshakeFlightTest, MultipleMessages) {
    HandshakeFlight flight(FlightType::SERVER_HELLO_FLIGHT, 5);
    
    // Add ServerHello
    ServerHello server_hello;
    server_hello.set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    HandshakeMessage sh_message(std::move(server_hello), 5);
    flight.add_message(std::move(sh_message));
    
    // Add Certificate (mock)
    Certificate certificate;
    HandshakeMessage cert_message(std::move(certificate), 6);
    flight.add_message(std::move(cert_message));
    
    EXPECT_EQ(flight.get_messages().size(), 2);
    
    auto range = flight.get_sequence_range();
    EXPECT_EQ(range.first, 5);
    EXPECT_EQ(range.second, 6); // Two messages
}

// ============================================================================
// FlightManager Tests
// ============================================================================

class FlightManagerTest : public MessageLayerComprehensiveTest {};

TEST_F(FlightManagerTest, BasicFlightManagement) {
    FlightManager manager;
    
    auto stats = manager.get_stats();
    EXPECT_EQ(stats.flights_created, 0);
    EXPECT_EQ(stats.flights_transmitted, 0);
    
    // Create flight
    auto result = manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_TRUE(result.is_success());
    
    stats = manager.get_stats();
    EXPECT_EQ(stats.flights_created, 1);
}

TEST_F(FlightManagerTest, MultipleFlightCreation) {
    FlightManager manager;
    
    // Create first flight
    auto result1 = manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_TRUE(result1.is_success());
    
    // Try to create another flight before completing first
    auto result2 = manager.create_flight(FlightType::SERVER_HELLO_FLIGHT);
    EXPECT_FALSE(result2.is_success());
    EXPECT_EQ(result2.error(), DTLSError::FLIGHT_IN_PROGRESS);
}

TEST_F(FlightManagerTest, AddMessageToFlight) {
    FlightManager manager;
    
    // Try to add message without current flight
    ClientHello client_hello;
    HandshakeMessage message(std::move(client_hello), 1);
    auto result = manager.add_message_to_current_flight(std::move(message));
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::NO_CURRENT_FLIGHT);
    
    // Create flight and then add message
    manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    
    ClientHello client_hello2;
    HandshakeMessage message2(std::move(client_hello2), 1);
    result = manager.add_message_to_current_flight(std::move(message2));
    EXPECT_TRUE(result.is_success());
}

TEST_F(FlightManagerTest, CompleteCurrentFlight) {
    FlightManager manager;
    
    // Try to complete without current flight
    auto result = manager.complete_current_flight();
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::NO_CURRENT_FLIGHT);
    
    // Create flight and add message
    manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    
    ClientHello client_hello;
    HandshakeMessage message(std::move(client_hello), 1);
    manager.add_message_to_current_flight(std::move(message));
    
    // Complete the flight
    result = manager.complete_current_flight();
    ASSERT_TRUE(result.is_success());
    
    auto flight = std::move(result.value());
    EXPECT_NE(flight, nullptr);
    EXPECT_EQ(flight->get_type(), FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_EQ(flight->get_messages().size(), 1);
}

TEST_F(FlightManagerTest, RetransmissionManagement) {
    FlightManager manager;
    
    // Set retransmission parameters
    manager.set_retransmission_timeout(std::chrono::milliseconds(100));
    manager.set_max_retransmissions(3);
    
    // Create and complete flight
    manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    ClientHello client_hello;
    HandshakeMessage message(std::move(client_hello), 1);
    manager.add_message_to_current_flight(std::move(message));
    auto flight_result = manager.complete_current_flight();
    ASSERT_TRUE(flight_result.is_success());
    
    FlightType flight_type = FlightType::CLIENT_HELLO_FLIGHT;
    
    // Initially should not need retransmission
    EXPECT_FALSE(manager.should_retransmit(flight_type));
    
    // Mark as transmitted
    manager.mark_flight_transmitted(flight_type);
    
    // Still should not need retransmission immediately
    EXPECT_FALSE(manager.should_retransmit(flight_type));
    
    // Wait for timeout and check again
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_TRUE(manager.should_retransmit(flight_type));
    
    // Mark as acknowledged - should no longer need retransmission
    manager.mark_flight_acknowledged(flight_type);
    EXPECT_FALSE(manager.should_retransmit(flight_type));
}

TEST_F(FlightManagerTest, RetransmissionLimits) {
    FlightManager manager;
    manager.set_retransmission_timeout(std::chrono::milliseconds(10));
    manager.set_max_retransmissions(2);
    
    // Create and complete flight
    manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    ClientHello client_hello;
    HandshakeMessage message(std::move(client_hello), 1);
    manager.add_message_to_current_flight(std::move(message));
    auto flight_result = manager.complete_current_flight();
    ASSERT_TRUE(flight_result.is_success());
    
    FlightType flight_type = FlightType::CLIENT_HELLO_FLIGHT;
    
    // Mark as transmitted multiple times (exceeding limit)
    for (int i = 0; i < 3; ++i) {
        manager.mark_flight_transmitted(flight_type);
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
    
    // Should not retransmit after hitting limit
    EXPECT_FALSE(manager.should_retransmit(flight_type));
}

// ============================================================================
// MessageLayer Integration Tests
// ============================================================================

class MessageLayerIntegrationTest : public MessageLayerComprehensiveTest {};

TEST_F(MessageLayerIntegrationTest, BasicInitialization) {
    // Create record layer
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    auto init_result = record_layer->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Create message layer
    auto message_layer = std::make_unique<MessageLayer>(std::move(record_layer));
    
    auto result = message_layer->initialize();
    EXPECT_TRUE(result.is_success());
}

TEST_F(MessageLayerIntegrationTest, InitializationWithoutRecordLayer) {
    auto message_layer = std::make_unique<MessageLayer>(nullptr);
    
    auto result = message_layer->initialize();
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::RECORD_LAYER_NOT_AVAILABLE);
}

TEST_F(MessageLayerIntegrationTest, FlightCreationAndManagement) {
    auto message_layer = message_layer_utils::create_test_message_layer();
    ASSERT_NE(message_layer, nullptr);
    
    // Start a flight
    auto result = message_layer->start_flight(FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_TRUE(result.is_success());
    
    // Add message to flight
    ClientHello client_hello;
    client_hello.set_cipher_suites({CipherSuite::TLS_AES_128_GCM_SHA256});
    HandshakeMessage message(std::move(client_hello), 1);
    
    result = message_layer->add_to_current_flight(std::move(message));
    EXPECT_TRUE(result.is_success());
    
    // Complete and send flight
    result = message_layer->complete_and_send_flight();
    EXPECT_TRUE(result.is_success());
    
    auto stats = message_layer->get_stats();
    EXPECT_GT(stats.flights_sent, 0);
}

TEST_F(MessageLayerIntegrationTest, MessageLayerConfiguration) {
    auto message_layer = message_layer_utils::create_test_message_layer();
    ASSERT_NE(message_layer, nullptr);
    
    // Set configuration parameters
    message_layer->set_max_fragment_size(512);
    message_layer->set_retransmission_timeout(std::chrono::milliseconds(500));
    message_layer->set_max_retransmissions(5);
    
    // Configuration should be accepted without error
    auto stats = message_layer->get_stats();
    EXPECT_EQ(stats.messages_sent, 0); // Initially zero
}

TEST_F(MessageLayerIntegrationTest, HandleRetransmissions) {
    auto message_layer = message_layer_utils::create_test_message_layer();
    ASSERT_NE(message_layer, nullptr);
    
    auto result = message_layer->handle_retransmissions();
    EXPECT_TRUE(result.is_success()); // Should succeed even with no flights
}

// ============================================================================
// Message Processing Tests
// ============================================================================

class MessageProcessingTest : public MessageLayerComprehensiveTest {};

TEST_F(MessageProcessingTest, ProcessInvalidContentType) {
    auto message_layer = message_layer_utils::create_test_message_layer();
    ASSERT_NE(message_layer, nullptr);
    
    // Create record with wrong content type
    Buffer payload(16);
    std::memcpy(payload.mutable_data(), test_message_data_.data(), 16);
    
    PlaintextRecord record(protocol::ContentType::APPLICATION_DATA, // Wrong type
                          static_cast<protocol::ProtocolVersion>(DTLS_V13),
                          0, 0, std::move(payload));
    
    auto result = message_layer->process_incoming_handshake_record(record);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_CONTENT_TYPE);
}

// ============================================================================
// Utility Function Tests
// ============================================================================

class UtilityFunctionTest : public MessageLayerComprehensiveTest {};

TEST_F(UtilityFunctionTest, CreateTestMessageLayer) {
    auto test_layer = message_layer_utils::create_test_message_layer();
    EXPECT_NE(test_layer, nullptr);
    
    if (test_layer) {
        auto stats = test_layer->get_stats();
        EXPECT_EQ(stats.messages_sent, 0);
        EXPECT_EQ(stats.messages_received, 0);
    }
}

TEST_F(UtilityFunctionTest, ValidateMessageLayerConfig) {
    auto test_layer = message_layer_utils::create_test_message_layer();
    ASSERT_NE(test_layer, nullptr);
    
    auto result = message_layer_utils::validate_message_layer_config(*test_layer);
    EXPECT_TRUE(result.is_success());
}

TEST_F(UtilityFunctionTest, GenerateTestHandshakeMessages) {
    auto result = message_layer_utils::generate_test_handshake_messages();
    EXPECT_TRUE(result.is_success());
    
    if (result.is_success()) {
        const auto& messages = result.value();
        EXPECT_GT(messages.size(), 0);
    }
}

TEST_F(UtilityFunctionTest, TestFragmentationReassembly) {
    auto messages_result = message_layer_utils::generate_test_handshake_messages();
    ASSERT_TRUE(messages_result.is_success());
    
    const auto& messages = messages_result.value();
    if (!messages.empty()) {
        auto result = message_layer_utils::test_fragmentation_reassembly(messages[0], 128);
        EXPECT_TRUE(result.is_success());
        
        if (result.is_success()) {
            EXPECT_TRUE(result.value());
        }
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

class ErrorHandlingTest : public MessageLayerComprehensiveTest {};

TEST_F(ErrorHandlingTest, SendMessageWithoutRecordLayer) {
    auto message_layer = std::make_unique<MessageLayer>(nullptr);
    
    ClientHello client_hello;
    HandshakeMessage message(std::move(client_hello), 1);
    
    auto result = message_layer->send_handshake_message(message);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::RECORD_LAYER_NOT_AVAILABLE);
}

TEST_F(ErrorHandlingTest, SendInvalidFlight) {
    auto message_layer = message_layer_utils::create_test_message_layer();
    ASSERT_NE(message_layer, nullptr);
    
    auto result = message_layer->send_handshake_flight(nullptr);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_FLIGHT);
}

TEST_F(ErrorHandlingTest, CompleteFlightWithoutCurrentFlight) {
    auto message_layer = message_layer_utils::create_test_message_layer();
    ASSERT_NE(message_layer, nullptr);
    
    auto result = message_layer->complete_and_send_flight();
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::NO_CURRENT_FLIGHT);
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

class PerformanceTest : public MessageLayerComprehensiveTest {};

TEST_F(PerformanceTest, LargeMessageFragmentation) {
    MessageReassembler reassembler;
    
    // Create large message data (4KB)
    std::vector<uint8_t> large_data(4096);
    for (size_t i = 0; i < large_data.size(); ++i) {
        large_data[i] = static_cast<uint8_t>(i % 256);
    }
    
    // Fragment into 128-byte chunks
    const size_t fragment_size = 128;
    size_t num_fragments = (large_data.size() + fragment_size - 1) / fragment_size;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_fragments; ++i) {
        size_t offset = i * fragment_size;
        size_t length = std::min(fragment_size, large_data.size() - offset);
        
        Buffer fragment_data(length);
        std::memcpy(fragment_data.mutable_data(), large_data.data() + offset, length);
        
        MessageFragment fragment(1, offset, length, large_data.size(), std::move(fragment_data));
        
        auto result = reassembler.add_fragment(fragment);
        ASSERT_TRUE(result.is_success());
        
        if (i == num_fragments - 1) {
            EXPECT_TRUE(result.value()); // Should be complete
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_TRUE(reassembler.is_complete());
    EXPECT_LT(duration.count(), 100); // Should complete in reasonable time
    
    auto message_result = reassembler.get_complete_message();
    ASSERT_TRUE(message_result.is_success());
    
    const auto& message = message_result.value();
    EXPECT_EQ(message.size(), large_data.size());
    EXPECT_EQ(std::memcmp(message.data(), large_data.data(), large_data.size()), 0);
}

TEST_F(PerformanceTest, ConcurrentReassembly) {
    const int num_threads = 4;
    const int messages_per_thread = 100;
    std::vector<std::thread> threads;
    std::vector<std::unique_ptr<MessageReassembler>> reassemblers(num_threads);
    
    // Initialize reassemblers
    for (int i = 0; i < num_threads; ++i) {
        reassemblers[i] = std::make_unique<MessageReassembler>();
    }
    
    // Launch threads
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&reassemblers, t, messages_per_thread, this]() {
            auto& reassembler = *reassemblers[t];
            
            for (int i = 0; i < messages_per_thread; ++i) {
                // Create unique message data
                std::vector<uint8_t> message_data(16);
                for (size_t j = 0; j < message_data.size(); ++j) {
                    message_data[j] = static_cast<uint8_t>((t * messages_per_thread + i + j) % 256);
                }
                
                Buffer fragment_data(message_data.size());
                std::memcpy(fragment_data.mutable_data(), message_data.data(), message_data.size());
                
                MessageFragment fragment(i, 0, message_data.size(), message_data.size(), std::move(fragment_data));
                
                auto result = reassembler.add_fragment(fragment);
                EXPECT_TRUE(result.is_success());
                EXPECT_TRUE(result.value()); // Complete message
                
                // Clear for next message
                reassembler.clear();
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
}

TEST_F(PerformanceTest, FlightManagerStressTest) {
    FlightManager manager;
    const int num_flights = 1000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_flights; ++i) {
        // Create flight
        auto create_result = manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
        ASSERT_TRUE(create_result.is_success());
        
        // Add message
        ClientHello client_hello;
        client_hello.set_cipher_suites({CipherSuite::TLS_AES_128_GCM_SHA256});
        HandshakeMessage message(std::move(client_hello), i);
        
        auto add_result = manager.add_message_to_current_flight(std::move(message));
        ASSERT_TRUE(add_result.is_success());
        
        // Complete flight
        auto complete_result = manager.complete_current_flight();
        ASSERT_TRUE(complete_result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_LT(duration.count(), 1000); // Should complete in reasonable time
    
    auto stats = manager.get_stats();
    EXPECT_EQ(stats.flights_created, num_flights);
}

// Test HandshakeFlight move semantics (classes without mutexes)
TEST_F(MessageLayerComprehensiveTest, HandshakeFlightMoveSemantics) {
    // Test HandshakeFlight move
    HandshakeFlight flight1(FlightType::CLIENT_HELLO_FLIGHT, 1);
    ClientHello client_hello;
    HandshakeMessage message(std::move(client_hello), 1);
    flight1.add_message(std::move(message));
    
    HandshakeFlight flight2 = std::move(flight1);
    EXPECT_TRUE(flight2.is_complete());
    EXPECT_GT(flight2.get_total_size(), 0);
}