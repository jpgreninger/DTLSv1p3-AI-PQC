/**
 * @file test_message_layer_comprehensive_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS message layer implementation
 * 
 * Target: Achieve >95% coverage for message_layer.cpp
 * Tests all major components: MessageFragment, MessageReassembler, HandshakeFlight,
 * FlightManager, MessageLayer functionality including fragmentation, reassembly,
 * flight management, and error handling
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <cstddef>
#include <algorithm>
#include <set>

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

class MessageLayerEnhancedTest : public ::testing::Test {
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
        
        // Create test message data of various sizes
        small_message_data_ = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };
        
        medium_message_data_.resize(512);
        for (size_t i = 0; i < medium_message_data_.size(); ++i) {
            medium_message_data_[i] = static_cast<uint8_t>(i % 256);
        }
        
        large_message_data_.resize(4096);
        std::mt19937 rng(123); // Fixed seed for reproducible tests
        for (size_t i = 0; i < large_message_data_.size(); ++i) {
            large_message_data_[i] = static_cast<uint8_t>(rng() % 256);
        }
        
        // Create maximum size message (near DTLS limit)
        max_message_data_.resize(16000);
        for (size_t i = 0; i < max_message_data_.size(); ++i) {
            max_message_data_[i] = static_cast<uint8_t>((i * 17) % 256);
        }
        
        // Create handshake message test data
        create_test_handshake_messages();
    }
    
    void create_test_handshake_messages() {
        // ClientHello message
        client_hello_data_ = {
            0x01, 0x00, 0x00, 0x30, // msg_type=1, length=48
            0x03, 0x04, // ProtocolVersion DTLS 1.3
            // Random (32 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x00, // Session ID length
            0x00, 0x02, // Cipher suites length
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x01, 0x00, // Compression methods
            0x00, 0x00  // Extensions length
        };
        
        // ServerHello message
        server_hello_data_ = {
            0x02, 0x00, 0x00, 0x30, // msg_type=2, length=48
            0x03, 0x04, // ProtocolVersion DTLS 1.3
            // Random (32 bytes)
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
            0x00, // Session ID length
            0x13, 0x01, // Selected cipher suite
            0x00, // Selected compression method
            0x00, 0x00  // Extensions length
        };
        
        // Certificate message
        certificate_data_.resize(1024);
        certificate_data_[0] = 0x0B; // msg_type=11
        certificate_data_[1] = 0x00; // length high
        certificate_data_[2] = 0x04; // length medium
        certificate_data_[3] = 0x00; // length low (1024 bytes)
        // Fill rest with test certificate data
        for (size_t i = 4; i < certificate_data_.size(); ++i) {
            certificate_data_[i] = static_cast<uint8_t>((i + 100) % 256);
        }
        
        // Finished message
        finished_data_ = {
            0x14, 0x00, 0x00, 0x20, // msg_type=20, length=32
            // Verify data (32 bytes)
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60
        };
    }
    
    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
    std::vector<uint8_t> small_message_data_;
    std::vector<uint8_t> medium_message_data_;
    std::vector<uint8_t> large_message_data_;
    std::vector<uint8_t> max_message_data_;
    std::vector<uint8_t> client_hello_data_;
    std::vector<uint8_t> server_hello_data_;
    std::vector<uint8_t> certificate_data_;
    std::vector<uint8_t> finished_data_;
};

// ============================================================================
// MessageFragment Comprehensive Tests
// ============================================================================

class MessageFragmentTest : public MessageLayerEnhancedTest {};

TEST_F(MessageFragmentTest, DefaultConstruction) {
    MessageFragment fragment;
    EXPECT_EQ(fragment.message_seq, 0);
    EXPECT_EQ(fragment.fragment_offset, 0);
    EXPECT_EQ(fragment.fragment_length, 0);
    EXPECT_EQ(fragment.total_length, 0);
    EXPECT_TRUE(fragment.fragment_data.empty());
}

TEST_F(MessageFragmentTest, ParameterizedConstruction) {
    MessageFragment fragment(1, 100, 200, 500, small_message_data_);
    
    EXPECT_EQ(fragment.message_seq, 1);
    EXPECT_EQ(fragment.fragment_offset, 100);
    EXPECT_EQ(fragment.fragment_length, 200);
    EXPECT_EQ(fragment.total_length, 500);
    EXPECT_EQ(fragment.fragment_data, small_message_data_);
}

TEST_F(MessageFragmentTest, IsCompleteMessage) {
    // Complete message (offset=0, fragment_length=total_length)
    MessageFragment complete(1, 0, 100, 100, medium_message_data_);
    EXPECT_TRUE(complete.is_complete_message());
    
    // Partial message (offset > 0)
    MessageFragment partial1(1, 50, 100, 200, medium_message_data_);
    EXPECT_FALSE(partial1.is_complete_message());
    
    // Partial message (fragment_length < total_length)
    MessageFragment partial2(1, 0, 100, 200, medium_message_data_);
    EXPECT_FALSE(partial2.is_complete_message());
    
    // Edge case: zero-length message
    MessageFragment empty(1, 0, 0, 0, {});
    EXPECT_TRUE(empty.is_complete_message());
}

TEST_F(MessageFragmentTest, IsValid) {
    // Valid fragment
    MessageFragment valid(1, 0, 100, 200, small_message_data_);
    EXPECT_TRUE(valid.is_valid());
    
    // Invalid: fragment_offset + fragment_length > total_length
    MessageFragment invalid1(1, 150, 100, 200, small_message_data_);
    EXPECT_FALSE(invalid1.is_valid());
    
    // Invalid: fragment_length > data size
    MessageFragment invalid2(1, 0, 1000, 2000, small_message_data_);
    EXPECT_FALSE(invalid2.is_valid());
    
    // Invalid: fragment_offset >= total_length (when total_length > 0)
    MessageFragment invalid3(1, 200, 50, 200, small_message_data_);
    EXPECT_FALSE(invalid3.is_valid());
    
    // Edge case: empty fragment of empty message
    MessageFragment empty_valid(1, 0, 0, 0, {});
    EXPECT_TRUE(empty_valid.is_valid());
}

TEST_F(MessageFragmentTest, LargeFragments) {
    MessageFragment large_fragment(1, 0, large_message_data_.size(), 
                                  large_message_data_.size(), large_message_data_);
    
    EXPECT_TRUE(large_fragment.is_valid());
    EXPECT_TRUE(large_fragment.is_complete_message());
    EXPECT_EQ(large_fragment.fragment_data.size(), large_message_data_.size());
}

TEST_F(MessageFragmentTest, BoundaryConditions) {
    // Maximum values
    MessageFragment max_fragment(0xFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, max_message_data_);
    EXPECT_TRUE(max_fragment.is_valid());
    
    // Zero sequence number (should be valid)
    MessageFragment zero_seq(0, 0, 100, 200, small_message_data_);
    EXPECT_TRUE(zero_seq.is_valid());
    
    // Fragment at end of message
    MessageFragment end_fragment(1, 900, 100, 1000, small_message_data_);
    EXPECT_TRUE(end_fragment.is_valid());
}

// ============================================================================
// MessageReassembler Comprehensive Tests
// ============================================================================

class MessageReassemblerTest : public MessageLayerEnhancedTest {};

TEST_F(MessageReassemblerTest, DefaultConstruction) {
    MessageReassembler reassembler;
    
    // Should have no active reassemblies
    auto result = reassembler.get_complete_message(1);
    EXPECT_FALSE(result.is_success());
}

TEST_F(MessageReassemblerTest, SingleFragmentMessage) {
    MessageReassembler reassembler;
    
    MessageFragment complete_fragment(1, 0, small_message_data_.size(), 
                                    small_message_data_.size(), small_message_data_);
    
    auto add_result = reassembler.add_fragment(complete_fragment);
    EXPECT_TRUE(add_result.is_success());
    EXPECT_TRUE(add_result.value()); // Should be complete
    
    auto message_result = reassembler.get_complete_message(1);
    EXPECT_TRUE(message_result.is_success());
    EXPECT_EQ(message_result.value(), small_message_data_);
}

TEST_F(MessageReassemblerTest, MultiFragmentMessage) {
    MessageReassembler reassembler;
    
    // Split medium message into 4 fragments
    size_t fragment_size = medium_message_data_.size() / 4;
    
    for (size_t i = 0; i < 4; ++i) {
        size_t offset = i * fragment_size;
        size_t length = (i == 3) ? medium_message_data_.size() - offset : fragment_size;
        
        std::vector<uint8_t> fragment_data(
            medium_message_data_.begin() + offset,
            medium_message_data_.begin() + offset + length
        );
        
        MessageFragment fragment(2, offset, length, medium_message_data_.size(), fragment_data);
        
        auto add_result = reassembler.add_fragment(fragment);
        EXPECT_TRUE(add_result.is_success());
        
        if (i == 3) {
            EXPECT_TRUE(add_result.value()); // Should be complete after last fragment
        } else {
            EXPECT_FALSE(add_result.value()); // Should not be complete yet
        }
    }
    
    auto message_result = reassembler.get_complete_message(2);
    EXPECT_TRUE(message_result.is_success());
    EXPECT_EQ(message_result.value(), medium_message_data_);
}

TEST_F(MessageReassemblerTest, OutOfOrderFragments) {
    MessageReassembler reassembler;
    
    // Split large message into 8 fragments and add them out of order
    size_t fragment_size = large_message_data_.size() / 8;
    std::vector<MessageFragment> fragments;
    
    for (size_t i = 0; i < 8; ++i) {
        size_t offset = i * fragment_size;
        size_t length = (i == 7) ? large_message_data_.size() - offset : fragment_size;
        
        std::vector<uint8_t> fragment_data(
            large_message_data_.begin() + offset,
            large_message_data_.begin() + offset + length
        );
        
        fragments.emplace_back(3, offset, length, large_message_data_.size(), fragment_data);
    }
    
    // Add fragments in reverse order
    for (int i = 7; i >= 0; --i) {
        auto add_result = reassembler.add_fragment(fragments[i]);
        EXPECT_TRUE(add_result.is_success());
        
        if (i == 0) {
            EXPECT_TRUE(add_result.value()); // Should be complete after last fragment
        } else {
            EXPECT_FALSE(add_result.value()); // Should not be complete yet
        }
    }
    
    auto message_result = reassembler.get_complete_message(3);
    EXPECT_TRUE(message_result.is_success());
    EXPECT_EQ(message_result.value(), large_message_data_);
}

TEST_F(MessageReassemblerTest, DuplicateFragments) {
    MessageReassembler reassembler;
    
    MessageFragment fragment(4, 0, 100, 200, small_message_data_);
    
    // Add same fragment twice
    auto add_result1 = reassembler.add_fragment(fragment);
    EXPECT_TRUE(add_result1.is_success());
    EXPECT_FALSE(add_result1.value()); // Not complete
    
    auto add_result2 = reassembler.add_fragment(fragment);
    EXPECT_TRUE(add_result2.is_success());
    EXPECT_FALSE(add_result2.value()); // Still not complete
    
    // Add second fragment to complete message
    MessageFragment fragment2(4, 100, 100, 200, small_message_data_);
    auto add_result3 = reassembler.add_fragment(fragment2);
    EXPECT_TRUE(add_result3.is_success());
    EXPECT_TRUE(add_result3.value()); // Now complete
}

TEST_F(MessageReassemblerTest, OverlappingFragments) {
    MessageReassembler reassembler;
    
    // Create overlapping fragments
    MessageFragment fragment1(5, 0, 150, 200, small_message_data_);
    MessageFragment fragment2(5, 100, 100, 200, small_message_data_);
    
    auto add_result1 = reassembler.add_fragment(fragment1);
    EXPECT_TRUE(add_result1.is_success());
    
    auto add_result2 = reassembler.add_fragment(fragment2);
    EXPECT_TRUE(add_result2.is_success());
    EXPECT_TRUE(add_result2.value()); // Should be complete due to overlap covering everything
}

TEST_F(MessageReassemblerTest, InvalidFragments) {
    MessageReassembler reassembler;
    
    // Invalid fragment (offset + length > total_length)
    MessageFragment invalid(6, 150, 100, 200, small_message_data_);
    auto add_result = reassembler.add_fragment(invalid);
    EXPECT_FALSE(add_result.is_success());
}

TEST_F(MessageReassemblerTest, MultipleSimultaneousReassemblies) {
    MessageReassembler reassembler;
    
    // Start reassembly for multiple message sequences
    for (uint16_t seq = 10; seq <= 15; ++seq) {
        // Add first fragment for each sequence
        MessageFragment fragment(seq, 0, 100, 300, small_message_data_);
        auto add_result = reassembler.add_fragment(fragment);
        EXPECT_TRUE(add_result.is_success());
        EXPECT_FALSE(add_result.value()); // Not complete yet
    }
    
    // Complete one of the messages
    MessageFragment fragment2(12, 100, 100, 300, small_message_data_);
    MessageFragment fragment3(12, 200, 100, 300, small_message_data_);
    
    EXPECT_TRUE(reassembler.add_fragment(fragment2).is_success());
    auto add_result = reassembler.add_fragment(fragment3);
    EXPECT_TRUE(add_result.is_success());
    EXPECT_TRUE(add_result.value()); // Message 12 should be complete
    
    // Verify we can get the complete message
    auto message_result = reassembler.get_complete_message(12);
    EXPECT_TRUE(message_result.is_success());
    
    // Other messages should still be incomplete
    auto incomplete_result = reassembler.get_complete_message(10);
    EXPECT_FALSE(incomplete_result.is_success());
}

TEST_F(MessageReassemblerTest, ClearReassembly) {
    MessageReassembler reassembler;
    
    MessageFragment fragment(7, 0, 100, 200, small_message_data_);
    EXPECT_TRUE(reassembler.add_fragment(fragment).is_success());
    
    // Clear the reassembly
    reassembler.clear_reassembly(7);
    
    // Should not be able to get the message
    auto message_result = reassembler.get_complete_message(7);
    EXPECT_FALSE(message_result.is_success());
}

TEST_F(MessageReassemblerTest, ResourceManagement) {
    MessageReassembler reassembler;
    
    // Add many incomplete reassemblies to test resource management
    for (uint16_t seq = 100; seq < 200; ++seq) {
        MessageFragment fragment(seq, 0, 100, 500, small_message_data_);
        auto add_result = reassembler.add_fragment(fragment);
        EXPECT_TRUE(add_result.is_success());
    }
    
    // All should be incomplete
    for (uint16_t seq = 100; seq < 110; ++seq) {
        auto message_result = reassembler.get_complete_message(seq);
        EXPECT_FALSE(message_result.is_success());
    }
}

// ============================================================================
// HandshakeFlight Tests
// ============================================================================

class HandshakeFlightTest : public MessageLayerEnhancedTest {};

TEST_F(HandshakeFlightTest, DefaultConstruction) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 1);
    
    EXPECT_EQ(flight.get_flight_type(), FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_EQ(flight.get_flight_number(), 1);
    EXPECT_TRUE(flight.get_messages().empty());
    EXPECT_FALSE(flight.is_complete());
}

TEST_F(HandshakeFlightTest, AddMessages) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 1);
    
    // Create a proper HandshakeMessage for testing
    ClientHello client_hello;
    client_hello.set_random(std::vector<uint8_t>(32, 0x42));
    HandshakeMessage message(std::move(client_hello), 1);
    
    // Add ClientHello message
    flight.add_message(std::move(message));
    
    auto messages = flight.get_messages();
    EXPECT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0].message_type(), HandshakeType::CLIENT_HELLO);
}

TEST_F(HandshakeFlightTest, MultipleMessages) {
    HandshakeFlight flight(FlightType::SERVER_CERTIFICATE_FLIGHT, 2);
    
    // Create proper HandshakeMessage objects
    ServerHello server_hello;
    server_hello.set_random(std::vector<uint8_t>(32, 0x43));
    HandshakeMessage hello_message(std::move(server_hello), 1);
    
    Certificate certificate;
    HandshakeMessage cert_message(std::move(certificate), 2);
    
    Finished finished;
    HandshakeMessage fin_message(std::move(finished), 3);
    
    // Add multiple messages to flight
    flight.add_message(std::move(hello_message));
    flight.add_message(std::move(cert_message));
    flight.add_message(std::move(fin_message));
    
    auto messages = flight.get_messages();
    EXPECT_EQ(messages.size(), 3);
    EXPECT_EQ(messages[0].message_type(), HandshakeType::SERVER_HELLO);
    EXPECT_EQ(messages[1].message_type(), HandshakeType::CERTIFICATE);
    EXPECT_EQ(messages[2].message_type(), HandshakeType::FINISHED);
}

TEST_F(HandshakeFlightTest, FlightCompletion) {
    HandshakeFlight flight(FlightType::CLIENT_FINISHED_FLIGHT, 3);
    
    EXPECT_FALSE(flight.is_complete());
    
    // Mark as complete
    flight.mark_complete();
    EXPECT_TRUE(flight.is_complete());
    
    // Can still add messages after marking complete
    EXPECT_TRUE(flight.add_message(finished_data_).is_success());
}

TEST_F(HandshakeFlightTest, FlightSerialization) {
    HandshakeFlight flight(FlightType::SERVER_HELLO_FLIGHT, 2);
    
    flight.add_message(server_hello_data_);
    flight.add_message(certificate_data_);
    
    auto serialized = flight.serialize();
    EXPECT_TRUE(serialized.is_success());
    
    // Serialized data should contain both messages
    auto data = serialized.value();
    EXPECT_GT(data.size(), server_hello_data_.size() + certificate_data_.size());
}

TEST_F(HandshakeFlightTest, EmptyFlightSerialization) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 1);
    
    auto serialized = flight.serialize();
    EXPECT_TRUE(serialized.is_success());
    
    // Empty flight should produce minimal serialized data
    auto data = serialized.value();
    EXPECT_GT(data.size(), 0); // Should have at least header information
}

TEST_F(HandshakeFlightTest, DifferentFlightTypes) {
    std::vector<FlightType> flight_types = {
        FlightType::CLIENT_HELLO_FLIGHT,
        FlightType::SERVER_HELLO_FLIGHT,
        FlightType::CLIENT_CERTIFICATE_FLIGHT,
        FlightType::SERVER_CERTIFICATE_FLIGHT,
        FlightType::CLIENT_FINISHED_FLIGHT,
        FlightType::SERVER_FINISHED_FLIGHT
    };
    
    for (size_t i = 0; i < flight_types.size(); ++i) {
        HandshakeFlight flight(flight_types[i], i + 1);
        EXPECT_EQ(flight.get_flight_type(), flight_types[i]);
        EXPECT_EQ(flight.get_flight_number(), i + 1);
    }
}

// ============================================================================
// FlightManager Tests
// ============================================================================

class FlightManagerTest : public MessageLayerEnhancedTest {};

TEST_F(FlightManagerTest, DefaultConstruction) {
    FlightManager manager;
    
    // Should have no active flights
    auto current_flight = manager.get_current_flight();
    EXPECT_FALSE(current_flight.is_success());
}

TEST_F(FlightManagerTest, CreateNewFlight) {
    FlightManager manager;
    
    auto create_result = manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_TRUE(create_result.is_success());
    
    auto current_flight = manager.get_current_flight();
    EXPECT_TRUE(current_flight.is_success());
    EXPECT_EQ(current_flight.value()->get_flight_type(), FlightType::CLIENT_HELLO_FLIGHT);
}

TEST_F(FlightManagerTest, AddMessageToCurrentFlight) {
    FlightManager manager;
    
    EXPECT_TRUE(manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT).is_success());
    
    auto add_result = manager.add_message_to_current_flight(client_hello_data_);
    EXPECT_TRUE(add_result.is_success());
    
    auto current_flight = manager.get_current_flight();
    EXPECT_TRUE(current_flight.is_success());
    
    auto messages = current_flight.value()->get_messages();
    EXPECT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0], client_hello_data_);
}

TEST_F(FlightManagerTest, CompleteCurrentFlight) {
    FlightManager manager;
    
    EXPECT_TRUE(manager.create_flight(FlightType::SERVER_HELLO_FLIGHT).is_success());
    EXPECT_TRUE(manager.add_message_to_current_flight(server_hello_data_).is_success());
    
    auto complete_result = manager.complete_current_flight();
    EXPECT_TRUE(complete_result.is_success());
    
    // Current flight should still be accessible but marked complete
    auto current_flight = manager.get_current_flight();
    EXPECT_TRUE(current_flight.is_success());
    EXPECT_TRUE(current_flight.value()->is_complete());
}

TEST_F(FlightManagerTest, MultipleFlights) {
    FlightManager manager;
    
    // Create and complete first flight
    EXPECT_TRUE(manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT).is_success());
    EXPECT_TRUE(manager.add_message_to_current_flight(client_hello_data_).is_success());
    EXPECT_TRUE(manager.complete_current_flight().is_success());
    
    // Create second flight
    EXPECT_TRUE(manager.create_flight(FlightType::SERVER_HELLO_FLIGHT).is_success());
    EXPECT_TRUE(manager.add_message_to_current_flight(server_hello_data_).is_success());
    EXPECT_TRUE(manager.add_message_to_current_flight(certificate_data_).is_success());
    
    auto current_flight = manager.get_current_flight();
    EXPECT_TRUE(current_flight.is_success());
    EXPECT_EQ(current_flight.value()->get_messages().size(), 2);
}

TEST_F(FlightManagerTest, GetFlightHistory) {
    FlightManager manager;
    
    // Create multiple flights
    std::vector<FlightType> flight_types = {
        FlightType::CLIENT_HELLO_FLIGHT,
        FlightType::SERVER_HELLO_FLIGHT,
        FlightType::CLIENT_FINISHED_FLIGHT
    };
    
    for (auto type : flight_types) {
        EXPECT_TRUE(manager.create_flight(type).is_success());
        EXPECT_TRUE(manager.add_message_to_current_flight(client_hello_data_).is_success());
        EXPECT_TRUE(manager.complete_current_flight().is_success());
    }
    
    auto history = manager.get_flight_history();
    EXPECT_EQ(history.size(), flight_types.size());
    
    for (size_t i = 0; i < flight_types.size(); ++i) {
        EXPECT_EQ(history[i]->get_flight_type(), flight_types[i]);
        EXPECT_TRUE(history[i]->is_complete());
    }
}

TEST_F(FlightManagerTest, FlightRetransmission) {
    FlightManager manager;
    
    EXPECT_TRUE(manager.create_flight(FlightType::CLIENT_HELLO_FLIGHT).is_success());
    EXPECT_TRUE(manager.add_message_to_current_flight(client_hello_data_).is_success());
    EXPECT_TRUE(manager.complete_current_flight().is_success());
    
    // Request retransmission of last flight
    auto retransmit_result = manager.retransmit_last_flight();
    EXPECT_TRUE(retransmit_result.is_success());
    
    // Should get the flight data for retransmission
    auto flight_data = retransmit_result.value();
    EXPECT_GT(flight_data.size(), 0);
}

TEST_F(FlightManagerTest, ErrorHandling) {
    FlightManager manager;
    
    // Try to add message without creating flight
    auto add_result = manager.add_message_to_current_flight(client_hello_data_);
    EXPECT_FALSE(add_result.is_success());
    
    // Try to complete non-existent flight
    auto complete_result = manager.complete_current_flight();
    EXPECT_FALSE(complete_result.is_success());
    
    // Try to retransmit when no flights exist
    auto retransmit_result = manager.retransmit_last_flight();
    EXPECT_FALSE(retransmit_result.is_success());
}

// ============================================================================
// MessageLayer Integration Tests
// ============================================================================

class MessageLayerIntegrationTest : public MessageLayerEnhancedTest {};

TEST_F(MessageLayerIntegrationTest, FullMessageProcessingWorkflow) {
    // Create record layer for integration
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    EXPECT_TRUE(record_layer->initialize().is_success());
    
    MessageLayer message_layer(std::move(record_layer));
    
    // Initialize message layer
    auto init_result = message_layer.initialize();
    EXPECT_TRUE(init_result.is_success());
    
    // Send a complete message
    auto send_result = message_layer.send_message(client_hello_data_);
    EXPECT_TRUE(send_result.is_success());
    
    // Process the sent message data (simulate receiving it)
    auto received_data = send_result.value();
    auto process_result = message_layer.process_received_data(received_data);
    EXPECT_TRUE(process_result.is_success());
    
    // Should be able to get the complete message
    auto message_result = message_layer.get_next_complete_message();
    EXPECT_TRUE(message_result.is_success());
    EXPECT_EQ(message_result.value(), client_hello_data_);
}

TEST_F(MessageLayerIntegrationTest, FragmentationAndReassembly) {
    auto record_layer = std::make_unique<RecordLayer>(
        crypto::ProviderFactory::instance().create_provider("openssl").value()
    );
    EXPECT_TRUE(record_layer->initialize().is_success());
    
    MessageLayer message_layer(std::move(record_layer));
    EXPECT_TRUE(message_layer.initialize().is_success());
    
    // Configure small fragment size to force fragmentation
    auto config_result = message_layer.set_max_fragment_size(100);
    EXPECT_TRUE(config_result.is_success());
    
    // Send large message that will be fragmented
    auto send_result = message_layer.send_message(large_message_data_);
    EXPECT_TRUE(send_result.is_success());
    
    auto fragments = send_result.value();
    EXPECT_GT(fragments.size(), large_message_data_.size()); // Should be larger due to fragmentation overhead
    
    // Process all fragments
    auto process_result = message_layer.process_received_data(fragments);
    EXPECT_TRUE(process_result.is_success());
    
    // Should reassemble to original message
    auto message_result = message_layer.get_next_complete_message();
    EXPECT_TRUE(message_result.is_success());
    EXPECT_EQ(message_result.value(), large_message_data_);
}

TEST_F(MessageLayerIntegrationTest, HandshakeFlightProcessing) {
    auto record_layer = std::make_unique<RecordLayer>(
        crypto::ProviderFactory::instance().create_provider("openssl").value()
    );
    EXPECT_TRUE(record_layer->initialize().is_success());
    
    MessageLayer message_layer(std::move(record_layer));
    EXPECT_TRUE(message_layer.initialize().is_success());
    
    // Start client hello flight
    auto flight_result = message_layer.start_handshake_flight(FlightType::CLIENT_HELLO_FLIGHT);
    EXPECT_TRUE(flight_result.is_success());
    
    // Add message to flight
    auto add_result = message_layer.add_message_to_flight(client_hello_data_);
    EXPECT_TRUE(add_result.is_success());
    
    // Send flight
    auto send_result = message_layer.send_current_flight();
    EXPECT_TRUE(send_result.is_success());
    
    auto flight_data = send_result.value();
    EXPECT_GT(flight_data.size(), client_hello_data_.size());
    
    // Process received flight
    auto process_result = message_layer.process_received_data(flight_data);
    EXPECT_TRUE(process_result.is_success());
    
    // Should be able to get the flight
    auto received_flight = message_layer.get_next_complete_flight();
    EXPECT_TRUE(received_flight.is_success());
    EXPECT_EQ(received_flight.value()->get_flight_type(), FlightType::CLIENT_HELLO_FLIGHT);
}

TEST_F(MessageLayerIntegrationTest, ConcurrentMessageProcessing) {
    const int num_threads = 4;
    const int messages_per_thread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([this, &success_count, &failure_count, t, messages_per_thread]() {
            auto thread_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
            if (!thread_crypto.is_success()) {
                thread_crypto = crypto::ProviderFactory::instance().create_provider("mock");
            }
            
            auto record_layer = std::make_unique<RecordLayer>(std::move(thread_crypto.value()));
            if (!record_layer->initialize().is_success()) {
                failure_count += messages_per_thread;
                return;
            }
            
            MessageLayer message_layer(std::move(record_layer));
            if (!message_layer.initialize().is_success()) {
                failure_count += messages_per_thread;
                return;
            }
            
            for (int i = 0; i < messages_per_thread; ++i) {
                // Create unique message data for this thread and iteration
                auto message_data = small_message_data_;
                message_data.push_back(static_cast<uint8_t>(t));
                message_data.push_back(static_cast<uint8_t>(i));
                
                auto send_result = message_layer.send_message(message_data);
                if (send_result.is_success()) {
                    auto process_result = message_layer.process_received_data(send_result.value());
                    if (process_result.is_success()) {
                        auto message_result = message_layer.get_next_complete_message();
                        if (message_result.is_success() && message_result.value() == message_data) {
                            success_count++;
                        } else {
                            failure_count++;
                        }
                    } else {
                        failure_count++;
                    }
                } else {
                    failure_count++;
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_GT(success_count.load(), num_threads * messages_per_thread * 0.8); // Allow some failures in concurrent test
    std::cout << "Concurrent test results: " << success_count.load() << " successes, " 
              << failure_count.load() << " failures" << std::endl;
}

// ============================================================================
// Performance Tests
// ============================================================================

class MessageLayerPerformanceTest : public MessageLayerEnhancedTest {};

TEST_F(MessageLayerPerformanceTest, MessageProcessingThroughput) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    EXPECT_TRUE(record_layer->initialize().is_success());
    
    MessageLayer message_layer(std::move(record_layer));
    EXPECT_TRUE(message_layer.initialize().is_success());
    
    const int num_messages = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_messages; ++i) {
        auto send_result = message_layer.send_message(medium_message_data_);
        EXPECT_TRUE(send_result.is_success());
        
        auto process_result = message_layer.process_received_data(send_result.value());
        EXPECT_TRUE(process_result.is_success());
        
        auto message_result = message_layer.get_next_complete_message();
        EXPECT_TRUE(message_result.is_success());
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "Processed " << num_messages << " messages in " << duration.count() << "ms" << std::endl;
    std::cout << "Throughput: " << (num_messages * 1000) / duration.count() << " messages/second" << std::endl;
    
    // Performance should be reasonable
    EXPECT_LT(duration.count(), 5000); // Less than 5 seconds for 1000 messages
}

// Add test main
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}