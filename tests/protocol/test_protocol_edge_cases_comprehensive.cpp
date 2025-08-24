#include <gtest/gtest.h>
#include <dtls/protocol/record_layer.h>
#include <dtls/protocol/message_layer.h>
#include <dtls/protocol/version_manager.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/core/error.h>
#include <thread>
#include <chrono>
#include <random>

using namespace dtls::v13::protocol;
using namespace dtls::v13::crypto;
using namespace dtls::v13::memory;
using namespace dtls::v13;

class ProtocolEdgeCasesTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto provider = ProviderFactory::instance().create_provider("openssl");
        ASSERT_TRUE(provider.is_ok());
        crypto_provider_ = std::move(provider.value());
        
        record_layer_ = std::make_unique<RecordLayer>(std::move(crypto_provider_));
        ASSERT_TRUE(record_layer_->initialize().is_ok());
    }

    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
    std::unique_ptr<RecordLayer> record_layer_;
};

// Record Layer Edge Cases
TEST_F(ProtocolEdgeCasesTest, AntiReplayWindowBoundaryConditions) {
    AntiReplayWindow window(64);
    
    // Test wraparound at maximum sequence number
    uint64_t max_seq = (1ULL << 48) - 1;
    EXPECT_TRUE(window.check_and_update(max_seq));
    
    // Test sequence number 0 after maximum
    EXPECT_FALSE(window.check_and_update(0));
    
    // Test large gaps
    uint64_t large_gap = max_seq - 1000;
    EXPECT_TRUE(window.check_and_update(large_gap));
    
    // Test exactly at window boundary
    uint64_t boundary = max_seq - 64;
    EXPECT_TRUE(window.check_and_update(boundary));
    
    // Test just outside window boundary
    uint64_t outside = max_seq - 65;
    EXPECT_FALSE(window.check_and_update(outside));
}

TEST_F(ProtocolEdgeCasesTest, SequenceNumberManagerOverflowEdgeCases) {
    SequenceNumberManager manager;
    
    // Test near overflow conditions
    for (uint64_t i = 0; i < (1ULL << 48) - 10; ++i) {
        auto seq = manager.get_next_sequence_number();
        EXPECT_EQ(seq, i);
        
        // Check overflow detection near the end
        if (i > (1ULL << 48) - 5) {
            EXPECT_TRUE(manager.would_overflow());
        }
    }
    
    // Test exact overflow condition
    auto seq = manager.get_next_sequence_number();
    EXPECT_EQ(seq, (1ULL << 48) - 1);
    EXPECT_TRUE(manager.would_overflow());
    
    // Reset and verify
    manager.reset();
    EXPECT_EQ(manager.get_current_sequence_number(), 0);
    EXPECT_FALSE(manager.would_overflow());
}

TEST_F(ProtocolEdgeCasesTest, EpochManagerMaximumEpochHandling) {
    EpochManager manager;
    
    // Advance to maximum epoch
    for (uint16_t i = 0; i < 65534; ++i) {
        auto result = manager.advance_epoch();
        ASSERT_TRUE(result.is_ok());
        EXPECT_EQ(result.value(), i + 1);
    }
    
    // Test maximum epoch
    EXPECT_EQ(manager.get_current_epoch(), 65535);
    
    // Try to advance beyond maximum - should fail
    auto result = manager.advance_epoch();
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_INVALID_STATE);
}

TEST_F(ProtocolEdgeCasesTest, ConnectionIDManagerInvalidIDs) {
    ConnectionIDManager manager;
    
    // Test with maximum length connection ID
    ConnectionID max_cid;
    max_cid.data.resize(255, 0xAA);
    max_cid.length = 255;
    
    manager.set_local_connection_id(max_cid);
    EXPECT_EQ(manager.get_local_connection_id().length, 255);
    EXPECT_TRUE(manager.is_connection_id_enabled());
    
    // Test empty connection ID
    ConnectionID empty_cid;
    empty_cid.length = 0;
    
    manager.set_peer_connection_id(empty_cid);
    EXPECT_EQ(manager.get_peer_connection_id().length, 0);
    
    // Test validation with mismatched CID
    ConnectionID wrong_cid;
    wrong_cid.data.resize(10, 0xBB);
    wrong_cid.length = 10;
    
    EXPECT_FALSE(manager.is_valid_connection_id(wrong_cid));
    EXPECT_TRUE(manager.is_valid_connection_id(max_cid));
}

TEST_F(ProtocolEdgeCasesTest, RecordLayerInvalidInputHandling) {
    // Test with null/empty plaintext
    DTLSPlaintext empty_plaintext;
    empty_plaintext.content_type = ContentType::HANDSHAKE;
    empty_plaintext.legacy_record_version = DTLS_V13;
    empty_plaintext.epoch = 0;
    empty_plaintext.sequence_number = 1;
    // Leave fragment empty
    
    auto result = record_layer_->protect_record(empty_plaintext);
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
    
    // Test with oversized fragment
    DTLSPlaintext oversized_plaintext;
    oversized_plaintext.content_type = ContentType::APPLICATION_DATA;
    oversized_plaintext.legacy_record_version = DTLS_V13;
    oversized_plaintext.epoch = 0;
    oversized_plaintext.sequence_number = 2;
    oversized_plaintext.fragment.resize(17000, 0xCC); // Larger than max DTLS record
    
    result = record_layer_->protect_record(oversized_plaintext);
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_RECORD_TOO_LARGE);
}

TEST_F(ProtocolEdgeCasesTest, RecordLayerCorruptedCiphertextHandling) {
    // First create a valid ciphertext
    DTLSPlaintext valid_plaintext;
    valid_plaintext.content_type = ContentType::HANDSHAKE;
    valid_plaintext.legacy_record_version = DTLS_V13;
    valid_plaintext.epoch = 0;
    valid_plaintext.sequence_number = 1;
    valid_plaintext.fragment = {0x01, 0x02, 0x03, 0x04}; // Some test data
    
    auto protect_result = record_layer_->protect_record(valid_plaintext);
    ASSERT_TRUE(protect_result.is_ok());
    
    auto ciphertext = protect_result.value();
    
    // Corrupt the authentication tag
    if (!ciphertext.encrypted_record.empty()) {
        ciphertext.encrypted_record.back() ^= 0xFF;
    }
    
    auto unprotect_result = record_layer_->unprotect_record(ciphertext);
    EXPECT_FALSE(unprotect_result.is_ok());
    EXPECT_EQ(unprotect_result.error().code(), ErrorCode::DTLS_ERROR_DECRYPT_ERROR);
}

// Message Layer Edge Cases
TEST_F(ProtocolEdgeCasesTest, MessageFragmentBoundaryConditions) {
    // Test fragment with zero length
    MessageFragment zero_fragment(1, 0, 0, 100, Buffer{});
    EXPECT_TRUE(zero_fragment.is_valid());
    EXPECT_FALSE(zero_fragment.is_complete_message());
    
    // Test fragment at exact boundary
    Buffer boundary_data(50, 0xAA);
    MessageFragment boundary_fragment(1, 0, 50, 50, std::move(boundary_data));
    EXPECT_TRUE(boundary_fragment.is_valid());
    EXPECT_TRUE(boundary_fragment.is_complete_message());
    
    // Test fragment beyond total length
    Buffer invalid_data(100, 0xBB);
    MessageFragment invalid_fragment(1, 50, 100, 75, std::move(invalid_data));
    EXPECT_FALSE(invalid_fragment.is_valid());
    
    // Test fragment with mismatched data size
    Buffer mismatched_data(10, 0xCC);
    MessageFragment mismatched_fragment(1, 0, 20, 100, std::move(mismatched_data));
    EXPECT_FALSE(mismatched_fragment.is_valid());
}

TEST_F(ProtocolEdgeCasesTest, MessageReassemblerOverlappingFragments) {
    MessageReassembler reassembler;
    
    // Add overlapping fragments
    Buffer data1(50, 0x11);
    MessageFragment fragment1(1, 0, 50, 100, std::move(data1));
    auto result1 = reassembler.add_fragment(fragment1);
    ASSERT_TRUE(result1.is_ok());
    EXPECT_FALSE(result1.value()); // Not complete yet
    
    // Add overlapping fragment
    Buffer data2(60, 0x22);
    MessageFragment fragment2(1, 40, 60, 100, std::move(data2));
    auto result2 = reassembler.add_fragment(fragment2);
    EXPECT_TRUE(result2.is_ok());
    EXPECT_TRUE(result2.value()); // Should be complete now
    
    EXPECT_TRUE(reassembler.is_complete());
    
    auto complete_result = reassembler.get_complete_message();
    ASSERT_TRUE(complete_result.is_ok());
    EXPECT_EQ(complete_result.value().size(), 100);
}

TEST_F(ProtocolEdgeCasesTest, MessageReassemblerOutOfOrderFragments) {
    MessageReassembler reassembler;
    
    // Add fragments in reverse order
    Buffer data3(30, 0x33);
    MessageFragment fragment3(1, 70, 30, 100, std::move(data3));
    auto result3 = reassembler.add_fragment(fragment3);
    ASSERT_TRUE(result3.is_ok());
    EXPECT_FALSE(result3.value());
    
    Buffer data2(40, 0x22);
    MessageFragment fragment2(1, 30, 40, 100, std::move(data2));
    auto result2 = reassembler.add_fragment(fragment2);
    ASSERT_TRUE(result2.is_ok());
    EXPECT_FALSE(result2.value());
    
    Buffer data1(30, 0x11);
    MessageFragment fragment1(1, 0, 30, 100, std::move(data1));
    auto result1 = reassembler.add_fragment(fragment1);
    ASSERT_TRUE(result1.is_ok());
    EXPECT_TRUE(result1.value()); // Now complete
    
    EXPECT_TRUE(reassembler.is_complete());
}

TEST_F(ProtocolEdgeCasesTest, HandshakeFlightMaximumMessages) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 0);
    
    // Add maximum number of handshake messages
    for (uint16_t i = 0; i < 1000; ++i) {
        HandshakeMessage message;
        message.msg_type = HandshakeType::CLIENT_HELLO;
        message.length = 100;
        message.message_seq = i;
        message.fragment_offset = 0;
        message.fragment_length = 100;
        message.body.resize(100, static_cast<uint8_t>(i % 256));
        
        flight.add_message(std::move(message));
    }
    
    EXPECT_EQ(flight.get_messages().size(), 1000);
    EXPECT_TRUE(flight.is_complete());
    
    // Test fragmentation with small max fragment size
    auto fragment_result = flight.fragment_messages(100);
    ASSERT_TRUE(fragment_result.is_ok());
    
    auto fragments = fragment_result.value();
    EXPECT_GT(fragments.size(), 1000); // Should have created many fragments
}

TEST_F(ProtocolEdgeCasesTest, FlightManagerRetransmissionStressTest) {
    FlightManager manager;
    
    // Set aggressive retransmission parameters
    manager.set_retransmission_timeout(std::chrono::milliseconds(1));
    manager.set_max_retransmissions(100);
    
    // Create multiple flights
    for (int i = 0; i < 10; ++i) {
        auto flight_type = static_cast<FlightType>(1 + (i % 6));
        auto create_result = manager.create_flight(flight_type);
        ASSERT_TRUE(create_result.is_ok());
        
        HandshakeMessage message;
        message.msg_type = HandshakeType::CLIENT_HELLO;
        message.length = 50;
        message.message_seq = i;
        message.fragment_offset = 0;
        message.fragment_length = 50;
        message.body.resize(50, static_cast<uint8_t>(i));
        
        auto add_result = manager.add_message_to_current_flight(std::move(message));
        ASSERT_TRUE(add_result.is_ok());
        
        auto complete_result = manager.complete_current_flight();
        ASSERT_TRUE(complete_result.is_ok());
        
        manager.mark_flight_transmitted(flight_type);
    }
    
    // Wait for retransmission conditions
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // Check retransmission status
    for (int i = 0; i < 10; ++i) {
        auto flight_type = static_cast<FlightType>(1 + (i % 6));
        EXPECT_TRUE(manager.should_retransmit(flight_type));
    }
}

// Version Manager Edge Cases
TEST_F(ProtocolEdgeCasesTest, VersionManagerInvalidVersionHandling) {
    VersionManager manager;
    
    // Test invalid version formats
    GlobalProtocolVersion invalid_version = static_cast<GlobalProtocolVersion>(0x0000);
    EXPECT_FALSE(manager.is_version_valid(invalid_version));
    EXPECT_FALSE(manager.is_version_supported(invalid_version));
    
    // Test future version
    GlobalProtocolVersion future_version = static_cast<GlobalProtocolVersion>(0x0305);
    EXPECT_FALSE(manager.is_version_supported(future_version));
    
    // Test very old version
    GlobalProtocolVersion ancient_version = static_cast<GlobalProtocolVersion>(0x0100);
    EXPECT_FALSE(manager.is_version_supported(ancient_version));
}

TEST_F(ProtocolEdgeCasesTest, VersionManagerMalformedClientHello) {
    VersionManager manager;
    
    // Create ClientHello with conflicting version information
    ClientHello malformed_hello;
    malformed_hello.legacy_version = DTLS_V12;
    
    // Add supported_versions extension with different versions
    Extension supported_versions_ext;
    supported_versions_ext.extension_type = ExtensionType::SUPPORTED_VERSIONS;
    
    // Malformed extension data (wrong length)
    supported_versions_ext.extension_data = {0x02, 0x03, 0x04}; // Invalid format
    malformed_hello.extensions.push_back(supported_versions_ext);
    
    auto result = manager.negotiate_version_from_client_hello(malformed_hello);
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_DECODE_ERROR);
}

TEST_F(ProtocolEdgeCasesTest, VersionManagerDowngradeAttackDetection) {
    VersionManager manager;
    
    // Set up server to support both DTLS 1.3 and 1.2
    std::vector<GlobalProtocolVersion> server_versions = {DTLS_V13, DTLS_V12};
    manager.set_supported_versions(server_versions);
    
    // Simulate client that supports DTLS 1.3 but is being downgraded
    std::vector<GlobalProtocolVersion> client_versions = {DTLS_V13, DTLS_V12};
    
    // Test legitimate downgrade
    EXPECT_FALSE(manager.detect_version_downgrade(DTLS_V12, client_versions, server_versions));
    
    // Test forced downgrade (should be detected)
    std::vector<GlobalProtocolVersion> limited_server_versions = {DTLS_V12};
    EXPECT_TRUE(manager.detect_version_downgrade(DTLS_V12, client_versions, limited_server_versions));
}

TEST_F(ProtocolEdgeCasesTest, VersionManagerCompatibilityContextEdgeCases) {
    VersionManager manager;
    
    // Test compatibility with empty context
    compatibility::DTLS12CompatibilityContext empty_context;
    auto config_result = manager.configure_dtls12_compatibility(empty_context);
    EXPECT_TRUE(config_result.is_ok());
    
    // Test ClientHello fallback decision with edge cases
    ClientHello edge_hello;
    edge_hello.legacy_version = static_cast<GlobalProtocolVersion>(0x0200); // Invalid version
    
    EXPECT_FALSE(manager.should_enable_dtls12_fallback(edge_hello));
}

// Concurrent Access Edge Cases
TEST_F(ProtocolEdgeCasesTest, RecordLayerConcurrentAccess) {
    const int num_threads = 10;
    const int operations_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    
    // Launch concurrent protection operations
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < operations_per_thread; ++i) {
                DTLSPlaintext plaintext;
                plaintext.content_type = ContentType::APPLICATION_DATA;
                plaintext.legacy_record_version = DTLS_V13;
                plaintext.epoch = 0;
                plaintext.sequence_number = t * operations_per_thread + i;
                plaintext.fragment = {static_cast<uint8_t>(t), static_cast<uint8_t>(i)};
                
                auto result = record_layer_->protect_record(plaintext);
                if (result.is_ok()) {
                    success_count++;
                } else {
                    failure_count++;
                }
                
                // Small delay to increase chance of race conditions
                std::this_thread::sleep_for(std::chrono::microseconds(1));
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_GT(success_count.load(), 0);
    EXPECT_EQ(success_count.load() + failure_count.load(), num_threads * operations_per_thread);
}

TEST_F(ProtocolEdgeCasesTest, MessageReassemblerConcurrentFragments) {
    MessageReassembler reassembler;
    const int num_threads = 5;
    const int fragments_per_thread = 20;
    std::vector<std::thread> threads;
    std::atomic<int> successful_adds{0};
    
    // Launch concurrent fragment additions
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < fragments_per_thread; ++i) {
                uint32_t offset = (t * fragments_per_thread + i) * 10;
                Buffer data(10, static_cast<uint8_t>(t * 10 + i));
                
                MessageFragment fragment(1, offset, 10, num_threads * fragments_per_thread * 10, std::move(data));
                
                auto result = reassembler.add_fragment(fragment);
                if (result.is_ok()) {
                    successful_adds++;
                }
                
                std::this_thread::sleep_for(std::chrono::microseconds(1));
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_GT(successful_adds.load(), 0);
    EXPECT_TRUE(reassembler.is_complete());
}

// Memory and Resource Edge Cases
TEST_F(ProtocolEdgeCasesTest, MessageLayerMemoryStressTest) {
    auto test_record_layer = record_layer_utils::create_test_record_layer();
    ASSERT_NE(test_record_layer, nullptr);
    
    MessageLayer message_layer(std::move(test_record_layer));
    auto init_result = message_layer.initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Create large number of concurrent reassemblers
    std::vector<std::unique_ptr<MessageReassembler>> reassemblers;
    for (int i = 0; i < 1000; ++i) {
        reassemblers.push_back(std::make_unique<MessageReassembler>());
        
        // Add one fragment to each
        Buffer data(1000, static_cast<uint8_t>(i % 256));
        MessageFragment fragment(i, 0, 1000, 2000, std::move(data));
        
        auto result = reassemblers.back()->add_fragment(fragment);
        EXPECT_TRUE(result.is_ok());
    }
    
    // Verify all reassemblers are functional
    for (const auto& reassembler : reassemblers) {
        EXPECT_FALSE(reassembler->is_complete());
        auto stats = reassembler->get_stats();
        EXPECT_EQ(stats.received_bytes, 1000);
        EXPECT_EQ(stats.total_length, 2000);
    }
    
    // Clear reassemblers to test cleanup
    reassemblers.clear();
}

TEST_F(ProtocolEdgeCasesTest, VersionManagerLargeExtensionHandling) {
    VersionManager manager;
    
    ClientHello large_hello;
    large_hello.legacy_version = DTLS_V12;
    
    // Create supported_versions extension with many versions
    Extension large_ext;
    large_ext.extension_type = ExtensionType::SUPPORTED_VERSIONS;
    
    // Create valid but large extension data
    std::vector<uint8_t> ext_data;
    ext_data.push_back(50); // Length of version list (25 versions * 2 bytes each)
    
    // Add 25 versions (some valid, some invalid)
    for (uint16_t i = 0; i < 25; ++i) {
        uint16_t version = 0x0300 + i; // Various version numbers
        ext_data.push_back(static_cast<uint8_t>(version >> 8));
        ext_data.push_back(static_cast<uint8_t>(version & 0xFF));
    }
    
    large_ext.extension_data = ext_data;
    large_hello.extensions.push_back(large_ext);
    
    auto result = manager.negotiate_version_from_client_hello(large_hello);
    
    // Should handle large extension gracefully
    if (result.is_ok()) {
        EXPECT_TRUE(manager.is_version_supported(result.value().negotiated_version));
    } else {
        // If it fails, should be due to no supported versions, not parsing error
        EXPECT_NE(result.error().code(), ErrorCode::DTLS_ERROR_DECODE_ERROR);
    }
}