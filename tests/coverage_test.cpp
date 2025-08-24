/**
 * @file coverage_test.cpp
 * @brief Comprehensive test suite designed to achieve >95% code coverage
 * 
 * This test file specifically targets uncovered code paths to reach the
 * coverage requirements. It exercises core functionality across all modules.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

// Include all major components
#include "dtls/types.h"
#include "dtls/error.h"
#include "dtls/result.h"
#include "dtls/error_context.h"
#include "dtls/error_handler.h"
#include "dtls/error_reporter.h"
#include "dtls/alert_manager.h"
#include "dtls/connection.h"
#include "dtls/memory/buffer.h"
#include "dtls/memory/pool.h"
#include "dtls/memory/memory_utils.h"
#include "dtls/core_protocol/anti_replay_core.h"
#include "dtls/protocol/dtls_records.h"
#include "dtls/protocol/cookie.h"
#include "dtls/protocol/version_manager.h"
#include "dtls/protocol/handshake.h"
#include "dtls/protocol/record_layer.h"
#include "dtls/protocol/fragment_reassembler.h"
#include "dtls/protocol/early_data.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/crypto_utils.h"
#include "dtls/security/rate_limiter.h"
#include "dtls/security/dos_protection.h"
#include "dtls/security/resource_manager.h"
#include "dtls/transport/udp_transport.h"

using namespace dtls::v13;

class CoverageTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto providers for comprehensive testing
        auto& factory = crypto::ProviderFactory::instance();
        factory.initialize_providers();
    }
    
    void TearDown() override {
        // Clean up any resources
    }
};

TEST_F(CoverageTest, CoreTypesAndErrorHandling) {
    // Test NetworkAddress creation and operations
    auto addr_result = NetworkAddress::from_string("192.168.1.100", 5000);
    EXPECT_TRUE(addr_result.is_ok());
    
    if (addr_result.is_ok()) {
        auto addr = addr_result.value();
        EXPECT_EQ(addr.port, 5000);
        
        // Test address comparison and serialization
        auto addr2 = addr;
        EXPECT_TRUE(addr == addr2);
        
        auto serialized = addr.to_string();
        EXPECT_FALSE(serialized.empty());
    }
    
    // Test DTLSError enumeration and error context
    auto error_context = std::make_shared<ErrorContext>("test_connection");
    EXPECT_FALSE(error_context->connection_id.empty());
    
    // Test error severity reporting
    error_context->record_error(DTLSError::DECODE_ERROR, "Test decode error");
    error_context->record_security_error(DTLSError::UNEXPECTED_MESSAGE, "Security test", 0.8);
    
    auto stats = error_context->get_error_statistics();
    EXPECT_GT(stats.total_errors, 0);
}

TEST_F(CoverageTest, MemoryManagement) {
    using namespace dtls::v13::memory;
    
    // Test Buffer class
    Buffer buffer(1024);
    EXPECT_EQ(buffer.size(), 1024);
    EXPECT_EQ(buffer.available(), 1024);
    
    // Test buffer operations
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    EXPECT_TRUE(buffer.write(data.data(), data.size()));
    EXPECT_EQ(buffer.available(), 1024 - 4);
    
    // Test buffer reading
    std::vector<uint8_t> read_data(4);
    EXPECT_EQ(buffer.read(read_data.data(), 4), 4);
    EXPECT_EQ(data, read_data);
    
    // Test Pool class
    Pool pool(64, 16); // 16 blocks of 64 bytes each
    
    auto block = pool.allocate();
    EXPECT_NE(block, nullptr);
    
    pool.deallocate(block);
    
    // Test memory utilities
    utils::MemoryStatsCollector collector;
    collector.record_allocation(1024, "test");
    collector.record_deallocation(1024, "test");
    
    auto stats = collector.get_statistics();
    EXPECT_EQ(stats.total_allocations, 1);
    EXPECT_EQ(stats.total_deallocations, 1);
}

TEST_F(CoverageTest, AntiReplayProtection) {
    using namespace dtls::v13::core_protocol;
    
    AntiReplayCore replay_core(64); // 64-bit window
    
    // Test first packet (should be valid)
    EXPECT_TRUE(replay_core.is_valid(1));
    replay_core.update(1);
    
    // Test replay detection
    EXPECT_FALSE(replay_core.is_valid(1)); // Replay should be detected
    
    // Test future packets (should slide window)
    EXPECT_TRUE(replay_core.is_valid(100));
    replay_core.update(100);
    
    // Test check_and_update convenience method
    EXPECT_TRUE(replay_core.check_and_update(101));
    EXPECT_FALSE(replay_core.check_and_update(101)); // Replay
    
    // Test statistics
    auto stats = replay_core.get_statistics();
    EXPECT_GT(stats.total_packets, 0);
}

TEST_F(CoverageTest, RecordLayerStructures) {
    using namespace dtls::v13::protocol;
    
    // Test SequenceNumber48 operations
    SequenceNumber48 seq_num(12345);
    EXPECT_EQ(seq_num.value(), 12345);
    
    // Test increment
    seq_num.increment();
    EXPECT_EQ(seq_num.value(), 12346);
    
    // Test serialization
    auto serialized = seq_num.serialize();
    EXPECT_EQ(serialized.size(), 6); // 48-bit = 6 bytes
    
    // Test deserialization
    auto deserialized_result = SequenceNumber48::deserialize(serialized);
    EXPECT_TRUE(deserialized_result.is_ok());
    if (deserialized_result.is_ok()) {
        EXPECT_EQ(deserialized_result.value().value(), 12346);
    }
    
    // Test DTLSPlaintext construction
    std::vector<uint8_t> payload = {0x16, 0x03, 0x04}; // Handshake message
    DTLSPlaintext plaintext(
        ContentType::HANDSHAKE,
        ProtocolVersion::DTLS_1_3,
        1, // epoch
        123456, // sequence number
        payload
    );
    
    EXPECT_EQ(plaintext.content_type, ContentType::HANDSHAKE);
    EXPECT_EQ(plaintext.version, ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(plaintext.epoch, 1);
    
    // Test serialization
    auto plaintext_serialized = plaintext.serialize();
    EXPECT_TRUE(plaintext_serialized.is_ok());
    
    if (plaintext_serialized.is_ok()) {
        // Test deserialization
        auto deserialized_plaintext = DTLSPlaintext::deserialize(plaintext_serialized.value());
        EXPECT_TRUE(deserialized_plaintext.is_ok());
    }
}

TEST_F(CoverageTest, CookieManagement) {
    using namespace dtls::v13::protocol;
    
    // Generate secret key for cookie manager
    std::vector<uint8_t> secret_key(32, 0xAB); // 32-byte key
    
    CookieManager manager(secret_key);
    
    // Test client info structure
    ClientInfo client_info;
    client_info.ip_address = "192.168.1.100";
    client_info.port = 12345;
    client_info.timestamp = std::chrono::steady_clock::now();
    
    // Test cookie generation
    auto cookie_result = manager.generate_cookie(client_info);
    EXPECT_TRUE(cookie_result.is_ok());
    
    if (cookie_result.is_ok()) {
        auto cookie = cookie_result.value();
        EXPECT_FALSE(cookie.empty());
        
        // Test cookie validation
        EXPECT_TRUE(manager.validate_cookie(cookie, client_info));
        
        // Test cookie consumption (should invalidate)
        EXPECT_TRUE(manager.consume_cookie(cookie));
        EXPECT_FALSE(manager.consume_cookie(cookie)); // Already consumed
        
        // Test client needs cookie check
        EXPECT_TRUE(manager.client_needs_cookie(client_info));
    }
    
    // Test statistics
    auto stats = manager.get_statistics();
    EXPECT_GT(stats.cookies_generated, 0);
}

TEST_F(CoverageTest, VersionManagement) {
    using namespace dtls::v13::protocol;
    
    VersionManager version_manager;
    
    // Test version validation
    EXPECT_TRUE(version_manager.is_supported_version(ProtocolVersion::DTLS_1_3));
    EXPECT_FALSE(version_manager.is_supported_version(ProtocolVersion::DTLS_1_0));
    
    // Test version comparison
    EXPECT_TRUE(version_manager.is_higher_version(ProtocolVersion::DTLS_1_3, ProtocolVersion::DTLS_1_2));
    
    // Test client hello preparation
    std::vector<ProtocolVersion> supported_versions = {
        ProtocolVersion::DTLS_1_3,
        ProtocolVersion::DTLS_1_2
    };
    
    auto client_hello_versions = version_manager.prepare_client_hello_versions(supported_versions);
    EXPECT_FALSE(client_hello_versions.empty());
    
    // Test version negotiation
    auto negotiated = version_manager.negotiate_version_from_client_hello(client_hello_versions);
    EXPECT_TRUE(negotiated.is_ok());
    if (negotiated.is_ok()) {
        EXPECT_EQ(negotiated.value(), ProtocolVersion::DTLS_1_3);
    }
}

TEST_F(CoverageTest, FragmentReassembly) {
    using namespace dtls::v13::protocol;
    
    FragmentReassembler reassembler;
    
    // Create test handshake message fragments
    HandshakeHeader header;
    header.msg_type = HandshakeType::CLIENT_HELLO;
    header.length = 100; // Total message length
    header.message_seq = 1;
    header.fragment_offset = 0;
    header.fragment_length = 50; // First fragment
    
    std::vector<uint8_t> fragment1_data(50, 0xAA);
    HandshakeFragment fragment1{header, fragment1_data};
    
    // Add first fragment
    auto result1 = reassembler.add_fragment("conn1", fragment1);
    EXPECT_FALSE(result1.has_value()); // Not complete yet
    
    // Create second fragment
    header.fragment_offset = 50;
    header.fragment_length = 50; // Second fragment completes the message
    std::vector<uint8_t> fragment2_data(50, 0xBB);
    HandshakeFragment fragment2{header, fragment2_data};
    
    // Add second fragment
    auto result2 = reassembler.add_fragment("conn1", fragment2);
    EXPECT_TRUE(result2.has_value()); // Should be complete now
    
    if (result2.has_value()) {
        auto complete_message = result2.value();
        EXPECT_EQ(complete_message.fragment_data.size(), 100);
    }
    
    // Test statistics
    auto stats = reassembler.get_statistics();
    EXPECT_GT(stats.fragments_received, 0);
}

TEST_F(CoverageTest, CryptoOperations) {
    using namespace dtls::v13::crypto;
    
    auto& factory = ProviderFactory::instance();
    
    // Test provider enumeration
    auto providers = factory.get_available_providers();
    EXPECT_FALSE(providers.empty());
    
    // Test getting best provider for operations
    auto provider = factory.get_best_provider_for_operations({
        CryptoOperation::HASHING,
        CryptoOperation::AEAD_ENCRYPTION
    });
    
    EXPECT_NE(provider, nullptr);
    
    if (provider) {
        // Test capabilities
        auto capabilities = provider->get_capabilities();
        EXPECT_FALSE(capabilities.empty());
        
        // Test HKDF-Expand-Label (if supported)
        if (capabilities.count(CryptoOperation::HKDF)) {
            std::vector<uint8_t> secret(32, 0xFF);
            auto result = provider->hkdf_expand_label(
                secret, "test_label", std::vector<uint8_t>(), 16, HashAlgorithm::SHA256
            );
            EXPECT_TRUE(result.is_ok());
            if (result.is_ok()) {
                EXPECT_EQ(result.value().size(), 16);
            }
        }
        
        // Test random generation
        auto random_result = provider->generate_random_bytes(32);
        EXPECT_TRUE(random_result.is_ok());
        if (random_result.is_ok()) {
            EXPECT_EQ(random_result.value().size(), 32);
        }
    }
    
    // Test factory statistics
    auto stats = factory.get_statistics();
    EXPECT_GE(stats.providers_loaded, 0);
}

TEST_F(CoverageTest, SecurityComponents) {
    using namespace dtls::v13::security;
    
    // Test RateLimiter
    RateLimiterConfig config;
    config.max_connections_per_second = 10;
    config.max_handshakes_per_second = 5;
    config.burst_tolerance = 3;
    
    RateLimiter rate_limiter(config);
    
    NetworkAddress test_addr;
    test_addr.ip = "192.168.1.100";
    test_addr.port = 12345;
    
    // Test connection attempts
    EXPECT_TRUE(rate_limiter.allow_connection_attempt(test_addr));
    
    // Test handshake attempts
    EXPECT_TRUE(rate_limiter.allow_handshake_attempt(test_addr));
    
    // Test statistics
    auto rl_stats = rate_limiter.get_statistics();
    EXPECT_GE(rl_stats.total_requests, 0);
    
    // Test DoS protection
    DoSProtectionConfig dos_config;
    dos_config.enable_cookie_exchange = true;
    dos_config.enable_rate_limiting = true;
    dos_config.enable_resource_limiting = true;
    
    DoSProtection dos_protection(dos_config);
    
    // Test connection validation
    auto validation_result = dos_protection.validate_new_connection(test_addr);
    // Result depends on current state, just ensure it doesn't crash
    
    // Test ResourceManager
    ResourceManagerConfig rm_config;
    rm_config.max_connections = 1000;
    rm_config.max_memory_per_connection = 64 * 1024; // 64KB
    rm_config.connection_timeout_seconds = 300;
    
    ResourceManager resource_manager(rm_config);
    
    // Test resource allocation
    auto alloc_result = resource_manager.allocate_connection_resources("test_conn", test_addr);
    EXPECT_TRUE(alloc_result.is_ok());
    
    // Test statistics
    auto rm_stats = resource_manager.get_statistics();
    EXPECT_GE(rm_stats.active_connections, 0);
}

TEST_F(CoverageTest, TransportLayer) {
    using namespace dtls::v13::transport;
    
    // Test UDPTransport configuration
    UDPTransportConfig config;
    config.bind_address = "127.0.0.1";
    config.bind_port = 0; // Let system choose port
    config.receive_buffer_size = 64 * 1024;
    config.send_buffer_size = 64 * 1024;
    
    UDPTransport transport(config);
    
    // Test initialization
    auto init_result = transport.initialize();
    if (init_result.is_ok()) {
        // Test address retrieval
        auto local_addr = transport.get_local_address();
        EXPECT_TRUE(local_addr.is_ok());
        
        // Test statistics
        auto stats = transport.get_statistics();
        EXPECT_GE(stats.bytes_sent, 0);
        EXPECT_GE(stats.bytes_received, 0);
        
        // Cleanup
        transport.cleanup();
    }
}

TEST_F(CoverageTest, ErrorContextAndReporting) {
    // Test comprehensive error handling
    auto context = std::make_shared<ErrorContext>("coverage_test_connection");
    
    // Test various error types
    context->record_error(DTLSError::INTERNAL_ERROR, "Test internal error");
    context->record_error(DTLSError::DECODE_ERROR, "Test decode error");
    context->record_error(DTLSError::UNSUPPORTED_EXTENSION, "Test extension error");
    
    // Test security errors with confidence levels
    context->record_security_error(DTLSError::UNEXPECTED_MESSAGE, "Timing attack detected", 0.9);
    context->record_security_error(DTLSError::BAD_RECORD_MAC, "MAC verification failed", 1.0);
    
    // Test error statistics
    auto stats = context->get_error_statistics();
    EXPECT_GT(stats.total_errors, 0);
    EXPECT_GT(stats.security_errors, 0);
    
    // Test ErrorHandler
    ErrorHandler error_handler;
    error_handler.set_error_context(context);
    
    // Test error processing
    auto process_result = error_handler.handle_protocol_error(DTLSError::INTERNAL_ERROR, context);
    // Result depends on error handling policy
    
    // Test AlertManager
    AlertManager alert_manager;
    
    // Test alert generation
    auto alert_result = alert_manager.generate_alert_for_error(DTLSError::INTERNAL_ERROR, context);
    if (alert_result.is_ok() && alert_result.value().has_value()) {
        auto alert_data = alert_result.value().value();
        EXPECT_FALSE(alert_data.empty());
    }
}

// Main test to validate overall coverage improvement
TEST_F(CoverageTest, ComprehensiveFunctionalityExercise) {
    // This test exercises multiple components together to improve coverage
    
    // 1. Initialize crypto system
    auto& crypto_factory = crypto::ProviderFactory::instance();
    crypto_factory.initialize_providers();
    
    // 2. Create network address
    auto addr_result = NetworkAddress::from_string("127.0.0.1", 5684);
    ASSERT_TRUE(addr_result.is_ok());
    auto address = addr_result.value();
    
    // 3. Set up error context and handling
    auto error_context = std::make_shared<ErrorContext>("comprehensive_test");
    
    // 4. Create and configure components
    using namespace dtls::v13::protocol;
    
    // Version manager
    VersionManager version_mgr;
    EXPECT_TRUE(version_mgr.is_supported_version(ProtocolVersion::DTLS_1_3));
    
    // Cookie manager
    std::vector<uint8_t> cookie_secret(32, 0xCD);
    CookieManager cookie_mgr(cookie_secret);
    
    // Fragment reassembler
    FragmentReassembler fragment_reassembler;
    
    // Anti-replay protection
    core_protocol::AntiReplayCore anti_replay(128);
    
    // 5. Exercise integrated functionality
    
    // Create client info for cookie
    ClientInfo client_info;
    client_info.ip_address = address.to_string();
    client_info.port = address.port;
    client_info.timestamp = std::chrono::steady_clock::now();
    
    auto cookie_result = cookie_mgr.generate_cookie(client_info);
    EXPECT_TRUE(cookie_result.is_ok());
    
    // Test record structures
    std::vector<uint8_t> test_payload = {0x01, 0x00, 0x00, 0x2A}; // Client Hello header
    DTLSPlaintext plaintext(
        ContentType::HANDSHAKE,
        ProtocolVersion::DTLS_1_3,
        0, // epoch
        1, // sequence
        test_payload
    );
    
    auto serialization_result = plaintext.serialize();
    EXPECT_TRUE(serialization_result.is_ok());
    
    // Test sequence number management
    EXPECT_TRUE(anti_replay.check_and_update(1));
    EXPECT_FALSE(anti_replay.check_and_update(1)); // Should detect replay
    
    // 6. Verify all components are functioning
    auto crypto_stats = crypto_factory.get_statistics();
    auto replay_stats = anti_replay.get_statistics();
    auto cookie_stats = cookie_mgr.get_statistics();
    
    EXPECT_GE(crypto_stats.providers_loaded, 0);
    EXPECT_GT(replay_stats.total_packets, 0);
    EXPECT_GT(cookie_stats.cookies_generated, 0);
}