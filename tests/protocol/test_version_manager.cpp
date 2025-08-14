#include <gtest/gtest.h>
#include "dtls/protocol/version_manager.h"
#include "dtls/protocol/handshake.h"
#include "dtls/types.h"
#include "dtls/memory/buffer.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;

// Import constants for easier use
using dtls::v13::DTLS_V13;
using dtls::v13::DTLS_V12;
using dtls::v13::DTLS_V10;

class VersionManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default configuration supports both DTLS 1.3 and 1.2
        VersionManager::Config config;
        config.supported_versions = {DTLS_V13, DTLS_V12};
        config.preferred_version = DTLS_V13;
        config.allow_version_downgrade = true;
        config.strict_version_checking = false;
        
        version_manager_ = std::make_unique<VersionManager>(config);
    }
    
    ClientHello create_test_client_hello(GlobalProtocolVersion legacy_version,
                                       const std::vector<GlobalProtocolVersion>& supported_versions = {}) {
        ClientHello client_hello;
        client_hello.set_legacy_version(static_cast<dtls::v13::protocol::ProtocolVersion>(legacy_version));
        
        // Add random data
        std::array<uint8_t, 32> random;
        for (size_t i = 0; i < 32; ++i) {
            random[i] = static_cast<uint8_t>(i);
        }
        client_hello.set_random(random);
        
        // Add cipher suites
        std::vector<CipherSuite> cipher_suites = {CipherSuite::TLS_AES_128_GCM_SHA256};
        client_hello.set_cipher_suites(std::move(cipher_suites));
        
        // Add supported_versions extension if specified
        if (!supported_versions.empty()) {
            auto ext_result = version_utils::create_supported_versions_extension(supported_versions);
            EXPECT_TRUE(ext_result.is_success());
            if (ext_result.is_success()) {
                client_hello.add_extension(std::move(ext_result.value()));
            }
        }
        
        return client_hello;
    }
    
    ServerHello create_test_server_hello(GlobalProtocolVersion legacy_version,
                                       const std::vector<GlobalProtocolVersion>& supported_versions = {}) {
        ServerHello server_hello;
        server_hello.set_legacy_version(static_cast<dtls::v13::protocol::ProtocolVersion>(legacy_version));
        
        // Add random data
        std::array<uint8_t, 32> random;
        for (size_t i = 0; i < 32; ++i) {
            random[i] = static_cast<uint8_t>(i + 32);
        }
        server_hello.set_random(random);
        
        // Add cipher suite
        server_hello.set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
        
        // Add supported_versions extension if specified
        if (!supported_versions.empty()) {
            auto ext_result = version_utils::create_supported_versions_extension(supported_versions);
            EXPECT_TRUE(ext_result.is_success());
            if (ext_result.is_success()) {
                server_hello.add_extension(std::move(ext_result.value()));
            }
        }
        
        return server_hello;
    }
    
    std::unique_ptr<VersionManager> version_manager_;
};

// Basic Version Manager Tests
TEST_F(VersionManagerTest, DefaultConfiguration) {
    auto supported_versions = version_manager_->get_supported_versions();
    EXPECT_EQ(supported_versions.size(), 2);
    EXPECT_EQ(supported_versions[0], DTLS_V13);  // Should be preferred/first
    EXPECT_EQ(supported_versions[1], DTLS_V12);
    
    EXPECT_EQ(version_manager_->get_preferred_version(), DTLS_V13);
    EXPECT_TRUE(version_manager_->is_version_supported(DTLS_V13));
    EXPECT_TRUE(version_manager_->is_version_supported(DTLS_V12));
    EXPECT_FALSE(version_manager_->is_version_supported(DTLS_V10));
}

TEST_F(VersionManagerTest, VersionValidation) {
    EXPECT_TRUE(version_manager_->is_version_valid(DTLS_V13));
    EXPECT_TRUE(version_manager_->is_version_valid(DTLS_V12));
    EXPECT_TRUE(version_manager_->is_version_valid(DTLS_V10));
    
    // Invalid version formats
    EXPECT_FALSE(version_manager_->is_version_valid(0x0303));  // TLS format
    EXPECT_FALSE(version_manager_->is_version_valid(0x1234));  // Random value
}

TEST_F(VersionManagerTest, VersionComparison) {
    EXPECT_TRUE(VersionManager::is_version_higher(DTLS_V13, DTLS_V12));
    EXPECT_TRUE(VersionManager::is_version_higher(DTLS_V12, DTLS_V10));
    EXPECT_FALSE(VersionManager::is_version_higher(DTLS_V12, DTLS_V13));
    
    EXPECT_TRUE(VersionManager::is_version_lower(DTLS_V12, DTLS_V13));
    EXPECT_TRUE(VersionManager::is_version_lower(DTLS_V10, DTLS_V12));
    EXPECT_FALSE(VersionManager::is_version_lower(DTLS_V13, DTLS_V12));
}

// ClientHello Processing Tests
TEST_F(VersionManagerTest, PrepareClientHello) {
    auto client_hello = create_test_client_hello(DTLS_V12);
    
    auto result = version_manager_->prepare_client_hello(client_hello);
    EXPECT_TRUE(result.is_success());
    
    // Should set legacy_version to DTLS 1.2
    EXPECT_EQ(client_hello.legacy_version(), static_cast<dtls::v13::protocol::ProtocolVersion>(DTLS_V12));
    
    // Should add supported_versions extension
    EXPECT_TRUE(client_hello.has_extension(dtls::v13::protocol::ExtensionType::SUPPORTED_VERSIONS));
    
    // Verify supported versions in extension
    auto ext = client_hello.get_extension(dtls::v13::protocol::ExtensionType::SUPPORTED_VERSIONS);
    ASSERT_TRUE(ext.has_value());
    
    auto parsed_versions = version_utils::parse_supported_versions_extension(ext.value());
    ASSERT_TRUE(parsed_versions.is_success());
    
    auto& versions = parsed_versions.value();
    EXPECT_EQ(versions.size(), 2);
    EXPECT_EQ(versions[0], DTLS_V13);
    EXPECT_EQ(versions[1], DTLS_V12);
}

TEST_F(VersionManagerTest, ValidateClientHelloVersions) {
    // Valid ClientHello with supported_versions extension
    auto client_hello = create_test_client_hello(DTLS_V12, {DTLS_V13, DTLS_V12});
    auto result = version_manager_->validate_client_hello_versions(client_hello);
    EXPECT_TRUE(result.is_valid);
    
    // Valid ClientHello without extension (legacy mode)
    auto legacy_client_hello = create_test_client_hello(DTLS_V12);
    result = version_manager_->validate_client_hello_versions(legacy_client_hello);
    EXPECT_TRUE(result.is_valid);
    
    // Invalid: unsupported version in extension
    auto unsupported_client_hello = create_test_client_hello(DTLS_V12, {DTLS_V10});
    result = version_manager_->validate_client_hello_versions(unsupported_client_hello);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_alert, AlertDescription::PROTOCOL_VERSION);
}

// Server-side Version Negotiation Tests  
TEST_F(VersionManagerTest, NegotiateVersionFromClientHello) {
    // Test DTLS 1.3 negotiation
    auto client_hello_v13 = create_test_client_hello(DTLS_V12, {DTLS_V13, DTLS_V12});
    auto result = version_manager_->negotiate_version_from_client_hello(client_hello_v13);
    ASSERT_TRUE(result.is_success());
    
    auto& negotiation_result = result.value();
    EXPECT_EQ(negotiation_result.negotiated_version, DTLS_V13);
    EXPECT_FALSE(negotiation_result.version_downgrade_detected);
    EXPECT_FALSE(negotiation_result.requires_hello_retry_request);
    
    // Test DTLS 1.2 fallback
    auto client_hello_v12 = create_test_client_hello(DTLS_V12, {DTLS_V12});
    result = version_manager_->negotiate_version_from_client_hello(client_hello_v12);
    ASSERT_TRUE(result.is_success());
    
    auto& negotiation_result_v12 = result.value();
    EXPECT_EQ(negotiation_result_v12.negotiated_version, DTLS_V12);
    
    // Test unsupported version
    auto client_hello_unsupported = create_test_client_hello(DTLS_V12, {DTLS_V10});
    result = version_manager_->negotiate_version_from_client_hello(client_hello_unsupported);
    ASSERT_TRUE(result.is_success());
    EXPECT_TRUE(result.value().error_alert.has_value());
    EXPECT_EQ(result.value().error_alert.value(), AlertDescription::PROTOCOL_VERSION);
}

// ServerHello Processing Tests
TEST_F(VersionManagerTest, PrepareServerHello) {
    auto server_hello = create_test_server_hello(DTLS_V12);
    
    // Test DTLS 1.3 server hello
    auto result = version_manager_->prepare_server_hello(server_hello, DTLS_V13);
    EXPECT_TRUE(result.is_success());
    
    // Should set legacy_version to DTLS 1.2
    EXPECT_EQ(server_hello.legacy_version(), static_cast<dtls::v13::protocol::ProtocolVersion>(DTLS_V12));
    
    // Should add supported_versions extension with DTLS 1.3
    EXPECT_TRUE(server_hello.has_extension(dtls::v13::protocol::ExtensionType::SUPPORTED_VERSIONS));
    
    auto ext = server_hello.get_extension(dtls::v13::protocol::ExtensionType::SUPPORTED_VERSIONS);
    ASSERT_TRUE(ext.has_value());
    
    auto parsed_versions = version_utils::parse_supported_versions_extension(ext.value());
    ASSERT_TRUE(parsed_versions.is_success());
    
    auto& versions = parsed_versions.value();
    EXPECT_EQ(versions.size(), 1);
    EXPECT_EQ(versions[0], DTLS_V13);
    
    // Test DTLS 1.2 server hello
    auto server_hello_v12 = create_test_server_hello(DTLS_V12);
    result = version_manager_->prepare_server_hello(server_hello_v12, DTLS_V12);
    EXPECT_TRUE(result.is_success());
    
    // Should set legacy_version to actual version for DTLS 1.2
    EXPECT_EQ(server_hello_v12.legacy_version(), static_cast<dtls::v13::protocol::ProtocolVersion>(DTLS_V12));
}

TEST_F(VersionManagerTest, ValidateServerHelloVersion) {
    std::vector<GlobalProtocolVersion> client_offered = {DTLS_V13, DTLS_V12};
    
    // Valid server hello selecting DTLS 1.3
    auto server_hello_v13 = create_test_server_hello(DTLS_V12, {DTLS_V13});
    auto result = version_manager_->validate_server_hello_version(server_hello_v13, client_offered);
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V13);
    
    // Valid server hello selecting DTLS 1.2
    auto server_hello_v12 = create_test_server_hello(DTLS_V12);  // No extension for DTLS 1.2
    result = version_manager_->validate_server_hello_version(server_hello_v12, client_offered);
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V12);
    
    // Invalid: server selects version not offered by client
    auto server_hello_invalid = create_test_server_hello(DTLS_V12, {DTLS_V10});
    result = version_manager_->validate_server_hello_version(server_hello_invalid, client_offered);
    EXPECT_FALSE(result.is_success());
}

// Version Downgrade Detection Tests
TEST_F(VersionManagerTest, VersionDowngradeDetection) {
    std::vector<GlobalProtocolVersion> client_versions = {DTLS_V13, DTLS_V12};
    std::vector<GlobalProtocolVersion> server_versions = {DTLS_V13, DTLS_V12};
    
    // No downgrade: highest mutual version selected
    bool downgrade = version_manager_->detect_version_downgrade(DTLS_V13, client_versions, server_versions);
    EXPECT_FALSE(downgrade);
    
    // Downgrade detected: lower version selected when higher available
    downgrade = version_manager_->detect_version_downgrade(DTLS_V12, client_versions, server_versions);
    EXPECT_TRUE(downgrade);
    
    // No downgrade when highest mutual is selected
    std::vector<GlobalProtocolVersion> server_v12_only = {DTLS_V12};
    downgrade = version_manager_->detect_version_downgrade(DTLS_V12, client_versions, server_v12_only);
    EXPECT_FALSE(downgrade);
}

// Backward Compatibility Tests
TEST_F(VersionManagerTest, BackwardCompatibilityCheck) {
    // DTLS 1.3 compatibility info
    auto compat_info = version_manager_->check_backward_compatibility(DTLS_V13);
    EXPECT_FALSE(compat_info.is_dtls12_compatible);
    EXPECT_FALSE(compat_info.requires_feature_fallback);
    
    // DTLS 1.2 compatibility info
    compat_info = version_manager_->check_backward_compatibility(DTLS_V12);
    EXPECT_TRUE(compat_info.is_dtls12_compatible);
    EXPECT_TRUE(compat_info.requires_feature_fallback);  // Since we support DTLS 1.3
    
    // Unsupported version
    compat_info = version_manager_->check_backward_compatibility(DTLS_V10);
    EXPECT_FALSE(compat_info.is_dtls12_compatible);
    EXPECT_FALSE(compat_info.requires_feature_fallback);
}

// DTLS 1.2 Compatibility Integration Tests
TEST_F(VersionManagerTest, DTLS12CompatibilityIntegration) {
    compatibility::DTLS12CompatibilityContext compat_context;
    compat_context.enable_dtls12_fallback = true;
    compat_context.strict_dtls13_security = false;
    
    auto result = version_manager_->configure_dtls12_compatibility(compat_context);
    EXPECT_TRUE(result.is_success());
    
    // Test fallback detection
    auto client_hello_v12_only = create_test_client_hello(DTLS_V12, {DTLS_V12});
    bool should_fallback = version_manager_->should_enable_dtls12_fallback(client_hello_v12_only);
    EXPECT_TRUE(should_fallback);
    
    auto client_hello_v13 = create_test_client_hello(DTLS_V12, {DTLS_V13, DTLS_V12});
    should_fallback = version_manager_->should_enable_dtls12_fallback(client_hello_v13);
    EXPECT_FALSE(should_fallback);
}

// Handshake Integration Tests
TEST_F(VersionManagerTest, HandshakeVersionNegotiation) {
    auto client_hello = create_test_client_hello(DTLS_V12, {DTLS_V13, DTLS_V12});
    
    auto result = version_manager_->process_client_hello_version_negotiation(client_hello);
    ASSERT_TRUE(result.is_success());
    
    auto& context = result.value();
    EXPECT_EQ(context.negotiated_version, DTLS_V13);
    EXPECT_TRUE(context.version_negotiation_complete);
    EXPECT_EQ(context.client_offered_versions.size(), 2);
    EXPECT_EQ(context.client_offered_versions[0], DTLS_V13);
    EXPECT_EQ(context.client_offered_versions[1], DTLS_V12);
}

TEST_F(VersionManagerTest, ApplyVersionToServerHello) {
    auto client_hello = create_test_client_hello(DTLS_V12, {DTLS_V13, DTLS_V12});
    auto context_result = version_manager_->process_client_hello_version_negotiation(client_hello);
    ASSERT_TRUE(context_result.is_success());
    
    auto& context = context_result.value();
    auto server_hello = create_test_server_hello(DTLS_V12);
    
    auto result = version_manager_->apply_version_to_server_hello(server_hello, context);
    EXPECT_TRUE(result.is_success());
    
    // Verify server hello has correct version setup
    EXPECT_EQ(server_hello.legacy_version(), static_cast<dtls::v13::protocol::ProtocolVersion>(DTLS_V12));
    EXPECT_TRUE(server_hello.has_extension(dtls::v13::protocol::ExtensionType::SUPPORTED_VERSIONS));
}

TEST_F(VersionManagerTest, ValidateHandshakeVersionConsistency) {
    auto client_hello = create_test_client_hello(DTLS_V12, {DTLS_V13, DTLS_V12});
    auto context_result = version_manager_->process_client_hello_version_negotiation(client_hello);
    ASSERT_TRUE(context_result.is_success());
    
    auto& context = context_result.value();
    auto server_hello = create_test_server_hello(DTLS_V12, {DTLS_V13});
    
    auto validation_result = version_manager_->validate_handshake_version_consistency(context, server_hello);
    EXPECT_TRUE(validation_result.is_valid);
    
    // Test inconsistent version
    auto bad_server_hello = create_test_server_hello(DTLS_V12, {DTLS_V12});  // Different from context
    validation_result = version_manager_->validate_handshake_version_consistency(context, bad_server_hello);
    EXPECT_FALSE(validation_result.is_valid);
}

// Alert Generation Tests
TEST_F(VersionManagerTest, AlertGeneration) {
    auto alert = version_manager_->create_protocol_version_alert();
    EXPECT_EQ(alert.level(), AlertLevel::FATAL);
    EXPECT_EQ(alert.description(), AlertDescription::PROTOCOL_VERSION);
    
    alert = version_manager_->create_inappropriate_fallback_alert();
    EXPECT_EQ(alert.level(), AlertLevel::FATAL);
    EXPECT_EQ(alert.description(), AlertDescription::INAPPROPRIATE_FALLBACK);
    
    alert = version_manager_->create_version_error_alert(DTLS_V10);
    EXPECT_EQ(alert.level(), AlertLevel::FATAL);
    // Should be PROTOCOL_VERSION since DTLS_V10 is valid format but unsupported
    EXPECT_EQ(alert.description(), AlertDescription::PROTOCOL_VERSION);
}

// Utility Functions Tests
TEST_F(VersionManagerTest, VersionStringConversion) {
    EXPECT_EQ(VersionManager::version_to_string(DTLS_V13), "DTLS 1.3");
    EXPECT_EQ(VersionManager::version_to_string(DTLS_V12), "DTLS 1.2");
    EXPECT_EQ(VersionManager::version_to_string(DTLS_V10), "DTLS 1.0");
    
    auto result = VersionManager::version_from_string("DTLS 1.3");
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V13);
    
    result = VersionManager::version_from_string("DTLSv1.2");
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V12);
    
    result = VersionManager::version_from_string("Invalid");
    EXPECT_FALSE(result.is_success());
}

// Version Utils Tests
TEST_F(VersionManagerTest, VersionUtilities) {
    std::vector<GlobalProtocolVersion> versions = {DTLS_V13, DTLS_V12};
    
    auto ext_result = version_utils::create_supported_versions_extension(versions);
    ASSERT_TRUE(ext_result.is_success());
    
    auto& extension = ext_result.value();
    EXPECT_TRUE(version_utils::is_supported_versions_extension(extension));
    EXPECT_TRUE(version_utils::validate_supported_versions_extension(extension));
    
    auto parsed_result = version_utils::parse_supported_versions_extension(extension);
    ASSERT_TRUE(parsed_result.is_success());
    
    auto& parsed_versions = parsed_result.value();
    EXPECT_EQ(parsed_versions.size(), 2);
    EXPECT_EQ(parsed_versions[0], DTLS_V13);
    EXPECT_EQ(parsed_versions[1], DTLS_V12);
    
    // Test legacy version handling
    EXPECT_EQ(version_utils::get_legacy_version_for_hello(DTLS_V13), DTLS_V12);
    EXPECT_EQ(version_utils::get_legacy_version_for_hello(DTLS_V12), DTLS_V12);
}