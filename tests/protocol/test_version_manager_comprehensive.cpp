/**
 * @file test_version_manager_comprehensive.cpp
 * @brief Comprehensive tests for DTLS version manager implementation
 * 
 * Targets version_manager.cpp which currently has 0% coverage (0/387 lines)
 * Tests all major components: VersionManager, version negotiation,
 * compatibility checking, alert generation, and utility functions
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <optional>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#include "dtls/protocol/version_manager.h"
#include "dtls/protocol/handshake.h"
#include "dtls/types.h"
#include "dtls/error.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;

class VersionManagerComprehensiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default configuration for most tests
        default_config_.supported_versions = {DTLS_V13, DTLS_V12};
        default_config_.preferred_version = DTLS_V13;
        default_config_.allow_version_downgrade = true;
        default_config_.strict_version_checking = false;
    }
    
    VersionManager::Config default_config_;
};

// ============================================================================
// Basic VersionManager Tests
// ============================================================================

class VersionManagerBasicTest : public VersionManagerComprehensiveTest {};

TEST_F(VersionManagerBasicTest, DefaultConstruction) {
    VersionManager vm;
    
    auto supported = vm.get_supported_versions();
    EXPECT_FALSE(supported.empty());
    EXPECT_EQ(vm.get_preferred_version(), DTLS_V13);
    
    // Should support both DTLS 1.3 and 1.2 by default
    EXPECT_TRUE(vm.is_version_supported(DTLS_V13));
    EXPECT_TRUE(vm.is_version_supported(DTLS_V12));
}

TEST_F(VersionManagerBasicTest, ConfigConstruction) {
    VersionManager::Config config;
    config.supported_versions = {DTLS_V12};
    config.preferred_version = DTLS_V12;
    
    VersionManager vm(config);
    
    auto supported = vm.get_supported_versions();
    EXPECT_EQ(supported.size(), 1);
    EXPECT_EQ(supported[0], DTLS_V12);
    EXPECT_EQ(vm.get_preferred_version(), DTLS_V12);
    
    EXPECT_FALSE(vm.is_version_supported(DTLS_V13));
    EXPECT_TRUE(vm.is_version_supported(DTLS_V12));
}

TEST_F(VersionManagerBasicTest, SetSupportedVersions) {
    VersionManager vm;
    
    std::vector<GlobalProtocolVersion> new_versions = {DTLS_V13, DTLS_V12, DTLS_V10};
    vm.set_supported_versions(new_versions);
    
    auto supported = vm.get_supported_versions();
    EXPECT_EQ(supported.size(), 3);
    
    // Should be sorted in preference order (highest first)
    EXPECT_EQ(supported[0], DTLS_V13);
    EXPECT_EQ(supported[1], DTLS_V12);
    EXPECT_EQ(supported[2], DTLS_V10);
    
    // Preferred version should be updated to highest
    EXPECT_EQ(vm.get_preferred_version(), DTLS_V13);
}

TEST_F(VersionManagerBasicTest, VersionValidation) {
    VersionManager vm;
    
    // Valid DTLS versions
    EXPECT_TRUE(vm.is_version_valid(DTLS_V13));
    EXPECT_TRUE(vm.is_version_valid(DTLS_V12));
    EXPECT_TRUE(vm.is_version_valid(DTLS_V10));
    
    // Invalid versions (not DTLS format)
    EXPECT_FALSE(vm.is_version_valid(static_cast<GlobalProtocolVersion>(0x0303))); // TLS 1.2
    EXPECT_FALSE(vm.is_version_valid(static_cast<GlobalProtocolVersion>(0x0304))); // TLS 1.3
    EXPECT_FALSE(vm.is_version_valid(static_cast<GlobalProtocolVersion>(0x1000))); // Random value
}

TEST_F(VersionManagerBasicTest, VersionComparison) {
    // Test version comparison utilities
    EXPECT_TRUE(VersionManager::is_version_higher(DTLS_V13, DTLS_V12));
    EXPECT_TRUE(VersionManager::is_version_higher(DTLS_V12, DTLS_V10));
    EXPECT_FALSE(VersionManager::is_version_higher(DTLS_V12, DTLS_V13));
    
    EXPECT_TRUE(VersionManager::is_version_lower(DTLS_V12, DTLS_V13));
    EXPECT_TRUE(VersionManager::is_version_lower(DTLS_V10, DTLS_V12));
    EXPECT_FALSE(VersionManager::is_version_lower(DTLS_V13, DTLS_V12));
}

TEST_F(VersionManagerBasicTest, VersionStringConversion) {
    EXPECT_EQ(VersionManager::version_to_string(DTLS_V13), "DTLS 1.3");
    EXPECT_EQ(VersionManager::version_to_string(DTLS_V12), "DTLS 1.2");
    EXPECT_EQ(VersionManager::version_to_string(DTLS_V10), "DTLS 1.0");
    
    // Unknown version should return hex format
    auto unknown = VersionManager::version_to_string(static_cast<GlobalProtocolVersion>(0x1234));
    EXPECT_NE(unknown.find("Unknown"), std::string::npos);
    EXPECT_NE(unknown.find("0x"), std::string::npos);
}

TEST_F(VersionManagerBasicTest, StringToVersionConversion) {
    auto result = VersionManager::version_from_string("DTLS 1.3");
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V13);
    
    result = VersionManager::version_from_string("DTLS 1.2");
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V12);
    
    result = VersionManager::version_from_string("DTLSv1.3");
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V13);
    
    // Invalid string
    result = VersionManager::version_from_string("Invalid Version");
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(VersionManagerBasicTest, VersionCategories) {
    VersionManager vm;
    
    EXPECT_TRUE(vm.is_dtls13_version(DTLS_V13));
    EXPECT_FALSE(vm.is_dtls13_version(DTLS_V12));
    
    EXPECT_TRUE(vm.is_dtls12_version(DTLS_V12));
    EXPECT_FALSE(vm.is_dtls12_version(DTLS_V13));
    
    EXPECT_TRUE(vm.is_legacy_version(DTLS_V12));
    EXPECT_TRUE(vm.is_legacy_version(DTLS_V10));
    EXPECT_FALSE(vm.is_legacy_version(DTLS_V13));
}

// ============================================================================
// ClientHello Preparation Tests
// ============================================================================

class ClientHelloPreparationTest : public VersionManagerComprehensiveTest {};

TEST_F(ClientHelloPreparationTest, PrepareClientHello) {
    VersionManager vm(default_config_);
    
    ClientHello client_hello;
    auto result = vm.prepare_client_hello(client_hello);
    ASSERT_TRUE(result.is_success());
    
    // Legacy version should be set to DTLS 1.2
    EXPECT_EQ(client_hello.legacy_version(), static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    // Should have supported_versions extension
    EXPECT_TRUE(client_hello.has_extension(protocol::ExtensionType::SUPPORTED_VERSIONS));
    
    auto ext = client_hello.get_extension(protocol::ExtensionType::SUPPORTED_VERSIONS);
    ASSERT_TRUE(ext.has_value());
    
    auto versions_result = version_utils::parse_supported_versions_extension(ext.value());
    ASSERT_TRUE(versions_result.is_success());
    
    const auto& versions = versions_result.value();
    EXPECT_EQ(versions.size(), 2);
    EXPECT_TRUE(std::find(versions.begin(), versions.end(), DTLS_V13) != versions.end());
    EXPECT_TRUE(std::find(versions.begin(), versions.end(), DTLS_V12) != versions.end());
}

TEST_F(ClientHelloPreparationTest, PrepareClientHelloSingleVersion) {
    VersionManager::Config config;
    config.supported_versions = {DTLS_V12};
    config.preferred_version = DTLS_V12;
    
    VersionManager vm(config);
    
    ClientHello client_hello;
    auto result = vm.prepare_client_hello(client_hello);
    ASSERT_TRUE(result.is_success());
    
    auto ext = client_hello.get_extension(protocol::ExtensionType::SUPPORTED_VERSIONS);
    ASSERT_TRUE(ext.has_value());
    
    auto versions_result = version_utils::parse_supported_versions_extension(ext.value());
    ASSERT_TRUE(versions_result.is_success());
    
    const auto& versions = versions_result.value();
    EXPECT_EQ(versions.size(), 1);
    EXPECT_EQ(versions[0], DTLS_V12);
}

// ============================================================================
// Version Negotiation Tests
// ============================================================================

class VersionNegotiationTest : public VersionManagerComprehensiveTest {};

TEST_F(VersionNegotiationTest, NegotiateSuccessful) {
    VersionManager vm(default_config_);
    
    // Create ClientHello with supported versions
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13, DTLS_V12});
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.negotiate_version_from_client_hello(client_hello);
    ASSERT_TRUE(result.is_success());
    
    const auto& negotiation = result.value();
    EXPECT_EQ(negotiation.negotiated_version, DTLS_V13); // Should select highest mutual version
    EXPECT_FALSE(negotiation.version_downgrade_detected);
    EXPECT_FALSE(negotiation.requires_hello_retry_request);
    EXPECT_FALSE(negotiation.error_alert.has_value());
}

TEST_F(VersionNegotiationTest, NegotiateWithDowngrade) {
    VersionManager::Config config;
    config.supported_versions = {DTLS_V12}; // Server only supports DTLS 1.2
    config.preferred_version = DTLS_V12;
    
    VersionManager vm(config);
    
    // Client offers both versions
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13, DTLS_V12});
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.negotiate_version_from_client_hello(client_hello);
    ASSERT_TRUE(result.is_success());
    
    const auto& negotiation = result.value();
    EXPECT_EQ(negotiation.negotiated_version, DTLS_V12); // Should downgrade to DTLS 1.2
}

TEST_F(VersionNegotiationTest, NegotiateNoMutualVersion) {
    VersionManager::Config config;
    config.supported_versions = {DTLS_V13}; // Server only supports DTLS 1.3
    config.preferred_version = DTLS_V13;
    
    VersionManager vm(config);
    
    // Client only offers DTLS 1.2
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V12});
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.negotiate_version_from_client_hello(client_hello);
    ASSERT_TRUE(result.is_success());
    
    const auto& negotiation = result.value();
    EXPECT_TRUE(negotiation.error_alert.has_value());
    EXPECT_EQ(negotiation.error_alert.value(), AlertDescription::PROTOCOL_VERSION);
}

TEST_F(VersionNegotiationTest, NegotiateWithoutExtension) {
    VersionManager vm(default_config_);
    
    // ClientHello without supported_versions extension
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto result = vm.negotiate_version_from_client_hello(client_hello);
    ASSERT_TRUE(result.is_success());
    
    const auto& negotiation = result.value();
    EXPECT_EQ(negotiation.negotiated_version, DTLS_V12); // Should use legacy version
}

TEST_F(VersionNegotiationTest, DowngradeDetection) {
    VersionManager::Config config = default_config_;
    config.strict_version_checking = true;
    config.allow_version_downgrade = false;
    
    VersionManager vm(config);
    
    // Simulate a scenario where downgrade is detected
    std::vector<GlobalProtocolVersion> client_versions = {DTLS_V13, DTLS_V12};
    std::vector<GlobalProtocolVersion> server_versions = {DTLS_V13, DTLS_V12};
    
    // Test downgrade detection
    bool downgrade = vm.detect_version_downgrade(DTLS_V12, client_versions, server_versions);
    EXPECT_TRUE(downgrade); // DTLS 1.2 is lower than highest mutual (DTLS 1.3)
    
    downgrade = vm.detect_version_downgrade(DTLS_V13, client_versions, server_versions);
    EXPECT_FALSE(downgrade); // DTLS 1.3 is the highest mutual version
}

// ============================================================================
// ServerHello Preparation Tests
// ============================================================================

class ServerHelloPreparationTest : public VersionManagerComprehensiveTest {};

TEST_F(ServerHelloPreparationTest, PrepareServerHelloDTLS13) {
    VersionManager vm(default_config_);
    
    ServerHello server_hello;
    auto result = vm.prepare_server_hello(server_hello, DTLS_V13);
    ASSERT_TRUE(result.is_success());
    
    // For DTLS 1.3, legacy_version should be DTLS 1.2
    EXPECT_EQ(server_hello.legacy_version(), static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    // Should have supported_versions extension
    EXPECT_TRUE(server_hello.has_extension(protocol::ExtensionType::SUPPORTED_VERSIONS));
    
    auto ext = server_hello.get_extension(protocol::ExtensionType::SUPPORTED_VERSIONS);
    ASSERT_TRUE(ext.has_value());
    
    auto versions_result = version_utils::parse_supported_versions_extension(ext.value());
    ASSERT_TRUE(versions_result.is_success());
    
    const auto& versions = versions_result.value();
    EXPECT_EQ(versions.size(), 1);
    EXPECT_EQ(versions[0], DTLS_V13);
}

TEST_F(ServerHelloPreparationTest, PrepareServerHelloDTLS12) {
    VersionManager vm(default_config_);
    
    ServerHello server_hello;
    auto result = vm.prepare_server_hello(server_hello, DTLS_V12);
    ASSERT_TRUE(result.is_success());
    
    // For DTLS 1.2, legacy_version should be the actual version
    EXPECT_EQ(server_hello.legacy_version(), static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    // Should not have supported_versions extension for DTLS 1.2
    EXPECT_FALSE(server_hello.has_extension(protocol::ExtensionType::SUPPORTED_VERSIONS));
}

TEST_F(ServerHelloPreparationTest, PrepareHelloRetryRequest) {
    VersionManager vm(default_config_);
    
    HelloRetryRequest hrr;
    auto result = vm.prepare_hello_retry_request(hrr, DTLS_V13);
    ASSERT_TRUE(result.is_success());
    
    // Should follow same rules as ServerHello
    EXPECT_EQ(hrr.legacy_version(), static_cast<protocol::ProtocolVersion>(DTLS_V12));
    EXPECT_TRUE(hrr.has_extension(protocol::ExtensionType::SUPPORTED_VERSIONS));
}

// ============================================================================
// Server Hello Validation Tests
// ============================================================================

class ServerHelloValidationTest : public VersionManagerComprehensiveTest {};

TEST_F(ServerHelloValidationTest, ValidateValidSelection) {
    VersionManager vm(default_config_);
    
    std::vector<GlobalProtocolVersion> client_offered = {DTLS_V13, DTLS_V12};
    
    ServerHello server_hello;
    server_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13});
    ASSERT_TRUE(version_ext.is_success());
    server_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.validate_server_hello_version(server_hello, client_offered);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), DTLS_V13);
}

TEST_F(ServerHelloValidationTest, ValidateUnofferedVersion) {
    VersionManager vm(default_config_);
    
    std::vector<GlobalProtocolVersion> client_offered = {DTLS_V12}; // Client only offered DTLS 1.2
    
    ServerHello server_hello;
    server_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13});
    ASSERT_TRUE(version_ext.is_success());
    server_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.validate_server_hello_version(server_hello, client_offered);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
}

TEST_F(ServerHelloValidationTest, ValidateUnsupportedVersion) {
    VersionManager::Config config;
    config.supported_versions = {DTLS_V12}; // We don't support DTLS 1.3
    config.preferred_version = DTLS_V12;
    
    VersionManager vm(config);
    
    std::vector<GlobalProtocolVersion> client_offered = {DTLS_V13, DTLS_V12};
    
    ServerHello server_hello;
    server_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13});
    ASSERT_TRUE(version_ext.is_success());
    server_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.validate_server_hello_version(server_hello, client_offered);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
}

// ============================================================================
// Validation Tests
// ============================================================================

class ValidationTest : public VersionManagerComprehensiveTest {};

TEST_F(ValidationTest, ValidateVersionFormat) {
    VersionManager vm;
    
    auto result = vm.validate_version_format(DTLS_V13);
    EXPECT_TRUE(result.is_valid);
    
    result = vm.validate_version_format(DTLS_V12);
    EXPECT_TRUE(result.is_valid);
    
    // Invalid format
    result = vm.validate_version_format(static_cast<GlobalProtocolVersion>(0x0303));
    EXPECT_FALSE(result.is_valid);
    EXPECT_TRUE(result.error_alert.has_value());
    EXPECT_EQ(result.error_alert.value(), AlertDescription::DECODE_ERROR);
}

TEST_F(ValidationTest, ValidateVersionSupport) {
    VersionManager vm(default_config_);
    
    auto result = vm.validate_version_support(DTLS_V13);
    EXPECT_TRUE(result.is_valid);
    
    result = vm.validate_version_support(DTLS_V12);
    EXPECT_TRUE(result.is_valid);
    
    // Unsupported version
    result = vm.validate_version_support(DTLS_V10);
    EXPECT_FALSE(result.is_valid);
    EXPECT_TRUE(result.error_alert.has_value());
    EXPECT_EQ(result.error_alert.value(), AlertDescription::PROTOCOL_VERSION);
}

TEST_F(ValidationTest, ValidateClientHelloVersions) {
    VersionManager vm(default_config_);
    
    // Valid ClientHello
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13, DTLS_V12});
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.validate_client_hello_versions(client_hello);
    EXPECT_TRUE(result.is_valid);
}

TEST_F(ValidationTest, ValidateClientHelloNoMutualSupport) {
    VersionManager::Config config;
    config.supported_versions = {DTLS_V13}; // Server only supports DTLS 1.3
    config.preferred_version = DTLS_V13;
    
    VersionManager vm(config);
    
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V12}); // Client only offers DTLS 1.2
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.validate_client_hello_versions(client_hello);
    EXPECT_FALSE(result.is_valid);
    EXPECT_TRUE(result.error_alert.has_value());
    EXPECT_EQ(result.error_alert.value(), AlertDescription::PROTOCOL_VERSION);
}

TEST_F(ValidationTest, ValidateServerHelloVersions) {
    VersionManager vm(default_config_);
    
    std::vector<GlobalProtocolVersion> client_offered = {DTLS_V13, DTLS_V12};
    
    // Valid ServerHello
    ServerHello server_hello;
    server_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13});
    ASSERT_TRUE(version_ext.is_success());
    server_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.validate_server_hello_versions(server_hello, client_offered);
    EXPECT_TRUE(result.is_valid);
}

// ============================================================================
// Alert Generation Tests
// ============================================================================

class AlertGenerationTest : public VersionManagerComprehensiveTest {};

TEST_F(AlertGenerationTest, GetVersionErrorAlert) {
    VersionManager vm;
    
    // Invalid version format
    auto alert = vm.get_version_error_alert(static_cast<GlobalProtocolVersion>(0x0303));
    EXPECT_EQ(alert, AlertDescription::DECODE_ERROR);
    
    // Unsupported version
    alert = vm.get_version_error_alert(DTLS_V10);
    EXPECT_EQ(alert, AlertDescription::PROTOCOL_VERSION);
    
    // Valid supported version
    alert = vm.get_version_error_alert(DTLS_V13);
    EXPECT_EQ(alert, AlertDescription::HANDSHAKE_FAILURE);
}

TEST_F(AlertGenerationTest, CreateAlerts) {
    VersionManager vm;
    
    auto alert = vm.create_version_error_alert(DTLS_V10);
    EXPECT_EQ(alert.level(), AlertLevel::FATAL);
    EXPECT_EQ(alert.description(), AlertDescription::PROTOCOL_VERSION);
    
    alert = vm.create_protocol_version_alert();
    EXPECT_EQ(alert.level(), AlertLevel::FATAL);
    EXPECT_EQ(alert.description(), AlertDescription::PROTOCOL_VERSION);
    
    alert = vm.create_inappropriate_fallback_alert();
    EXPECT_EQ(alert.level(), AlertLevel::FATAL);
    EXPECT_EQ(alert.description(), AlertDescription::INAPPROPRIATE_FALLBACK);
    
    alert = vm.create_unsupported_extension_alert();
    EXPECT_EQ(alert.level(), AlertLevel::FATAL);
    EXPECT_EQ(alert.description(), AlertDescription::UNSUPPORTED_EXTENSION);
}

// ============================================================================
// Compatibility Tests
// ============================================================================

class CompatibilityTest : public VersionManagerComprehensiveTest {};

TEST_F(CompatibilityTest, BackwardCompatibilityDTLS12) {
    VersionManager vm(default_config_);
    
    auto info = vm.check_backward_compatibility(DTLS_V12);
    EXPECT_TRUE(info.is_dtls12_compatible);
    EXPECT_TRUE(info.requires_feature_fallback);
    EXPECT_FALSE(info.compatibility_notes.empty());
    
    // Should mention full DTLS 1.2 compatibility
    bool found_compatibility_note = false;
    for (const auto& note : info.compatibility_notes) {
        if (note.find("Full DTLS 1.2 compatibility") != std::string::npos) {
            found_compatibility_note = true;
            break;
        }
    }
    EXPECT_TRUE(found_compatibility_note);
}

TEST_F(CompatibilityTest, BackwardCompatibilityDTLS13) {
    VersionManager vm(default_config_);
    
    auto info = vm.check_backward_compatibility(DTLS_V13);
    EXPECT_FALSE(info.is_dtls12_compatible);
    EXPECT_FALSE(info.requires_feature_fallback);
    EXPECT_FALSE(info.compatibility_notes.empty());
    
    // Should mention DTLS 1.3 only
    bool found_dtls13_note = false;
    for (const auto& note : info.compatibility_notes) {
        if (note.find("DTLS 1.3 only") != std::string::npos) {
            found_dtls13_note = true;
            break;
        }
    }
    EXPECT_TRUE(found_dtls13_note);
}

TEST_F(CompatibilityTest, ShouldEnableDTLS12Fallback) {
    VersionManager vm(default_config_);
    
    // Client that supports DTLS 1.3
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13, DTLS_V12});
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    bool should_fallback = vm.should_enable_dtls12_fallback(client_hello);
    EXPECT_FALSE(should_fallback); // Client supports DTLS 1.3
    
    // Client that only supports DTLS 1.2
    ClientHello dtls12_client;
    dtls12_client.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto dtls12_ext = version_utils::create_supported_versions_extension({DTLS_V12});
    ASSERT_TRUE(dtls12_ext.is_success());
    dtls12_client.add_extension(std::move(dtls12_ext.value()));
    
    should_fallback = vm.should_enable_dtls12_fallback(dtls12_client);
    EXPECT_TRUE(should_fallback); // Client doesn't support DTLS 1.3
}

// ============================================================================
// Handshake Integration Tests
// ============================================================================

class HandshakeIntegrationTest : public VersionManagerComprehensiveTest {};

TEST_F(HandshakeIntegrationTest, ProcessClientHelloVersionNegotiation) {
    VersionManager vm(default_config_);
    
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13, DTLS_V12});
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.process_client_hello_version_negotiation(client_hello);
    ASSERT_TRUE(result.is_success());
    
    const auto& context = result.value();
    EXPECT_EQ(context.negotiated_version, DTLS_V13);
    EXPECT_TRUE(context.version_negotiation_complete);
    EXPECT_EQ(context.client_offered_versions.size(), 2);
    EXPECT_FALSE(context.requires_version_downgrade);
}

TEST_F(HandshakeIntegrationTest, ApplyVersionToServerHello) {
    VersionManager vm(default_config_);
    
    VersionManager::HandshakeVersionContext context;
    context.negotiated_version = DTLS_V13;
    context.version_negotiation_complete = true;
    
    ServerHello server_hello;
    auto result = vm.apply_version_to_server_hello(server_hello, context);
    ASSERT_TRUE(result.is_success());
    
    EXPECT_EQ(server_hello.legacy_version(), static_cast<protocol::ProtocolVersion>(DTLS_V12));
    EXPECT_TRUE(server_hello.has_extension(protocol::ExtensionType::SUPPORTED_VERSIONS));
}

TEST_F(HandshakeIntegrationTest, ApplyVersionToHelloRetryRequest) {
    VersionManager vm(default_config_);
    
    VersionManager::HandshakeVersionContext context;
    context.negotiated_version = DTLS_V13;
    context.version_negotiation_complete = true;
    
    HelloRetryRequest hrr;
    auto result = vm.apply_version_to_hello_retry_request(hrr, context);
    ASSERT_TRUE(result.is_success());
    
    EXPECT_EQ(hrr.legacy_version(), static_cast<protocol::ProtocolVersion>(DTLS_V12));
    EXPECT_TRUE(hrr.has_extension(protocol::ExtensionType::SUPPORTED_VERSIONS));
}

TEST_F(HandshakeIntegrationTest, ValidateHandshakeVersionConsistency) {
    VersionManager vm(default_config_);
    
    VersionManager::HandshakeVersionContext context;
    context.negotiated_version = DTLS_V13;
    context.client_offered_versions = {DTLS_V13, DTLS_V12};
    context.version_negotiation_complete = true;
    
    ServerHello server_hello;
    server_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13});
    ASSERT_TRUE(version_ext.is_success());
    server_hello.add_extension(std::move(version_ext.value()));
    
    auto result = vm.validate_handshake_version_consistency(context, server_hello);
    EXPECT_TRUE(result.is_valid);
}

TEST_F(HandshakeIntegrationTest, IncompleteNegotiationContext) {
    VersionManager vm(default_config_);
    
    VersionManager::HandshakeVersionContext context;
    context.negotiated_version = DTLS_V13;
    context.version_negotiation_complete = false; // Not complete
    
    ServerHello server_hello;
    auto result = vm.apply_version_to_server_hello(server_hello, context);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_STATE);
}

// ============================================================================
// Utility Function Tests
// ============================================================================

class UtilityFunctionTest : public VersionManagerComprehensiveTest {};

TEST_F(UtilityFunctionTest, CreateSupportedVersionsExtension) {
    std::vector<GlobalProtocolVersion> versions = {DTLS_V13, DTLS_V12};
    
    auto result = version_utils::create_supported_versions_extension(versions);
    ASSERT_TRUE(result.is_success());
    
    const auto& ext = result.value();
    EXPECT_EQ(ext.type, protocol::ExtensionType::SUPPORTED_VERSIONS);
    EXPECT_GT(ext.data.size(), 0);
    
    // Verify we can parse it back
    auto parsed = version_utils::parse_supported_versions_extension(ext);
    ASSERT_TRUE(parsed.is_success());
    
    const auto& parsed_versions = parsed.value();
    EXPECT_EQ(parsed_versions.size(), 2);
    EXPECT_EQ(parsed_versions[0], DTLS_V13);
    EXPECT_EQ(parsed_versions[1], DTLS_V12);
}

TEST_F(UtilityFunctionTest, CreateEmptyVersionsExtension) {
    std::vector<GlobalProtocolVersion> empty_versions;
    
    auto result = version_utils::create_supported_versions_extension(empty_versions);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(UtilityFunctionTest, ParseSupportedVersionsExtension) {
    // Create extension manually
    memory::Buffer data(5); // 1 byte length + 2 versions * 2 bytes each
    auto resize_result = data.resize(5);
    ASSERT_TRUE(resize_result.is_success());
    
    std::byte* ptr = data.mutable_data();
    ptr[0] = static_cast<std::byte>(4); // Length: 4 bytes (2 versions)
    
    // DTLS 1.3 (0xFEFC)
    uint16_t dtls13_net = htons(static_cast<uint16_t>(DTLS_V13));
    std::memcpy(ptr + 1, &dtls13_net, 2);
    
    // DTLS 1.2 (0xFEFD)
    uint16_t dtls12_net = htons(static_cast<uint16_t>(DTLS_V12));
    std::memcpy(ptr + 3, &dtls12_net, 2);
    
    Extension ext(protocol::ExtensionType::SUPPORTED_VERSIONS, std::move(data));
    
    auto result = version_utils::parse_supported_versions_extension(ext);
    ASSERT_TRUE(result.is_success());
    
    const auto& versions = result.value();
    EXPECT_EQ(versions.size(), 2);
    EXPECT_EQ(versions[0], DTLS_V13);
    EXPECT_EQ(versions[1], DTLS_V12);
}

TEST_F(UtilityFunctionTest, ParseInvalidExtension) {
    // Wrong extension type
    memory::Buffer data(1);
    auto resize_result = data.resize(1);
    ASSERT_TRUE(resize_result.is_success());
    
    Extension ext(protocol::ExtensionType::SERVER_NAME, std::move(data));
    
    auto result = version_utils::parse_supported_versions_extension(ext);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::UNSUPPORTED_EXTENSION);
}

TEST_F(UtilityFunctionTest, ParseMalformedExtension) {
    // Too short data
    memory::Buffer data(0);
    Extension ext(protocol::ExtensionType::SUPPORTED_VERSIONS, std::move(data));
    
    auto result = version_utils::parse_supported_versions_extension(ext);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
}

TEST_F(UtilityFunctionTest, IsAndValidateSupportedVersionsExtension) {
    auto ext_result = version_utils::create_supported_versions_extension({DTLS_V13});
    ASSERT_TRUE(ext_result.is_success());
    
    const auto& ext = ext_result.value();
    
    EXPECT_TRUE(version_utils::is_supported_versions_extension(ext));
    EXPECT_TRUE(version_utils::validate_supported_versions_extension(ext));
    
    // Test with wrong extension type
    memory::Buffer data(1);
    auto resize_result = data.resize(1);
    ASSERT_TRUE(resize_result.is_success());
    
    Extension wrong_ext(protocol::ExtensionType::SERVER_NAME, std::move(data));
    EXPECT_FALSE(version_utils::is_supported_versions_extension(wrong_ext));
    EXPECT_FALSE(version_utils::validate_supported_versions_extension(wrong_ext));
}

TEST_F(UtilityFunctionTest, GetLegacyVersionForHello) {
    // For DTLS 1.3, should return DTLS 1.2
    auto legacy = version_utils::get_legacy_version_for_hello(DTLS_V13);
    EXPECT_EQ(legacy, version_utils::constants::DEFAULT_LEGACY_VERSION);
    
    // For other versions, should return the actual version
    legacy = version_utils::get_legacy_version_for_hello(DTLS_V12);
    EXPECT_EQ(legacy, DTLS_V12);
    
    legacy = version_utils::get_legacy_version_for_hello(DTLS_V10);
    EXPECT_EQ(legacy, DTLS_V10);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

class ErrorHandlingTest : public VersionManagerComprehensiveTest {};

TEST_F(ErrorHandlingTest, InvalidConfiguration) {
    VersionManager::Config config;
    config.supported_versions = {}; // Empty - should throw
    
    EXPECT_THROW(VersionManager vm(config), std::invalid_argument);
}

TEST_F(ErrorHandlingTest, InvalidVersionCombination) {
    VersionManager::Config config;
    config.supported_versions = {static_cast<GlobalProtocolVersion>(0x1234)}; // Invalid version
    config.preferred_version = static_cast<GlobalProtocolVersion>(0x1234);
    
    EXPECT_THROW(VersionManager vm(config), std::invalid_argument);
}

TEST_F(ErrorHandlingTest, PreferredVersionNotSupported) {
    VersionManager::Config config;
    config.supported_versions = {DTLS_V12};
    config.preferred_version = DTLS_V13; // Not in supported list
    
    EXPECT_THROW(VersionManager vm(config), std::invalid_argument);
}

TEST_F(ErrorHandlingTest, ExtractVersionsFromInvalidClientHello) {
    VersionManager vm(default_config_);
    
    // ClientHello without supported_versions extension
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto result = vm.extract_supported_versions_from_client_hello(client_hello);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::MISSING_EXTENSION);
}

// ============================================================================
// Performance Tests
// ============================================================================

class PerformanceTest : public VersionManagerComprehensiveTest {};

TEST_F(PerformanceTest, VersionNegotiationPerformance) {
    VersionManager vm(default_config_);
    
    ClientHello client_hello;
    client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(DTLS_V12));
    
    auto version_ext = version_utils::create_supported_versions_extension({DTLS_V13, DTLS_V12});
    ASSERT_TRUE(version_ext.is_success());
    client_hello.add_extension(std::move(version_ext.value()));
    
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto result = vm.negotiate_version_from_client_hello(client_hello);
        ASSERT_TRUE(result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_LT(duration.count(), 100); // Should complete quickly
}

TEST_F(PerformanceTest, ExtensionParsingPerformance) {
    std::vector<GlobalProtocolVersion> versions = {DTLS_V13, DTLS_V12, DTLS_V10};
    
    auto ext_result = version_utils::create_supported_versions_extension(versions);
    ASSERT_TRUE(ext_result.is_success());
    
    const auto& ext = ext_result.value();
    
    const int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto result = version_utils::parse_supported_versions_extension(ext);
        ASSERT_TRUE(result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_LT(duration.count(), 100); // Should complete quickly
}

// Additional comprehensive tests
TEST_F(VersionManagerComprehensiveTest, ComprehensiveVersionScenarios) {
    // Test all supported version scenarios
    std::vector<std::vector<GlobalProtocolVersion>> test_scenarios = {
        {DTLS_V13},
        {DTLS_V12},
        {DTLS_V13, DTLS_V12},
        {DTLS_V13, DTLS_V12, DTLS_V10}
    };
    
    for (const auto& scenario : test_scenarios) {
        VersionManager::Config config;
        config.supported_versions = scenario;
        config.preferred_version = scenario.front(); // Highest version
        
        EXPECT_NO_THROW(VersionManager vm(config));
        
        VersionManager vm(config);
        EXPECT_EQ(vm.get_supported_versions().size(), scenario.size());
        EXPECT_EQ(vm.get_preferred_version(), scenario.front());
    }
}