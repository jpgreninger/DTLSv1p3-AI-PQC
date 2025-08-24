/**
 * @file test_version_manager_comprehensive_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS version manager implementation
 * 
 * Target: Achieve >95% coverage for version_manager.cpp
 * Tests all major components: VersionManager, version negotiation,
 * compatibility checking, alert generation, utility functions, and error handling
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <optional>
#include <algorithm>
#include <set>

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

class VersionManagerEnhancedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default configuration for most tests
        default_config_.supported_versions = {DTLS_V13, DTLS_V12};
        default_config_.preferred_version = DTLS_V13;
        default_config_.allow_version_downgrade = true;
        default_config_.strict_version_checking = false;
        default_config_.enable_version_fallback = true;
        default_config_.max_downgrade_distance = 1;
        
        // Strict configuration for security tests
        strict_config_.supported_versions = {DTLS_V13};
        strict_config_.preferred_version = DTLS_V13;
        strict_config_.allow_version_downgrade = false;
        strict_config_.strict_version_checking = true;
        strict_config_.enable_version_fallback = false;
        strict_config_.max_downgrade_distance = 0;
        
        // Permissive configuration for compatibility tests
        permissive_config_.supported_versions = {DTLS_V13, DTLS_V12, DTLS_V11, DTLS_V10};
        permissive_config_.preferred_version = DTLS_V13;
        permissive_config_.allow_version_downgrade = true;
        permissive_config_.strict_version_checking = false;
        permissive_config_.enable_version_fallback = true;
        permissive_config_.max_downgrade_distance = 3;
        
        // Create test extension data
        create_test_extension_data();
    }
    
    void create_test_extension_data() {
        // Supported versions extension for DTLS 1.3
        dtls13_extension_ = {
            0x00, 0x2B, // Extension type: supported_versions
            0x00, 0x03, // Extension length: 3
            0x02,       // Vector length: 2
            0xfe, 0xfc  // DTLS 1.3 (0xfefc)
        };
        
        // Supported versions extension for DTLS 1.2 + 1.3
        dtls12_13_extension_ = {
            0x00, 0x2B, // Extension type: supported_versions
            0x00, 0x05, // Extension length: 5
            0x04,       // Vector length: 4
            0xfe, 0xfc, // DTLS 1.3
            0xfe, 0xfd  // DTLS 1.2
        };
        
        // Supported versions extension for multiple versions
        multi_version_extension_ = {
            0x00, 0x2B, // Extension type: supported_versions
            0x00, 0x09, // Extension length: 9
            0x08,       // Vector length: 8
            0xfe, 0xfc, // DTLS 1.3
            0xfe, 0xfd, // DTLS 1.2
            0xfe, 0xfe, // DTLS 1.1
            0xfe, 0xff  // DTLS 1.0
        };
        
        // Invalid extension (malformed)
        invalid_extension_ = {
            0x00, 0x2B, // Extension type: supported_versions
            0x00, 0x02, // Extension length: 2 (too short)
            0x04        // Vector length: 4 (but only 1 byte following)
        };
        
        // Empty extension
        empty_extension_ = {
            0x00, 0x2B, // Extension type: supported_versions
            0x00, 0x01, // Extension length: 1
            0x00        // Vector length: 0
        };
    }
    
    VersionManager::Config default_config_;
    VersionManager::Config strict_config_;
    VersionManager::Config permissive_config_;
    std::vector<uint8_t> dtls13_extension_;
    std::vector<uint8_t> dtls12_13_extension_;
    std::vector<uint8_t> multi_version_extension_;
    std::vector<uint8_t> invalid_extension_;
    std::vector<uint8_t> empty_extension_;
};

// ============================================================================
// VersionManager Basic Tests
// ============================================================================

class VersionManagerBasicTest : public VersionManagerEnhancedTest {};

TEST_F(VersionManagerBasicTest, DefaultConstruction) {
    VersionManager vm;
    
    // Should have default configuration
    auto config = vm.get_config();
    EXPECT_FALSE(config.supported_versions.empty());
    EXPECT_NE(config.preferred_version, static_cast<ProtocolVersion>(0));
}

TEST_F(VersionManagerBasicTest, CustomConfiguration) {
    VersionManager vm(default_config_);
    
    auto config = vm.get_config();
    EXPECT_EQ(config.supported_versions, default_config_.supported_versions);
    EXPECT_EQ(config.preferred_version, default_config_.preferred_version);
    EXPECT_EQ(config.allow_version_downgrade, default_config_.allow_version_downgrade);
}

TEST_F(VersionManagerBasicTest, UpdateConfiguration) {
    VersionManager vm;
    
    auto update_result = vm.update_config(strict_config_);
    EXPECT_TRUE(update_result.is_success());
    
    auto config = vm.get_config();
    EXPECT_EQ(config.supported_versions, strict_config_.supported_versions);
    EXPECT_EQ(config.preferred_version, strict_config_.preferred_version);
    EXPECT_EQ(config.strict_version_checking, strict_config_.strict_version_checking);
}

TEST_F(VersionManagerBasicTest, SupportedVersionsManagement) {
    VersionManager vm;
    
    // Test adding version
    auto add_result = vm.add_supported_version(DTLS_V11);
    EXPECT_TRUE(add_result.is_success());
    
    EXPECT_TRUE(vm.is_version_supported(DTLS_V11));
    
    // Test removing version
    auto remove_result = vm.remove_supported_version(DTLS_V11);
    EXPECT_TRUE(remove_result.is_success());
    
    EXPECT_FALSE(vm.is_version_supported(DTLS_V11));
}

TEST_F(VersionManagerBasicTest, VersionSupport) {
    VersionManager vm(default_config_);
    
    EXPECT_TRUE(vm.is_version_supported(DTLS_V13));
    EXPECT_TRUE(vm.is_version_supported(DTLS_V12));
    EXPECT_FALSE(vm.is_version_supported(DTLS_V11));
    EXPECT_FALSE(vm.is_version_supported(DTLS_V10));
}

TEST_F(VersionManagerBasicTest, PreferredVersion) {
    VersionManager vm(default_config_);
    
    EXPECT_EQ(vm.get_preferred_version(), DTLS_V13);
    
    auto set_result = vm.set_preferred_version(DTLS_V12);
    EXPECT_TRUE(set_result.is_success());
    EXPECT_EQ(vm.get_preferred_version(), DTLS_V12);
}

TEST_F(VersionManagerBasicTest, InvalidPreferredVersion) {
    VersionManager vm(strict_config_);
    
    // Try to set unsupported version as preferred
    auto set_result = vm.set_preferred_version(DTLS_V11);
    EXPECT_FALSE(set_result.is_success());
    
    // Preferred version should remain unchanged
    EXPECT_EQ(vm.get_preferred_version(), DTLS_V13);
}

// ============================================================================
// Version Negotiation Tests
// ============================================================================

class VersionNegotiationTest : public VersionManagerEnhancedTest {};

TEST_F(VersionNegotiationTest, SuccessfulNegotiation) {
    VersionManager vm(default_config_);
    
    std::vector<ProtocolVersion> client_versions = {DTLS_V13, DTLS_V12};
    auto negotiate_result = vm.negotiate_version(client_versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_EQ(result.negotiated_version, DTLS_V13); // Should pick highest common version
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.version_downgrade_detected);
}

TEST_F(VersionNegotiationTest, VersionDowngrade) {
    VersionManager vm(default_config_);
    
    // Client only supports DTLS 1.2
    std::vector<ProtocolVersion> client_versions = {DTLS_V12};
    auto negotiate_result = vm.negotiate_version(client_versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_EQ(result.negotiated_version, DTLS_V12);
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.version_downgrade_detected); // Downgrade from preferred DTLS 1.3
}

TEST_F(VersionNegotiationTest, NoCommonVersion) {
    VersionManager vm(strict_config_); // Only supports DTLS 1.3
    
    // Client only supports older versions
    std::vector<ProtocolVersion> client_versions = {DTLS_V12, DTLS_V11};
    auto negotiate_result = vm.negotiate_version(client_versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.negotiated_version, static_cast<ProtocolVersion>(0));
}

TEST_F(VersionNegotiationTest, StrictVersionChecking) {
    VersionManager vm(strict_config_);
    
    // Client supports DTLS 1.3 but also older versions
    std::vector<ProtocolVersion> client_versions = {DTLS_V13, DTLS_V12, DTLS_V11};
    auto negotiate_result = vm.negotiate_version(client_versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_EQ(result.negotiated_version, DTLS_V13);
    EXPECT_TRUE(result.success);
}

TEST_F(VersionNegotiationTest, DowngradeNotAllowed) {
    VersionManager vm(strict_config_);
    
    // Client only supports DTLS 1.2
    std::vector<ProtocolVersion> client_versions = {DTLS_V12};
    auto negotiate_result = vm.negotiate_version(client_versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_FALSE(result.success); // Should fail because downgrade not allowed
}

TEST_F(VersionNegotiationTest, MaxDowngradeDistance) {
    auto config = default_config_;
    config.max_downgrade_distance = 1;
    VersionManager vm(config);
    
    // Try to downgrade by 2 versions (DTLS 1.3 -> DTLS 1.1)
    std::vector<ProtocolVersion> client_versions = {DTLS_V11};
    auto negotiate_result = vm.negotiate_version(client_versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_FALSE(result.success); // Should fail due to max downgrade distance
}

TEST_F(VersionNegotiationTest, EmptyClientVersions) {
    VersionManager vm(default_config_);
    
    std::vector<ProtocolVersion> empty_versions;
    auto negotiate_result = vm.negotiate_version(empty_versions);
    
    EXPECT_FALSE(negotiate_result.is_success()); // Should return error
}

TEST_F(VersionNegotiationTest, DuplicateClientVersions) {
    VersionManager vm(default_config_);
    
    // Client sends duplicate versions
    std::vector<ProtocolVersion> duplicate_versions = {DTLS_V13, DTLS_V12, DTLS_V13, DTLS_V12};
    auto negotiate_result = vm.negotiate_version(duplicate_versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_EQ(result.negotiated_version, DTLS_V13);
    EXPECT_TRUE(result.success);
}

TEST_F(VersionNegotiationTest, UnknownVersions) {
    VersionManager vm(default_config_);
    
    // Client sends unknown/future versions
    ProtocolVersion future_version = {0xfe, 0xfb}; // Hypothetical DTLS 1.4
    std::vector<ProtocolVersion> versions = {future_version, DTLS_V13, DTLS_V12};
    auto negotiate_result = vm.negotiate_version(versions);
    
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto result = negotiate_result.value();
    EXPECT_EQ(result.negotiated_version, DTLS_V13); // Should pick highest known version
    EXPECT_TRUE(result.success);
}

// ============================================================================
// Extension Processing Tests
// ============================================================================

class ExtensionProcessingTest : public VersionManagerEnhancedTest {};

TEST_F(ExtensionProcessingTest, CreateSupportedVersionsExtension) {
    VersionManager vm(default_config_);
    
    auto create_result = vm.create_supported_versions_extension();
    EXPECT_TRUE(create_result.is_success());
    
    auto extension_data = create_result.value();
    EXPECT_GT(extension_data.size(), 4); // Should have header + version data
    
    // Verify extension type
    EXPECT_EQ(extension_data[0], 0x00);
    EXPECT_EQ(extension_data[1], 0x2B); // supported_versions extension
}

TEST_F(ExtensionProcessingTest, ParseValidExtension) {
    auto parse_result = version_utils::parse_supported_versions_extension(dtls13_extension_);
    EXPECT_TRUE(parse_result.is_success());
    
    auto versions = parse_result.value();
    EXPECT_EQ(versions.size(), 1);
    EXPECT_EQ(versions[0], DTLS_V13);
}

TEST_F(ExtensionProcessingTest, ParseMultiVersionExtension) {
    auto parse_result = version_utils::parse_supported_versions_extension(dtls12_13_extension_);
    EXPECT_TRUE(parse_result.is_success());
    
    auto versions = parse_result.value();
    EXPECT_EQ(versions.size(), 2);
    EXPECT_EQ(versions[0], DTLS_V13);
    EXPECT_EQ(versions[1], DTLS_V12);
}

TEST_F(ExtensionProcessingTest, ParseComplexExtension) {
    auto parse_result = version_utils::parse_supported_versions_extension(multi_version_extension_);
    EXPECT_TRUE(parse_result.is_success());
    
    auto versions = parse_result.value();
    EXPECT_EQ(versions.size(), 4);
    EXPECT_EQ(versions[0], DTLS_V13);
    EXPECT_EQ(versions[1], DTLS_V12);
    EXPECT_EQ(versions[2], DTLS_V11);
    EXPECT_EQ(versions[3], DTLS_V10);
}

TEST_F(ExtensionProcessingTest, ParseInvalidExtension) {
    auto parse_result = version_utils::parse_supported_versions_extension(invalid_extension_);
    EXPECT_FALSE(parse_result.is_success());
}

TEST_F(ExtensionProcessingTest, ParseEmptyExtension) {
    auto parse_result = version_utils::parse_supported_versions_extension(empty_extension_);
    EXPECT_TRUE(parse_result.is_success());
    
    auto versions = parse_result.value();
    EXPECT_TRUE(versions.empty());
}

TEST_F(ExtensionProcessingTest, ValidateExtension) {
    EXPECT_TRUE(version_utils::validate_supported_versions_extension(dtls13_extension_));
    EXPECT_TRUE(version_utils::validate_supported_versions_extension(dtls12_13_extension_));
    EXPECT_TRUE(version_utils::validate_supported_versions_extension(multi_version_extension_));
    EXPECT_FALSE(version_utils::validate_supported_versions_extension(invalid_extension_));
    EXPECT_TRUE(version_utils::validate_supported_versions_extension(empty_extension_));
}

TEST_F(ExtensionProcessingTest, IsExtensionPresent) {
    EXPECT_TRUE(version_utils::is_supported_versions_extension(dtls13_extension_));
    EXPECT_TRUE(version_utils::is_supported_versions_extension(dtls12_13_extension_));
    
    // Test non-supported-versions extension
    std::vector<uint8_t> other_extension = {
        0x00, 0x10, // Different extension type
        0x00, 0x02,
        0x00, 0x01
    };
    EXPECT_FALSE(version_utils::is_supported_versions_extension(other_extension));
}

TEST_F(ExtensionProcessingTest, RoundTripExtension) {
    VersionManager vm(permissive_config_);
    
    // Create extension
    auto create_result = vm.create_supported_versions_extension();
    EXPECT_TRUE(create_result.is_success());
    
    auto extension_data = create_result.value();
    
    // Parse it back
    auto parse_result = version_utils::parse_supported_versions_extension(extension_data);
    EXPECT_TRUE(parse_result.is_success());
    
    auto parsed_versions = parse_result.value();
    
    // Should match original supported versions
    EXPECT_EQ(parsed_versions.size(), permissive_config_.supported_versions.size());
    for (size_t i = 0; i < parsed_versions.size(); ++i) {
        EXPECT_EQ(parsed_versions[i], permissive_config_.supported_versions[i]);
    }
}

// ============================================================================
// Compatibility Checking Tests
// ============================================================================

class CompatibilityTest : public VersionManagerEnhancedTest {};

TEST_F(CompatibilityTest, BasicCompatibilityCheck) {
    VersionManager vm(default_config_);
    
    auto compat_result = vm.check_compatibility(DTLS_V13);
    EXPECT_TRUE(compat_result.is_success());
    
    auto info = compat_result.value();
    EXPECT_TRUE(info.is_compatible);
    EXPECT_FALSE(info.requires_downgrade);
    EXPECT_TRUE(info.recommended_version == DTLS_V13);
}

TEST_F(CompatibilityTest, DowngradeCompatibility) {
    VersionManager vm(default_config_);
    
    auto compat_result = vm.check_compatibility(DTLS_V12);
    EXPECT_TRUE(compat_result.is_success());
    
    auto info = compat_result.value();
    EXPECT_TRUE(info.is_compatible);
    EXPECT_TRUE(info.requires_downgrade);
    EXPECT_TRUE(info.recommended_version == DTLS_V12);
}

TEST_F(CompatibilityTest, IncompatibleVersion) {
    VersionManager vm(strict_config_);
    
    auto compat_result = vm.check_compatibility(DTLS_V12);
    EXPECT_TRUE(compat_result.is_success());
    
    auto info = compat_result.value();
    EXPECT_FALSE(info.is_compatible);
    EXPECT_FALSE(info.requires_downgrade);
}

TEST_F(CompatibilityTest, FutureVersionCompatibility) {
    VersionManager vm(default_config_);
    
    ProtocolVersion future_version = {0xfe, 0xfb}; // Hypothetical DTLS 1.4
    auto compat_result = vm.check_compatibility(future_version);
    EXPECT_TRUE(compat_result.is_success());
    
    auto info = compat_result.value();
    EXPECT_FALSE(info.is_compatible); // Future versions not supported
}

TEST_F(CompatibilityTest, LegacyVersionCompatibility) {
    VersionManager vm(permissive_config_);
    
    auto compat_result = vm.check_compatibility(DTLS_V10);
    EXPECT_TRUE(compat_result.is_success());
    
    auto info = compat_result.value();
    EXPECT_TRUE(info.is_compatible);
    EXPECT_TRUE(info.requires_downgrade);
    EXPECT_TRUE(info.recommended_version == DTLS_V10);
}

TEST_F(CompatibilityTest, CompatibilityWithConstraints) {
    auto config = default_config_;
    config.max_downgrade_distance = 1;
    VersionManager vm(config);
    
    // Check compatibility with version that's too far down
    auto compat_result = vm.check_compatibility(DTLS_V10);
    EXPECT_TRUE(compat_result.is_success());
    
    auto info = compat_result.value();
    EXPECT_FALSE(info.is_compatible); // Should be incompatible due to distance
}

// ============================================================================
// Alert Generation Tests
// ============================================================================

class AlertGenerationTest : public VersionManagerEnhancedTest {};

TEST_F(AlertGenerationTest, UnsupportedVersionAlert) {
    VersionManager vm(strict_config_);
    
    auto alert_result = vm.generate_unsupported_version_alert(DTLS_V12);
    EXPECT_TRUE(alert_result.is_success());
    
    auto alert = alert_result.value();
    EXPECT_EQ(alert.level, AlertLevel::FATAL);
    EXPECT_EQ(alert.description, AlertDescription::PROTOCOL_VERSION);
}

TEST_F(AlertGenerationTest, DowngradeDetectedAlert) {
    VersionManager vm(strict_config_);
    
    auto alert_result = vm.generate_downgrade_detected_alert(DTLS_V13, DTLS_V12);
    EXPECT_TRUE(alert_result.is_success());
    
    auto alert = alert_result.value();
    EXPECT_EQ(alert.level, AlertLevel::FATAL);
    EXPECT_EQ(alert.description, AlertDescription::INAPPROPRIATE_FALLBACK);
}

TEST_F(AlertGenerationTest, IncompatibleVersionAlert) {
    VersionManager vm(default_config_);
    
    ProtocolVersion unknown_version = {0xff, 0xff};
    auto alert_result = vm.generate_unsupported_version_alert(unknown_version);
    EXPECT_TRUE(alert_result.is_success());
    
    auto alert = alert_result.value();
    EXPECT_EQ(alert.level, AlertLevel::FATAL);
    EXPECT_EQ(alert.description, AlertDescription::PROTOCOL_VERSION);
}

// ============================================================================
// Utility Functions Tests
// ============================================================================

class UtilityFunctionsTest : public VersionManagerEnhancedTest {};

TEST_F(UtilityFunctionsTest, LegacyVersionForHello) {
    // For DTLS 1.3, legacy version should be DTLS 1.2
    auto legacy_v13 = version_utils::get_legacy_version_for_hello(DTLS_V13);
    EXPECT_EQ(legacy_v13, DTLS_V12);
    
    // For DTLS 1.2, legacy version should be itself
    auto legacy_v12 = version_utils::get_legacy_version_for_hello(DTLS_V12);
    EXPECT_EQ(legacy_v12, DTLS_V12);
    
    // For older versions, should be itself
    auto legacy_v11 = version_utils::get_legacy_version_for_hello(DTLS_V11);
    EXPECT_EQ(legacy_v11, DTLS_V11);
}

TEST_F(UtilityFunctionsTest, VersionConstants) {
    // Test that constants are properly defined
    EXPECT_NE(version_utils::constants::MIN_SUPPORTED_VERSION, static_cast<ProtocolVersion>(0));
    EXPECT_NE(version_utils::constants::MAX_SUPPORTED_VERSION, static_cast<ProtocolVersion>(0));
    EXPECT_NE(version_utils::constants::DEFAULT_LEGACY_VERSION, static_cast<ProtocolVersion>(0));
    EXPECT_GT(version_utils::constants::MAX_VERSION_DOWNGRADE_TOLERANCE, 0);
}

TEST_F(UtilityFunctionsTest, VersionComparison) {
    // DTLS version comparison (note: higher major/minor values = older versions in DTLS)
    EXPECT_TRUE(DTLS_V13.major == 0xfe && DTLS_V13.minor == 0xfc);
    EXPECT_TRUE(DTLS_V12.major == 0xfe && DTLS_V12.minor == 0xfd);
    EXPECT_TRUE(DTLS_V11.major == 0xfe && DTLS_V11.minor == 0xfe);
    EXPECT_TRUE(DTLS_V10.major == 0xfe && DTLS_V10.minor == 0xff);
    
    // In DTLS, newer versions have lower minor version numbers
    EXPECT_LT(DTLS_V13.minor, DTLS_V12.minor);
    EXPECT_LT(DTLS_V12.minor, DTLS_V11.minor);
    EXPECT_LT(DTLS_V11.minor, DTLS_V10.minor);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

class VersionManagerErrorTest : public VersionManagerEnhancedTest {};

TEST_F(VersionManagerErrorTest, InvalidConfiguration) {
    VersionManager::Config invalid_config;
    invalid_config.supported_versions.clear(); // No supported versions
    invalid_config.preferred_version = DTLS_V13;
    
    VersionManager vm;
    auto update_result = vm.update_config(invalid_config);
    EXPECT_FALSE(update_result.is_success());
}

TEST_F(VersionManagerErrorTest, UnsupportedPreferredVersion) {
    VersionManager::Config invalid_config;
    invalid_config.supported_versions = {DTLS_V12};
    invalid_config.preferred_version = DTLS_V13; // Not in supported list
    
    VersionManager vm;
    auto update_result = vm.update_config(invalid_config);
    EXPECT_FALSE(update_result.is_success());
}

TEST_F(VersionManagerErrorTest, MalformedExtensionData) {
    // Test various malformed extension scenarios
    std::vector<std::vector<uint8_t>> malformed_extensions = {
        {0x00}, // Too short
        {0x00, 0x2B}, // Missing length
        {0x00, 0x2B, 0x00}, // Incomplete length
        {0x00, 0x2B, 0x00, 0x05, 0x04, 0xfe}, // Incomplete version data
    };
    
    for (const auto& ext : malformed_extensions) {
        auto parse_result = version_utils::parse_supported_versions_extension(ext);
        EXPECT_FALSE(parse_result.is_success());
        
        EXPECT_FALSE(version_utils::validate_supported_versions_extension(ext));
    }
}

TEST_F(VersionManagerErrorTest, NegotiationWithEmptyConfig) {
    VersionManager::Config empty_config;
    empty_config.supported_versions.clear();
    
    VersionManager vm;
    auto update_result = vm.update_config(empty_config);
    EXPECT_FALSE(update_result.is_success());
    
    // VM should still have valid config, so negotiation should work
    std::vector<ProtocolVersion> client_versions = {DTLS_V13};
    auto negotiate_result = vm.negotiate_version(client_versions);
    EXPECT_TRUE(negotiate_result.is_success());
}

TEST_F(VersionManagerErrorTest, RemoveLastSupportedVersion) {
    VersionManager vm(strict_config_); // Only supports DTLS 1.3
    
    auto remove_result = vm.remove_supported_version(DTLS_V13);
    EXPECT_FALSE(remove_result.is_success()); // Should fail to prevent empty config
}

TEST_F(VersionManagerErrorTest, AddDuplicateVersion) {
    VersionManager vm(default_config_);
    
    // Try to add version that's already supported
    auto add_result = vm.add_supported_version(DTLS_V13);
    EXPECT_TRUE(add_result.is_success()); // Should succeed (no-op)
    
    // Configuration should remain unchanged
    auto config = vm.get_config();
    EXPECT_EQ(config.supported_versions.size(), default_config_.supported_versions.size());
}

// ============================================================================
// Handshake Context Tests
// ============================================================================

class HandshakeContextTest : public VersionManagerEnhancedTest {};

TEST_F(HandshakeContextTest, ContextCreation) {
    VersionManager vm(default_config_);
    
    auto context_result = vm.create_handshake_context(DTLS_V13);
    EXPECT_TRUE(context_result.is_success());
    
    auto context = context_result.value();
    EXPECT_EQ(context.negotiated_version, DTLS_V13);
    EXPECT_FALSE(context.version_downgrade_occurred);
    EXPECT_TRUE(context.version_extensions_processed);
}

TEST_F(HandshakeContextTest, ContextWithDowngrade) {
    VersionManager vm(default_config_);
    
    auto context_result = vm.create_handshake_context(DTLS_V12);
    EXPECT_TRUE(context_result.is_success());
    
    auto context = context_result.value();
    EXPECT_EQ(context.negotiated_version, DTLS_V12);
    EXPECT_TRUE(context.version_downgrade_occurred);
}

TEST_F(HandshakeContextTest, ContextValidation) {
    VersionManager vm(default_config_);
    
    auto context_result = vm.create_handshake_context(DTLS_V13);
    EXPECT_TRUE(context_result.is_success());
    
    auto context = context_result.value();
    auto validate_result = vm.validate_handshake_context(context);
    EXPECT_TRUE(validate_result.is_success());
    
    auto validation = validate_result.value();
    EXPECT_TRUE(validation.is_valid);
    EXPECT_TRUE(validation.context_complete);
}

TEST_F(HandshakeContextTest, InvalidContextValidation) {
    VersionManager vm(strict_config_);
    
    // Create context with unsupported version
    VersionManager::HandshakeVersionContext invalid_context;
    invalid_context.negotiated_version = DTLS_V12; // Not supported in strict config
    invalid_context.version_downgrade_occurred = true;
    
    auto validate_result = vm.validate_handshake_context(invalid_context);
    EXPECT_TRUE(validate_result.is_success());
    
    auto validation = validate_result.value();
    EXPECT_FALSE(validation.is_valid);
}

// ============================================================================
// Stress and Performance Tests
// ============================================================================

class VersionManagerStressTest : public VersionManagerEnhancedTest {};

TEST_F(VersionManagerStressTest, MultipleNegotiations) {
    VersionManager vm(permissive_config_);
    
    const int num_negotiations = 1000;
    std::vector<ProtocolVersion> test_versions = {DTLS_V13, DTLS_V12, DTLS_V11, DTLS_V10};
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_negotiations; ++i) {
        auto negotiate_result = vm.negotiate_version(test_versions);
        EXPECT_TRUE(negotiate_result.is_success());
        
        auto result = negotiate_result.value();
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.negotiated_version, DTLS_V13); // Should always pick highest
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    std::cout << "Completed " << num_negotiations << " negotiations in " 
              << duration.count() << "μs" << std::endl;
    std::cout << "Average time per negotiation: " 
              << static_cast<double>(duration.count()) / num_negotiations << "μs" << std::endl;
    
    // Performance should be reasonable
    EXPECT_LT(duration.count(), 100000); // Less than 100ms for 1000 negotiations
}

TEST_F(VersionManagerStressTest, ExtensionProcessingPerformance) {
    const int num_operations = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_operations; ++i) {
        // Parse extension
        auto parse_result = version_utils::parse_supported_versions_extension(multi_version_extension_);
        EXPECT_TRUE(parse_result.is_success());
        
        // Validate extension
        bool valid = version_utils::validate_supported_versions_extension(multi_version_extension_);
        EXPECT_TRUE(valid);
        
        // Check if it's supported versions extension
        bool is_supported = version_utils::is_supported_versions_extension(multi_version_extension_);
        EXPECT_TRUE(is_supported);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    std::cout << "Completed " << (num_operations * 3) << " extension operations in " 
              << duration.count() << "μs" << std::endl;
    
    // Performance should be reasonable
    EXPECT_LT(duration.count(), 50000); // Less than 50ms for 3000 operations
}

TEST_F(VersionManagerStressTest, ConcurrentNegotiations) {
    const int num_threads = 4;
    const int negotiations_per_thread = 250;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([this, &success_count, &failure_count, t, negotiations_per_thread]() {
            VersionManager vm(permissive_config_);
            std::vector<ProtocolVersion> test_versions = {DTLS_V13, DTLS_V12, DTLS_V11};
            
            for (int i = 0; i < negotiations_per_thread; ++i) {
                auto negotiate_result = vm.negotiate_version(test_versions);
                if (negotiate_result.is_success() && negotiate_result.value().success) {
                    success_count++;
                } else {
                    failure_count++;
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(success_count.load(), num_threads * negotiations_per_thread);
    EXPECT_EQ(failure_count.load(), 0);
}

// ============================================================================
// Integration Tests
// ============================================================================

class VersionManagerIntegrationTest : public VersionManagerEnhancedTest {};

TEST_F(VersionManagerIntegrationTest, FullHandshakeNegotiation) {
    VersionManager server_vm(default_config_);
    VersionManager client_vm(default_config_);
    
    // Client creates supported versions extension
    auto client_ext_result = client_vm.create_supported_versions_extension();
    EXPECT_TRUE(client_ext_result.is_success());
    
    auto client_extension = client_ext_result.value();
    
    // Server parses client extension
    auto parse_result = version_utils::parse_supported_versions_extension(client_extension);
    EXPECT_TRUE(parse_result.is_success());
    
    auto client_versions = parse_result.value();
    
    // Server negotiates version
    auto negotiate_result = server_vm.negotiate_version(client_versions);
    EXPECT_TRUE(negotiate_result.is_success());
    
    auto negotiation = negotiate_result.value();
    EXPECT_TRUE(negotiation.success);
    EXPECT_EQ(negotiation.negotiated_version, DTLS_V13);
    
    // Server creates handshake context
    auto context_result = server_vm.create_handshake_context(negotiation.negotiated_version);
    EXPECT_TRUE(context_result.is_success());
    
    auto context = context_result.value();
    EXPECT_EQ(context.negotiated_version, DTLS_V13);
    
    // Validate context
    auto validate_result = server_vm.validate_handshake_context(context);
    EXPECT_TRUE(validate_result.is_success());
    EXPECT_TRUE(validate_result.value().is_valid);
}

TEST_F(VersionManagerIntegrationTest, CrossVersionCompatibility) {
    // Test compatibility between different version configurations
    std::vector<VersionManager::Config> configs = {
        strict_config_,
        default_config_,
        permissive_config_
    };
    
    for (size_t i = 0; i < configs.size(); ++i) {
        for (size_t j = 0; j < configs.size(); ++j) {
            VersionManager client_vm(configs[i]);
            VersionManager server_vm(configs[j]);
            
            // Create client extension
            auto client_ext_result = client_vm.create_supported_versions_extension();
            EXPECT_TRUE(client_ext_result.is_success());
            
            // Parse and negotiate
            auto parse_result = version_utils::parse_supported_versions_extension(client_ext_result.value());
            EXPECT_TRUE(parse_result.is_success());
            
            auto negotiate_result = server_vm.negotiate_version(parse_result.value());
            EXPECT_TRUE(negotiate_result.is_success());
            
            // Result depends on compatibility between configurations
            auto negotiation = negotiate_result.value();
            
            if (i == 0 && j != 0) {
                // Strict client with non-strict server
                EXPECT_TRUE(negotiation.success);
                EXPECT_EQ(negotiation.negotiated_version, DTLS_V13);
            } else if (i != 0 && j == 0) {
                // Non-strict client with strict server
                // May succeed or fail depending on client's supported versions
                if (negotiation.success) {
                    EXPECT_EQ(negotiation.negotiated_version, DTLS_V13);
                }
            } else {
                // Compatible configurations should succeed
                EXPECT_TRUE(negotiation.success);
            }
        }
    }
}

// Add test main
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}