#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/protocol/handshake.h"
#include "dtls/compatibility/dtls12_compat.h"
#include <vector>
#include <optional>

namespace dtls::v13::protocol {

// Use global version type to avoid conflicts with protocol::ProtocolVersion enum
using GlobalProtocolVersion = dtls::v13::ProtocolVersion;

/**
 * @brief Protocol Version Manager for DTLS v1.3
 * 
 * @details Comprehensive version negotiation system handling DTLS protocol version 
 * negotiation, validation, and backward compatibility checks following @rfc{9147} specifications.
 * 
 * @par Key Features:
 * - 🔄 **Bidirectional Version Negotiation**: Client and server-side version handling
 * - 🛡️ **Security-First Design**: Built-in downgrade attack detection 
 * - 🔧 **Backward Compatible**: Seamless DTLS v1.2 fallback support
 * - ⚡ **High Performance**: Optimized for production environments
 * 
 * @security This class implements critical security measures including version downgrade
 * attack detection as specified in RFC 9147 Section 4.1.3.
 * 
 * @example{
 * ```cpp
 * // Server-side version negotiation
 * VersionManager vm;
 * auto result = vm.negotiate_version_from_client_hello(client_hello);
 * if (result.is_ok()) {
 *     auto negotiated = result.value().negotiated_version;
 *     // Apply to ServerHello...
 * }
 * ```
 * }
 * 
 * @since DTLS v1.3 Implementation v1.0.0
 * @author DTLS v1.3 Implementation Team
 */
class DTLS_API VersionManager {
public:
    /**
     * @brief Version negotiation result structure
     * 
     * @details Contains the outcome of version negotiation including security checks
     * and any required follow-up actions.
     * 
     * @see negotiate_version_from_client_hello()
     */
    struct NegotiationResult {
        GlobalProtocolVersion negotiated_version;
        bool version_downgrade_detected;
        bool requires_hello_retry_request;
        std::optional<AlertDescription> error_alert;
        
        NegotiationResult() = default;
        NegotiationResult(GlobalProtocolVersion version) 
            : negotiated_version(version), version_downgrade_detected(false),
              requires_hello_retry_request(false) {}
    };
    
    /**
     * Configuration for version manager
     */
    struct Config {
        std::vector<GlobalProtocolVersion> supported_versions;
        GlobalProtocolVersion preferred_version;
        bool allow_version_downgrade{true};
        bool strict_version_checking{false};
        
        Config() : supported_versions{dtls::v13::DTLS_V13, dtls::v13::DTLS_V12}, 
                   preferred_version{dtls::v13::DTLS_V13} {}
    };
    
    /**
     * Constructor
     */
    VersionManager();
    explicit VersionManager(const Config& config);
    
    /**
     * Get supported protocol versions in preference order
     */
    const std::vector<GlobalProtocolVersion>& get_supported_versions() const;
    
    /**
     * Set supported protocol versions
     */
    void set_supported_versions(const std::vector<GlobalProtocolVersion>& versions);
    
    /**
     * Get preferred (highest priority) version
     */
    GlobalProtocolVersion get_preferred_version() const;
    
    /**
     * Check if a specific version is supported
     */
    bool is_version_supported(GlobalProtocolVersion version) const;
    
    /**
     * Validate protocol version format and value
     */
    bool is_version_valid(GlobalProtocolVersion version) const;
    
    /**
     * Client-side version negotiation: prepare ClientHello with appropriate
     * legacy_version and supported_versions extension
     */
    Result<void> prepare_client_hello(ClientHello& client_hello) const;
    
    /**
     * @brief Server-side version negotiation from ClientHello
     * 
     * @details Analyzes the ClientHello message to determine the optimal protocol version
     * for the connection, considering supported versions extension and legacy compatibility.
     * 
     * @param client_hello The received ClientHello message containing version preferences
     * @returns NegotiationResult containing negotiated version and security analysis
     * 
     * @complexity{O(n*m) where n=client versions, m=server versions}
     * @performance Optimized for typical negotiation scenarios with early exit strategies
     * 
     * @security Implements mandatory downgrade attack detection per @rfc{9147} Section 4.1.3
     * 
     * @example{
     * ```cpp
     * VersionManager server_vm;
     * auto result = server_vm.negotiate_version_from_client_hello(client_hello);
     * if (result.is_ok() && !result.value().version_downgrade_detected) {
     *     // Safe to proceed with negotiated version
     *     auto version = result.value().negotiated_version;
     * }
     * ```
     * }
     */
    Result<NegotiationResult> negotiate_version_from_client_hello(
        const ClientHello& client_hello) const;
    
    /**
     * Client-side version verification: validate ServerHello version selection
     */
    Result<GlobalProtocolVersion> validate_server_hello_version(
        const ServerHello& server_hello,
        const std::vector<GlobalProtocolVersion>& client_offered_versions) const;
    
    /**
     * Server-side ServerHello preparation: set appropriate version fields
     */
    Result<void> prepare_server_hello(ServerHello& server_hello,
                                     GlobalProtocolVersion negotiated_version) const;
    
    /**
     * HelloRetryRequest version handling
     */
    Result<void> prepare_hello_retry_request(HelloRetryRequest& hrr,
                                           GlobalProtocolVersion negotiated_version) const;
    
    /**
     * Extract supported versions from ClientHello extension
     */
    Result<std::vector<GlobalProtocolVersion>> extract_supported_versions_from_client_hello(
        const ClientHello& client_hello) const;
    
    /**
     * Check for version downgrade attack detection (RFC 9147 Section 4.1.3)
     */
    bool detect_version_downgrade(GlobalProtocolVersion negotiated_version,
                                 const std::vector<GlobalProtocolVersion>& client_versions,
                                 const std::vector<GlobalProtocolVersion>& server_versions) const;
    
    /**
     * Get appropriate alert for version-related errors
     */
    AlertDescription get_version_error_alert(GlobalProtocolVersion attempted_version) const;
    
    /**
     * Backward compatibility checks
     */
    struct CompatibilityInfo {
        bool is_dtls12_compatible;
        bool requires_feature_fallback;
        std::vector<std::string> compatibility_notes;
        
        CompatibilityInfo() : is_dtls12_compatible(false), requires_feature_fallback(false) {}
    };
    
    CompatibilityInfo check_backward_compatibility(GlobalProtocolVersion version) const;
    
    /**
     * Integration with DTLS 1.2 compatibility layer
     */
    Result<void> configure_dtls12_compatibility(
        const compatibility::DTLS12CompatibilityContext& compat_context);
    
    bool should_enable_dtls12_fallback(const ClientHello& client_hello) const;
    
    Result<GlobalProtocolVersion> negotiate_with_compatibility_context(
        const ClientHello& client_hello,
        const compatibility::DTLS12CompatibilityContext& compat_context) const;
    
    /**
     * Version comparison utilities
     */
    static bool is_version_higher(GlobalProtocolVersion a, GlobalProtocolVersion b);
    static bool is_version_lower(GlobalProtocolVersion a, GlobalProtocolVersion b);
    static std::string version_to_string(GlobalProtocolVersion version);
    static Result<GlobalProtocolVersion> version_from_string(const std::string& version_str);
    
    /**
     * RFC 9147 specific version validation
     */
    bool is_dtls13_version(GlobalProtocolVersion version) const;
    bool is_dtls12_version(GlobalProtocolVersion version) const;
    bool is_legacy_version(GlobalProtocolVersion version) const;
    
    /**
     * Version validation and error handling
     */
    struct ValidationResult {
        bool is_valid;
        std::optional<AlertDescription> error_alert;
        std::string error_message;
        
        ValidationResult(bool valid = true) : is_valid(valid) {}
        ValidationResult(AlertDescription alert, const std::string& message)
            : is_valid(false), error_alert(alert), error_message(message) {}
    };
    
    ValidationResult validate_version_format(GlobalProtocolVersion version) const;
    ValidationResult validate_version_support(GlobalProtocolVersion version) const;
    ValidationResult validate_client_hello_versions(const ClientHello& client_hello) const;
    ValidationResult validate_server_hello_versions(const ServerHello& server_hello,
                                                   const std::vector<GlobalProtocolVersion>& client_offered) const;
    
    /**
     * Alert generation for version-related errors
     */
    protocol::Alert create_version_error_alert(GlobalProtocolVersion attempted_version,
                                              const std::string& context = "") const;
    
    protocol::Alert create_protocol_version_alert() const;
    protocol::Alert create_inappropriate_fallback_alert() const;
    protocol::Alert create_unsupported_extension_alert() const;
    
    /**
     * Handshake integration utilities
     */
    struct HandshakeVersionContext {
        GlobalProtocolVersion negotiated_version{dtls::v13::DTLS_V13};
        std::vector<GlobalProtocolVersion> client_offered_versions;
        bool requires_version_downgrade{false};
        bool version_negotiation_complete{false};
        std::optional<compatibility::DTLS12CompatibilityContext> compat_context;
        
        HandshakeVersionContext() = default;
    };
    
    /**
     * Process ClientHello for version negotiation
     */
    Result<HandshakeVersionContext> process_client_hello_version_negotiation(
        const ClientHello& client_hello,
        const std::optional<compatibility::DTLS12CompatibilityContext>& compat_context = std::nullopt) const;
    
    /**
     * Prepare ServerHello with negotiated version
     */
    Result<void> apply_version_to_server_hello(ServerHello& server_hello,
                                             const HandshakeVersionContext& context) const;
    
    /**
     * Prepare HelloRetryRequest with negotiated version
     */
    Result<void> apply_version_to_hello_retry_request(HelloRetryRequest& hrr,
                                                    const HandshakeVersionContext& context) const;
    
    /**
     * Validate version consistency in handshake flow
     */
    ValidationResult validate_handshake_version_consistency(
        const HandshakeVersionContext& context,
        const ServerHello& server_hello) const;

private:
    /**
     * Internal helper methods
     */
    Result<Extension> create_supported_versions_extension() const;
    Result<std::vector<GlobalProtocolVersion>> parse_supported_versions_extension(
        const Extension& ext) const;
    
    bool is_valid_version_combination(const std::vector<GlobalProtocolVersion>& versions) const;
    GlobalProtocolVersion select_best_version(const std::vector<GlobalProtocolVersion>& client_versions,
                                       const std::vector<GlobalProtocolVersion>& server_versions) const;
    
    void validate_configuration() const;
    
    // Configuration
    Config config_;
    
    // Version mapping for string conversion
    static const std::unordered_map<GlobalProtocolVersion, std::string> version_names_;
    static const std::unordered_map<std::string, GlobalProtocolVersion> name_to_version_;
};

/**
 * Version negotiation utilities
 */
namespace version_utils {
    
    /**
     * Create supported_versions extension with given versions
     */
    Result<Extension> create_supported_versions_extension(
        const std::vector<GlobalProtocolVersion>& versions);
    
    /**
     * Parse supported_versions extension
     */
    Result<std::vector<GlobalProtocolVersion>> parse_supported_versions_extension(
        const Extension& extension);
    
    /**
     * Check if extension is a supported_versions extension
     */
    bool is_supported_versions_extension(const Extension& extension);
    
    /**
     * Validate supported_versions extension format
     */
    bool validate_supported_versions_extension(const Extension& extension);
    
    /**
     * Get legacy version for wire compatibility
     */
    GlobalProtocolVersion get_legacy_version_for_hello(GlobalProtocolVersion actual_version);
    
    /**
     * Constants for version-specific behavior
     */
    namespace constants {
        // Minimum supported version
        constexpr GlobalProtocolVersion MIN_SUPPORTED_VERSION = dtls::v13::DTLS_V12;
        
        // Maximum supported version  
        constexpr GlobalProtocolVersion MAX_SUPPORTED_VERSION = dtls::v13::DTLS_V13;
        
        // Default legacy version for ClientHello/ServerHello
        constexpr GlobalProtocolVersion DEFAULT_LEGACY_VERSION = dtls::v13::DTLS_V12;
        
        // Version downgrade detection thresholds
        constexpr size_t MAX_VERSION_DOWNGRADE_TOLERANCE = 1;
    }
}

} // namespace dtls::v13::protocol