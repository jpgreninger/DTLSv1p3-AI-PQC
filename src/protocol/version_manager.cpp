#include "dtls/protocol/version_manager.h"
#include "dtls/error.h"
#include "dtls/error_handler.h"
#include <algorithm>
#include <unordered_map>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace dtls::v13::protocol {

// Static version name mappings
const std::unordered_map<GlobalProtocolVersion, std::string> VersionManager::version_names_ = {
    {dtls::v13::DTLS_V13, "DTLS 1.3"},
    {dtls::v13::DTLS_V12, "DTLS 1.2"},
    {dtls::v13::DTLS_V10, "DTLS 1.0"}
};

const std::unordered_map<std::string, GlobalProtocolVersion> VersionManager::name_to_version_ = {
    {"DTLS 1.3", dtls::v13::DTLS_V13},
    {"DTLS 1.2", dtls::v13::DTLS_V12},
    {"DTLS 1.0", dtls::v13::DTLS_V10},
    {"DTLSv1.3", dtls::v13::DTLS_V13},
    {"DTLSv1.2", dtls::v13::DTLS_V12},
    {"DTLSv1.0", dtls::v13::DTLS_V10}
};

VersionManager::VersionManager() : config_{} {
    validate_configuration();
}

VersionManager::VersionManager(const Config& config) : config_(config) {
    validate_configuration();
}

const std::vector<GlobalProtocolVersion>& VersionManager::get_supported_versions() const {
    return config_.supported_versions;
}

void VersionManager::set_supported_versions(const std::vector<GlobalProtocolVersion>& versions) {
    config_.supported_versions = versions;
    
    // Sort in preference order (highest first)
    std::sort(config_.supported_versions.begin(), config_.supported_versions.end(),
              [](GlobalProtocolVersion a, GlobalProtocolVersion b) {
                  return is_version_higher(a, b);
              });
    
    // Update preferred version to highest supported
    if (!config_.supported_versions.empty()) {
        config_.preferred_version = config_.supported_versions.front();
    }
    
    validate_configuration();
}

GlobalProtocolVersion VersionManager::get_preferred_version() const {
    return config_.preferred_version;
}

bool VersionManager::is_version_supported(GlobalProtocolVersion version) const {
    return std::find(config_.supported_versions.begin(), 
                     config_.supported_versions.end(), 
                     version) != config_.supported_versions.end();
}

bool VersionManager::is_version_valid(GlobalProtocolVersion version) const {
    // RFC 9147: Valid DTLS versions use the pattern 0xFE**
    // DTLS 1.0: 0xFEFF, DTLS 1.2: 0xFEFD, DTLS 1.3: 0xFEFC
    uint16_t version_val = static_cast<uint16_t>(version);
    return (version_val & 0xFF00) == 0xFE00;
}

Result<void> VersionManager::prepare_client_hello(ClientHello& client_hello) const {
    // RFC 9147 Section 4.1.2: ClientHello.legacy_version MUST be set to DTLS 1.2
    client_hello.set_legacy_version(ProtocolVersion::DTLS_1_2);
    
    // Add supported_versions extension with all supported versions
    auto version_ext_result = version_utils::create_supported_versions_extension(config_.supported_versions);
    if (!version_ext_result.is_success()) {
        return Result<void>(version_ext_result.error());
    }
    
    client_hello.add_extension(std::move(version_ext_result.value()));
    
    return Result<void>();
}

Result<VersionManager::NegotiationResult> VersionManager::negotiate_version_from_client_hello(
    const ClientHello& client_hello) const {
    
    NegotiationResult result;
    
    // Extract client's supported versions from extension
    auto client_versions_result = extract_supported_versions_from_client_hello(client_hello);
    if (!client_versions_result.is_success()) {
        // If no supported_versions extension, use legacy_version
        std::vector<GlobalProtocolVersion> legacy_versions = {static_cast<GlobalProtocolVersion>(client_hello.legacy_version())};
        client_versions_result = Result<std::vector<GlobalProtocolVersion>>(std::move(legacy_versions));
    }
    
    const auto& client_versions = client_versions_result.value();
    
    // Select best mutually supported version
    auto negotiated_version = select_best_version(client_versions, config_.supported_versions);
    
    if (negotiated_version == static_cast<GlobalProtocolVersion>(0)) {
        result.error_alert = AlertDescription::PROTOCOL_VERSION;
        return Result<NegotiationResult>(std::move(result));
    }
    
    // Check for version downgrade attacks
    if (config_.strict_version_checking) {
        result.version_downgrade_detected = detect_version_downgrade(
            negotiated_version, client_versions, config_.supported_versions);
        
        if (result.version_downgrade_detected && !config_.allow_version_downgrade) {
            result.error_alert = AlertDescription::INAPPROPRIATE_FALLBACK;
            return Result<NegotiationResult>(std::move(result));
        }
    }
    
    result.negotiated_version = negotiated_version;
    
    return Result<NegotiationResult>(std::move(result));
}

Result<GlobalProtocolVersion> VersionManager::validate_server_hello_version(
    const ServerHello& server_hello,
    const std::vector<GlobalProtocolVersion>& client_offered_versions) const {
    
    // RFC 9147: Check if server selected a version we offered
    GlobalProtocolVersion server_version = static_cast<GlobalProtocolVersion>(server_hello.legacy_version());
    
    // For DTLS 1.3, the actual version should be in supported_versions extension
    auto server_versions_ext = server_hello.get_extension(ExtensionType::SUPPORTED_VERSIONS);
    if (server_versions_ext.has_value()) {
        auto parsed_versions = parse_supported_versions_extension(server_versions_ext.value());
        if (parsed_versions.is_success() && !parsed_versions.value().empty()) {
            server_version = parsed_versions.value().front();
        }
    }
    
    // Verify server selected a version we offered
    bool version_offered = std::find(client_offered_versions.begin(),
                                   client_offered_versions.end(),
                                   server_version) != client_offered_versions.end();
    
    if (!version_offered) {
        return Result<GlobalProtocolVersion>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
    }
    
    // Verify the version is actually supported by us
    if (!is_version_supported(server_version)) {
        return Result<GlobalProtocolVersion>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
    }
    
    return Result<GlobalProtocolVersion>(server_version);
}

Result<void> VersionManager::prepare_server_hello(ServerHello& server_hello,
                                                 GlobalProtocolVersion negotiated_version) const {
    if (is_dtls13_version(negotiated_version)) {
        // RFC 9147: For DTLS 1.3, set legacy_version to DTLS 1.2
        server_hello.set_legacy_version(static_cast<ProtocolVersion>(version_utils::constants::DEFAULT_LEGACY_VERSION));
        
        // Add supported_versions extension with negotiated version
        auto version_ext_result = version_utils::create_supported_versions_extension({negotiated_version});
        if (!version_ext_result.is_success()) {
            return Result<void>(version_ext_result.error());
        }
        
        server_hello.add_extension(std::move(version_ext_result.value()));
    } else {
        // For DTLS 1.2 and earlier, set legacy_version to actual version
        server_hello.set_legacy_version(static_cast<ProtocolVersion>(negotiated_version));
    }
    
    return Result<void>();
}

Result<void> VersionManager::prepare_hello_retry_request(HelloRetryRequest& hrr,
                                                       GlobalProtocolVersion negotiated_version) const {
    // HelloRetryRequest follows same version rules as ServerHello
    if (is_dtls13_version(negotiated_version)) {
        hrr.set_legacy_version(static_cast<ProtocolVersion>(version_utils::constants::DEFAULT_LEGACY_VERSION));
        
        auto version_ext_result = version_utils::create_supported_versions_extension({negotiated_version});
        if (!version_ext_result.is_success()) {
            return Result<void>(version_ext_result.error());
        }
        
        hrr.add_extension(std::move(version_ext_result.value()));
    } else {
        hrr.set_legacy_version(static_cast<ProtocolVersion>(negotiated_version));
    }
    
    return Result<void>();
}

Result<std::vector<GlobalProtocolVersion>> VersionManager::extract_supported_versions_from_client_hello(
    const ClientHello& client_hello) const {
    
    auto version_ext = client_hello.get_extension(ExtensionType::SUPPORTED_VERSIONS);
    if (!version_ext.has_value()) {
        return Result<std::vector<GlobalProtocolVersion>>(DTLSError::MISSING_EXTENSION);
    }
    
    return parse_supported_versions_extension(version_ext.value());
}

bool VersionManager::detect_version_downgrade(GlobalProtocolVersion negotiated_version,
                                             const std::vector<GlobalProtocolVersion>& client_versions,
                                             const std::vector<GlobalProtocolVersion>& server_versions) const {
    // Find highest mutually supported version
    GlobalProtocolVersion highest_mutual = static_cast<GlobalProtocolVersion>(0);
    
    for (auto client_ver : client_versions) {
        for (auto server_ver : server_versions) {
            if (client_ver == server_ver) {
                if (highest_mutual == static_cast<GlobalProtocolVersion>(0) || is_version_higher(client_ver, highest_mutual)) {
                    highest_mutual = client_ver;
                }
            }
        }
    }
    
    // If negotiated version is lower than highest mutual, it's a potential downgrade
    return (highest_mutual != static_cast<GlobalProtocolVersion>(0)) && is_version_lower(negotiated_version, highest_mutual);
}

AlertDescription VersionManager::get_version_error_alert(GlobalProtocolVersion attempted_version) const {
    if (!is_version_valid(attempted_version)) {
        return AlertDescription::DECODE_ERROR;
    }
    
    if (!is_version_supported(attempted_version)) {
        return AlertDescription::PROTOCOL_VERSION;
    }
    
    return AlertDescription::HANDSHAKE_FAILURE;
}

VersionManager::CompatibilityInfo VersionManager::check_backward_compatibility(GlobalProtocolVersion version) const {
    CompatibilityInfo info;
    
    if (is_dtls12_version(version)) {
        info.is_dtls12_compatible = true;
        info.compatibility_notes.push_back("Full DTLS 1.2 compatibility");
        
        // Check if we need to disable DTLS 1.3 specific features
        if (is_version_supported(dtls::v13::DTLS_V13)) {
            info.requires_feature_fallback = true;
            info.compatibility_notes.push_back("Disable DTLS 1.3 features: 0-RTT, ACK messages, Connection ID");
        }
    } else if (is_dtls13_version(version)) {
        info.is_dtls12_compatible = false;
        info.compatibility_notes.push_back("DTLS 1.3 only - no backward compatibility");
    } else {
        info.is_dtls12_compatible = false;
        info.compatibility_notes.push_back("Unsupported version");
    }
    
    return info;
}

Result<void> VersionManager::configure_dtls12_compatibility(
    const compatibility::DTLS12CompatibilityContext& compat_context) {
    
    // Update configuration based on compatibility context
    if (compat_context.enable_dtls12_fallback) {
        // Ensure DTLS 1.2 is in supported versions if fallback is enabled
        if (!is_version_supported(dtls::v13::DTLS_V12)) {
            config_.supported_versions.push_back(dtls::v13::DTLS_V12);
            std::sort(config_.supported_versions.begin(), config_.supported_versions.end(),
                      [](GlobalProtocolVersion a, GlobalProtocolVersion b) {
                          return is_version_higher(a, b);
                      });
        }
        config_.allow_version_downgrade = true;
    }
    
    // Configure strict security mode
    if (compat_context.strict_dtls13_security) {
        config_.strict_version_checking = true;
        config_.allow_version_downgrade = false;
    }
    
    return Result<void>();
}

bool VersionManager::should_enable_dtls12_fallback(const ClientHello& client_hello) const {
    // Check if client only supports DTLS 1.2 or earlier
    auto client_versions_result = extract_supported_versions_from_client_hello(client_hello);
    
    if (!client_versions_result.is_success()) {
        // No supported_versions extension - check legacy_version
        return static_cast<GlobalProtocolVersion>(client_hello.legacy_version()) == dtls::v13::DTLS_V12 || 
               is_version_lower(static_cast<GlobalProtocolVersion>(client_hello.legacy_version()), dtls::v13::DTLS_V12);
    }
    
    const auto& client_versions = client_versions_result.value();
    
    // Check if client doesn't support DTLS 1.3
    bool supports_dtls13 = std::find(client_versions.begin(), client_versions.end(), 
                                   dtls::v13::DTLS_V13) != client_versions.end();
    
    return !supports_dtls13;
}

Result<GlobalProtocolVersion> VersionManager::negotiate_with_compatibility_context(
    const ClientHello& client_hello,
    const compatibility::DTLS12CompatibilityContext& compat_context) const {
    
    // First try normal negotiation
    auto negotiation_result = negotiate_version_from_client_hello(client_hello);
    if (!negotiation_result.is_success()) {
        return Result<GlobalProtocolVersion>(negotiation_result.error());
    }
    
    auto& result = negotiation_result.value();
    if (result.error_alert.has_value()) {
        return Result<GlobalProtocolVersion>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
    }
    
    // Check if we should use DTLS 1.2 fallback
    if (result.negotiated_version == dtls::v13::DTLS_V12 && compat_context.enable_dtls12_fallback) {
        // Additional validation for DTLS 1.2 context
        auto validation_result = compatibility::utils::validate_dtls12_context(compat_context);
        if (!validation_result.is_success()) {
            return Result<GlobalProtocolVersion>(validation_result.error());
        }
    }
    
    return Result<GlobalProtocolVersion>(result.negotiated_version);
}

bool VersionManager::is_version_higher(GlobalProtocolVersion a, GlobalProtocolVersion b) {
    // DTLS versions are inverted: lower numerical value = higher version
    // DTLS 1.3 (0xFEFC) > DTLS 1.2 (0xFEFD) > DTLS 1.0 (0xFEFF)
    return static_cast<uint16_t>(a) < static_cast<uint16_t>(b);
}

bool VersionManager::is_version_lower(GlobalProtocolVersion a, GlobalProtocolVersion b) {
    return static_cast<uint16_t>(a) > static_cast<uint16_t>(b);
}

std::string VersionManager::version_to_string(GlobalProtocolVersion version) {
    auto it = version_names_.find(version);
    if (it != version_names_.end()) {
        return it->second;
    }
    
    // Format unknown versions as hex
    return "Unknown(0x" + std::to_string(static_cast<uint16_t>(version)) + ")";
}

Result<GlobalProtocolVersion> VersionManager::version_from_string(const std::string& version_str) {
    auto it = name_to_version_.find(version_str);
    if (it != name_to_version_.end()) {
        return Result<GlobalProtocolVersion>(it->second);
    }
    
    return Result<GlobalProtocolVersion>(DTLSError::INVALID_PARAMETER);
}

bool VersionManager::is_dtls13_version(GlobalProtocolVersion version) const {
    return version == dtls::v13::DTLS_V13;
}

bool VersionManager::is_dtls12_version(GlobalProtocolVersion version) const {
    return version == dtls::v13::DTLS_V12;
}

bool VersionManager::is_legacy_version(GlobalProtocolVersion version) const {
    return version == dtls::v13::DTLS_V10 || version == dtls::v13::DTLS_V12;
}

VersionManager::ValidationResult VersionManager::validate_version_format(GlobalProtocolVersion version) const {
    if (!is_version_valid(version)) {
        return ValidationResult(AlertDescription::DECODE_ERROR, 
                              "Invalid DTLS version format: " + version_to_string(version));
    }
    return ValidationResult(true);
}

VersionManager::ValidationResult VersionManager::validate_version_support(GlobalProtocolVersion version) const {
    auto format_result = validate_version_format(version);
    if (!format_result.is_valid) {
        return format_result;
    }
    
    if (!is_version_supported(version)) {
        return ValidationResult(AlertDescription::PROTOCOL_VERSION,
                              "Unsupported DTLS version: " + version_to_string(version));
    }
    
    return ValidationResult(true);
}

VersionManager::ValidationResult VersionManager::validate_client_hello_versions(
    const ClientHello& client_hello) const {
    
    // Check legacy_version format
    auto legacy_result = validate_version_format(static_cast<GlobalProtocolVersion>(client_hello.legacy_version()));
    if (!legacy_result.is_valid) {
        return legacy_result;
    }
    
    // RFC 9147: For DTLS 1.3, legacy_version should be DTLS 1.2
    bool has_supported_versions_ext = client_hello.has_extension(ExtensionType::SUPPORTED_VERSIONS);
    
    if (has_supported_versions_ext) {
        // Extract and validate supported versions
        auto versions_result = extract_supported_versions_from_client_hello(client_hello);
        if (!versions_result.is_success()) {
            return ValidationResult(AlertDescription::DECODE_ERROR,
                                  "Malformed supported_versions extension");
        }
        
        const auto& versions = versions_result.value();
        if (versions.empty()) {
            return ValidationResult(AlertDescription::DECODE_ERROR,
                                  "Empty supported_versions extension");
        }
        
        // Validate each version format
        for (auto version : versions) {
            auto version_result = validate_version_format(version);
            if (!version_result.is_valid) {
                return version_result;
            }
        }
        
        // Check if any version is mutually supported
        bool has_supported = false;
        for (auto version : versions) {
            if (is_version_supported(version)) {
                has_supported = true;
                break;
            }
        }
        
        if (!has_supported) {
            return ValidationResult(AlertDescription::PROTOCOL_VERSION,
                                  "No mutually supported DTLS versions");
        }
    } else {
        // No supported_versions extension - validate legacy_version
        auto support_result = validate_version_support(static_cast<GlobalProtocolVersion>(client_hello.legacy_version()));
        if (!support_result.is_valid) {
            return support_result;
        }
    }
    
    return ValidationResult(true);
}

VersionManager::ValidationResult VersionManager::validate_server_hello_versions(
    const ServerHello& server_hello,
    const std::vector<GlobalProtocolVersion>& client_offered) const {
    
    // Check legacy_version format
    auto legacy_result = validate_version_format(static_cast<GlobalProtocolVersion>(server_hello.legacy_version()));
    if (!legacy_result.is_valid) {
        return legacy_result;
    }
    
    GlobalProtocolVersion selected_version = static_cast<GlobalProtocolVersion>(server_hello.legacy_version());
    
    // Check if server included supported_versions extension
    if (server_hello.has_extension(ExtensionType::SUPPORTED_VERSIONS)) {
        auto ext = server_hello.get_extension(ExtensionType::SUPPORTED_VERSIONS);
        if (ext.has_value()) {
            auto parsed_versions = parse_supported_versions_extension(ext.value());
            if (!parsed_versions.is_success()) {
                return ValidationResult(AlertDescription::DECODE_ERROR,
                                      "Malformed server supported_versions extension");
            }
            
            if (parsed_versions.value().size() != 1) {
                return ValidationResult(AlertDescription::DECODE_ERROR,
                                      "Server supported_versions must contain exactly one version");
            }
            
            selected_version = parsed_versions.value().front();
        }
    }
    
    // Validate selected version was offered by client
    bool version_offered = std::find(client_offered.begin(), client_offered.end(), 
                                   selected_version) != client_offered.end();
    
    if (!version_offered) {
        return ValidationResult(AlertDescription::ILLEGAL_PARAMETER,
                              "Server selected version not offered by client: " + 
                              version_to_string(selected_version));
    }
    
    // Validate we support the selected version
    auto support_result = validate_version_support(selected_version);
    if (!support_result.is_valid) {
        return support_result;
    }
    
    return ValidationResult(true);
}

protocol::Alert VersionManager::create_version_error_alert(GlobalProtocolVersion attempted_version,
                                                           const std::string& context) const {
    AlertDescription desc = get_version_error_alert(attempted_version);
    return protocol::Alert(AlertLevel::FATAL, desc);
}

protocol::Alert VersionManager::create_protocol_version_alert() const {
    return protocol::Alert(AlertLevel::FATAL, AlertDescription::PROTOCOL_VERSION);
}

protocol::Alert VersionManager::create_inappropriate_fallback_alert() const {
    return protocol::Alert(AlertLevel::FATAL, AlertDescription::INAPPROPRIATE_FALLBACK);
}

protocol::Alert VersionManager::create_unsupported_extension_alert() const {
    return protocol::Alert(AlertLevel::FATAL, AlertDescription::UNSUPPORTED_EXTENSION);
}

Result<VersionManager::HandshakeVersionContext> VersionManager::process_client_hello_version_negotiation(
    const ClientHello& client_hello,
    const std::optional<compatibility::DTLS12CompatibilityContext>& compat_context) const {
    
    HandshakeVersionContext context;
    
    // Store compatibility context if provided
    context.compat_context = compat_context;
    
    // Validate client hello versions
    auto validation_result = validate_client_hello_versions(client_hello);
    if (!validation_result.is_valid) {
        return Result<HandshakeVersionContext>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    // Extract client offered versions
    auto client_versions_result = extract_supported_versions_from_client_hello(client_hello);
    if (client_versions_result.is_success()) {
        context.client_offered_versions = client_versions_result.value();
    } else {
        // Fall back to legacy_version
        context.client_offered_versions = {static_cast<GlobalProtocolVersion>(client_hello.legacy_version())};
    }
    
    // Perform version negotiation
    GlobalProtocolVersion negotiated_version;
    if (compat_context.has_value()) {
        auto negotiation_result = negotiate_with_compatibility_context(client_hello, compat_context.value());
        if (!negotiation_result.is_success()) {
            return Result<HandshakeVersionContext>(negotiation_result.error());
        }
        negotiated_version = negotiation_result.value();
    } else {
        auto negotiation_result = negotiate_version_from_client_hello(client_hello);
        if (!negotiation_result.is_success()) {
            return Result<HandshakeVersionContext>(negotiation_result.error());
        }
        
        auto& result = negotiation_result.value();
        if (result.error_alert.has_value()) {
            return Result<HandshakeVersionContext>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
        }
        
        negotiated_version = result.negotiated_version;
        context.requires_version_downgrade = result.version_downgrade_detected;
    }
    
    context.negotiated_version = negotiated_version;
    context.version_negotiation_complete = true;
    
    return Result<HandshakeVersionContext>(std::move(context));
}

Result<void> VersionManager::apply_version_to_server_hello(ServerHello& server_hello,
                                                         const HandshakeVersionContext& context) const {
    
    if (!context.version_negotiation_complete) {
        return Result<void>(DTLSError::INVALID_STATE);
    }
    
    return prepare_server_hello(server_hello, context.negotiated_version);
}

Result<void> VersionManager::apply_version_to_hello_retry_request(HelloRetryRequest& hrr,
                                                                const HandshakeVersionContext& context) const {
    
    if (!context.version_negotiation_complete) {
        return Result<void>(DTLSError::INVALID_STATE);
    }
    
    return prepare_hello_retry_request(hrr, context.negotiated_version);
}

VersionManager::ValidationResult VersionManager::validate_handshake_version_consistency(
    const HandshakeVersionContext& context,
    const ServerHello& server_hello) const {
    
    // Validate server hello versions against negotiated context
    auto validation_result = validate_server_hello_versions(server_hello, context.client_offered_versions);
    if (!validation_result.is_valid) {
        return validation_result;
    }
    
    // Extract actual server version
    GlobalProtocolVersion server_version = static_cast<GlobalProtocolVersion>(server_hello.legacy_version());
    if (server_hello.has_extension(ExtensionType::SUPPORTED_VERSIONS)) {
        auto ext = server_hello.get_extension(ExtensionType::SUPPORTED_VERSIONS);
        if (ext.has_value()) {
            auto parsed_versions = parse_supported_versions_extension(ext.value());
            if (parsed_versions.is_success() && !parsed_versions.value().empty()) {
                server_version = parsed_versions.value().front();
            }
        }
    }
    
    // Check consistency with negotiated version
    if (server_version != context.negotiated_version) {
        return ValidationResult(AlertDescription::INTERNAL_ERROR,
                              "Server version inconsistent with negotiated version");
    }
    
    return ValidationResult(true);
}

Result<Extension> VersionManager::create_supported_versions_extension() const {
    return version_utils::create_supported_versions_extension(config_.supported_versions);
}

Result<std::vector<GlobalProtocolVersion>> VersionManager::parse_supported_versions_extension(
    const Extension& ext) const {
    return version_utils::parse_supported_versions_extension(ext);
}

bool VersionManager::is_valid_version_combination(const std::vector<GlobalProtocolVersion>& versions) const {
    for (auto version : versions) {
        if (!is_version_valid(version)) {
            return false;
        }
    }
    return !versions.empty();
}

GlobalProtocolVersion VersionManager::select_best_version(const std::vector<GlobalProtocolVersion>& client_versions,
                                                   const std::vector<GlobalProtocolVersion>& server_versions) const {
    // Find highest mutually supported version
    GlobalProtocolVersion best_version = static_cast<GlobalProtocolVersion>(0);
    
    for (auto server_ver : server_versions) {
        for (auto client_ver : client_versions) {
            if (server_ver == client_ver) {
                if (best_version == static_cast<GlobalProtocolVersion>(0) || is_version_higher(server_ver, best_version)) {
                    best_version = server_ver;
                }
            }
        }
    }
    
    return best_version;
}

void VersionManager::validate_configuration() const {
    if (config_.supported_versions.empty()) {
        throw std::invalid_argument("VersionManager: No supported versions configured");
    }
    
    if (!is_valid_version_combination(config_.supported_versions)) {
        throw std::invalid_argument("VersionManager: Invalid version combination");
    }
    
    if (!is_version_supported(config_.preferred_version)) {
        throw std::invalid_argument("VersionManager: Preferred version not in supported list");
    }
}

// Version utilities implementation
namespace version_utils {

Result<Extension> create_supported_versions_extension(const std::vector<GlobalProtocolVersion>& versions) {
    if (versions.empty()) {
        return Result<Extension>(DTLSError::INVALID_PARAMETER);
    }
    
    // Calculate buffer size: 1 byte length + 2 bytes per version
    size_t buffer_size = 1 + versions.size() * 2;
    memory::Buffer data(buffer_size);
    auto resize_result = data.resize(buffer_size);
    if (!resize_result.is_success()) {
        return Result<Extension>(resize_result.error());
    }
    
    std::byte* ptr = data.mutable_data();
    size_t offset = 0;
    
    // Length of version list
    ptr[offset++] = static_cast<std::byte>(versions.size() * 2);
    
    // Version list
    for (GlobalProtocolVersion version : versions) {
        uint16_t version_net = htons(static_cast<uint16_t>(version));
        std::memcpy(ptr + offset, &version_net, 2);
        offset += 2;
    }
    
    return Result<Extension>(Extension(ExtensionType::SUPPORTED_VERSIONS, std::move(data)));
}

Result<std::vector<GlobalProtocolVersion>> parse_supported_versions_extension(const Extension& extension) {
    if (extension.type != ExtensionType::SUPPORTED_VERSIONS) {
        return Result<std::vector<GlobalProtocolVersion>>(DTLSError::UNSUPPORTED_EXTENSION);
    }
    
    const auto& data = extension.data;
    if (data.size() < 1) {
        return Result<std::vector<GlobalProtocolVersion>>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = data.data();
    size_t offset = 0;
    
    // Read length
    uint8_t length = static_cast<uint8_t>(ptr[offset++]);
    
    // Validate length
    if (length % 2 != 0 || offset + length > data.size()) {
        return Result<std::vector<GlobalProtocolVersion>>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    // Parse versions
    std::vector<GlobalProtocolVersion> versions;
    size_t num_versions = length / 2;
    versions.reserve(num_versions);
    
    for (size_t i = 0; i < num_versions; ++i) {
        if (offset + 2 > data.size()) {
            return Result<std::vector<GlobalProtocolVersion>>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
        }
        
        uint16_t version_net;
        std::memcpy(&version_net, ptr + offset, 2);
        GlobalProtocolVersion version = static_cast<GlobalProtocolVersion>(ntohs(version_net));
        versions.push_back(version);
        offset += 2;
    }
    
    return Result<std::vector<GlobalProtocolVersion>>(std::move(versions));
}

bool is_supported_versions_extension(const Extension& extension) {
    return extension.type == ExtensionType::SUPPORTED_VERSIONS;
}

bool validate_supported_versions_extension(const Extension& extension) {
    if (!dtls::v13::protocol::is_supported_versions_extension(extension)) {
        return false;
    }
    
    // Use the local parse_supported_versions_extension function (in version_utils namespace)
    auto parse_result = dtls::v13::protocol::version_utils::parse_supported_versions_extension(extension);
    return parse_result.is_success() && !parse_result.value().empty();
}

GlobalProtocolVersion get_legacy_version_for_hello(GlobalProtocolVersion actual_version) {
    // RFC 9147: For DTLS 1.3, legacy_version should be DTLS 1.2
    if (actual_version == dtls::v13::DTLS_V13) {
        return constants::DEFAULT_LEGACY_VERSION;
    }
    
    // For other versions, use the actual version
    return actual_version;
}

} // namespace version_utils

} // namespace dtls::v13::protocol