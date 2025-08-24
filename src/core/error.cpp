#include <dtls/error.h>
#include <dtls/types.h>
#include <unordered_map>

namespace dtls {
namespace v13 {

// Error message mapping
std::string DTLSErrorCategory::message(int ev) const {
    DTLSError error = static_cast<DTLSError>(ev);
    
    static const std::unordered_map<DTLSError, std::string> error_messages = {
        // General errors (1-19)
        {DTLSError::SUCCESS, "Success"},
        {DTLSError::INVALID_PARAMETER, "Invalid parameter provided"},
        {DTLSError::INSUFFICIENT_BUFFER, "Buffer too small for operation"},
        {DTLSError::OUT_OF_MEMORY, "Memory allocation failed"},
        {DTLSError::TIMEOUT, "Operation timed out"},
        {DTLSError::OPERATION_ABORTED, "Operation was aborted"},
        {DTLSError::NOT_INITIALIZED, "Component not initialized"},
        {DTLSError::ALREADY_INITIALIZED, "Component already initialized"},
        {DTLSError::RESOURCE_UNAVAILABLE, "Required resource not available"},
        {DTLSError::OPERATION_NOT_SUPPORTED, "Operation not supported"},
        {DTLSError::INTERNAL_ERROR, "Internal implementation error"},
        
        // Protocol errors (20-49)
        {DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED, "DTLS protocol version not supported"},
        {DTLSError::INVALID_MESSAGE_FORMAT, "Invalid message format"},
        {DTLSError::UNEXPECTED_MESSAGE, "Unexpected message type"},
        {DTLSError::MESSAGE_TOO_LARGE, "Message exceeds maximum size"},
        {DTLSError::SEQUENCE_NUMBER_OVERFLOW, "Sequence number overflow"},
        {DTLSError::EPOCH_MISMATCH, "Epoch mismatch in record"},
        {DTLSError::RECORD_OVERFLOW, "Record size overflow"},
        {DTLSError::FRAGMENTATION_ERROR, "Message fragmentation error"},
        {DTLSError::EXTENSION_ERROR, "Extension processing error"},
        {DTLSError::STATE_MACHINE_ERROR, "Invalid state for operation"},
        
        // Handshake errors (50-79)
        {DTLSError::HANDSHAKE_FAILURE, "Handshake negotiation failed"},
        {DTLSError::CERTIFICATE_VERIFY_FAILED, "Certificate verification failed"},
        {DTLSError::CERTIFICATE_EXPIRED, "Certificate has expired"},
        {DTLSError::CERTIFICATE_REVOKED, "Certificate has been revoked"},
        {DTLSError::CERTIFICATE_UNKNOWN, "Unknown certificate error"},
        {DTLSError::UNKNOWN_CA, "Unknown certificate authority"},
        {DTLSError::ACCESS_DENIED, "Access denied"},
        {DTLSError::DECODE_ERROR, "Message decode error"},
        {DTLSError::ILLEGAL_PARAMETER, "Illegal parameter in message"},
        {DTLSError::MISSING_EXTENSION, "Required extension missing"},
        {DTLSError::UNSUPPORTED_EXTENSION, "Unsupported extension"},
        {DTLSError::UNRECOGNIZED_NAME, "Unrecognized server name"},
        {DTLSError::BAD_CERTIFICATE_STATUS_RESPONSE, "Bad certificate status response"},
        {DTLSError::CERTIFICATE_REQUIRED, "Certificate required but not provided"},
        {DTLSError::NO_APPLICATION_PROTOCOL, "No application protocol agreement"},
        
        // Cryptographic errors (80-109)
        {DTLSError::DECRYPT_ERROR, "Decryption failed"},
        {DTLSError::BAD_RECORD_MAC, "Record MAC verification failed"},
        {DTLSError::KEY_DERIVATION_FAILED, "Key derivation failed"},
        {DTLSError::SIGNATURE_VERIFICATION_FAILED, "Digital signature verification failed"},
        {DTLSError::CIPHER_SUITE_NOT_SUPPORTED, "Cipher suite not supported"},
        {DTLSError::CRYPTO_PROVIDER_ERROR, "Cryptographic provider error"},
        {DTLSError::RANDOM_GENERATION_FAILED, "Random number generation failed"},
        {DTLSError::KEY_EXCHANGE_FAILED, "Key exchange failed"},
        {DTLSError::INSUFFICIENT_SECURITY, "Insufficient security level"},
        {DTLSError::CRYPTO_HARDWARE_ERROR, "Cryptographic hardware error"},
        
        // Connection errors (110-129)
        {DTLSError::CONNECTION_CLOSED, "Connection closed by peer"},
        {DTLSError::CONNECTION_RESET, "Connection reset"},
        {DTLSError::CONNECTION_REFUSED, "Connection refused"},
        {DTLSError::CONNECTION_TIMEOUT, "Connection timeout"},
        {DTLSError::CONNECTION_ID_MISMATCH, "Connection ID mismatch"},
        {DTLSError::CONNECTION_MIGRATION_FAILED, "Connection migration failed"},
        {DTLSError::MAX_CONNECTIONS_EXCEEDED, "Maximum connections exceeded"},
        {DTLSError::CONNECTION_NOT_FOUND, "Connection not found"},
        {DTLSError::DUPLICATE_CONNECTION, "Duplicate connection attempt"},
        {DTLSError::CONNECTION_STATE_ERROR, "Invalid connection state"},
        
        // Network errors (130-149)
        {DTLSError::NETWORK_ERROR, "Network error"},
        {DTLSError::ADDRESS_RESOLUTION_FAILED, "Address resolution failed"},
        {DTLSError::SOCKET_ERROR, "Socket operation failed"},
        {DTLSError::SEND_ERROR, "Send operation failed"},
        {DTLSError::RECEIVE_ERROR, "Receive operation failed"},
        {DTLSError::NETWORK_UNREACHABLE, "Network unreachable"},
        {DTLSError::HOST_UNREACHABLE, "Host unreachable"},
        {DTLSError::PORT_UNREACHABLE, "Port unreachable"},
        {DTLSError::NETWORK_DOWN, "Network interface down"},
        {DTLSError::MTU_EXCEEDED, "Maximum transmission unit exceeded"},
        
        // Security errors (150-169)
        {DTLSError::REPLAY_ATTACK_DETECTED, "Replay attack detected"},
        {DTLSError::TAMPERING_DETECTED, "Message tampering detected"},
        {DTLSError::SECURITY_POLICY_VIOLATION, "Security policy violation"},
        {DTLSError::AUTHENTICATION_FAILED, "Authentication failed"},
        {DTLSError::AUTHORIZATION_FAILED, "Authorization failed"},
        {DTLSError::UNKNOWN_PSK_IDENTITY, "Unknown PSK identity"},
        {DTLSError::PSK_IDENTITY_REQUIRED, "PSK identity required"},
        {DTLSError::EARLY_DATA_REJECTED, "Early data rejected"},
        {DTLSError::CERTIFICATE_TRANSPARENCY_ERROR, "Certificate transparency error"},
        {DTLSError::OCSP_ERROR, "OCSP validation error"},
        
        // Configuration errors (170-189)
        {DTLSError::INVALID_CONFIGURATION, "Invalid configuration"},
        {DTLSError::MISSING_CONFIGURATION, "Missing required configuration"},
        {DTLSError::CONFIGURATION_CONFLICT, "Configuration conflict"},
        {DTLSError::FEATURE_NOT_ENABLED, "Feature not enabled"},
        {DTLSError::QUOTA_EXCEEDED, "Resource quota exceeded"},
        {DTLSError::POLICY_VIOLATION, "Policy violation"},
        {DTLSError::LICENSE_ERROR, "License validation error"},
        {DTLSError::VERSION_MISMATCH, "Version mismatch"},
        {DTLSError::COMPATIBILITY_ERROR, "Compatibility error"},
        {DTLSError::DEPENDENCY_ERROR, "Dependency error"},
        
        // User errors (190-199)
        {DTLSError::USER_CANCELED, "Operation canceled by user"},
        {DTLSError::USER_INTERVENTION_REQUIRED, "User intervention required"},
        {DTLSError::PERMISSION_DENIED, "Permission denied"},
        {DTLSError::QUOTA_EXHAUSTED, "User quota exhausted"},
        {DTLSError::RATE_LIMITED, "Rate limit exceeded"},
        {DTLSError::SERVICE_UNAVAILABLE, "Service temporarily unavailable"},
        {DTLSError::MAINTENANCE_MODE, "System in maintenance mode"},
        {DTLSError::DEPRECATED_FEATURE, "Feature is deprecated"},
        {DTLSError::TRIAL_EXPIRED, "Trial period expired"},
        {DTLSError::ACCOUNT_SUSPENDED, "Account suspended"}
    };
    
    auto it = error_messages.find(error);
    if (it != error_messages.end()) {
        return it->second;
    }
    
    return "Unknown DTLS error (" + std::to_string(ev) + ")";
}

bool DTLSErrorCategory::equivalent(const std::error_code& code, int condition) const noexcept {
    // Only consider equivalent if both the category and value match
    return (code.category() == *this) && (code.value() == condition);
}

// Utility functions
std::string error_message(DTLSError error) {
    return DTLSErrorCategory::instance().message(static_cast<int>(error));
}

bool is_fatal_error(DTLSError error) {
    // Determine if an error is fatal and should terminate the connection
    switch (error) {
        // Non-fatal errors that allow retry or recovery
        case DTLSError::SUCCESS:
        case DTLSError::TIMEOUT:
        case DTLSError::OPERATION_ABORTED:
        case DTLSError::RESOURCE_UNAVAILABLE:
        case DTLSError::CONNECTION_TIMEOUT:
        case DTLSError::NETWORK_UNREACHABLE:
        case DTLSError::HOST_UNREACHABLE:
        case DTLSError::PORT_UNREACHABLE:
        case DTLSError::USER_CANCELED:
        case DTLSError::RATE_LIMITED:
        case DTLSError::SERVICE_UNAVAILABLE:
        case DTLSError::MAINTENANCE_MODE:
        // RFC 9147: Invalid records should be silently discarded (non-fatal)
        case DTLSError::INVALID_RECORD_HEADER:
            return false;
            
        // Fatal errors that require connection termination
        case DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED:
        case DTLSError::HANDSHAKE_FAILURE:
        case DTLSError::CERTIFICATE_VERIFY_FAILED:
        case DTLSError::CERTIFICATE_EXPIRED:
        case DTLSError::CERTIFICATE_REVOKED:
        case DTLSError::UNKNOWN_CA:
        case DTLSError::ACCESS_DENIED:
        case DTLSError::DECODE_ERROR:
        case DTLSError::ILLEGAL_PARAMETER:
        case DTLSError::DECRYPT_ERROR:
        case DTLSError::BAD_RECORD_MAC:
        case DTLSError::SIGNATURE_VERIFICATION_FAILED:
        case DTLSError::CIPHER_SUITE_NOT_SUPPORTED:
        case DTLSError::KEY_EXCHANGE_FAILED:
        case DTLSError::INSUFFICIENT_SECURITY:
        case DTLSError::REPLAY_ATTACK_DETECTED:
        case DTLSError::TAMPERING_DETECTED:
        case DTLSError::SECURITY_POLICY_VIOLATION:
        case DTLSError::AUTHENTICATION_FAILED:
        case DTLSError::AUTHORIZATION_FAILED:
        case DTLSError::PERMISSION_DENIED:
            return true;
            
        default:
            // Conservative approach: treat unknown errors as fatal
            return true;
    }
}

bool is_retryable_error(DTLSError error) {
    // Determine if an operation can be retried after this error
    switch (error) {
        // Retryable errors
        case DTLSError::TIMEOUT:
        case DTLSError::RESOURCE_UNAVAILABLE:
        case DTLSError::CONNECTION_TIMEOUT:
        case DTLSError::NETWORK_ERROR:
        case DTLSError::SOCKET_ERROR:
        case DTLSError::SEND_ERROR:
        case DTLSError::RECEIVE_ERROR:
        case DTLSError::NETWORK_UNREACHABLE:
        case DTLSError::HOST_UNREACHABLE:
        case DTLSError::NETWORK_DOWN:
        case DTLSError::RATE_LIMITED:
        case DTLSError::SERVICE_UNAVAILABLE:
        case DTLSError::MAINTENANCE_MODE:
            return true;
            
        // Non-retryable errors
        case DTLSError::INVALID_PARAMETER:
        case DTLSError::OUT_OF_MEMORY:
        case DTLSError::ALREADY_INITIALIZED:
        case DTLSError::OPERATION_NOT_SUPPORTED:
        case DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED:
        case DTLSError::INVALID_MESSAGE_FORMAT:
        case DTLSError::HANDSHAKE_FAILURE:
        case DTLSError::CERTIFICATE_VERIFY_FAILED:
        case DTLSError::CERTIFICATE_EXPIRED:
        case DTLSError::CERTIFICATE_REVOKED:
        case DTLSError::UNKNOWN_CA:
        case DTLSError::ACCESS_DENIED:
        case DTLSError::DECODE_ERROR:
        case DTLSError::ILLEGAL_PARAMETER:
        case DTLSError::DECRYPT_ERROR:
        case DTLSError::BAD_RECORD_MAC:
        case DTLSError::SIGNATURE_VERIFICATION_FAILED:
        case DTLSError::CIPHER_SUITE_NOT_SUPPORTED:
        case DTLSError::INSUFFICIENT_SECURITY:
        case DTLSError::CONNECTION_CLOSED:
        case DTLSError::CONNECTION_RESET:
        case DTLSError::CONNECTION_REFUSED:
        case DTLSError::REPLAY_ATTACK_DETECTED:
        case DTLSError::TAMPERING_DETECTED:
        case DTLSError::AUTHENTICATION_FAILED:
        case DTLSError::AUTHORIZATION_FAILED:
        case DTLSError::PERMISSION_DENIED:
        case DTLSError::USER_CANCELED:
            return false;
            
        default:
            // Conservative approach: don't retry unknown errors
            return false;
    }
}

AlertDescription error_to_alert(DTLSError error) {
    // Map DTLS errors to appropriate alert descriptions
    static const std::unordered_map<DTLSError, AlertDescription> error_to_alert_map = {
        {DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED, AlertDescription::PROTOCOL_VERSION},
        {DTLSError::INVALID_MESSAGE_FORMAT, AlertDescription::DECODE_ERROR},
        {DTLSError::UNEXPECTED_MESSAGE, AlertDescription::UNEXPECTED_MESSAGE},
        {DTLSError::MESSAGE_TOO_LARGE, AlertDescription::RECORD_OVERFLOW},
        {DTLSError::RECORD_OVERFLOW, AlertDescription::RECORD_OVERFLOW},
        {DTLSError::HANDSHAKE_FAILURE, AlertDescription::HANDSHAKE_FAILURE},
        {DTLSError::CERTIFICATE_VERIFY_FAILED, AlertDescription::BAD_CERTIFICATE},
        {DTLSError::CERTIFICATE_EXPIRED, AlertDescription::CERTIFICATE_EXPIRED},
        {DTLSError::CERTIFICATE_REVOKED, AlertDescription::CERTIFICATE_REVOKED},
        {DTLSError::CERTIFICATE_UNKNOWN, AlertDescription::CERTIFICATE_UNKNOWN},
        {DTLSError::UNKNOWN_CA, AlertDescription::UNKNOWN_CA},
        {DTLSError::ACCESS_DENIED, AlertDescription::ACCESS_DENIED},
        {DTLSError::DECODE_ERROR, AlertDescription::DECODE_ERROR},
        {DTLSError::ILLEGAL_PARAMETER, AlertDescription::ILLEGAL_PARAMETER},
        {DTLSError::MISSING_EXTENSION, AlertDescription::MISSING_EXTENSION},
        {DTLSError::UNSUPPORTED_EXTENSION, AlertDescription::UNSUPPORTED_EXTENSION},
        {DTLSError::UNRECOGNIZED_NAME, AlertDescription::UNRECOGNIZED_NAME},
        {DTLSError::BAD_CERTIFICATE_STATUS_RESPONSE, AlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE},
        {DTLSError::CERTIFICATE_REQUIRED, AlertDescription::CERTIFICATE_REQUIRED},
        {DTLSError::NO_APPLICATION_PROTOCOL, AlertDescription::NO_APPLICATION_PROTOCOL},
        {DTLSError::DECRYPT_ERROR, AlertDescription::DECRYPT_ERROR},
        {DTLSError::BAD_RECORD_MAC, AlertDescription::BAD_RECORD_MAC},
        {DTLSError::INSUFFICIENT_SECURITY, AlertDescription::INSUFFICIENT_SECURITY},
        {DTLSError::INTERNAL_ERROR, AlertDescription::INTERNAL_ERROR},
        {DTLSError::USER_CANCELED, AlertDescription::USER_CANCELED},
        {DTLSError::UNKNOWN_PSK_IDENTITY, AlertDescription::UNKNOWN_PSK_IDENTITY},
        // Additional DTLS v1.3 mappings (RFC 9147)
        {DTLSError::CONNECTION_ID_MISMATCH, AlertDescription::TOO_MANY_CIDS_REQUESTED}
    };
    
    auto it = error_to_alert_map.find(error);
    if (it != error_to_alert_map.end()) {
        return it->second;
    }
    
    // Default to internal error for unmapped errors
    return AlertDescription::INTERNAL_ERROR;
}

DTLSError alert_to_error(AlertDescription alert) {
    // Map alert descriptions to DTLS errors
    static const std::unordered_map<AlertDescription, DTLSError> alert_to_error_map = {
        {AlertDescription::UNEXPECTED_MESSAGE, DTLSError::UNEXPECTED_MESSAGE},
        {AlertDescription::BAD_RECORD_MAC, DTLSError::BAD_RECORD_MAC},
        {AlertDescription::RECORD_OVERFLOW, DTLSError::RECORD_OVERFLOW},
        {AlertDescription::HANDSHAKE_FAILURE, DTLSError::HANDSHAKE_FAILURE},
        {AlertDescription::BAD_CERTIFICATE, DTLSError::CERTIFICATE_VERIFY_FAILED},
        {AlertDescription::UNSUPPORTED_CERTIFICATE, DTLSError::CERTIFICATE_VERIFY_FAILED},
        {AlertDescription::CERTIFICATE_REVOKED, DTLSError::CERTIFICATE_REVOKED},
        {AlertDescription::CERTIFICATE_EXPIRED, DTLSError::CERTIFICATE_EXPIRED},
        {AlertDescription::CERTIFICATE_UNKNOWN, DTLSError::CERTIFICATE_UNKNOWN},
        {AlertDescription::ILLEGAL_PARAMETER, DTLSError::ILLEGAL_PARAMETER},
        {AlertDescription::UNKNOWN_CA, DTLSError::UNKNOWN_CA},
        {AlertDescription::ACCESS_DENIED, DTLSError::ACCESS_DENIED},
        {AlertDescription::DECODE_ERROR, DTLSError::DECODE_ERROR},
        {AlertDescription::DECRYPT_ERROR, DTLSError::DECRYPT_ERROR},
        {AlertDescription::PROTOCOL_VERSION, DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED},
        {AlertDescription::INSUFFICIENT_SECURITY, DTLSError::INSUFFICIENT_SECURITY},
        {AlertDescription::INTERNAL_ERROR, DTLSError::INTERNAL_ERROR},
        {AlertDescription::USER_CANCELED, DTLSError::USER_CANCELED},
        {AlertDescription::MISSING_EXTENSION, DTLSError::MISSING_EXTENSION},
        {AlertDescription::UNSUPPORTED_EXTENSION, DTLSError::UNSUPPORTED_EXTENSION},
        {AlertDescription::UNRECOGNIZED_NAME, DTLSError::UNRECOGNIZED_NAME},
        {AlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE, DTLSError::BAD_CERTIFICATE_STATUS_RESPONSE},
        {AlertDescription::UNKNOWN_PSK_IDENTITY, DTLSError::UNKNOWN_PSK_IDENTITY},
        {AlertDescription::CERTIFICATE_REQUIRED, DTLSError::CERTIFICATE_REQUIRED},
        {AlertDescription::NO_APPLICATION_PROTOCOL, DTLSError::NO_APPLICATION_PROTOCOL},
        // Additional DTLS v1.3 reverse mappings (RFC 9147)
        {AlertDescription::TOO_MANY_CIDS_REQUESTED, DTLSError::CONNECTION_ID_MISMATCH},
        // Connection management alerts
        {AlertDescription::CLOSE_NOTIFY, DTLSError::CONNECTION_CLOSED}
    };
    
    auto it = alert_to_error_map.find(alert);
    if (it != alert_to_error_map.end()) {
        return it->second;
    }
    
    // Default to internal error for unmapped alerts
    return DTLSError::INTERNAL_ERROR;
}

} // namespace v13
} // namespace dtls