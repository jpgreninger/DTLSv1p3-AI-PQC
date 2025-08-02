#ifndef DTLS_ERROR_H
#define DTLS_ERROR_H

#include <dtls/config.h>
#include <system_error>
#include <string>
#include <cstdint>

// Forward declaration to avoid circular includes  
namespace dtls { namespace v13 { enum class AlertDescription : std::uint8_t; } }

namespace dtls {
namespace v13 {

// DTLS-specific error codes
enum class DTLSError : int {
    SUCCESS = 0,
    
    // General errors (1-19)
    INVALID_PARAMETER = 1,
    INSUFFICIENT_BUFFER = 2,  
    BUFFER_TOO_SMALL = 3,
    OUT_OF_MEMORY = 4,
    TIMEOUT = 5,
    OPERATION_ABORTED = 6,
    NOT_INITIALIZED = 7,
    ALREADY_INITIALIZED = 8,
    RESOURCE_UNAVAILABLE = 9,
    OPERATION_NOT_SUPPORTED = 10,
    INTERNAL_ERROR = 11,
    
    // Protocol errors (20-49)
    PROTOCOL_VERSION_NOT_SUPPORTED = 21,
    INVALID_MESSAGE_FORMAT = 22,
    UNEXPECTED_MESSAGE = 23,
    MESSAGE_TOO_LARGE = 24,
    SEQUENCE_NUMBER_OVERFLOW = 25,
    EPOCH_MISMATCH = 26,
    RECORD_OVERFLOW = 27,
    FRAGMENTATION_ERROR = 28,
    EXTENSION_ERROR = 29,
    STATE_MACHINE_ERROR = 30,
    
    // Record layer errors (31-40)
    INVALID_RECORD_HEADER = 31,
    INVALID_PLAINTEXT_RECORD = 32,
    INVALID_CIPHERTEXT_RECORD = 33,
    INSUFFICIENT_BUFFER_SIZE = 34,
    INVALID_CONTENT_TYPE = 35,
    RECORD_LENGTH_MISMATCH = 36,
    UNSUPPORTED_RECORD_VERSION = 37,
    
    // Handshake errors (51-80)
    HANDSHAKE_FAILURE = 51,
    CERTIFICATE_VERIFY_FAILED = 52,
    CERTIFICATE_EXPIRED = 53,
    CERTIFICATE_REVOKED = 54,
    CERTIFICATE_UNKNOWN = 55,
    UNKNOWN_CA = 56,
    ACCESS_DENIED = 57,
    DECODE_ERROR = 58,
    ILLEGAL_PARAMETER = 59,
    MISSING_EXTENSION = 60,
    UNSUPPORTED_EXTENSION = 61,
    UNRECOGNIZED_NAME = 62,
    BAD_CERTIFICATE_STATUS_RESPONSE = 63,
    CERTIFICATE_REQUIRED = 64,
    NO_APPLICATION_PROTOCOL = 65,
    UNSUPPORTED_HANDSHAKE_TYPE = 66,
    INVALID_STATE = 67,
    RESOURCE_EXHAUSTED = 68,
    HANDSHAKE_TIMEOUT = 69,
    
    // Message layer errors (70-90)
    INVALID_MESSAGE_FRAGMENT = 70,
    FRAGMENT_LENGTH_MISMATCH = 71,
    OVERLAPPING_FRAGMENT = 72,
    MESSAGE_NOT_COMPLETE = 73,
    SERIALIZATION_FAILED = 74,
    FLIGHT_IN_PROGRESS = 75,
    NO_CURRENT_FLIGHT = 76,
    INCOMPLETE_FLIGHT = 77,
    INVALID_FLIGHT = 78,
    RECORD_LAYER_NOT_AVAILABLE = 79,
    CRYPTO_PROVIDER_NOT_AVAILABLE = 80,
    EPOCH_NOT_FOUND = 81,
    EPOCH_OVERFLOW = 82,
    INVALID_EPOCH = 83,
    INVALID_CONNECTION_ID = 84,
    
    // Additional error codes
    INVALID_KEY_MATERIAL = 85,
    INVALID_IV_SIZE = 86,
    INITIALIZATION_FAILED = 87,
    
    // Cryptographic errors (92-111)  
    DECRYPT_ERROR = 92,
    BAD_RECORD_MAC = 93,
    KEY_DERIVATION_FAILED = 94,
    SIGNATURE_VERIFICATION_FAILED = 95,
    CIPHER_SUITE_NOT_SUPPORTED = 96,
    CRYPTO_PROVIDER_ERROR = 97,
    RANDOM_GENERATION_FAILED = 98,
    KEY_EXCHANGE_FAILED = 99,
    INSUFFICIENT_SECURITY = 100,
    CRYPTO_HARDWARE_ERROR = 101,
    
    // Connection errors (112-131)
    CONNECTION_CLOSED = 112,
    CONNECTION_RESET = 113,
    CONNECTION_REFUSED = 114,
    CONNECTION_TIMEOUT = 115,
    CONNECTION_ID_MISMATCH = 116,
    CONNECTION_MIGRATION_FAILED = 117,
    MAX_CONNECTIONS_EXCEEDED = 118,
    CONNECTION_NOT_FOUND = 119,
    DUPLICATE_CONNECTION = 120,
    CONNECTION_STATE_ERROR = 121,
    
    // Network errors (132-151)
    NETWORK_ERROR = 132,
    ADDRESS_RESOLUTION_FAILED = 133,
    SOCKET_ERROR = 134,
    SEND_ERROR = 135,
    RECEIVE_ERROR = 136,
    NETWORK_UNREACHABLE = 137,
    HOST_UNREACHABLE = 138,
    PORT_UNREACHABLE = 139,
    NETWORK_DOWN = 140,
    MTU_EXCEEDED = 141,
    TRANSPORT_ERROR = 142,
    
    // Security errors (152-171)
    REPLAY_ATTACK_DETECTED = 152,
    TAMPERING_DETECTED = 153,
    SECURITY_POLICY_VIOLATION = 154,
    AUTHENTICATION_FAILED = 155,
    AUTHORIZATION_FAILED = 156,
    UNKNOWN_PSK_IDENTITY = 157,
    PSK_IDENTITY_REQUIRED = 158,
    EARLY_DATA_REJECTED = 159,
    CERTIFICATE_TRANSPARENCY_ERROR = 160,
    OCSP_ERROR = 161,
    
    // Configuration errors (172-191)
    INVALID_CONFIGURATION = 172,
    MISSING_CONFIGURATION = 173,
    CONFIGURATION_CONFLICT = 174,
    FEATURE_NOT_ENABLED = 175,
    QUOTA_EXCEEDED = 176,
    POLICY_VIOLATION = 177,
    LICENSE_ERROR = 178,
    VERSION_MISMATCH = 179,
    COMPATIBILITY_ERROR = 180,
    DEPENDENCY_ERROR = 181,
    
    // User errors (192-201)
    USER_CANCELED = 192,
    USER_INTERVENTION_REQUIRED = 193,
    PERMISSION_DENIED = 194,
    QUOTA_EXHAUSTED = 195,
    RATE_LIMITED = 196,
    SERVICE_UNAVAILABLE = 197,
    MAINTENANCE_MODE = 198,
    DEPRECATED_FEATURE = 199,
    TRIAL_EXPIRED = 200,
    ACCOUNT_SUSPENDED = 201
};

// Error category for DTLS errors
class DTLSErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "dtls";
    }
    
    std::string message(int ev) const override;
    
    bool equivalent(const std::error_code& code, int condition) const noexcept override;
    
    static const DTLSErrorCategory& instance() {
        static DTLSErrorCategory instance;
        return instance;
    }
};

// Create error code from DTLS error
inline std::error_code make_error_code(DTLSError e) {
    return std::error_code(static_cast<int>(e), DTLSErrorCategory::instance());
}

// Exception class for DTLS errors
class DTLS_API DTLSException : public std::system_error {
public:
    explicit DTLSException(DTLSError error)
        : std::system_error(make_error_code(error)) {}
    
    DTLSException(DTLSError error, const std::string& what_arg)
        : std::system_error(make_error_code(error), what_arg) {}
    
    DTLSException(DTLSError error, const char* what_arg)
        : std::system_error(make_error_code(error), what_arg) {}
    
    DTLSError dtls_error() const noexcept {
        return static_cast<DTLSError>(code().value());
    }
};

// Utility functions
DTLS_API std::string error_message(DTLSError error);
DTLS_API bool is_fatal_error(DTLSError error);
DTLS_API bool is_retryable_error(DTLSError error);
DTLS_API AlertDescription error_to_alert(DTLSError error);
DTLS_API DTLSError alert_to_error(AlertDescription alert);

// Macros for error handling
#define DTLS_THROW_IF_ERROR(error) \
    do { \
        if ((error) != DTLSError::SUCCESS) { \
            throw DTLSException((error)); \
        } \
    } while (0)

#define DTLS_RETURN_IF_ERROR(result) \
    do { \
        if (!(result).is_success()) { \
            return (result).error(); \
        } \
    } while (0)

} // namespace v13
} // namespace dtls

// Make DTLSError compatible with std::error_code
namespace std {
template<>
struct is_error_code_enum<dtls::v13::DTLSError> : true_type {};
}

#endif // DTLS_ERROR_H