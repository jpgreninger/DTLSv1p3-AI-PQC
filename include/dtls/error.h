#ifndef DTLS_ERROR_H
#define DTLS_ERROR_H

#include <dtls/config.h>
#include <system_error>
#include <string>

namespace dtls {
namespace v13 {

// DTLS-specific error codes
enum class DTLSError : int {
    SUCCESS = 0,
    
    // General errors (1-19)
    INVALID_PARAMETER = 1,
    INSUFFICIENT_BUFFER = 2,  
    OUT_OF_MEMORY = 3,
    TIMEOUT = 4,
    OPERATION_ABORTED = 5,
    NOT_INITIALIZED = 6,
    ALREADY_INITIALIZED = 7,
    RESOURCE_UNAVAILABLE = 8,
    OPERATION_NOT_SUPPORTED = 9,
    INTERNAL_ERROR = 10,
    
    // Protocol errors (20-49)
    PROTOCOL_VERSION_NOT_SUPPORTED = 20,
    INVALID_MESSAGE_FORMAT = 21,
    UNEXPECTED_MESSAGE = 22,
    MESSAGE_TOO_LARGE = 23,
    SEQUENCE_NUMBER_OVERFLOW = 24,
    EPOCH_MISMATCH = 25,
    RECORD_OVERFLOW = 26,
    FRAGMENTATION_ERROR = 27,
    EXTENSION_ERROR = 28,
    STATE_MACHINE_ERROR = 29,
    
    // Record layer errors (30-39)
    INVALID_RECORD_HEADER = 30,
    INVALID_PLAINTEXT_RECORD = 31,
    INVALID_CIPHERTEXT_RECORD = 32,
    INSUFFICIENT_BUFFER_SIZE = 33,
    INVALID_CONTENT_TYPE = 34,
    RECORD_LENGTH_MISMATCH = 35,
    UNSUPPORTED_RECORD_VERSION = 36,
    
    // Handshake errors (50-79)
    HANDSHAKE_FAILURE = 50,
    CERTIFICATE_VERIFY_FAILED = 51,
    CERTIFICATE_EXPIRED = 52,
    CERTIFICATE_REVOKED = 53,
    CERTIFICATE_UNKNOWN = 54,
    UNKNOWN_CA = 55,
    ACCESS_DENIED = 56,
    DECODE_ERROR = 57,
    ILLEGAL_PARAMETER = 58,
    MISSING_EXTENSION = 59,
    UNSUPPORTED_EXTENSION = 60,
    UNRECOGNIZED_NAME = 61,
    BAD_CERTIFICATE_STATUS_RESPONSE = 62,
    CERTIFICATE_REQUIRED = 63,
    NO_APPLICATION_PROTOCOL = 64,
    UNSUPPORTED_HANDSHAKE_TYPE = 65,
    
    // Message layer errors (66-79)
    INVALID_MESSAGE_FRAGMENT = 66,
    FRAGMENT_LENGTH_MISMATCH = 67,
    OVERLAPPING_FRAGMENT = 68,
    MESSAGE_NOT_COMPLETE = 69,
    SERIALIZATION_FAILED = 70,
    FLIGHT_IN_PROGRESS = 71,
    NO_CURRENT_FLIGHT = 72,
    INCOMPLETE_FLIGHT = 73,
    INVALID_FLIGHT = 74,
    RECORD_LAYER_NOT_AVAILABLE = 75,
    CRYPTO_PROVIDER_NOT_AVAILABLE = 76,
    EPOCH_NOT_FOUND = 77,
    EPOCH_OVERFLOW = 78,
    INVALID_CONNECTION_ID = 79,
    
    // Additional error codes
    INVALID_KEY_MATERIAL = 80,
    INVALID_IV_SIZE = 81,
    INITIALIZATION_FAILED = 82,
    
    // Cryptographic errors (90-109)  
    DECRYPT_ERROR = 90,
    BAD_RECORD_MAC = 91,
    KEY_DERIVATION_FAILED = 92,
    SIGNATURE_VERIFICATION_FAILED = 93,
    CIPHER_SUITE_NOT_SUPPORTED = 94,
    CRYPTO_PROVIDER_ERROR = 95,
    RANDOM_GENERATION_FAILED = 96,
    KEY_EXCHANGE_FAILED = 97,
    INSUFFICIENT_SECURITY = 98,
    CRYPTO_HARDWARE_ERROR = 99,
    
    // Connection errors (110-129)
    CONNECTION_CLOSED = 110,
    CONNECTION_RESET = 111,
    CONNECTION_REFUSED = 112,
    CONNECTION_TIMEOUT = 113,
    CONNECTION_ID_MISMATCH = 114,
    CONNECTION_MIGRATION_FAILED = 115,
    MAX_CONNECTIONS_EXCEEDED = 116,
    CONNECTION_NOT_FOUND = 117,
    DUPLICATE_CONNECTION = 118,
    CONNECTION_STATE_ERROR = 119,
    
    // Network errors (130-149)
    NETWORK_ERROR = 130,
    ADDRESS_RESOLUTION_FAILED = 131,
    SOCKET_ERROR = 132,
    SEND_ERROR = 133,
    RECEIVE_ERROR = 134,
    NETWORK_UNREACHABLE = 135,
    HOST_UNREACHABLE = 136,
    PORT_UNREACHABLE = 137,
    NETWORK_DOWN = 138,
    MTU_EXCEEDED = 139,
    
    // Security errors (150-169)
    REPLAY_ATTACK_DETECTED = 150,
    TAMPERING_DETECTED = 151,
    SECURITY_POLICY_VIOLATION = 152,
    AUTHENTICATION_FAILED = 153,
    AUTHORIZATION_FAILED = 154,
    UNKNOWN_PSK_IDENTITY = 155,
    PSK_IDENTITY_REQUIRED = 156,
    EARLY_DATA_REJECTED = 157,
    CERTIFICATE_TRANSPARENCY_ERROR = 158,
    OCSP_ERROR = 159,
    
    // Configuration errors (170-189)
    INVALID_CONFIGURATION = 170,
    MISSING_CONFIGURATION = 171,
    CONFIGURATION_CONFLICT = 172,
    FEATURE_NOT_ENABLED = 173,
    QUOTA_EXCEEDED = 174,
    POLICY_VIOLATION = 175,
    LICENSE_ERROR = 176,
    VERSION_MISMATCH = 177,
    COMPATIBILITY_ERROR = 178,
    DEPENDENCY_ERROR = 179,
    
    // User errors (190-199)
    USER_CANCELED = 190,
    USER_INTERVENTION_REQUIRED = 191,
    PERMISSION_DENIED = 192,
    QUOTA_EXHAUSTED = 193,
    RATE_LIMITED = 194,
    SERVICE_UNAVAILABLE = 195,
    MAINTENANCE_MODE = 196,
    DEPRECATED_FEATURE = 197,
    TRIAL_EXPIRED = 198,
    ACCOUNT_SUSPENDED = 199
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