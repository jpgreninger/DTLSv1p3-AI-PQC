#ifndef DTLS_TYPES_H
#define DTLS_TYPES_H

#include <dtls/config.h>
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <chrono>
#include <optional>

namespace dtls {
namespace v13 {

// Basic protocol types
using ProtocolVersion = uint16_t;
using Epoch = uint16_t;
using SequenceNumber = uint64_t;
using Length = uint16_t;

// DTLS version constants
constexpr ProtocolVersion DTLS_V10 = 0xFEFF;
constexpr ProtocolVersion DTLS_V12 = 0xFEFD;
constexpr ProtocolVersion DTLS_V13 = 0xFEFC;

// Content types
enum class ContentType : uint8_t {
    INVALID = 0,
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    HEARTBEAT = 24,
    TLS12_CID = 25,
    ACK = 26
};

// Handshake message types
enum class HandshakeType : uint8_t {
    HELLO_REQUEST_RESERVED = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    HELLO_VERIFY_REQUEST_RESERVED = 3,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    HELLO_RETRY_REQUEST = 6,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE_RESERVED = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE_RESERVED = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE_RESERVED = 16,
    FINISHED = 20,
    CERTIFICATE_URL_RESERVED = 21,
    CERTIFICATE_STATUS_RESERVED = 22,
    SUPPLEMENTAL_DATA_RESERVED = 23,
    KEY_UPDATE = 24,
    ACK = 26,
    MESSAGE_HASH = 254
};

// Alert levels
enum class AlertLevel : uint8_t {
    WARNING = 1,
    FATAL = 2
};

// Alert descriptions
enum class AlertDescription : uint8_t {
    CLOSE_NOTIFY = 0,
    UNEXPECTED_MESSAGE = 10,
    BAD_RECORD_MAC = 20,
    RECORD_OVERFLOW = 22,
    HANDSHAKE_FAILURE = 40,
    BAD_CERTIFICATE = 42,
    UNSUPPORTED_CERTIFICATE = 43,
    CERTIFICATE_REVOKED = 44,
    CERTIFICATE_EXPIRED = 45,
    CERTIFICATE_UNKNOWN = 46,
    ILLEGAL_PARAMETER = 47,
    UNKNOWN_CA = 48,
    ACCESS_DENIED = 49,
    DECODE_ERROR = 50,
    DECRYPT_ERROR = 51,
    PROTOCOL_VERSION = 70,
    INSUFFICIENT_SECURITY = 71,
    INTERNAL_ERROR = 80,
    INAPPROPRIATE_FALLBACK = 86,
    USER_CANCELED = 90,
    MISSING_EXTENSION = 109,
    UNSUPPORTED_EXTENSION = 110,
    UNRECOGNIZED_NAME = 112,
    BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    UNKNOWN_PSK_IDENTITY = 115,
    CERTIFICATE_REQUIRED = 116,
    NO_APPLICATION_PROTOCOL = 120
};

// Cipher suites
enum class CipherSuite : uint16_t {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305
};

// Named groups (key exchange)
enum class NamedGroup : uint16_t {
    // Elliptic Curve Groups (ECDHE)
    SECP256R1 = 23,
    SECP384R1 = 24,
    SECP521R1 = 25,
    X25519 = 29,
    X448 = 30,
    
    // Finite Field Groups (DHE)
    FFDHE2048 = 256,
    FFDHE3072 = 257,
    FFDHE4096 = 258,
    FFDHE6144 = 259,
    FFDHE8192 = 260
};

// Signature algorithms
enum class SignatureScheme : uint16_t {
    // RSASSA-PKCS1-v1_5 algorithms
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,
    
    // ECDSA algorithms
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
    
    // RSASSA-PSS algorithms
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,
    RSA_PSS_PSS_SHA256 = 0x0809,
    RSA_PSS_PSS_SHA384 = 0x080A,
    RSA_PSS_PSS_SHA512 = 0x080B,
    
    // EdDSA algorithms
    ED25519 = 0x0807,
    ED448 = 0x0808
};

// Hash algorithms
enum class HashAlgorithm : uint8_t {
    NONE = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
    SHA3_256 = 7,
    SHA3_384 = 8,
    SHA3_512 = 9
};

// AEAD cipher algorithms
enum class AEADCipher : uint8_t {
    AES_128_GCM = 1,
    AES_256_GCM = 2,
    CHACHA20_POLY1305 = 3,
    AES_128_CCM = 4,
    AES_128_CCM_8 = 5
};

// Extension types
enum class ExtensionType : uint16_t {
    SERVER_NAME = 0,
    MAX_FRAGMENT_LENGTH = 1,
    STATUS_REQUEST = 5,
    SUPPORTED_GROUPS = 10,
    SIGNATURE_ALGORITHMS = 13,
    USE_SRTP = 14,
    HEARTBEAT = 15,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
    SIGNED_CERTIFICATE_TIMESTAMP = 18,
    CLIENT_CERTIFICATE_TYPE = 19,
    SERVER_CERTIFICATE_TYPE = 20,
    PADDING = 21,
    PRE_SHARED_KEY = 41,
    EARLY_DATA = 42,
    SUPPORTED_VERSIONS = 43,
    COOKIE = 44,
    PSK_KEY_EXCHANGE_MODES = 45,
    CERTIFICATE_AUTHORITIES = 47,
    OID_FILTERS = 48,
    POST_HANDSHAKE_AUTH = 49,
    SIGNATURE_ALGORITHMS_CERT = 50,
    KEY_SHARE = 51,
    CONNECTION_ID = 54,
    EXTERNAL_ID_HASH = 55,
    EXTERNAL_SESSION_ID = 56
};

// Connection states
enum class ConnectionState : uint8_t {
    INITIAL = 0,
    WAIT_SERVER_HELLO = 1,
    WAIT_ENCRYPTED_EXTENSIONS = 2,
    WAIT_CERTIFICATE_OR_CERT_REQUEST = 3,
    WAIT_CERTIFICATE_VERIFY = 4,
    WAIT_SERVER_FINISHED = 5,
    WAIT_CLIENT_CERTIFICATE = 6,
    WAIT_CLIENT_CERTIFICATE_VERIFY = 7,
    WAIT_CLIENT_FINISHED = 8,
    CONNECTED = 9,
    CLOSED = 10,
    // Early data states (RFC 9147 Section 4.2.10)
    EARLY_DATA = 11,           // Client sending early data
    WAIT_END_OF_EARLY_DATA = 12, // Server waiting for EndOfEarlyData
    EARLY_DATA_REJECTED = 13   // Early data was rejected by server
};

// Security levels
enum class SecurityLevel : uint8_t {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    MAXIMUM = 4
};

// Connection ID type (max 20 bytes)
using ConnectionID = std::vector<uint8_t>;

// Random value (32 bytes)
using Random = std::array<uint8_t, 32>;

// Session ID (max 32 bytes)
using SessionID = std::vector<uint8_t>;

// Cookie (max 255 bytes)
using Cookie = std::vector<uint8_t>;

// Key material
using KeyMaterial = std::vector<uint8_t>;

// Certificate data
using CertificateData = std::vector<uint8_t>;

// Timing types
using Timestamp = std::chrono::steady_clock::time_point;
using Duration = std::chrono::milliseconds;

// Network address types
struct NetworkAddress {
    enum class Family : uint8_t {
        IPv4 = 4,
        IPv6 = 6
    };
    
    Family family;
    std::array<uint8_t, 16> address{}; // IPv6 size covers IPv4
    uint16_t port{0};
    
    bool is_ipv4() const noexcept { return family == Family::IPv4; }
    bool is_ipv6() const noexcept { return family == Family::IPv6; }
    
    // Comparison operators
    bool operator==(const NetworkAddress& other) const noexcept;
    bool operator!=(const NetworkAddress& other) const noexcept;
    bool operator<(const NetworkAddress& other) const noexcept;
    
    // Factory methods
    static NetworkAddress from_ipv4(uint32_t ipv4_addr, uint16_t port_num);
    static NetworkAddress from_ipv6(const std::array<uint8_t, 16>& ipv6_addr, uint16_t port_num);
    
    // Conversion methods
    uint32_t to_ipv4() const;
    std::array<uint8_t, 16> to_ipv6() const;
};;

// Utility functions
DTLS_API std::string to_string(ContentType type);
DTLS_API std::string to_string(HandshakeType type);
DTLS_API std::string to_string(AlertLevel level);
DTLS_API std::string to_string(AlertDescription desc);
DTLS_API std::string to_string(CipherSuite suite);
DTLS_API std::string to_string(ConnectionState state);
DTLS_API std::string to_string(const NetworkAddress& addr);

// Size constants
constexpr size_t MAX_RECORD_LENGTH = 16384;
constexpr size_t MAX_HANDSHAKE_MESSAGE_LENGTH = 16777215;
constexpr size_t MAX_CONNECTION_ID_LENGTH = 20;
constexpr size_t MAX_COOKIE_LENGTH = 255;
constexpr size_t RANDOM_LENGTH = 32;
constexpr size_t MAX_SESSION_ID_LENGTH = 32;

// Timing constants
constexpr Duration DEFAULT_RETRANSMISSION_TIMEOUT{1000};
constexpr Duration MAX_RETRANSMISSION_TIMEOUT{60000};
constexpr size_t MAX_RETRANSMISSIONS = 3;

} // namespace v13
} // namespace dtls

#endif // DTLS_TYPES_H