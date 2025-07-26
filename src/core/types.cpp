#include <dtls/types.h>
#include <sstream>
#include <iomanip>
#include <unordered_map>

namespace dtls {
namespace v13 {

// String conversion functions for enums
std::string to_string(ContentType type) {
    static const std::unordered_map<ContentType, std::string> content_type_names = {
        {ContentType::INVALID, "INVALID"},
        {ContentType::CHANGE_CIPHER_SPEC, "CHANGE_CIPHER_SPEC"},
        {ContentType::ALERT, "ALERT"},
        {ContentType::HANDSHAKE, "HANDSHAKE"},
        {ContentType::APPLICATION_DATA, "APPLICATION_DATA"},
        {ContentType::HEARTBEAT, "HEARTBEAT"},
        {ContentType::TLS12_CID, "TLS12_CID"},
        {ContentType::ACK, "ACK"}
    };
    
    auto it = content_type_names.find(type);
    if (it != content_type_names.end()) {
        return it->second;
    }
    
    std::ostringstream oss;
    oss << "UNKNOWN_CONTENT_TYPE(" << static_cast<uint8_t>(type) << ")";
    return oss.str();
}

std::string to_string(HandshakeType type) {
    static const std::unordered_map<HandshakeType, std::string> handshake_type_names = {
        {HandshakeType::HELLO_REQUEST_RESERVED, "HELLO_REQUEST_RESERVED"},
        {HandshakeType::CLIENT_HELLO, "CLIENT_HELLO"},
        {HandshakeType::SERVER_HELLO, "SERVER_HELLO"},
        {HandshakeType::HELLO_VERIFY_REQUEST_RESERVED, "HELLO_VERIFY_REQUEST_RESERVED"},
        {HandshakeType::NEW_SESSION_TICKET, "NEW_SESSION_TICKET"},
        {HandshakeType::END_OF_EARLY_DATA, "END_OF_EARLY_DATA"},
        {HandshakeType::HELLO_RETRY_REQUEST, "HELLO_RETRY_REQUEST"},
        {HandshakeType::ENCRYPTED_EXTENSIONS, "ENCRYPTED_EXTENSIONS"},
        {HandshakeType::CERTIFICATE, "CERTIFICATE"},
        {HandshakeType::SERVER_KEY_EXCHANGE_RESERVED, "SERVER_KEY_EXCHANGE_RESERVED"},
        {HandshakeType::CERTIFICATE_REQUEST, "CERTIFICATE_REQUEST"},
        {HandshakeType::SERVER_HELLO_DONE_RESERVED, "SERVER_HELLO_DONE_RESERVED"},
        {HandshakeType::CERTIFICATE_VERIFY, "CERTIFICATE_VERIFY"},
        {HandshakeType::CLIENT_KEY_EXCHANGE_RESERVED, "CLIENT_KEY_EXCHANGE_RESERVED"},
        {HandshakeType::FINISHED, "FINISHED"},
        {HandshakeType::CERTIFICATE_URL_RESERVED, "CERTIFICATE_URL_RESERVED"},
        {HandshakeType::CERTIFICATE_STATUS_RESERVED, "CERTIFICATE_STATUS_RESERVED"},
        {HandshakeType::SUPPLEMENTAL_DATA_RESERVED, "SUPPLEMENTAL_DATA_RESERVED"},
        {HandshakeType::KEY_UPDATE, "KEY_UPDATE"},
        {HandshakeType::ACK, "ACK"},
        {HandshakeType::MESSAGE_HASH, "MESSAGE_HASH"}
    };
    
    auto it = handshake_type_names.find(type);
    if (it != handshake_type_names.end()) {
        return it->second;
    }
    
    std::ostringstream oss;
    oss << "UNKNOWN_HANDSHAKE_TYPE(" << static_cast<uint8_t>(type) << ")";
    return oss.str();
}

std::string to_string(AlertLevel level) {
    switch (level) {
        case AlertLevel::WARNING: return "WARNING";
        case AlertLevel::FATAL: return "FATAL";
        default:
            std::ostringstream oss;
            oss << "UNKNOWN_ALERT_LEVEL(" << static_cast<uint8_t>(level) << ")";
            return oss.str();
    }
}

std::string to_string(AlertDescription desc) {
    static const std::unordered_map<AlertDescription, std::string> alert_desc_names = {
        {AlertDescription::CLOSE_NOTIFY, "CLOSE_NOTIFY"},
        {AlertDescription::UNEXPECTED_MESSAGE, "UNEXPECTED_MESSAGE"},
        {AlertDescription::BAD_RECORD_MAC, "BAD_RECORD_MAC"},
        {AlertDescription::RECORD_OVERFLOW, "RECORD_OVERFLOW"},
        {AlertDescription::HANDSHAKE_FAILURE, "HANDSHAKE_FAILURE"},
        {AlertDescription::BAD_CERTIFICATE, "BAD_CERTIFICATE"},
        {AlertDescription::UNSUPPORTED_CERTIFICATE, "UNSUPPORTED_CERTIFICATE"},
        {AlertDescription::CERTIFICATE_REVOKED, "CERTIFICATE_REVOKED"},
        {AlertDescription::CERTIFICATE_EXPIRED, "CERTIFICATE_EXPIRED"},
        {AlertDescription::CERTIFICATE_UNKNOWN, "CERTIFICATE_UNKNOWN"},
        {AlertDescription::ILLEGAL_PARAMETER, "ILLEGAL_PARAMETER"},
        {AlertDescription::UNKNOWN_CA, "UNKNOWN_CA"},
        {AlertDescription::ACCESS_DENIED, "ACCESS_DENIED"},
        {AlertDescription::DECODE_ERROR, "DECODE_ERROR"},
        {AlertDescription::DECRYPT_ERROR, "DECRYPT_ERROR"},
        {AlertDescription::PROTOCOL_VERSION, "PROTOCOL_VERSION"},
        {AlertDescription::INSUFFICIENT_SECURITY, "INSUFFICIENT_SECURITY"},
        {AlertDescription::INTERNAL_ERROR, "INTERNAL_ERROR"},
        {AlertDescription::INAPPROPRIATE_FALLBACK, "INAPPROPRIATE_FALLBACK"},
        {AlertDescription::USER_CANCELED, "USER_CANCELED"},
        {AlertDescription::MISSING_EXTENSION, "MISSING_EXTENSION"},
        {AlertDescription::UNSUPPORTED_EXTENSION, "UNSUPPORTED_EXTENSION"},
        {AlertDescription::UNRECOGNIZED_NAME, "UNRECOGNIZED_NAME"},
        {AlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE, "BAD_CERTIFICATE_STATUS_RESPONSE"},
        {AlertDescription::UNKNOWN_PSK_IDENTITY, "UNKNOWN_PSK_IDENTITY"},
        {AlertDescription::CERTIFICATE_REQUIRED, "CERTIFICATE_REQUIRED"},
        {AlertDescription::NO_APPLICATION_PROTOCOL, "NO_APPLICATION_PROTOCOL"}
    };
    
    auto it = alert_desc_names.find(desc);
    if (it != alert_desc_names.end()) {
        return it->second;
    }
    
    std::ostringstream oss;
    oss << "UNKNOWN_ALERT_DESC(" << static_cast<uint8_t>(desc) << ")";
    return oss.str();
}

std::string to_string(CipherSuite suite) {
    static const std::unordered_map<CipherSuite, std::string> cipher_suite_names = {
        {CipherSuite::TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
        {CipherSuite::TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
        {CipherSuite::TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
        {CipherSuite::TLS_AES_128_CCM_SHA256, "TLS_AES_128_CCM_SHA256"},
        {CipherSuite::TLS_AES_128_CCM_8_SHA256, "TLS_AES_128_CCM_8_SHA256"}
    };
    
    auto it = cipher_suite_names.find(suite);
    if (it != cipher_suite_names.end()) {
        return it->second;
    }
    
    std::ostringstream oss;
    oss << "UNKNOWN_CIPHER_SUITE(0x" << std::hex << std::setfill('0') << std::setw(4) 
        << static_cast<uint16_t>(suite) << ")";
    return oss.str();
}

std::string to_string(ConnectionState state) {
    static const std::unordered_map<ConnectionState, std::string> state_names = {
        {ConnectionState::INITIAL, "INITIAL"},
        {ConnectionState::WAIT_SERVER_HELLO, "WAIT_SERVER_HELLO"},
        {ConnectionState::WAIT_ENCRYPTED_EXTENSIONS, "WAIT_ENCRYPTED_EXTENSIONS"},
        {ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST, "WAIT_CERTIFICATE_OR_CERT_REQUEST"},
        {ConnectionState::WAIT_CERTIFICATE_VERIFY, "WAIT_CERTIFICATE_VERIFY"},
        {ConnectionState::WAIT_SERVER_FINISHED, "WAIT_SERVER_FINISHED"},
        {ConnectionState::WAIT_CLIENT_CERTIFICATE, "WAIT_CLIENT_CERTIFICATE"},
        {ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY, "WAIT_CLIENT_CERTIFICATE_VERIFY"},
        {ConnectionState::WAIT_CLIENT_FINISHED, "WAIT_CLIENT_FINISHED"},
        {ConnectionState::CONNECTED, "CONNECTED"},
        {ConnectionState::CLOSED, "CLOSED"}
    };
    
    auto it = state_names.find(state);
    if (it != state_names.end()) {
        return it->second;
    }
    
    std::ostringstream oss;
    oss << "UNKNOWN_CONNECTION_STATE(" << static_cast<uint8_t>(state) << ")";
    return oss.str();
}

std::string to_string(const NetworkAddress& addr) {
    std::ostringstream oss;
    
    if (addr.is_ipv4()) {
        // IPv4 address format: a.b.c.d:port
        oss << static_cast<int>(addr.address[0]) << "."
            << static_cast<int>(addr.address[1]) << "."
            << static_cast<int>(addr.address[2]) << "."
            << static_cast<int>(addr.address[3]) << ":"
            << addr.port;
    } else if (addr.is_ipv6()) {
        // IPv6 address format: [a:b:c:d:e:f:g:h]:port
        oss << "[";
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0) oss << ":";
            uint16_t segment = (static_cast<uint16_t>(addr.address[i]) << 8) |
                              static_cast<uint16_t>(addr.address[i + 1]);
            oss << std::hex << segment;
        }
        oss << "]:" << std::dec << addr.port;
    } else {
        oss << "UNKNOWN_ADDRESS_FAMILY:" << addr.port;
    }
    
    return oss.str();
}

// Utility functions for cipher suite information
namespace cipher_suite_info {

struct CipherSuiteProperties {
    AEADCipher aead_cipher;
    HashAlgorithm hash_algorithm;
    size_t key_length;
    size_t iv_length;
    size_t tag_length;
    size_t hash_length;
};

static const std::unordered_map<CipherSuite, CipherSuiteProperties> cipher_properties = {
    {CipherSuite::TLS_AES_128_GCM_SHA256, {
        AEADCipher::AES_128_GCM, HashAlgorithm::SHA256, 16, 12, 16, 32}},
    {CipherSuite::TLS_AES_256_GCM_SHA384, {
        AEADCipher::AES_256_GCM, HashAlgorithm::SHA384, 32, 12, 16, 48}},
    {CipherSuite::TLS_CHACHA20_POLY1305_SHA256, {
        AEADCipher::CHACHA20_POLY1305, HashAlgorithm::SHA256, 32, 12, 16, 32}},
    {CipherSuite::TLS_AES_128_CCM_SHA256, {
        AEADCipher::AES_128_CCM, HashAlgorithm::SHA256, 16, 12, 16, 32}},
    {CipherSuite::TLS_AES_128_CCM_8_SHA256, {
        AEADCipher::AES_128_CCM_8, HashAlgorithm::SHA256, 16, 12, 8, 32}}
};

} // namespace cipher_suite_info

// Helper functions for getting cipher suite properties
AEADCipher get_aead_cipher(CipherSuite suite) {
    auto it = cipher_suite_info::cipher_properties.find(suite);
    return (it != cipher_suite_info::cipher_properties.end()) ? 
           it->second.aead_cipher : AEADCipher::AES_128_GCM;
}

HashAlgorithm get_hash_algorithm(CipherSuite suite) {
    auto it = cipher_suite_info::cipher_properties.find(suite);
    return (it != cipher_suite_info::cipher_properties.end()) ? 
           it->second.hash_algorithm : HashAlgorithm::SHA256;
}

size_t get_key_length(CipherSuite suite) {
    auto it = cipher_suite_info::cipher_properties.find(suite);
    return (it != cipher_suite_info::cipher_properties.end()) ? 
           it->second.key_length : 16;
}

size_t get_iv_length(CipherSuite suite) {
    auto it = cipher_suite_info::cipher_properties.find(suite);
    return (it != cipher_suite_info::cipher_properties.end()) ? 
           it->second.iv_length : 12;
}

size_t get_tag_length(CipherSuite suite) {
    auto it = cipher_suite_info::cipher_properties.find(suite);
    return (it != cipher_suite_info::cipher_properties.end()) ? 
           it->second.tag_length : 16;
}

size_t get_hash_length(CipherSuite suite) {
    auto it = cipher_suite_info::cipher_properties.find(suite);
    return (it != cipher_suite_info::cipher_properties.end()) ? 
           it->second.hash_length : 32;
}

// Network address utility functions
bool NetworkAddress::operator==(const NetworkAddress& other) const noexcept {
    return family == other.family && 
           port == other.port && 
           address == other.address;
}

bool NetworkAddress::operator!=(const NetworkAddress& other) const noexcept {
    return !(*this == other);
}

bool NetworkAddress::operator<(const NetworkAddress& other) const noexcept {
    if (family != other.family) {
        return family < other.family;
    }
    if (port != other.port) {
        return port < other.port;
    }
    return address < other.address;
}

NetworkAddress NetworkAddress::from_ipv4(uint32_t ipv4_addr, uint16_t port_num) {
    NetworkAddress addr;
    addr.family = Family::IPv4;
    addr.port = port_num;
    addr.address.fill(0);
    addr.address[0] = static_cast<uint8_t>((ipv4_addr >> 24) & 0xFF);
    addr.address[1] = static_cast<uint8_t>((ipv4_addr >> 16) & 0xFF);
    addr.address[2] = static_cast<uint8_t>((ipv4_addr >> 8) & 0xFF);
    addr.address[3] = static_cast<uint8_t>(ipv4_addr & 0xFF);
    return addr;
}

NetworkAddress NetworkAddress::from_ipv6(const std::array<uint8_t, 16>& ipv6_addr, uint16_t port_num) {
    NetworkAddress addr;
    addr.family = Family::IPv6;
    addr.port = port_num;
    addr.address = ipv6_addr;
    return addr;
}

uint32_t NetworkAddress::to_ipv4() const {
    if (!is_ipv4()) {
        return 0;
    }
    return (static_cast<uint32_t>(address[0]) << 24) |
           (static_cast<uint32_t>(address[1]) << 16) |
           (static_cast<uint32_t>(address[2]) << 8) |
           static_cast<uint32_t>(address[3]);
}

std::array<uint8_t, 16> NetworkAddress::to_ipv6() const {
    return address;
}

} // namespace v13
} // namespace dtls