#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory.h"
#include "dtls/protocol/record.h"
#include <cstdint>
#include <vector>
#include <array>
#include <optional>
#include <cstring>

namespace dtls::v13::protocol {

// Use HandshakeType from dtls/types.h

enum class ExtensionType : uint16_t {
    SERVER_NAME = 0,
    MAX_FRAGMENT_LENGTH = 1,
    CLIENT_CERTIFICATE_URL = 2,
    TRUSTED_CA_KEYS = 3,
    TRUNCATED_HMAC = 4,
    STATUS_REQUEST = 5,
    USER_MAPPING = 6,
    CLIENT_AUTHZ = 7,
    SERVER_AUTHZ = 8,
    CERT_TYPE = 9,
    SUPPORTED_GROUPS = 10,
    EC_POINT_FORMATS = 11,
    SRP = 12,
    SIGNATURE_ALGORITHMS = 13,
    USE_SRTP = 14,
    HEARTBEAT = 15,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
    STATUS_REQUEST_V2 = 17,
    SIGNED_CERTIFICATE_TIMESTAMP = 18,
    CLIENT_CERTIFICATE_TYPE = 19,
    SERVER_CERTIFICATE_TYPE = 20,
    PADDING = 21,
    ENCRYPT_THEN_MAC = 22,
    EXTENDED_MASTER_SECRET = 23,
    TOKEN_BINDING = 24,
    CACHED_INFO = 25,
    TLS_LTS = 26,
    COMPRESS_CERTIFICATE = 27,
    RECORD_SIZE_LIMIT = 28,
    PWD_PROTECT = 29,
    PWD_CLEAR = 30,
    PASSWORD_SALT = 31,
    TICKET_PINNING = 32,
    TLS_CERT_WITH_EXTERN_PSK = 33,
    DELEGATED_CREDENTIAL = 34,
    SESSION_TICKET = 35,
    TLMSP = 36,
    TLMSP_PROXYING = 37,
    TLMSP_DELEGATE = 38,
    SUPPORTED_EKT_CIPHERS = 39,
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
    CONNECTION_ID_DEPRECATED = 53,
    CONNECTION_ID = 54,
    EXTERNAL_ID_HASH = 55,
    EXTERNAL_SESSION_ID = 56,
    QUIC_TRANSPORT_PARAMETERS = 57,
    TICKET_REQUEST = 58,
    DNSSEC_CHAIN = 59
};

// Use CipherSuite from dtls/types.h

enum class NamedGroup : uint16_t {
    // Elliptic Curve Groups (ECDHE)
    SECP256R1 = 0x0017,
    SECP384R1 = 0x0018,
    SECP521R1 = 0x0019,
    X25519 = 0x001d,
    X448 = 0x001e,
    
    // Finite Field Groups (DHE)
    FFDHE2048 = 0x0100,
    FFDHE3072 = 0x0101,
    FFDHE4096 = 0x0102,
    FFDHE6144 = 0x0103,
    FFDHE8192 = 0x0104
};

enum class SignatureScheme : uint16_t {
    // RSASSA-PKCS1-v1_5 algorithms
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,
    
    // ECDSA algorithms
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
    
    // RSASSA-PSS algorithms with public key OID rsaEncryption
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,
    
    // EdDSA algorithms
    ED25519 = 0x0807,
    ED448 = 0x0808,
    
    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RSA_PSS_PSS_SHA256 = 0x0809,
    RSA_PSS_PSS_SHA384 = 0x080a,
    RSA_PSS_PSS_SHA512 = 0x080b
};

struct Extension {
    ExtensionType type;
    memory::Buffer data;
    
    Extension() = default;
    Extension(ExtensionType ext_type, memory::Buffer ext_data) 
        : type(ext_type), data(std::move(ext_data)) {}
    
    // Copy constructor - creates a copy of the buffer
    Extension(const Extension& other) : type(other.type) {
        if (other.data.size() > 0) {
            data = memory::Buffer(other.data.size());
            auto resize_result = data.resize(other.data.size());
            if (resize_result.is_success()) {
                std::memcpy(data.mutable_data(), other.data.data(), other.data.size());
            }
        }
    }
    
    // Copy assignment
    Extension& operator=(const Extension& other) {
        if (this != &other) {
            type = other.type;
            if (other.data.size() > 0) {
                data = memory::Buffer(other.data.size());
                auto resize_result = data.resize(other.data.size());
                if (resize_result.is_success()) {
                    std::memcpy(data.mutable_data(), other.data.data(), other.data.size());
                }
            } else {
                data = memory::Buffer();
            }
        }
        return *this;
    }
    
    // Move constructor and assignment (default should work)
    Extension(Extension&& other) = default;
    Extension& operator=(Extension&& other) = default;
    
    // Equality operators
    bool operator==(const Extension& other) const {
        if (type != other.type) return false;
        if (data.size() != other.data.size()) return false;
        if (data.size() == 0) return true;
        return std::memcmp(data.data(), other.data.data(), data.size()) == 0;
    }
    
    bool operator!=(const Extension& other) const {
        return !(*this == other);
    }
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<Extension> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    size_t serialized_size() const;
    bool is_valid() const;
};

struct HandshakeHeader {
    HandshakeType msg_type;
    uint32_t length;        // 24-bit length
    uint16_t message_seq;   // DTLS-specific
    uint32_t fragment_offset; // 24-bit offset
    uint32_t fragment_length; // 24-bit length
    
    static constexpr size_t SERIALIZED_SIZE = 12;
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<HandshakeHeader> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const;
    bool is_fragmented() const { return fragment_offset != 0 || fragment_length != length; }
};

class ClientHello {
private:
    ProtocolVersion legacy_version_;
    std::array<uint8_t, 32> random_;
    memory::Buffer legacy_session_id_;
    memory::Buffer cookie_;  // DTLS-specific
    std::vector<CipherSuite> cipher_suites_;
    std::vector<uint8_t> legacy_compression_methods_;
    std::vector<Extension> extensions_;
    
public:
    ClientHello();
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    ClientHello(const ClientHello&) = delete;
    ClientHello& operator=(const ClientHello&) = delete;
    ClientHello(ClientHello&&) = default;
    ClientHello& operator=(ClientHello&&) = default;
    
    // Accessors
    ProtocolVersion legacy_version() const { return legacy_version_; }
    const std::array<uint8_t, 32>& random() const { return random_; }
    const memory::Buffer& legacy_session_id() const { return legacy_session_id_; }
    const memory::Buffer& cookie() const { return cookie_; }
    const std::vector<CipherSuite>& cipher_suites() const { return cipher_suites_; }
    const std::vector<Extension>& extensions() const { return extensions_; }
    
    // Mutators
    void set_legacy_version(ProtocolVersion version) { legacy_version_ = version; }
    void set_random(const std::array<uint8_t, 32>& random) { random_ = random; }
    void set_legacy_session_id(memory::Buffer session_id) { legacy_session_id_ = std::move(session_id); }
    void set_cookie(memory::Buffer cookie) { cookie_ = std::move(cookie); }
    void set_cipher_suites(std::vector<CipherSuite> suites) { cipher_suites_ = std::move(suites); }
    void add_extension(Extension extension) { extensions_.push_back(std::move(extension)); }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<ClientHello> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
    
    // Extension helpers
    std::optional<Extension> get_extension(ExtensionType type) const;
    bool has_extension(ExtensionType type) const;
};

class ServerHello {
private:
    ProtocolVersion legacy_version_;
    std::array<uint8_t, 32> random_;
    memory::Buffer legacy_session_id_echo_;
    CipherSuite cipher_suite_;
    uint8_t legacy_compression_method_;
    std::vector<Extension> extensions_;
    
public:
    ServerHello();
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    ServerHello(const ServerHello&) = delete;
    ServerHello& operator=(const ServerHello&) = delete;
    ServerHello(ServerHello&&) = default;
    ServerHello& operator=(ServerHello&&) = default;
    
    // Accessors
    ProtocolVersion legacy_version() const { return legacy_version_; }
    const std::array<uint8_t, 32>& random() const { return random_; }
    const memory::Buffer& legacy_session_id_echo() const { return legacy_session_id_echo_; }
    CipherSuite cipher_suite() const { return cipher_suite_; }
    const std::vector<Extension>& extensions() const { return extensions_; }
    
    // Mutators
    void set_legacy_version(ProtocolVersion version) { legacy_version_ = version; }
    void set_random(const std::array<uint8_t, 32>& random) { random_ = random; }
    void set_legacy_session_id_echo(memory::Buffer session_id) { legacy_session_id_echo_ = std::move(session_id); }
    void set_cipher_suite(CipherSuite suite) { cipher_suite_ = suite; }
    void add_extension(Extension extension) { extensions_.push_back(std::move(extension)); }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<ServerHello> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
    
    // Extension helpers
    std::optional<Extension> get_extension(ExtensionType type) const;
    bool has_extension(ExtensionType type) const;
};

class HelloRetryRequest {
private:
    ProtocolVersion legacy_version_;
    std::array<uint8_t, 32> random_;
    memory::Buffer legacy_session_id_echo_;
    CipherSuite cipher_suite_;
    uint8_t legacy_compression_method_;
    std::vector<Extension> extensions_;
    
    // HelloRetryRequest-specific special random (RFC 9147 Section 4.2.1)
    static constexpr std::array<uint8_t, 32> HELLO_RETRY_REQUEST_RANDOM = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };
    
public:
    HelloRetryRequest();
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    HelloRetryRequest(const HelloRetryRequest&) = delete;
    HelloRetryRequest& operator=(const HelloRetryRequest&) = delete;
    HelloRetryRequest(HelloRetryRequest&&) = default;
    HelloRetryRequest& operator=(HelloRetryRequest&&) = default;
    
    // Accessors
    ProtocolVersion legacy_version() const { return legacy_version_; }
    const std::array<uint8_t, 32>& random() const { return random_; }
    const memory::Buffer& legacy_session_id_echo() const { return legacy_session_id_echo_; }
    CipherSuite cipher_suite() const { return cipher_suite_; }
    const std::vector<Extension>& extensions() const { return extensions_; }
    
    // Mutators
    void set_legacy_version(ProtocolVersion version) { legacy_version_ = version; }
    void set_legacy_session_id_echo(memory::Buffer session_id) { legacy_session_id_echo_ = std::move(session_id); }
    void set_cipher_suite(CipherSuite suite) { cipher_suite_ = suite; }
    void add_extension(Extension extension) { extensions_.push_back(std::move(extension)); }
    
    // HelloRetryRequest-specific methods
    void set_cookie(const memory::Buffer& cookie);
    void set_selected_group(NamedGroup group);
    std::optional<memory::Buffer> get_cookie() const;
    std::optional<NamedGroup> get_selected_group() const;
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<HelloRetryRequest> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
    
    // Extension helpers
    std::optional<Extension> get_extension(ExtensionType type) const;
    bool has_extension(ExtensionType type) const;
    
    // Static helpers
    static bool is_hello_retry_request_random(const std::array<uint8_t, 32>& random);
};

struct CertificateEntry {
    memory::Buffer cert_data;
    std::vector<Extension> extensions;
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    CertificateEntry() = default;
    CertificateEntry(const CertificateEntry&) = delete;
    CertificateEntry& operator=(const CertificateEntry&) = delete;
    CertificateEntry(CertificateEntry&&) = default;
    CertificateEntry& operator=(CertificateEntry&&) = default;
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<CertificateEntry> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    size_t serialized_size() const;
    bool is_valid() const;
};

class Certificate {
private:
    memory::Buffer certificate_request_context_;
    std::vector<CertificateEntry> certificate_list_;
    
public:
    Certificate() = default;
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
    Certificate(Certificate&&) = default;
    Certificate& operator=(Certificate&&) = default;
    
    // Accessors
    const memory::Buffer& certificate_request_context() const { return certificate_request_context_; }
    const std::vector<CertificateEntry>& certificate_list() const { return certificate_list_; }
    
    // Mutators
    void set_certificate_request_context(memory::Buffer context) { certificate_request_context_ = std::move(context); }
    void set_certificate_list(std::vector<CertificateEntry> certs) { certificate_list_ = std::move(certs); }
    void add_certificate(CertificateEntry cert) { certificate_list_.push_back(std::move(cert)); }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<Certificate> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
};

// CertificateRequest message (RFC 9147 Section 4.3.2)
class CertificateRequest {
private:
    memory::Buffer certificate_request_context_;
    std::vector<Extension> extensions_;
    
public:
    CertificateRequest() = default;
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    CertificateRequest(const CertificateRequest&) = delete;
    CertificateRequest& operator=(const CertificateRequest&) = delete;
    CertificateRequest(CertificateRequest&&) = default;
    CertificateRequest& operator=(CertificateRequest&&) = default;
    
    // Accessors
    const memory::Buffer& certificate_request_context() const { return certificate_request_context_; }
    const std::vector<Extension>& extensions() const { return extensions_; }
    
    // Mutators
    void set_certificate_request_context(memory::Buffer context) { certificate_request_context_ = std::move(context); }
    void add_extension(Extension extension) { extensions_.push_back(std::move(extension)); }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<CertificateRequest> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const { return true; } // Context and extensions can be empty
    size_t serialized_size() const;
    
    // Extension helpers
    std::optional<Extension> get_extension(ExtensionType type) const;
    bool has_extension(ExtensionType type) const;
};

// Alert message (RFC 9147 Section 4.7)
class Alert {
private:
    AlertLevel level_;
    AlertDescription description_;
    
public:
    Alert() = default;
    Alert(AlertLevel level, AlertDescription description) 
        : level_(level), description_(description) {}
    
    // Accessors
    AlertLevel level() const { return level_; }
    AlertDescription description() const { return description_; }
    
    // Mutators
    void set_level(AlertLevel level) { level_ = level; }
    void set_description(AlertDescription description) { description_ = description; }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<Alert> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    static Result<Alert> deserialize_from_zerocopy(const memory::ZeroCopyBuffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const { return true; } // All alert combinations are valid
    size_t serialized_size() const { return 2; } // Always 2 bytes
    
    // Utility methods
    bool is_fatal() const { return level_ == AlertLevel::FATAL; }
    bool is_warning() const { return level_ == AlertLevel::WARNING; }
    
    // Equality operators
    bool operator==(const Alert& other) const {
        return level_ == other.level_ && description_ == other.description_;
    }
    
    bool operator!=(const Alert& other) const {
        return !(*this == other);
    }
};

class CertificateVerify {
private:
    SignatureScheme algorithm_;
    memory::Buffer signature_;
    
public:
    CertificateVerify() = default;
    CertificateVerify(SignatureScheme algorithm, memory::Buffer signature)
        : algorithm_(algorithm), signature_(std::move(signature)) {}
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    CertificateVerify(const CertificateVerify&) = delete;
    CertificateVerify& operator=(const CertificateVerify&) = delete;
    CertificateVerify(CertificateVerify&&) = default;
    CertificateVerify& operator=(CertificateVerify&&) = default;
    
    // Accessors
    SignatureScheme algorithm() const { return algorithm_; }
    const memory::Buffer& signature() const { return signature_; }
    
    // Mutators
    void set_algorithm(SignatureScheme algorithm) { algorithm_ = algorithm; }
    void set_signature(memory::Buffer signature) { signature_ = std::move(signature); }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<CertificateVerify> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
};

class Finished {
private:
    memory::Buffer verify_data_;
    
public:
    Finished() = default;
    explicit Finished(memory::Buffer verify_data) : verify_data_(std::move(verify_data)) {}
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    Finished(const Finished&) = delete;
    Finished& operator=(const Finished&) = delete;
    Finished(Finished&&) = default;
    Finished& operator=(Finished&&) = default;
    
    // Accessors
    const memory::Buffer& verify_data() const { return verify_data_; }
    
    // Mutators
    void set_verify_data(memory::Buffer data) { verify_data_ = std::move(data); }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<Finished> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
};

struct ACKRange {
    uint32_t start_sequence;  // 24-bit value stored in 32-bit
    uint32_t end_sequence;    // 24-bit value stored in 32-bit
    
    ACKRange() = default;
    ACKRange(uint32_t start, uint32_t end) : start_sequence(start), end_sequence(end) {}
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<ACKRange> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const { return 6; } // 3 bytes + 3 bytes
    
    // Comparison operators
    bool operator==(const ACKRange& other) const {
        return start_sequence == other.start_sequence && end_sequence == other.end_sequence;
    }
    
    bool operator<(const ACKRange& other) const {
        return start_sequence < other.start_sequence;
    }
    
    // Range operations
    bool contains(uint32_t sequence) const {
        return sequence >= start_sequence && sequence <= end_sequence;
    }
    
    bool overlaps(const ACKRange& other) const {
        return !(end_sequence < other.start_sequence || start_sequence > other.end_sequence);
    }
    
    uint32_t length() const {
        return end_sequence >= start_sequence ? (end_sequence - start_sequence + 1) : 0;
    }
};

class ACK {
private:
    std::vector<ACKRange> ack_ranges_;
    
public:
    ACK() = default;
    explicit ACK(std::vector<ACKRange> ranges) : ack_ranges_(std::move(ranges)) {}
    
    // Accessors
    const std::vector<ACKRange>& ack_ranges() const { return ack_ranges_; }
    
    // Mutators
    void set_ack_ranges(std::vector<ACKRange> ranges) { ack_ranges_ = std::move(ranges); }
    void add_ack_range(const ACKRange& range) { ack_ranges_.push_back(range); }
    void add_ack_range(uint32_t start, uint32_t end) { ack_ranges_.emplace_back(start, end); }
    
    // Convenience methods
    void acknowledge_sequence(uint32_t sequence);
    void acknowledge_range(uint32_t start, uint32_t end);
    bool is_sequence_acknowledged(uint32_t sequence) const;
    void clear() { ack_ranges_.clear(); }
    bool empty() const { return ack_ranges_.empty(); }
    size_t range_count() const { return ack_ranges_.size(); }
    
    // Range optimization
    void optimize_ranges(); // Merge overlapping/adjacent ranges
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<ACK> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
};

// Key update request field (RFC 9147 Section 4.6.3)
enum class KeyUpdateRequest : uint8_t {
    UPDATE_NOT_REQUESTED = 0,
    UPDATE_REQUESTED = 1
};

// KeyUpdate message (RFC 9147 Section 4.6.3)
class KeyUpdate {
private:
    KeyUpdateRequest update_request_;
    
public:
    // Constructors
    KeyUpdate() : update_request_(KeyUpdateRequest::UPDATE_NOT_REQUESTED) {}
    explicit KeyUpdate(KeyUpdateRequest request) : update_request_(request) {}
    
    // Accessors
    KeyUpdateRequest update_request() const noexcept { return update_request_; }
    void set_update_request(KeyUpdateRequest request) noexcept { update_request_ = request; }
    
    // Key update logic
    bool requests_peer_update() const noexcept { 
        return update_request_ == KeyUpdateRequest::UPDATE_REQUESTED; 
    }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<KeyUpdate> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const noexcept;
    static constexpr size_t serialized_size() noexcept { return 1; } // Just the request field
    
    // Equality
    bool operator==(const KeyUpdate& other) const noexcept {
        return update_request_ == other.update_request_;
    }
    
    bool operator!=(const KeyUpdate& other) const noexcept {
        return !(*this == other);
    }
};

// EndOfEarlyData message (RFC 9147 Section 4.2.10)
class EndOfEarlyData {
public:
    // EndOfEarlyData has no content, just the handshake header
    EndOfEarlyData() = default;
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<EndOfEarlyData> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const { return true; } // Always valid since no content
    size_t serialized_size() const { return 0; } // No body content
    
    // Equality operators
    bool operator==(const EndOfEarlyData& other) const {
        (void)other; // Suppress unused parameter warning
        return true; // All EndOfEarlyData messages are equal
    }
    
    bool operator!=(const EndOfEarlyData& other) const {
        return !(*this == other);
    }
};

// NewSessionTicket message (RFC 9147 Section 4.2.11)
class NewSessionTicket {
private:
    uint32_t ticket_lifetime_;           // Lifetime in seconds
    uint32_t ticket_age_add_;           // Random value for obfuscation
    std::vector<uint8_t> ticket_nonce_; // Unique per ticket
    std::vector<uint8_t> ticket_;       // Encrypted ticket data
    std::vector<Extension> extensions_; // Extensions (like early_data)
    
public:
    // Constructors
    NewSessionTicket() : ticket_lifetime_(0), ticket_age_add_(0) {}
    
    NewSessionTicket(uint32_t lifetime, uint32_t age_add, 
                     const std::vector<uint8_t>& nonce,
                     const std::vector<uint8_t>& ticket) 
        : ticket_lifetime_(lifetime), ticket_age_add_(age_add), 
          ticket_nonce_(nonce), ticket_(ticket) {}
    
    // Accessors
    uint32_t ticket_lifetime() const noexcept { return ticket_lifetime_; }
    uint32_t ticket_age_add() const noexcept { return ticket_age_add_; }
    const std::vector<uint8_t>& ticket_nonce() const noexcept { return ticket_nonce_; }
    const std::vector<uint8_t>& ticket() const noexcept { return ticket_; }
    const std::vector<Extension>& extensions() const noexcept { return extensions_; }
    
    // Mutators
    void set_ticket_lifetime(uint32_t lifetime) noexcept { ticket_lifetime_ = lifetime; }
    void set_ticket_age_add(uint32_t age_add) noexcept { ticket_age_add_ = age_add; }
    void set_ticket_nonce(const std::vector<uint8_t>& nonce) { ticket_nonce_ = nonce; }
    void set_ticket(const std::vector<uint8_t>& ticket) { ticket_ = ticket; }
    
    // Extension management
    void add_extension(const Extension& ext) { extensions_.push_back(ext); }
    
    template<typename T>
    const T* get_extension() const {
        auto type_value = static_cast<uint16_t>(T::extension_type);
        for (const auto& ext : extensions_) {
            if (static_cast<uint16_t>(ext.type) == type_value) {
                // Note: This requires proper extension parsing implementation
                return nullptr; // TODO: Implement proper extension parsing
            }
        }
        return nullptr;
    }
    
    bool has_extension(ExtensionType type) const {
        for (const auto& ext : extensions_) {
            if (ext.type == type) {
                return true;
            }
        }
        return false;
    }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<NewSessionTicket> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
    
    // Equality operators
    bool operator==(const NewSessionTicket& other) const {
        return ticket_lifetime_ == other.ticket_lifetime_ &&
               ticket_age_add_ == other.ticket_age_add_ &&
               ticket_nonce_ == other.ticket_nonce_ &&
               ticket_ == other.ticket_ &&
               extensions_ == other.extensions_;
    }
    
    bool operator!=(const NewSessionTicket& other) const {
        return !(*this == other);
    }
};

// Handshake message wrapper
class HandshakeMessage {
private:
    HandshakeHeader header_;
    std::variant<ClientHello, ServerHello, HelloRetryRequest, Certificate, CertificateRequest, CertificateVerify, Finished, KeyUpdate, ACK, EndOfEarlyData, NewSessionTicket> message_;
    
public:
    HandshakeMessage() = default;
    
    // Move-only semantics (copy disabled due to Buffer containing move-only ZeroCopyBuffer)
    HandshakeMessage(const HandshakeMessage&) = delete;
    HandshakeMessage& operator=(const HandshakeMessage&) = delete;
    HandshakeMessage(HandshakeMessage&&) = default;
    HandshakeMessage& operator=(HandshakeMessage&&) = default;
    
    template<typename T>
    HandshakeMessage(T&& msg, uint16_t message_seq = 0) {
        message_ = std::forward<T>(msg);
        header_.msg_type = get_handshake_type<std::decay_t<T>>();
        header_.message_seq = message_seq;
        header_.fragment_offset = 0;
        header_.length = std::get<std::decay_t<T>>(message_).serialized_size();
        header_.fragment_length = header_.length;
    }
    
    // Accessors
    const HandshakeHeader& header() const { return header_; }
    HandshakeHeader& header() { return header_; }
    HandshakeType message_type() const { return header_.msg_type; }
    
    template<typename T>
    const T& get() const {
        return std::get<T>(message_);
    }
    
    template<typename T>
    T& get() {
        return std::get<T>(message_);
    }
    
    template<typename T>
    bool holds() const {
        return std::holds_alternative<T>(message_);
    }
    
    // Access to the message variant
    const auto& message() const { return message_; }
    auto& message() { return message_; }
    
    // Serialization
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<HandshakeMessage> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    // Validation
    bool is_valid() const;
    size_t serialized_size() const;
    
private:
    template<typename T>
    static constexpr HandshakeType get_handshake_type();
};

// Template specializations for handshake type mapping
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<ClientHello>() { return HandshakeType::CLIENT_HELLO; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<ServerHello>() { return HandshakeType::SERVER_HELLO; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<HelloRetryRequest>() { return HandshakeType::HELLO_RETRY_REQUEST; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<Certificate>() { return HandshakeType::CERTIFICATE; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<CertificateRequest>() { return HandshakeType::CERTIFICATE_REQUEST; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<CertificateVerify>() { return HandshakeType::CERTIFICATE_VERIFY; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<Finished>() { return HandshakeType::FINISHED; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<KeyUpdate>() { return HandshakeType::KEY_UPDATE; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<ACK>() { return HandshakeType::ACK; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<EndOfEarlyData>() { return HandshakeType::END_OF_EARLY_DATA; }
template<> constexpr HandshakeType HandshakeMessage::get_handshake_type<NewSessionTicket>() { return HandshakeType::NEW_SESSION_TICKET; }

// Early Data Extension Structure (RFC 9147)
struct EarlyDataExtension {
    uint32_t max_early_data_size; // Maximum early data the server will accept
    
    EarlyDataExtension() : max_early_data_size(0) {}
    explicit EarlyDataExtension(uint32_t max_size) : max_early_data_size(max_size) {}
    
    static constexpr ExtensionType extension_type = ExtensionType::EARLY_DATA;
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<EarlyDataExtension> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const { return true; } // Always valid
    size_t serialized_size() const;
    
    bool operator==(const EarlyDataExtension& other) const {
        return max_early_data_size == other.max_early_data_size;
    }
    
    bool operator!=(const EarlyDataExtension& other) const {
        return !(*this == other);
    }
};

// Pre-Shared Key Extension Structures (RFC 9147)
struct PskIdentity {
    std::vector<uint8_t> identity;
    uint32_t obfuscated_ticket_age;  // Ticket age + ticket_age_add
    
    PskIdentity() : obfuscated_ticket_age(0) {}
    PskIdentity(const std::vector<uint8_t>& id, uint32_t age) 
        : identity(id), obfuscated_ticket_age(age) {}
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<PskIdentity> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    size_t serialized_size() const;
    bool is_valid() const;
    
    bool operator==(const PskIdentity& other) const {
        return identity == other.identity && obfuscated_ticket_age == other.obfuscated_ticket_age;
    }
};

struct PreSharedKeyExtension {
    std::vector<PskIdentity> identities;
    std::vector<std::vector<uint8_t>> binders; // PSK binder values
    
    PreSharedKeyExtension() = default;
    
    static constexpr ExtensionType extension_type = ExtensionType::PRE_SHARED_KEY;
    
    void add_identity(const PskIdentity& identity) { identities.push_back(identity); }
    void add_binder(const std::vector<uint8_t>& binder) { binders.push_back(binder); }
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<PreSharedKeyExtension> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const;
    size_t serialized_size() const;
    
    bool operator==(const PreSharedKeyExtension& other) const {
        return identities == other.identities && binders == other.binders;
    }
    
    bool operator!=(const PreSharedKeyExtension& other) const {
        return !(*this == other);
    }
};

// PSK Key Exchange Modes Extension (RFC 9147)
enum class PskKeyExchangeMode : uint8_t {
    PSK_KE = 0,      // PSK-only key establishment
    PSK_DHE_KE = 1   // PSK with (EC)DHE key establishment
};

struct PskKeyExchangeModesExtension {
    std::vector<PskKeyExchangeMode> modes;
    
    PskKeyExchangeModesExtension() = default;
    explicit PskKeyExchangeModesExtension(const std::vector<PskKeyExchangeMode>& exchange_modes) 
        : modes(exchange_modes) {}
    
    static constexpr ExtensionType extension_type = ExtensionType::PSK_KEY_EXCHANGE_MODES;
    
    void add_mode(PskKeyExchangeMode mode) { modes.push_back(mode); }
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<PskKeyExchangeModesExtension> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const { return !modes.empty(); }
    size_t serialized_size() const;
    
    bool operator==(const PskKeyExchangeModesExtension& other) const {
        return modes == other.modes;
    }
    
    bool operator!=(const PskKeyExchangeModesExtension& other) const {
        return !(*this == other);
    }
};

// Connection ID Extension (RFC 9146/9147)
struct ConnectionIdExtension {
    std::vector<uint8_t> connection_id;
    
    ConnectionIdExtension() = default;
    explicit ConnectionIdExtension(const std::vector<uint8_t>& cid) : connection_id(cid) {}
    
    static constexpr ExtensionType extension_type = ExtensionType::CONNECTION_ID;
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<ConnectionIdExtension> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const { 
        // RFC 9146: CID length must be 0-20 bytes
        return connection_id.size() <= MAX_CONNECTION_ID_LENGTH; 
    }
    
    size_t serialized_size() const { 
        return 1 + connection_id.size(); // 1 byte length + CID data
    }
    
    // Equality operators
    bool operator==(const ConnectionIdExtension& other) const {
        return connection_id == other.connection_id;
    }
    
    bool operator!=(const ConnectionIdExtension& other) const {
        return !(*this == other);
    }
};

// Utility functions
bool is_supported_cipher_suite(CipherSuite suite);
bool is_supported_signature_scheme(SignatureScheme scheme);
bool is_supported_named_group(NamedGroup group);
bool requires_certificate(CipherSuite suite);

Result<memory::Buffer> create_random();
Result<Extension> create_supported_versions_extension(const std::vector<ProtocolVersion>& versions);
Result<Extension> create_supported_groups_extension(const std::vector<NamedGroup>& groups);
Result<Extension> create_signature_algorithms_extension(const std::vector<SignatureScheme>& schemes);

// HelloRetryRequest-specific utility functions
Result<Extension> create_cookie_extension(const memory::Buffer& cookie);
Result<Extension> create_key_share_hello_retry_request_extension(NamedGroup selected_group);
Result<memory::Buffer> extract_cookie_from_extension(const Extension& cookie_ext);
Result<NamedGroup> extract_selected_group_from_extension(const Extension& key_share_ext);

// Early Data and PSK utility functions
Result<Extension> create_early_data_extension(uint32_t max_early_data_size = 0);
Result<Extension> create_psk_extension(const std::vector<PskIdentity>& identities, 
                                       const std::vector<std::vector<uint8_t>>& binders);
Result<Extension> create_psk_key_exchange_modes_extension(const std::vector<PskKeyExchangeMode>& modes);

// Connection ID utility functions
Result<Extension> create_connection_id_extension(const std::vector<uint8_t>& connection_id);
Result<ConnectionIdExtension> parse_connection_id_extension(const Extension& ext);

// Alert utility functions
Alert create_close_notify_alert();
Alert create_fatal_alert(AlertDescription description);
Alert create_warning_alert(AlertDescription description);
Result<memory::Buffer> serialize_alert(const Alert& alert);

// Extension parsing utilities
Result<EarlyDataExtension> parse_early_data_extension(const Extension& ext);
Result<PreSharedKeyExtension> parse_psk_extension(const Extension& ext);
Result<PskKeyExchangeModesExtension> parse_psk_key_exchange_modes_extension(const Extension& ext);

// PSK binder calculation utilities  
Result<std::vector<uint8_t>> calculate_psk_binder(const std::vector<uint8_t>& psk,
                                                  const std::vector<uint8_t>& handshake_context,
                                                  const std::string& label);
bool verify_psk_binder(const std::vector<uint8_t>& psk,
                       const std::vector<uint8_t>& handshake_context,
                       const std::vector<uint8_t>& expected_binder,
                       const std::string& label);

// ACK utility functions
Result<ACK> create_ack_message(const std::vector<uint32_t>& acknowledged_sequences);
Result<ACK> create_ack_message_from_ranges(const std::vector<std::pair<uint32_t, uint32_t>>& ranges);
bool is_ack_message_valid(const ACK& ack_message);
std::vector<uint32_t> get_missing_sequences(const ACK& ack_message, uint32_t max_sequence);
bool should_send_ack(const std::vector<uint32_t>& received_sequences, const ACK& last_ack_sent);

}  // namespace dtls::v13::protocol