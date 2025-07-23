#include "dtls/protocol/handshake.h"
#include "dtls/error.h"
#include <algorithm>
#include <cstring>
#include <random>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

namespace dtls::v13::protocol {

// Helper functions for byte order conversion
inline void copy_to_byte_buffer(std::byte* dest, const void* src, size_t size) {
    std::memcpy(dest, src, size);
}

inline void copy_from_byte_buffer(void* dest, const std::byte* src, size_t size) {
    std::memcpy(dest, src, size);
}

// Extension implementation
Result<size_t> Extension::serialize(memory::Buffer& buffer) const {
    size_t total_size = 4 + data.size(); // 2 bytes type + 2 bytes length + data
    
    if (buffer.capacity() < total_size) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    std::byte* ptr = buffer.mutable_data();
    size_t offset = 0;
    
    // Extension type (2 bytes)
    uint16_t type_net = htons(static_cast<uint16_t>(type));
    copy_to_byte_buffer(ptr + offset, &type_net, 2);
    offset += 2;
    
    // Extension data length (2 bytes)
    uint16_t length_net = htons(static_cast<uint16_t>(data.size()));
    copy_to_byte_buffer(ptr + offset, &length_net, 2);
    offset += 2;
    
    // Extension data
    if (data.size() > 0) {
        copy_to_byte_buffer(ptr + offset, data.data(), data.size());
    }
    
    return Result<size_t>(total_size);
}

Result<Extension> Extension::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 4) {
        return Result<Extension>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    size_t pos = 0;
    
    // Extension type
    uint16_t type_net;
    copy_from_byte_buffer(&type_net, ptr + pos, 2);
    ExtensionType ext_type = static_cast<ExtensionType>(ntohs(type_net));
    pos += 2;
    
    // Extension data length
    uint16_t length_net;
    copy_from_byte_buffer(&length_net, ptr + pos, 2);
    uint16_t data_length = ntohs(length_net);
    pos += 2;
    
    if (buffer.size() < offset + 4 + data_length) {
        return Result<Extension>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Extension data
    memory::Buffer ext_data(data_length);
    if (data_length > 0) {
        auto resize_result = ext_data.resize(data_length);
        if (!resize_result.is_success()) {
            return Result<Extension>(resize_result.error());
        }
        copy_to_byte_buffer(ext_data.mutable_data(), ptr + pos, data_length);
    }
    
    return Result<Extension>(Extension(ext_type, std::move(ext_data)));
}

size_t Extension::serialized_size() const {
    return 4 + data.size();
}

bool Extension::is_valid() const {
    return data.size() <= 65535; // Max extension length
}

// HandshakeHeader implementation
Result<size_t> HandshakeHeader::serialize(memory::Buffer& buffer) const {
    if (buffer.capacity() < SERIALIZED_SIZE) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    auto resize_result = buffer.resize(SERIALIZED_SIZE);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    std::byte* ptr = buffer.mutable_data();
    size_t offset = 0;
    
    // Message type (1 byte)
    ptr[offset++] = static_cast<std::byte>(static_cast<uint8_t>(msg_type));
    
    // Length (3 bytes, big-endian)
    uint32_t length_be = htonl(length);
    copy_to_byte_buffer(ptr + offset, reinterpret_cast<uint8_t*>(&length_be) + 1, 3);
    offset += 3;
    
    // Message sequence (2 bytes)
    uint16_t seq_net = htons(message_seq);
    copy_to_byte_buffer(ptr + offset, &seq_net, 2);
    offset += 2;
    
    // Fragment offset (3 bytes, big-endian)
    uint32_t frag_offset_be = htonl(fragment_offset);
    copy_to_byte_buffer(ptr + offset, reinterpret_cast<uint8_t*>(&frag_offset_be) + 1, 3);
    offset += 3;
    
    // Fragment length (3 bytes, big-endian)
    uint32_t frag_length_be = htonl(fragment_length);
    copy_to_byte_buffer(ptr + offset, reinterpret_cast<uint8_t*>(&frag_length_be) + 1, 3);
    offset += 3;
    
    return Result<size_t>(SERIALIZED_SIZE);
}

Result<HandshakeHeader> HandshakeHeader::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + SERIALIZED_SIZE) {
        return Result<HandshakeHeader>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    HandshakeHeader header;
    size_t pos = 0;
    
    // Message type
    header.msg_type = static_cast<HandshakeType>(static_cast<uint8_t>(ptr[pos++]));
    
    // Length (3 bytes)
    uint32_t length_be = 0;
    copy_from_byte_buffer(reinterpret_cast<uint8_t*>(&length_be) + 1, ptr + pos, 3);
    header.length = ntohl(length_be);
    pos += 3;
    
    // Message sequence
    uint16_t seq_net;
    copy_from_byte_buffer(&seq_net, ptr + pos, 2);
    header.message_seq = ntohs(seq_net);
    pos += 2;
    
    // Fragment offset (3 bytes)
    uint32_t frag_offset_be = 0;
    copy_from_byte_buffer(reinterpret_cast<uint8_t*>(&frag_offset_be) + 1, ptr + pos, 3);
    header.fragment_offset = ntohl(frag_offset_be);
    pos += 3;
    
    // Fragment length (3 bytes)
    uint32_t frag_length_be = 0;
    copy_from_byte_buffer(reinterpret_cast<uint8_t*>(&frag_length_be) + 1, ptr + pos, 3);
    header.fragment_length = ntohl(frag_length_be);
    pos += 3;
    
    if (!header.is_valid()) {
        return Result<HandshakeHeader>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<HandshakeHeader>(std::move(header));
}

bool HandshakeHeader::is_valid() const {
    // Check if fragment offset + fragment length <= total length
    if (fragment_offset + fragment_length > length) {
        return false;
    }
    
    // Check maximum message size (RFC 9147)
    if (length > 262144) { // 2^18 bytes
        return false;
    }
    
    return true;
}

// ClientHello implementation
ClientHello::ClientHello() 
    : legacy_version_(ProtocolVersion::DTLS_1_2)
    , legacy_compression_methods_{0} // No compression
{
    // Initialize random with current time and random data
    auto random_result = create_random();
    if (random_result.is_success()) {
        memory::Buffer rand_buf = std::move(random_result.value());
        if (rand_buf.size() >= 32) {
            std::memcpy(random_.data(), rand_buf.data(), 32);
        }
    }
}

Result<size_t> ClientHello::serialize(memory::Buffer& buffer) const {
    if (!is_valid()) {
        return Result<size_t>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    size_t total_size = serialized_size();
    if (buffer.capacity() < total_size) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    std::byte* ptr = buffer.mutable_data();
    size_t offset = 0;
    
    // Legacy version (2 bytes)
    uint16_t version_net = htons(static_cast<uint16_t>(legacy_version_));
    copy_to_byte_buffer(ptr + offset, &version_net, 2);
    offset += 2;
    
    // Random (32 bytes)
    copy_to_byte_buffer(ptr + offset, random_.data(), 32);
    offset += 32;
    
    // Legacy session ID
    uint8_t session_id_len = static_cast<uint8_t>(legacy_session_id_.size());
    ptr[offset++] = static_cast<std::byte>(session_id_len);
    if (session_id_len > 0) {
        copy_to_byte_buffer(ptr + offset, legacy_session_id_.data(), session_id_len);
        offset += session_id_len;
    }
    
    // Cookie (DTLS-specific)
    uint8_t cookie_len = static_cast<uint8_t>(cookie_.size());
    ptr[offset++] = static_cast<std::byte>(cookie_len);
    if (cookie_len > 0) {
        copy_to_byte_buffer(ptr + offset, cookie_.data(), cookie_len);
        offset += cookie_len;
    }
    
    // Cipher suites
    uint16_t cipher_suites_len = static_cast<uint16_t>(cipher_suites_.size() * 2);
    uint16_t cipher_suites_len_net = htons(cipher_suites_len);
    copy_to_byte_buffer(ptr + offset, &cipher_suites_len_net, 2);
    offset += 2;
    
    for (CipherSuite suite : cipher_suites_) {
        uint16_t suite_net = htons(static_cast<uint16_t>(suite));
        copy_to_byte_buffer(ptr + offset, &suite_net, 2);
        offset += 2;
    }
    
    // Legacy compression methods
    uint8_t compression_len = static_cast<uint8_t>(legacy_compression_methods_.size());
    ptr[offset++] = static_cast<std::byte>(compression_len);
    for (uint8_t method : legacy_compression_methods_) {
        ptr[offset++] = static_cast<std::byte>(method);
    }
    
    // Extensions
    size_t extensions_size = 0;
    for (const auto& ext : extensions_) {
        extensions_size += ext.serialized_size();
    }
    
    uint16_t extensions_len_net = htons(static_cast<uint16_t>(extensions_size));
    copy_to_byte_buffer(ptr + offset, &extensions_len_net, 2);
    offset += 2;
    
    for (const auto& ext : extensions_) {
        memory::Buffer ext_buffer(ext.serialized_size());
        auto ext_result = ext.serialize(ext_buffer);
        if (!ext_result.is_success()) {
            return Result<size_t>(ext_result.error());
        }
        copy_to_byte_buffer(ptr + offset, ext_buffer.data(), ext_buffer.size());
        offset += ext_buffer.size();
    }
    
    return Result<size_t>(total_size);
}

bool ClientHello::is_valid() const {
    // Check basic constraints
    if (legacy_session_id_.size() > 32) return false;
    if (cookie_.size() > 255) return false;
    if (cipher_suites_.empty()) return false;
    if (legacy_compression_methods_.empty()) return false;
    
    // Must include null compression method
    if (std::find(legacy_compression_methods_.begin(), 
                  legacy_compression_methods_.end(), 0) == legacy_compression_methods_.end()) {
        return false;
    }
    
    return true;
}

size_t ClientHello::serialized_size() const {
    size_t size = 2 + 32 + 1 + legacy_session_id_.size() + 1 + cookie_.size() + 
                  2 + (cipher_suites_.size() * 2) + 1 + legacy_compression_methods_.size() + 2;
    
    for (const auto& ext : extensions_) {
        size += ext.serialized_size();
    }
    
    return size;
}

std::optional<Extension> ClientHello::get_extension(ExtensionType type) const {
    auto it = std::find_if(extensions_.begin(), extensions_.end(),
        [type](const Extension& ext) { return ext.type == type; });
    
    if (it != extensions_.end()) {
        return *it;
    }
    return std::nullopt;
}

bool ClientHello::has_extension(ExtensionType type) const {
    return get_extension(type).has_value();
}

// ServerHello implementation
ServerHello::ServerHello()
    : legacy_version_(ProtocolVersion::DTLS_1_2)
    , cipher_suite_(CipherSuite::TLS_AES_128_GCM_SHA256)
    , legacy_compression_method_(0)
{
    // Initialize random
    auto random_result = create_random();
    if (random_result.is_success()) {
        memory::Buffer rand_buf = std::move(random_result.value());
        if (rand_buf.size() >= 32) {
            std::memcpy(random_.data(), rand_buf.data(), 32);
        }
    }
}

Result<size_t> ServerHello::serialize(memory::Buffer& buffer) const {
    if (!is_valid()) {
        return Result<size_t>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    size_t total_size = serialized_size();
    if (buffer.capacity() < total_size) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    std::byte* ptr = buffer.mutable_data();
    size_t offset = 0;
    
    // Legacy version (2 bytes)
    uint16_t version_net = htons(static_cast<uint16_t>(legacy_version_));
    copy_to_byte_buffer(ptr + offset, &version_net, 2);
    offset += 2;
    
    // Random (32 bytes)
    copy_to_byte_buffer(ptr + offset, random_.data(), 32);
    offset += 32;
    
    // Legacy session ID echo
    uint8_t session_id_len = static_cast<uint8_t>(legacy_session_id_echo_.size());
    ptr[offset++] = static_cast<std::byte>(session_id_len);
    if (session_id_len > 0) {
        copy_to_byte_buffer(ptr + offset, legacy_session_id_echo_.data(), session_id_len);
        offset += session_id_len;
    }
    
    // Cipher suite (2 bytes)
    uint16_t suite_net = htons(static_cast<uint16_t>(cipher_suite_));
    copy_to_byte_buffer(ptr + offset, &suite_net, 2);
    offset += 2;
    
    // Legacy compression method (1 byte)
    ptr[offset++] = static_cast<std::byte>(legacy_compression_method_);
    
    // Extensions
    size_t extensions_size = 0;
    for (const auto& ext : extensions_) {
        extensions_size += ext.serialized_size();
    }
    
    uint16_t extensions_len_net = htons(static_cast<uint16_t>(extensions_size));
    copy_to_byte_buffer(ptr + offset, &extensions_len_net, 2);
    offset += 2;
    
    for (const auto& ext : extensions_) {
        memory::Buffer ext_buffer(ext.serialized_size());
        auto ext_result = ext.serialize(ext_buffer);
        if (!ext_result.is_success()) {
            return Result<size_t>(ext_result.error());
        }
        copy_to_byte_buffer(ptr + offset, ext_buffer.data(), ext_buffer.size());
        offset += ext_buffer.size();
    }
    
    return Result<size_t>(total_size);
}

bool ServerHello::is_valid() const {
    if (legacy_session_id_echo_.size() > 32) return false;
    if (legacy_compression_method_ != 0) return false; // Must be null compression
    
    return true;
}

size_t ServerHello::serialized_size() const {
    size_t size = 2 + 32 + 1 + legacy_session_id_echo_.size() + 2 + 1 + 2;
    
    for (const auto& ext : extensions_) {
        size += ext.serialized_size();
    }
    
    return size;
}

std::optional<Extension> ServerHello::get_extension(ExtensionType type) const {
    auto it = std::find_if(extensions_.begin(), extensions_.end(),
        [type](const Extension& ext) { return ext.type == type; });
    
    if (it != extensions_.end()) {
        return *it;
    }
    return std::nullopt;
}

bool ServerHello::has_extension(ExtensionType type) const {
    return get_extension(type).has_value();
}

// CertificateVerify implementation
Result<size_t> CertificateVerify::serialize(memory::Buffer& buffer) const {
    if (!is_valid()) {
        return Result<size_t>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    size_t total_size = serialized_size();
    if (buffer.capacity() < total_size) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    std::byte* ptr = buffer.mutable_data();
    size_t offset = 0;
    
    // Algorithm (2 bytes)
    uint16_t algorithm_net = htons(static_cast<uint16_t>(algorithm_));
    copy_to_byte_buffer(ptr + offset, &algorithm_net, 2);
    offset += 2;
    
    // Signature length (2 bytes)
    uint16_t sig_len_net = htons(static_cast<uint16_t>(signature_.size()));
    copy_to_byte_buffer(ptr + offset, &sig_len_net, 2);
    offset += 2;
    
    // Signature
    if (signature_.size() > 0) {
        copy_to_byte_buffer(ptr + offset, signature_.data(), signature_.size());
    }
    
    return Result<size_t>(total_size);
}

bool CertificateVerify::is_valid() const {
    return signature_.size() > 0 && signature_.size() <= 65535;
}

size_t CertificateVerify::serialized_size() const {
    return 4 + signature_.size();
}

// Finished implementation
Result<size_t> Finished::serialize(memory::Buffer& buffer) const {
    if (!is_valid()) {
        return Result<size_t>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    size_t total_size = verify_data_.size();
    if (buffer.capacity() < total_size) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    if (verify_data_.size() > 0) {
        copy_to_byte_buffer(buffer.mutable_data(), verify_data_.data(), verify_data_.size());
    }
    
    return Result<size_t>(total_size);
}

bool Finished::is_valid() const {
    // Verify data should be hash length (typically 32 or 48 bytes)
    return verify_data_.size() >= 12 && verify_data_.size() <= 64;
}

size_t Finished::serialized_size() const {
    return verify_data_.size();
}

// Utility functions
bool is_supported_cipher_suite(CipherSuite suite) {
    switch (suite) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384:
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_AES_128_CCM_8_SHA256:
            return true;
        default:
            return false;
    }
}

bool is_supported_signature_scheme(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::RSA_PSS_RSAE_SHA256:
        case SignatureScheme::RSA_PSS_RSAE_SHA384:
        case SignatureScheme::RSA_PSS_RSAE_SHA512:
        case SignatureScheme::ECDSA_SECP256R1_SHA256:
        case SignatureScheme::ECDSA_SECP384R1_SHA384:
        case SignatureScheme::ECDSA_SECP521R1_SHA512:
        case SignatureScheme::ED25519:
        case SignatureScheme::ED448:
            return true;
        default:
            return false;
    }
}

bool is_supported_named_group(NamedGroup group) {
    switch (group) {
        case NamedGroup::SECP256R1:
        case NamedGroup::SECP384R1:
        case NamedGroup::SECP521R1:
        case NamedGroup::X25519:
        case NamedGroup::X448:
            return true;
        default:
            return false;
    }
}

bool requires_certificate(CipherSuite suite) {
    // All DTLS 1.3 cipher suites require certificates for authentication
    return is_supported_cipher_suite(suite);
}

Result<memory::Buffer> create_random() {
    memory::Buffer random_buffer(32);
    auto resize_result = random_buffer.resize(32);
    if (!resize_result.is_success()) {
        return Result<memory::Buffer>(resize_result.error());
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    for (size_t i = 0; i < 32; ++i) {
        random_buffer.mutable_data()[i] = static_cast<std::byte>(dis(gen));
    }
    
    return Result<memory::Buffer>(std::move(random_buffer));
}

Result<Extension> create_supported_versions_extension(const std::vector<ProtocolVersion>& versions) {
    memory::Buffer data(1 + versions.size() * 2);
    auto resize_result = data.resize(1 + versions.size() * 2);
    if (!resize_result.is_success()) {
        return Result<Extension>(resize_result.error());
    }
    
    std::byte* ptr = data.mutable_data();
    size_t offset = 0;
    
    // Length of version list
    ptr[offset++] = static_cast<std::byte>(versions.size() * 2);
    
    // Version list
    for (ProtocolVersion version : versions) {
        uint16_t version_net = htons(static_cast<uint16_t>(version));
        copy_to_byte_buffer(ptr + offset, &version_net, 2);
        offset += 2;
    }
    
    return Result<Extension>(Extension(ExtensionType::SUPPORTED_VERSIONS, std::move(data)));
}

}  // namespace dtls::v13::protocol