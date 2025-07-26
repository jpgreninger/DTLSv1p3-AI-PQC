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

// HelloRetryRequest implementation
HelloRetryRequest::HelloRetryRequest()
    : legacy_version_(ProtocolVersion::DTLS_1_2)
    , random_(HELLO_RETRY_REQUEST_RANDOM)
    , cipher_suite_(CipherSuite::TLS_AES_128_GCM_SHA256)
    , legacy_compression_method_(0)
{
    // HelloRetryRequest uses the special fixed random value
    // No need to generate random as it's set in the initializer list
}

void HelloRetryRequest::set_cookie(const memory::Buffer& cookie) {
    // Remove existing cookie extension if present
    extensions_.erase(
        std::remove_if(extensions_.begin(), extensions_.end(),
            [](const Extension& ext) { return ext.type == ExtensionType::COOKIE; }),
        extensions_.end());
    
    // Add new cookie extension
    auto cookie_ext_result = create_cookie_extension(cookie);
    if (cookie_ext_result.is_success()) {
        extensions_.push_back(std::move(cookie_ext_result.value()));
    }
}

void HelloRetryRequest::set_selected_group(NamedGroup group) {
    // Remove existing key_share extension if present
    extensions_.erase(
        std::remove_if(extensions_.begin(), extensions_.end(),
            [](const Extension& ext) { return ext.type == ExtensionType::KEY_SHARE; }),
        extensions_.end());
    
    // Add new key_share extension with selected group
    auto key_share_ext_result = create_key_share_hello_retry_request_extension(group);
    if (key_share_ext_result.is_success()) {
        extensions_.push_back(std::move(key_share_ext_result.value()));
    }
}

std::optional<memory::Buffer> HelloRetryRequest::get_cookie() const {
    auto cookie_ext = get_extension(ExtensionType::COOKIE);
    if (!cookie_ext.has_value()) {
        return std::nullopt;
    }
    
    auto cookie_result = extract_cookie_from_extension(cookie_ext.value());
    if (!cookie_result.is_success()) {
        return std::nullopt;
    }
    
    return cookie_result.value();
}

std::optional<NamedGroup> HelloRetryRequest::get_selected_group() const {
    auto key_share_ext = get_extension(ExtensionType::KEY_SHARE);
    if (!key_share_ext.has_value()) {
        return std::nullopt;
    }
    
    auto group_result = extract_selected_group_from_extension(key_share_ext.value());
    if (!group_result.is_success()) {
        return std::nullopt;
    }
    
    return group_result.value();
}

Result<size_t> HelloRetryRequest::serialize(memory::Buffer& buffer) const {
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
    
    // Random (32 bytes) - always the special HelloRetryRequest value
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

Result<HelloRetryRequest> HelloRetryRequest::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 38) { // Minimum size: version(2) + random(32) + session_id_len(1) + cipher_suite(2) + compression(1)
        return Result<HelloRetryRequest>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    HelloRetryRequest hello_retry_request;
    size_t pos = 0;
    
    // Legacy version (2 bytes)
    uint16_t version_net;
    copy_from_byte_buffer(&version_net, ptr + pos, 2);
    hello_retry_request.legacy_version_ = static_cast<ProtocolVersion>(ntohs(version_net));
    pos += 2;
    
    // Random (32 bytes) - must be the special HelloRetryRequest value
    copy_from_byte_buffer(hello_retry_request.random_.data(), ptr + pos, 32);
    pos += 32;
    
    // Validate that this is actually a HelloRetryRequest by checking the random value
    if (!is_hello_retry_request_random(hello_retry_request.random_)) {
        return Result<HelloRetryRequest>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    // Legacy session ID echo
    uint8_t session_id_len = static_cast<uint8_t>(ptr[pos++]);
    if (buffer.size() < offset + pos + session_id_len) {
        return Result<HelloRetryRequest>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    if (session_id_len > 0) {
        hello_retry_request.legacy_session_id_echo_ = memory::Buffer(session_id_len);
        auto resize_result = hello_retry_request.legacy_session_id_echo_.resize(session_id_len);
        if (!resize_result.is_success()) {
            return Result<HelloRetryRequest>(resize_result.error());
        }
        copy_to_byte_buffer(hello_retry_request.legacy_session_id_echo_.mutable_data(), ptr + pos, session_id_len);
        pos += session_id_len;
    }
    
    // Cipher suite (2 bytes)
    if (buffer.size() < offset + pos + 2) {
        return Result<HelloRetryRequest>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint16_t suite_net;
    copy_from_byte_buffer(&suite_net, ptr + pos, 2);
    hello_retry_request.cipher_suite_ = static_cast<CipherSuite>(ntohs(suite_net));
    pos += 2;
    
    // Legacy compression method (1 byte)
    if (buffer.size() < offset + pos + 1) {
        return Result<HelloRetryRequest>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    hello_retry_request.legacy_compression_method_ = static_cast<uint8_t>(ptr[pos++]);
    
    // Extensions length (2 bytes)
    if (buffer.size() < offset + pos + 2) {
        return Result<HelloRetryRequest>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint16_t extensions_len_net;
    copy_from_byte_buffer(&extensions_len_net, ptr + pos, 2);
    uint16_t extensions_len = ntohs(extensions_len_net);
    pos += 2;
    
    if (buffer.size() < offset + pos + extensions_len) {
        return Result<HelloRetryRequest>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Parse extensions
    size_t extensions_parsed = 0;
    while (extensions_parsed < extensions_len) {
        auto ext_result = Extension::deserialize(buffer, offset + pos + extensions_parsed);
        if (!ext_result.is_success()) {
            return Result<HelloRetryRequest>(ext_result.error());
        }
        
        Extension ext = std::move(ext_result.value());
        extensions_parsed += ext.serialized_size();
        hello_retry_request.extensions_.push_back(std::move(ext));
    }
    
    // Validate the message
    if (!hello_retry_request.is_valid()) {
        return Result<HelloRetryRequest>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<HelloRetryRequest>(std::move(hello_retry_request));
}

bool HelloRetryRequest::is_valid() const {
    // Must use the special HelloRetryRequest random value
    if (random_ != HELLO_RETRY_REQUEST_RANDOM) {
        return false;
    }
    
    if (legacy_session_id_echo_.size() > 32) return false;
    if (legacy_compression_method_ != 0) return false; // Must be null compression
    
    // HelloRetryRequest must contain cookie extension for DTLS
    if (!has_extension(ExtensionType::COOKIE)) {
        return false;
    }
    
    return true;
}

size_t HelloRetryRequest::serialized_size() const {
    size_t size = 2 + 32 + 1 + legacy_session_id_echo_.size() + 2 + 1 + 2;
    
    for (const auto& ext : extensions_) {
        size += ext.serialized_size();
    }
    
    return size;
}

std::optional<Extension> HelloRetryRequest::get_extension(ExtensionType type) const {
    for (const auto& ext : extensions_) {
        if (ext.type == type) {
            return ext;
        }
    }
    return std::nullopt;
}

bool HelloRetryRequest::has_extension(ExtensionType type) const {
    return get_extension(type).has_value();
}

bool HelloRetryRequest::is_hello_retry_request_random(const std::array<uint8_t, 32>& random) {
    return std::equal(random.begin(), random.end(), HELLO_RETRY_REQUEST_RANDOM.begin());
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

Result<Extension> create_supported_groups_extension(const std::vector<NamedGroup>& groups) {
    memory::Buffer data(2 + groups.size() * 2);
    auto resize_result = data.resize(2 + groups.size() * 2);
    if (!resize_result.is_success()) {
        return Result<Extension>(resize_result.error());
    }
    
    std::byte* ptr = data.mutable_data();
    size_t offset = 0;
    
    // Length of group list (2 bytes)
    uint16_t groups_len_net = htons(static_cast<uint16_t>(groups.size() * 2));
    copy_to_byte_buffer(ptr + offset, &groups_len_net, 2);
    offset += 2;
    
    // Group list
    for (NamedGroup group : groups) {
        uint16_t group_net = htons(static_cast<uint16_t>(group));
        copy_to_byte_buffer(ptr + offset, &group_net, 2);
        offset += 2;
    }
    
    return Result<Extension>(Extension(ExtensionType::SUPPORTED_GROUPS, std::move(data)));
}

Result<Extension> create_signature_algorithms_extension(const std::vector<SignatureScheme>& schemes) {
    memory::Buffer data(2 + schemes.size() * 2);
    auto resize_result = data.resize(2 + schemes.size() * 2);
    if (!resize_result.is_success()) {
        return Result<Extension>(resize_result.error());
    }
    
    std::byte* ptr = data.mutable_data();
    size_t offset = 0;
    
    // Length of scheme list (2 bytes)
    uint16_t schemes_len_net = htons(static_cast<uint16_t>(schemes.size() * 2));
    copy_to_byte_buffer(ptr + offset, &schemes_len_net, 2);
    offset += 2;
    
    // Scheme list
    for (SignatureScheme scheme : schemes) {
        uint16_t scheme_net = htons(static_cast<uint16_t>(scheme));
        copy_to_byte_buffer(ptr + offset, &scheme_net, 2);
        offset += 2;
    }
    
    return Result<Extension>(Extension(ExtensionType::SIGNATURE_ALGORITHMS, std::move(data)));
}

// ClientHello deserialize implementation
Result<ClientHello> ClientHello::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 34) { // Minimum size: version(2) + random(32)
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    ClientHello client_hello;
    size_t pos = 0;
    
    // Legacy version (2 bytes)
    uint16_t version_net;
    copy_from_byte_buffer(&version_net, ptr + pos, 2);
    client_hello.legacy_version_ = static_cast<ProtocolVersion>(ntohs(version_net));
    pos += 2;
    
    // Random (32 bytes)
    copy_from_byte_buffer(client_hello.random_.data(), ptr + pos, 32);
    pos += 32;
    
    // Legacy session ID
    if (buffer.size() < offset + pos + 1) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint8_t session_id_len = static_cast<uint8_t>(ptr[pos++]);
    if (buffer.size() < offset + pos + session_id_len) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    if (session_id_len > 0) {
        client_hello.legacy_session_id_ = memory::Buffer(session_id_len);
        auto resize_result = client_hello.legacy_session_id_.resize(session_id_len);
        if (!resize_result.is_success()) {
            return Result<ClientHello>(resize_result.error());
        }
        copy_to_byte_buffer(client_hello.legacy_session_id_.mutable_data(), ptr + pos, session_id_len);
        pos += session_id_len;
    }
    
    // Cookie (DTLS-specific)
    if (buffer.size() < offset + pos + 1) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint8_t cookie_len = static_cast<uint8_t>(ptr[pos++]);
    if (buffer.size() < offset + pos + cookie_len) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    if (cookie_len > 0) {
        client_hello.cookie_ = memory::Buffer(cookie_len);
        auto resize_result = client_hello.cookie_.resize(cookie_len);
        if (!resize_result.is_success()) {
            return Result<ClientHello>(resize_result.error());
        }
        copy_to_byte_buffer(client_hello.cookie_.mutable_data(), ptr + pos, cookie_len);
        pos += cookie_len;
    }
    
    // Cipher suites
    if (buffer.size() < offset + pos + 2) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint16_t cipher_suites_len_net;
    copy_from_byte_buffer(&cipher_suites_len_net, ptr + pos, 2);
    uint16_t cipher_suites_len = ntohs(cipher_suites_len_net);
    pos += 2;
    
    if (buffer.size() < offset + pos + cipher_suites_len || cipher_suites_len % 2 != 0) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    size_t num_cipher_suites = cipher_suites_len / 2;
    client_hello.cipher_suites_.reserve(num_cipher_suites);
    
    for (size_t i = 0; i < num_cipher_suites; ++i) {
        uint16_t suite_net;
        copy_from_byte_buffer(&suite_net, ptr + pos, 2);
        client_hello.cipher_suites_.push_back(static_cast<CipherSuite>(ntohs(suite_net)));
        pos += 2;
    }
    
    // Legacy compression methods
    if (buffer.size() < offset + pos + 1) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint8_t compression_len = static_cast<uint8_t>(ptr[pos++]);
    if (buffer.size() < offset + pos + compression_len) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    client_hello.legacy_compression_methods_.reserve(compression_len);
    for (size_t i = 0; i < compression_len; ++i) {
        client_hello.legacy_compression_methods_.push_back(static_cast<uint8_t>(ptr[pos++]));
    }
    
    // Extensions
    if (buffer.size() < offset + pos + 2) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint16_t extensions_len_net;
    copy_from_byte_buffer(&extensions_len_net, ptr + pos, 2);
    uint16_t extensions_len = ntohs(extensions_len_net);
    pos += 2;
    
    if (buffer.size() < offset + pos + extensions_len) {
        return Result<ClientHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    size_t extensions_end = pos + extensions_len;
    while (pos < extensions_end) {
        auto ext_result = Extension::deserialize(buffer, offset + pos);
        if (!ext_result.is_success()) {
            return Result<ClientHello>(ext_result.error());
        }
        
        Extension ext = std::move(ext_result.value());
        pos += ext.serialized_size();
        client_hello.extensions_.push_back(std::move(ext));
    }
    
    if (!client_hello.is_valid()) {
        return Result<ClientHello>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<ClientHello>(std::move(client_hello));
}

// ServerHello deserialize implementation
Result<ServerHello> ServerHello::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 38) { // Minimum size: version(2) + random(32) + session_id_len(1) + cipher_suite(2) + compression(1)
        return Result<ServerHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    ServerHello server_hello;
    size_t pos = 0;
    
    // Legacy version (2 bytes)
    uint16_t version_net;
    copy_from_byte_buffer(&version_net, ptr + pos, 2);
    server_hello.legacy_version_ = static_cast<ProtocolVersion>(ntohs(version_net));
    pos += 2;
    
    // Random (32 bytes)
    copy_from_byte_buffer(server_hello.random_.data(), ptr + pos, 32);
    pos += 32;
    
    // Legacy session ID echo
    uint8_t session_id_len = static_cast<uint8_t>(ptr[pos++]);
    if (buffer.size() < offset + pos + session_id_len) {
        return Result<ServerHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    if (session_id_len > 0) {
        server_hello.legacy_session_id_echo_ = memory::Buffer(session_id_len);
        auto resize_result = server_hello.legacy_session_id_echo_.resize(session_id_len);
        if (!resize_result.is_success()) {
            return Result<ServerHello>(resize_result.error());
        }
        copy_to_byte_buffer(server_hello.legacy_session_id_echo_.mutable_data(), ptr + pos, session_id_len);
        pos += session_id_len;
    }
    
    // Cipher suite (2 bytes)
    if (buffer.size() < offset + pos + 2) {
        return Result<ServerHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint16_t suite_net;
    copy_from_byte_buffer(&suite_net, ptr + pos, 2);
    server_hello.cipher_suite_ = static_cast<CipherSuite>(ntohs(suite_net));
    pos += 2;
    
    // Legacy compression method (1 byte)
    if (buffer.size() < offset + pos + 1) {
        return Result<ServerHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    server_hello.legacy_compression_method_ = static_cast<uint8_t>(ptr[pos++]);
    
    // Extensions
    if (buffer.size() < offset + pos + 2) {
        return Result<ServerHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    uint16_t extensions_len_net;
    copy_from_byte_buffer(&extensions_len_net, ptr + pos, 2);
    uint16_t extensions_len = ntohs(extensions_len_net);
    pos += 2;
    
    if (buffer.size() < offset + pos + extensions_len) {
        return Result<ServerHello>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    size_t extensions_end = pos + extensions_len;
    while (pos < extensions_end) {
        auto ext_result = Extension::deserialize(buffer, offset + pos);
        if (!ext_result.is_success()) {
            return Result<ServerHello>(ext_result.error());
        }
        
        Extension ext = std::move(ext_result.value());
        pos += ext.serialized_size();
        server_hello.extensions_.push_back(std::move(ext));
    }
    
    if (!server_hello.is_valid()) {
        return Result<ServerHello>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<ServerHello>(std::move(server_hello));
}

// CertificateEntry implementation
Result<size_t> CertificateEntry::serialize(memory::Buffer& buffer) const {
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
    
    // Certificate data length (3 bytes, big-endian)
    uint32_t cert_len_be = htonl(static_cast<uint32_t>(cert_data.size()));
    copy_to_byte_buffer(ptr + offset, reinterpret_cast<uint8_t*>(&cert_len_be) + 1, 3);
    offset += 3;
    
    // Certificate data
    if (cert_data.size() > 0) {
        copy_to_byte_buffer(ptr + offset, cert_data.data(), cert_data.size());
        offset += cert_data.size();
    }
    
    // Extensions length (2 bytes)
    size_t extensions_size = 0;
    for (const auto& ext : extensions) {
        extensions_size += ext.serialized_size();
    }
    
    uint16_t extensions_len_net = htons(static_cast<uint16_t>(extensions_size));
    copy_to_byte_buffer(ptr + offset, &extensions_len_net, 2);
    offset += 2;
    
    // Extensions
    for (const auto& ext : extensions) {
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

Result<CertificateEntry> CertificateEntry::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 5) { // 3 bytes cert length + 2 bytes ext length
        return Result<CertificateEntry>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    CertificateEntry cert_entry;
    size_t pos = 0;
    
    // Certificate data length (3 bytes)
    uint32_t cert_len_be = 0;
    copy_from_byte_buffer(reinterpret_cast<uint8_t*>(&cert_len_be) + 1, ptr + pos, 3);
    uint32_t cert_len = ntohl(cert_len_be);
    pos += 3;
    
    if (buffer.size() < offset + pos + cert_len + 2) {
        return Result<CertificateEntry>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Certificate data
    if (cert_len > 0) {
        cert_entry.cert_data = memory::Buffer(cert_len);
        auto resize_result = cert_entry.cert_data.resize(cert_len);
        if (!resize_result.is_success()) {
            return Result<CertificateEntry>(resize_result.error());
        }
        copy_to_byte_buffer(cert_entry.cert_data.mutable_data(), ptr + pos, cert_len);
        pos += cert_len;
    }
    
    // Extensions length (2 bytes)
    uint16_t extensions_len_net;
    copy_from_byte_buffer(&extensions_len_net, ptr + pos, 2);
    uint16_t extensions_len = ntohs(extensions_len_net);
    pos += 2;
    
    if (buffer.size() < offset + pos + extensions_len) {
        return Result<CertificateEntry>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Extensions
    size_t extensions_end = pos + extensions_len;
    while (pos < extensions_end) {
        auto ext_result = Extension::deserialize(buffer, offset + pos);
        if (!ext_result.is_success()) {
            return Result<CertificateEntry>(ext_result.error());
        }
        
        Extension ext = std::move(ext_result.value());
        pos += ext.serialized_size();
        cert_entry.extensions.push_back(std::move(ext));
    }
    
    if (!cert_entry.is_valid()) {
        return Result<CertificateEntry>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<CertificateEntry>(std::move(cert_entry));
}

size_t CertificateEntry::serialized_size() const {
    size_t size = 3 + cert_data.size() + 2; // cert_len + cert_data + ext_len
    
    for (const auto& ext : extensions) {
        size += ext.serialized_size();
    }
    
    return size;
}

bool CertificateEntry::is_valid() const {
    return cert_data.size() <= 16777215; // Max 24-bit value
}

// Certificate class implementation
Result<size_t> Certificate::serialize(memory::Buffer& buffer) const {
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
    
    // Certificate request context length (1 byte)
    uint8_t context_len = static_cast<uint8_t>(certificate_request_context_.size());
    ptr[offset++] = static_cast<std::byte>(context_len);
    
    // Certificate request context
    if (context_len > 0) {
        copy_to_byte_buffer(ptr + offset, certificate_request_context_.data(), context_len);
        offset += context_len;
    }
    
    // Certificate list length (3 bytes)
    size_t cert_list_size = 0;
    for (const auto& cert : certificate_list_) {
        cert_list_size += cert.serialized_size();
    }
    
    uint32_t cert_list_len_be = htonl(static_cast<uint32_t>(cert_list_size));
    copy_to_byte_buffer(ptr + offset, reinterpret_cast<uint8_t*>(&cert_list_len_be) + 1, 3);
    offset += 3;
    
    // Certificate list
    for (const auto& cert : certificate_list_) {
        memory::Buffer cert_buffer(cert.serialized_size());
        auto cert_result = cert.serialize(cert_buffer);
        if (!cert_result.is_success()) {
            return Result<size_t>(cert_result.error());
        }
        copy_to_byte_buffer(ptr + offset, cert_buffer.data(), cert_buffer.size());
        offset += cert_buffer.size();
    }
    
    return Result<size_t>(total_size);
}

Result<Certificate> Certificate::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 4) { // 1 byte context len + 3 bytes cert list len
        return Result<Certificate>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    Certificate certificate;
    size_t pos = 0;
    
    // Certificate request context length
    uint8_t context_len = static_cast<uint8_t>(ptr[pos++]);
    if (buffer.size() < offset + pos + context_len + 3) {
        return Result<Certificate>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Certificate request context
    if (context_len > 0) {
        certificate.certificate_request_context_ = memory::Buffer(context_len);
        auto resize_result = certificate.certificate_request_context_.resize(context_len);
        if (!resize_result.is_success()) {
            return Result<Certificate>(resize_result.error());
        }
        copy_to_byte_buffer(certificate.certificate_request_context_.mutable_data(), ptr + pos, context_len);
        pos += context_len;
    }
    
    // Certificate list length (3 bytes)
    uint32_t cert_list_len_be = 0;
    copy_from_byte_buffer(reinterpret_cast<uint8_t*>(&cert_list_len_be) + 1, ptr + pos, 3);
    uint32_t cert_list_len = ntohl(cert_list_len_be);
    pos += 3;
    
    if (buffer.size() < offset + pos + cert_list_len) {
        return Result<Certificate>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Certificate list
    size_t cert_list_end = pos + cert_list_len;
    while (pos < cert_list_end) {
        auto cert_result = CertificateEntry::deserialize(buffer, offset + pos);
        if (!cert_result.is_success()) {
            return Result<Certificate>(cert_result.error());
        }
        
        CertificateEntry cert = std::move(cert_result.value());
        pos += cert.serialized_size();
        certificate.certificate_list_.push_back(std::move(cert));
    }
    
    if (!certificate.is_valid()) {
        return Result<Certificate>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<Certificate>(std::move(certificate));
}

bool Certificate::is_valid() const {
    return certificate_request_context_.size() <= 255;
}

size_t Certificate::serialized_size() const {
    size_t size = 1 + certificate_request_context_.size() + 3; // context_len + context + cert_list_len
    
    for (const auto& cert : certificate_list_) {
        size += cert.serialized_size();
    }
    
    return size;
}

// CertificateVerify deserialize implementation
Result<CertificateVerify> CertificateVerify::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 4) { // 2 bytes algorithm + 2 bytes signature length
        return Result<CertificateVerify>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    CertificateVerify cert_verify;
    size_t pos = 0;
    
    // Algorithm (2 bytes)
    uint16_t algorithm_net;
    copy_from_byte_buffer(&algorithm_net, ptr + pos, 2);
    cert_verify.algorithm_ = static_cast<SignatureScheme>(ntohs(algorithm_net));
    pos += 2;
    
    // Signature length (2 bytes)
    uint16_t sig_len_net;
    copy_from_byte_buffer(&sig_len_net, ptr + pos, 2);
    uint16_t sig_len = ntohs(sig_len_net);
    pos += 2;
    
    if (buffer.size() < offset + pos + sig_len) {
        return Result<CertificateVerify>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Signature
    if (sig_len > 0) {
        cert_verify.signature_ = memory::Buffer(sig_len);
        auto resize_result = cert_verify.signature_.resize(sig_len);
        if (!resize_result.is_success()) {
            return Result<CertificateVerify>(resize_result.error());
        }
        copy_to_byte_buffer(cert_verify.signature_.mutable_data(), ptr + pos, sig_len);
    }
    
    if (!cert_verify.is_valid()) {
        return Result<CertificateVerify>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<CertificateVerify>(std::move(cert_verify));
}

// Finished deserialize implementation
Result<Finished> Finished::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() <= offset) {
        return Result<Finished>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    size_t verify_data_len = buffer.size() - offset;
    Finished finished;
    
    if (verify_data_len > 0) {
        finished.verify_data_ = memory::Buffer(verify_data_len);
        auto resize_result = finished.verify_data_.resize(verify_data_len);
        if (!resize_result.is_success()) {
            return Result<Finished>(resize_result.error());
        }
        copy_to_byte_buffer(finished.verify_data_.mutable_data(), buffer.data() + offset, verify_data_len);
    }
    
    if (!finished.is_valid()) {
        return Result<Finished>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<Finished>(std::move(finished));
}

// HandshakeMessage implementation
Result<size_t> HandshakeMessage::serialize(memory::Buffer& buffer) const {
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
    
    // Serialize header
    memory::Buffer header_buffer(HandshakeHeader::SERIALIZED_SIZE);
    auto header_result = header_.serialize(header_buffer);
    if (!header_result.is_success()) {
        return Result<size_t>(header_result.error());
    }
    
    copy_to_byte_buffer(buffer.mutable_data(), header_buffer.data(), HandshakeHeader::SERIALIZED_SIZE);
    
    // Serialize message payload
    memory::Buffer payload_buffer(total_size - HandshakeHeader::SERIALIZED_SIZE);
    size_t payload_size = 0;
    
    std::visit([&](const auto& msg) {
        auto msg_result = msg.serialize(payload_buffer);
        if (msg_result.is_success()) {
            payload_size = msg_result.value();
        }
    }, message_);
    
    if (payload_size > 0) {
        copy_to_byte_buffer(buffer.mutable_data() + HandshakeHeader::SERIALIZED_SIZE, 
                           payload_buffer.data(), payload_size);
    }
    
    return Result<size_t>(total_size);
}

Result<HandshakeMessage> HandshakeMessage::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + HandshakeHeader::SERIALIZED_SIZE) {
        return Result<HandshakeMessage>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Deserialize header
    auto header_result = HandshakeHeader::deserialize(buffer, offset);
    if (!header_result.is_success()) {
        return Result<HandshakeMessage>(header_result.error());
    }
    
    HandshakeHeader header = std::move(header_result.value());
    size_t payload_offset = offset + HandshakeHeader::SERIALIZED_SIZE;
    
    // Deserialize message based on type
    HandshakeMessage handshake_msg;
    handshake_msg.header_ = header;
    
    switch (header.msg_type) {
        case HandshakeType::CLIENT_HELLO: {
            auto msg_result = ClientHello::deserialize(buffer, payload_offset);
            if (!msg_result.is_success()) {
                return Result<HandshakeMessage>(msg_result.error());
            }
            handshake_msg.message_ = std::move(msg_result.value());
            break;
        }
        case HandshakeType::SERVER_HELLO: {
            auto msg_result = ServerHello::deserialize(buffer, payload_offset);
            if (!msg_result.is_success()) {
                return Result<HandshakeMessage>(msg_result.error());
            }
            handshake_msg.message_ = std::move(msg_result.value());
            break;
        }
        case HandshakeType::HELLO_RETRY_REQUEST: {
            auto msg_result = HelloRetryRequest::deserialize(buffer, payload_offset);
            if (!msg_result.is_success()) {
                return Result<HandshakeMessage>(msg_result.error());
            }
            handshake_msg.message_ = std::move(msg_result.value());
            break;
        }
        case HandshakeType::CERTIFICATE: {
            auto msg_result = Certificate::deserialize(buffer, payload_offset);
            if (!msg_result.is_success()) {
                return Result<HandshakeMessage>(msg_result.error());
            }
            handshake_msg.message_ = std::move(msg_result.value());
            break;
        }
        case HandshakeType::CERTIFICATE_VERIFY: {
            auto msg_result = CertificateVerify::deserialize(buffer, payload_offset);
            if (!msg_result.is_success()) {
                return Result<HandshakeMessage>(msg_result.error());
            }
            handshake_msg.message_ = std::move(msg_result.value());
            break;
        }
        case HandshakeType::FINISHED: {
            auto msg_result = Finished::deserialize(buffer, payload_offset);
            if (!msg_result.is_success()) {
                return Result<HandshakeMessage>(msg_result.error());
            }
            handshake_msg.message_ = std::move(msg_result.value());
            break;
        }
        case HandshakeType::ACK: {
            auto msg_result = ACK::deserialize(buffer, payload_offset);
            if (!msg_result.is_success()) {
                return Result<HandshakeMessage>(msg_result.error());
            }
            handshake_msg.message_ = std::move(msg_result.value());
            break;
        }
        default:
            return Result<HandshakeMessage>(DTLSError::UNSUPPORTED_HANDSHAKE_TYPE);
    }
    
    if (!handshake_msg.is_valid()) {
        return Result<HandshakeMessage>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<HandshakeMessage>(std::move(handshake_msg));
}

bool HandshakeMessage::is_valid() const {
    if (!header_.is_valid()) {
        return false;
    }
    
    // Validate message content matches header type
    bool valid_variant = std::visit([this](const auto& msg) -> bool {
        using T = std::decay_t<decltype(msg)>;
        return header_.msg_type == get_handshake_type<T>() && msg.is_valid();
    }, message_);
    
    return valid_variant;
}

size_t HandshakeMessage::serialized_size() const {
    size_t payload_size = std::visit([](const auto& msg) {
        return msg.serialized_size();
    }, message_);
    
    return HandshakeHeader::SERIALIZED_SIZE + payload_size;
}

// ACKRange implementation
Result<size_t> ACKRange::serialize(memory::Buffer& buffer) const {
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
    
    // Start sequence (3 bytes - 24-bit big-endian)
    uint32_t start_net = htonl(start_sequence);
    copy_to_byte_buffer(ptr + offset, reinterpret_cast<const std::byte*>(&start_net) + 1, 3);
    offset += 3;
    
    // End sequence (3 bytes - 24-bit big-endian)
    uint32_t end_net = htonl(end_sequence);
    copy_to_byte_buffer(ptr + offset, reinterpret_cast<const std::byte*>(&end_net) + 1, 3);
    offset += 3;
    
    return Result<size_t>(total_size);
}

Result<ACKRange> ACKRange::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 6) { // 3 + 3 bytes
        return Result<ACKRange>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    
    // Start sequence (3 bytes)
    uint32_t start_net = 0;
    copy_from_byte_buffer(reinterpret_cast<std::byte*>(&start_net) + 1, ptr, 3);
    uint32_t start = ntohl(start_net);
    ptr += 3;
    
    // End sequence (3 bytes)
    uint32_t end_net = 0;
    copy_from_byte_buffer(reinterpret_cast<std::byte*>(&end_net) + 1, ptr, 3);
    uint32_t end = ntohl(end_net);
    
    ACKRange range(start, end);
    
    if (!range.is_valid()) {
        return Result<ACKRange>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<ACKRange>(std::move(range));
}

bool ACKRange::is_valid() const {
    // Check 24-bit limits (0 to 2^24-1)
    return start_sequence <= 0xFFFFFF && 
           end_sequence <= 0xFFFFFF && 
           start_sequence <= end_sequence;
}

// ACK implementation
void ACK::acknowledge_sequence(uint32_t sequence) {
    // Find if sequence fits in any existing range
    for (auto& range : ack_ranges_) {
        if (range.contains(sequence)) {
            return; // Already acknowledged
        }
        
        // Check if we can extend an existing range
        if (sequence == range.start_sequence - 1) {
            range.start_sequence = sequence;
            optimize_ranges();
            return;
        }
        if (sequence == range.end_sequence + 1) {
            range.end_sequence = sequence;
            optimize_ranges();
            return;
        }
    }
    
    // Add new single-sequence range
    ack_ranges_.emplace_back(sequence, sequence);
    optimize_ranges();
}

void ACK::acknowledge_range(uint32_t start, uint32_t end) {
    if (start > end) return;
    
    ack_ranges_.emplace_back(start, end);
    optimize_ranges();
}

bool ACK::is_sequence_acknowledged(uint32_t sequence) const {
    for (const auto& range : ack_ranges_) {
        if (range.contains(sequence)) {
            return true;
        }
    }
    return false;
}

void ACK::optimize_ranges() {
    if (ack_ranges_.size() <= 1) return;
    
    // Sort ranges by start sequence
    std::sort(ack_ranges_.begin(), ack_ranges_.end());
    
    // Merge overlapping and adjacent ranges
    std::vector<ACKRange> merged;
    merged.reserve(ack_ranges_.size());
    
    merged.push_back(ack_ranges_[0]);
    
    for (size_t i = 1; i < ack_ranges_.size(); ++i) {
        ACKRange& last = merged.back();
        const ACKRange& current = ack_ranges_[i];
        
        // Check if ranges overlap or are adjacent
        if (current.start_sequence <= last.end_sequence + 1) {
            // Merge ranges
            last.end_sequence = std::max(last.end_sequence, current.end_sequence);
        } else {
            // Non-overlapping, add new range
            merged.push_back(current);
        }
    }
    
    ack_ranges_ = std::move(merged);
}

Result<size_t> ACK::serialize(memory::Buffer& buffer) const {
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
    
    // ACK ranges length (2 bytes)
    uint16_t ranges_length = static_cast<uint16_t>(ack_ranges_.size() * 6); // 6 bytes per range
    uint16_t length_net = htons(ranges_length);
    copy_to_byte_buffer(ptr + offset, &length_net, 2);
    offset += 2;
    
    // Serialize each ACK range
    for (const auto& range : ack_ranges_) {
        memory::Buffer range_buffer(6);
        auto range_result = range.serialize(range_buffer);
        if (!range_result.is_success()) {
            return Result<size_t>(range_result.error());
        }
        
        copy_to_byte_buffer(ptr + offset, range_buffer.data(), 6);
        offset += 6;
    }
    
    return Result<size_t>(total_size);
}

Result<ACK> ACK::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 2) {
        return Result<ACK>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* ptr = buffer.data() + offset;
    
    // Read ranges length (2 bytes)
    uint16_t ranges_length_net;
    copy_from_byte_buffer(&ranges_length_net, ptr, 2);
    uint16_t ranges_length = ntohs(ranges_length_net);
    ptr += 2;
    
    if (ranges_length % 6 != 0) {
        return Result<ACK>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    size_t num_ranges = ranges_length / 6;
    if (buffer.size() < offset + 2 + ranges_length) {
        return Result<ACK>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    std::vector<ACKRange> ranges;
    ranges.reserve(num_ranges);
    
    size_t range_offset = offset + 2;
    for (size_t i = 0; i < num_ranges; ++i) {
        auto range_result = ACKRange::deserialize(buffer, range_offset);
        if (!range_result.is_success()) {
            return Result<ACK>(range_result.error());
        }
        
        ranges.push_back(std::move(range_result.value()));
        range_offset += 6;
    }
    
    ACK ack(std::move(ranges));
    
    if (!ack.is_valid()) {
        return Result<ACK>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<ACK>(std::move(ack));
}

bool ACK::is_valid() const {
    // Check maximum number of ranges (64KB / 6 bytes per range)
    if (ack_ranges_.size() > 10922) { // 65535 / 6
        return false;
    }
    
    // Check that all ranges are valid
    for (const auto& range : ack_ranges_) {
        if (!range.is_valid()) {
            return false;
        }
    }
    
    // Check for overlapping ranges (should be optimized)
    for (size_t i = 0; i < ack_ranges_.size(); ++i) {
        for (size_t j = i + 1; j < ack_ranges_.size(); ++j) {
            if (ack_ranges_[i].overlaps(ack_ranges_[j])) {
                return false;
            }
        }
    }
    
    return true;
}

size_t ACK::serialized_size() const {
    return 2 + (ack_ranges_.size() * 6); // 2 bytes length + 6 bytes per range
}

// ACK utility functions implementation
Result<ACK> create_ack_message(const std::vector<uint32_t>& acknowledged_sequences) {
    if (acknowledged_sequences.empty()) {
        return Result<ACK>(ACK{});
    }
    
    // Sort sequences for range creation
    std::vector<uint32_t> sorted_sequences = acknowledged_sequences;
    std::sort(sorted_sequences.begin(), sorted_sequences.end());
    
    // Remove duplicates
    sorted_sequences.erase(std::unique(sorted_sequences.begin(), sorted_sequences.end()), 
                          sorted_sequences.end());
    
    ACK ack_message;
    
    // Create ranges from consecutive sequences
    uint32_t range_start = sorted_sequences[0];
    uint32_t range_end = sorted_sequences[0];
    
    for (size_t i = 1; i < sorted_sequences.size(); ++i) {
        if (sorted_sequences[i] == range_end + 1) {
            // Extend current range
            range_end = sorted_sequences[i];
        } else {
            // End current range and start new one
            ack_message.add_ack_range(range_start, range_end);
            range_start = sorted_sequences[i];
            range_end = sorted_sequences[i];
        }
    }
    
    // Add the final range
    ack_message.add_ack_range(range_start, range_end);
    
    if (!ack_message.is_valid()) {
        return Result<ACK>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<ACK>(std::move(ack_message));
}

Result<ACK> create_ack_message_from_ranges(const std::vector<std::pair<uint32_t, uint32_t>>& ranges) {
    ACK ack_message;
    
    for (const auto& range_pair : ranges) {
        if (range_pair.first > range_pair.second) {
            return Result<ACK>(DTLSError::INVALID_PARAMETER);
        }
        
        ack_message.add_ack_range(range_pair.first, range_pair.second);
    }
    
    // Optimize the ranges
    ack_message.optimize_ranges();
    
    if (!ack_message.is_valid()) {
        return Result<ACK>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return Result<ACK>(std::move(ack_message));
}

bool is_ack_message_valid(const ACK& ack_message) {
    return ack_message.is_valid();
}

std::vector<uint32_t> get_missing_sequences(const ACK& ack_message, uint32_t max_sequence) {
    std::vector<uint32_t> missing_sequences;
    
    if (max_sequence == 0 || max_sequence > 0xFFFFFF) {
        return missing_sequences; // Invalid max_sequence
    }
    
    const auto& ranges = ack_message.ack_ranges();
    
    // If no ACK ranges, all sequences are missing
    if (ranges.empty()) {
        for (uint32_t seq = 0; seq <= max_sequence; ++seq) {
            missing_sequences.push_back(seq);
        }
        return missing_sequences;
    }
    
    // Sort ranges by start sequence for processing
    std::vector<ACKRange> sorted_ranges = ranges;
    std::sort(sorted_ranges.begin(), sorted_ranges.end());
    
    uint32_t current_seq = 0;
    
    for (const auto& range : sorted_ranges) {
        // Add missing sequences before this range
        while (current_seq < range.start_sequence) {
            missing_sequences.push_back(current_seq);
            ++current_seq;
        }
        
        // Skip sequences covered by this range
        current_seq = std::max(current_seq, range.end_sequence + 1);
    }
    
    // Add any remaining missing sequences after the last range
    while (current_seq <= max_sequence) {
        missing_sequences.push_back(current_seq);
        ++current_seq;
    }
    
    return missing_sequences;
}

bool should_send_ack(const std::vector<uint32_t>& received_sequences, const ACK& last_ack_sent) {
    if (received_sequences.empty()) {
        return false; // No new sequences to acknowledge
    }
    
    // Check if any received sequences are not already acknowledged
    for (uint32_t seq : received_sequences) {
        if (!last_ack_sent.is_sequence_acknowledged(seq)) {
            return true; // Found unacknowledged sequence
        }
    }
    
    return false; // All sequences already acknowledged
}

// HelloRetryRequest utility functions implementation
Result<Extension> create_cookie_extension(const memory::Buffer& cookie) {
    if (cookie.size() == 0 || cookie.size() > 65535) {
        return Result<Extension>(DTLSError::INVALID_PARAMETER);
    }
    
    // Cookie extension format: length(2 bytes) + cookie data
    memory::Buffer ext_data(2 + cookie.size());
    auto resize_result = ext_data.resize(2 + cookie.size());
    if (!resize_result.is_success()) {
        return Result<Extension>(resize_result.error());
    }
    
    std::byte* ptr = ext_data.mutable_data();
    size_t offset = 0;
    
    // Cookie length (2 bytes)
    uint16_t cookie_len_net = htons(static_cast<uint16_t>(cookie.size()));
    copy_to_byte_buffer(ptr + offset, &cookie_len_net, 2);
    offset += 2;
    
    // Cookie data
    copy_to_byte_buffer(ptr + offset, cookie.data(), cookie.size());
    
    return Result<Extension>(Extension(ExtensionType::COOKIE, std::move(ext_data)));
}

Result<Extension> create_key_share_hello_retry_request_extension(NamedGroup selected_group) {
    // Key share extension for HelloRetryRequest only contains the selected group (2 bytes)
    memory::Buffer ext_data(2);
    auto resize_result = ext_data.resize(2);
    if (!resize_result.is_success()) {
        return Result<Extension>(resize_result.error());
    }
    
    std::byte* ptr = ext_data.mutable_data();
    
    // Selected group (2 bytes)
    uint16_t group_net = htons(static_cast<uint16_t>(selected_group));
    copy_to_byte_buffer(ptr, &group_net, 2);
    
    return Result<Extension>(Extension(ExtensionType::KEY_SHARE, std::move(ext_data)));
}

Result<memory::Buffer> extract_cookie_from_extension(const Extension& cookie_ext) {
    if (cookie_ext.type != ExtensionType::COOKIE) {
        return Result<memory::Buffer>(DTLSError::INVALID_PARAMETER);
    }
    
    if (cookie_ext.data.size() < 2) {
        return Result<memory::Buffer>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    const std::byte* ptr = cookie_ext.data.data();
    
    // Read cookie length (2 bytes)
    uint16_t cookie_len_net;
    copy_from_byte_buffer(&cookie_len_net, ptr, 2);
    uint16_t cookie_len = ntohs(cookie_len_net);
    
    if (cookie_ext.data.size() != 2 + cookie_len) {
        return Result<memory::Buffer>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    // Extract cookie data
    memory::Buffer cookie(cookie_len);
    if (cookie_len > 0) {
        auto resize_result = cookie.resize(cookie_len);
        if (!resize_result.is_success()) {
            return Result<memory::Buffer>(resize_result.error());
        }
        copy_to_byte_buffer(cookie.mutable_data(), ptr + 2, cookie_len);
    }
    
    return Result<memory::Buffer>(std::move(cookie));
}

Result<NamedGroup> extract_selected_group_from_extension(const Extension& key_share_ext) {
    if (key_share_ext.type != ExtensionType::KEY_SHARE) {
        return Result<NamedGroup>(DTLSError::INVALID_PARAMETER);
    }
    
    if (key_share_ext.data.size() != 2) {
        return Result<NamedGroup>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    const std::byte* ptr = key_share_ext.data.data();
    
    // Read selected group (2 bytes)
    uint16_t group_net;
    copy_from_byte_buffer(&group_net, ptr, 2);
    NamedGroup selected_group = static_cast<NamedGroup>(ntohs(group_net));
    
    return Result<NamedGroup>(selected_group);
}

}  // namespace dtls::v13::protocol