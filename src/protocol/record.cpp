#include "dtls/protocol/record.h"
#include "dtls/error.h"
#include <algorithm>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #define htobe64(x) _byteswap_uint64(x)
    #define be64toh(x) _byteswap_uint64(x)
#else
    #include <arpa/inet.h>
    #if defined(__APPLE__)
        #include <libkern/OSByteOrder.h>
        #define htobe64(x) OSSwapHostToBigInt64(x)
        #define be64toh(x) OSSwapBigToHostInt64(x)
    #elif defined(__linux__)
        #include <endian.h>
    #else
        // Fallback implementation
        #define htobe64(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
        #define be64toh(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
    #endif
#endif

namespace dtls::v13::protocol {

// Helper function to convert uint8_t array to std::byte
inline void copy_to_byte_buffer(std::byte* dest, const void* src, size_t size) {
    std::memcpy(dest, src, size);
}

// Helper function to convert std::byte array to uint8_t
inline void copy_from_byte_buffer(void* dest, const std::byte* src, size_t size) {
    std::memcpy(dest, src, size);
}

Result<size_t> RecordHeader::serialize(memory::Buffer& buffer) const {
    if (buffer.capacity() < SERIALIZED_SIZE) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    if (!is_valid()) {
        return Result<size_t>(DTLSError::INVALID_RECORD_HEADER);
    }
    
    // Resize buffer to ensure we have space
    auto resize_result = buffer.resize(SERIALIZED_SIZE);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    std::byte* data = buffer.mutable_data();
    size_t offset = 0;
    
    // Content type (1 byte)
    data[offset++] = static_cast<std::byte>(static_cast<uint8_t>(content_type));
    
    // Protocol version (2 bytes, network byte order)
    uint16_t version_net = htons(static_cast<uint16_t>(version));
    copy_to_byte_buffer(data + offset, &version_net, 2);
    offset += 2;
    
    // Epoch (2 bytes, network byte order)
    uint16_t epoch_net = htons(epoch);
    copy_to_byte_buffer(data + offset, &epoch_net, 2);
    offset += 2;
    
    // Sequence number (6 bytes, network byte order - only lower 48 bits)
    uint64_t seq_net = htobe64(sequence_number);
    copy_to_byte_buffer(data + offset, reinterpret_cast<uint8_t*>(&seq_net) + 2, 6);
    offset += 6;
    
    // Length (2 bytes, network byte order)
    uint16_t length_net = htons(length);
    copy_to_byte_buffer(data + offset, &length_net, 2);
    offset += 2;
    
    return Result<size_t>(SERIALIZED_SIZE);
}

Result<RecordHeader> RecordHeader::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + SERIALIZED_SIZE) {
        return Result<RecordHeader>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    const std::byte* data = buffer.data() + offset;
    RecordHeader header;
    size_t pos = 0;
    
    // Content type (1 byte)
    header.content_type = static_cast<ContentType>(static_cast<uint8_t>(data[pos++]));
    
    // Protocol version (2 bytes, network byte order)
    uint16_t version_net;
    copy_from_byte_buffer(&version_net, data + pos, 2);
    header.version = static_cast<ProtocolVersion>(ntohs(version_net));
    pos += 2;
    
    // Epoch (2 bytes, network byte order)
    uint16_t epoch_net;
    copy_from_byte_buffer(&epoch_net, data + pos, 2);
    header.epoch = ntohs(epoch_net);
    pos += 2;
    
    // Sequence number (6 bytes, network byte order)
    uint64_t seq_net = 0;
    copy_from_byte_buffer(reinterpret_cast<uint8_t*>(&seq_net) + 2, data + pos, 6);
    header.sequence_number = be64toh(seq_net);
    pos += 6;
    
    // Length (2 bytes, network byte order)
    uint16_t length_net;
    copy_from_byte_buffer(&length_net, data + pos, 2);
    header.length = ntohs(length_net);
    pos += 2;
    
    if (!header.is_valid()) {
        return Result<RecordHeader>(DTLSError::INVALID_RECORD_HEADER);
    }
    
    return Result<RecordHeader>(std::move(header));
}

bool RecordHeader::is_valid() const {
    // Check content type
    if (content_type == ContentType::INVALID) {
        return false;
    }
    
    // Check protocol version
    if (version != ProtocolVersion::DTLS_1_3 && 
        version != ProtocolVersion::DTLS_1_2 &&
        version != ProtocolVersion::DTLS_1_0) {
        return false;
    }
    
    // Check length constraints (RFC 9147: maximum fragment length is 2^14)
    if (length > 16384) {
        return false;
    }
    
    return true;
}

PlaintextRecord::PlaintextRecord(ContentType content_type, ProtocolVersion version,
                               uint16_t epoch, uint64_t sequence_number,
                               memory::Buffer payload)
    : payload_(std::move(payload)) {
    header_.content_type = content_type;
    header_.version = version;
    header_.epoch = epoch;
    header_.sequence_number = sequence_number;
    header_.length = static_cast<uint16_t>(payload_.size());
}

Result<size_t> PlaintextRecord::serialize(memory::Buffer& buffer) const {
    if (!is_valid()) {
        return Result<size_t>(DTLSError::INVALID_PLAINTEXT_RECORD);
    }
    
    size_t total_size = RecordHeader::SERIALIZED_SIZE + payload_.size();
    if (buffer.capacity() < total_size) {
        return Result<size_t>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    // Resize buffer to accommodate header + payload
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return Result<size_t>(resize_result.error());
    }
    
    // Create a temporary buffer for header serialization
    memory::Buffer header_buffer(RecordHeader::SERIALIZED_SIZE);
    auto header_result = header_.serialize(header_buffer);
    if (!header_result.is_success()) {
        return header_result;
    }
    
    // Copy header to main buffer
    copy_to_byte_buffer(buffer.mutable_data(), header_buffer.data(), RecordHeader::SERIALIZED_SIZE);
    
    // Copy payload
    if (payload_.size() > 0) {
        copy_to_byte_buffer(buffer.mutable_data() + RecordHeader::SERIALIZED_SIZE, 
                           payload_.data(), payload_.size());
    }
    
    return Result<size_t>(total_size);
}

bool PlaintextRecord::is_valid() const {
    if (!header_.is_valid()) {
        return false;
    }
    
    // Check payload size matches header
    if (header_.length != payload_.size()) {
        return false;
    }
    
    return true;
}

size_t PlaintextRecord::total_size() const {
    return RecordHeader::SERIALIZED_SIZE + payload_.size();
}

// Utility functions
Result<ContentType> extract_content_type(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() <= offset) {
        return Result<ContentType>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    ContentType content_type = static_cast<ContentType>(static_cast<uint8_t>(buffer.data()[offset]));
    if (content_type == ContentType::INVALID) {
        return Result<ContentType>(DTLSError::INVALID_CONTENT_TYPE);
    }
    
    return Result<ContentType>(content_type);
}

Result<ProtocolVersion> extract_protocol_version(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 2) {
        return Result<ProtocolVersion>(DTLSError::INSUFFICIENT_BUFFER_SIZE);
    }
    
    uint16_t version_net;
    copy_from_byte_buffer(&version_net, buffer.data() + offset, 2);
    ProtocolVersion version = static_cast<ProtocolVersion>(ntohs(version_net));
    
    return Result<ProtocolVersion>(version);
}

bool is_dtls_record(const memory::Buffer& buffer, size_t min_length) {
    if (buffer.size() < min_length) {
        return false;
    }
    
    // Check if first byte looks like a valid content type
    auto content_type_result = extract_content_type(buffer, 0);
    if (!content_type_result.is_success()) {
        return false;
    }
    
    // Check if version looks valid
    auto version_result = extract_protocol_version(buffer, 1);
    if (!version_result.is_success()) {
        return false;
    }
    
    ProtocolVersion version = version_result.value();
    return (version == ProtocolVersion::DTLS_1_3 || 
            version == ProtocolVersion::DTLS_1_2 ||
            version == ProtocolVersion::DTLS_1_0);
}

}  // namespace dtls::v13::protocol