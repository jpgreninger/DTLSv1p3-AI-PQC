#include <dtls/protocol/dtls_records.h>
#include <dtls/error.h>
#include <cstring>
#include <algorithm>

namespace dtls::v13::protocol {

// SequenceNumber48 Implementation
Result<void> SequenceNumber48::serialize_to_buffer(uint8_t* buffer) const {
    if (!buffer) {
        return make_error<void>(DTLSError::INTERNAL_ERROR, "Null buffer provided");
    }
    
    // Store 48-bit value in big-endian format
    uint64_t val = value;
    buffer[0] = (val >> 40) & 0xFF;
    buffer[1] = (val >> 32) & 0xFF;
    buffer[2] = (val >> 24) & 0xFF;
    buffer[3] = (val >> 16) & 0xFF;
    buffer[4] = (val >> 8) & 0xFF;
    buffer[5] = val & 0xFF;
    
    return make_result();
}

Result<SequenceNumber48> SequenceNumber48::deserialize_from_buffer(const uint8_t* buffer) {
    if (!buffer) {
        return make_error<SequenceNumber48>(DTLSError::INTERNAL_ERROR, "Null buffer provided");
    }
    
    // Read 48-bit value from big-endian format
    uint64_t val = 0;
    val |= (static_cast<uint64_t>(buffer[0]) << 40);
    val |= (static_cast<uint64_t>(buffer[1]) << 32);
    val |= (static_cast<uint64_t>(buffer[2]) << 24);
    val |= (static_cast<uint64_t>(buffer[3]) << 16);
    val |= (static_cast<uint64_t>(buffer[4]) << 8);
    val |= static_cast<uint64_t>(buffer[5]);
    
    return make_result(SequenceNumber48(val));
}

// DTLSPlaintext Implementation
DTLSPlaintext::DTLSPlaintext(ContentType content_type, ProtocolVersion proto_version,
                             uint16_t epoch_num, SequenceNumber48 seq_num,
                             memory::ZeroCopyBuffer payload)
    : type(content_type)
    , version(proto_version)
    , epoch(epoch_num)
    , sequence_number(seq_num)
    , fragment(std::move(payload))
{
    update_length();
}

DTLSPlaintext::DTLSPlaintext(const DTLSPlaintext& other)
    : type(other.type)
    , version(other.version)
    , epoch(other.epoch)
    , sequence_number(other.sequence_number)
    , length(other.length)
{
    // Zero-copy sharing for fragment buffer
    if (other.fragment.size() > 0) {
        // Use zero-copy sharing - the ZeroCopyBuffer copy constructor handles reference counting
        fragment = other.fragment;
    }
}

DTLSPlaintext& DTLSPlaintext::operator=(const DTLSPlaintext& other) {
    if (this != &other) {
        type = other.type;
        version = other.version;
        epoch = other.epoch;
        sequence_number = other.sequence_number;
        length = other.length;
        
        // Zero-copy sharing for fragment buffer
        // The ZeroCopyBuffer assignment operator handles reference counting
        fragment = other.fragment;
    }
    return *this;
}

Result<size_t> DTLSPlaintext::serialize(memory::Buffer& buffer) const {
    size_t total_size = HEADER_SIZE + fragment.size();
    
    // Ensure buffer has enough space
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return make_error<size_t>(DTLSError::INTERNAL_ERROR, "Failed to resize buffer");
    }
    
    uint8_t* data = reinterpret_cast<uint8_t*>(buffer.mutable_data());
    size_t offset = 0;
    
    // Serialize header fields
    data[offset++] = static_cast<uint8_t>(type);
    
    // Protocol version (big-endian uint16_t)
    uint16_t version_raw = static_cast<uint16_t>(version);
    data[offset++] = (version_raw >> 8) & 0xFF;
    data[offset++] = version_raw & 0xFF;
    
    // Epoch (big-endian uint16_t)
    data[offset++] = (epoch >> 8) & 0xFF;
    data[offset++] = epoch & 0xFF;
    
    // Sequence number (48-bit, big-endian)
    auto seq_result = sequence_number.serialize_to_buffer(&data[offset]);
    if (!seq_result.is_success()) {
        return make_error<size_t>(seq_result.error(), "Failed to serialize sequence number");
    }
    offset += SequenceNumber48::SERIALIZED_SIZE;
    
    // Length (big-endian uint16_t)
    data[offset++] = (length >> 8) & 0xFF;
    data[offset++] = length & 0xFF;
    
    // Fragment data
    if (fragment.size() > 0) {
        std::memcpy(&data[offset], fragment.data(), fragment.size());
        offset += fragment.size();
    }
    
    return make_result(offset);
}

Result<DTLSPlaintext> DTLSPlaintext::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + HEADER_SIZE) {
        return make_error<DTLSPlaintext>(DTLSError::DECODE_ERROR, "Buffer too small for DTLS header");
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
    size_t pos = offset;
    
    // Deserialize header fields
    ContentType content_type = static_cast<ContentType>(data[pos++]);
    
    // Protocol version (big-endian uint16_t)
    uint16_t version_raw = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    ProtocolVersion proto_version = static_cast<ProtocolVersion>(version_raw);
    pos += 2;
    
    // Epoch (big-endian uint16_t)
    uint16_t epoch_val = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    // Sequence number (48-bit, big-endian)
    auto seq_result = SequenceNumber48::deserialize_from_buffer(&data[pos]);
    if (!seq_result.is_success()) {
        return make_error<DTLSPlaintext>(seq_result.error(), "Failed to deserialize sequence number");
    }
    SequenceNumber48 seq_num = seq_result.value();
    pos += SequenceNumber48::SERIALIZED_SIZE;
    
    // Length (big-endian uint16_t)
    uint16_t fragment_length = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    // Validate length
    if (fragment_length > MAX_FRAGMENT_LENGTH) {
        return make_error<DTLSPlaintext>(DTLSError::RECORD_OVERFLOW, "Fragment length exceeds maximum");
    }
    
    if (buffer.size() < pos + fragment_length) {
        return make_error<DTLSPlaintext>(DTLSError::DECODE_ERROR, "Buffer too small for fragment");
    }
    
    // Extract fragment
    memory::Buffer fragment_buf;
    if (fragment_length > 0) {
        fragment_buf = memory::Buffer(fragment_length);
        auto resize_result = fragment_buf.resize(fragment_length);
        if (!resize_result.is_success()) {
            return make_error<DTLSPlaintext>(DTLSError::INTERNAL_ERROR, "Failed to allocate fragment buffer");
        }
        std::memcpy(fragment_buf.mutable_data(), &data[pos], fragment_length);
    }
    
    DTLSPlaintext record(content_type, proto_version, epoch_val, seq_num, std::move(fragment_buf));
    record.length = fragment_length; // Ensure length matches what was deserialized
    
    return make_result(std::move(record));
}

bool DTLSPlaintext::is_valid() const {
    // Check content type
    if (type == ContentType::INVALID) {
        return false;
    }
    
    // Check protocol version (should be DTLS v1.3)
    if (version != ::dtls::v13::protocol::ProtocolVersion::DTLS_1_3) {
        return false;
    }
    
    // Check fragment length consistency
    if (length != fragment.size()) {
        return false;
    }
    
    // Check maximum fragment length
    if (length > MAX_FRAGMENT_LENGTH) {
        return false;
    }
    
    return true;
}

size_t DTLSPlaintext::total_size() const {
    return HEADER_SIZE + fragment.size();
}

void DTLSPlaintext::set_fragment(memory::Buffer f) {
    fragment = std::move(f);
    update_length();
}

void DTLSPlaintext::update_length() {
    length = static_cast<uint16_t>(fragment.size());
}

// DTLSCiphertext Implementation
DTLSCiphertext::DTLSCiphertext(ContentType content_type, ProtocolVersion proto_version,
                               uint16_t epoch_num, SequenceNumber48 encrypted_seq_num,
                               memory::ZeroCopyBuffer encrypted_payload)
    : type(content_type)
    , version(proto_version)
    , epoch(epoch_num)
    , encrypted_sequence_number(encrypted_seq_num)
    , encrypted_record(std::move(encrypted_payload))
    , connection_id_length(0)
    , has_connection_id(false)
{
    connection_id.fill(0);
    update_length();
}

DTLSCiphertext::DTLSCiphertext(const DTLSCiphertext& other)
    : type(other.type)
    , version(other.version)
    , epoch(other.epoch)
    , encrypted_sequence_number(other.encrypted_sequence_number)
    , length(other.length)
    , connection_id(other.connection_id)
    , connection_id_length(other.connection_id_length)
    , has_connection_id(other.has_connection_id)
{
    // Zero-copy sharing for encrypted record buffer
    if (other.encrypted_record.size() > 0) {
        // Use zero-copy sharing - the ZeroCopyBuffer copy constructor handles reference counting
        encrypted_record = other.encrypted_record;
    }
}

DTLSCiphertext& DTLSCiphertext::operator=(const DTLSCiphertext& other) {
    if (this != &other) {
        type = other.type;
        version = other.version;
        epoch = other.epoch;
        encrypted_sequence_number = other.encrypted_sequence_number;
        length = other.length;
        connection_id = other.connection_id;
        connection_id_length = other.connection_id_length;
        has_connection_id = other.has_connection_id;
        
        // Zero-copy sharing for encrypted record buffer
        // The ZeroCopyBuffer assignment operator handles reference counting
        encrypted_record = other.encrypted_record;
    }
    return *this;
}

Result<size_t> DTLSCiphertext::serialize(memory::Buffer& buffer) const {
    size_t total_size = HEADER_SIZE + encrypted_record.size();
    if (has_connection_id) {
        total_size += 1 + connection_id_length; // Length byte + CID
    }
    
    // Ensure buffer has enough space
    auto resize_result = buffer.resize(total_size);
    if (!resize_result.is_success()) {
        return make_error<size_t>(DTLSError::INTERNAL_ERROR, "Failed to resize buffer");
    }
    
    uint8_t* data = reinterpret_cast<uint8_t*>(buffer.mutable_data());
    size_t offset = 0;
    
    // Serialize header fields (same as DTLSPlaintext)
    data[offset++] = static_cast<uint8_t>(type);
    
    // Protocol version (big-endian uint16_t)
    uint16_t version_raw = static_cast<uint16_t>(version);
    data[offset++] = (version_raw >> 8) & 0xFF;
    data[offset++] = version_raw & 0xFF;
    
    // Epoch (big-endian uint16_t)
    data[offset++] = (epoch >> 8) & 0xFF;
    data[offset++] = epoch & 0xFF;
    
    // Encrypted sequence number (48-bit, big-endian)
    auto seq_result = encrypted_sequence_number.serialize_to_buffer(&data[offset]);
    if (!seq_result.is_success()) {
        return make_error<size_t>(seq_result.error(), "Failed to serialize encrypted sequence number");
    }
    offset += SequenceNumber48::SERIALIZED_SIZE;
    
    // Length (big-endian uint16_t) - includes CID if present
    uint16_t serialized_length = length;
    if (has_connection_id) {
        serialized_length += 1 + connection_id_length;
    }
    data[offset++] = (serialized_length >> 8) & 0xFF;
    data[offset++] = serialized_length & 0xFF;
    
    // Connection ID if present
    if (has_connection_id) {
        data[offset++] = connection_id_length;
        if (connection_id_length > 0) {
            std::memcpy(&data[offset], connection_id.data(), connection_id_length);
            offset += connection_id_length;
        }
    }
    
    // Encrypted record data
    if (encrypted_record.size() > 0) {
        std::memcpy(&data[offset], encrypted_record.data(), encrypted_record.size());
        offset += encrypted_record.size();
    }
    
    return make_result(offset);
}

Result<DTLSCiphertext> DTLSCiphertext::deserialize(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + HEADER_SIZE) {
        return make_error<DTLSCiphertext>(DTLSError::DECODE_ERROR, "Buffer too small for DTLS header");
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
    size_t pos = offset;
    
    // Deserialize header fields (same as DTLSPlaintext)
    ContentType content_type = static_cast<ContentType>(data[pos++]);
    
    // Protocol version (big-endian uint16_t)
    uint16_t version_raw = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    ProtocolVersion proto_version = static_cast<ProtocolVersion>(version_raw);
    pos += 2;
    
    // Epoch (big-endian uint16_t)
    uint16_t epoch_val = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    // Encrypted sequence number (48-bit, big-endian)
    auto seq_result = SequenceNumber48::deserialize_from_buffer(&data[pos]);
    if (!seq_result.is_success()) {
        return make_error<DTLSCiphertext>(seq_result.error(), "Failed to deserialize encrypted sequence number");
    }
    SequenceNumber48 encrypted_seq_num = seq_result.value();
    pos += SequenceNumber48::SERIALIZED_SIZE;
    
    // Length (big-endian uint16_t)
    uint16_t total_length = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    // Validate total buffer size
    if (buffer.size() < pos + total_length) {
        return make_error<DTLSCiphertext>(DTLSError::DECODE_ERROR, "Buffer too small for encrypted record");
    }
    
    DTLSCiphertext record;
    record.type = content_type;
    record.version = proto_version;
    record.epoch = epoch_val;
    record.encrypted_sequence_number = encrypted_seq_num;
    
    // Check if Connection ID is present (heuristic: if type is not application_data for encrypted record)
    // In practice, we'd need additional context to determine CID presence
    // For now, we'll assume no CID unless we can detect it
    
    size_t encrypted_data_length = total_length;
    
    // Extract encrypted record
    if (encrypted_data_length > 0) {
        record.encrypted_record = memory::Buffer(encrypted_data_length);
        auto resize_result = record.encrypted_record.resize(encrypted_data_length);
        if (!resize_result.is_success()) {
            return make_error<DTLSCiphertext>(DTLSError::INTERNAL_ERROR, "Failed to allocate encrypted record buffer");
        }
        std::memcpy(record.encrypted_record.mutable_data(), &data[pos], encrypted_data_length);
    }
    
    record.length = static_cast<uint16_t>(record.encrypted_record.size());
    
    return make_result(std::move(record));
}

bool DTLSCiphertext::is_valid() const {
    // For encrypted records, type should typically be application_data
    if (type == ContentType::INVALID) {
        return false;
    }
    
    // Check protocol version (should be DTLS v1.3)
    if (version != ::dtls::v13::protocol::ProtocolVersion::DTLS_1_3) {
        return false;
    }
    
    // Check encrypted record length consistency
    uint16_t expected_length = encrypted_record.size();
    if (has_connection_id) {
        expected_length += 1 + connection_id_length;
    }
    if (length != encrypted_record.size()) {
        return false;
    }
    
    // Check maximum encrypted record length
    if (encrypted_record.size() > MAX_ENCRYPTED_RECORD_LENGTH) {
        return false;
    }
    
    // Validate connection ID length if present
    if (has_connection_id && connection_id_length > MAX_CONNECTION_ID_LENGTH) {
        return false;
    }
    
    return true;
}

size_t DTLSCiphertext::total_size() const {
    size_t size = HEADER_SIZE + encrypted_record.size();
    if (has_connection_id) {
        size += 1 + connection_id_length; // Length byte + CID
    }
    return size;
}

void DTLSCiphertext::set_connection_id(const uint8_t* cid, uint8_t cid_length) {
    if (cid_length > MAX_CONNECTION_ID_LENGTH) {
        return; // Invalid length
    }
    
    connection_id_length = cid_length;
    has_connection_id = (cid_length > 0);
    
    if (cid_length > 0 && cid) {
        std::memcpy(connection_id.data(), cid, cid_length);
        // Zero out unused portion
        if (cid_length < MAX_CONNECTION_ID_LENGTH) {
            std::memset(connection_id.data() + cid_length, 0, MAX_CONNECTION_ID_LENGTH - cid_length);
        }
    } else {
        connection_id.fill(0);
    }
}

void DTLSCiphertext::set_connection_id(const std::vector<uint8_t>& cid) {
    set_connection_id(cid.data(), static_cast<uint8_t>(std::min(cid.size(), static_cast<size_t>(MAX_CONNECTION_ID_LENGTH))));
}

void DTLSCiphertext::clear_connection_id() {
    connection_id.fill(0);
    connection_id_length = 0;
    has_connection_id = false;
}

std::vector<uint8_t> DTLSCiphertext::get_connection_id_vector() const {
    if (!has_connection_id || connection_id_length == 0) {
        return {};
    }
    return std::vector<uint8_t>(connection_id.begin(), connection_id.begin() + connection_id_length);
}

void DTLSCiphertext::set_encrypted_record(memory::Buffer record) {
    encrypted_record = std::move(record);
    update_length();
}

void DTLSCiphertext::update_length() {
    length = static_cast<uint16_t>(encrypted_record.size());
}

// Utility functions implementation
namespace dtls_records_utils {

Result<ContentType> extract_content_type(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() <= offset) {
        return make_error<ContentType>(DTLSError::DECODE_ERROR, "Buffer too small to extract content type");
    }
    
    return make_result(static_cast<ContentType>(buffer.data()[offset]));
}

Result<ProtocolVersion> extract_protocol_version(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 2) {
        return make_error<ProtocolVersion>(DTLSError::DECODE_ERROR, "Buffer too small to extract protocol version");
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
    uint16_t version_raw = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    ProtocolVersion version = static_cast<ProtocolVersion>(version_raw);
    
    return make_result(version);
}

Result<uint16_t> extract_epoch(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + 2) {
        return make_error<uint16_t>(DTLSError::DECODE_ERROR, "Buffer too small to extract epoch");
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
    uint16_t epoch = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    
    return make_result(epoch);
}

Result<SequenceNumber48> extract_sequence_number(const memory::Buffer& buffer, size_t offset) {
    if (buffer.size() < offset + SequenceNumber48::SERIALIZED_SIZE) {
        return make_error<SequenceNumber48>(DTLSError::DECODE_ERROR, "Buffer too small to extract sequence number");
    }
    
    return SequenceNumber48::deserialize_from_buffer(reinterpret_cast<const uint8_t*>(&buffer.data()[offset]));
}

bool is_dtls_record(const memory::Buffer& buffer, size_t min_length) {
    if (buffer.size() < min_length) {
        return false;
    }
    
    // Basic validation of content type
    auto content_type_result = extract_content_type(buffer);
    if (!content_type_result.is_success()) {
        return false;
    }
    
    ContentType type = content_type_result.value();
    if (type == ContentType::INVALID) {
        return false;
    }
    
    // Basic validation of protocol version
    auto version_result = extract_protocol_version(buffer);
    if (!version_result.is_success()) {
        return false;
    }
    
    ProtocolVersion version = version_result.value();
    // Accept DTLS v1.0, v1.2, and v1.3
    return (version == ::dtls::v13::protocol::ProtocolVersion::DTLS_1_0 || 
            version == ::dtls::v13::protocol::ProtocolVersion::DTLS_1_2 || 
            version == ::dtls::v13::protocol::ProtocolVersion::DTLS_1_3);
}

bool validate_record_length(uint16_t declared_length, size_t actual_payload_size) {
    return declared_length == actual_payload_size && 
           declared_length <= DTLSPlaintext::MAX_FRAGMENT_LENGTH;
}

bool is_sequence_number_near_overflow(SequenceNumber48 sequence_number, double threshold) {
    if (threshold < 0.0 || threshold > 1.0) {
        threshold = 0.9; // Default to 90%
    }
    
    uint64_t max_value = 0xFFFFFFFFFFFFULL; // 48-bit max
    uint64_t threshold_value = static_cast<uint64_t>(max_value * threshold);
    
    return sequence_number.value >= threshold_value;
}

} // namespace dtls_records_utils

} // namespace dtls::v13::protocol