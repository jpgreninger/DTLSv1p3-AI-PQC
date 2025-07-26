#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory.h"
#include <cstdint>
#include <array>

namespace dtls::v13::protocol {

/**
 * 48-bit sequence number type for DTLS v1.3 compliance
 * RFC 9147 Section 4.1.1 and 4.1.2 specify 48-bit sequence numbers
 */
struct SequenceNumber48 {
    uint64_t value : 48;  // 48-bit value stored in 64-bit container
    
    SequenceNumber48() : value(0) {}
    explicit SequenceNumber48(uint64_t v) : value(v & 0xFFFFFFFFFFFFULL) {}
    
    operator uint64_t() const { return value; }
    
    SequenceNumber48& operator++() {
        value = (value + 1) & 0xFFFFFFFFFFFFULL;
        return *this;
    }
    
    SequenceNumber48 operator++(int) {
        SequenceNumber48 temp = *this;
        ++(*this);
        return temp;
    }
    
    bool would_overflow() const {
        return value == 0xFFFFFFFFFFFFULL;
    }
    
    // Serialization support
    Result<void> serialize_to_buffer(uint8_t* buffer) const;
    static Result<SequenceNumber48> deserialize_from_buffer(const uint8_t* buffer);
    
    static constexpr size_t SERIALIZED_SIZE = 6; // 48 bits = 6 bytes
};

/**
 * DTLSPlaintext structure as specified in RFC 9147 Section 4.1.1
 * 
 * This is the unified header format for DTLS v1.3 that provides
 * backward compatibility while supporting new features.
 */
struct DTLSPlaintext {
    ContentType type;                    // handshake(22), application_data(23), etc.
    ProtocolVersion version;             // {254, 253} for DTLS v1.3
    uint16_t epoch;                      // Key epoch number
    SequenceNumber48 sequence_number;    // 6-byte sequence number  
    uint16_t length;                     // Payload length (0-16384 bytes)
    memory::Buffer fragment;             // Actual payload
    
    static constexpr size_t HEADER_SIZE = 13; // 1+2+2+6+2 bytes
    static constexpr uint16_t MAX_FRAGMENT_LENGTH = 16384;
    
    DTLSPlaintext() = default;
    DTLSPlaintext(ContentType content_type, ProtocolVersion proto_version,
                  uint16_t epoch_num, SequenceNumber48 seq_num,
                  memory::Buffer payload);
    
    // Copy constructor and assignment
    DTLSPlaintext(const DTLSPlaintext& other);
    DTLSPlaintext& operator=(const DTLSPlaintext& other);
    
    // Move constructor and assignment
    DTLSPlaintext(DTLSPlaintext&& other) noexcept = default;
    DTLSPlaintext& operator=(DTLSPlaintext&& other) noexcept = default;
    
    /**
     * Serialize the DTLSPlaintext structure to a buffer
     * @param buffer Output buffer to write serialized data
     * @return Number of bytes written or error
     */
    Result<size_t> serialize(memory::Buffer& buffer) const;
    
    /**
     * Deserialize DTLSPlaintext from buffer
     * @param buffer Input buffer containing serialized data
     * @param offset Offset in buffer to start reading from
     * @return Deserialized DTLSPlaintext structure or error
     */
    static Result<DTLSPlaintext> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    /**
     * Validate the DTLSPlaintext structure
     * @return true if valid, false otherwise
     */
    bool is_valid() const;
    
    /**
     * Get total size when serialized (header + fragment)
     * @return Total serialized size in bytes
     */
    size_t total_size() const;
    
    // Accessors
    ContentType get_type() const { return type; }
    ProtocolVersion get_version() const { return version; }
    uint16_t get_epoch() const { return epoch; }
    SequenceNumber48 get_sequence_number() const { return sequence_number; }
    uint16_t get_length() const { return length; }
    const memory::Buffer& get_fragment() const { return fragment; }
    
    // Mutators
    void set_type(ContentType t) { type = t; }
    void set_version(ProtocolVersion v) { version = v; }
    void set_epoch(uint16_t e) { epoch = e; }
    void set_sequence_number(SequenceNumber48 seq) { sequence_number = seq; }
    void set_fragment(memory::Buffer f);
    
private:
    void update_length();
};

/**
 * DTLSCiphertext structure as specified in RFC 9147 Section 4.1.2
 * 
 * This structure contains encrypted records with AEAD protection.
 * The sequence number is encrypted using per-traffic-key encryption.
 */
struct DTLSCiphertext {
    ContentType type;                         // Always application_data(23) for encrypted records
    ProtocolVersion version;                  // {254, 253} for DTLS v1.3
    uint16_t epoch;                          // Current key epoch
    SequenceNumber48 encrypted_sequence_number; // Encrypted 48-bit sequence number
    uint16_t length;                         // Encrypted payload + authentication tag length
    memory::Buffer encrypted_record;         // AEAD encrypted data including auth tag
    
    // Optional Connection ID (RFC 9146)
    std::array<uint8_t, 20> connection_id;   // Max 20 bytes as per RFC
    uint8_t connection_id_length;            // Actual CID length (0-20)
    bool has_connection_id;                  // Whether CID is present
    
    static constexpr size_t HEADER_SIZE = 13; // Same as DTLSPlaintext
    static constexpr size_t MAX_CONNECTION_ID_LENGTH = 20;
    static constexpr uint16_t MAX_ENCRYPTED_RECORD_LENGTH = 16384 + 256; // Max fragment + max auth tag
    
    DTLSCiphertext() = default;
    DTLSCiphertext(ContentType content_type, ProtocolVersion proto_version,
                   uint16_t epoch_num, SequenceNumber48 encrypted_seq_num,
                   memory::Buffer encrypted_payload);
    
    // Copy constructor and assignment
    DTLSCiphertext(const DTLSCiphertext& other);
    DTLSCiphertext& operator=(const DTLSCiphertext& other);
    
    // Move constructor and assignment
    DTLSCiphertext(DTLSCiphertext&& other) noexcept = default;
    DTLSCiphertext& operator=(DTLSCiphertext&& other) noexcept = default;
    
    /**
     * Serialize the DTLSCiphertext structure to a buffer
     * @param buffer Output buffer to write serialized data  
     * @return Number of bytes written or error
     */
    Result<size_t> serialize(memory::Buffer& buffer) const;
    
    /**
     * Deserialize DTLSCiphertext from buffer
     * @param buffer Input buffer containing serialized data
     * @param offset Offset in buffer to start reading from
     * @return Deserialized DTLSCiphertext structure or error
     */
    static Result<DTLSCiphertext> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    /**
     * Validate the DTLSCiphertext structure
     * @return true if valid, false otherwise
     */
    bool is_valid() const;
    
    /**
     * Get total size when serialized (header + encrypted_record + optional CID)
     * @return Total serialized size in bytes
     */
    size_t total_size() const;
    
    // Connection ID management
    void set_connection_id(const uint8_t* cid, uint8_t cid_length);
    void set_connection_id(const std::vector<uint8_t>& cid);
    void clear_connection_id();
    bool has_cid() const { return has_connection_id; }
    uint8_t get_connection_id_length() const { return connection_id_length; }
    const uint8_t* get_connection_id() const { return connection_id.data(); }
    std::vector<uint8_t> get_connection_id_vector() const;
    
    // Accessors
    ContentType get_type() const { return type; }
    ProtocolVersion get_version() const { return version; }
    uint16_t get_epoch() const { return epoch; }
    SequenceNumber48 get_encrypted_sequence_number() const { return encrypted_sequence_number; }
    uint16_t get_length() const { return length; }
    const memory::Buffer& get_encrypted_record() const { return encrypted_record; }
    
    // Mutators
    void set_type(ContentType t) { type = t; }
    void set_version(ProtocolVersion v) { version = v; }
    void set_epoch(uint16_t e) { epoch = e; }
    void set_encrypted_sequence_number(SequenceNumber48 seq) { encrypted_sequence_number = seq; }
    void set_encrypted_record(memory::Buffer record);
    
private:
    void update_length();
};

// Utility functions for record processing
namespace dtls_records_utils {

/**
 * Extract content type from buffer without full deserialization
 * @param buffer Buffer containing serialized record
 * @param offset Offset to start reading from
 * @return Content type or error
 */
Result<ContentType> extract_content_type(const memory::Buffer& buffer, size_t offset = 0);

/**
 * Extract protocol version from buffer without full deserialization
 * @param buffer Buffer containing serialized record
 * @param offset Offset to start reading from (should be offset + 1 for version field)
 * @return Protocol version or error
 */
Result<ProtocolVersion> extract_protocol_version(const memory::Buffer& buffer, size_t offset = 1);

/**
 * Extract epoch from buffer without full deserialization
 * @param buffer Buffer containing serialized record
 * @param offset Offset to start reading from (should be offset + 3 for epoch field)
 * @return Epoch value or error
 */
Result<uint16_t> extract_epoch(const memory::Buffer& buffer, size_t offset = 3);

/**
 * Extract sequence number from buffer without full deserialization
 * @param buffer Buffer containing serialized record
 * @param offset Offset to start reading from (should be offset + 5 for sequence field)
 * @return 48-bit sequence number or error
 */
Result<SequenceNumber48> extract_sequence_number(const memory::Buffer& buffer, size_t offset = 5);

/**
 * Check if buffer contains a valid DTLS record header
 * @param buffer Buffer to check
 * @param min_length Minimum expected length
 * @return true if valid DTLS record header detected
 */
bool is_dtls_record(const memory::Buffer& buffer, size_t min_length = DTLSPlaintext::HEADER_SIZE);

/**
 * Validate record length field against actual payload
 * @param declared_length Length field from record header
 * @param actual_payload_size Actual size of payload buffer
 * @return true if lengths are consistent
 */
bool validate_record_length(uint16_t declared_length, size_t actual_payload_size);

/**
 * Check if sequence number indicates potential overflow
 * @param sequence_number Current sequence number
 * @param threshold Threshold for warning (default: 90% of max value)
 * @return true if approaching overflow
 */
bool is_sequence_number_near_overflow(SequenceNumber48 sequence_number, 
                                     double threshold = 0.9);

} // namespace dtls_records_utils

} // namespace dtls::v13::protocol