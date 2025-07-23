#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory.h"
#include <cstdint>
#include <array>

namespace dtls::v13::protocol {

enum class ContentType : uint8_t {
    INVALID = 0,
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    HEARTBEAT = 24,
    TLS12_CID = 25  // RFC 9146 compatibility
};

enum class ProtocolVersion : uint16_t {
    DTLS_1_0 = 0xfeff,
    DTLS_1_2 = 0xfefd,
    DTLS_1_3 = 0xfefc
};

struct RecordHeader {
    ContentType content_type;
    ProtocolVersion version;
    uint16_t epoch;
    uint64_t sequence_number;
    uint16_t length;

    static constexpr size_t SERIALIZED_SIZE = 13;
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<RecordHeader> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const;
};

class PlaintextRecord {
private:
    RecordHeader header_;
    memory::Buffer payload_;
    
public:
    PlaintextRecord() = default;
    PlaintextRecord(ContentType content_type, ProtocolVersion version, 
                   uint16_t epoch, uint64_t sequence_number,
                   memory::Buffer payload);
    
    const RecordHeader& header() const { return header_; }
    const memory::Buffer& payload() const { return payload_; }
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<PlaintextRecord> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const;
    size_t total_size() const;
    
    void set_epoch(uint16_t epoch) { header_.epoch = epoch; }
    void set_sequence_number(uint64_t seq_num) { header_.sequence_number = seq_num; }
};

class CiphertextRecord {
private:
    RecordHeader header_;
    memory::Buffer encrypted_payload_;
    memory::Buffer authentication_tag_;
    std::array<uint8_t, 16> connection_id_;  // Optional CID
    bool has_connection_id_;
    
public:
    CiphertextRecord() = default;
    CiphertextRecord(ContentType content_type, ProtocolVersion version,
                    uint16_t epoch, uint64_t sequence_number,
                    memory::Buffer encrypted_payload,
                    memory::Buffer auth_tag);
    
    const RecordHeader& header() const { return header_; }
    const memory::Buffer& encrypted_payload() const { return encrypted_payload_; }
    const memory::Buffer& authentication_tag() const { return authentication_tag_; }
    
    bool has_connection_id() const { return has_connection_id_; }
    const std::array<uint8_t, 16>& connection_id() const { return connection_id_; }
    
    void set_connection_id(const std::array<uint8_t, 16>& cid);
    void clear_connection_id();
    
    Result<size_t> serialize(memory::Buffer& buffer) const;
    static Result<CiphertextRecord> deserialize(const memory::Buffer& buffer, size_t offset = 0);
    
    bool is_valid() const;
    size_t total_size() const;
    
    void set_epoch(uint16_t epoch) { header_.epoch = epoch; }
    void set_sequence_number(uint64_t seq_num) { header_.sequence_number = seq_num; }
};

Result<ContentType> extract_content_type(const memory::Buffer& buffer, size_t offset = 0);
Result<ProtocolVersion> extract_protocol_version(const memory::Buffer& buffer, size_t offset = 1);

bool is_dtls_record(const memory::Buffer& buffer, size_t min_length = 13);

}  // namespace dtls::v13::protocol