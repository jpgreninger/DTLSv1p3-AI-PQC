#include <gtest/gtest.h>
#include "dtls/protocol/record.h"
#include "dtls/memory/buffer.h"
#include <arpa/inet.h>  // For htons
#include <cstring>      // For std::memcpy

using namespace dtls::v13;
using namespace dtls::v13::protocol;

/**
 * @brief Comprehensive test suite for record.cpp
 * 
 * This test suite provides extensive coverage for all record-related
 * functionality including RecordHeader, PlaintextRecord, CiphertextRecord,
 * and utility functions to achieve >95% code coverage.
 */
class RecordComprehensiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up common test data
    }
    
    // Helper to create a valid record header
    RecordHeader create_valid_header() {
        RecordHeader header;
        header.content_type = protocol::ContentType::HANDSHAKE;
        header.version = protocol::ProtocolVersion::DTLS_1_3;
        header.epoch = 1;
        header.sequence_number = 123;
        header.length = 100;
        return header;
    }
    
    // Helper to create test payload
    memory::Buffer create_test_payload(size_t size) {
        memory::Buffer payload(size);
        auto resize_result = payload.resize(size);
        EXPECT_TRUE(resize_result.is_success());
        
        for (size_t i = 0; i < size; ++i) {
            payload.mutable_data()[i] = static_cast<std::byte>(i % 256);
        }
        return payload;
    }
};

/**
 * @brief Test suite for RecordHeader functionality
 */
class RecordHeaderTest : public RecordComprehensiveTest {};

/**
 * @brief Test RecordHeader serialization with valid data
 */
TEST_F(RecordHeaderTest, TestValidSerialization) {
    RecordHeader header = create_valid_header();
    
    memory::Buffer buffer(RecordHeader::SERIALIZED_SIZE);
    auto result = header.serialize(buffer);
    
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), RecordHeader::SERIALIZED_SIZE);
    EXPECT_EQ(buffer.size(), RecordHeader::SERIALIZED_SIZE);
    
    // Verify the serialized data structure
    const std::byte* data = buffer.data();
    EXPECT_EQ(static_cast<uint8_t>(data[0]), static_cast<uint8_t>(protocol::ContentType::HANDSHAKE));
}

/**
 * @brief Test RecordHeader serialization with insufficient buffer
 */
TEST_F(RecordHeaderTest, TestInsufficientBufferSerialization) {
    RecordHeader header = create_valid_header();
    
    // Create buffer that's too small
    memory::Buffer small_buffer(RecordHeader::SERIALIZED_SIZE - 1);
    auto result = header.serialize(small_buffer);
    
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
}

/**
 * @brief Test RecordHeader serialization with invalid header
 */
TEST_F(RecordHeaderTest, TestInvalidHeaderSerialization) {
    RecordHeader invalid_header;
    invalid_header.content_type = protocol::ContentType::INVALID; // Invalid content type
    invalid_header.version = protocol::ProtocolVersion::DTLS_1_3;
    invalid_header.epoch = 1;
    invalid_header.sequence_number = 123;
    invalid_header.length = 100;
    
    memory::Buffer buffer(RecordHeader::SERIALIZED_SIZE);
    auto result = invalid_header.serialize(buffer);
    
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_RECORD_HEADER);
}

/**
 * @brief Test RecordHeader deserialization with valid data
 */
TEST_F(RecordHeaderTest, TestValidDeserialization) {
    RecordHeader original_header = create_valid_header();
    
    // First serialize
    memory::Buffer buffer(RecordHeader::SERIALIZED_SIZE);
    auto serialize_result = original_header.serialize(buffer);
    ASSERT_TRUE(serialize_result.is_success());
    
    // Then deserialize
    auto deserialize_result = RecordHeader::deserialize(buffer, 0);
    ASSERT_TRUE(deserialize_result.is_success());
    
    const RecordHeader& deserialized = deserialize_result.value();
    EXPECT_EQ(deserialized.content_type, original_header.content_type);
    EXPECT_EQ(deserialized.version, original_header.version);
    EXPECT_EQ(deserialized.epoch, original_header.epoch);
    EXPECT_EQ(deserialized.sequence_number, original_header.sequence_number);
    EXPECT_EQ(deserialized.length, original_header.length);
}

/**
 * @brief Test RecordHeader deserialization with insufficient buffer
 */
TEST_F(RecordHeaderTest, TestInsufficientBufferDeserialization) {
    memory::Buffer small_buffer(RecordHeader::SERIALIZED_SIZE - 1);
    auto result = RecordHeader::deserialize(small_buffer, 0);
    
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
}

/**
 * @brief Test RecordHeader deserialization with invalid offset
 */
TEST_F(RecordHeaderTest, TestInvalidOffsetDeserialization) {
    memory::Buffer buffer(RecordHeader::SERIALIZED_SIZE);
    
    // Try to deserialize with offset that would go beyond buffer
    auto result = RecordHeader::deserialize(buffer, 1);
    
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
}

/**
 * @brief Test RecordHeader validation with various content types
 */
TEST_F(RecordHeaderTest, TestContentTypeValidation) {
    std::vector<protocol::ContentType> valid_types = {
        protocol::ContentType::HANDSHAKE,
        protocol::ContentType::APPLICATION_DATA,
        protocol::ContentType::ALERT,
        protocol::ContentType::CHANGE_CIPHER_SPEC,
        protocol::ContentType::HEARTBEAT,
        protocol::ContentType::TLS12_CID
    };
    
    for (auto content_type : valid_types) {
        RecordHeader header = create_valid_header();
        header.content_type = content_type;
        EXPECT_TRUE(header.is_valid()) << "Content type " << static_cast<int>(content_type) << " should be valid";
    }
    
    // Test invalid content type
    RecordHeader invalid_header = create_valid_header();
    invalid_header.content_type = protocol::ContentType::INVALID;
    EXPECT_FALSE(invalid_header.is_valid());
}

/**
 * @brief Test RecordHeader validation with various protocol versions
 */
TEST_F(RecordHeaderTest, TestProtocolVersionValidation) {
    std::vector<protocol::ProtocolVersion> valid_versions = {
        protocol::ProtocolVersion::DTLS_1_3,
        protocol::ProtocolVersion::DTLS_1_2,
        protocol::ProtocolVersion::DTLS_1_0
    };
    
    for (auto version : valid_versions) {
        RecordHeader header = create_valid_header();
        header.version = version;
        EXPECT_TRUE(header.is_valid()) << "Version " << static_cast<int>(version) << " should be valid";
    }
    
    // Test invalid version
    RecordHeader invalid_header = create_valid_header();
    invalid_header.version = static_cast<protocol::ProtocolVersion>(0x1234); // Invalid version
    EXPECT_FALSE(invalid_header.is_valid());
}

/**
 * @brief Test RecordHeader length validation
 */
TEST_F(RecordHeaderTest, TestLengthValidation) {
    RecordHeader header = create_valid_header();
    
    // Test valid lengths
    header.length = 0;
    EXPECT_TRUE(header.is_valid());
    
    header.length = 16384; // Maximum allowed
    EXPECT_TRUE(header.is_valid());
    
    // Test invalid length (too large)
    header.length = 16385;
    EXPECT_FALSE(header.is_valid());
    
    header.length = 65535; // Way too large
    EXPECT_FALSE(header.is_valid());
}

/**
 * @brief Test suite for PlaintextRecord functionality
 */
class PlaintextRecordTest : public RecordComprehensiveTest {};

/**
 * @brief Test PlaintextRecord construction
 */
TEST_F(PlaintextRecordTest, TestConstruction) {
    memory::Buffer payload = create_test_payload(100);
    
    PlaintextRecord record(
        protocol::ContentType::HANDSHAKE,
        protocol::ProtocolVersion::DTLS_1_3,
        1,      // epoch
        123,    // sequence_number
        std::move(payload)
    );
    
    EXPECT_TRUE(record.is_valid());
    EXPECT_EQ(record.header().content_type, protocol::ContentType::HANDSHAKE);
    EXPECT_EQ(record.header().version, protocol::ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.header().epoch, 1);
    EXPECT_EQ(record.header().sequence_number, 123);
    EXPECT_EQ(record.header().length, 100);
    EXPECT_EQ(record.payload().size(), 100);
    EXPECT_EQ(record.total_size(), RecordHeader::SERIALIZED_SIZE + 100);
}

/**
 * @brief Test PlaintextRecord with empty payload
 */
TEST_F(PlaintextRecordTest, TestEmptyPayload) {
    memory::Buffer empty_payload(0);
    auto resize_result = empty_payload.resize(0);
    ASSERT_TRUE(resize_result.is_success());
    
    PlaintextRecord record(
        protocol::ContentType::ALERT,
        protocol::ProtocolVersion::DTLS_1_3,
        0,      // epoch
        1,      // sequence_number
        std::move(empty_payload)
    );
    
    EXPECT_TRUE(record.is_valid());
    EXPECT_EQ(record.header().length, 0);
    EXPECT_EQ(record.payload().size(), 0);
    EXPECT_EQ(record.total_size(), RecordHeader::SERIALIZED_SIZE);
}

/**
 * @brief Test PlaintextRecord serialization
 */
TEST_F(PlaintextRecordTest, TestSerialization) {
    memory::Buffer payload = create_test_payload(50);
    
    PlaintextRecord record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_2,
        2,      // epoch
        456,    // sequence_number
        std::move(payload)
    );
    
    size_t expected_size = record.total_size();
    memory::Buffer buffer(expected_size);
    auto result = record.serialize(buffer);
    
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), expected_size);
    EXPECT_EQ(buffer.size(), expected_size);
}

/**
 * @brief Test PlaintextRecord serialization with insufficient buffer
 */
TEST_F(PlaintextRecordTest, TestInsufficientBufferSerialization) {
    memory::Buffer payload = create_test_payload(100);
    
    PlaintextRecord record(
        protocol::ContentType::HANDSHAKE,
        protocol::ProtocolVersion::DTLS_1_3,
        1, 123, std::move(payload)
    );
    
    // Create buffer that's too small
    memory::Buffer small_buffer(record.total_size() - 1);
    auto result = record.serialize(small_buffer);
    
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
}

/**
 * @brief Test PlaintextRecord validation with payload length mismatch
 */
TEST_F(PlaintextRecordTest, TestPayloadLengthMismatch) {
    memory::Buffer payload = create_test_payload(100);
    
    PlaintextRecord record(
        protocol::ContentType::HANDSHAKE,
        protocol::ProtocolVersion::DTLS_1_3,
        1, 123, std::move(payload)
    );
    
    // Manually modify header length to create mismatch
    const_cast<RecordHeader&>(record.header()).length = 99; // Different from payload size
    
    EXPECT_FALSE(record.is_valid());
}

/**
 * @brief Test suite for utility functions
 */
class RecordUtilityTest : public RecordComprehensiveTest {};

/**
 * @brief Test extract_content_type function
 */
TEST_F(RecordUtilityTest, TestExtractContentType) {
    memory::Buffer buffer(10);
    auto resize_result = buffer.resize(10);
    ASSERT_TRUE(resize_result.is_success());
    
    // Set first byte to a valid content type
    buffer.mutable_data()[0] = static_cast<std::byte>(static_cast<uint8_t>(protocol::ContentType::HANDSHAKE));
    
    auto result = extract_content_type(buffer, 0);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), protocol::ContentType::HANDSHAKE);
}

/**
 * @brief Test extract_content_type with invalid content type
 */
TEST_F(RecordUtilityTest, TestExtractInvalidContentType) {
    memory::Buffer buffer(10);
    auto resize_result = buffer.resize(10);
    ASSERT_TRUE(resize_result.is_success());
    
    // Set first byte to invalid content type
    buffer.mutable_data()[0] = static_cast<std::byte>(static_cast<uint8_t>(protocol::ContentType::INVALID));
    
    auto result = extract_content_type(buffer, 0);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_CONTENT_TYPE);
}

/**
 * @brief Test extract_content_type with insufficient buffer
 */
TEST_F(RecordUtilityTest, TestExtractContentTypeInsufficientBuffer) {
    memory::Buffer empty_buffer(0);
    auto resize_result = empty_buffer.resize(0);
    ASSERT_TRUE(resize_result.is_success());
    
    auto result = extract_content_type(empty_buffer, 0);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
    
    // Test with offset beyond buffer
    memory::Buffer small_buffer(1);
    resize_result = small_buffer.resize(1);
    ASSERT_TRUE(resize_result.is_success());
    
    result = extract_content_type(small_buffer, 1);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
}

/**
 * @brief Test extract_protocol_version function
 */
TEST_F(RecordUtilityTest, TestExtractProtocolVersion) {
    memory::Buffer buffer(10);
    auto resize_result = buffer.resize(10);
    ASSERT_TRUE(resize_result.is_success());
    
    // Set bytes 0-1 to DTLS 1.3 version (0xfefc in network byte order)
    uint16_t version_be = htons(static_cast<uint16_t>(protocol::ProtocolVersion::DTLS_1_3));
    std::memcpy(buffer.mutable_data(), &version_be, 2);
    
    auto result = extract_protocol_version(buffer, 0);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), protocol::ProtocolVersion::DTLS_1_3);
}

/**
 * @brief Test extract_protocol_version with insufficient buffer
 */
TEST_F(RecordUtilityTest, TestExtractProtocolVersionInsufficientBuffer) {
    memory::Buffer small_buffer(1);
    auto resize_result = small_buffer.resize(1);
    ASSERT_TRUE(resize_result.is_success());
    
    auto result = extract_protocol_version(small_buffer, 0);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
    
    // Test with offset that would require data beyond buffer
    memory::Buffer buffer(2);
    resize_result = buffer.resize(2);
    ASSERT_TRUE(resize_result.is_success());
    
    result = extract_protocol_version(buffer, 1);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
}

/**
 * @brief Test is_dtls_record function
 */
TEST_F(RecordUtilityTest, TestIsDtlsRecord) {
    memory::Buffer buffer(10);
    auto resize_result = buffer.resize(10);
    ASSERT_TRUE(resize_result.is_success());
    
    // Create a valid-looking DTLS record start
    buffer.mutable_data()[0] = static_cast<std::byte>(static_cast<uint8_t>(protocol::ContentType::HANDSHAKE));
    uint16_t version_be = htons(static_cast<uint16_t>(protocol::ProtocolVersion::DTLS_1_3));
    std::memcpy(buffer.mutable_data() + 1, &version_be, 2);
    
    EXPECT_TRUE(is_dtls_record(buffer, 3));
    EXPECT_TRUE(is_dtls_record(buffer, 10));
}

/**
 * @brief Test is_dtls_record with invalid data
 */
TEST_F(RecordUtilityTest, TestIsDtlsRecordInvalid) {
    memory::Buffer buffer(10);
    auto resize_result = buffer.resize(10);
    ASSERT_TRUE(resize_result.is_success());
    
    // Set invalid content type
    buffer.mutable_data()[0] = static_cast<std::byte>(static_cast<uint8_t>(protocol::ContentType::INVALID));
    uint16_t version_be = htons(static_cast<uint16_t>(protocol::ProtocolVersion::DTLS_1_3));
    std::memcpy(buffer.mutable_data() + 1, &version_be, 2);
    
    EXPECT_FALSE(is_dtls_record(buffer, 3));
    
    // Set valid content type but invalid version
    buffer.mutable_data()[0] = static_cast<std::byte>(static_cast<uint8_t>(protocol::ContentType::HANDSHAKE));
    version_be = htons(0x1234); // Invalid version
    std::memcpy(buffer.mutable_data() + 1, &version_be, 2);
    
    EXPECT_FALSE(is_dtls_record(buffer, 3));
}

/**
 * @brief Test is_dtls_record with insufficient buffer
 */
TEST_F(RecordUtilityTest, TestIsDtlsRecordInsufficientBuffer) {
    memory::Buffer small_buffer(2);
    auto resize_result = small_buffer.resize(2);
    ASSERT_TRUE(resize_result.is_success());
    
    EXPECT_FALSE(is_dtls_record(small_buffer, 3)); // Requires at least 3 bytes
    EXPECT_FALSE(is_dtls_record(small_buffer, 10)); // Requires at least 10 bytes
}

/**
 * @brief Test suite for CiphertextRecord functionality
 */
class CiphertextRecordTest : public RecordComprehensiveTest {};

/**
 * @brief Test CiphertextRecord construction
 */
TEST_F(CiphertextRecordTest, TestConstruction) {
    memory::Buffer encrypted_payload_buf = create_test_payload(100);
    memory::Buffer auth_tag_buf = create_test_payload(16);
    
    memory::ZeroCopyBuffer encrypted_payload(100);
    memory::ZeroCopyBuffer auth_tag(16);
    
    // Resize buffers to actual size
    auto resize_result1 = encrypted_payload.resize(100);
    auto resize_result2 = auth_tag.resize(16);
    ASSERT_TRUE(resize_result1.is_success());
    ASSERT_TRUE(resize_result2.is_success());
    
    // Copy data to ZeroCopyBuffer
    std::memcpy(encrypted_payload.mutable_data(), encrypted_payload_buf.data(), 100);
    std::memcpy(auth_tag.mutable_data(), auth_tag_buf.data(), 16);
    
    CiphertextRecord record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_3,
        1,      // epoch
        123,    // sequence_number
        std::move(encrypted_payload),
        std::move(auth_tag)
    );
    
    EXPECT_TRUE(record.is_valid());
    EXPECT_EQ(record.header().content_type, protocol::ContentType::APPLICATION_DATA);
    EXPECT_EQ(record.header().version, protocol::ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.header().epoch, 1);
    EXPECT_EQ(record.header().sequence_number, 123);
    EXPECT_EQ(record.header().length, 116); // 100 + 16
    EXPECT_EQ(record.encrypted_payload().size(), 100);
    EXPECT_EQ(record.authentication_tag().size(), 16);
    EXPECT_FALSE(record.has_connection_id());
}

/**
 * @brief Test CiphertextRecord with connection ID
 */
TEST_F(CiphertextRecordTest, TestConnectionId) {
    memory::Buffer encrypted_payload_buf = create_test_payload(50);
    memory::Buffer auth_tag_buf = create_test_payload(16);
    
    memory::ZeroCopyBuffer encrypted_payload(50);
    memory::ZeroCopyBuffer auth_tag(16);
    
    // Resize buffers to actual size
    auto resize_result1 = encrypted_payload.resize(50);
    auto resize_result2 = auth_tag.resize(16);
    ASSERT_TRUE(resize_result1.is_success());
    ASSERT_TRUE(resize_result2.is_success());
    
    // Copy data to ZeroCopyBuffer
    std::memcpy(encrypted_payload.mutable_data(), encrypted_payload_buf.data(), 50);
    std::memcpy(auth_tag.mutable_data(), auth_tag_buf.data(), 16);
    
    CiphertextRecord record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_3,
        1, 123,
        std::move(encrypted_payload),
        std::move(auth_tag)
    );
    
    // Test setting connection ID
    std::vector<uint8_t> cid = {0x01, 0x02, 0x03, 0x04};
    record.set_connection_id(cid);
    
    EXPECT_TRUE(record.has_connection_id());
    EXPECT_EQ(record.connection_id(), cid);
    EXPECT_EQ(record.header().length, 70); // 50 + 16 + 4
    
    // Test clearing connection ID
    record.clear_connection_id();
    EXPECT_FALSE(record.has_connection_id());
    EXPECT_TRUE(record.connection_id().empty());
    EXPECT_EQ(record.header().length, 66); // 50 + 16
}

/**
 * @brief Test CiphertextRecord with invalid connection ID (too long)
 */
TEST_F(CiphertextRecordTest, TestInvalidConnectionId) {
    memory::Buffer encrypted_payload_buf = create_test_payload(50);
    memory::Buffer auth_tag_buf = create_test_payload(16);
    
    memory::ZeroCopyBuffer encrypted_payload(50);
    memory::ZeroCopyBuffer auth_tag(16);
    
    // Resize buffers to actual size
    auto resize_result1 = encrypted_payload.resize(50);
    auto resize_result2 = auth_tag.resize(16);
    ASSERT_TRUE(resize_result1.is_success());
    ASSERT_TRUE(resize_result2.is_success());
    
    // Copy data to ZeroCopyBuffer
    std::memcpy(encrypted_payload.mutable_data(), encrypted_payload_buf.data(), 50);
    std::memcpy(auth_tag.mutable_data(), auth_tag_buf.data(), 16);
    
    CiphertextRecord record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_3,
        1, 123,
        std::move(encrypted_payload),
        std::move(auth_tag)
    );
    
    // Create CID that's too long (> MAX_CONNECTION_ID_LENGTH)
    std::vector<uint8_t> long_cid(256, 0x42); // 256 bytes is too long
    record.set_connection_id(long_cid);
    
    // Should not accept the invalid CID
    EXPECT_FALSE(record.has_connection_id());
    EXPECT_TRUE(record.connection_id().empty());
}

/**
 * @brief Test CiphertextRecord serialization
 */
TEST_F(CiphertextRecordTest, TestSerialization) {
    memory::Buffer encrypted_payload_buf = create_test_payload(30);
    memory::Buffer auth_tag_buf = create_test_payload(16);
    
    memory::ZeroCopyBuffer encrypted_payload(30);
    memory::ZeroCopyBuffer auth_tag(16);
    
    // Resize buffers to actual size
    auto resize_result1 = encrypted_payload.resize(30);
    auto resize_result2 = auth_tag.resize(16);
    ASSERT_TRUE(resize_result1.is_success());
    ASSERT_TRUE(resize_result2.is_success());
    
    // Copy data to ZeroCopyBuffer
    std::memcpy(encrypted_payload.mutable_data(), encrypted_payload_buf.data(), 30);
    std::memcpy(auth_tag.mutable_data(), auth_tag_buf.data(), 16);
    
    CiphertextRecord record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_3,
        1, 123,
        std::move(encrypted_payload),
        std::move(auth_tag)
    );
    
    size_t expected_size = record.total_size();
    memory::Buffer buffer(expected_size);
    auto result = record.serialize(buffer);
    
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), expected_size);
    EXPECT_EQ(buffer.size(), expected_size);
}

/**
 * @brief Test CiphertextRecord serialization with connection ID
 */
TEST_F(CiphertextRecordTest, TestSerializationWithConnectionId) {
    memory::Buffer encrypted_payload_buf = create_test_payload(20);
    memory::Buffer auth_tag_buf = create_test_payload(16);
    
    memory::ZeroCopyBuffer encrypted_payload(20);
    memory::ZeroCopyBuffer auth_tag(16);
    
    // Resize buffers to actual size
    auto resize_result1 = encrypted_payload.resize(20);
    auto resize_result2 = auth_tag.resize(16);
    ASSERT_TRUE(resize_result1.is_success());
    ASSERT_TRUE(resize_result2.is_success());
    
    // Copy data to ZeroCopyBuffer
    std::memcpy(encrypted_payload.mutable_data(), encrypted_payload_buf.data(), 20);
    std::memcpy(auth_tag.mutable_data(), auth_tag_buf.data(), 16);
    
    CiphertextRecord record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_3,
        1, 123,
        std::move(encrypted_payload),
        std::move(auth_tag)
    );
    
    std::vector<uint8_t> cid = {0xAA, 0xBB, 0xCC};
    record.set_connection_id(cid);
    
    size_t expected_size = record.total_size();
    memory::Buffer buffer(expected_size);
    auto result = record.serialize(buffer);
    
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), expected_size);
    EXPECT_EQ(buffer.size(), expected_size);
}

/**
 * @brief Test CiphertextRecord deserialization
 */
TEST_F(CiphertextRecordTest, TestDeserialization) {
    // Create a buffer with valid record header + encrypted data
    memory::Buffer test_buffer(RecordHeader::SERIALIZED_SIZE + 32); // 16 bytes payload + 16 bytes auth tag
    auto resize_result = test_buffer.resize(RecordHeader::SERIALIZED_SIZE + 32);
    ASSERT_TRUE(resize_result.is_success());
    
    // Create and serialize a header
    RecordHeader header;
    header.content_type = protocol::ContentType::APPLICATION_DATA;
    header.version = protocol::ProtocolVersion::DTLS_1_3;
    header.epoch = 1;
    header.sequence_number = 123;
    header.length = 32; // 16 bytes payload + 16 bytes auth tag
    
    memory::Buffer header_buffer(RecordHeader::SERIALIZED_SIZE);
    auto header_result = header.serialize(header_buffer);
    ASSERT_TRUE(header_result.is_success());
    
    // Copy header to test buffer
    std::memcpy(test_buffer.mutable_data(), header_buffer.data(), RecordHeader::SERIALIZED_SIZE);
    
    // Fill payload and auth tag sections with test data
    for (size_t i = RecordHeader::SERIALIZED_SIZE; i < test_buffer.size(); ++i) {
        test_buffer.mutable_data()[i] = static_cast<std::byte>(i % 256);
    }
    
    // Test deserialization
    auto result = CiphertextRecord::deserialize(test_buffer, 0);
    ASSERT_TRUE(result.is_success());
    
    const CiphertextRecord& record = result.value();
    EXPECT_TRUE(record.is_valid());
    EXPECT_EQ(record.header().content_type, protocol::ContentType::APPLICATION_DATA);
    EXPECT_EQ(record.header().version, protocol::ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.header().epoch, 1);
    EXPECT_EQ(record.header().sequence_number, 123);
    EXPECT_EQ(record.encrypted_payload().size(), 16);
    EXPECT_EQ(record.authentication_tag().size(), 16);
}

/**
 * @brief Test CiphertextRecord deserialization with no auth tag
 */
TEST_F(CiphertextRecordTest, TestDeserializationNoAuthTag) {
    // Create a buffer with only encrypted payload (< 16 bytes)
    memory::Buffer test_buffer(RecordHeader::SERIALIZED_SIZE + 10);
    auto resize_result = test_buffer.resize(RecordHeader::SERIALIZED_SIZE + 10);
    ASSERT_TRUE(resize_result.is_success());
    
    // Create and serialize a header
    RecordHeader header;
    header.content_type = protocol::ContentType::APPLICATION_DATA;
    header.version = protocol::ProtocolVersion::DTLS_1_3;
    header.epoch = 1;
    header.sequence_number = 123;
    header.length = 10; // Only encrypted payload, no auth tag
    
    memory::Buffer header_buffer(RecordHeader::SERIALIZED_SIZE);
    auto header_result = header.serialize(header_buffer);
    ASSERT_TRUE(header_result.is_success());
    
    // Copy header to test buffer
    std::memcpy(test_buffer.mutable_data(), header_buffer.data(), RecordHeader::SERIALIZED_SIZE);
    
    // Fill payload section with test data
    for (size_t i = RecordHeader::SERIALIZED_SIZE; i < test_buffer.size(); ++i) {
        test_buffer.mutable_data()[i] = static_cast<std::byte>(i % 256);
    }
    
    // Test deserialization
    auto result = CiphertextRecord::deserialize(test_buffer, 0);
    ASSERT_TRUE(result.is_success());
    
    const CiphertextRecord& record = result.value();
    EXPECT_EQ(record.encrypted_payload().size(), 10);
    EXPECT_EQ(record.authentication_tag().size(), 0);
}

/**
 * @brief Edge cases and boundary testing
 */
class RecordEdgeCasesTest : public RecordComprehensiveTest {};

/**
 * @brief Test with maximum allowed record length
 */
TEST_F(RecordEdgeCasesTest, TestMaximumRecordLength) {
    memory::Buffer large_payload = create_test_payload(16384); // Maximum allowed
    
    PlaintextRecord record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_3,
        1, 123, std::move(large_payload)
    );
    
    EXPECT_TRUE(record.is_valid());
    EXPECT_EQ(record.header().length, 16384);
}

/**
 * @brief Test round-trip serialization/deserialization
 */
TEST_F(RecordEdgeCasesTest, TestRoundTripSerialization) {
    RecordHeader original_header = create_valid_header();
    
    // Serialize
    memory::Buffer buffer(RecordHeader::SERIALIZED_SIZE);
    auto serialize_result = original_header.serialize(buffer);
    ASSERT_TRUE(serialize_result.is_success());
    
    // Deserialize
    auto deserialize_result = RecordHeader::deserialize(buffer, 0);
    ASSERT_TRUE(deserialize_result.is_success());
    
    // Compare
    const RecordHeader& roundtrip_header = deserialize_result.value();
    EXPECT_EQ(roundtrip_header.content_type, original_header.content_type);
    EXPECT_EQ(roundtrip_header.version, original_header.version);
    EXPECT_EQ(roundtrip_header.epoch, original_header.epoch);
    EXPECT_EQ(roundtrip_header.sequence_number, original_header.sequence_number);
    EXPECT_EQ(roundtrip_header.length, original_header.length);
}

/**
 * @brief Test with various sequence numbers including edge cases
 */
TEST_F(RecordEdgeCasesTest, TestSequenceNumberEdgeCases) {
    std::vector<uint64_t> test_sequence_numbers = {
        0,                          // Minimum
        1,                          // Small value
        0xFFFFFFFF,                // 32-bit max
        0xFFFFFFFFFFFF,            // 48-bit max (DTLS sequence number limit)
        0x123456789ABC,            // Random value
    };
    
    for (uint64_t seq_num : test_sequence_numbers) {
        RecordHeader header = create_valid_header();
        header.sequence_number = seq_num;
        
        // Test serialization/deserialization
        memory::Buffer buffer(RecordHeader::SERIALIZED_SIZE);
        auto serialize_result = header.serialize(buffer);
        ASSERT_TRUE(serialize_result.is_success());
        
        auto deserialize_result = RecordHeader::deserialize(buffer, 0);
        ASSERT_TRUE(deserialize_result.is_success());
        
        EXPECT_EQ(deserialize_result.value().sequence_number, seq_num & 0xFFFFFFFFFFFF); // Mask to 48 bits
    }
}

/**
 * @brief Performance test for record operations
 */
TEST_F(RecordEdgeCasesTest, TestPerformance) {
    const int iterations = 1000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        RecordHeader header = create_valid_header();
        header.sequence_number = i;
        
        memory::Buffer buffer(RecordHeader::SERIALIZED_SIZE);
        auto result = header.serialize(buffer);
        ASSERT_TRUE(result.is_success());
        
        auto deserialize_result = RecordHeader::deserialize(buffer, 0);
        ASSERT_TRUE(deserialize_result.is_success());
        
        // Prevent optimization
        volatile bool valid = deserialize_result.value().is_valid();
        (void)valid;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete reasonably quickly (less than 100ms for 1000 iterations)
    EXPECT_LT(duration.count(), 100000);
}