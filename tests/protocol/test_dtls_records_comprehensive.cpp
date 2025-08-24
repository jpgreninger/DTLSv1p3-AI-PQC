/**
 * @file test_dtls_records_comprehensive.cpp
 * @brief Comprehensive tests for DTLS record layer structures
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <random>
#include <chrono>
#include <cstddef>
#include <numeric>

#include "dtls/protocol/dtls_records.h"
#include "dtls/types.h"
#include "dtls/memory/buffer.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

// Use alias to resolve ContentType ambiguity - use the protocol namespace types
using DTLSContentType = dtls::v13::protocol::ContentType;
using DTLSProtocolVersion = dtls::v13::protocol::ProtocolVersion;

class DTLSRecordsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
        test_payload_.resize(1024);
        for (size_t i = 0; i < test_payload_.size(); ++i) {
            test_payload_[i] = static_cast<std::byte>(i % 256);
        }
        
        small_payload_ = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
        
        large_payload_.resize(DTLSPlaintext::MAX_FRAGMENT_LENGTH);
        std::fill(large_payload_.begin(), large_payload_.end(), std::byte{0xAA});
        
        oversized_payload_.resize(DTLSPlaintext::MAX_FRAGMENT_LENGTH + 1000);
        std::fill(oversized_payload_.begin(), oversized_payload_.end(), std::byte{0xBB});
    }
    
    std::vector<std::byte> test_payload_;
    std::vector<std::byte> small_payload_;
    std::vector<std::byte> large_payload_;
    std::vector<std::byte> oversized_payload_;
};

// Test SequenceNumber48 basic operations
TEST_F(DTLSRecordsTest, SequenceNumber48BasicOperations) {
    // Default construction
    SequenceNumber48 seq1;
    EXPECT_EQ(seq1.value, 0);
    EXPECT_EQ(static_cast<uint64_t>(seq1), 0);
    
    // Value construction
    SequenceNumber48 seq2(0x123456789ABC);
    EXPECT_EQ(seq2.value, 0x123456789ABC);
    EXPECT_EQ(static_cast<uint64_t>(seq2), 0x123456789ABC);
    
    // Test 48-bit masking
    SequenceNumber48 seq3(0xFFFFFFFFFFFFFFFF);  // Full 64-bit value
    EXPECT_EQ(seq3.value, 0xFFFFFFFFFFFF);      // Should be masked to 48 bits
    
    // Test increment operators
    SequenceNumber48 seq4(100);
    auto pre_inc = ++seq4;
    EXPECT_EQ(seq4.value, 101);
    EXPECT_EQ(pre_inc.value, 101);
    
    auto post_inc = seq4++;
    EXPECT_EQ(seq4.value, 102);
    EXPECT_EQ(post_inc.value, 101);
    
    // Test overflow detection
    SequenceNumber48 max_seq(0xFFFFFFFFFFFF);
    EXPECT_TRUE(max_seq.would_overflow());
    
    SequenceNumber48 not_max(0xFFFFFFFFFFFE);
    EXPECT_FALSE(not_max.would_overflow());
}

// Test SequenceNumber48 serialization and deserialization
TEST_F(DTLSRecordsTest, SequenceNumber48Serialization) {
    SequenceNumber48 original(0x123456789ABC);
    
    // Test serialization
    uint8_t buffer[SequenceNumber48::SERIALIZED_SIZE];
    auto serialize_result = original.serialize_to_buffer(buffer);
    ASSERT_TRUE(serialize_result.is_ok());
    
    // Verify serialized format (big-endian)
    EXPECT_EQ(buffer[0], 0x12);
    EXPECT_EQ(buffer[1], 0x34);
    EXPECT_EQ(buffer[2], 0x56);
    EXPECT_EQ(buffer[3], 0x78);
    EXPECT_EQ(buffer[4], 0x9A);
    EXPECT_EQ(buffer[5], 0xBC);
    
    // Test deserialization
    auto deserialize_result = SequenceNumber48::deserialize_from_buffer(buffer);
    ASSERT_TRUE(deserialize_result.is_ok());
    
    auto deserialized = deserialize_result.value();
    EXPECT_EQ(deserialized.value, original.value);
    
    // Test edge cases
    SequenceNumber48 zero(0);
    auto zero_result = zero.serialize_to_buffer(buffer);
    ASSERT_TRUE(zero_result.is_ok());
    
    for (size_t i = 0; i < SequenceNumber48::SERIALIZED_SIZE; ++i) {
        EXPECT_EQ(buffer[i], 0);
    }
    
    SequenceNumber48 max_val(0xFFFFFFFFFFFF);
    auto max_result = max_val.serialize_to_buffer(buffer);
    ASSERT_TRUE(max_result.is_ok());
    
    for (size_t i = 0; i < SequenceNumber48::SERIALIZED_SIZE; ++i) {
        EXPECT_EQ(buffer[i], 0xFF);
    }
}

// Test DTLSPlaintext basic construction and properties
TEST_F(DTLSRecordsTest, DTLSPlaintextConstruction) {
    // Default construction - note that default constructor leaves fields uninitialized
    // We'll test the parameterized constructor instead which is the main use case
    DTLSPlaintext record1;
    // Don't test uninitialized values - they're random
    
    // Parameterized construction
    memory::ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
    DTLSPlaintext record2(
        DTLSContentType::HANDSHAKE,
        DTLSProtocolVersion::DTLS_1_3,
        1,
        SequenceNumber48(42),
        std::move(payload)
    );
    
    EXPECT_EQ(record2.type, DTLSContentType::HANDSHAKE);
    EXPECT_EQ(record2.version, DTLSProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record2.epoch, 1);
    EXPECT_EQ(static_cast<uint64_t>(record2.sequence_number), 42);
    EXPECT_EQ(record2.length, small_payload_.size());
    EXPECT_EQ(record2.fragment.size(), small_payload_.size());
    
    // Copy construction
    DTLSPlaintext record3 = record2;
    EXPECT_EQ(record3.type, record2.type);
    EXPECT_EQ(record3.version, record2.version);
    EXPECT_EQ(record3.epoch, record2.epoch);
    EXPECT_EQ(static_cast<uint64_t>(record3.sequence_number), static_cast<uint64_t>(record2.sequence_number));
    EXPECT_EQ(record3.fragment.size(), record2.fragment.size());
}

// Test DTLSPlaintext validation
TEST_F(DTLSRecordsTest, DTLSPlaintextValidation) {
    // Valid record
    memory::ZeroCopyBuffer valid_payload(small_payload_.data(), small_payload_.size());
    DTLSPlaintext valid_record(
        DTLSContentType::APPLICATION_DATA,
        DTLSProtocolVersion::DTLS_1_3,
        2,
        SequenceNumber48(100),
        std::move(valid_payload)
    );
    EXPECT_TRUE(valid_record.is_valid());
    
    // Invalid content type
    DTLSPlaintext invalid_type = valid_record;
    invalid_type.type = DTLSContentType::INVALID;
    EXPECT_FALSE(invalid_type.is_valid());
    
    // Invalid version
    DTLSPlaintext invalid_version = valid_record;
    invalid_version.version = DTLSProtocolVersion{0x0000}; // Invalid version
    EXPECT_FALSE(invalid_version.is_valid());
    
    // Fragment too large
    memory::ZeroCopyBuffer oversized_buffer(oversized_payload_.data(), oversized_payload_.size());
    DTLSPlaintext oversized_record(
        DTLSContentType::APPLICATION_DATA,
        DTLSProtocolVersion::DTLS_1_3,
        1,
        SequenceNumber48(1),
        std::move(oversized_buffer)
    );
    EXPECT_FALSE(oversized_record.is_valid());
    
    // Length mismatch
    DTLSPlaintext length_mismatch = valid_record;
    length_mismatch.length = 9999; // Doesn't match fragment size
    EXPECT_FALSE(length_mismatch.is_valid());
}

// Test DTLSPlaintext serialization
TEST_F(DTLSRecordsTest, DTLSPlaintextSerialization) {
    memory::ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
    DTLSPlaintext record(
        DTLSContentType::HANDSHAKE,
        DTLSProtocolVersion::DTLS_1_3,
        3,
        SequenceNumber48(0x123456789ABC),
        std::move(payload)
    );
    
    // Test serialization
    memory::Buffer output_buffer(1024);
    auto serialize_result = record.serialize(output_buffer);
    ASSERT_TRUE(serialize_result.is_ok());
    
    size_t expected_size = DTLSPlaintext::HEADER_SIZE + small_payload_.size();
    EXPECT_EQ(serialize_result.value(), expected_size);
    EXPECT_EQ(output_buffer.size(), expected_size);
    
    // Verify serialized header format
    const uint8_t* data = reinterpret_cast<const uint8_t*>(output_buffer.data());
    
    // Content type (1 byte)
    EXPECT_EQ(data[0], static_cast<uint8_t>(DTLSContentType::HANDSHAKE));
    
    // Version (2 bytes, big-endian)
    uint16_t version = static_cast<uint16_t>(DTLSProtocolVersion::DTLS_1_3);
    EXPECT_EQ(data[1], (version >> 8) & 0xFF);
    EXPECT_EQ(data[2], version & 0xFF);
    
    // Epoch (2 bytes, big-endian)
    EXPECT_EQ(data[3], 0x00);
    EXPECT_EQ(data[4], 0x03);
    
    // Sequence number (6 bytes, big-endian)
    EXPECT_EQ(data[5], 0x12);
    EXPECT_EQ(data[6], 0x34);
    EXPECT_EQ(data[7], 0x56);
    EXPECT_EQ(data[8], 0x78);
    EXPECT_EQ(data[9], 0x9A);
    EXPECT_EQ(data[10], 0xBC);
    
    // Length (2 bytes, big-endian)
    uint16_t expected_length = static_cast<uint16_t>(small_payload_.size());
    EXPECT_EQ(data[11], (expected_length >> 8) & 0xFF);
    EXPECT_EQ(data[12], expected_length & 0xFF);
    
    // Payload
    EXPECT_EQ(std::memcmp(data + DTLSPlaintext::HEADER_SIZE, small_payload_.data(), small_payload_.size()), 0);
}

// Test DTLSPlaintext deserialization
TEST_F(DTLSRecordsTest, DTLSPlaintextDeserialization) {
    // Create a serialized record first
    memory::ZeroCopyBuffer payload(test_payload_.data(), test_payload_.size());
    DTLSPlaintext original(
        DTLSContentType::APPLICATION_DATA,
        DTLSProtocolVersion::DTLS_1_3,
        5,
        SequenceNumber48(0xABCDEF123456),
        std::move(payload)
    );
    
    memory::Buffer serialized_buffer(1024);
    auto serialize_result = original.serialize(serialized_buffer);
    ASSERT_TRUE(serialize_result.is_ok());
    
    // Test deserialization
    auto deserialize_result = DTLSPlaintext::deserialize(serialized_buffer);
    ASSERT_TRUE(deserialize_result.is_ok());
    
    auto deserialized = deserialize_result.value();
    
    // Verify all fields match
    EXPECT_EQ(deserialized.type, original.type);
    EXPECT_EQ(deserialized.version, original.version);
    EXPECT_EQ(deserialized.epoch, original.epoch);
    EXPECT_EQ(static_cast<uint64_t>(deserialized.sequence_number), static_cast<uint64_t>(original.sequence_number));
    EXPECT_EQ(deserialized.length, original.length);
    EXPECT_EQ(deserialized.fragment.size(), original.fragment.size());
    
    // Verify payload data
    EXPECT_EQ(std::memcmp(
        deserialized.fragment.data(), 
        test_payload_.data(), 
        test_payload_.size()
    ), 0);
    
    // Test deserialization with offset
    memory::Buffer buffer_with_prefix(1024);
    std::vector<std::byte> prefix(10, std::byte{0xFF});
    auto append_result = buffer_with_prefix.append(prefix.data(), prefix.size());
    ASSERT_TRUE(append_result.is_ok());
    append_result = buffer_with_prefix.append(serialized_buffer.data(), serialized_buffer.size());
    ASSERT_TRUE(append_result.is_ok());
    
    auto offset_deserialize_result = DTLSPlaintext::deserialize(buffer_with_prefix, prefix.size());
    ASSERT_TRUE(offset_deserialize_result.is_ok());
    
    auto offset_deserialized = offset_deserialize_result.value();
    EXPECT_EQ(offset_deserialized.type, original.type);
    EXPECT_EQ(static_cast<uint64_t>(offset_deserialized.sequence_number), static_cast<uint64_t>(original.sequence_number));
}

// Test DTLSPlaintext error conditions during deserialization
TEST_F(DTLSRecordsTest, DTLSPlaintextDeserializationErrors) {
    // Buffer too small for header
    memory::Buffer tiny_buffer(5); // Less than HEADER_SIZE
    std::string hello = "HELLO";
    auto append_result = tiny_buffer.append(reinterpret_cast<const std::byte*>(hello.c_str()), 5);
    ASSERT_TRUE(append_result.is_ok());
    
    auto result1 = DTLSPlaintext::deserialize(tiny_buffer);
    EXPECT_TRUE(result1.is_error());
    
    // Invalid content type (using INVALID = 0)
    memory::Buffer invalid_content_buffer(20);
    std::vector<uint8_t> invalid_header = {
        0x00, // ContentType::INVALID (0)
        0xFE, 0xFC, // DTLS v1.3 version
        0x00, 0x01, // Epoch
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sequence number
        0x00, 0x04, // Length = 4
        0xDE, 0xAD, 0xBE, 0xEF // Payload
    };
    append_result = invalid_content_buffer.append(reinterpret_cast<const std::byte*>(invalid_header.data()), invalid_header.size());
    ASSERT_TRUE(append_result.is_ok());
    
    auto result2 = DTLSPlaintext::deserialize(invalid_content_buffer);
    // The deserializer should succeed but the record should fail validation due to INVALID content type
    ASSERT_TRUE(result2.is_success());
    auto record = result2.value();
    EXPECT_FALSE(record.is_valid()); // ContentType::INVALID should fail validation
    
    // Length field doesn't match available data
    memory::Buffer length_mismatch_buffer(20);
    std::vector<uint8_t> mismatch_header = {
        static_cast<uint8_t>(DTLSContentType::HANDSHAKE),
        0xFE, 0xFC, // DTLS v1.3 version
        0x00, 0x01, // Epoch
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sequence number
        0x00, 0x10, // Length = 16, but only 4 bytes follow
        0xDE, 0xAD, 0xBE, 0xEF // Only 4 bytes of payload
    };
    append_result = length_mismatch_buffer.append(reinterpret_cast<const std::byte*>(mismatch_header.data()), mismatch_header.size());
    ASSERT_TRUE(append_result.is_ok());
    
    auto result3 = DTLSPlaintext::deserialize(length_mismatch_buffer);
    EXPECT_TRUE(result3.is_error());
    
    // Fragment length exceeds maximum
    memory::Buffer oversized_header_buffer(20);
    std::vector<uint8_t> oversized_header = {
        static_cast<uint8_t>(DTLSContentType::APPLICATION_DATA),
        0xFE, 0xFC, // DTLS v1.3 version
        0x00, 0x01, // Epoch
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sequence number
        0xFF, 0xFF, // Length = 65535 (exceeds MAX_FRAGMENT_LENGTH)
        0xDE, 0xAD, 0xBE, 0xEF // Payload
    };
    append_result = oversized_header_buffer.append(reinterpret_cast<const std::byte*>(oversized_header.data()), oversized_header.size());
    ASSERT_TRUE(append_result.is_ok());
    
    auto result4 = DTLSPlaintext::deserialize(oversized_header_buffer);
    EXPECT_TRUE(result4.is_error());
}

// Test DTLSPlaintext size calculations
TEST_F(DTLSRecordsTest, DTLSPlaintextSizeCalculations) {
    memory::ZeroCopyBuffer payload(test_payload_.data(), test_payload_.size());
    DTLSPlaintext record(
        DTLSContentType::HANDSHAKE,
        DTLSProtocolVersion::DTLS_1_3,
        1,
        SequenceNumber48(1),
        std::move(payload)
    );
    
    // Test total size calculation
    size_t expected_total_size = DTLSPlaintext::HEADER_SIZE + test_payload_.size();
    EXPECT_EQ(record.total_size(), expected_total_size);
    
    // Test header size constant
    EXPECT_EQ(DTLSPlaintext::HEADER_SIZE, 13); // 1+2+2+6+2
    
    // Test maximum fragment length constant
    EXPECT_EQ(DTLSPlaintext::MAX_FRAGMENT_LENGTH, 16384);
}

// Test DTLSPlaintext with different content types
TEST_F(DTLSRecordsTest, DTLSPlaintextContentTypes) {
    std::vector<DTLSContentType> valid_types = {
        DTLSContentType::CHANGE_CIPHER_SPEC,
        DTLSContentType::ALERT,
        DTLSContentType::HANDSHAKE,
        DTLSContentType::APPLICATION_DATA,
        DTLSContentType::HEARTBEAT,
        DTLSContentType::TLS12_CID
    };
    
    for (auto content_type : valid_types) {
        memory::ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
        DTLSPlaintext record(
            content_type,
            DTLSProtocolVersion::DTLS_1_3,
            1,
            SequenceNumber48(1),
            std::move(payload)
        );
        
        EXPECT_TRUE(record.is_valid());
        EXPECT_EQ(record.type, content_type);
        
        // Test serialization round-trip
        memory::Buffer serialize_buffer(1024);
        auto serialize_result = record.serialize(serialize_buffer);
        ASSERT_TRUE(serialize_result.is_ok());
        
        auto deserialize_result = DTLSPlaintext::deserialize(serialize_buffer);
        ASSERT_TRUE(deserialize_result.is_ok());
        
        auto deserialized = deserialize_result.value();
        EXPECT_EQ(deserialized.type, content_type);
    }
}

// Test DTLSPlaintext with different protocol versions
TEST_F(DTLSRecordsTest, DTLSPlaintextProtocolVersions) {
    std::vector<DTLSProtocolVersion> versions = {DTLSProtocolVersion::DTLS_1_0, DTLSProtocolVersion::DTLS_1_2, DTLSProtocolVersion::DTLS_1_3};
    
    for (auto version : versions) {
        memory::ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
        DTLSPlaintext record(
            DTLSContentType::HANDSHAKE,
            version,
            1,
            SequenceNumber48(1),
            std::move(payload)
        );
        
        EXPECT_EQ(record.version, version);
        
        // Test serialization preserves version
        memory::Buffer serialize_buffer(1024);
        auto serialize_result = record.serialize(serialize_buffer);
        ASSERT_TRUE(serialize_result.is_ok());
        
        auto deserialize_result = DTLSPlaintext::deserialize(serialize_buffer);
        ASSERT_TRUE(deserialize_result.is_ok());
        
        auto deserialized = deserialize_result.value();
        EXPECT_EQ(deserialized.version, version);
    }
}

// Test DTLSPlaintext with edge case sequence numbers
TEST_F(DTLSRecordsTest, DTLSPlaintextSequenceNumberEdgeCases) {
    std::vector<uint64_t> test_sequence_numbers = {
        0,                          // Minimum
        1,                          // First valid
        0x123456789ABC,            // Arbitrary value
        0xFFFFFFFFFFFF,            // Maximum 48-bit value
        0xFFFFFFFFFFFFFFFF          // Should be masked to 48 bits
    };
    
    for (auto seq_num : test_sequence_numbers) {
        memory::ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
        DTLSPlaintext record(
            DTLSContentType::APPLICATION_DATA,
            DTLSProtocolVersion::DTLS_1_3,
            1,
            SequenceNumber48(seq_num),
            std::move(payload)
        );
        
        // Verify 48-bit masking
        uint64_t expected_seq = seq_num & 0xFFFFFFFFFFFF;
        EXPECT_EQ(static_cast<uint64_t>(record.sequence_number), expected_seq);
        
        // Test serialization round-trip
        memory::Buffer serialize_buffer(1024);
        auto serialize_result = record.serialize(serialize_buffer);
        ASSERT_TRUE(serialize_result.is_ok());
        
        auto deserialize_result = DTLSPlaintext::deserialize(serialize_buffer);
        ASSERT_TRUE(deserialize_result.is_ok());
        
        auto deserialized = deserialize_result.value();
        EXPECT_EQ(static_cast<uint64_t>(deserialized.sequence_number), expected_seq);
    }
}

// Test DTLSPlaintext performance characteristics
TEST_F(DTLSRecordsTest, DTLSPlaintextPerformance) {
    constexpr int num_operations = 1000;
    std::vector<DTLSPlaintext> records;
    records.reserve(num_operations);
    
    // Measure construction time
    auto start_construction = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_operations; ++i) {
        memory::ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
        records.emplace_back(
            DTLSContentType::APPLICATION_DATA,
            DTLSProtocolVersion::DTLS_1_3,
            static_cast<uint16_t>(i % 65536),
            SequenceNumber48(i),
            std::move(payload)
        );
    }
    
    auto end_construction = std::chrono::high_resolution_clock::now();
    auto construction_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end_construction - start_construction);
    
    // Measure serialization time
    std::vector<memory::Buffer> serialized_buffers;
    serialized_buffers.reserve(num_operations);
    
    auto start_serialization = std::chrono::high_resolution_clock::now();
    
    for (auto& record : records) {
        memory::Buffer buffer(1024);
        auto result = record.serialize(buffer);
        ASSERT_TRUE(result.is_ok());
        serialized_buffers.push_back(std::move(buffer));
    }
    
    auto end_serialization = std::chrono::high_resolution_clock::now();
    auto serialization_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end_serialization - start_serialization);
    
    // Measure deserialization time
    auto start_deserialization = std::chrono::high_resolution_clock::now();
    
    for (const auto& buffer : serialized_buffers) {
        auto result = DTLSPlaintext::deserialize(buffer);
        ASSERT_TRUE(result.is_ok());
    }
    
    auto end_deserialization = std::chrono::high_resolution_clock::now();
    auto deserialization_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end_deserialization - start_deserialization);
    
    // Performance expectations (adjust based on actual hardware)
    EXPECT_LT(construction_time.count(), 10000); // Less than 10ms for 1000 constructions
    EXPECT_LT(serialization_time.count(), 20000); // Less than 20ms for 1000 serializations  
    EXPECT_LT(deserialization_time.count(), 20000); // Less than 20ms for 1000 deserializations
    
    // Log performance metrics
    std::cout << "Construction: " << construction_time.count() << " μs (" 
              << (construction_time.count() / num_operations) << " μs per operation)" << std::endl;
    std::cout << "Serialization: " << serialization_time.count() << " μs (" 
              << (serialization_time.count() / num_operations) << " μs per operation)" << std::endl;
    std::cout << "Deserialization: " << deserialization_time.count() << " μs (" 
              << (deserialization_time.count() / num_operations) << " μs per operation)" << std::endl;
}