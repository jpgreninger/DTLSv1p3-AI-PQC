#include <gtest/gtest.h>
#include <dtls/protocol/dtls_records.h>
#include <dtls/memory/buffer.h>
#include <dtls/error.h>
#include <vector>
#include <cstring>

using namespace dtls::v13::memory;
using namespace dtls::v13;
// Use explicit namespaces to avoid ambiguity with dtls::v13 types
namespace protocol = dtls::v13::protocol;

class DTLSRecordsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up common test data
        test_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        test_buffer = ZeroCopyBuffer(test_data.size());
        test_buffer.resize(test_data.size());
        std::memcpy(test_buffer.mutable_data(), test_data.data(), test_data.size());
    }
    
    std::vector<uint8_t> test_data;
    ZeroCopyBuffer test_buffer;
};

// protocol::SequenceNumber48 Tests
TEST_F(DTLSRecordsTest, SequenceNumber48Construction) {
    protocol::SequenceNumber48 seq1;
    EXPECT_EQ(seq1.value, 0);
    
    protocol::SequenceNumber48 seq2(0x123456789ABC);
    EXPECT_EQ(seq2.value, 0x123456789ABC);
    
    // Test 48-bit limit (should mask higher bits)
    protocol::SequenceNumber48 seq3(0xFFFFFFFFFFFFFFFF);
    EXPECT_EQ(seq3.value, 0xFFFFFFFFFFFF);
}

TEST_F(DTLSRecordsTest, SequenceNumber48Increment) {
    protocol::SequenceNumber48 seq(100);
    
    protocol::SequenceNumber48 result = seq++;
    EXPECT_EQ(result.value, 100);
    EXPECT_EQ(seq.value, 101);
    
    result = ++seq;
    EXPECT_EQ(result.value, 102);
    EXPECT_EQ(seq.value, 102);
}

TEST_F(DTLSRecordsTest, SequenceNumber48Overflow) {
    protocol::SequenceNumber48 seq(0xFFFFFFFFFFFF);
    EXPECT_TRUE(seq.would_overflow());
    
    seq++;
    EXPECT_EQ(seq.value, 0); // Should wrap to 0
    EXPECT_FALSE(seq.would_overflow());
}

TEST_F(DTLSRecordsTest, SequenceNumber48Serialization) {
    protocol::SequenceNumber48 seq(0x123456789ABC);
    uint8_t buffer[6];
    
    auto result = seq.serialize_to_buffer(buffer);
    ASSERT_TRUE(result.is_success());
    
    // Check big-endian serialization
    EXPECT_EQ(buffer[0], 0x12);
    EXPECT_EQ(buffer[1], 0x34);
    EXPECT_EQ(buffer[2], 0x56);
    EXPECT_EQ(buffer[3], 0x78);
    EXPECT_EQ(buffer[4], 0x9A);
    EXPECT_EQ(buffer[5], 0xBC);
}

TEST_F(DTLSRecordsTest, SequenceNumber48Deserialization) {
    uint8_t buffer[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    
    auto result = protocol::SequenceNumber48::deserialize_from_buffer(buffer);
    ASSERT_TRUE(result.is_success());
    
    protocol::SequenceNumber48 seq = result.value();
    EXPECT_EQ(seq.value, 0x123456789ABC);
}

TEST_F(DTLSRecordsTest, SequenceNumber48RoundTrip) {
    protocol::SequenceNumber48 original(0xABCDEF123456);
    uint8_t buffer[6];
    
    auto serialize_result = original.serialize_to_buffer(buffer);
    ASSERT_TRUE(serialize_result.is_success());
    
    auto deserialize_result = protocol::SequenceNumber48::deserialize_from_buffer(buffer);
    ASSERT_TRUE(deserialize_result.is_success());
    
    EXPECT_EQ(original.value, deserialize_result.value().value);
}

// protocol::DTLSPlaintext Tests
TEST_F(DTLSRecordsTest, DTLSPlaintextConstruction) {
    protocol::DTLSPlaintext record(protocol::ContentType::HANDSHAKE, protocol::ProtocolVersion::DTLS_1_3, 
                        1, protocol::SequenceNumber48(100), std::move(test_buffer));
    
    EXPECT_EQ(record.get_type(), protocol::ContentType::HANDSHAKE);
    EXPECT_EQ(record.get_version(), protocol::ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.get_epoch(), 1);
    EXPECT_EQ(record.get_sequence_number().value, 100);
    EXPECT_EQ(record.get_length(), test_data.size());
    EXPECT_TRUE(record.is_valid());
}

TEST_F(DTLSRecordsTest, DTLSPlaintextCopyConstructor) {
    protocol::DTLSPlaintext original(protocol::ContentType::HANDSHAKE, protocol::ProtocolVersion::DTLS_1_3,
                          1, protocol::SequenceNumber48(100), std::move(test_buffer));
    
    protocol::DTLSPlaintext copy(original);
    
    EXPECT_EQ(copy.get_type(), original.get_type());
    EXPECT_EQ(copy.get_epoch(), original.get_epoch());
    EXPECT_EQ(copy.get_sequence_number().value, original.get_sequence_number().value);
    EXPECT_EQ(copy.get_length(), original.get_length());
    
    // Verify deep copy of fragment
    EXPECT_EQ(copy.get_fragment().size(), test_data.size());
    EXPECT_EQ(std::memcmp(copy.get_fragment().data(), test_data.data(), test_data.size()), 0);
}

TEST_F(DTLSRecordsTest, DTLSPlaintextSerialization) {
    protocol::DTLSPlaintext record(protocol::ContentType::HANDSHAKE, protocol::ProtocolVersion::DTLS_1_3,
                        0x1234, protocol::SequenceNumber48(0x123456789ABC), std::move(test_buffer));
    
    ZeroCopyBuffer output_buffer;
    auto result = record.serialize(output_buffer);
    ASSERT_TRUE(result.is_success());
    
    size_t bytes_written = result.value();
    EXPECT_EQ(bytes_written, protocol::DTLSPlaintext::HEADER_SIZE + test_data.size());
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(output_buffer.data());
    
    // Check header fields
    EXPECT_EQ(data[0], static_cast<uint8_t>(protocol::ContentType::HANDSHAKE));
    EXPECT_EQ((data[1] << 8) | data[2], static_cast<uint16_t>(protocol::ProtocolVersion::DTLS_1_3));
    EXPECT_EQ((data[3] << 8) | data[4], 0x1234); // epoch
    
    // Check sequence number (48-bit big-endian)
    uint64_t seq = 0;
    seq |= (static_cast<uint64_t>(data[5]) << 40);
    seq |= (static_cast<uint64_t>(data[6]) << 32);
    seq |= (static_cast<uint64_t>(data[7]) << 24);
    seq |= (static_cast<uint64_t>(data[8]) << 16);
    seq |= (static_cast<uint64_t>(data[9]) << 8);
    seq |= static_cast<uint64_t>(data[10]);
    EXPECT_EQ(seq, 0x123456789ABC);
    
    // Check length
    EXPECT_EQ((data[11] << 8) | data[12], test_data.size());
    
    // Check fragment data
    EXPECT_EQ(std::memcmp(&data[13], test_data.data(), test_data.size()), 0);
}

TEST_F(DTLSRecordsTest, DTLSPlaintextDeserialization) {
    // Create test serialized data
    std::vector<uint8_t> serialized_data = {
        static_cast<uint8_t>(protocol::ContentType::APPLICATION_DATA), // type
        0xFE, 0xFC,                                          // version (DTLS 1.3)  
        0x12, 0x34,                                          // epoch
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,                 // sequence number
        0x00, 0x08,                                          // length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08      // fragment
    };
    
    ZeroCopyBuffer input_buffer(serialized_data.size());
    input_buffer.resize(serialized_data.size());
    std::memcpy(input_buffer.mutable_data(), serialized_data.data(), serialized_data.size());
    
    auto result = protocol::DTLSPlaintext::deserialize(input_buffer);
    ASSERT_TRUE(result.is_success());
    
    protocol::DTLSPlaintext record = result.value();
    EXPECT_EQ(record.get_type(), protocol::ContentType::APPLICATION_DATA);
    EXPECT_EQ(record.get_version(), protocol::ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.get_epoch(), 0x1234);
    EXPECT_EQ(record.get_sequence_number().value, 0x123456789ABC);
    EXPECT_EQ(record.get_length(), 8);
    EXPECT_TRUE(record.is_valid());
}

TEST_F(DTLSRecordsTest, DTLSPlaintextRoundTrip) {
    protocol::DTLSPlaintext original(protocol::ContentType::ALERT, protocol::ProtocolVersion::DTLS_1_3,
                          0x5678, protocol::SequenceNumber48(0xDEADBEEFCAFE), std::move(test_buffer));
    
    ZeroCopyBuffer serialized;
    auto serialize_result = original.serialize(serialized);
    ASSERT_TRUE(serialize_result.is_success());
    
    auto deserialize_result = protocol::DTLSPlaintext::deserialize(serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    protocol::DTLSPlaintext deserialized = deserialize_result.value();
    
    EXPECT_EQ(deserialized.get_type(), original.get_type());
    EXPECT_EQ(deserialized.get_version(), original.get_version());
    EXPECT_EQ(deserialized.get_epoch(), original.get_epoch());
    EXPECT_EQ(deserialized.get_sequence_number().value, original.get_sequence_number().value);
    EXPECT_EQ(deserialized.get_length(), original.get_length());
    
    // Note: Original buffer was moved, so we compare with the test_data directly
    EXPECT_EQ(std::memcmp(deserialized.get_fragment().data(), test_data.data(), test_data.size()), 0);
}

TEST_F(DTLSRecordsTest, DTLSPlaintextValidation) {
    // Valid record
    protocol::DTLSPlaintext valid_record(protocol::ContentType::HANDSHAKE, protocol::ProtocolVersion::DTLS_1_3,
                              1, protocol::SequenceNumber48(100), ZeroCopyBuffer(100));
    EXPECT_TRUE(valid_record.is_valid());
    
    // Invalid content type
    protocol::DTLSPlaintext invalid_type(protocol::ContentType::INVALID, protocol::ProtocolVersion::DTLS_1_3,
                              1, protocol::SequenceNumber48(100), ZeroCopyBuffer(100));
    EXPECT_FALSE(invalid_type.is_valid());
    
    // Invalid protocol version
    protocol::DTLSPlaintext invalid_version(protocol::ContentType::HANDSHAKE, protocol::ProtocolVersion::DTLS_1_2,
                                 1, protocol::SequenceNumber48(100), ZeroCopyBuffer(100));
    EXPECT_FALSE(invalid_version.is_valid());
    
    // Fragment too large - create buffer with actual 20000 bytes of data
    std::vector<uint8_t> large_data(20000, 0x42);  // Create vector with 20000 bytes
    memory::ZeroCopyBuffer large_buffer(reinterpret_cast<const std::byte*>(large_data.data()), large_data.size());
    
    protocol::DTLSPlaintext large_fragment(protocol::ContentType::HANDSHAKE, protocol::ProtocolVersion::DTLS_1_3,
                                1, protocol::SequenceNumber48(100), std::move(large_buffer));
    
    EXPECT_FALSE(large_fragment.is_valid());
}

// protocol::DTLSCiphertext Tests
TEST_F(DTLSRecordsTest, DTLSCiphertextConstruction) {
    protocol::DTLSCiphertext record(protocol::ContentType::APPLICATION_DATA, protocol::ProtocolVersion::DTLS_1_3,
                         1, protocol::SequenceNumber48(100), std::move(test_buffer));
    
    EXPECT_EQ(record.get_type(), protocol::ContentType::APPLICATION_DATA);
    EXPECT_EQ(record.get_version(), protocol::ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.get_epoch(), 1);
    EXPECT_EQ(record.get_encrypted_sequence_number().value, 100);
    EXPECT_EQ(record.get_length(), test_data.size());
    EXPECT_FALSE(record.has_cid());
    EXPECT_TRUE(record.is_valid());
}

TEST_F(DTLSRecordsTest, DTLSCiphertextConnectionID) {
    protocol::DTLSCiphertext record(protocol::ContentType::APPLICATION_DATA, protocol::ProtocolVersion::DTLS_1_3,
                         1, protocol::SequenceNumber48(100), ZeroCopyBuffer(100));
    
    std::vector<uint8_t> cid = {0xAA, 0xBB, 0xCC, 0xDD};
    record.set_connection_id(cid);
    
    EXPECT_TRUE(record.has_cid());
    EXPECT_EQ(record.get_connection_id_length(), 4);
    
    auto retrieved_cid = record.get_connection_id_vector();
    EXPECT_EQ(retrieved_cid, cid);
    
    record.clear_connection_id();
    EXPECT_FALSE(record.has_cid());
    EXPECT_EQ(record.get_connection_id_length(), 0);
}

TEST_F(DTLSRecordsTest, DTLSCiphertextSerialization) {
    protocol::DTLSCiphertext record(protocol::ContentType::APPLICATION_DATA, protocol::ProtocolVersion::DTLS_1_3,
                         0x9876, protocol::SequenceNumber48(0xFEDCBA987654), std::move(test_buffer));
    
    ZeroCopyBuffer output_buffer;
    auto result = record.serialize(output_buffer);
    ASSERT_TRUE(result.is_success());
    
    size_t bytes_written = result.value();
    EXPECT_EQ(bytes_written, protocol::DTLSCiphertext::HEADER_SIZE + test_data.size());
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(output_buffer.data());
    
    // Check header fields (same format as protocol::DTLSPlaintext)
    EXPECT_EQ(data[0], static_cast<uint8_t>(protocol::ContentType::APPLICATION_DATA));
    EXPECT_EQ((data[1] << 8) | data[2], static_cast<uint16_t>(protocol::ProtocolVersion::DTLS_1_3));
    EXPECT_EQ((data[3] << 8) | data[4], 0x9876); // epoch
    
    // Check encrypted sequence number
    uint64_t seq = 0;
    seq |= (static_cast<uint64_t>(data[5]) << 40);
    seq |= (static_cast<uint64_t>(data[6]) << 32);
    seq |= (static_cast<uint64_t>(data[7]) << 24);
    seq |= (static_cast<uint64_t>(data[8]) << 16);
    seq |= (static_cast<uint64_t>(data[9]) << 8);
    seq |= static_cast<uint64_t>(data[10]);
    EXPECT_EQ(seq, 0xFEDCBA987654);
    
    // Check length
    EXPECT_EQ((data[11] << 8) | data[12], test_data.size());
    
    // Check encrypted record data
    EXPECT_EQ(std::memcmp(&data[13], test_data.data(), test_data.size()), 0);
}

TEST_F(DTLSRecordsTest, DTLSCiphertextRoundTrip) {
    protocol::DTLSCiphertext original(protocol::ContentType::APPLICATION_DATA, protocol::ProtocolVersion::DTLS_1_3,
                           0xABCD, protocol::SequenceNumber48(0x111111111111), std::move(test_buffer));
    
    ZeroCopyBuffer serialized;
    auto serialize_result = original.serialize(serialized);
    ASSERT_TRUE(serialize_result.is_success());
    
    auto deserialize_result = protocol::DTLSCiphertext::deserialize(serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    protocol::DTLSCiphertext deserialized = deserialize_result.value();
    
    EXPECT_EQ(deserialized.get_type(), original.get_type());
    EXPECT_EQ(deserialized.get_version(), original.get_version());
    EXPECT_EQ(deserialized.get_epoch(), original.get_epoch());
    EXPECT_EQ(deserialized.get_encrypted_sequence_number().value, 
              original.get_encrypted_sequence_number().value);
    EXPECT_EQ(deserialized.get_length(), original.get_length());
}

// Utility Functions Tests
TEST_F(DTLSRecordsTest, UtilityFunctions) {
    // Create a test record
    protocol::DTLSPlaintext record(protocol::ContentType::HANDSHAKE, protocol::ProtocolVersion::DTLS_1_3,
                        0x1234, protocol::SequenceNumber48(0x567890ABCDEF), ZeroCopyBuffer(100));
    
    ZeroCopyBuffer serialized;
    auto result = record.serialize(serialized);
    ASSERT_TRUE(result.is_success());
    
    // Test utility functions
    auto type_result = protocol::dtls_records_utils::extract_content_type(serialized);
    ASSERT_TRUE(type_result.is_success());
    EXPECT_EQ(type_result.value(), protocol::ContentType::HANDSHAKE);
    
    auto version_result = protocol::dtls_records_utils::extract_protocol_version(serialized);
    ASSERT_TRUE(version_result.is_success());
    EXPECT_EQ(version_result.value(), protocol::ProtocolVersion::DTLS_1_3);
    
    auto epoch_result = protocol::dtls_records_utils::extract_epoch(serialized);
    ASSERT_TRUE(epoch_result.is_success());
    EXPECT_EQ(epoch_result.value(), 0x1234);
    
    auto seq_result = protocol::dtls_records_utils::extract_sequence_number(serialized);
    ASSERT_TRUE(seq_result.is_success());
    EXPECT_EQ(seq_result.value().value, 0x567890ABCDEF);
    
    EXPECT_TRUE(protocol::dtls_records_utils::is_dtls_record(serialized));
    EXPECT_TRUE(protocol::dtls_records_utils::validate_record_length(100, 100));
    EXPECT_FALSE(protocol::dtls_records_utils::validate_record_length(100, 200));
}

TEST_F(DTLSRecordsTest, SequenceNumberOverflowDetection) {
    // Test near overflow detection (90% of 48-bit max)
    protocol::SequenceNumber48 near_overflow(0xE66666666665ULL); // 90% of max
    EXPECT_TRUE(protocol::dtls_records_utils::is_sequence_number_near_overflow(near_overflow));
    
    protocol::SequenceNumber48 not_near_overflow(0x1999999999999ULL); // ~10% of max  
    EXPECT_FALSE(protocol::dtls_records_utils::is_sequence_number_near_overflow(not_near_overflow));
    
    protocol::SequenceNumber48 at_max(0xFFFFFFFFFFFFULL);
    EXPECT_TRUE(protocol::dtls_records_utils::is_sequence_number_near_overflow(at_max));
    
    // Test edge case: exactly at 90% threshold
    protocol::SequenceNumber48 exactly_90_percent(0xE66666666666ULL); // Exactly 90%
    EXPECT_TRUE(protocol::dtls_records_utils::is_sequence_number_near_overflow(exactly_90_percent));
}

TEST_F(DTLSRecordsTest, ErrorHandling) {
    // Test deserialization with insufficient buffer
    ZeroCopyBuffer small_buffer(5);
    small_buffer.resize(5);
    
    auto result = protocol::DTLSPlaintext::deserialize(small_buffer);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), dtls::v13::DTLSError::DECODE_ERROR);
    
    // Test sequence number serialization with null buffer
    protocol::SequenceNumber48 seq(100);
    auto seq_result = seq.serialize_to_buffer(nullptr);
    EXPECT_FALSE(seq_result.is_success());
    EXPECT_EQ(seq_result.error(), dtls::v13::DTLSError::INTERNAL_ERROR);
}

TEST_F(DTLSRecordsTest, MaximumSizes) {
    // Test maximum fragment size
    ZeroCopyBuffer max_fragment(protocol::DTLSPlaintext::MAX_FRAGMENT_LENGTH);
    max_fragment.resize(protocol::DTLSPlaintext::MAX_FRAGMENT_LENGTH);
    
    protocol::DTLSPlaintext max_record(protocol::ContentType::APPLICATION_DATA, protocol::ProtocolVersion::DTLS_1_3,
                            1, protocol::SequenceNumber48(100), std::move(max_fragment));
    EXPECT_TRUE(max_record.is_valid());
    
    // Test oversized fragment
    ZeroCopyBuffer oversized_fragment(protocol::DTLSPlaintext::MAX_FRAGMENT_LENGTH + 1);
    oversized_fragment.resize(protocol::DTLSPlaintext::MAX_FRAGMENT_LENGTH + 1);
    
    protocol::DTLSPlaintext oversized_record(protocol::ContentType::APPLICATION_DATA, protocol::ProtocolVersion::DTLS_1_3,
                                  1, protocol::SequenceNumber48(100), std::move(oversized_fragment));
    EXPECT_FALSE(oversized_record.is_valid());
}

// Performance Tests
TEST_F(DTLSRecordsTest, SerializationPerformance) {
    const int iterations = 1000;
    ZeroCopyBuffer test_payload(1000);
    test_payload.resize(1000);
    
    // Time protocol::DTLSPlaintext serialization
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        ZeroCopyBuffer payload_copy(test_payload.size());
        payload_copy.resize(test_payload.size());
        std::memcpy(payload_copy.mutable_data(), test_payload.data(), test_payload.size());
        
        protocol::DTLSPlaintext record(protocol::ContentType::APPLICATION_DATA, protocol::ProtocolVersion::DTLS_1_3,
                            i, protocol::SequenceNumber48(i), std::move(payload_copy));
        
        ZeroCopyBuffer output;
        auto result = record.serialize(output);
        EXPECT_TRUE(result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should be reasonably fast (less than 1ms per operation on average)
    EXPECT_LT(duration.count() / iterations, 1000); // Less than 1000 microseconds per op
    
    std::cout << "Average serialization time: " << (duration.count() / iterations) 
              << " microseconds per record" << std::endl;
}