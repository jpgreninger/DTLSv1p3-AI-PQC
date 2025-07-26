#include <gtest/gtest.h>
#include <dtls/protocol/dtls_records.h>
#include <dtls/memory/buffer.h>
#include <vector>
#include <cstring>

using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

class DTLSRecordsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up common test data
        test_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        test_buffer = Buffer(test_data.size());
        test_buffer.resize(test_data.size());
        std::memcpy(test_buffer.mutable_data(), test_data.data(), test_data.size());
    }
    
    std::vector<uint8_t> test_data;
    Buffer test_buffer;
};

// SequenceNumber48 Tests
TEST_F(DTLSRecordsTest, SequenceNumber48Construction) {
    SequenceNumber48 seq1;
    EXPECT_EQ(seq1.value, 0);
    
    SequenceNumber48 seq2(0x123456789ABC);
    EXPECT_EQ(seq2.value, 0x123456789ABC);
    
    // Test 48-bit limit (should mask higher bits)
    SequenceNumber48 seq3(0xFFFFFFFFFFFFFFFF);
    EXPECT_EQ(seq3.value, 0xFFFFFFFFFFFF);
}

TEST_F(DTLSRecordsTest, SequenceNumber48Increment) {
    SequenceNumber48 seq(100);
    
    SequenceNumber48 result = seq++;
    EXPECT_EQ(result.value, 100);
    EXPECT_EQ(seq.value, 101);
    
    result = ++seq;
    EXPECT_EQ(result.value, 102);
    EXPECT_EQ(seq.value, 102);
}

TEST_F(DTLSRecordsTest, SequenceNumber48Overflow) {
    SequenceNumber48 seq(0xFFFFFFFFFFFF);
    EXPECT_TRUE(seq.would_overflow());
    
    seq++;
    EXPECT_EQ(seq.value, 0); // Should wrap to 0
    EXPECT_FALSE(seq.would_overflow());
}

TEST_F(DTLSRecordsTest, SequenceNumber48Serialization) {
    SequenceNumber48 seq(0x123456789ABC);
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
    
    auto result = SequenceNumber48::deserialize_from_buffer(buffer);
    ASSERT_TRUE(result.is_success());
    
    SequenceNumber48 seq = result.value();
    EXPECT_EQ(seq.value, 0x123456789ABC);
}

TEST_F(DTLSRecordsTest, SequenceNumber48RoundTrip) {
    SequenceNumber48 original(0xABCDEF123456);
    uint8_t buffer[6];
    
    auto serialize_result = original.serialize_to_buffer(buffer);
    ASSERT_TRUE(serialize_result.is_success());
    
    auto deserialize_result = SequenceNumber48::deserialize_from_buffer(buffer);
    ASSERT_TRUE(deserialize_result.is_success());
    
    EXPECT_EQ(original.value, deserialize_result.value().value);
}

// DTLSPlaintext Tests
TEST_F(DTLSRecordsTest, DTLSPlaintextConstruction) {
    DTLSPlaintext record(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_3, 
                        1, SequenceNumber48(100), std::move(test_buffer));
    
    EXPECT_EQ(record.get_type(), ContentType::HANDSHAKE);
    EXPECT_EQ(record.get_version(), ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.get_epoch(), 1);
    EXPECT_EQ(record.get_sequence_number().value, 100);
    EXPECT_EQ(record.get_length(), test_data.size());
    EXPECT_TRUE(record.is_valid());
}

TEST_F(DTLSRecordsTest, DTLSPlaintextCopyConstructor) {
    DTLSPlaintext original(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_3,
                          1, SequenceNumber48(100), std::move(test_buffer));
    
    DTLSPlaintext copy(original);
    
    EXPECT_EQ(copy.get_type(), original.get_type());
    EXPECT_EQ(copy.get_epoch(), original.get_epoch());
    EXPECT_EQ(copy.get_sequence_number().value, original.get_sequence_number().value);
    EXPECT_EQ(copy.get_length(), original.get_length());
    
    // Verify deep copy of fragment
    EXPECT_EQ(copy.get_fragment().size(), test_data.size());
    EXPECT_EQ(std::memcmp(copy.get_fragment().data(), test_data.data(), test_data.size()), 0);
}

TEST_F(DTLSRecordsTest, DTLSPlaintextSerialization) {
    DTLSPlaintext record(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_3,
                        0x1234, SequenceNumber48(0x123456789ABC), std::move(test_buffer));
    
    Buffer output_buffer;
    auto result = record.serialize(output_buffer);
    ASSERT_TRUE(result.is_success());
    
    size_t bytes_written = result.value();
    EXPECT_EQ(bytes_written, DTLSPlaintext::HEADER_SIZE + test_data.size());
    
    const uint8_t* data = output_buffer.data();
    
    // Check header fields
    EXPECT_EQ(data[0], static_cast<uint8_t>(ContentType::HANDSHAKE));
    EXPECT_EQ((data[1] << 8) | data[2], ProtocolVersion::DTLS_1_3);
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
        static_cast<uint8_t>(ContentType::APPLICATION_DATA), // type
        0xFE, 0xFC,                                          // version (DTLS 1.3)  
        0x12, 0x34,                                          // epoch
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,                 // sequence number
        0x00, 0x08,                                          // length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08      // fragment
    };
    
    Buffer input_buffer(serialized_data.size());
    input_buffer.resize(serialized_data.size());
    std::memcpy(input_buffer.mutable_data(), serialized_data.data(), serialized_data.size());
    
    auto result = DTLSPlaintext::deserialize(input_buffer);
    ASSERT_TRUE(result.is_success());
    
    DTLSPlaintext record = result.value();
    EXPECT_EQ(record.get_type(), ContentType::APPLICATION_DATA);
    EXPECT_EQ(record.get_version(), ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.get_epoch(), 0x1234);
    EXPECT_EQ(record.get_sequence_number().value, 0x123456789ABC);
    EXPECT_EQ(record.get_length(), 8);
    EXPECT_TRUE(record.is_valid());
}

TEST_F(DTLSRecordsTest, DTLSPlaintextRoundTrip) {
    DTLSPlaintext original(ContentType::ALERT, ProtocolVersion::DTLS_1_3,
                          0x5678, SequenceNumber48(0xDEADBEEFCAFE), std::move(test_buffer));
    
    Buffer serialized;
    auto serialize_result = original.serialize(serialized);
    ASSERT_TRUE(serialize_result.is_success());
    
    auto deserialize_result = DTLSPlaintext::deserialize(serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    DTLSPlaintext deserialized = deserialize_result.value();
    
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
    DTLSPlaintext valid_record(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_3,
                              1, SequenceNumber48(100), Buffer(100));
    EXPECT_TRUE(valid_record.is_valid());
    
    // Invalid content type
    DTLSPlaintext invalid_type(ContentType::INVALID, ProtocolVersion::DTLS_1_3,
                              1, SequenceNumber48(100), Buffer(100));
    EXPECT_FALSE(invalid_type.is_valid());
    
    // Invalid protocol version
    DTLSPlaintext invalid_version(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_2,
                                 1, SequenceNumber48(100), Buffer(100));
    EXPECT_FALSE(invalid_version.is_valid());
    
    // Fragment too large
    DTLSPlaintext large_fragment(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_3,
                                1, SequenceNumber48(100), Buffer(20000));
    EXPECT_FALSE(large_fragment.is_valid());
}

// DTLSCiphertext Tests
TEST_F(DTLSRecordsTest, DTLSCiphertextConstruction) {
    DTLSCiphertext record(ContentType::APPLICATION_DATA, ProtocolVersion::DTLS_1_3,
                         1, SequenceNumber48(100), std::move(test_buffer));
    
    EXPECT_EQ(record.get_type(), ContentType::APPLICATION_DATA);
    EXPECT_EQ(record.get_version(), ProtocolVersion::DTLS_1_3);
    EXPECT_EQ(record.get_epoch(), 1);
    EXPECT_EQ(record.get_encrypted_sequence_number().value, 100);
    EXPECT_EQ(record.get_length(), test_data.size());
    EXPECT_FALSE(record.has_cid());
    EXPECT_TRUE(record.is_valid());
}

TEST_F(DTLSRecordsTest, DTLSCiphertextConnectionID) {
    DTLSCiphertext record(ContentType::APPLICATION_DATA, ProtocolVersion::DTLS_1_3,
                         1, SequenceNumber48(100), Buffer(100));
    
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
    DTLSCiphertext record(ContentType::APPLICATION_DATA, ProtocolVersion::DTLS_1_3,
                         0x9876, SequenceNumber48(0xFEDCBA987654), std::move(test_buffer));
    
    Buffer output_buffer;
    auto result = record.serialize(output_buffer);
    ASSERT_TRUE(result.is_success());
    
    size_t bytes_written = result.value();
    EXPECT_EQ(bytes_written, DTLSCiphertext::HEADER_SIZE + test_data.size());
    
    const uint8_t* data = output_buffer.data();
    
    // Check header fields (same format as DTLSPlaintext)
    EXPECT_EQ(data[0], static_cast<uint8_t>(ContentType::APPLICATION_DATA));
    EXPECT_EQ((data[1] << 8) | data[2], ProtocolVersion::DTLS_1_3);
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
    DTLSCiphertext original(ContentType::APPLICATION_DATA, ProtocolVersion::DTLS_1_3,
                           0xABCD, SequenceNumber48(0x111111111111), std::move(test_buffer));
    
    Buffer serialized;
    auto serialize_result = original.serialize(serialized);
    ASSERT_TRUE(serialize_result.is_success());
    
    auto deserialize_result = DTLSCiphertext::deserialize(serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    DTLSCiphertext deserialized = deserialize_result.value();
    
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
    DTLSPlaintext record(ContentType::HANDSHAKE, ProtocolVersion::DTLS_1_3,
                        0x1234, SequenceNumber48(0x567890ABCDEF), Buffer(100));
    
    Buffer serialized;
    auto result = record.serialize(serialized);
    ASSERT_TRUE(result.is_success());
    
    // Test utility functions
    auto type_result = dtls_records_utils::extract_content_type(serialized);
    ASSERT_TRUE(type_result.is_success());
    EXPECT_EQ(type_result.value(), ContentType::HANDSHAKE);
    
    auto version_result = dtls_records_utils::extract_protocol_version(serialized);
    ASSERT_TRUE(version_result.is_success());
    EXPECT_EQ(version_result.value(), ProtocolVersion::DTLS_1_3);
    
    auto epoch_result = dtls_records_utils::extract_epoch(serialized);
    ASSERT_TRUE(epoch_result.is_success());
    EXPECT_EQ(epoch_result.value(), 0x1234);
    
    auto seq_result = dtls_records_utils::extract_sequence_number(serialized);
    ASSERT_TRUE(seq_result.is_success());
    EXPECT_EQ(seq_result.value().value, 0x567890ABCDEF);
    
    EXPECT_TRUE(dtls_records_utils::is_dtls_record(serialized));
    EXPECT_TRUE(dtls_records_utils::validate_record_length(100, 100));
    EXPECT_FALSE(dtls_records_utils::validate_record_length(100, 200));
}

TEST_F(DTLSRecordsTest, SequenceNumberOverflowDetection) {
    // Test near overflow detection
    SequenceNumber48 near_overflow(0xE666666666666); // ~90% of max
    EXPECT_TRUE(dtls_records_utils::is_sequence_number_near_overflow(near_overflow));
    
    SequenceNumber48 not_near_overflow(0x1000000000000); // ~6% of max
    EXPECT_FALSE(dtls_records_utils::is_sequence_number_near_overflow(not_near_overflow));
    
    SequenceNumber48 at_max(0xFFFFFFFFFFFF);
    EXPECT_TRUE(dtls_records_utils::is_sequence_number_near_overflow(at_max));
}

TEST_F(DTLSRecordsTest, ErrorHandling) {
    // Test deserialization with insufficient buffer
    Buffer small_buffer(5);
    small_buffer.resize(5);
    
    auto result = DTLSPlaintext::deserialize(small_buffer);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::DECODE_ERROR);
    
    // Test sequence number serialization with null buffer
    SequenceNumber48 seq(100);
    auto seq_result = seq.serialize_to_buffer(nullptr);
    EXPECT_FALSE(seq_result.is_success());
    EXPECT_EQ(seq_result.error(), DTLSError::INTERNAL_ERROR);
}

TEST_F(DTLSRecordsTest, MaximumSizes) {
    // Test maximum fragment size
    Buffer max_fragment(DTLSPlaintext::MAX_FRAGMENT_LENGTH);
    max_fragment.resize(DTLSPlaintext::MAX_FRAGMENT_LENGTH);
    
    DTLSPlaintext max_record(ContentType::APPLICATION_DATA, ProtocolVersion::DTLS_1_3,
                            1, SequenceNumber48(100), std::move(max_fragment));
    EXPECT_TRUE(max_record.is_valid());
    
    // Test oversized fragment
    Buffer oversized_fragment(DTLSPlaintext::MAX_FRAGMENT_LENGTH + 1);
    oversized_fragment.resize(DTLSPlaintext::MAX_FRAGMENT_LENGTH + 1);
    
    DTLSPlaintext oversized_record(ContentType::APPLICATION_DATA, ProtocolVersion::DTLS_1_3,
                                  1, SequenceNumber48(100), std::move(oversized_fragment));
    EXPECT_FALSE(oversized_record.is_valid());
}

// Performance Tests
TEST_F(DTLSRecordsTest, SerializationPerformance) {
    const int iterations = 1000;
    Buffer test_payload(1000);
    test_payload.resize(1000);
    
    // Time DTLSPlaintext serialization
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        Buffer payload_copy(test_payload.size());
        payload_copy.resize(test_payload.size());
        std::memcpy(payload_copy.mutable_data(), test_payload.data(), test_payload.size());
        
        DTLSPlaintext record(ContentType::APPLICATION_DATA, ProtocolVersion::DTLS_1_3,
                            i, SequenceNumber48(i), std::move(payload_copy));
        
        Buffer output;
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