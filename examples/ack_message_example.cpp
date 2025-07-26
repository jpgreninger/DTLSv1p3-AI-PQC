#include <iostream>
#include <vector>
#include <dtls/protocol/handshake.h>
#include <dtls/memory/buffer.h>

using namespace dtls::v13::protocol;
using namespace dtls::v13;

int main() {
    std::cout << "DTLS v1.3 ACK Message Implementation Test\n";
    std::cout << "==========================================\n\n";

    // Test 1: Create ACK message from individual sequences
    std::cout << "Test 1: Creating ACK message from sequences [1, 2, 3, 5, 7, 8, 9]\n";
    std::vector<uint32_t> sequences = {1, 2, 3, 5, 7, 8, 9};
    
    auto ack_result = create_ack_message(sequences);
    if (!ack_result.is_success()) {
        std::cout << "Failed to create ACK message\n";
        return 1;
    }
    
    ACK ack_message = std::move(ack_result.value());
    std::cout << "ACK message created with " << ack_message.range_count() << " ranges\n";
    
    // Display ranges
    for (const auto& range : ack_message.ack_ranges()) {
        std::cout << "  Range: " << range.start_sequence << " - " << range.end_sequence << "\n";
    }
    
    // Test 2: Serialize and deserialize ACK message
    std::cout << "\nTest 2: Serialization and deserialization\n";
    
    memory::Buffer serialize_buffer(ack_message.serialized_size());
    auto serialize_result = ack_message.serialize(serialize_buffer);
    if (!serialize_result.is_success()) {
        std::cout << "Failed to serialize ACK message\n";
        return 1;
    }
    
    std::cout << "Serialized ACK message size: " << serialize_result.value() << " bytes\n";
    
    // Deserialize
    auto deserialize_result = ACK::deserialize(serialize_buffer, 0);
    if (!deserialize_result.is_success()) {
        std::cout << "Failed to deserialize ACK message\n";
        return 1;
    }
    
    ACK deserialized_ack = std::move(deserialize_result.value());
    std::cout << "Deserialized ACK message with " << deserialized_ack.range_count() << " ranges\n";
    
    // Test 3: Create HandshakeMessage with ACK
    std::cout << "\nTest 3: Creating HandshakeMessage with ACK\n";
    
    HandshakeMessage handshake_msg(ack_message, 42); // sequence number 42
    
    if (!handshake_msg.is_valid()) {
        std::cout << "HandshakeMessage is not valid\n";
        return 1;
    }
    
    std::cout << "HandshakeMessage created successfully\n";
    std::cout << "Message type: " << static_cast<int>(handshake_msg.message_type()) << " (should be 26 for ACK)\n";
    std::cout << "Message sequence: " << handshake_msg.header().message_seq << "\n";
    
    // Test 4: Serialize complete handshake message
    std::cout << "\nTest 4: Complete handshake message serialization\n";
    
    memory::Buffer handshake_buffer(handshake_msg.serialized_size());
    auto handshake_serialize_result = handshake_msg.serialize(handshake_buffer);
    if (!handshake_serialize_result.is_success()) {
        std::cout << "Failed to serialize handshake message\n";
        return 1;
    }
    
    std::cout << "Handshake message serialized: " << handshake_serialize_result.value() << " bytes\n";
    
    // Test 5: Utility functions
    std::cout << "\nTest 5: Utility functions\n";
    
    // Test sequence checking
    std::cout << "Sequence 2 acknowledged: " << (ack_message.is_sequence_acknowledged(2) ? "Yes" : "No") << "\n";
    std::cout << "Sequence 4 acknowledged: " << (ack_message.is_sequence_acknowledged(4) ? "Yes" : "No") << "\n";
    std::cout << "Sequence 6 acknowledged: " << (ack_message.is_sequence_acknowledged(6) ? "Yes" : "No") << "\n";
    
    // Test missing sequences
    auto missing_sequences = get_missing_sequences(ack_message, 10);
    std::cout << "Missing sequences (0-10): ";
    for (uint32_t seq : missing_sequences) {
        std::cout << seq << " ";
    }
    std::cout << "\n";
    
    // Test range operations
    ACKRange test_range(5, 10);
    std::cout << "Range [5-10] contains sequence 7: " << (test_range.contains(7) ? "Yes" : "No") << "\n";
    std::cout << "Range [5-10] contains sequence 15: " << (test_range.contains(15) ? "Yes" : "No") << "\n";
    
    std::cout << "\nAll tests completed successfully!\n";
    return 0;
}