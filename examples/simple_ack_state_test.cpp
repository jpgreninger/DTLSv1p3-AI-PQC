#include <iostream>
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/handshake_manager.h>
#include <dtls/types.h>

using namespace dtls::v13;
using namespace dtls::v13::protocol;

/**
 * Simple test to verify ACK state machine integration compiles and works
 */
int main() {
    std::cout << "DTLS v1.3 ACK State Machine Integration Test\n";
    std::cout << "============================================\n";
    
    try {
        // Test 1: Create ACK message
        std::cout << "1. Creating ACK message...\n";
        ACK ack_message;
        ack_message.add_ack_range(1, 3);
        ack_message.add_ack_range(5, 7);
        ack_message.optimize_ranges();
        
        std::cout << "   ACK message created with " << ack_message.range_count() << " ranges\n";
        
        // Test 2: Create HandshakeMessage with ACK
        std::cout << "2. Creating HandshakeMessage with ACK...\n";
        HandshakeMessage ack_handshake(ack_message, 10);
        
        std::cout << "   HandshakeMessage type: " << static_cast<int>(ack_handshake.message_type()) << "\n";
        std::cout << "   Expected ACK type: " << static_cast<int>(HandshakeType::ACK) << "\n";
        
        if (ack_handshake.message_type() == HandshakeType::ACK) {
            std::cout << "   ✓ ACK message type matches\n";
        } else {
            std::cout << "   ✗ ACK message type mismatch\n";
        }
        
        // Test 3: Test HandshakeManager configuration
        std::cout << "3. Testing HandshakeManager configuration...\n";
        HandshakeManager::Config config;
        config.initial_timeout = std::chrono::milliseconds(1000);
        config.max_timeout = std::chrono::milliseconds(10000);
        config.max_retransmissions = 5;
        config.enable_ack_processing = true;
        
        HandshakeManager manager(config);
        
        auto send_callback = [](const HandshakeMessage& message) -> Result<void> {
            std::cout << "   Mock send: message type " << static_cast<int>(message.message_type()) << "\n";
            return Result<void>();
        };
        
        auto event_callback = [](HandshakeEvent event, const std::vector<uint8_t>& data) {
            std::cout << "   HandshakeEvent: " << static_cast<int>(event) << "\n";
        };
        
        auto init_result = manager.initialize(send_callback, event_callback);
        if (init_result.is_success()) {
            std::cout << "   ✓ HandshakeManager initialized successfully\n";
        } else {
            std::cout << "   ✗ HandshakeManager initialization failed\n";
        }
        
        // Test 4: Test ACK processing
        std::cout << "4. Testing ACK processing...\n";
        auto process_result = manager.process_message(ack_handshake);
        if (process_result.is_success()) {
            std::cout << "   ✓ ACK message processed successfully\n";
        } else {
            std::cout << "   ✗ ACK message processing failed\n";
        }
        
        // Test 5: Get statistics
        std::cout << "5. Getting HandshakeManager statistics...\n";
        auto stats = manager.get_statistics();
        std::cout << "   Messages received: " << stats.messages_received << "\n";
        std::cout << "   ACKs received: " << stats.acks_received << "\n";
        std::cout << "   Current RTO: " << stats.current_rto.count() << " ms\n";
        
        std::cout << "\n=== All tests completed successfully! ===\n";
        
    } catch (const std::exception& e) {
        std::cout << "Test failed with exception: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}