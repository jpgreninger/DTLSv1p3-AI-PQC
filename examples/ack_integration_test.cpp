#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>

#include <dtls/protocol/handshake.h>
#include <dtls/protocol/handshake_manager.h>
#include <dtls/memory/buffer.h>

using namespace dtls::v13::protocol;
using namespace dtls::v13;

/**
 * Mock transport layer for testing
 */
class MockTransport {
public:
    struct Message {
        HandshakeMessage message;
        std::chrono::steady_clock::time_point timestamp;
        
        Message(HandshakeMessage msg) 
            : message(std::move(msg)), timestamp(std::chrono::steady_clock::now()) {}
    };
    
    void send_message(const HandshakeMessage& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        outbound_queue_.emplace(message);
        cv_.notify_one();
    }
    
    bool receive_message(HandshakeMessage& message, std::chrono::milliseconds timeout = std::chrono::milliseconds(100)) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (cv_.wait_for(lock, timeout, [this] { return !outbound_queue_.empty(); })) {
            message = std::move(outbound_queue_.front().message);
            outbound_queue_.pop();
            return true;
        }
        
        return false;
    }
    
    size_t pending_messages() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return outbound_queue_.size();
    }
    
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::queue<Message> empty;
        outbound_queue_.swap(empty);
    }

private:
    std::queue<Message> outbound_queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

/**
 * Test peer that uses HandshakeManager
 */
class TestPeer {
public:
    TestPeer(const std::string& name, std::shared_ptr<MockTransport> transport)
        : name_(name), transport_(transport) {
        
        // Initialize handshake manager
        HandshakeManager::Config config;
        config.initial_timeout = std::chrono::milliseconds(500);
        config.max_retransmissions = 3;
        config.enable_ack_processing = true;
        
        handshake_manager_ = std::make_unique<HandshakeManager>(config);
        
        // Setup callbacks
        auto send_callback = [this](const HandshakeMessage& message) -> Result<void> {
            std::cout << "[" << name_ << "] Sending message type " 
                      << static_cast<int>(message.message_type()) 
                      << " seq=" << message.header().message_seq << "\n";
            
            transport_->send_message(message);
            return Result<void>();
        };
        
        auto event_callback = [this](HandshakeEvent event, const std::vector<uint8_t>& data) {
            std::string event_name;
            switch (event) {
                case HandshakeEvent::MESSAGE_RECEIVED: event_name = "MESSAGE_RECEIVED"; break;
                case HandshakeEvent::MESSAGE_SENT: event_name = "MESSAGE_SENT"; break;
                case HandshakeEvent::ACK_RECEIVED: event_name = "ACK_RECEIVED"; break;
                case HandshakeEvent::ACK_SENT: event_name = "ACK_SENT"; break;
                case HandshakeEvent::RETRANSMISSION_NEEDED: event_name = "RETRANSMISSION_NEEDED"; break;
                case HandshakeEvent::TIMEOUT_OCCURRED: event_name = "TIMEOUT_OCCURRED"; break;
                case HandshakeEvent::HANDSHAKE_COMPLETE: event_name = "HANDSHAKE_COMPLETE"; break;
                case HandshakeEvent::HANDSHAKE_FAILED: event_name = "HANDSHAKE_FAILED"; break;
            }
            
            std::cout << "[" << name_ << "] Event: " << event_name << "\n";
        };
        
        auto init_result = handshake_manager_->initialize(send_callback, event_callback);
        if (!init_result.is_success()) {
            throw std::runtime_error("Failed to initialize handshake manager");
        }
    }
    
    void send_handshake_message(HandshakeType type) {
        HandshakeMessage message;
        
        switch (type) {
            case HandshakeType::CLIENT_HELLO: {
                ClientHello client_hello;
                client_hello.set_legacy_version(DTLS_V13);
                
                // Set a random value
                std::array<uint8_t, 32> random;
                for (size_t i = 0; i < 32; ++i) {
                    random[i] = static_cast<uint8_t>(i + sequence_counter_);
                }
                client_hello.set_random(random);
                
                message = HandshakeMessage(client_hello, sequence_counter_++);
                break;
            }
            case HandshakeType::SERVER_HELLO: {
                ServerHello server_hello;
                server_hello.set_legacy_version(DTLS_V13);
                server_hello.set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
                
                // Set a random value
                std::array<uint8_t, 32> random;
                for (size_t i = 0; i < 32; ++i) {
                    random[i] = static_cast<uint8_t>(i + sequence_counter_ + 100);
                }
                server_hello.set_random(random);
                
                message = HandshakeMessage(server_hello, sequence_counter_++);
                break;
            }
            case HandshakeType::FINISHED: {
                Finished finished;
                memory::Buffer verify_data(12);
                for (size_t i = 0; i < 12; ++i) {
                    *(verify_data.mutable_data() + i) = static_cast<std::byte>(i);
                }
                finished.set_verify_data(std::move(verify_data));
                
                message = HandshakeMessage(finished, sequence_counter_++);
                break;
            }
            default:
                throw std::runtime_error("Unsupported message type for test");
        }
        
        auto send_result = handshake_manager_->send_message(message);
        if (!send_result.is_success()) {
            std::cout << "[" << name_ << "] Failed to send message\n";
        }
    }
    
    void process_incoming_messages() {
        HandshakeMessage message;
        while (transport_->receive_message(message, std::chrono::milliseconds(50))) {
            std::cout << "[" << name_ << "] Received message type " 
                      << static_cast<int>(message.message_type()) 
                      << " seq=" << message.header().message_seq << "\n";
            
            auto process_result = handshake_manager_->process_message(message);
            if (!process_result.is_success()) {
                std::cout << "[" << name_ << "] Failed to process message\n";
            }
        }
    }
    
    void process_timeouts() {
        auto timeout_result = handshake_manager_->process_timeouts();
        if (!timeout_result.is_success()) {
            std::cout << "[" << name_ << "] Failed to process timeouts\n";
        }
    }
    
    void print_statistics() {
        auto stats = handshake_manager_->get_statistics();
        std::cout << "[" << name_ << "] Statistics:\n";
        std::cout << "  Messages sent: " << stats.messages_sent << "\n";
        std::cout << "  Messages received: " << stats.messages_received << "\n";
        std::cout << "  ACKs sent: " << stats.acks_sent << "\n";
        std::cout << "  ACKs received: " << stats.acks_received << "\n";
        std::cout << "  Retransmissions: " << stats.retransmissions << "\n";
        std::cout << "  Messages in flight: " << stats.messages_in_flight << "\n";
        std::cout << "  Current RTO: " << stats.current_rto.count() << " ms\n";
    }
    
    const std::string& name() const { return name_; }

private:
    std::string name_;
    std::shared_ptr<MockTransport> transport_;
    std::unique_ptr<HandshakeManager> handshake_manager_;
    uint32_t sequence_counter_{0};
};

void run_basic_ack_test() {
    std::cout << "\n=== Basic ACK Test ===\n";
    
    auto transport = std::make_shared<MockTransport>();
    TestPeer client("Client", transport);
    TestPeer server("Server", transport);
    
    // Client sends ClientHello
    client.send_handshake_message(HandshakeType::CLIENT_HELLO);
    
    // Server processes message and sends ACK + ServerHello
    server.process_incoming_messages();
    server.send_handshake_message(HandshakeType::SERVER_HELLO);
    
    // Client processes messages
    client.process_incoming_messages();
    
    // Small delay to see ACK processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::cout << "\nFinal statistics:\n";
    client.print_statistics();
    server.print_statistics();
}

void run_retransmission_test() {
    std::cout << "\n=== Retransmission Test ===\n";
    
    auto transport = std::make_shared<MockTransport>();
    TestPeer client("Client", transport);
    TestPeer server("Server", transport);
    
    // Client sends message
    client.send_handshake_message(HandshakeType::CLIENT_HELLO);
    
    // Server receives but doesn't send ACK (simulate ACK loss)
    server.process_incoming_messages();
    transport->clear(); // Clear any ACKs
    
    std::cout << "Simulating ACK loss - waiting for retransmission...\n";
    
    // Wait for timeout and retransmission
    for (int i = 0; i < 10; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        client.process_timeouts();
        
        if (transport->pending_messages() > 0) {
            std::cout << "Retransmission detected!\n";
            break;
        }
    }
    
    // Server processes retransmitted message
    server.process_incoming_messages();
    
    // Now let ACKs through
    client.process_incoming_messages();
    
    std::cout << "\nFinal statistics:\n";
    client.print_statistics();
    server.print_statistics();
}

void run_out_of_order_test() {
    std::cout << "\n=== Out-of-Order Message Test ===\n";
    
    auto transport = std::make_shared<MockTransport>();
    TestPeer client("Client", transport);
    TestPeer server("Server", transport);
    
    // Send multiple messages
    client.send_handshake_message(HandshakeType::CLIENT_HELLO);
    server.send_handshake_message(HandshakeType::SERVER_HELLO);
    server.send_handshake_message(HandshakeType::FINISHED);
    
    // Process messages in different order
    HandshakeMessage msg1, msg2, msg3;
    transport->receive_message(msg1); // ClientHello
    transport->receive_message(msg2); // ServerHello  
    transport->receive_message(msg3); // Finished
    
    // Server receives ClientHello
    server.handshake_manager_->process_message(msg1);
    
    // Client receives Finished first (out of order)
    std::cout << "Processing Finished message out of order...\n";
    client.handshake_manager_->process_message(msg3);
    
    // Then ServerHello
    std::cout << "Processing ServerHello message...\n";
    client.handshake_manager_->process_message(msg2);
    
    // Process ACKs
    client.process_incoming_messages();
    server.process_incoming_messages();
    
    std::cout << "\nFinal statistics:\n";
    client.print_statistics();
    server.print_statistics();
}

int main() {
    std::cout << "DTLS v1.3 ACK Integration Test\n";
    std::cout << "===============================\n";
    
    try {
        // Test 1: Basic ACK functionality
        run_basic_ack_test();
        
        // Test 2: Retransmission handling
        run_retransmission_test();
        
        // Test 3: Out-of-order message handling
        run_out_of_order_test();
        
        std::cout << "\n=== All tests completed successfully! ===\n";
        
    } catch (const std::exception& e) {
        std::cout << "Test failed with exception: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}