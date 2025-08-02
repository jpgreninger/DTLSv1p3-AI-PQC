/**
 * Simple DTLS v1.3 Client Example
 * 
 * Demonstrates basic DTLS client functionality:
 * - Connection establishment with handshake
 * - Secure data transmission
 * - Proper connection cleanup
 */

#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/transport/udp_transport.h>
#include <dtls/memory/buffer.h>
#include <dtls/result.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <iomanip>

using namespace dtls::v13;

class DTLSClient {
private:
    std::unique_ptr<Connection> connection_;
    std::unique_ptr<transport::UDPTransport> transport_;
    ConnectionConfig config_;
    bool connected_;

public:
    DTLSClient() : connected_(false) {
        setup_default_config();
    }
    
    ~DTLSClient() {
        disconnect();
    }
    
    void setup_default_config() {
        // Configure supported cipher suites (DTLS v1.3)
        config_.supported_cipher_suites = {
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        };
        
        // Configure supported groups for key exchange
        config_.supported_groups = {
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1
        };
        
        // Configure signature algorithms
        config_.supported_signatures = {
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::ED25519
        };
        
        // Set timeouts and retry parameters
        config_.handshake_timeout = std::chrono::seconds(30);
        config_.retransmission_timeout = std::chrono::milliseconds(1000);
        config_.max_retransmissions = 6;
        
        // Enable modern DTLS features
        config_.enable_connection_id = true;
        config_.connection_id_length = 8;
        config_.enable_early_data = false; // Disabled for simplicity
        config_.enable_session_resumption = true;
        
        // Buffer configuration
        config_.receive_buffer_size = 16384;
        config_.send_buffer_size = 16384;
    }
    
    bool connect(const std::string& server_address, uint16_t server_port) {
        std::cout << "=== DTLS Client Connection ===" << std::endl;
        std::cout << "Connecting to " << server_address << ":" << server_port << std::endl;
        
        try {
            // Create crypto provider
            auto crypto_provider_result = crypto::ProviderFactory::instance().create_default_provider();
            if (!crypto_provider_result) {
                std::cerr << "Failed to create crypto provider: " << crypto_provider_result.error() << std::endl;
                return false;
            }
            auto crypto_provider = std::move(crypto_provider_result.value());
            
            // Create and configure transport
            transport::TransportConfig transport_config;
            transport_config.receive_buffer_size = config_.receive_buffer_size;
            transport_config.send_buffer_size = config_.send_buffer_size;
            transport_config.worker_threads = 1;
            
            transport_ = std::make_unique<transport::UDPTransport>(transport_config);
            
            auto init_result = transport_->initialize();
            if (!init_result) {
                std::cerr << "Failed to initialize transport" << std::endl;
                return false;
            }
            
            // Bind to any available local port
            transport::NetworkEndpoint local_endpoint("0.0.0.0", 0);
            auto bind_result = transport_->bind(local_endpoint);
            if (!bind_result) {
                std::cerr << "Failed to bind transport" << std::endl;
                return false;
            }
            
            auto actual_endpoint = transport_->get_local_endpoint();
            if (actual_endpoint) {
                std::cout << "Client bound to: " << actual_endpoint.value().to_string() << std::endl;
            }
            
            // Start transport
            auto start_result = transport_->start();
            if (!start_result) {
                std::cerr << "Failed to start transport" << std::endl;
                return false;
            }
            
            // Create DTLS connection
            transport::NetworkEndpoint server_endpoint(server_address, server_port);
            auto connection_result = Connection::create_client(
                config_, 
                std::move(crypto_provider), 
                NetworkAddress::from_ipv4(0x7F000001, server_port),  // 127.0.0.1
                [this](ConnectionEvent event, const std::vector<uint8_t>& data) {
                    handle_connection_event(event, data);
                }
            );
            if (!connection_result) {
                std::cerr << "Failed to create DTLS connection: " << connection_result.error() << std::endl;
                return false;
            }
            connection_ = std::move(connection_result.value());
            
            // Initialize connection
            auto conn_init_result = connection_->initialize();
            if (!conn_init_result) {
                std::cerr << "Failed to initialize connection: " << conn_init_result.error() << std::endl;
                return false;
            }
            
            // Initiate DTLS handshake
            auto handshake_result = connection_->start_handshake();
            if (!handshake_result) {
                std::cerr << "Failed to start DTLS handshake: " << handshake_result.error() << std::endl;
                return false;
            }
            
            // Wait for handshake completion
            std::cout << "Performing DTLS handshake..." << std::endl;
            if (!wait_for_connection()) {
                std::cerr << "Handshake timeout or failed" << std::endl;
                return false;
            }
            
            connected_ = true;
            std::cout << "DTLS connection established successfully!" << std::endl;
            
            // Display connection information
            display_connection_info();
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "Connection error: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool send_message(const std::string& message) {
        if (!connected_ || !connection_) {
            std::cerr << "Not connected to server" << std::endl;
            return false;
        }
        
        std::cout << "Sending: \"" << message << "\"" << std::endl;
        
        // Convert message to buffer
        std::vector<uint8_t> data(message.begin(), message.end());
        memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(data.data()), data.size());
        
        // Send encrypted data
        auto send_result = connection_->send_application_data(buffer);
        if (!send_result) {
            std::cerr << "Failed to send message: " << send_result.error() << std::endl;
            return false;
        }
        
        std::cout << "Message sent successfully (" << data.size() << " bytes)" << std::endl;
        return true;
    }
    
    std::string receive_message(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
        if (!connected_ || !connection_) {
            return "";
        }
        
        auto start_time = std::chrono::steady_clock::now();
        
        while (std::chrono::steady_clock::now() - start_time < timeout) {
            auto receive_result = connection_->receive_application_data();
            if (receive_result) {
                const auto& buffer = receive_result.value();
                const auto* data = buffer.data();
                size_t size = buffer.size();
                std::string message(reinterpret_cast<const char*>(data), size);
                std::cout << "Received: \"" << message << "\" (" << size << " bytes)" << std::endl;
                return message;
            }
            
            // Brief sleep to avoid busy waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        return ""; // Timeout
    }
    
    void disconnect() {
        if (connected_ && connection_) {
            std::cout << "Closing DTLS connection..." << std::endl;
            connection_->close();
            connected_ = false;
        }
        
        if (transport_) {
            transport_->stop();
        }
        
        // Display final statistics
        if (connection_) {
            display_connection_stats();
        }
    }
    
    bool is_connected() const {
        return connected_ && connection_ && connection_->is_connected();
    }

private:
    void handle_connection_event(ConnectionEvent event, const std::vector<uint8_t>& data) {
        switch (event) {
            case ConnectionEvent::HANDSHAKE_STARTED:
                std::cout << "[EVENT] Handshake started" << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_COMPLETED:
                std::cout << "[EVENT] Handshake completed" << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_FAILED:
                std::cout << "[EVENT] Handshake failed" << std::endl;
                break;
            case ConnectionEvent::DATA_RECEIVED:
                // Data is handled separately in receive_message()
                break;
            case ConnectionEvent::CONNECTION_CLOSED:
                std::cout << "[EVENT] Connection closed" << std::endl;
                connected_ = false;
                break;
            case ConnectionEvent::ERROR_OCCURRED:
                std::cout << "[EVENT] Error occurred" << std::endl;
                break;
            case ConnectionEvent::ALERT_RECEIVED:
                std::cout << "[EVENT] Alert received" << std::endl;
                break;
            case ConnectionEvent::KEY_UPDATE_COMPLETED:
                std::cout << "[EVENT] Key update completed" << std::endl;
                break;
        }
    }
    
    bool wait_for_connection() {
        auto start_time = std::chrono::steady_clock::now();
        const auto timeout = config_.handshake_timeout;
        
        while (std::chrono::steady_clock::now() - start_time < timeout) {
            if (connection_->is_connected()) {
                return true;
            }
            
            // Check handshake completion status through connection state
            if (connection_->get_state() == ConnectionState::CLOSED) {
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        return false;
    }
    
    void display_connection_info() {
        if (!connection_) return;
        
        std::cout << "\n=== Connection Information ===" << std::endl;
        
        // Display connection state
        std::cout << "Connection State: ";
        switch (connection_->get_state()) {
            case ConnectionState::INITIAL: std::cout << "INITIAL"; break;
            case ConnectionState::WAIT_SERVER_HELLO: std::cout << "WAIT_SERVER_HELLO"; break;
            case ConnectionState::WAIT_ENCRYPTED_EXTENSIONS: std::cout << "WAIT_ENCRYPTED_EXTENSIONS"; break;
            case ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST: std::cout << "WAIT_CERTIFICATE_OR_CERT_REQUEST"; break;
            case ConnectionState::WAIT_CERTIFICATE_VERIFY: std::cout << "WAIT_CERTIFICATE_VERIFY"; break;
            case ConnectionState::WAIT_SERVER_FINISHED: std::cout << "WAIT_SERVER_FINISHED"; break;
            case ConnectionState::WAIT_CLIENT_CERTIFICATE: std::cout << "WAIT_CLIENT_CERTIFICATE"; break;
            case ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY: std::cout << "WAIT_CLIENT_CERTIFICATE_VERIFY"; break;
            case ConnectionState::WAIT_CLIENT_FINISHED: std::cout << "WAIT_CLIENT_FINISHED"; break;
            case ConnectionState::CONNECTED: std::cout << "CONNECTED"; break;
            case ConnectionState::CLOSED: std::cout << "CLOSED"; break;
            case ConnectionState::EARLY_DATA: std::cout << "EARLY_DATA"; break;
            case ConnectionState::WAIT_END_OF_EARLY_DATA: std::cout << "WAIT_END_OF_EARLY_DATA"; break;
            case ConnectionState::EARLY_DATA_REJECTED: std::cout << "EARLY_DATA_REJECTED"; break;
            default: std::cout << "UNKNOWN"; break;
        }
        std::cout << std::endl;
        
        // Display peer address  
        std::cout << "Peer Address: " << to_string(connection_->get_peer_address()) << std::endl;
        std::cout << "Client Mode: " << (connection_->is_client() ? "Yes" : "No") << std::endl;
        
        // Try to get connection IDs if available
        auto local_id_result = connection_->get_local_connection_id();
        if (local_id_result && !local_id_result.value().empty()) {
            std::cout << "Local Connection ID: ";
            for (uint8_t byte : local_id_result.value()) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << std::dec << std::endl;
        }
        
        auto peer_id_result = connection_->get_peer_connection_id();
        if (peer_id_result && !peer_id_result.value().empty()) {
            std::cout << "Peer Connection ID: ";
            for (uint8_t byte : peer_id_result.value()) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << std::dec << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    void display_connection_stats() {
        if (!connection_) return;
        
        auto stats = connection_->get_stats();
        
        std::cout << "\n=== Connection Statistics ===" << std::endl;
        std::cout << "Handshake Duration: " << stats.handshake_duration.count() << " ms" << std::endl;
        std::cout << "Handshake Retransmissions: " << stats.handshake_retransmissions << std::endl;
        std::cout << "Bytes Sent: " << stats.bytes_sent << std::endl;
        std::cout << "Bytes Received: " << stats.bytes_received << std::endl;
        std::cout << "Records Sent: " << stats.records_sent << std::endl;
        std::cout << "Records Received: " << stats.records_received << std::endl;
        std::cout << "Decrypt Errors: " << stats.decrypt_errors << std::endl;
        std::cout << "Sequence Errors: " << stats.sequence_errors << std::endl;
        std::cout << "Protocol Errors: " << stats.protocol_errors << std::endl;
        
        auto duration = std::chrono::steady_clock::now() - stats.connection_start;
        std::cout << "Connection Duration: " 
                 << std::chrono::duration_cast<std::chrono::seconds>(duration).count() 
                 << " seconds" << std::endl;
        std::cout << std::endl;
    }
};

// Interactive client demo function
void run_interactive_client() {
    std::cout << "DTLS v1.3 Interactive Client Demo" << std::endl;
    std::cout << "=================================" << std::endl;
    
    DTLSClient client;
    
    // Get server connection details
    std::string server_address;
    uint16_t server_port;
    
    std::cout << "Enter server address (default: 127.0.0.1): ";
    std::getline(std::cin, server_address);
    if (server_address.empty()) {
        server_address = "127.0.0.1";
    }
    
    std::cout << "Enter server port (default: 4433): ";
    std::string port_str;
    std::getline(std::cin, port_str);
    if (port_str.empty()) {
        server_port = 4433;
    } else {
        server_port = static_cast<uint16_t>(std::stoi(port_str));
    }
    
    // Connect to server
    if (!client.connect(server_address, server_port)) {
        std::cerr << "Failed to connect to server" << std::endl;
        return;
    }
    
    // Interactive message loop
    std::cout << "\nEnter messages to send (type 'quit' to exit):" << std::endl;
    std::string input;
    
    while (std::getline(std::cin, input)) {
        if (input == "quit" || input == "exit") {
            break;
        }
        
        if (input.empty()) {
            continue;
        }
        
        // Send message
        if (client.send_message(input)) {
            // Wait for response
            std::string response = client.receive_message(std::chrono::milliseconds(5000));
            if (response.empty()) {
                std::cout << "No response received (timeout)" << std::endl;
            }
        }
        
        if (!client.is_connected()) {
            std::cout << "Connection lost" << std::endl;
            break;
        }
    }
    
    // Cleanup handled by destructor
    std::cout << "Client demo completed." << std::endl;
}

// Simple automated client demo
void run_automated_client_demo() {
    std::cout << "DTLS v1.3 Automated Client Demo" << std::endl;
    std::cout << "================================" << std::endl;
    
    DTLSClient client;
    
    // Connect to local server
    if (!client.connect("127.0.0.1", 4433)) {
        std::cerr << "Failed to connect to server at 127.0.0.1:4433" << std::endl;
        std::cerr << "Make sure the DTLS server is running first." << std::endl;
        return;
    }
    
    // Send test messages
    std::vector<std::string> test_messages = {
        "Hello, DTLS Server!",
        "This is a test message.",
        "DTLS v1.3 is working great!",
        "Testing secure communication.",
        "Final test message."
    };
    
    for (const auto& message : test_messages) {
        if (client.send_message(message)) {
            // Wait for echo response
            std::string response = client.receive_message(std::chrono::milliseconds(2000));
            if (response.empty()) {
                std::cout << "No response received for: " << message << std::endl;
            }
        }
        
        // Brief pause between messages
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (!client.is_connected()) {
            std::cout << "Connection lost during demo" << std::endl;
            break;
        }
    }
    
    std::cout << "Automated demo completed." << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        if (argc > 1 && std::string(argv[1]) == "--interactive") {
            run_interactive_client();
        } else {
            run_automated_client_demo();
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}