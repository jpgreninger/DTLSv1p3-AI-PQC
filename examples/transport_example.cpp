/**
 * UDP Transport Layer Example
 * 
 * Demonstrates the usage of the DTLS v1.3 UDP transport layer
 * for basic packet sending and receiving.
 */

#include <dtls/transport/udp_transport.h>
#include <dtls/memory/pool.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <string>

using namespace dtls::v13;

void print_stats(const transport::TransportStats& stats) {
    std::cout << "\n=== Transport Statistics ===" << std::endl;
    std::cout << "Packets sent: " << stats.packets_sent << std::endl;
    std::cout << "Packets received: " << stats.packets_received << std::endl;
    std::cout << "Bytes sent: " << stats.bytes_sent << std::endl;
    std::cout << "Bytes received: " << stats.bytes_received << std::endl;
    std::cout << "Send errors: " << stats.send_errors << std::endl;
    std::cout << "Receive errors: " << stats.receive_errors << std::endl;
    std::cout << "Current connections: " << stats.current_connections << std::endl;
    std::cout << "Average send time: " << stats.average_send_time.count() << " μs" << std::endl;
    std::cout << "Average receive time: " << stats.average_receive_time.count() << " μs" << std::endl;
}

void transport_event_callback(transport::TransportEvent event,
                             const transport::NetworkEndpoint& endpoint,
                             const std::vector<uint8_t>& data) {
    switch (event) {
        case transport::TransportEvent::PACKET_RECEIVED:
            std::cout << "[EVENT] Packet received from " << endpoint.to_string()
                     << " (" << data.size() << " bytes)" << std::endl;
            break;
        case transport::TransportEvent::PACKET_SENT:
            std::cout << "[EVENT] Packet sent to " << endpoint.to_string() << std::endl;
            break;
        case transport::TransportEvent::SEND_ERROR:
            std::cout << "[ERROR] Send error to " << endpoint.to_string() << std::endl;
            break;
        case transport::TransportEvent::RECEIVE_ERROR:
            std::cout << "[ERROR] Receive error from " << endpoint.to_string() << std::endl;
            break;
        case transport::TransportEvent::SOCKET_ERROR:
            std::cout << "[ERROR] Socket error" << std::endl;
            break;
        default:
            std::cout << "[EVENT] Other transport event" << std::endl;
            break;
    }
}

void server_example() {
    std::cout << "\n=== Server Example ===" << std::endl;
    
    // Create transport configuration
    transport::TransportConfig config;
    config.receive_buffer_size = 8192;
    config.send_buffer_size = 8192;
    config.worker_threads = 1;
    
    // Create and initialize transport
    transport::UDPTransport server_transport(config);
    auto init_result = server_transport.initialize();
    if (!init_result) {
        std::cout << "Failed to initialize server transport" << std::endl;
        return;
    }
    
    // Set event callback
    server_transport.set_event_callback(transport_event_callback);
    
    // Bind to local endpoint
    transport::NetworkEndpoint server_endpoint("127.0.0.1", 12345);
    auto bind_result = server_transport.bind(server_endpoint);
    if (!bind_result) {
        std::cout << "Failed to bind server transport" << std::endl;
        return;
    }
    
    // Get actual bound endpoint
    auto local_endpoint_result = server_transport.get_local_endpoint();
    if (local_endpoint_result) {
        std::cout << "Server bound to: " << local_endpoint_result.value().to_string() << std::endl;
    }
    
    // Start transport
    auto start_result = server_transport.start();
    if (!start_result) {
        std::cout << "Failed to start server transport" << std::endl;
        return;
    }
    
    std::cout << "Server transport started, listening for packets..." << std::endl;
    
    // Receive loop
    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Try to receive packets
        auto packet_result = server_transport.receive_packet();
        if (packet_result) {
            const auto& packet = packet_result.value();
            std::cout << "Received packet from " << packet.source.to_string()
                     << ": " << std::string(reinterpret_cast<const char*>(packet.data.data()), 
                                           packet.data.size()) << std::endl;
            
            // Echo back
            std::string response = "Echo: " + std::string(
                reinterpret_cast<const char*>(packet.data.data()), packet.data.size());
            auto response_buffer = memory::make_buffer(response.data(), response.size());
            
            auto send_result = server_transport.send_packet(packet.source, response_buffer);
            if (send_result) {
                std::cout << "Echoed response to " << packet.source.to_string() << std::endl;
            }
        }
    }
    
    // Stop transport
    server_transport.stop();
    
    // Print final statistics
    print_stats(server_transport.get_stats());
}

void client_example() {
    std::cout << "\n=== Client Example ===" << std::endl;
    
    // Wait a bit for server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create transport configuration
    transport::TransportConfig config;
    config.receive_buffer_size = 8192;
    config.send_buffer_size = 8192;
    config.worker_threads = 1;
    
    // Create and initialize transport
    transport::UDPTransport client_transport(config);
    auto init_result = client_transport.initialize();
    if (!init_result) {
        std::cout << "Failed to initialize client transport" << std::endl;
        return;
    }
    
    // Set event callback
    client_transport.set_event_callback(transport_event_callback);
    
    // Bind to any available port
    transport::NetworkEndpoint client_endpoint("127.0.0.1", 0);
    auto bind_result = client_transport.bind(client_endpoint);
    if (!bind_result) {
        std::cout << "Failed to bind client transport" << std::endl;
        return;
    }
    
    // Get actual bound endpoint
    auto local_endpoint_result = client_transport.get_local_endpoint();
    if (local_endpoint_result) {
        std::cout << "Client bound to: " << local_endpoint_result.value().to_string() << std::endl;
    }
    
    // Start transport
    auto start_result = client_transport.start();
    if (!start_result) {
        std::cout << "Failed to start client transport" << std::endl;
        return;
    }
    
    // Server endpoint
    transport::NetworkEndpoint server_endpoint("127.0.0.1", 12345);
    
    // Send some test messages
    for (int i = 0; i < 3; ++i) {
        std::string message = "Hello from client #" + std::to_string(i);
        auto message_buffer = memory::make_buffer(message.data(), message.size());
        
        std::cout << "Sending: " << message << std::endl;
        auto send_result = client_transport.send_packet(server_endpoint, message_buffer);
        if (!send_result) {
            std::cout << "Failed to send message" << std::endl;
        }
        
        // Wait for response
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        auto packet_result = client_transport.receive_packet();
        if (packet_result) {
            const auto& packet = packet_result.value();
            std::cout << "Received response: " 
                     << std::string(reinterpret_cast<const char*>(packet.data.data()), 
                                   packet.data.size()) << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Stop transport
    client_transport.stop();
    
    // Print final statistics
    print_stats(client_transport.get_stats());
}

void hostname_resolution_example() {
    std::cout << "\n=== Hostname Resolution Example ===" << std::endl;
    
    // Resolve localhost
    auto endpoints_result = transport::UDPTransport::resolve_hostname("localhost", 80);
    if (endpoints_result) {
        std::cout << "Resolved localhost:" << std::endl;
        for (const auto& endpoint : endpoints_result.value()) {
            std::cout << "  " << endpoint.to_string() << std::endl;
        }
    } else {
        std::cout << "Failed to resolve localhost" << std::endl;
    }
    
    // Get local addresses
    auto local_addresses_result = transport::UDPTransport::get_local_addresses();
    if (local_addresses_result) {
        std::cout << "Local addresses:" << std::endl;
        for (const auto& endpoint : local_addresses_result.value()) {
            std::cout << "  " << endpoint.to_string() << std::endl;
        }
    }
}

int main() {
    std::cout << "DTLS v1.3 UDP Transport Layer Example" << std::endl;
    std::cout << "====================================" << std::endl;
    
    try {
        // Demonstrate hostname resolution
        hostname_resolution_example();
        
        // Run server and client examples concurrently
        std::thread server_thread(server_example);
        std::thread client_thread(client_example);
        
        // Wait for both to complete
        server_thread.join();
        client_thread.join();
        
        std::cout << "\nTransport layer example completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}