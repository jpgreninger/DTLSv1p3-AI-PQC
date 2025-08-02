/**
 * DTLS v1.3 Multi-Connection Server Example
 * 
 * Demonstrates advanced server capabilities for handling multiple concurrent connections:
 * - High-performance multi-threaded server architecture
 * - Connection pooling and resource management
 * - Load balancing across worker threads
 * - Performance monitoring and statistics
 * - Graceful connection lifecycle management
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
#include <memory>
#include <map>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <algorithm>
#include <csignal>
#include <iomanip>

using namespace dtls::v13;

class MultiConnectionServer {
private:
    // Server configuration
    ConnectionConfig server_config_;
    std::unique_ptr<transport::UDPTransport> transport_;
    std::unique_ptr<ConnectionManager> connection_manager_;
    
    // Multi-threading components
    std::vector<std::thread> worker_threads_;
    std::atomic<bool> server_running_{false};
    std::thread main_server_thread_;
    std::thread statistics_thread_;
    
    // Connection management
    std::map<std::string, std::unique_ptr<Connection>> active_connections_;
    std::mutex connections_mutex_;
    std::atomic<size_t> connection_counter_{0};
    
    // Load balancing
    std::vector<std::queue<std::string>> worker_queues_;
    std::vector<std::unique_ptr<std::mutex>> worker_queue_mutexes_;
    std::vector<std::unique_ptr<std::condition_variable>> worker_conditions_;
    size_t num_workers_;
    std::atomic<size_t> round_robin_counter_{0};
    
    // Statistics and monitoring
    std::atomic<uint64_t> total_connections_{0};
    std::atomic<uint64_t> active_connection_count_{0};
    std::atomic<uint64_t> total_messages_processed_{0};
    std::atomic<uint64_t> total_bytes_processed_{0};
    std::atomic<uint64_t> handshakes_completed_{0};
    std::atomic<uint64_t> handshakes_failed_{0};
    std::atomic<uint64_t> connection_errors_{0};
    
    // Per-worker statistics
    std::vector<std::unique_ptr<std::atomic<uint64_t>>> worker_message_counts_;
    std::vector<std::unique_ptr<std::atomic<uint64_t>>> worker_byte_counts_;
    
    // Performance monitoring
    std::chrono::steady_clock::time_point server_start_time_;
    std::atomic<double> messages_per_second_{0.0};
    std::atomic<double> bytes_per_second_{0.0};

public:
    MultiConnectionServer(size_t num_workers = 4) : num_workers_(num_workers) {
        setup_server_configuration();
        initialize_worker_infrastructure();
    }
    
    ~MultiConnectionServer() {
        stop_server();
    }
    
    void setup_server_configuration() {
        // Optimize configuration for high-performance multi-connection scenarios
        server_config_.supported_cipher_suites = {
            CipherSuite::TLS_AES_128_GCM_SHA256,  // Faster for high throughput
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        };
        
        server_config_.supported_groups = {
            NamedGroup::X25519,      // Fast elliptic curve
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1
        };
        
        server_config_.supported_signatures = {
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::ED25519
        };
        
        // Optimize for performance and scale
        server_config_.handshake_timeout = std::chrono::seconds(15);
        server_config_.retransmission_timeout = std::chrono::milliseconds(500);
        server_config_.max_retransmissions = 4;
        
        // Enable modern features for better scalability
        server_config_.enable_connection_id = true;
        server_config_.connection_id_length = 8;
        server_config_.enable_early_data = true;
        server_config_.max_early_data_size = 8192;
        server_config_.enable_session_resumption = true;
        
        // Optimize buffer sizes for multi-connection
        server_config_.receive_buffer_size = 32768;
        server_config_.send_buffer_size = 32768;
    }
    
    void initialize_worker_infrastructure() {
        // Initialize per-worker data structures
        worker_queues_.resize(num_workers_);
        worker_queue_mutexes_.reserve(num_workers_);
        worker_conditions_.reserve(num_workers_);
        worker_message_counts_.reserve(num_workers_);
        
        // Initialize unique_ptr containers
        for (size_t i = 0; i < num_workers_; ++i) {
            worker_queue_mutexes_.emplace_back(std::make_unique<std::mutex>());
            worker_conditions_.emplace_back(std::make_unique<std::condition_variable>());
            worker_message_counts_.emplace_back(std::make_unique<std::atomic<uint64_t>>(0));
            worker_byte_counts_.emplace_back(std::make_unique<std::atomic<uint64_t>>(0));
        }
        
        std::cout << "Initialized infrastructure for " << num_workers_ << " worker threads" << std::endl;
    }
    
    bool start_server(const std::string& bind_address = "0.0.0.0", uint16_t bind_port = 4433) {
        std::cout << "=== Multi-Connection DTLS Server Startup ===" << std::endl;
        std::cout << "Starting server on " << bind_address << ":" << bind_port << std::endl;
        std::cout << "Worker threads: " << num_workers_ << std::endl;
        
        try {
            // Initialize crypto system
            if (!crypto::is_crypto_system_initialized()) {
                auto crypto_result = crypto::initialize_crypto_system();
                if (!crypto_result) {
                    std::cerr << "Failed to initialize crypto system" << std::endl;
                    return false;
                }
            }
            
            // Create and configure transport for high-performance
            transport::TransportConfig transport_config;
            transport_config.receive_buffer_size = server_config_.receive_buffer_size;
            transport_config.send_buffer_size = server_config_.send_buffer_size;
            transport_config.worker_threads = static_cast<int>(num_workers_);
            transport_config.max_connections = 1000; // Support up to 1000 concurrent connections
            transport_config.reuse_address = true;
            transport_config.reuse_port = true;
            transport_config.receive_buffer_size = 1048576; // 1MB socket buffer
            transport_config.send_buffer_size = 1048576;
            
            transport_ = std::make_unique<transport::UDPTransport>(transport_config);
            
            auto init_result = transport_->initialize();
            if (!init_result) {
                std::cerr << "Failed to initialize transport" << std::endl;
                return false;
            }
            
            // Bind to specified address and port
            transport::NetworkEndpoint bind_endpoint(bind_address, bind_port);
            auto bind_result = transport_->bind(bind_endpoint);
            if (!bind_result) {
                std::cerr << "Failed to bind to " << bind_address << ":" << bind_port << std::endl;
                return false;
            }
            
            auto actual_endpoint = transport_->get_local_endpoint();
            if (actual_endpoint) {
                std::cout << "Server bound to: " << actual_endpoint.value().to_string() << std::endl;
            }
            
            // Start transport
            auto start_result = transport_->start();
            if (!start_result) {
                std::cerr << "Failed to start transport" << std::endl;
                return false;
            }
            
            // Create connection manager
            connection_manager_ = std::make_unique<ConnectionManager>();
            if (!connection_manager_) {
                std::cerr << "Failed to create connection manager" << std::endl;
                return false;
            }
            
            // Set up connection event callbacks
            // Note: New connection handling will be done differently with current API
            
            // Start worker threads
            server_running_ = true;
            server_start_time_ = std::chrono::steady_clock::now();
            
            for (size_t i = 0; i < num_workers_; ++i) {
                worker_threads_.emplace_back(&MultiConnectionServer::worker_thread_main, this, i);
            }
            
            // Start main server thread
            main_server_thread_ = std::thread(&MultiConnectionServer::main_server_loop, this);
            
            // Start statistics thread
            statistics_thread_ = std::thread(&MultiConnectionServer::statistics_loop, this);
            
            std::cout << "Multi-connection DTLS server started successfully!" << std::endl;
            std::cout << "Waiting for client connections..." << std::endl;
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "Server startup error: " << e.what() << std::endl;
            return false;
        }
    }
    
    void stop_server() {
        if (!server_running_) return;
        
        std::cout << "\n=== Multi-Connection Server Shutdown ===" << std::endl;
        
        server_running_ = false;
        
        // Notify all worker threads
        for (size_t i = 0; i < num_workers_; ++i) {
            worker_conditions_[i]->notify_all();
        }
        
        // Wait for all worker threads to finish
        for (auto& worker : worker_threads_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        
        // Wait for main server thread
        if (main_server_thread_.joinable()) {
            main_server_thread_.join();
        }
        
        // Wait for statistics thread
        if (statistics_thread_.joinable()) {
            statistics_thread_.join();
        }
        
        // Close all active connections
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            for (auto& [endpoint, connection] : active_connections_) {
                connection->close();
            }
            active_connections_.clear();
        }
        
        // Stop transport
        if (transport_) {
            transport_->stop();
        }
        
        // Display final statistics
        display_final_statistics();
        
        std::cout << "Multi-connection server stopped." << std::endl;
    }
    
    void run_server() {
        std::cout << "\nServer running. Press Ctrl+C to stop..." << std::endl;
        
        // Simple signal handling for demo purposes
        while (server_running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

private:
    void main_server_loop() {
        std::cout << "[MAIN] Server main loop started" << std::endl;
        
        while (server_running_) {
            try {
                // Process incoming connections and events
                // Process events by checking connection states
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                
                // Brief sleep to avoid busy waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                
            } catch (const std::exception& e) {
                std::cerr << "[MAIN] Processing error: " << e.what() << std::endl;
            }
        }
        
        std::cout << "[MAIN] Server main loop stopped" << std::endl;
    }
    
    void worker_thread_main(size_t worker_id) {
        std::cout << "[WORKER-" << worker_id << "] Worker thread started" << std::endl;
        
        while (server_running_) {
            std::unique_lock<std::mutex> lock(*worker_queue_mutexes_[worker_id]);
            
            // Wait for work or shutdown signal
            worker_conditions_[worker_id]->wait(lock, [this, worker_id]() {
                return !worker_queues_[worker_id].empty() || !server_running_;
            });
            
            // Process all queued connections
            while (!worker_queues_[worker_id].empty() && server_running_) {
                std::string endpoint_key = worker_queues_[worker_id].front();
                worker_queues_[worker_id].pop();
                lock.unlock();
                
                // Process this connection
                process_connection_messages(worker_id, endpoint_key);
                
                lock.lock();
            }
        }
        
        std::cout << "[WORKER-" << worker_id << "] Worker thread stopped" << std::endl;
    }
    
    void statistics_loop() {
        std::cout << "[STATS] Statistics thread started" << std::endl;
        
        auto last_update = std::chrono::steady_clock::now();
        uint64_t last_message_count = 0;
        uint64_t last_byte_count = 0;
        
        while (server_running_) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            auto now = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_update).count();
            
            if (duration > 0) {
                uint64_t current_messages = total_messages_processed_.load();
                uint64_t current_bytes = total_bytes_processed_.load();
                
                double msgs_per_sec = static_cast<double>(current_messages - last_message_count) / duration;
                double bytes_per_sec = static_cast<double>(current_bytes - last_byte_count) / duration;
                
                messages_per_second_ = msgs_per_sec;
                bytes_per_second_ = bytes_per_sec;
                
                last_message_count = current_messages;
                last_byte_count = current_bytes;
                last_update = now;
                
                // Display periodic statistics
                display_periodic_statistics();
            }
        }
        
        std::cout << "[STATS] Statistics thread stopped" << std::endl;
    }
    
    void handle_new_connection(std::unique_ptr<Connection> connection) {
        if (!connection) return;
        
        // Get client endpoint information
        auto remote_address = connection->get_peer_address();
        std::string endpoint_key = to_string(remote_address);
        
        std::cout << "[MAIN] New client connection from: " << endpoint_key << std::endl;
        
        // Set up connection event callback
        connection->set_event_callback([this, endpoint_key](ConnectionEvent event, const std::vector<uint8_t>& data) {
            handle_connection_event(endpoint_key, event, data);
        });
        
        // Store connection
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            active_connections_[endpoint_key] = std::move(connection);
        }
        
        // Update statistics
        total_connections_++;
        active_connection_count_++;
        
        // Assign to worker using round-robin load balancing
        size_t worker_id = round_robin_counter_++ % num_workers_;
        
        {
            std::lock_guard<std::mutex> lock(*worker_queue_mutexes_[worker_id]);
            worker_queues_[worker_id].push(endpoint_key);
        }
        worker_conditions_[worker_id]->notify_one();
        
        std::cout << "[MAIN] Connection " << endpoint_key << " assigned to worker " << worker_id << std::endl;
    }
    
    void handle_connection_event(const std::string& endpoint, ConnectionEvent event, const std::vector<uint8_t>& data) {
        switch (event) {
            case ConnectionEvent::HANDSHAKE_STARTED:
                std::cout << "[" << endpoint << "] Handshake started" << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_COMPLETED:
                std::cout << "[" << endpoint << "] Handshake completed" << std::endl;
                handshakes_completed_++;
                break;
            case ConnectionEvent::HANDSHAKE_FAILED:
                std::cout << "[" << endpoint << "] Handshake failed" << std::endl;
                handshakes_failed_++;
                break;
            case ConnectionEvent::DATA_RECEIVED:
                // Data will be processed by worker threads
                break;
            case ConnectionEvent::CONNECTION_CLOSED:
                std::cout << "[" << endpoint << "] Connection closed" << std::endl;
                cleanup_connection(endpoint);
                break;
            case ConnectionEvent::ERROR_OCCURRED:
                std::cout << "[" << endpoint << "] Error occurred" << std::endl;
                connection_errors_++;
                break;
            case ConnectionEvent::ALERT_RECEIVED:
                std::cout << "[" << endpoint << "] Alert received" << std::endl;
                break;
            case ConnectionEvent::KEY_UPDATE_COMPLETED:
                std::cout << "[" << endpoint << "] Key update completed" << std::endl;
                break;
            case ConnectionEvent::EARLY_DATA_ACCEPTED:
                std::cout << "[" << endpoint << "] Early data accepted" << std::endl;
                break;
            case ConnectionEvent::EARLY_DATA_REJECTED:
                std::cout << "[" << endpoint << "] Early data rejected" << std::endl;
                break;
            case ConnectionEvent::EARLY_DATA_RECEIVED:
                std::cout << "[" << endpoint << "] Early data received" << std::endl;
                break;
            case ConnectionEvent::NEW_SESSION_TICKET_RECEIVED:
                std::cout << "[" << endpoint << "] New session ticket received" << std::endl;
                break;
        }
    }
    
    void process_connection_messages(size_t worker_id, const std::string& endpoint_key) {
        std::unique_ptr<Connection> connection;
        
        // Get connection from active connections
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = active_connections_.find(endpoint_key);
            if (it == active_connections_.end()) {
                return; // Connection no longer exists
            }
            connection = std::move(it->second);
        }
        
        if (!connection || !connection->is_connected()) {
            // Re-add connection if it still exists
            if (connection) {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                active_connections_[endpoint_key] = std::move(connection);
            }
            return;
        }
        
        // Process any available messages
        while (server_running_) {
            auto receive_result = connection->receive_application_data();
            if (!receive_result) {
                break; // No more messages
            }
            
            const auto& data = receive_result.value();
            if (data.empty()) {
                break;
            }
            
            // Process the message
            std::string message(reinterpret_cast<const char*>(data.data()), data.size());
            
            // Generate response based on message content
            std::string response;
            if (message.find("ping") != std::string::npos) {
                response = "pong";
            } else if (message.find("time") != std::string::npos) {
                auto now = std::chrono::system_clock::now();
                auto time_t = std::chrono::system_clock::to_time_t(now);
                response = "Server time: " + std::string(std::ctime(&time_t));
                response.pop_back(); // Remove newline
            } else if (message.find("stats") != std::string::npos) {
                response = "Active connections: " + std::to_string(active_connection_count_.load()) +
                          ", Messages/sec: " + std::to_string(messages_per_second_.load());
            } else {
                response = "Echo from worker-" + std::to_string(worker_id) + ": " + message;
            }
            
            // Send response
            std::vector<uint8_t> response_data(response.begin(), response.end());
            memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(response_data.data()), response_data.size());
            auto send_result = connection->send_application_data(buffer);
            if (!send_result) {
                std::cerr << "[WORKER-" << worker_id << "] Failed to send response to " 
                         << endpoint_key << ": " << send_result.error() << std::endl;
            }
            
            // Update worker statistics
            (*worker_message_counts_[worker_id])++;
            (*worker_byte_counts_[worker_id]) += data.size();
            total_messages_processed_++;
            total_bytes_processed_ += data.size();
        }
        
        // Return connection to active connections
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            active_connections_[endpoint_key] = std::move(connection);
        }
    }
    
    void cleanup_connection(const std::string& endpoint) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = active_connections_.find(endpoint);
        if (it != active_connections_.end()) {
            active_connections_.erase(it);
            active_connection_count_--;
        }
    }
    
    void display_periodic_statistics() {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - server_start_time_);
        
        std::cout << "\n=== Server Statistics Update ===" << std::endl;
        std::cout << "Uptime: " << uptime.count() << " seconds" << std::endl;
        std::cout << "Active Connections: " << active_connection_count_.load() << std::endl;
        std::cout << "Total Connections: " << total_connections_.load() << std::endl;
        std::cout << "Messages/sec: " << std::fixed << std::setprecision(2) << messages_per_second_.load() << std::endl;
        std::cout << "Bytes/sec: " << std::fixed << std::setprecision(2) << bytes_per_second_.load() << std::endl;
        std::cout << "Total Messages: " << total_messages_processed_.load() << std::endl;
        std::cout << "Total Bytes: " << total_bytes_processed_.load() << std::endl;
        std::cout << "Handshakes Completed: " << handshakes_completed_.load() << std::endl;
        std::cout << "Handshakes Failed: " << handshakes_failed_.load() << std::endl;
        
        // Per-worker statistics
        std::cout << "\nPer-Worker Statistics:" << std::endl;
        for (size_t i = 0; i < num_workers_; ++i) {
            std::cout << "  Worker " << i << ": " 
                     << worker_message_counts_[i]->load() << " messages, "
                     << worker_byte_counts_[i]->load() << " bytes" << std::endl;
        }
        
        if (transport_) {
            auto transport_stats = transport_->get_stats();
            std::cout << "\nTransport Statistics:" << std::endl;
            std::cout << "  Packets Sent: " << transport_stats.packets_sent << std::endl;
            std::cout << "  Packets Received: " << transport_stats.packets_received << std::endl;
            std::cout << "  Send Errors: " << transport_stats.send_errors << std::endl;
            std::cout << "  Receive Errors: " << transport_stats.receive_errors << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    void display_final_statistics() {
        auto now = std::chrono::steady_clock::now();
        auto total_uptime = std::chrono::duration_cast<std::chrono::seconds>(now - server_start_time_);
        
        std::cout << "\n=== Final Server Statistics ===" << std::endl;
        std::cout << "Total Uptime: " << total_uptime.count() << " seconds" << std::endl;
        std::cout << "Total Connections Handled: " << total_connections_.load() << std::endl;
        std::cout << "Total Messages Processed: " << total_messages_processed_.load() << std::endl;
        std::cout << "Total Bytes Processed: " << total_bytes_processed_.load() << std::endl;
        std::cout << "Successful Handshakes: " << handshakes_completed_.load() << std::endl;
        std::cout << "Failed Handshakes: " << handshakes_failed_.load() << std::endl;
        std::cout << "Connection Errors: " << connection_errors_.load() << std::endl;
        
        if (total_uptime.count() > 0) {
            double avg_msgs_per_sec = static_cast<double>(total_messages_processed_.load()) / total_uptime.count();
            double avg_bytes_per_sec = static_cast<double>(total_bytes_processed_.load()) / total_uptime.count();
            
            std::cout << "Average Messages/sec: " << std::fixed << std::setprecision(2) << avg_msgs_per_sec << std::endl;
            std::cout << "Average Bytes/sec: " << std::fixed << std::setprecision(2) << avg_bytes_per_sec << std::endl;
        }
        
        // Final per-worker statistics
        std::cout << "\nFinal Per-Worker Statistics:" << std::endl;
        for (size_t i = 0; i < num_workers_; ++i) {
            std::cout << "  Worker " << i << ": " 
                     << worker_message_counts_[i]->load() << " messages, "
                     << worker_byte_counts_[i]->load() << " bytes" << std::endl;
        }
        
        if (transport_) {
            auto transport_stats = transport_->get_stats();
            std::cout << "\nFinal Transport Statistics:" << std::endl;
            std::cout << "Packets Sent: " << transport_stats.packets_sent << std::endl;
            std::cout << "Packets Received: " << transport_stats.packets_received << std::endl;
            std::cout << "Bytes Sent: " << transport_stats.bytes_sent << std::endl;
            std::cout << "Bytes Received: " << transport_stats.bytes_received << std::endl;
            std::cout << "Send Errors: " << transport_stats.send_errors << std::endl;
            std::cout << "Receive Errors: " << transport_stats.receive_errors << std::endl;
            std::cout << "Socket Errors: " << transport_stats.socket_errors << std::endl;
        }
        
        std::cout << std::endl;
    }
};

// Signal handling for graceful shutdown
std::atomic<bool> shutdown_requested{false};
MultiConnectionServer* global_server_instance = nullptr;

void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    shutdown_requested = true;
    if (global_server_instance) {
        global_server_instance->stop_server();
    }
}

int main(int argc, char* argv[]) {
    try {
        // Parse command line arguments
        std::string bind_address = "0.0.0.0";
        uint16_t bind_port = 4433;
        size_t num_workers = 4;
        
        if (argc >= 2) {
            bind_address = argv[1];
        }
        if (argc >= 3) {
            bind_port = static_cast<uint16_t>(std::stoi(argv[2]));
        }
        if (argc >= 4) {
            num_workers = static_cast<size_t>(std::stoi(argv[3]));
        }
        
        std::cout << "DTLS v1.3 Multi-Connection Server Example" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        // Install signal handlers for graceful shutdown
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        // Create and start server
        MultiConnectionServer server(num_workers);
        global_server_instance = &server;
        
        if (!server.start_server(bind_address, bind_port)) {
            std::cerr << "Failed to start multi-connection DTLS server" << std::endl;
            return 1;
        }
        
        // Run server until shutdown is requested
        while (!shutdown_requested) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cout << "Server shutdown completed." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}