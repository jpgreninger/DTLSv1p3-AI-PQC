#ifndef DTLS_MOCK_TRANSPORT_H
#define DTLS_MOCK_TRANSPORT_H

#include <dtls/transport/udp_transport.h>
#include <dtls/result.h>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <chrono>

namespace dtls {
namespace test {

/**
 * Mock Transport for Testing
 * 
 * Provides controllable transport layer for DTLS testing with:
 * - Packet loss simulation
 * - Network delay simulation
 * - Bandwidth limiting
 * - Error injection
 * - Message interception and logging
 */
class MockTransport : public transport::TransportInterface {
public:
    /**
     * Network condition simulation parameters
     */
    struct NetworkConditions {
        double packet_loss_rate = 0.0;        // 0.0 to 1.0
        std::chrono::milliseconds latency{0}; // Network latency
        uint32_t bandwidth_kbps = 0;          // 0 = unlimited
        double corruption_rate = 0.0;         // Packet corruption rate
        bool enable_reordering = false;       // Packet reordering
    };
    
    /**
     * Transport statistics
     */
    struct TransportStats {
        std::atomic<uint64_t> packets_sent{0};
        std::atomic<uint64_t> packets_received{0};
        std::atomic<uint64_t> packets_lost{0};
        std::atomic<uint64_t> packets_corrupted{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
    };
    
    MockTransport(const std::string& local_addr, uint16_t local_port);
    virtual ~MockTransport();
    
    // TransportInterface implementation
    Result<void> bind() override;
    Result<void> connect(const std::string& remote_addr, uint16_t remote_port) override;
    Result<size_t> send(const std::vector<uint8_t>& data) override;
    Result<std::vector<uint8_t>> receive(std::chrono::milliseconds timeout) override;
    Result<void> shutdown() override;
    
    bool is_bound() const override;
    bool is_connected() const override;
    std::string get_local_address() const override;
    uint16_t get_local_port() const override;
    
    // Mock-specific functionality
    void set_network_conditions(const NetworkConditions& conditions);
    NetworkConditions get_network_conditions() const;
    
    void set_peer_transport(MockTransport* peer);
    void disconnect_peer();
    
    TransportStats get_statistics() const;
    void reset_statistics();
    
    // Error injection
    void inject_send_error(bool enable);
    void inject_receive_error(bool enable);
    void set_error_rate(double rate);
    
    // Message interception
    using MessageInterceptor = std::function<bool(const std::vector<uint8_t>&, bool)>; // data, is_outgoing
    void set_message_interceptor(MessageInterceptor interceptor);
    void clear_message_interceptor();
    
    // Packet manipulation
    void drop_next_packets(size_t count);
    void corrupt_next_packets(size_t count);
    void delay_next_packets(std::chrono::milliseconds delay);
    
    // State control
    void pause_transmission(bool pause);
    void set_mtu(size_t mtu);
    size_t get_mtu() const;
    
private:
    struct PendingPacket {
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point delivery_time;
        bool corrupted = false;
    };
    
    // Network simulation
    bool should_drop_packet() const;
    bool should_corrupt_packet() const;
    void simulate_bandwidth_limit(size_t data_size);
    std::vector<uint8_t> corrupt_packet(const std::vector<uint8_t>& data) const;
    
    // Packet delivery
    void deliver_packet(const std::vector<uint8_t>& data);
    void process_pending_packets();
    
    // Configuration
    std::string local_address_;
    uint16_t local_port_;
    std::string remote_address_;
    uint16_t remote_port_;
    
    // State
    std::atomic<bool> bound_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<bool> transmission_paused_{false};
    
    // Network conditions
    mutable std::mutex conditions_mutex_;
    NetworkConditions conditions_;
    
    // Peer connection
    MockTransport* peer_transport_ = nullptr;
    mutable std::mutex peer_mutex_;
    
    // Receive queue
    std::queue<std::vector<uint8_t>> receive_queue_;
    mutable std::mutex receive_mutex_;
    std::condition_variable receive_condition_;
    
    // Pending packets for delay simulation
    std::queue<PendingPacket> pending_packets_;
    mutable std::mutex pending_mutex_;
    
    // Statistics
    mutable TransportStats stats_;
    
    // Error injection
    std::atomic<bool> inject_send_error_{false};
    std::atomic<bool> inject_receive_error_{false};
    std::atomic<double> error_rate_{0.0};
    
    // Message interception
    MessageInterceptor message_interceptor_;
    mutable std::mutex interceptor_mutex_;
    
    // Packet manipulation
    std::atomic<size_t> packets_to_drop_{0};
    std::atomic<size_t> packets_to_corrupt_{0};
    std::atomic<std::chrono::milliseconds> packet_delay_{0};
    
    // Configuration
    std::atomic<size_t> mtu_{1500};
    
    // Bandwidth limiting
    std::chrono::steady_clock::time_point last_send_time_;
    mutable std::mutex bandwidth_mutex_;
    
    // Random number generation for network simulation
    mutable std::random_device random_device_;
    mutable std::mt19937 random_generator_;
    
    // Helper methods
    void log_packet(const std::vector<uint8_t>& data, bool outgoing) const;
    bool is_error_injected() const;
};

/**
 * Mock Transport Factory
 * 
 * Creates connected mock transport pairs for testing
 */
class MockTransportFactory {
public:
    struct TransportPair {
        std::unique_ptr<MockTransport> client;
        std::unique_ptr<MockTransport> server;
    };
    
    /**
     * Create connected transport pair
     */
    static TransportPair create_connected_pair(
        const std::string& client_addr = "127.0.0.1",
        uint16_t client_port = 0,
        const std::string& server_addr = "127.0.0.1", 
        uint16_t server_port = 4433);
    
    /**
     * Create transport with specific network conditions
     */
    static std::unique_ptr<MockTransport> create_with_conditions(
        const std::string& addr,
        uint16_t port,
        const MockTransport::NetworkConditions& conditions);
    
    /**
     * Create unreliable transport for stress testing  
     */
    static std::unique_ptr<MockTransport> create_unreliable(
        const std::string& addr,
        uint16_t port,
        double loss_rate = 0.1,
        std::chrono::milliseconds latency = std::chrono::milliseconds(50));
};

} // namespace test
} // namespace dtls

#endif // DTLS_MOCK_TRANSPORT_H