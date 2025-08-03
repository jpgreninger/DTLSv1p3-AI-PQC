#include "mock_transport.h"
#include <algorithm>
#include <random>
#include <iostream>
#include <thread>

namespace dtls {
namespace test {

MockTransport::MockTransport(const std::string& local_addr, uint16_t local_port)
    : local_address_(local_addr)
    , local_port_(local_port)
    , random_generator_(random_device_()) {
}

MockTransport::~MockTransport() {
    MockTransport::shutdown();
}

dtls::v13::Result<void> MockTransport::bind() {
    if (bound_.load()) {
        return dtls::v13::make_error<void>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport already bound");
    }
    
    bound_.store(true);
    return dtls::v13::make_result();
}

dtls::v13::Result<void> MockTransport::connect(const std::string& remote_addr, uint16_t remote_port) {
    if (!bound_.load()) {
        return dtls::v13::make_error<void>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport not bound");
    }
    
    if (connected_.load()) {
        return dtls::v13::make_error<void>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport already connected");
    }
    
    remote_address_ = remote_addr;
    remote_port_ = remote_port;
    connected_.store(true);
    
    return dtls::v13::make_result();
}

dtls::v13::Result<size_t> MockTransport::send(const std::vector<uint8_t>& data) {
    if (!connected_.load()) {
        return dtls::v13::make_error<size_t>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport not connected");
    }
    
    if (shutdown_.load()) {
        return dtls::v13::make_error<size_t>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport shutdown");
    }
    
    if (transmission_paused_.load()) {
        return dtls::v13::make_error<size_t>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transmission paused");
    }
    
    // Check for error injection
    if (inject_send_error_.load() || is_error_injected()) {
        stats_.errors_encountered.fetch_add(1);
        return dtls::v13::make_error<size_t>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Injected send error");
    }
    
    // Check MTU
    if (data.size() > mtu_.load()) {
        return dtls::v13::make_error<size_t>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Packet size exceeds MTU");
    }
    
    // Check for packet drop
    if (packets_to_drop_.load() > 0) {
        packets_to_drop_.fetch_sub(1);
        stats_.packets_lost.fetch_add(1);
        return dtls::v13::make_result<size_t>(data.size()); // Pretend we sent it
    }
    
    // Network simulation
    if (should_drop_packet()) {
        stats_.packets_lost.fetch_add(1);
        return dtls::v13::make_result<size_t>(data.size()); // Pretend we sent it
    }
    
    // Bandwidth limiting
    simulate_bandwidth_limit(data.size());
    
    // Message interception
    {
        std::lock_guard<std::mutex> lock(interceptor_mutex_);
        if (message_interceptor_ && !message_interceptor_(data, true)) {
            return dtls::v13::make_error<size_t>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Message intercepted");
        }
    }
    
    // Packet corruption
    std::vector<uint8_t> packet_data = data;
    if (packets_to_corrupt_.load() > 0) {
        packets_to_corrupt_.fetch_sub(1);
        packet_data = corrupt_packet(data);
        stats_.packets_corrupted.fetch_add(1);
    } else if (should_corrupt_packet()) {
        packet_data = corrupt_packet(data);
        stats_.packets_corrupted.fetch_add(1);
    }
    
    // Deliver packet to peer
    deliver_packet(packet_data);
    
    // Update statistics
    stats_.packets_sent.fetch_add(1);
    stats_.bytes_sent.fetch_add(data.size());
    
    log_packet(data, true);
    
    return dtls::v13::make_result<size_t>(data.size());
}

dtls::v13::Result<std::vector<uint8_t>> MockTransport::receive(std::chrono::milliseconds timeout) {
    if (!connected_.load()) {
        return dtls::v13::make_error<std::vector<uint8_t>>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport not connected");
    }
    
    if (shutdown_.load()) {
        return dtls::v13::make_error<std::vector<uint8_t>>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport shutdown");
    }
    
    // Check for error injection
    if (inject_receive_error_.load() || is_error_injected()) {
        stats_.errors_encountered.fetch_add(1);
        return dtls::v13::make_error<std::vector<uint8_t>>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Injected receive error");
    }
    
    // Process any pending packets first
    process_pending_packets();
    
    std::unique_lock<std::mutex> lock(receive_mutex_);
    
    // Wait for data or timeout
    if (receive_condition_.wait_for(lock, timeout, [this] { return !receive_queue_.empty() || shutdown_.load(); })) {
        if (shutdown_.load()) {
            return dtls::v13::make_error<std::vector<uint8_t>>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport shutdown");
        }
        
        if (!receive_queue_.empty()) {
            auto data = std::move(receive_queue_.front());
            receive_queue_.pop();
            
            // Update statistics
            stats_.packets_received.fetch_add(1);
            stats_.bytes_received.fetch_add(data.size());
            
            // Message interception
            {
                std::lock_guard<std::mutex> interceptor_lock(interceptor_mutex_);
                if (message_interceptor_) {
                    message_interceptor_(data, false);
                }
            }
            
            log_packet(data, false);
            
            return dtls::v13::make_result<std::vector<uint8_t>>(std::move(data));
        }
    }
    
    return dtls::v13::make_error<std::vector<uint8_t>>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Receive timeout");
}

dtls::v13::Result<void> MockTransport::shutdown() {
    shutdown_.store(true);
    connected_.store(false);
    bound_.store(false);
    
    // Disconnect from peer
    {
        std::lock_guard<std::mutex> lock(peer_mutex_);
        if (peer_transport_) {
            peer_transport_->peer_transport_ = nullptr;
            peer_transport_ = nullptr;
        }
    }
    
    // Wake up any waiting receive operations
    receive_condition_.notify_all();
    
    return dtls::v13::make_result();
}

bool MockTransport::is_bound() const {
    return bound_.load();
}

bool MockTransport::is_connected() const {
    return connected_.load();
}

std::string MockTransport::get_local_address() const {
    return local_address_;
}

uint16_t MockTransport::get_local_port() const {
    return local_port_;
}

// Mock-specific functionality
void MockTransport::set_network_conditions(const NetworkConditions& conditions) {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    conditions_ = conditions;
}

MockTransport::NetworkConditions MockTransport::get_network_conditions() const {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    return conditions_;
}

void MockTransport::set_peer_transport(MockTransport* peer) {
    std::lock_guard<std::mutex> lock(peer_mutex_);
    peer_transport_ = peer;
    if (peer && peer->peer_transport_ != this) {
        peer->set_peer_transport(this);
    }
}

void MockTransport::disconnect_peer() {
    std::lock_guard<std::mutex> lock(peer_mutex_);
    if (peer_transport_) {
        peer_transport_->peer_transport_ = nullptr;
        peer_transport_ = nullptr;
    }
}

MockTransport::TransportStatsSnapshot MockTransport::get_statistics() const {
    // Create a snapshot of the atomic values
    TransportStatsSnapshot snapshot;
    snapshot.packets_sent = stats_.packets_sent.load();
    snapshot.packets_received = stats_.packets_received.load();
    snapshot.packets_lost = stats_.packets_lost.load();
    snapshot.packets_corrupted = stats_.packets_corrupted.load();
    snapshot.bytes_sent = stats_.bytes_sent.load();
    snapshot.bytes_received = stats_.bytes_received.load();
    snapshot.errors_encountered = stats_.errors_encountered.load();
    return snapshot;
}

void MockTransport::reset_statistics() {
    stats_.packets_sent.store(0);
    stats_.packets_received.store(0);
    stats_.packets_lost.store(0);
    stats_.packets_corrupted.store(0);
    stats_.bytes_sent.store(0);
    stats_.bytes_received.store(0);
    stats_.errors_encountered.store(0);
}

void MockTransport::inject_send_error(bool enable) {
    inject_send_error_.store(enable);
}

void MockTransport::inject_receive_error(bool enable) {
    inject_receive_error_.store(enable);
}

void MockTransport::set_error_rate(double rate) {
    error_rate_.store(rate);
}

void MockTransport::set_message_interceptor(MessageInterceptor interceptor) {
    std::lock_guard<std::mutex> lock(interceptor_mutex_);
    message_interceptor_ = std::move(interceptor);
}

void MockTransport::clear_message_interceptor() {
    std::lock_guard<std::mutex> lock(interceptor_mutex_);
    message_interceptor_ = nullptr;
}

void MockTransport::drop_next_packets(size_t count) {
    packets_to_drop_.store(count);
}

void MockTransport::corrupt_next_packets(size_t count) {
    packets_to_corrupt_.store(count);
}

void MockTransport::delay_next_packets(std::chrono::milliseconds delay) {
    packet_delay_.store(delay);
}

void MockTransport::pause_transmission(bool pause) {
    transmission_paused_.store(pause);
}

void MockTransport::set_mtu(size_t mtu) {
    mtu_.store(mtu);
}

size_t MockTransport::get_mtu() const {
    return mtu_.load();
}

// Helper methods
bool MockTransport::should_drop_packet() const {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    if (conditions_.packet_loss_rate <= 0.0) {
        return false;
    }
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(random_generator_) < conditions_.packet_loss_rate;
}

bool MockTransport::should_corrupt_packet() const {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    if (conditions_.corruption_rate <= 0.0) {
        return false;
    }
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(random_generator_) < conditions_.corruption_rate;
}

void MockTransport::simulate_bandwidth_limit(size_t data_size) {
    std::lock_guard<std::mutex> lock(bandwidth_mutex_);
    std::lock_guard<std::mutex> conditions_lock(conditions_mutex_);
    
    if (conditions_.bandwidth_kbps == 0) {
        return; // No bandwidth limit
    }
    
    auto now = std::chrono::steady_clock::now();
    auto time_since_last_send = now - last_send_time_;
    
    // Calculate minimum time required for this packet size
    auto required_time = std::chrono::milliseconds(
        (data_size * 8 * 1000) / (conditions_.bandwidth_kbps * 1024)
    );
    
    if (time_since_last_send < required_time) {
        auto sleep_time = required_time - time_since_last_send;
        std::this_thread::sleep_for(sleep_time);
    }
    
    last_send_time_ = std::chrono::steady_clock::now();
}

std::vector<uint8_t> MockTransport::corrupt_packet(const std::vector<uint8_t>& data) const {
    auto corrupted = data;
    if (!corrupted.empty()) {
        // Flip a random bit
        std::uniform_int_distribution<size_t> byte_dist(0, corrupted.size() - 1);
        std::uniform_int_distribution<int> bit_dist(0, 7);
        
        size_t byte_idx = byte_dist(random_generator_);
        int bit_idx = bit_dist(random_generator_);
        
        corrupted[byte_idx] ^= (1 << bit_idx);
    }
    return corrupted;
}

void MockTransport::deliver_packet(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> peer_lock(peer_mutex_);
    if (!peer_transport_) {
        return; // No peer to deliver to
    }
    
    std::lock_guard<std::mutex> conditions_lock(conditions_mutex_);
    auto delivery_time = std::chrono::steady_clock::now() + conditions_.latency;
    
    // Add to pending packets if there's a delay
    if (conditions_.latency > std::chrono::milliseconds(0) || packet_delay_.load() > std::chrono::milliseconds(0)) {
        std::lock_guard<std::mutex> pending_lock(pending_mutex_);
        PendingPacket packet;
        packet.data = data;
        packet.delivery_time = delivery_time + packet_delay_.load();
        pending_packets_.push(std::move(packet));
    } else {
        // Deliver immediately
        std::lock_guard<std::mutex> receive_lock(peer_transport_->receive_mutex_);
        peer_transport_->receive_queue_.push(data);
        peer_transport_->receive_condition_.notify_one();
    }
}

void MockTransport::process_pending_packets() {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto now = std::chrono::steady_clock::now();
    
    while (!pending_packets_.empty() && pending_packets_.front().delivery_time <= now) {
        auto packet = std::move(pending_packets_.front());
        pending_packets_.pop();
        
        // Deliver the packet
        std::lock_guard<std::mutex> receive_lock(receive_mutex_);
        receive_queue_.push(std::move(packet.data));
        receive_condition_.notify_one();
    }
}

void MockTransport::log_packet(const std::vector<uint8_t>& data, bool outgoing) const {
    // Simple logging - could be enhanced based on needs
    #ifdef DTLS_DEBUG_TRANSPORT
    std::cout << (outgoing ? "SEND" : "RECV") << ": " << data.size() << " bytes" << std::endl;
    #endif
}

bool MockTransport::is_error_injected() const {
    double rate = error_rate_.load();
    if (rate <= 0.0) {
        return false;
    }
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(random_generator_) < rate;
}

// MockTransportFactory implementation
MockTransportFactory::TransportPair MockTransportFactory::create_connected_pair(
    const std::string& client_addr,
    uint16_t client_port,
    const std::string& server_addr,
    uint16_t server_port) {
    
    auto client = std::make_unique<MockTransport>(client_addr, client_port);
    auto server = std::make_unique<MockTransport>(server_addr, server_port);
    
    // Bind both transports
    client->bind();
    server->bind();
    
    // Connect them to each other
    client->connect(server_addr, server_port);
    server->connect(client_addr, client_port);
    
    // Set up peer relationship
    client->set_peer_transport(server.get());
    
    return {std::move(client), std::move(server)};
}

std::unique_ptr<MockTransport> MockTransportFactory::create_with_conditions(
    const std::string& addr,
    uint16_t port,
    const MockTransport::NetworkConditions& conditions) {
    
    auto transport = std::make_unique<MockTransport>(addr, port);
    transport->set_network_conditions(conditions);
    transport->bind();
    
    return transport;
}

std::unique_ptr<MockTransport> MockTransportFactory::create_unreliable(
    const std::string& addr,
    uint16_t port,
    double loss_rate,
    std::chrono::milliseconds latency) {
    
    MockTransport::NetworkConditions conditions;
    conditions.packet_loss_rate = loss_rate;
    conditions.latency = latency;
    
    return create_with_conditions(addr, port, conditions);
}

// Legacy interface compatibility methods
void MockTransport::set_packet_loss_rate(double rate) {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    conditions_.packet_loss_rate = rate;
}

void MockTransport::set_network_delay(std::chrono::microseconds delay) {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    conditions_.latency = std::chrono::duration_cast<std::chrono::milliseconds>(delay);
}

void MockTransport::set_bandwidth_limit(uint32_t bandwidth_kbps) {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    conditions_.bandwidth_kbps = bandwidth_kbps;
}

void MockTransport::reset() {
    // Reset all state
    reset_statistics();
    
    // Clear packet manipulation settings
    packets_to_drop_.store(0);
    packets_to_corrupt_.store(0);
    packet_delay_.store(std::chrono::milliseconds(0));
    
    // Clear error injection
    inject_send_error_.store(false);
    inject_receive_error_.store(false);
    error_rate_.store(0.0);
    
    // Clear pending packets
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        while (!pending_packets_.empty()) {
            pending_packets_.pop();
        }
    }
    
    // Clear receive queue
    {
        std::lock_guard<std::mutex> lock(receive_mutex_);
        while (!receive_queue_.empty()) {
            receive_queue_.pop();
        }
    }
    
    // Reset network conditions
    {
        std::lock_guard<std::mutex> lock(conditions_mutex_);
        conditions_ = NetworkConditions{}; // Reset to defaults
    }
    
    // Reset state flags
    transmission_paused_.store(false);
    mtu_.store(1500);
    
    // Clear message interceptor
    {
        std::lock_guard<std::mutex> lock(interceptor_mutex_);
        message_interceptor_ = nullptr;
    }
}

void MockTransport::process_pending_messages() {
    process_pending_packets();
}

// Mock endpoint creation (simplified interface)
std::unique_ptr<MockTransport::MockEndpoint> MockTransport::create_endpoint(const std::string& name) {
    auto endpoint = std::make_unique<MockEndpoint>();
    endpoint->name = name;
    endpoint->transport = this;
    return endpoint;
}

void MockTransport::connect_endpoints(std::unique_ptr<MockEndpoint>& client, std::unique_ptr<MockEndpoint>& server) {
    if (client && server && client->transport && server->transport) {
        client->transport->set_peer_transport(server->transport);
    }
}

} // namespace test
} // namespace dtls