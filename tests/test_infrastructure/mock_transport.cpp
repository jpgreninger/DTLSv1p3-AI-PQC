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
    shutdown();
}

Result<void> MockTransport::bind() {
    if (bound_.load()) {
        return Result<void>::error("Transport already bound");
    }
    
    // Simulate binding process
    bound_ = true;
    return Result<void>::ok();
}

Result<void> MockTransport::connect(const std::string& remote_addr, uint16_t remote_port) {
    if (!bound_.load()) {
        return Result<void>::error("Transport not bound");
    }
    
    if (connected_.load()) {
        return Result<void>::error("Transport already connected");
    }
    
    remote_address_ = remote_addr;
    remote_port_ = remote_port;
    connected_ = true;
    
    return Result<void>::ok();
}

Result<size_t> MockTransport::send(const std::vector<uint8_t>& data) {
    if (!bound_.load()) {
        return Result<size_t>::error("Transport not bound");
    }
    
    if (shutdown_.load()) {
        return Result<size_t>::error("Transport shutdown");
    }
    
    if (transmission_paused_.load()) {
        return Result<size_t>::error("Transmission paused");
    }
    
    // Check for error injection
    if (inject_send_error_.load() || is_error_injected()) {
        stats_.errors_encountered++;
        return Result<size_t>::error("Injected send error");
    }
    
    // Check if packet should be dropped
    if (should_drop_packet() || packets_to_drop_.load() > 0) {
        if (packets_to_drop_.load() > 0) {
            packets_to_drop_--;
        }
        stats_.packets_lost++;
        return Result<size_t>::ok(data.size()); // Return success but don't deliver
    }
    
    // Apply bandwidth limiting
    simulate_bandwidth_limit(data.size());
    
    // Process the packet (corruption, delay, etc.)
    std::vector<uint8_t> processed_data = data;
    
    if (should_corrupt_packet() || packets_to_corrupt_.load() > 0) {
        if (packets_to_corrupt_.load() > 0) {
            packets_to_corrupt_--;
        }
        processed_data = corrupt_packet(data);
        stats_.packets_corrupted++;
    }
    
    // Log packet if interceptor is set
    log_packet(data, true);
    
    // Check for message interception
    {
        std::lock_guard<std::mutex> lock(interceptor_mutex_);
        if (message_interceptor_ && !message_interceptor_(data, true)) {
            return Result<size_t>::error("Packet blocked by interceptor");
        }
    }
    
    // Apply delay if configured
    std::chrono::milliseconds delay = packet_delay_.load();
    if (delay.count() > 0) {
        packet_delay_ = std::chrono::milliseconds(0); // Reset single-use delay
    } else {
        std::lock_guard<std::mutex> lock(conditions_mutex_);
        delay = conditions_.latency;
    }
    
    if (delay.count() > 0) {
        // Schedule delayed delivery
        PendingPacket pending;
        pending.data = processed_data;
        pending.delivery_time = std::chrono::steady_clock::now() + delay;
        pending.corrupted = processed_data != data;
        
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            pending_packets_.push(pending);
        }
        
        // Process pending packets in a separate thread
        std::thread([this]() { process_pending_packets(); }).detach();
    } else {
        // Immediate delivery
        deliver_packet(processed_data);
    }
    
    stats_.packets_sent++;
    stats_.bytes_sent += data.size();
    
    return Result<size_t>::ok(data.size());
}

Result<std::vector<uint8_t>> MockTransport::receive(std::chrono::milliseconds timeout) {
    if (!bound_.load()) {
        return Result<std::vector<uint8_t>>::error("Transport not bound");
    }
    
    if (shutdown_.load()) {
        return Result<std::vector<uint8_t>>::error("Transport shutdown");
    }
    
    // Check for error injection
    if (inject_receive_error_.load() || is_error_injected()) {
        return Result<std::vector<uint8_t>>::error("Injected receive error");
    }
    
    std::unique_lock<std::mutex> lock(receive_mutex_);
    
    // Wait for data with timeout
    bool data_available = receive_condition_.wait_for(lock, timeout, [this]() {
        return !receive_queue_.empty() || shutdown_.load();
    });
    
    if (shutdown_.load()) {
        return Result<std::vector<uint8_t>>::error("Transport shutdown during receive");
    }
    
    if (!data_available || receive_queue_.empty()) {
        return Result<std::vector<uint8_t>>::error("Receive timeout");
    }
    
    std::vector<uint8_t> data = receive_queue_.front();
    receive_queue_.pop();
    
    stats_.packets_received++;
    stats_.bytes_received += data.size();
    
    // Log packet if interceptor is set
    log_packet(data, false);
    
    // Check for message interception
    {
        std::lock_guard<std::mutex> interceptor_lock(interceptor_mutex_);
        if (message_interceptor_ && !message_interceptor_(data, false)) {
            return Result<std::vector<uint8_t>>::error("Packet blocked by interceptor");
        }
    }
    
    return Result<std::vector<uint8_t>>::ok(data);
}

Result<void> MockTransport::shutdown() {
    if (shutdown_.load()) {
        return Result<void>::ok();
    }
    
    shutdown_ = true;
    connected_ = false;
    bound_ = false;
    
    // Wake up any waiting receivers
    receive_condition_.notify_all();
    
    // Disconnect peer
    disconnect_peer();
    
    return Result<void>::ok();
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
}

void MockTransport::disconnect_peer() {
    std::lock_guard<std::mutex> lock(peer_mutex_);
    peer_transport_ = nullptr;
}

MockTransport::TransportStats MockTransport::get_statistics() const {
    return stats_;
}

void MockTransport::reset_statistics() {
    stats_.packets_sent = 0;
    stats_.packets_received = 0;
    stats_.packets_lost = 0;
    stats_.packets_corrupted = 0;
    stats_.bytes_sent = 0;
    stats_.bytes_received = 0;
}

void MockTransport::inject_send_error(bool enable) {
    inject_send_error_ = enable;
}

void MockTransport::inject_receive_error(bool enable) {
    inject_receive_error_ = enable;
}

void MockTransport::set_error_rate(double rate) {
    error_rate_ = std::clamp(rate, 0.0, 1.0);
}

void MockTransport::set_message_interceptor(MessageInterceptor interceptor) {
    std::lock_guard<std::mutex> lock(interceptor_mutex_);
    message_interceptor_ = interceptor;
}

void MockTransport::clear_message_interceptor() {
    std::lock_guard<std::mutex> lock(interceptor_mutex_);
    message_interceptor_ = nullptr;
}

void MockTransport::drop_next_packets(size_t count) {
    packets_to_drop_ = count;
}

void MockTransport::corrupt_next_packets(size_t count) {
    packets_to_corrupt_ = count;
}

void MockTransport::delay_next_packets(std::chrono::milliseconds delay) {
    packet_delay_ = delay;
}

void MockTransport::pause_transmission(bool pause) {
    transmission_paused_ = pause;
}

void MockTransport::set_mtu(size_t mtu) {
    mtu_ = mtu;
}

size_t MockTransport::get_mtu() const {
    return mtu_.load();
}

bool MockTransport::should_drop_packet() const {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    if (conditions_.packet_loss_rate <= 0.0) {
        return false;
    }
    
    std::uniform_real_distribution<double> dis(0.0, 1.0);
    return dis(random_generator_) < conditions_.packet_loss_rate;
}

bool MockTransport::should_corrupt_packet() const {
    std::lock_guard<std::mutex> lock(conditions_mutex_);
    if (conditions_.corruption_rate <= 0.0) {
        return false;
    }
    
    std::uniform_real_distribution<double> dis(0.0, 1.0);
    return dis(random_generator_) < conditions_.corruption_rate;
}

void MockTransport::simulate_bandwidth_limit(size_t data_size) {
    std::lock_guard<std::mutex> lock(bandwidth_mutex_);
    
    NetworkConditions conditions;
    {
        std::lock_guard<std::mutex> cond_lock(conditions_mutex_);
        conditions = conditions_;
    }
    
    if (conditions.bandwidth_kbps == 0) {
        return; // No bandwidth limit
    }
    
    auto current_time = std::chrono::steady_clock::now();
    
    // Calculate required delay based on bandwidth
    double bytes_per_ms = (conditions.bandwidth_kbps * 1024.0) / (8.0 * 1000.0);
    auto required_delay = std::chrono::milliseconds(
        static_cast<long>(data_size / bytes_per_ms));
    
    auto elapsed = current_time - last_send_time_;
    if (elapsed < required_delay) {
        std::this_thread::sleep_for(required_delay - elapsed);
    }
    
    last_send_time_ = std::chrono::steady_clock::now();
}

std::vector<uint8_t> MockTransport::corrupt_packet(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> corrupted = data;
    
    if (corrupted.empty()) {
        return corrupted;
    }
    
    // Corrupt a few random bytes
    std::uniform_int_distribution<size_t> pos_dis(0, corrupted.size() - 1);
    std::uniform_int_distribution<uint8_t> byte_dis(0, 255);
    
    size_t num_corruptions = std::max(1UL, corrupted.size() / 100); // 1% of bytes
    
    for (size_t i = 0; i < num_corruptions; ++i) {
        size_t pos = pos_dis(random_generator_);
        corrupted[pos] = byte_dis(random_generator_);
    }
    
    return corrupted;
}

void MockTransport::deliver_packet(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> peer_lock(peer_mutex_);
    
    if (!peer_transport_) {
        return; // No peer to deliver to
    }
    
    // Deliver to peer's receive queue
    std::lock_guard<std::mutex> receive_lock(peer_transport_->receive_mutex_);
    peer_transport_->receive_queue_.push(data);
    peer_transport_->receive_condition_.notify_one();
}

void MockTransport::process_pending_packets() {
    while (true) {
        PendingPacket pending;
        bool has_packet = false;
        
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            if (!pending_packets_.empty()) {
                auto now = std::chrono::steady_clock::now();
                if (now >= pending_packets_.front().delivery_time) {
                    pending = pending_packets_.front();
                    pending_packets_.pop();
                    has_packet = true;
                }
            }
        }
        
        if (!has_packet) {
            break; // No more packets ready for delivery
        }
        
        deliver_packet(pending.data);
    }
}

void MockTransport::log_packet(const std::vector<uint8_t>& data, bool outgoing) const {
    // Optional logging for debugging
    // Uncomment for verbose packet logging
    /*
    std::cout << (outgoing ? "SEND" : "RECV") << " [" << local_address_ << ":" << local_port_ << "] "
              << data.size() << " bytes" << std::endl;
    */
}

bool MockTransport::is_error_injected() const {
    double rate = error_rate_.load();
    if (rate <= 0.0) {
        return false;
    }
    
    std::uniform_real_distribution<double> dis(0.0, 1.0);
    return dis(random_generator_) < rate;
}

// MockTransportFactory Implementation
MockTransportFactory::TransportPair MockTransportFactory::create_connected_pair(
    const std::string& client_addr, uint16_t client_port,
    const std::string& server_addr, uint16_t server_port) {
    
    TransportPair pair;
    
    pair.client = std::make_unique<MockTransport>(client_addr, client_port);
    pair.server = std::make_unique<MockTransport>(server_addr, server_port);
    
    // Bind both transports
    auto client_bind = pair.client->bind();
    auto server_bind = pair.server->bind();
    
    if (!client_bind.is_ok() || !server_bind.is_ok()) {
        throw std::runtime_error("Failed to bind transport pair");
    }
    
    // Connect them as peers
    pair.client->set_peer_transport(pair.server.get());
    pair.server->set_peer_transport(pair.client.get());
    
    return pair;
}

std::unique_ptr<MockTransport> MockTransportFactory::create_with_conditions(
    const std::string& addr, uint16_t port,
    const MockTransport::NetworkConditions& conditions) {
    
    auto transport = std::make_unique<MockTransport>(addr, port);
    transport->set_network_conditions(conditions);
    
    auto bind_result = transport->bind();
    if (!bind_result.is_ok()) {
        throw std::runtime_error("Failed to bind transport with conditions");
    }
    
    return transport;
}

std::unique_ptr<MockTransport> MockTransportFactory::create_unreliable(
    const std::string& addr, uint16_t port,
    double loss_rate, std::chrono::milliseconds latency) {
    
    MockTransport::NetworkConditions conditions;
    conditions.packet_loss_rate = loss_rate;
    conditions.latency = latency;
    conditions.corruption_rate = 0.01; // 1% corruption
    conditions.enable_reordering = true;
    
    return create_with_conditions(addr, port, conditions);
}

} // namespace test
} // namespace dtls