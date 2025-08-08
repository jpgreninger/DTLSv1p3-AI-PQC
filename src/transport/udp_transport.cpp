#include <dtls/transport/udp_transport.h>
#include <dtls/memory/pool.h>

#include <cstring>
#include <algorithm>
#include <sstream>
#ifndef _WIN32
#include <errno.h>
#endif

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

namespace dtls {
namespace v13 {
namespace transport {

namespace {

#ifdef _WIN32
class WSAInitializer {
public:
    WSAInitializer() {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        initialized_ = (result == 0);
    }
    
    ~WSAInitializer() {
        if (initialized_) {
            WSACleanup();
        }
    }
    
    bool is_initialized() const { return initialized_; }
    
private:
    bool initialized_ = false;
};

static WSAInitializer g_wsa_initializer;
#endif

// Helper function to get last socket error
int get_last_socket_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

// Helper function to check if error is would-block
bool is_would_block_error(int error) {
#ifdef _WIN32
    return error == WSAEWOULDBLOCK;
#else
    return error == EWOULDBLOCK || error == EAGAIN;
#endif
}

// Helper function to close socket
void close_socket_handle(SocketHandle socket) {
    if (socket != INVALID_SOCKET_HANDLE) {
#ifdef _WIN32
        closesocket(socket);
#else
        close(socket);
#endif
    }
}

// Helper function to set socket non-blocking
Result<void> set_socket_nonblocking(SocketHandle socket) {
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        return make_error<void>(DTLSError::SOCKET_ERROR);
    }
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1 || fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        return make_error<void>(DTLSError::SOCKET_ERROR);
    }
#endif
    return make_result();
}

}  // anonymous namespace

// UDPTransport implementation

UDPTransport::UDPTransport() : UDPTransport(TransportConfig{}) {}

UDPTransport::UDPTransport(const TransportConfig& config)
    : config_(config)
    , state_(State::UNINITIALIZED)
    , socket_(INVALID_SOCKET_HANDLE) {
}

UDPTransport::~UDPTransport() {
    if (state_ != State::UNINITIALIZED && state_ != State::STOPPED) {
        force_stop();
    }
}

Result<void> UDPTransport::platform_initialize() {
#ifdef _WIN32
    if (!g_wsa_initializer.is_initialized()) {
        return make_error<void>(DTLSError::INITIALIZATION_FAILED);
    }
#endif
    return make_result();
}

void UDPTransport::platform_cleanup() {
    // Cleanup is handled by global destructors
}

Result<void> UDPTransport::initialize() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ != State::UNINITIALIZED) {
        return make_error<void>(DTLSError::ALREADY_INITIALIZED);
    }
    
    // Initialize platform-specific networking
    auto platform_result = platform_initialize();
    if (!platform_result) {
        return platform_result;
    }
    
    // Initialize statistics
    stats_ = TransportStats{};
    
    state_ = State::INITIALIZED;
    return make_result();
}

Result<void> UDPTransport::create_socket() {
    // Create UDP socket
    socket_ = socket(local_endpoint_.family == NetworkAddress::Family::IPv6 ? AF_INET6 : AF_INET,
                    SOCK_DGRAM, IPPROTO_UDP);
    
    if (socket_ == INVALID_SOCKET_HANDLE) {
        return make_error<void>(DTLSError::SOCKET_ERROR);
    }
    
    return configure_socket();
}

Result<void> UDPTransport::configure_socket() {
    if (socket_ == INVALID_SOCKET_HANDLE) {
        return make_error<void>(DTLSError::SOCKET_ERROR);
    }
    
    // Set socket options
    int opt = 1;
    
    // Reuse address
    if (config_.reuse_address) {
        if (setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, 
                      reinterpret_cast<const char*>(&opt), sizeof(opt)) != 0) {
            return make_error<void>(DTLSError::SOCKET_ERROR);
        }
    }
    
    // Reuse port (Linux/BSD specific)
#ifdef SO_REUSEPORT
    if (config_.reuse_port) {
        if (setsockopt(socket_, SOL_SOCKET, SO_REUSEPORT,
                      reinterpret_cast<const char*>(&opt), sizeof(opt)) != 0) {
            return make_error<void>(DTLSError::SOCKET_ERROR);
        }
    }
#endif
    
    // Set receive buffer size
    int recv_buf_size = static_cast<int>(config_.receive_buffer_size);
    if (setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
                  reinterpret_cast<const char*>(&recv_buf_size), sizeof(recv_buf_size)) != 0) {
        return make_error<void>(DTLSError::SOCKET_ERROR);
    }
    
    // Set send buffer size
    int send_buf_size = static_cast<int>(config_.send_buffer_size);
    if (setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
                  reinterpret_cast<const char*>(&send_buf_size), sizeof(send_buf_size)) != 0) {
        return make_error<void>(DTLSError::SOCKET_ERROR);
    }
    
    // Set non-blocking if enabled
    if (config_.enable_nonblocking) {
        auto nb_result = set_socket_nonblocking(socket_);
        if (!nb_result) {
            return nb_result;
        }
    }
    
    return make_result();
}

Result<void> UDPTransport::bind(const NetworkEndpoint& local_endpoint) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ != State::INITIALIZED) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    local_endpoint_ = local_endpoint;
    
    // Create and configure socket
    auto socket_result = create_socket();
    if (!socket_result) {
        return socket_result;
    }
    
    // Convert endpoint to socket address
    sockaddr_storage addr;
    socklen_t addr_len;
    auto addr_result = endpoint_to_socket_address(local_endpoint, addr, addr_len);
    if (!addr_result) {
        close_socket();
        return addr_result;
    }
    
    // Bind socket
    if (::bind(socket_, reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) {
        int error = get_last_socket_error();
        close_socket();
        // In debug builds, we could log the specific error
        #ifdef DEBUG
        // Error codes like EADDRINUSE (98), EACCES (13), etc. could be handled specifically
        #endif
        return make_error<void>(DTLSError::SOCKET_ERROR);
    }
    
    // Get actual bound address (in case port was 0)
    socklen_t actual_len = sizeof(addr);
    if (getsockname(socket_, reinterpret_cast<sockaddr*>(&addr), &actual_len) == 0) {
        auto endpoint_result = socket_address_to_endpoint(
            reinterpret_cast<const sockaddr*>(&addr), actual_len);
        if (endpoint_result) {
            local_endpoint_ = endpoint_result.value();
        }
    }
    
    state_ = State::BOUND;
    return make_result();
}

Result<void> UDPTransport::start() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ != State::BOUND) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    should_stop_ = false;
    
    try {
        // Start worker threads
        worker_threads_.reserve(config_.worker_threads);
        for (uint32_t i = 0; i < config_.worker_threads; ++i) {
            worker_threads_.emplace_back(&UDPTransport::worker_thread_main, this);
        }
        
        // Start receive thread
        receive_thread_ = std::thread(&UDPTransport::receive_thread_main, this);
        
        // Start send thread
        send_thread_ = std::thread(&UDPTransport::send_thread_main, this);
        
    } catch (const std::exception&) {
        should_stop_ = true;
        return make_error<void>(DTLSError::INTERNAL_ERROR);
    }
    
    state_ = State::RUNNING;
    update_last_activity();
    
    return make_result();
}

Result<void> UDPTransport::stop() {
    std::unique_lock<std::mutex> lock(state_mutex_);
    
    if (state_ != State::RUNNING) {
        return make_result();  // Already stopped
    }
    
    state_ = State::STOPPING;
    lock.unlock();
    
    // Signal threads to stop
    should_stop_ = true;
    
    // Wake up waiting threads
    receive_queue_cv_.notify_all();
    send_queue_cv_.notify_all();
    
    // Wait for threads to finish
    if (receive_thread_.joinable()) {
        receive_thread_.join();
    }
    
    if (send_thread_.joinable()) {
        send_thread_.join();
    }
    
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    worker_threads_.clear();
    
    // Close socket
    close_socket();
    
    // Clear queues
    {
        std::lock_guard<std::mutex> recv_lock(receive_queue_mutex_);
        std::queue<UDPPacket> empty_recv;
        receive_queue_.swap(empty_recv);
    }
    
    {
        std::lock_guard<std::mutex> send_lock(send_queue_mutex_);
        std::queue<UDPPacket> empty_send;
        send_queue_.swap(empty_send);
    }
    
    lock.lock();
    state_ = State::STOPPED;
    
    return make_result();
}

void UDPTransport::force_stop() {
    should_stop_ = true;
    
    // Force close socket to unblock receive operations
    if (socket_ != INVALID_SOCKET_HANDLE) {
        close_socket_handle(socket_);
        socket_ = INVALID_SOCKET_HANDLE;
    }
    
    // Wake up all threads
    receive_queue_cv_.notify_all();
    send_queue_cv_.notify_all();
    
    // Wait for threads (with timeout to avoid indefinite blocking)
    auto join_with_timeout = [](std::thread& t, std::chrono::milliseconds timeout) {
        if (t.joinable()) {
            t.join();  // In practice, we'd implement timeout here
        }
    };
    
    join_with_timeout(receive_thread_, std::chrono::milliseconds(1000));
    join_with_timeout(send_thread_, std::chrono::milliseconds(1000));
    
    for (auto& thread : worker_threads_) {
        join_with_timeout(thread, std::chrono::milliseconds(1000));
    }
    
    worker_threads_.clear();
    
    std::lock_guard<std::mutex> lock(state_mutex_);
    state_ = State::STOPPED;
}

Result<void> UDPTransport::send_packet(const NetworkEndpoint& destination, 
                                      const memory::ZeroCopyBuffer& data) {
    if (!is_running()) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    if (data.empty()) {
        return make_error<void>(DTLSError::INVALID_PARAMETER);
    }
    
    // Create packet (we need to copy the data since ZeroCopyBuffer can't be copied)
    memory::ZeroCopyBuffer data_copy(data.data(), data.size());
    UDPPacket packet(local_endpoint_, destination, std::move(data_copy));
    
    // Add to send queue
    {
        std::lock_guard<std::mutex> lock(send_queue_mutex_);
        
        if (send_queue_.size() >= config_.max_send_queue_size) {
            stats_.dropped_packets++;
            return make_error<void>(DTLSError::QUOTA_EXCEEDED);
        }
        
        send_queue_.push(std::move(packet));
    }
    
    send_queue_cv_.notify_one();
    return make_result();
}

Result<UDPPacket> UDPTransport::receive_packet() {
    std::lock_guard<std::mutex> lock(receive_queue_mutex_);
    
    if (receive_queue_.empty()) {
        return make_error<UDPPacket>(DTLSError::RESOURCE_UNAVAILABLE);
    }
    
    auto packet = std::move(receive_queue_.front());
    receive_queue_.pop();
    
    return make_result(std::move(packet));
}

bool UDPTransport::is_running() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_ == State::RUNNING;
}

Result<NetworkEndpoint> UDPTransport::get_local_endpoint() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ < State::BOUND) {
        return make_error<NetworkEndpoint>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    return make_result(local_endpoint_);
}

const TransportStats& UDPTransport::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

const TransportConfig& UDPTransport::get_config() const {
    return config_;
}

void UDPTransport::set_event_callback(TransportEventCallback callback) {
    event_callback_ = std::move(callback);
}

Result<void> UDPTransport::add_connection(const NetworkEndpoint& remote_endpoint) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    std::string key = remote_endpoint.to_string();
    active_connections_[key] = std::chrono::steady_clock::now();
    
    stats_.current_connections = static_cast<uint32_t>(active_connections_.size());
    if (stats_.current_connections > stats_.peak_connections) {
        stats_.peak_connections = stats_.current_connections;
    }
    
    return make_result();
}

Result<void> UDPTransport::remove_connection(const NetworkEndpoint& remote_endpoint) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    std::string key = remote_endpoint.to_string();
    auto it = active_connections_.find(key);
    if (it != active_connections_.end()) {
        active_connections_.erase(it);
        stats_.current_connections = static_cast<uint32_t>(active_connections_.size());
        return make_result();
    }
    
    return make_error<void>(DTLSError::CONNECTION_NOT_FOUND);
}

std::vector<NetworkEndpoint> UDPTransport::get_active_connections() const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    std::vector<NetworkEndpoint> connections;
    connections.reserve(active_connections_.size());
    
    for (const auto& [endpoint_str, timestamp] : active_connections_) {
        // Parse endpoint string back to NetworkEndpoint
        // This is a simplified implementation
        size_t colon_pos = endpoint_str.find_last_of(':');
        if (colon_pos != std::string::npos) {
            std::string addr = endpoint_str.substr(0, colon_pos);
            uint16_t port = static_cast<uint16_t>(std::stoul(endpoint_str.substr(colon_pos + 1)));
            
            // Remove brackets for IPv6
            if (addr.front() == '[' && addr.back() == ']') {
                addr = addr.substr(1, addr.length() - 2);
            }
            
            NetworkAddress::Family family = (endpoint_str.find('[') != std::string::npos) ?
                NetworkAddress::Family::IPv6 : NetworkAddress::Family::IPv4;
            
            connections.emplace_back(addr, port, family);
        }
    }
    
    return connections;
}

// Static utility methods

Result<std::vector<NetworkEndpoint>> UDPTransport::resolve_hostname(
    const std::string& hostname, 
    uint16_t port, 
    NetworkAddress::Family preferred_family) {
    
    struct addrinfo hints, *result, *rp;
    std::memset(&hints, 0, sizeof(hints));
    
    hints.ai_family = (preferred_family == NetworkAddress::Family::IPv6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    
    int status = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hints, &result);
    if (status != 0) {
        return make_error<std::vector<NetworkEndpoint>>(DTLSError::ADDRESS_RESOLUTION_FAILED);
    }
    
    std::vector<NetworkEndpoint> endpoints;
    
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        char addr_str[INET6_ADDRSTRLEN];
        void* addr_ptr;
        NetworkAddress::Family family;
        
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            addr_ptr = &(ipv4->sin_addr);
            family = NetworkAddress::Family::IPv4;
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            addr_ptr = &(ipv6->sin6_addr);
            family = NetworkAddress::Family::IPv6;
        } else {
            continue;
        }
        
        if (inet_ntop(rp->ai_family, addr_ptr, addr_str, sizeof(addr_str))) {
            endpoints.emplace_back(std::string(addr_str), port, family);
        }
    }
    
    freeaddrinfo(result);
    
    if (endpoints.empty()) {
        return make_error<std::vector<NetworkEndpoint>>(DTLSError::ADDRESS_RESOLUTION_FAILED);
    }
    
    return make_result(std::move(endpoints));
}

Result<std::vector<NetworkEndpoint>> UDPTransport::get_local_addresses() {
    // This is a simplified implementation
    // A full implementation would enumerate network interfaces
    std::vector<NetworkEndpoint> addresses;
    
    // Add localhost addresses
    addresses.emplace_back("127.0.0.1", 0, NetworkAddress::Family::IPv4);
    addresses.emplace_back("::1", 0, NetworkAddress::Family::IPv6);
    
    return make_result(std::move(addresses));
}

// Private implementation methods

Result<void> UDPTransport::close_socket() {
    if (socket_ != INVALID_SOCKET_HANDLE) {
        close_socket_handle(socket_);
        socket_ = INVALID_SOCKET_HANDLE;
    }
    return make_result();
}

Result<NetworkEndpoint> UDPTransport::socket_address_to_endpoint(
    const sockaddr* addr, socklen_t len) const {
    
    char addr_str[INET6_ADDRSTRLEN];
    uint16_t port;
    NetworkAddress::Family family;
    
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in* ipv4 = reinterpret_cast<const struct sockaddr_in*>(addr);
        if (!inet_ntop(AF_INET, &(ipv4->sin_addr), addr_str, sizeof(addr_str))) {
            return make_error<NetworkEndpoint>(DTLSError::ADDRESS_RESOLUTION_FAILED);
        }
        port = ntohs(ipv4->sin_port);
        family = NetworkAddress::Family::IPv4;
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6* ipv6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
        if (!inet_ntop(AF_INET6, &(ipv6->sin6_addr), addr_str, sizeof(addr_str))) {
            return make_error<NetworkEndpoint>(DTLSError::ADDRESS_RESOLUTION_FAILED);
        }
        port = ntohs(ipv6->sin6_port);
        family = NetworkAddress::Family::IPv6;
    } else {
        return make_error<NetworkEndpoint>(DTLSError::INVALID_PARAMETER);
    }
    
    return make_result(NetworkEndpoint(std::string(addr_str), port, family));
}

Result<void> UDPTransport::endpoint_to_socket_address(
    const NetworkEndpoint& endpoint, sockaddr_storage& addr, socklen_t& len) const {
    
    std::memset(&addr, 0, sizeof(addr));
    
    if (endpoint.family == NetworkAddress::Family::IPv4) {
        struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(&addr);
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(endpoint.port);
        
        if (inet_pton(AF_INET, endpoint.address.c_str(), &(ipv4->sin_addr)) != 1) {
            return make_error<void>(DTLSError::INVALID_PARAMETER);
        }
        
        len = sizeof(struct sockaddr_in);
    } else if (endpoint.family == NetworkAddress::Family::IPv6) {
        struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(endpoint.port);
        
        if (inet_pton(AF_INET6, endpoint.address.c_str(), &(ipv6->sin6_addr)) != 1) {
            return make_error<void>(DTLSError::INVALID_PARAMETER);
        }
        
        len = sizeof(struct sockaddr_in6);
    } else {
        return make_error<void>(DTLSError::INVALID_PARAMETER);
    }
    
    return make_result();
}

void UDPTransport::worker_thread_main() {
    while (!should_stop_) {
        // Process events with timeout
        auto start_time = std::chrono::steady_clock::now();
        
        // Clean up idle connections periodically
        cleanup_idle_connections();
        
        // Sleep for a short time to avoid busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.poll_timeout_ms));
    }
}

void UDPTransport::receive_thread_main() {
    constexpr size_t BUFFER_SIZE = 65536;  // 64KB buffer
    auto buffer = memory::make_buffer(BUFFER_SIZE);
    
    while (!should_stop_) {
        sockaddr_storage source_addr;
        socklen_t addr_len = sizeof(source_addr);
        
        auto start_time = std::chrono::steady_clock::now();
        auto receive_result = platform_receive(reinterpret_cast<void*>(buffer->mutable_data()), buffer->capacity(), source_addr, addr_len);
        auto end_time = std::chrono::steady_clock::now();
        
        if (!receive_result) {
            continue;  // Error handled in platform_receive
        }
        
        ssize_t bytes_received = receive_result.value();
        if (bytes_received <= 0) {
            continue;
        }
        
        // Convert source address to endpoint
        auto endpoint_result = socket_address_to_endpoint(
            reinterpret_cast<const sockaddr*>(&source_addr), addr_len);
        if (!endpoint_result) {
            continue;
        }
        
        // Create packet data
        memory::ZeroCopyBuffer packet_data(buffer->data(), static_cast<size_t>(bytes_received));
        
        // Handle received packet
        auto handle_result = handle_received_packet(endpoint_result.value(), packet_data);
        if (handle_result) {
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            update_stats_on_receive(static_cast<size_t>(bytes_received), duration);
        }
    }
}

void UDPTransport::send_thread_main() {
    while (!should_stop_) {
        std::unique_lock<std::mutex> lock(send_queue_mutex_);
        
        // Wait for packets to send
        send_queue_cv_.wait(lock, [this] { return !send_queue_.empty() || should_stop_; });
        
        if (should_stop_) {
            break;
        }
        
        // Process all available packets
        while (!send_queue_.empty()) {
            auto packet = std::move(send_queue_.front());
            send_queue_.pop();
            lock.unlock();
            
            // Convert destination to socket address
            sockaddr_storage dest_addr;
            socklen_t addr_len;
            auto addr_result = endpoint_to_socket_address(packet.destination, dest_addr, addr_len);
            if (!addr_result) {
                stats_.send_errors++;
                lock.lock();
                continue;
            }
            
            // Send packet
            auto start_time = std::chrono::steady_clock::now();
            auto send_result = platform_send(packet.data.data(), packet.data.size(),
                                           reinterpret_cast<const sockaddr*>(&dest_addr), addr_len);
            auto end_time = std::chrono::steady_clock::now();
            
            if (send_result) {
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
                update_stats_on_send(packet.data.size(), duration);
                fire_event(TransportEvent::PACKET_SENT, packet.destination);
            } else {
                stats_.send_errors++;
                fire_event(TransportEvent::SEND_ERROR, packet.destination);
            }
            
            lock.lock();
        }
    }
}

Result<void> UDPTransport::handle_received_packet(const NetworkEndpoint& source, 
                                                 const memory::ZeroCopyBuffer& data) {
    // Update connection activity
    update_connection_activity(source);
    
    // Create packet (create a copy since we can't copy ZeroCopyBuffer)
    memory::ZeroCopyBuffer data_copy(data.data(), data.size());
    UDPPacket packet(source, local_endpoint_, std::move(data_copy));
    
    // Add to receive queue
    {
        std::lock_guard<std::mutex> lock(receive_queue_mutex_);
        
        if (receive_queue_.size() >= config_.max_receive_queue_size) {
            stats_.dropped_packets++;
            return make_error<void>(DTLSError::QUOTA_EXCEEDED);
        }
        
        receive_queue_.push(std::move(packet));
    }
    
    receive_queue_cv_.notify_one();
    fire_event(TransportEvent::PACKET_RECEIVED, source);
    
    return make_result();
}

void UDPTransport::update_connection_activity(const NetworkEndpoint& endpoint) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    std::string key = endpoint.to_string();
    active_connections_[key] = std::chrono::steady_clock::now();
}

void UDPTransport::cleanup_idle_connections() {
    auto now = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto it = active_connections_.begin();
    while (it != active_connections_.end()) {
        if (now - it->second > config_.idle_timeout) {
            it = active_connections_.erase(it);
        } else {
            ++it;
        }
    }
    
    stats_.current_connections = static_cast<uint32_t>(active_connections_.size());
}

void UDPTransport::fire_event(TransportEvent event, 
                             const NetworkEndpoint& endpoint,
                             const std::vector<uint8_t>& data) {
    if (event_callback_) {
        event_callback_(event, endpoint, data);
    }
}

void UDPTransport::update_stats_on_send(size_t bytes, std::chrono::microseconds duration) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.packets_sent++;
    stats_.bytes_sent += bytes;
    
    // Update average send time
    if (stats_.packets_sent == 1) {
        stats_.average_send_time = duration;
    } else {
        auto total_time = stats_.average_send_time * (stats_.packets_sent - 1) + duration;
        stats_.average_send_time = total_time / stats_.packets_sent;
    }
    
    update_last_activity();
}

void UDPTransport::update_stats_on_receive(size_t bytes, std::chrono::microseconds duration) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.packets_received++;
    stats_.bytes_received += bytes;
    
    // Update average receive time
    if (stats_.packets_received == 1) {
        stats_.average_receive_time = duration;
    } else {
        auto total_time = stats_.average_receive_time * (stats_.packets_received - 1) + duration;
        stats_.average_receive_time = total_time / stats_.packets_received;
    }
    
    update_last_activity();
}

void UDPTransport::update_last_activity() {
    stats_.last_activity = std::chrono::steady_clock::now();
}

Result<ssize_t> UDPTransport::platform_send(const void* data, size_t len, 
                                           const sockaddr* addr, socklen_t addr_len) {
    if (socket_ == INVALID_SOCKET_HANDLE) {
        return make_error<ssize_t>(DTLSError::SOCKET_ERROR);
    }
    
    ssize_t bytes_sent = sendto(socket_, reinterpret_cast<const char*>(data), len, 0, addr, addr_len);
    
    if (bytes_sent < 0) {
        int error = get_last_socket_error();
        if (is_would_block_error(error)) {
            return make_result<ssize_t>(0);  // Would block, try again later
        }
        return make_error<ssize_t>(DTLSError::SEND_ERROR);
    }
    
    return make_result(bytes_sent);
}

Result<ssize_t> UDPTransport::platform_receive(void* data, size_t len, 
                                              sockaddr_storage& addr, socklen_t& addr_len) {
    if (socket_ == INVALID_SOCKET_HANDLE) {
        return make_error<ssize_t>(DTLSError::SOCKET_ERROR);
    }
    
    ssize_t bytes_received = recvfrom(socket_, reinterpret_cast<char*>(data), len, 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addr_len);
    
    if (bytes_received < 0) {
        int error = get_last_socket_error();
        if (is_would_block_error(error)) {
            return make_result<ssize_t>(0);  // Would block, try again later
        }
        return make_error<ssize_t>(DTLSError::RECEIVE_ERROR);
    }
    
    return make_result(bytes_received);
}

// TransportManager implementation

TransportManager::~TransportManager() {
    stop_transport();
}

Result<void> TransportManager::create_transport(const TransportConfig& config) {
    transport_ = std::make_unique<UDPTransport>(config);
    return transport_->initialize();
}

Result<void> TransportManager::start_transport(const NetworkEndpoint& bind_endpoint) {
    if (!transport_) {
        return make_error<void>(DTLSError::NOT_INITIALIZED);
    }
    
    auto bind_result = transport_->bind(bind_endpoint);
    if (!bind_result) {
        return bind_result;
    }
    
    auto start_result = transport_->start();
    if (start_result) {
        is_started_ = true;
    }
    
    return start_result;
}

void TransportManager::stop_transport() {
    if (transport_ && is_started_) {
        transport_->stop();
        is_started_ = false;
    }
}

}  // namespace transport
}  // namespace v13
}  // namespace dtls