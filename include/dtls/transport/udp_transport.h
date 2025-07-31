#pragma once

#include <dtls/error.h>
#include <dtls/result.h>
#include <dtls/types.h>
#include <dtls/memory/buffer.h>

#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <condition_variable>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#endif

namespace dtls {
namespace v13 {
namespace transport {

// Platform-specific socket type
#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle INVALID_SOCKET_HANDLE = INVALID_SOCKET;
#else
using SocketHandle = int;
constexpr SocketHandle INVALID_SOCKET_HANDLE = -1;
#endif

/**
 * Network endpoint representing an address and port
 */
struct NetworkEndpoint {
    std::string address;
    uint16_t port;
    NetworkAddress::Family family;
    
    NetworkEndpoint() : port(0), family(NetworkAddress::Family::IPv4) {}
    NetworkEndpoint(const std::string& addr, uint16_t p, NetworkAddress::Family f = NetworkAddress::Family::IPv4)
        : address(addr), port(p), family(f) {}
    
    bool operator==(const NetworkEndpoint& other) const {
        return address == other.address && port == other.port && family == other.family;
    }
    
    bool operator!=(const NetworkEndpoint& other) const {
        return !(*this == other);
    }
    
    std::string to_string() const {
        return (family == NetworkAddress::Family::IPv6) ? 
               "[" + address + "]:" + std::to_string(port) :
               address + ":" + std::to_string(port);
    }
};

/**
 * UDP packet structure for transport
 */
struct UDPPacket {
    NetworkEndpoint source;
    NetworkEndpoint destination;
    memory::ZeroCopyBuffer data;
    std::chrono::steady_clock::time_point timestamp;
    
    UDPPacket() = default;
    UDPPacket(const NetworkEndpoint& src, const NetworkEndpoint& dst, memory::ZeroCopyBuffer buffer)
        : source(src), destination(dst), data(std::move(buffer)), timestamp(std::chrono::steady_clock::now()) {}
};

/**
 * Transport statistics and metrics
 */
struct TransportStats {
    // Packet statistics
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    
    // Error statistics
    uint32_t send_errors = 0;
    uint32_t receive_errors = 0;
    uint32_t socket_errors = 0;
    uint32_t dropped_packets = 0;
    
    // Performance metrics
    std::chrono::microseconds average_send_time{0};
    std::chrono::microseconds average_receive_time{0};
    uint32_t current_connections = 0;
    uint32_t peak_connections = 0;
    
    // Network timing
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_activity;
    
    TransportStats() {
        start_time = std::chrono::steady_clock::now();
        last_activity = start_time;
    }
};

/**
 * Transport event types
 */
enum class TransportEvent : uint8_t {
    PACKET_RECEIVED,
    PACKET_SENT,
    SEND_ERROR,
    RECEIVE_ERROR,
    SOCKET_ERROR,
    CONNECTION_TIMEOUT,
    INTERFACE_CHANGE
};

/**
 * Transport event callback
 */
using TransportEventCallback = std::function<void(TransportEvent event, 
                                                 const NetworkEndpoint& endpoint,
                                                 const std::vector<uint8_t>& data)>;

/**
 * Transport configuration
 */
struct TransportConfig {
    // Socket configuration
    size_t receive_buffer_size = 65536;  // 64KB
    size_t send_buffer_size = 65536;     // 64KB
    bool reuse_address = true;
    bool reuse_port = false;
    
    // Threading configuration
    uint32_t worker_threads = 2;
    uint32_t max_connections = 10000;
    
    // Timeout configuration
    std::chrono::milliseconds send_timeout{5000};      // 5 seconds
    std::chrono::milliseconds receive_timeout{1000};   // 1 second
    std::chrono::milliseconds idle_timeout{300000};    // 5 minutes
    
    // Queue configuration
    size_t max_send_queue_size = 1000;
    size_t max_receive_queue_size = 1000;
    
    // Performance tuning
    bool enable_nonblocking = true;
    bool enable_fast_path = true;
    uint32_t poll_timeout_ms = 100;
    
    TransportConfig() = default;
};

/**
 * UDP Transport implementation for DTLS v1.3
 * 
 * Provides multi-threaded UDP socket handling with event-driven processing,
 * connection multiplexing, and comprehensive error handling.
 */
/**
 * Abstract transport interface for DTLS
 * 
 * Provides a common interface for different transport implementations
 * to be used by the DTLS protocol layer and in testing.
 */
class DTLS_API TransportInterface {
public:
    virtual ~TransportInterface() = default;
    
    /**
     * Bind to local address/port
     */
    virtual Result<void> bind() = 0;
    
    /**
     * Connect to remote endpoint
     */
    virtual Result<void> connect(const std::string& remote_addr, uint16_t remote_port) = 0;
    
    /**
     * Send data to connected endpoint
     */
    virtual Result<size_t> send(const std::vector<uint8_t>& data) = 0;
    
    /**
     * Receive data from connected endpoint
     */
    virtual Result<std::vector<uint8_t>> receive(std::chrono::milliseconds timeout) = 0;
    
    /**
     * Shutdown the transport
     */
    virtual Result<void> shutdown() = 0;
    
    /**
     * Check if transport is bound
     */
    virtual bool is_bound() const = 0;
    
    /**
     * Check if transport is connected
     */
    virtual bool is_connected() const = 0;
    
    /**
     * Get local address
     */
    virtual std::string get_local_address() const = 0;
    
    /**
     * Get local port
     */
    virtual uint16_t get_local_port() const = 0;
};
class DTLS_API UDPTransport {
public:
    UDPTransport();
    explicit UDPTransport(const TransportConfig& config);
    ~UDPTransport();
    
    // Non-copyable, movable
    UDPTransport(const UDPTransport&) = delete;
    UDPTransport& operator=(const UDPTransport&) = delete;
    UDPTransport(UDPTransport&&) noexcept = default;
    UDPTransport& operator=(UDPTransport&&) noexcept = default;
    
    /**
     * Initialize the transport
     */
    Result<void> initialize();
    
    /**
     * Bind to a local endpoint
     */
    Result<void> bind(const NetworkEndpoint& local_endpoint);
    
    /**
     * Start the transport (begin processing)
     */
    Result<void> start();
    
    /**
     * Stop the transport gracefully
     */
    Result<void> stop();
    
    /**
     * Force stop the transport immediately
     */
    void force_stop();
    
    /**
     * Send a packet to a remote endpoint
     */
    Result<void> send_packet(const NetworkEndpoint& destination, 
                            const memory::ZeroCopyBuffer& data);
    
    /**
     * Receive a packet (non-blocking)
     */
    Result<UDPPacket> receive_packet();
    
    /**
     * Check if transport is running
     */
    bool is_running() const;
    
    /**
     * Get local bound endpoint
     */
    Result<NetworkEndpoint> get_local_endpoint() const;
    
    /**
     * Get transport statistics
     */
    const TransportStats& get_stats() const;
    
    /**
     * Get configuration
     */
    const TransportConfig& get_config() const;
    
    /**
     * Set event callback
     */
    void set_event_callback(TransportEventCallback callback);
    
    /**
     * Add a remote endpoint for connection tracking
     */
    Result<void> add_connection(const NetworkEndpoint& remote_endpoint);
    
    /**
     * Remove a remote endpoint
     */
    Result<void> remove_connection(const NetworkEndpoint& remote_endpoint);
    
    /**
     * Get active connections
     */
    std::vector<NetworkEndpoint> get_active_connections() const;
    
    /**
     * Resolve hostname to network endpoints
     */
    static Result<std::vector<NetworkEndpoint>> resolve_hostname(
        const std::string& hostname, 
        uint16_t port, 
        NetworkAddress::Family preferred_family = NetworkAddress::Family::IPv4
    );
    
    /**
     * Get network interface addresses
     */
    static Result<std::vector<NetworkEndpoint>> get_local_addresses();
    
private:
    // Internal state management
    enum class State {
        UNINITIALIZED,
        INITIALIZED,
        BOUND,
        RUNNING,
        STOPPING,
        STOPPED
    };
    
    // Socket management
    Result<void> create_socket();
    Result<void> configure_socket();
    Result<void> close_socket();
    Result<NetworkEndpoint> socket_address_to_endpoint(const sockaddr* addr, socklen_t len) const;
    Result<void> endpoint_to_socket_address(const NetworkEndpoint& endpoint, 
                                           sockaddr_storage& addr, socklen_t& len) const;
    
    // Threading and event processing
    void worker_thread_main();
    void receive_thread_main();
    void send_thread_main();
    Result<void> process_receive_events();
    Result<void> process_send_events();
    
    // Packet processing
    Result<void> handle_received_packet(const NetworkEndpoint& source, 
                                       const memory::ZeroCopyBuffer& data);
    Result<void> enqueue_outgoing_packet(const NetworkEndpoint& destination,
                                        const memory::ZeroCopyBuffer& data);
    
    // Connection management
    void update_connection_activity(const NetworkEndpoint& endpoint);
    void cleanup_idle_connections();
    
    // Event handling
    void fire_event(TransportEvent event, 
                   const NetworkEndpoint& endpoint,
                   const std::vector<uint8_t>& data = {});
    
    // Utility methods
    void update_stats_on_send(size_t bytes, std::chrono::microseconds duration);
    void update_stats_on_receive(size_t bytes, std::chrono::microseconds duration);
    void update_last_activity();
    
    // Platform-specific implementations
    Result<ssize_t> platform_send(const void* data, size_t len, 
                                 const sockaddr* addr, socklen_t addr_len);
    Result<ssize_t> platform_receive(void* data, size_t len, 
                                    sockaddr_storage& addr, socklen_t& addr_len);
    
    // Member variables
    TransportConfig config_;
    State state_;
    mutable std::mutex state_mutex_;
    
    // Socket
    SocketHandle socket_;
    NetworkEndpoint local_endpoint_;
    
    // Threading
    std::vector<std::thread> worker_threads_;
    std::thread receive_thread_;
    std::thread send_thread_;
    std::atomic<bool> should_stop_{false};
    
    // Packet queues
    std::queue<UDPPacket> receive_queue_;
    std::queue<UDPPacket> send_queue_;
    mutable std::mutex receive_queue_mutex_;
    mutable std::mutex send_queue_mutex_;
    std::condition_variable receive_queue_cv_;
    std::condition_variable send_queue_cv_;
    
    // Connection tracking
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> active_connections_;
    mutable std::mutex connections_mutex_;
    
    // Statistics and events
    TransportStats stats_;
    TransportEventCallback event_callback_;
    mutable std::mutex stats_mutex_;
    
    // Platform-specific cleanup
    static void platform_cleanup();
    static Result<void> platform_initialize();
};

/**
 * RAII helper for transport lifecycle management
 */
class DTLS_API TransportManager {
public:
    TransportManager() = default;
    ~TransportManager();
    
    Result<void> create_transport(const TransportConfig& config = {});
    UDPTransport* get_transport() const { return transport_.get(); }
    Result<void> start_transport(const NetworkEndpoint& bind_endpoint);
    void stop_transport();
    
private:
    std::unique_ptr<UDPTransport> transport_;
    bool is_started_ = false;
};

}  // namespace transport
}  // namespace v13
}  // namespace dtls