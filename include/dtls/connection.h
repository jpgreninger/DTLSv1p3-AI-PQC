#pragma once

#include <dtls/error.h>
#include <dtls/result.h>
#include <dtls/types.h>
#include <dtls/crypto/provider.h>
#include <dtls/protocol/record_layer.h>
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/early_data.h>
#include <dtls/memory/buffer.h>
#include <dtls/transport/udp_transport.h>

#include <memory>
#include <functional>
#include <chrono>
#include <vector>

namespace dtls {
namespace v13 {

// Forward declarations
namespace protocol {
    class HandshakeManager;
    class MessageLayer;
    class SessionTicketManager;
    class EarlyDataReplayProtection;
    struct EarlyDataContext;
}

/**
 * Connection configuration parameters
 */
struct ConnectionConfig {
    // Security configuration
    std::vector<CipherSuite> supported_cipher_suites;
    std::vector<NamedGroup> supported_groups;
    std::vector<SignatureScheme> supported_signatures;
    
    // Connection parameters
    std::chrono::milliseconds handshake_timeout{10000};  // 10 seconds
    std::chrono::milliseconds retransmission_timeout{1000};  // 1 second
    uint32_t max_retransmissions = 5;
    
    // Connection ID support
    bool enable_connection_id = true;
    size_t connection_id_length = 8;
    
    // Early data support
    bool enable_early_data = false;
    size_t max_early_data_size = 16384;  // 16KB
    
    // Early data configuration
    std::chrono::milliseconds early_data_timeout{5000}; // Max time to wait for early data acceptance
    bool allow_early_data_replay_protection{true};      // Enable replay protection for early data
    
    // Session management
    bool enable_session_resumption = true;
    std::chrono::seconds session_lifetime{7200};  // 2 hours
    
    // Performance tuning
    size_t receive_buffer_size = 65536;  // 64KB
    size_t send_buffer_size = 65536;     // 64KB
    
    ConnectionConfig() = default;
};

/**
 * Connection statistics and metrics
 */
struct ConnectionStats {
    // Handshake metrics
    std::chrono::milliseconds handshake_duration{0};
    uint32_t handshake_retransmissions = 0;
    
    // Data transfer metrics
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t records_sent = 0;
    uint64_t records_received = 0;
    
    // Error metrics
    uint32_t decrypt_errors = 0;
    uint32_t sequence_errors = 0;
    uint32_t protocol_errors = 0;
    
    // Key update metrics
    uint32_t key_updates_performed = 0;
    
    // Connection timing
    std::chrono::steady_clock::time_point connection_start;
    std::chrono::steady_clock::time_point last_activity;
    
    ConnectionStats() {
        connection_start = std::chrono::steady_clock::now();
        last_activity = connection_start;
    }
};

/**
 * Connection event types for callbacks
 */
enum class ConnectionEvent : uint8_t {
    HANDSHAKE_STARTED,
    HANDSHAKE_COMPLETED,
    HANDSHAKE_FAILED,
    DATA_RECEIVED,
    CONNECTION_CLOSED,
    ERROR_OCCURRED,
    ALERT_RECEIVED,
    KEY_UPDATE_COMPLETED,
    // Early data events (RFC 9147)
    EARLY_DATA_ACCEPTED,      // Server accepted early data
    EARLY_DATA_REJECTED,      // Server rejected early data
    EARLY_DATA_RECEIVED,      // Data received during early data phase
    NEW_SESSION_TICKET_RECEIVED // New session ticket for future 0-RTT
};

/**
 * Connection event callback function type
 */
using ConnectionEventCallback = std::function<void(ConnectionEvent event, 
                                                  const std::vector<uint8_t>& data)>;

/**
 * DTLS v1.3 Connection implementation
 * 
 * This class represents a single DTLS connection and integrates all protocol
 * layers including handshake management, record layer processing, and 
 * application data handling.
 */
class DTLS_API Connection {
public:
    /**
     * Create a new connection (client mode)
     */
    static Result<std::unique_ptr<Connection>> create_client(
        const ConnectionConfig& config,
        std::unique_ptr<crypto::CryptoProvider> crypto_provider,
        const NetworkAddress& server_address,
        ConnectionEventCallback event_callback = nullptr
    );
    
    /**
     * Create a new connection (server mode)
     */
    static Result<std::unique_ptr<Connection>> create_server(
        const ConnectionConfig& config,
        std::unique_ptr<crypto::CryptoProvider> crypto_provider,
        const NetworkAddress& client_address,
        ConnectionEventCallback event_callback = nullptr
    );
    
    ~Connection();
    
    // Non-copyable, movable
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) noexcept = default;
    Connection& operator=(Connection&&) noexcept = default;
    
    /**
     * Initialize the connection
     */
    Result<void> initialize();
    
    /**
     * Start the handshake process
     */
    Result<void> start_handshake();
    
    /**
     * Process incoming network data
     */
    Result<void> process_incoming_data(const memory::ZeroCopyBuffer& data);
    
    /**
     * Send application data
     */
    Result<void> send_application_data(const memory::ZeroCopyBuffer& data);
    
    /**
     * Receive application data (non-blocking)
     */
    Result<memory::ZeroCopyBuffer> receive_application_data();
    
    /**
     * Close the connection gracefully
     */
    Result<void> close();
    
    /**
     * Force close the connection immediately
     */
    void force_close();
    
    /**
     * Check if connection is established
     */
    bool is_connected() const;
    
    /**
     * Check if handshake is complete
     */
    bool is_handshake_complete() const;
    
    /**
     * Get current connection state
     */
    ConnectionState get_state() const;
    
    /**
     * Get connection statistics
     */
    const ConnectionStats& get_stats() const;
    
    /**
     * Get connection configuration
     */
    const ConnectionConfig& get_config() const;
    
    /**
     * Get local connection ID (if enabled)
     */
    Result<ConnectionID> get_local_connection_id() const;
    
    /**
     * Get peer connection ID (if enabled)
     */
    Result<ConnectionID> get_peer_connection_id() const;
    
    /**
     * Update connection keys (key update)
     */
    Result<void> update_keys();
    
    /**
     * Export key material (RFC 5705)
     */
    Result<std::vector<uint8_t>> export_key_material(
        const std::string& label,
        const std::vector<uint8_t>& context,
        size_t length
    );
    
    /**
     * Set event callback
     */
    void set_event_callback(ConnectionEventCallback callback);
    
    /**
     * Get network address of peer
     */
    const NetworkAddress& get_peer_address() const;
    
    /**
     * Check if this is a client connection
     */
    bool is_client() const;
    
    /**
     * Check if this is a server connection
     */
    bool is_server() const;
    
    /**
     * Process handshake timeouts (should be called periodically)
     */
    Result<void> process_handshake_timeouts();
    
    // ========== Early Data Support (RFC 9147) ==========
    
    /**
     * Send early data (0-RTT) - client only
     * Must be called after start_handshake() but before handshake completion
     */
    Result<void> send_early_data(const memory::ZeroCopyBuffer& data);
    
    /**
     * Check if early data can be sent (client has valid session ticket)
     */
    bool can_send_early_data() const;
    
    /**
     * Check if early data was accepted by the server
     */
    bool is_early_data_accepted() const;
    
    /**
     * Check if early data was rejected by the server
     */
    bool is_early_data_rejected() const;
    
    /**
     * Get early data statistics
     */
    struct EarlyDataStats {
        size_t bytes_sent = 0;
        size_t bytes_accepted = 0;
        size_t bytes_rejected = 0;
        std::chrono::milliseconds response_time{0};
        bool was_attempted = false;
    };
    EarlyDataStats get_early_data_stats() const;
    
    /**
     * Store a session ticket for future early data use
     */
    Result<void> store_session_ticket(const protocol::NewSessionTicket& ticket);
    
    /**
     * Get available session tickets for early data
     */
    std::vector<std::string> get_available_session_tickets() const;
    
    /**
     * Clear all stored session tickets
     */
    void clear_session_tickets();
    
private:
    // Private constructor - use factory methods
    Connection(const ConnectionConfig& config,
              std::unique_ptr<crypto::CryptoProvider> crypto_provider,
              const NetworkAddress& peer_address,
              bool is_client,
              ConnectionEventCallback event_callback);
    
    // Internal state management
    Result<void> transition_state(ConnectionState new_state);
    bool is_valid_state_transition(ConnectionState from, ConnectionState to) const;
    Result<void> perform_state_transition(ConnectionState from, ConnectionState to);
    void fire_state_transition_events(ConnectionState from, ConnectionState to);
    void fire_event(ConnectionEvent event, const std::vector<uint8_t>& data = {});
    Result<void> handle_handshake_message(const protocol::HandshakeMessage& message);
    
    // Specific handshake message handlers  
    Result<void> handle_client_hello_message(const protocol::HandshakeMessage& message);
    Result<void> handle_server_hello_message(const protocol::HandshakeMessage& message);
    Result<void> handle_hello_retry_request_message(const protocol::HandshakeMessage& message);
    Result<void> handle_encrypted_extensions_message(const protocol::HandshakeMessage& message);
    Result<void> handle_certificate_request_message(const protocol::HandshakeMessage& message);
    Result<void> handle_certificate_message(const protocol::HandshakeMessage& message);
    Result<void> handle_certificate_verify_message(const protocol::HandshakeMessage& message);
    Result<void> handle_finished_message(const protocol::HandshakeMessage& message);
    Result<void> handle_new_session_ticket_message(const protocol::HandshakeMessage& message);
    Result<void> handle_key_update_message(const protocol::HandshakeMessage& message);
    Result<void> handle_end_of_early_data_message(const protocol::HandshakeMessage& message);
    Result<void> handle_application_data(const memory::ZeroCopyBuffer& data);
    Result<void> handle_alert(AlertLevel level, AlertDescription description);
    Result<void> process_record(const protocol::PlaintextRecord& record);
    Result<void> process_record_data(const memory::ZeroCopyBuffer& record_data);
    Result<void> handle_handshake_data(const memory::ZeroCopyBuffer& data);
    Result<void> handle_alert_data(const memory::ZeroCopyBuffer& data);
    
    // ACK processing methods
    Result<void> handle_ack_message(const protocol::ACK& ack_message);
    Result<void> send_handshake_message(const protocol::HandshakeMessage& message);
    bool should_process_ack_for_state(ConnectionState state) const;
    void handle_transport_event(transport::TransportEvent event,
                               const transport::NetworkEndpoint& endpoint,
                               const std::vector<uint8_t>& data);
    
    // Connection lifecycle management
    Result<void> cleanup_resources();
    void update_last_activity();
    uint32_t get_next_handshake_sequence();
    
    // Member variables
    ConnectionConfig config_;
    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
    // TODO: Enable when incomplete types are properly implemented
    // std::unique_ptr<protocol::RecordLayer> record_layer_;
    std::unique_ptr<protocol::HandshakeManager> handshake_manager_;
    // std::unique_ptr<protocol::MessageLayer> message_layer_;
    std::unique_ptr<transport::UDPTransport> transport_;
    
    NetworkAddress peer_address_;
    bool is_client_;
    ConnectionState state_;
    ConnectionStats stats_;
    ConnectionEventCallback event_callback_;
    
    // Application data buffers
    std::vector<memory::ZeroCopyBuffer> receive_queue_;
    mutable std::mutex receive_queue_mutex_;
    
    // Connection management
    mutable std::mutex state_mutex_;
    std::atomic<uint32_t> next_handshake_sequence_{0};
    std::atomic<bool> is_closing_{false};
    std::atomic<bool> force_closed_{false};
    
    // Early data support
    std::unique_ptr<protocol::SessionTicketManager> session_ticket_manager_;
    std::unique_ptr<protocol::EarlyDataReplayProtection> replay_protection_;
    protocol::EarlyDataContext early_data_context_;
    mutable std::mutex early_data_mutex_;
};

/**
 * Simple Context wrapper for DTLS connections
 * 
 * Provides a simplified interface for testing and basic usage.
 * This is essentially an alias/wrapper around Connection with
 * default configuration.
 */
class DTLS_API Context {
public:
    /**
     * Create a default client context
     */
    static Result<std::unique_ptr<Context>> create_client();
    
    /**
     * Create a default server context  
     */
    static Result<std::unique_ptr<Context>> create_server();
    
    ~Context() = default;
    
    // Non-copyable, movable
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) noexcept = default;
    Context& operator=(Context&&) noexcept = default;
    
    /**
     * Initialize the context
     */
    Result<void> initialize();
    
    /**
     * Get the underlying connection (for advanced usage)
     */
    Connection* get_connection() const { return connection_.get(); }
    
private:
    Context(std::unique_ptr<Connection> connection) : connection_(std::move(connection)) {}
    
    std::unique_ptr<Connection> connection_;
};

/**
 * Connection Manager for handling multiple connections
 */
class DTLS_API ConnectionManager {
public:
    ConnectionManager() = default;
    ~ConnectionManager() = default;
    
    // Non-copyable, movable
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;
    ConnectionManager(ConnectionManager&&) noexcept = default;
    ConnectionManager& operator=(ConnectionManager&&) noexcept = default;
    
    /**
     * Add a connection to the manager
     */
    Result<void> add_connection(std::unique_ptr<Connection> connection);
    
    /**
     * Remove a connection from the manager
     */
    Result<void> remove_connection(const ConnectionID& connection_id);
    
    /**
     * Find connection by connection ID
     */
    Result<Connection*> find_connection(const ConnectionID& connection_id);
    
    /**
     * Find connection by network address
     */
    Result<Connection*> find_connection(const NetworkAddress& address);
    
    /**
     * Get all active connections
     */
    std::vector<Connection*> get_all_connections();
    
    /**
     * Close all connections
     */
    void close_all_connections();
    
    /**
     * Get connection count
     */
    size_t get_connection_count() const;
    
    /**
     * Cleanup closed connections
     */
    void cleanup_closed_connections();
    
private:
    std::vector<std::unique_ptr<Connection>> connections_;
    mutable std::mutex connections_mutex_;
};

}  // namespace v13
}  // namespace dtls