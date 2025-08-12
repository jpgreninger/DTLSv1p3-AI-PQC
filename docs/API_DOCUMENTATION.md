# DTLS v1.3 API Documentation

Complete reference for the DTLS v1.3 C++ library public API. This implementation follows RFC 9147 specifications and provides both high-level convenience APIs and low-level control interfaces.

## Table of Contents

- [Quick Start](#quick-start)
- [Core API](#core-api)
- [Connection Management](#connection-management)
- [Cryptographic Interface](#cryptographic-interface)
- [Protocol Layer](#protocol-layer)
- [Memory Management](#memory-management)
- [Error Handling](#error-handling)
- [Configuration](#configuration)
- [Performance Monitoring](#performance-monitoring)
- [Security Features](#security-features)
- [Examples](#examples)

## Quick Start

### Basic Client Connection

```cpp
#include <dtls/connection.h>
#include <dtls/crypto/provider_factory.h>

using namespace dtls::v13;

// Initialize crypto provider
auto crypto_manager = crypto::ProviderFactory::instance()
    .create_provider("openssl");

// Configure connection
ConnectionConfig config;
config.handshake_timeout = std::chrono::seconds(10);
config.enable_early_data = true;
config.supported_cipher_suites = {
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256
};

// Create connection
auto connection_result = Connection::create_client(
    NetworkAddress::from_string("192.168.1.100:4433"),
    config,
    std::move(crypto_manager)
);

if (!connection_result) {
    std::cerr << "Failed to create connection: " 
              << connection_result.error().message() << std::endl;
    return -1;
}

auto connection = std::move(connection_result.value());

// Perform handshake
auto handshake_result = connection->handshake();
if (!handshake_result) {
    std::cerr << "Handshake failed: " 
              << handshake_result.error().message() << std::endl;
    return -1;
}

// Send application data
std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
auto send_result = connection->send(data);
if (!send_result) {
    std::cerr << "Send failed: " 
              << send_result.error().message() << std::endl;
    return -1;
}
```

### Basic Server Setup

```cpp
#include <dtls/connection.h>
#include <dtls/crypto/provider_factory.h>

using namespace dtls::v13;

// Server configuration
ConnectionConfig server_config;
server_config.enable_connection_id = true;
server_config.connection_id_length = 8;
server_config.max_early_data_size = 16384;

// Create connection manager
auto manager_result = ConnectionManager::create(server_config);
auto& manager = manager_result.value();

// Set up event callbacks
manager.set_event_callback([](ConnectionEvent event, const Connection& conn) {
    switch (event) {
        case ConnectionEvent::HANDSHAKE_COMPLETED:
            std::cout << "Client connected successfully" << std::endl;
            break;
        case ConnectionEvent::DATA_RECEIVED:
            // Handle incoming data
            break;
        case ConnectionEvent::CONNECTION_CLOSED:
            std::cout << "Client disconnected" << std::endl;
            break;
    }
});

// Start server
auto bind_result = manager.bind(NetworkAddress::from_string("0.0.0.0:4433"));
if (!bind_result) {
    std::cerr << "Failed to bind server" << std::endl;
    return -1;
}

// Run server loop
manager.run();
```

## Core API

### Types and Constants

The core types are defined in `include/dtls/types.h`:

```cpp
namespace dtls::v13 {
    // Protocol version constants
    constexpr ProtocolVersion DTLS_V13{254, 252};
    
    // Connection identifiers and session data
    using ConnectionID = std::vector<uint8_t>;
    using SessionID = std::vector<uint8_t>;
    using Random = std::array<uint8_t, 32>;
    using KeyMaterial = std::vector<uint8_t>;
    
    // Network addressing
    struct NetworkAddress {
        enum class Family { IPv4, IPv6 } family;
        std::array<uint8_t, 16> address;
        uint16_t port;
        
        static NetworkAddress from_ipv4(uint32_t ip, uint16_t port);
        static NetworkAddress from_ipv6(const std::array<uint8_t, 16>& ip, uint16_t port);
        static Result<NetworkAddress> from_string(const std::string& addr);
        
        bool is_ipv4() const;
        bool is_ipv6() const;
        std::string to_string() const;
    };
    
    // Protocol enums
    enum class ContentType : uint8_t {
        INVALID = 0,
        CHANGE_CIPHER_SPEC = 20,
        ALERT = 21,
        HANDSHAKE = 22,
        APPLICATION_DATA = 23,
        HEARTBEAT = 24,
        TLS12_CID = 25,
        ACK = 26
    };
    
    enum class HandshakeType : uint8_t {
        CLIENT_HELLO = 1,
        SERVER_HELLO = 2,
        NEW_SESSION_TICKET = 4,
        END_OF_EARLY_DATA = 5,
        HELLO_RETRY_REQUEST = 6,
        ENCRYPTED_EXTENSIONS = 8,
        CERTIFICATE = 11,
        CERTIFICATE_REQUEST = 13,
        CERTIFICATE_VERIFY = 15,
        FINISHED = 20,
        KEY_UPDATE = 24,
        ACK = 26,
        MESSAGE_HASH = 254
    };
    
    enum class CipherSuite : uint16_t {
        TLS_AES_128_GCM_SHA256 = 0x1301,
        TLS_AES_256_GCM_SHA384 = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
        TLS_AES_128_CCM_SHA256 = 0x1304,
        TLS_AES_128_CCM_8_SHA256 = 0x1305
    };
    
    enum class ConnectionState {
        INITIAL,
        WAIT_SERVER_HELLO,
        WAIT_ENCRYPTED_EXTENSIONS,
        WAIT_CERTIFICATE_OR_CERT_REQUEST,
        WAIT_CERTIFICATE_VERIFY,
        WAIT_SERVER_FINISHED,
        WAIT_CLIENT_CERTIFICATE,
        WAIT_CLIENT_CERTIFICATE_VERIFY,
        WAIT_CLIENT_FINISHED,
        CONNECTED,
        CLOSED,
        EARLY_DATA,
        WAIT_END_OF_EARLY_DATA,
        EARLY_DATA_REJECTED
    };
}
```

### Result Type System

The library uses a Result<T> type for error handling instead of exceptions:

```cpp
template<typename T>
class Result {
public:
    // Check if result contains a value
    bool has_value() const;
    explicit operator bool() const;
    
    // Access value (only if has_value() == true)
    T& value();
    const T& value() const;
    T& operator*();
    const T& operator*() const;
    
    // Access error (only if has_value() == false)
    const Error& error() const;
    
    // Convenience methods
    T value_or(T&& default_value) const;
    
    // Factory methods
    static Result<T> success(T&& value);
    static Result<T> failure(Error error);
};

// Usage examples
Result<Connection> conn_result = Connection::create_client(...);
if (conn_result) {
    auto& connection = *conn_result;
    // Use connection
} else {
    std::cerr << "Error: " << conn_result.error().message() << std::endl;
}
```

## Connection Management

### Connection Class

The main interface for DTLS connections:

```cpp
class Connection {
public:
    // Factory methods
    static Result<std::unique_ptr<Connection>> create_client(
        const NetworkAddress& server_address,
        const ConnectionConfig& config,
        std::unique_ptr<crypto::CryptoProvider> crypto_provider
    );
    
    static Result<std::unique_ptr<Connection>> create_server(
        const NetworkAddress& bind_address,
        const ConnectionConfig& config,
        std::unique_ptr<crypto::CryptoProvider> crypto_provider
    );
    
    // Connection lifecycle
    Result<void> handshake();
    Result<void> handshake_async(std::function<void(Result<void>)> callback);
    
    Result<void> close();
    Result<void> close(AlertDescription alert = AlertDescription::CLOSE_NOTIFY);
    
    // Data transmission
    Result<size_t> send(const std::vector<uint8_t>& data);
    Result<size_t> send(const uint8_t* data, size_t length);
    Result<std::vector<uint8_t>> receive();
    Result<size_t> receive(uint8_t* buffer, size_t buffer_size);
    
    // Early data (0-RTT) support
    Result<size_t> send_early_data(const std::vector<uint8_t>& data);
    Result<bool> is_early_data_accepted() const;
    
    // Key management
    Result<void> update_keys();
    Result<void> request_post_handshake_auth();
    
    // State information
    ConnectionState get_state() const;
    bool is_connected() const;
    bool is_handshake_complete() const;
    
    // Connection properties
    CipherSuite get_negotiated_cipher_suite() const;
    ProtocolVersion get_negotiated_version() const;
    std::optional<ConnectionID> get_connection_id() const;
    std::optional<ConnectionID> get_peer_connection_id() const;
    
    // Statistics and monitoring
    const ConnectionStats& get_statistics() const;
    void reset_statistics();
    
    // Advanced features
    Result<void> set_connection_id(const ConnectionID& cid);
    Result<void> migrate_connection(const NetworkAddress& new_address);
    Result<std::vector<uint8_t>> export_keying_material(
        const std::string& label,
        size_t length,
        const std::vector<uint8_t>& context = {}
    );
    
    // Event handling
    void set_event_callback(ConnectionEventCallback callback);
    
private:
    Connection() = default;
};
```

### Connection Configuration

```cpp
struct ConnectionConfig {
    // Cryptographic preferences
    std::vector<CipherSuite> supported_cipher_suites = {
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    
    std::vector<NamedGroup> supported_groups = {
        NamedGroup::X25519,
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1
    };
    
    std::vector<SignatureScheme> supported_signatures = {
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ED25519
    };
    
    // Timing configuration
    std::chrono::milliseconds handshake_timeout{10000};
    std::chrono::milliseconds retransmission_timeout{1000};
    uint32_t max_retransmissions = 5;
    
    // Connection ID support
    bool enable_connection_id = true;
    uint8_t connection_id_length = 8;
    
    // Early data (0-RTT) configuration
    bool enable_early_data = true;
    uint32_t max_early_data_size = 16384;
    std::chrono::milliseconds early_data_timeout{5000};
    bool allow_early_data_replay_protection = true;
    
    // Session management
    bool enable_session_resumption = true;
    std::chrono::seconds session_lifetime{7200};
    
    // Buffer sizes
    size_t receive_buffer_size = 65536;
    size_t send_buffer_size = 65536;
    
    // Error recovery configuration
    ErrorRecoveryConfig error_recovery;
    
    // Factory method with defaults
    static ConnectionConfig default_client_config();
    static ConnectionConfig default_server_config();
};
```

### Connection Events

```cpp
enum class ConnectionEvent {
    HANDSHAKE_STARTED,
    HANDSHAKE_COMPLETED,
    HANDSHAKE_FAILED,
    DATA_RECEIVED,
    CONNECTION_CLOSED,
    ERROR_OCCURRED,
    ALERT_RECEIVED,
    KEY_UPDATE_COMPLETED,
    EARLY_DATA_ACCEPTED,
    EARLY_DATA_REJECTED,
    EARLY_DATA_RECEIVED,
    NEW_SESSION_TICKET_RECEIVED,
    RECOVERY_STARTED,
    RECOVERY_SUCCEEDED,
    RECOVERY_FAILED,
    CONNECTION_DEGRADED,
    CONNECTION_RESTORED
};

using ConnectionEventCallback = std::function<void(ConnectionEvent, const Connection&)>;

// Example usage
connection->set_event_callback([](ConnectionEvent event, const Connection& conn) {
    switch (event) {
        case ConnectionEvent::HANDSHAKE_COMPLETED:
            std::cout << "Handshake completed with cipher suite: " 
                      << static_cast<int>(conn.get_negotiated_cipher_suite()) << std::endl;
            break;
        
        case ConnectionEvent::DATA_RECEIVED:
            // Handle incoming application data
            auto data = conn.receive();
            if (data) {
                process_application_data(*data);
            }
            break;
        
        case ConnectionEvent::ERROR_OCCURRED:
            std::cerr << "Connection error occurred" << std::endl;
            break;
    }
});
```

### Connection Manager

For server applications managing multiple connections:

```cpp
class ConnectionManager {
public:
    static Result<std::unique_ptr<ConnectionManager>> create(
        const ConnectionConfig& config
    );
    
    // Server lifecycle
    Result<void> bind(const NetworkAddress& address);
    Result<void> listen(int backlog = 128);
    void run();
    void stop();
    
    // Connection management
    std::vector<std::shared_ptr<Connection>> get_active_connections();
    size_t get_connection_count() const;
    
    // Event handling
    void set_event_callback(ConnectionEventCallback callback);
    void set_new_connection_callback(
        std::function<void(std::shared_ptr<Connection>)> callback
    );
    
    // Configuration
    void set_max_connections(size_t max_connections);
    void set_connection_timeout(std::chrono::seconds timeout);
    
    // Statistics
    struct ServerStats {
        size_t total_connections_accepted;
        size_t active_connections;
        size_t failed_handshakes;
        size_t bytes_sent;
        size_t bytes_received;
        std::chrono::steady_clock::time_point start_time;
    };
    
    const ServerStats& get_server_statistics() const;
    
private:
    ConnectionManager() = default;
};
```

## Cryptographic Interface

### Provider Factory

The cryptographic operations are abstracted through a provider system:

```cpp
namespace dtls::v13::crypto {

class ProviderFactory {
public:
    static ProviderFactory& instance();
    
    // Provider registration
    void register_provider(
        const std::string& name,
        const std::string& description,
        std::function<std::unique_ptr<CryptoProvider>()> factory,
        int priority = 0
    );
    
    // Provider creation
    Result<std::unique_ptr<CryptoProvider>> create_provider(
        const std::string& name = "default"
    );
    
    Result<std::unique_ptr<CryptoProvider>> create_best_available_provider();
    
    // Provider information
    std::vector<std::string> get_available_providers() const;
    std::vector<ProviderRegistration> get_provider_registrations() const;
    bool is_provider_available(const std::string& name) const;
    
    // Provider management
    Result<void> load_plugin(const std::string& plugin_path);
    void unload_all_plugins();
    
    // Health monitoring
    Result<ProviderCompatibilityResult> check_compatibility(
        const std::string& provider_name,
        const std::vector<CipherSuite>& required_suites
    ) const;
    
private:
    ProviderFactory() = default;
};

// Built-in provider availability check
namespace builtin {
    bool is_openssl_available();
    bool is_botan_available();
    bool is_hardware_acceleration_available();
}

}
```

### Crypto Provider Interface

```cpp
class CryptoProvider {
public:
    virtual ~CryptoProvider() = default;
    
    // Provider information
    virtual std::string get_name() const = 0;
    virtual std::string get_version() const = 0;
    virtual std::vector<CipherSuite> get_supported_cipher_suites() const = 0;
    virtual std::vector<NamedGroup> get_supported_groups() const = 0;
    virtual std::vector<SignatureScheme> get_supported_signatures() const = 0;
    
    // Key generation and management
    virtual Result<KeyMaterial> generate_key_pair(NamedGroup group) = 0;
    virtual Result<KeyMaterial> derive_shared_secret(
        const KeyMaterial& private_key,
        const KeyMaterial& peer_public_key,
        NamedGroup group
    ) = 0;
    
    // HKDF operations (RFC 5869)
    virtual Result<KeyMaterial> hkdf_extract(
        const KeyMaterial& salt,
        const KeyMaterial& ikm,
        HashAlgorithm hash
    ) = 0;
    
    virtual Result<KeyMaterial> hkdf_expand_label(
        const KeyMaterial& prk,
        const std::string& label,
        const KeyMaterial& context,
        size_t length,
        HashAlgorithm hash
    ) = 0;
    
    // AEAD encryption/decryption
    virtual Result<std::vector<uint8_t>> aead_encrypt(
        const KeyMaterial& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher
    ) = 0;
    
    virtual Result<std::vector<uint8_t>> aead_decrypt(
        const KeyMaterial& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher
    ) = 0;
    
    // Digital signatures
    virtual Result<std::vector<uint8_t>> sign(
        const KeyMaterial& private_key,
        const std::vector<uint8_t>& message,
        SignatureScheme scheme
    ) = 0;
    
    virtual Result<bool> verify(
        const KeyMaterial& public_key,
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature,
        SignatureScheme scheme
    ) = 0;
    
    // Hash functions
    virtual Result<std::vector<uint8_t>> hash(
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm
    ) = 0;
    
    virtual Result<std::vector<uint8_t>> hmac(
        const KeyMaterial& key,
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm
    ) = 0;
    
    // Random number generation
    virtual Result<std::vector<uint8_t>> generate_random(size_t length) = 0;
    
    // Certificate operations
    virtual Result<std::vector<uint8_t>> parse_certificate(
        const std::vector<uint8_t>& cert_data
    ) = 0;
    
    virtual Result<KeyMaterial> extract_public_key(
        const std::vector<uint8_t>& certificate
    ) = 0;
    
    // Hardware acceleration support
    virtual bool supports_hardware_acceleration() const = 0;
    virtual Result<void> enable_hardware_acceleration() = 0;
};
```

### Provider Manager

For advanced provider management and load balancing:

```cpp
class ProviderManager {
public:
    explicit ProviderManager(ProviderPoolConfig config = {});
    
    // Provider pool management
    Result<void> add_provider(std::unique_ptr<CryptoProvider> provider);
    Result<void> remove_provider(const std::string& name);
    
    // Operation delegation with load balancing
    Result<std::unique_ptr<CryptoProvider>> get_provider();
    Result<std::unique_ptr<CryptoProvider>> get_provider_for_operation(
        const std::string& operation_type
    );
    
    // Health monitoring
    void enable_health_monitoring(std::chrono::seconds interval);
    void disable_health_monitoring();
    std::vector<ProviderHealth> get_provider_health() const;
    
    // Performance metrics
    struct PerformanceMetrics {
        std::chrono::nanoseconds avg_operation_time;
        size_t operations_per_second;
        double success_rate;
        size_t total_operations;
    };
    
    PerformanceMetrics get_performance_metrics(const std::string& provider) const;
    
private:
    ProviderPoolConfig config_;
    std::vector<std::unique_ptr<CryptoProvider>> providers_;
    mutable std::mutex providers_mutex_;
};
```

## Protocol Layer

### Record Layer Interface

Low-level record processing:

```cpp
namespace dtls::v13::protocol {

class RecordLayer {
public:
    static Result<std::unique_ptr<RecordLayer>> create(
        std::unique_ptr<crypto::CryptoProvider> crypto_provider
    );
    
    // Record processing
    Result<std::vector<uint8_t>> encrypt_record(
        ContentType content_type,
        const std::vector<uint8_t>& plaintext,
        Epoch epoch,
        SequenceNumber sequence_number,
        const std::optional<ConnectionID>& connection_id = std::nullopt
    );
    
    Result<DecryptedRecord> decrypt_record(
        const std::vector<uint8_t>& encrypted_record
    );
    
    // Key management
    Result<void> set_write_keys(
        Epoch epoch,
        const KeyMaterial& write_key,
        const KeyMaterial& write_iv,
        AEADCipher cipher
    );
    
    Result<void> set_read_keys(
        Epoch epoch,
        const KeyMaterial& read_key,
        const KeyMaterial& read_iv,
        AEADCipher cipher
    );
    
    Result<void> update_keys(const KeyMaterial& update_secret);
    
    // Sequence number management
    SequenceNumber get_next_write_sequence(Epoch epoch);
    Result<void> validate_read_sequence(
        Epoch epoch,
        SequenceNumber sequence_number
    );
    
    // Connection ID support
    Result<void> set_connection_id(const ConnectionID& cid);
    std::optional<ConnectionID> get_connection_id() const;
    
    // Anti-replay protection
    void enable_anti_replay_protection(size_t window_size = 64);
    void disable_anti_replay_protection();
    
private:
    RecordLayer() = default;
};

struct DecryptedRecord {
    ContentType content_type;
    std::vector<uint8_t> plaintext;
    Epoch epoch;
    SequenceNumber sequence_number;
    std::optional<ConnectionID> connection_id;
};

}
```

### Handshake Manager

High-level handshake protocol management:

```cpp
class HandshakeManager {
public:
    static Result<std::unique_ptr<HandshakeManager>> create_client(
        const ConnectionConfig& config,
        std::unique_ptr<crypto::CryptoProvider> crypto_provider
    );
    
    static Result<std::unique_ptr<HandshakeManager>> create_server(
        const ConnectionConfig& config,
        std::unique_ptr<crypto::CryptoProvider> crypto_provider
    );
    
    // Handshake execution
    Result<void> start_handshake();
    Result<HandshakeState> process_message(const std::vector<uint8_t>& message);
    Result<std::vector<uint8_t>> get_next_message();
    
    // State queries
    bool is_handshake_complete() const;
    ConnectionState get_connection_state() const;
    
    // Negotiated parameters
    CipherSuite get_negotiated_cipher_suite() const;
    ProtocolVersion get_negotiated_version() const;
    std::optional<ConnectionID> get_negotiated_connection_id() const;
    
    // Session management
    Result<std::vector<uint8_t>> export_session_ticket();
    Result<void> import_session_ticket(const std::vector<uint8_t>& ticket);
    
    // Early data support
    Result<void> send_early_data(const std::vector<uint8_t>& data);
    Result<std::vector<uint8_t>> receive_early_data();
    bool is_early_data_accepted() const;
    
    // Key material export
    Result<KeyMaterial> export_keying_material(
        const std::string& label,
        size_t length,
        const std::vector<uint8_t>& context = {}
    ) const;
    
    // Certificate handling
    Result<void> set_certificate_chain(
        const std::vector<std::vector<uint8_t>>& cert_chain
    );
    
    Result<void> set_private_key(const KeyMaterial& private_key);
    
    Result<void> set_certificate_verify_callback(
        std::function<bool(const std::vector<std::vector<uint8_t>>&)> callback
    );
    
private:
    HandshakeManager() = default;
};

enum class HandshakeState {
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    NEED_MORE_DATA,
    EARLY_DATA_READY,
    HELLO_RETRY_REQUEST
};
```

## Memory Management

### Buffer Management

Efficient memory handling for network operations:

```cpp
namespace dtls::v13::memory {

class Buffer {
public:
    // Construction
    Buffer();
    explicit Buffer(size_t capacity);
    Buffer(const uint8_t* data, size_t size);
    Buffer(const std::vector<uint8_t>& data);
    
    // Data access
    uint8_t* data();
    const uint8_t* data() const;
    size_t size() const;
    size_t capacity() const;
    bool empty() const;
    
    // Data manipulation
    void resize(size_t new_size);
    void reserve(size_t new_capacity);
    void clear();
    
    Result<void> append(const uint8_t* data, size_t size);
    Result<void> append(const std::vector<uint8_t>& data);
    Result<void> append(const Buffer& other);
    
    Result<void> prepend(const uint8_t* data, size_t size);
    
    // Zero-copy operations
    Buffer slice(size_t offset, size_t length) const;
    std::vector<Buffer> split_at(const std::vector<size_t>& offsets) const;
    
    // Security features
    void secure_zero();  // Secure memory clearing
    bool is_secure() const;
    
    // Conversion
    std::vector<uint8_t> to_vector() const;
    std::string to_hex_string() const;
    
private:
    std::unique_ptr<uint8_t[]> data_;
    size_t size_;
    size_t capacity_;
    bool secure_;
};

class BufferPool {
public:
    static BufferPool& instance();
    
    // Buffer acquisition and release
    Result<Buffer> acquire(size_t min_size);
    void release(Buffer&& buffer);
    
    // Pool configuration
    void set_max_pool_size(size_t max_buffers);
    void set_buffer_sizes(const std::vector<size_t>& sizes);
    
    // Statistics
    struct PoolStats {
        size_t total_buffers;
        size_t available_buffers;
        size_t allocations;
        size_t deallocations;
        size_t pool_hits;
        size_t pool_misses;
    };
    
    PoolStats get_statistics() const;
    void reset_statistics();
    
private:
    BufferPool() = default;
};

}
```

## Error Handling

### Error Types and Codes

```cpp
namespace dtls::v13 {

enum class ErrorCode {
    // Success
    SUCCESS = 0,
    
    // Network errors
    NETWORK_ERROR = 1000,
    CONNECTION_FAILED,
    CONNECTION_TIMEOUT,
    CONNECTION_CLOSED,
    BIND_FAILED,
    
    // Protocol errors
    PROTOCOL_ERROR = 2000,
    INVALID_MESSAGE,
    INVALID_VERSION,
    UNSUPPORTED_CIPHER_SUITE,
    HANDSHAKE_FAILED,
    CERTIFICATE_ERROR,
    SIGNATURE_VERIFICATION_FAILED,
    
    // Cryptographic errors
    CRYPTO_ERROR = 3000,
    KEY_GENERATION_FAILED,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    SIGNATURE_FAILED,
    HASH_FAILED,
    RANDOM_GENERATION_FAILED,
    
    // Memory errors
    MEMORY_ERROR = 4000,
    OUT_OF_MEMORY,
    BUFFER_OVERFLOW,
    INVALID_BUFFER_SIZE,
    
    // Configuration errors
    CONFIG_ERROR = 5000,
    INVALID_CONFIGURATION,
    MISSING_CONFIGURATION,
    UNSUPPORTED_FEATURE
};

class Error {
public:
    Error(ErrorCode code, const std::string& message);
    Error(ErrorCode code, const std::string& message, 
          const std::string& detail);
    
    ErrorCode code() const;
    const std::string& message() const;
    const std::string& detail() const;
    
    // Error chaining
    Error& caused_by(const Error& cause);
    const Error* get_cause() const;
    
    // String representation
    std::string to_string() const;
    
    // Predefined error creators
    static Error network_error(const std::string& message);
    static Error protocol_error(const std::string& message);
    static Error crypto_error(const std::string& message);
    static Error memory_error(const std::string& message);
    static Error config_error(const std::string& message);
    
private:
    ErrorCode code_;
    std::string message_;
    std::string detail_;
    std::unique_ptr<Error> cause_;
};

}
```

### Error Recovery

Advanced error handling and recovery mechanisms:

```cpp
struct ErrorRecoveryConfig {
    uint32_t max_retries = 3;
    std::chrono::milliseconds initial_retry_delay{1000};
    std::chrono::milliseconds max_retry_delay{30000};
    double backoff_multiplier = 2.0;
    
    uint32_t max_consecutive_errors = 10;
    uint32_t max_errors_per_minute = 50;
    uint32_t degraded_mode_threshold = 5;
    
    RecoveryStrategy handshake_error_strategy = RecoveryStrategy::RETRY_WITH_BACKOFF;
    RecoveryStrategy crypto_error_strategy = RecoveryStrategy::RETRY_IMMEDIATE;
    RecoveryStrategy network_error_strategy = RecoveryStrategy::RETRY_WITH_BACKOFF;
    RecoveryStrategy protocol_error_strategy = RecoveryStrategy::RESET_CONNECTION;
    
    std::chrono::seconds health_check_interval{60};
    std::chrono::seconds error_rate_window{60};
    
    bool enable_automatic_recovery = true;
};

enum class RecoveryStrategy {
    NONE,                    // No recovery attempt
    RETRY_IMMEDIATE,         // Immediate retry
    RETRY_WITH_BACKOFF,      // Exponential backoff retry
    GRACEFUL_DEGRADATION,    // Reduce functionality
    RESET_CONNECTION,        // Reset and reconnect
    FAILOVER,               // Switch to backup
    ABORT_CONNECTION        // Terminate connection
};
```

## Configuration

### System Configuration

```cpp
namespace dtls::v13::config {

struct SystemConfig {
    // Threading configuration
    uint32_t worker_threads = std::thread::hardware_concurrency();
    bool enable_thread_pool = true;
    size_t max_concurrent_handshakes = 1000;
    
    // Memory configuration
    size_t default_buffer_size = 16384;
    size_t max_buffer_pool_size = 10000;
    bool enable_secure_memory = true;
    bool enable_memory_debugging = false;
    
    // Security configuration
    SecurityLevel default_security_level = SecurityLevel::HIGH;
    bool enforce_perfect_forward_secrecy = true;
    bool allow_weak_cipher_suites = false;
    std::chrono::seconds session_ticket_lifetime{7200};
    
    // Performance configuration
    bool enable_zero_copy_operations = true;
    bool enable_hardware_acceleration = true;
    uint32_t max_connections_per_thread = 100;
    
    // Logging and monitoring
    LogLevel default_log_level = LogLevel::INFO;
    bool enable_performance_metrics = true;
    std::chrono::seconds metrics_collection_interval{60};
    
    // Load from configuration file
    static Result<SystemConfig> from_file(const std::string& config_path);
    static Result<SystemConfig> from_json(const std::string& json_config);
    
    // Validation
    Result<void> validate() const;
};

// Global configuration access
Result<void> set_global_config(const SystemConfig& config);
const SystemConfig& get_global_config();

}
```

## Performance Monitoring

### Metrics Collection

```cpp
namespace dtls::v13::monitoring {

struct ConnectionMetrics {
    // Timing metrics
    std::chrono::nanoseconds handshake_time;
    std::chrono::nanoseconds avg_round_trip_time;
    std::chrono::nanoseconds crypto_operation_time;
    
    // Throughput metrics
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t records_sent;
    uint32_t records_received;
    double throughput_mbps;
    
    // Error metrics
    uint32_t handshake_failures;
    uint32_t crypto_errors;
    uint32_t network_errors;
    uint32_t protocol_errors;
    
    // Security metrics
    uint32_t replay_attacks_blocked;
    uint32_t invalid_signatures;
    uint32_t certificate_failures;
    uint32_t dos_attacks_blocked;
};

struct SystemMetrics {
    // Resource utilization
    double cpu_usage_percent;
    size_t memory_usage_bytes;
    uint32_t active_connections;
    uint32_t pending_handshakes;
    
    // Performance metrics
    uint32_t connections_per_second;
    uint32_t handshakes_per_second;
    double avg_handshake_time_ms;
    double avg_throughput_mbps;
    
    // System health
    uint32_t total_errors_per_minute;
    double error_rate_percent;
    uint32_t degraded_connections;
    uint32_t failed_connections;
};

class MetricsCollector {
public:
    static MetricsCollector& instance();
    
    // Metrics collection
    void record_handshake_time(std::chrono::nanoseconds duration);
    void record_bytes_transferred(size_t bytes, bool sent);
    void record_error(ErrorCode error_code);
    void record_crypto_operation_time(std::chrono::nanoseconds duration);
    
    // Metrics retrieval
    ConnectionMetrics get_connection_metrics(const Connection& connection) const;
    SystemMetrics get_system_metrics() const;
    
    // Reporting
    std::string generate_metrics_report() const;
    Result<void> export_metrics_to_file(const std::string& filepath) const;
    
    // Configuration
    void set_collection_interval(std::chrono::seconds interval);
    void enable_detailed_metrics(bool enable);
    void reset_all_metrics();
    
private:
    MetricsCollector() = default;
};

}
```

## Security Features

### DoS Protection

```cpp
namespace dtls::v13::security {

class DoSProtection {
public:
    struct DoSConfig {
        // Rate limiting
        uint32_t max_connections_per_ip = 100;
        uint32_t max_handshakes_per_second = 1000;
        uint32_t max_requests_per_minute = 60000;
        
        // Resource limits
        size_t max_memory_per_connection = 65536;
        size_t max_total_memory = 100 * 1024 * 1024;  // 100MB
        uint32_t max_concurrent_handshakes = 10000;
        
        // Cookie verification
        bool enable_cookie_verification = true;
        std::chrono::seconds cookie_lifetime{300};
        size_t cookie_key_rotation_interval = 3600;
        
        // Timeout protection
        std::chrono::seconds connection_timeout{300};
        std::chrono::seconds handshake_timeout{30};
        std::chrono::seconds idle_timeout{900};
    };
    
    explicit DoSProtection(const DoSConfig& config);
    
    // Request validation
    Result<bool> should_accept_connection(const NetworkAddress& client_addr);
    Result<bool> validate_handshake_rate(const NetworkAddress& client_addr);
    Result<bool> check_resource_limits() const;
    
    // Cookie verification
    Result<std::vector<uint8_t>> generate_cookie(
        const NetworkAddress& client_addr,
        const std::vector<uint8_t>& client_hello
    );
    
    Result<bool> verify_cookie(
        const NetworkAddress& client_addr,
        const std::vector<uint8_t>& client_hello,
        const std::vector<uint8_t>& cookie
    );
    
    // Statistics
    struct DoSStats {
        uint64_t total_connections_blocked;
        uint64_t rate_limited_requests;
        uint64_t cookie_verification_failures;
        uint64_t resource_limit_violations;
        uint32_t currently_blocked_ips;
    };
    
    DoSStats get_statistics() const;
    void reset_statistics();
    
private:
    DoSConfig config_;
};

}
```

## Examples

### Complete Client Example

```cpp
#include <dtls/dtls.h>
#include <iostream>
#include <vector>

int main() {
    using namespace dtls::v13;
    
    try {
        // Initialize crypto provider
        auto& factory = crypto::ProviderFactory::instance();
        auto crypto_result = factory.create_provider("openssl");
        if (!crypto_result) {
            std::cerr << "Failed to create crypto provider: " 
                      << crypto_result.error().message() << std::endl;
            return 1;
        }
        
        // Configure connection
        auto config = ConnectionConfig::default_client_config();
        config.enable_early_data = true;
        config.handshake_timeout = std::chrono::seconds(10);
        
        // Create connection
        auto server_addr = NetworkAddress::from_string("example.com:4433");
        if (!server_addr) {
            std::cerr << "Invalid server address" << std::endl;
            return 1;
        }
        
        auto conn_result = Connection::create_client(
            *server_addr, config, std::move(*crypto_result)
        );
        
        if (!conn_result) {
            std::cerr << "Failed to create connection: " 
                      << conn_result.error().message() << std::endl;
            return 1;
        }
        
        auto connection = std::move(*conn_result);
        
        // Set up event handling
        connection->set_event_callback([](ConnectionEvent event, const Connection& conn) {
            switch (event) {
                case ConnectionEvent::HANDSHAKE_COMPLETED:
                    std::cout << "Handshake completed successfully!" << std::endl;
                    std::cout << "Cipher suite: " 
                              << static_cast<int>(conn.get_negotiated_cipher_suite()) 
                              << std::endl;
                    break;
                
                case ConnectionEvent::DATA_RECEIVED:
                    std::cout << "Data received from server" << std::endl;
                    break;
                
                case ConnectionEvent::ERROR_OCCURRED:
                    std::cerr << "Connection error occurred" << std::endl;
                    break;
                    
                default:
                    break;
            }
        });
        
        // Perform handshake
        auto handshake_result = connection->handshake();
        if (!handshake_result) {
            std::cerr << "Handshake failed: " 
                      << handshake_result.error().message() << std::endl;
            return 1;
        }
        
        // Send HTTP request
        std::string http_request = 
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n"
            "\r\n";
        
        std::vector<uint8_t> request_data(http_request.begin(), http_request.end());
        auto send_result = connection->send(request_data);
        if (!send_result) {
            std::cerr << "Failed to send data: " 
                      << send_result.error().message() << std::endl;
            return 1;
        }
        
        std::cout << "Sent " << *send_result << " bytes" << std::endl;
        
        // Receive response
        auto response_result = connection->receive();
        if (!response_result) {
            std::cerr << "Failed to receive data: " 
                      << response_result.error().message() << std::endl;
            return 1;
        }
        
        std::cout << "Received " << response_result->size() << " bytes" << std::endl;
        std::string response(response_result->begin(), response_result->end());
        std::cout << "Response: " << response << std::endl;
        
        // Print connection statistics
        const auto& stats = connection->get_statistics();
        std::cout << "Connection Statistics:" << std::endl;
        std::cout << "  Handshake duration: " 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(
                      stats.handshake_duration).count() << "ms" << std::endl;
        std::cout << "  Bytes sent: " << stats.bytes_sent << std::endl;
        std::cout << "  Bytes received: " << stats.bytes_received << std::endl;
        std::cout << "  Records sent: " << stats.records_sent << std::endl;
        std::cout << "  Records received: " << stats.records_received << std::endl;
        
        // Close connection gracefully
        auto close_result = connection->close();
        if (!close_result) {
            std::cerr << "Failed to close connection properly" << std::endl;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
}
```

### Complete Server Example

```cpp
#include <dtls/dtls.h>
#include <iostream>
#include <thread>
#include <signal.h>

std::atomic<bool> g_running{true};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_running = false;
    }
}

class EchoServer {
private:
    std::unique_ptr<dtls::v13::ConnectionManager> manager_;
    std::vector<std::shared_ptr<dtls::v13::Connection>> active_connections_;
    std::mutex connections_mutex_;
    
public:
    bool start(const std::string& bind_address) {
        using namespace dtls::v13;
        
        // Configure server
        auto config = ConnectionConfig::default_server_config();
        config.max_early_data_size = 16384;
        config.enable_connection_id = true;
        config.connection_id_length = 8;
        
        // Create connection manager
        auto manager_result = ConnectionManager::create(config);
        if (!manager_result) {
            std::cerr << "Failed to create connection manager: " 
                      << manager_result.error().message() << std::endl;
            return false;
        }
        
        manager_ = std::move(*manager_result);
        
        // Set up event callbacks
        manager_->set_event_callback([this](ConnectionEvent event, const Connection& conn) {
            this->handle_connection_event(event, conn);
        });
        
        manager_->set_new_connection_callback([this](std::shared_ptr<Connection> conn) {
            this->handle_new_connection(std::move(conn));
        });
        
        // Bind to address
        auto addr_result = NetworkAddress::from_string(bind_address);
        if (!addr_result) {
            std::cerr << "Invalid bind address: " << bind_address << std::endl;
            return false;
        }
        
        auto bind_result = manager_->bind(*addr_result);
        if (!bind_result) {
            std::cerr << "Failed to bind to " << bind_address << ": " 
                      << bind_result.error().message() << std::endl;
            return false;
        }
        
        std::cout << "DTLS server listening on " << bind_address << std::endl;
        
        // Start server loop
        manager_->run();
        return true;
    }
    
    void stop() {
        if (manager_) {
            manager_->stop();
        }
        
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& conn : active_connections_) {
            conn->close();
        }
        active_connections_.clear();
    }
    
private:
    void handle_connection_event(dtls::v13::ConnectionEvent event, 
                                 const dtls::v13::Connection& conn) {
        using namespace dtls::v13;
        
        switch (event) {
            case ConnectionEvent::HANDSHAKE_COMPLETED:
                std::cout << "Client handshake completed" << std::endl;
                break;
                
            case ConnectionEvent::DATA_RECEIVED: {
                // Echo received data back to client
                auto data_result = const_cast<Connection&>(conn).receive();
                if (data_result) {
                    std::cout << "Received " << data_result->size() 
                              << " bytes from client" << std::endl;
                    
                    // Echo the data back
                    auto send_result = const_cast<Connection&>(conn).send(*data_result);
                    if (!send_result) {
                        std::cerr << "Failed to echo data: " 
                                  << send_result.error().message() << std::endl;
                    } else {
                        std::cout << "Echoed " << *send_result << " bytes back" << std::endl;
                    }
                }
                break;
            }
            
            case ConnectionEvent::CONNECTION_CLOSED:
                std::cout << "Client disconnected" << std::endl;
                remove_connection(conn);
                break;
                
            case ConnectionEvent::ERROR_OCCURRED:
                std::cerr << "Connection error occurred" << std::endl;
                remove_connection(conn);
                break;
                
            case ConnectionEvent::EARLY_DATA_RECEIVED:
                std::cout << "Early data received from client" << std::endl;
                break;
                
            default:
                break;
        }
    }
    
    void handle_new_connection(std::shared_ptr<dtls::v13::Connection> conn) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        active_connections_.push_back(std::move(conn));
        
        std::cout << "New client connected. Total connections: " 
                  << active_connections_.size() << std::endl;
    }
    
    void remove_connection(const dtls::v13::Connection& conn) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        active_connections_.erase(
            std::remove_if(active_connections_.begin(), active_connections_.end(),
                [&conn](const std::weak_ptr<dtls::v13::Connection>& weak_conn) {
                    auto shared_conn = weak_conn.lock();
                    return !shared_conn || shared_conn.get() == &conn;
                }),
            active_connections_.end()
        );
    }
};

int main(int argc, char* argv[]) {
    // Set up signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::string bind_address = "0.0.0.0:4433";
    if (argc > 1) {
        bind_address = argv[1];
    }
    
    EchoServer server;
    
    if (!server.start(bind_address)) {
        return 1;
    }
    
    // Wait for shutdown signal
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "Shutting down server..." << std::endl;
    server.stop();
    
    return 0;
}
```

### Early Data (0-RTT) Example

```cpp
#include <dtls/dtls.h>
#include <iostream>

int main() {
    using namespace dtls::v13;
    
    // Configure client with early data support
    auto config = ConnectionConfig::default_client_config();
    config.enable_early_data = true;
    config.max_early_data_size = 16384;
    
    auto crypto_result = crypto::ProviderFactory::instance().create_provider("openssl");
    auto addr_result = NetworkAddress::from_string("example.com:4433");
    
    auto conn_result = Connection::create_client(
        *addr_result, config, std::move(*crypto_result)
    );
    
    auto connection = std::move(*conn_result);
    
    // For 0-RTT, we need a previously established session
    // In practice, this would be loaded from storage
    std::vector<uint8_t> session_ticket = load_previous_session_ticket();
    
    if (!session_ticket.empty()) {
        // Import previous session for resumption
        auto handshake_mgr = HandshakeManager::create_client(config, 
                                crypto::ProviderFactory::instance().create_provider("openssl").value());
        auto import_result = handshake_mgr->import_session_ticket(session_ticket);
        
        if (import_result) {
            // Send early data before completing handshake
            std::string early_data = "GET /early HTTP/1.1\r\nHost: example.com\r\n\r\n";
            std::vector<uint8_t> early_data_bytes(early_data.begin(), early_data.end());
            
            auto early_send_result = connection->send_early_data(early_data_bytes);
            if (early_send_result) {
                std::cout << "Sent " << *early_send_result << " bytes as early data" << std::endl;
            }
        }
    }
    
    // Complete handshake
    auto handshake_result = connection->handshake();
    if (!handshake_result) {
        std::cerr << "Handshake failed: " << handshake_result.error().message() << std::endl;
        return 1;
    }
    
    // Check if early data was accepted
    if (connection->is_early_data_accepted()) {
        std::cout << "Early data was accepted by server!" << std::endl;
    } else {
        std::cout << "Early data was rejected, need to resend" << std::endl;
        // Resend the data in normal mode
    }
    
    return 0;
}

std::vector<uint8_t> load_previous_session_ticket() {
    // Implementation would load from persistent storage
    // Return empty vector if no previous session available
    return {};
}
```

---

## License

This API documentation is part of the DTLS v1.3 implementation project.

## Support

For questions about API usage, please refer to the examples above or consult the project documentation.