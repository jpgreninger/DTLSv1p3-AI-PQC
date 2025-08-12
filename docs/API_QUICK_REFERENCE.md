# DTLS v1.3 API Quick Reference

## Essential Headers

```cpp
#include <dtls/connection.h>       // Main connection API
#include <dtls/types.h>            // Core types and enums
#include <dtls/crypto/provider_factory.h>  // Crypto provider management
#include <dtls/result.h>           // Error handling
#include <dtls/protocol.h>         // Protocol constants
#include <dtls/memory.h>           // Buffer management
```

## Quick Start Patterns

### Client Connection
```cpp
using namespace dtls::v13;

// 1. Create crypto provider
auto crypto = crypto::ProviderFactory::instance().create_provider("openssl");

// 2. Configure connection
ConnectionConfig config = ConnectionConfig::default_client_config();

// 3. Create and connect
auto conn = Connection::create_client(
    NetworkAddress::from_string("server.com:4433").value(),
    config, 
    std::move(crypto.value())
);

// 4. Handshake and communicate
conn->handshake();
conn->send({'H','e','l','l','o'});
auto response = conn->receive();
```

### Server Setup
```cpp
auto manager = ConnectionManager::create(ConnectionConfig::default_server_config());
manager->bind(NetworkAddress::from_string("0.0.0.0:4433").value());
manager->set_event_callback([](ConnectionEvent event, const Connection& conn) {
    // Handle events
});
manager->run();
```

## Core Types Reference

| Type | Description | Usage |
|------|-------------|-------|
| `Result<T>` | Error handling wrapper | `if (result) { use(*result); }` |
| `NetworkAddress` | IP address + port | `NetworkAddress::from_string("1.2.3.4:443")` |
| `ConnectionConfig` | Connection settings | `ConnectionConfig::default_client_config()` |
| `ConnectionID` | Connection identifier | `std::vector<uint8_t>` |
| `KeyMaterial` | Cryptographic keys | `std::vector<uint8_t>` |
| `Buffer` | Efficient byte buffer | `Buffer buffer(1024);` |

## Enums Quick Reference

### CipherSuite
```cpp
CipherSuite::TLS_AES_256_GCM_SHA384        // Recommended
CipherSuite::TLS_AES_128_GCM_SHA256        // Fast
CipherSuite::TLS_CHACHA20_POLY1305_SHA256  // Mobile-friendly
```

### ConnectionState
```cpp
ConnectionState::INITIAL           // Starting state
ConnectionState::CONNECTED         // Ready for data
ConnectionState::CLOSED           // Connection closed
ConnectionState::EARLY_DATA       // 0-RTT mode
```

### ConnectionEvent
```cpp
ConnectionEvent::HANDSHAKE_COMPLETED    // Ready to send data
ConnectionEvent::DATA_RECEIVED          // New data available
ConnectionEvent::CONNECTION_CLOSED      // Peer closed
ConnectionEvent::ERROR_OCCURRED         // Error occurred
```

## Error Handling Patterns

### Result Type Usage
```cpp
// Check and use
auto result = connection->send(data);
if (result) {
    std::cout << "Sent " << *result << " bytes\n";
} else {
    std::cerr << "Error: " << result.error().message() << "\n";
}

// Value or default
size_t bytes_sent = result.value_or(0);

// Chain operations
auto final_result = connection->handshake()
    .and_then([&]() { return connection->send(data); })
    .and_then([&]() { return connection->receive(); });
```

### Common Error Codes
```cpp
ErrorCode::NETWORK_ERROR          // Network issues
ErrorCode::HANDSHAKE_FAILED       // Handshake problems
ErrorCode::CRYPTO_ERROR           // Cryptographic failures
ErrorCode::PROTOCOL_ERROR         // Protocol violations
ErrorCode::OUT_OF_MEMORY          // Memory allocation failed
```

## Connection Management

### Basic Operations
```cpp
// Create connection
auto conn = Connection::create_client(address, config, crypto_provider);

// Lifecycle
conn->handshake();                 // Perform handshake
conn->send(data);                 // Send application data
auto received = conn->receive();   // Receive data
conn->close();                    // Graceful close

// State queries
bool connected = conn->is_connected();
ConnectionState state = conn->get_state();
CipherSuite suite = conn->get_negotiated_cipher_suite();
```

### Event Handling
```cpp
conn->set_event_callback([](ConnectionEvent event, const Connection& conn) {
    switch (event) {
        case ConnectionEvent::HANDSHAKE_COMPLETED:
            // Connection ready
            break;
        case ConnectionEvent::DATA_RECEIVED:
            // Process conn.receive()
            break;
        case ConnectionEvent::ERROR_OCCURRED:
            // Handle error
            break;
    }
});
```

### Configuration Options
```cpp
ConnectionConfig config;

// Crypto preferences
config.supported_cipher_suites = {
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256
};

// Timeouts
config.handshake_timeout = std::chrono::seconds(10);
config.retransmission_timeout = std::chrono::milliseconds(1000);

// Features
config.enable_connection_id = true;
config.enable_early_data = true;
config.max_early_data_size = 16384;

// Error recovery
config.error_recovery.max_retries = 3;
config.error_recovery.enable_automatic_recovery = true;
```

## Crypto Provider Management

### Factory Usage
```cpp
auto& factory = crypto::ProviderFactory::instance();

// Create default provider
auto provider = factory.create_provider();

// Create specific provider
auto openssl_provider = factory.create_provider("openssl");
auto botan_provider = factory.create_provider("botan");

// Check availability
bool available = factory.is_provider_available("openssl");

// List providers
auto providers = factory.get_available_providers();
```

### Provider Capabilities
```cpp
// Query capabilities
auto suites = provider->get_supported_cipher_suites();
auto groups = provider->get_supported_groups();
auto signatures = provider->get_supported_signatures();

// Hardware acceleration
if (provider->supports_hardware_acceleration()) {
    provider->enable_hardware_acceleration();
}
```

## Memory Management

### Buffer Operations
```cpp
// Create buffers
Buffer buffer(1024);                    // 1KB capacity
Buffer data_buffer({'H','e','l','l','o'});  // From data

// Manipulate
buffer.append(additional_data);
Buffer slice = buffer.slice(10, 100);   // Offset 10, length 100
buffer.secure_zero();                   // Secure cleanup

// Pool usage
auto& pool = BufferPool::instance();
auto pooled_buffer = pool.acquire(2048);
// ... use buffer ...
pool.release(std::move(pooled_buffer));
```

### Zero-Copy Operations
```cpp
// Efficient data handling
auto send_result = connection->send(buffer.data(), buffer.size());
auto receive_buffer = Buffer(4096);
auto bytes_received = connection->receive(receive_buffer.data(), 
                                         receive_buffer.capacity());
```

## Advanced Features

### Early Data (0-RTT)
```cpp
// Client side
if (has_previous_session) {
    conn->send_early_data(early_data);
}
conn->handshake();
if (conn->is_early_data_accepted()) {
    // Early data was processed
} else {
    // Resend as regular data
    conn->send(early_data);
}
```

### Connection ID Migration
```cpp
// Enable connection ID
config.enable_connection_id = true;
config.connection_id_length = 8;

// Migrate connection
auto new_address = NetworkAddress::from_string("10.0.0.2:5000");
conn->migrate_connection(new_address.value());
```

### Key Updates
```cpp
// Request key update for forward secrecy
conn->update_keys();

// Export keying material for other uses
auto exported = conn->export_keying_material("EXPORTER-Label", 32);
```

### Session Management
```cpp
// Server: Create session ticket
auto ticket_data = handshake_mgr->export_session_ticket();
// Store ticket_data for client

// Client: Resume session
handshake_mgr->import_session_ticket(stored_ticket_data);
```

## Performance Monitoring

### Connection Statistics
```cpp
const auto& stats = conn->get_statistics();

std::cout << "Handshake time: " 
          << std::chrono::duration_cast<std::chrono::milliseconds>(
              stats.handshake_duration).count() << "ms\n";
          
std::cout << "Throughput: " << stats.bytes_sent + stats.bytes_received 
          << " bytes\n";
          
std::cout << "Errors: " << stats.decrypt_errors + stats.protocol_errors 
          << "\n";
```

### System Metrics
```cpp
auto& metrics = monitoring::MetricsCollector::instance();

// Get system-wide metrics
auto system_stats = metrics.get_system_metrics();
std::cout << "Connections/sec: " << system_stats.connections_per_second << "\n";
std::cout << "Memory usage: " << system_stats.memory_usage_bytes << " bytes\n";

// Generate report
std::string report = metrics.generate_metrics_report();
std::cout << report << std::endl;
```

## Security Features

### DoS Protection
```cpp
security::DoSProtection::DoSConfig dos_config;
dos_config.max_connections_per_ip = 100;
dos_config.max_handshakes_per_second = 1000;
dos_config.enable_cookie_verification = true;

security::DoSProtection dos_protection(dos_config);

// In server loop
if (dos_protection.should_accept_connection(client_addr)) {
    // Accept connection
}
```

### Certificate Validation
```cpp
handshake_mgr->set_certificate_verify_callback(
    [](const std::vector<std::vector<uint8_t>>& cert_chain) -> bool {
        // Custom certificate validation logic
        return validate_certificate_chain(cert_chain);
    }
);
```

## Common Patterns

### Async Operations
```cpp
// Async handshake
conn->handshake_async([](Result<void> result) {
    if (result) {
        std::cout << "Handshake completed asynchronously\n";
    } else {
        std::cerr << "Handshake failed: " << result.error().message() << "\n";
    }
});
```

### Error Recovery
```cpp
// Configure automatic recovery
config.error_recovery.max_retries = 5;
config.error_recovery.initial_retry_delay = std::chrono::seconds(1);
config.error_recovery.backoff_multiplier = 2.0;
config.error_recovery.enable_automatic_recovery = true;

// Handle recovery events
conn->set_event_callback([](ConnectionEvent event, const Connection& conn) {
    if (event == ConnectionEvent::RECOVERY_SUCCEEDED) {
        std::cout << "Connection recovered successfully\n";
    }
});
```

### Multi-threaded Usage
```cpp
// Thread-safe operations
std::vector<std::thread> workers;
std::shared_ptr<Connection> shared_conn = std::move(conn);

for (int i = 0; i < 4; ++i) {
    workers.emplace_back([shared_conn]() {
        // Each thread can safely use the connection
        auto data = generate_data();
        shared_conn->send(data);
    });
}

for (auto& worker : workers) {
    worker.join();
}
```

## Debugging and Logging

### Debug Configuration
```cpp
config::SystemConfig system_config;
system_config.default_log_level = LogLevel::DEBUG;
system_config.enable_memory_debugging = true;
config::set_global_config(system_config);
```

### Performance Profiling
```cpp
// Enable detailed metrics
auto& metrics = monitoring::MetricsCollector::instance();
metrics.enable_detailed_metrics(true);

// Profile specific operations
auto start = std::chrono::high_resolution_clock::now();
conn->handshake();
auto duration = std::chrono::high_resolution_clock::now() - start;

metrics.record_handshake_time(
    std::chrono::duration_cast<std::chrono::nanoseconds>(duration)
);
```

## Build Integration

### CMake Integration
```cmake
find_package(DTLSv13 REQUIRED)
target_link_libraries(your_target DTLSv13::DTLSv13)
```

### Compiler Requirements
- C++20 or later
- OpenSSL 1.1.1+ or 3.0+
- CMake 3.20+

## Common Error Solutions

| Error | Likely Cause | Solution |
|-------|--------------|----------|
| `HANDSHAKE_FAILED` | Certificate issues | Check certificate chain |
| `CRYPTO_ERROR` | Provider unavailable | Install OpenSSL/Botan |
| `NETWORK_ERROR` | Connection refused | Check server address/port |
| `OUT_OF_MEMORY` | Large buffers | Configure buffer pool |
| `PROTOCOL_ERROR` | Version mismatch | Ensure DTLS v1.3 support |

## Best Practices

1. **Always check Result<T> return values**
2. **Use connection pooling for servers**
3. **Enable connection ID for NAT traversal**
4. **Configure appropriate timeouts**
5. **Use early data only with idempotent operations**
6. **Implement proper certificate validation**
7. **Monitor connection health and metrics**
8. **Handle errors gracefully with recovery**
9. **Use secure memory for sensitive data**
10. **Test with multiple crypto providers**