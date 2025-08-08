# DTLS v1.3 Example Applications

This directory contains example applications demonstrating DTLS v1.3 functionality.

## Basic Examples

### transport_example
Demonstrates UDP transport layer functionality without DTLS encryption.
Usage: `./transport_example`

### dtls_client_example  
Simple DTLS client with interactive and automated modes.
Usage: 
- Interactive: `./dtls_client_example --interactive`
- Automated: `./dtls_client_example`

### dtls_server_example
Simple DTLS server supporting multiple concurrent connections.
Usage: `./dtls_server_example [bind_address] [bind_port]`
Default: `./dtls_server_example 0.0.0.0 4433`

## Advanced Examples (Week 14)

### dtls_connection_migration_example
Demonstrates connection migration using Connection IDs.
- Shows seamless connection migration during address changes
- Validates Connection ID functionality
Usage: `./dtls_connection_migration_example`

### dtls_early_data_example
Demonstrates early data (0-RTT) functionality for reduced latency.
- Session resumption with Pre-Shared Keys
- 0-RTT data transmission
- Performance comparison with full handshake
Usage: `./dtls_early_data_example`

### dtls_multi_connection_server_example
High-performance server handling multiple concurrent connections.
- Multi-threaded architecture with worker threads
- Load balancing and performance monitoring
- Real-time statistics and connection management
Usage: `./dtls_multi_connection_server_example [bind_address] [bind_port] [num_workers]`
Default: `./dtls_multi_connection_server_example 0.0.0.0 4433 4`

## Build Instructions

Examples are built automatically when DTLS_BUILD_EXAMPLES=ON:

```bash
mkdir build && cd build
cmake -DDTLS_BUILD_EXAMPLES=ON ..
make
```

## Running Examples

Use the provided CMake targets:

```bash
# Basic examples
make run_basic_examples

# Client-server demo (requires coordination)
make run_dtls_server     # Terminal 1
make run_dtls_client_auto # Terminal 2

# Advanced examples  
make run_advanced_examples

# Individual examples
make run_migration_demo
make run_early_data_demo
make run_multi_server

# All examples
make run_all_examples
```

## Testing Client-Server Communication

1. Start the server:
   ```bash
   ./dtls_server_example 0.0.0.0 4433
   ```

2. In another terminal, run the client:
   ```bash
   ./dtls_client_example --interactive
   ```

3. For automated testing:
   ```bash
   ./dtls_client_example
   ```

## Performance Testing

The multi-connection server can be tested with multiple clients:

```bash
# Terminal 1: Start high-performance server
./dtls_multi_connection_server_example 0.0.0.0 4433 8

# Terminals 2-N: Start multiple clients
./dtls_client_example &
./dtls_client_example &
# ... repeat for desired load
```

## Requirements

- OpenSSL (required for cryptographic operations)
- Botan (optional, for alternative crypto provider)
- Threads (required for multi-threaded examples)
- C++20 compiler with full standard library support

All examples include comprehensive error handling and demonstrate best practices for DTLS v1.3 usage.
