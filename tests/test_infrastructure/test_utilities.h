#ifndef DTLS_TEST_UTILITIES_H
#define DTLS_TEST_UTILITIES_H

#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/protocol.h>
#include <dtls/result.h>
#include "test_certificates.h"
#include "mock_transport.h"
#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <chrono>
#include <atomic>
#include <functional>

namespace dtls {
namespace test {

/**
 * Test Environment Configuration
 */
struct TestEnvironmentConfig {
    bool use_real_crypto = true;
    bool enable_certificate_validation = false;
    std::chrono::milliseconds handshake_timeout{10000};
    std::chrono::milliseconds data_timeout{5000};
    bool verbose_logging = false;
    uint16_t server_port = 4433;
    std::string server_address = "127.0.0.1";
};

/**
 * DTLS Test Environment
 * 
 * Provides a complete testing environment for DTLS integration tests
 */
class DTLSTestEnvironment {
public:
    explicit DTLSTestEnvironment(const TestEnvironmentConfig& config = TestEnvironmentConfig{});
    ~DTLSTestEnvironment();
    
    // Environment setup and teardown
    void SetUp();
    void TearDown();
    
    // Connection creation (returns raw pointers managed by internal contexts)
    v13::Connection* create_client_connection();
    v13::Connection* create_server_connection();
    
    // Transport management
    void set_network_conditions(const MockTransport::NetworkConditions& conditions);
    void enable_packet_interception(bool enable);
    
    // Test execution helpers
    bool perform_handshake(v13::Connection* client, v13::Connection* server);
    bool transfer_data(v13::Connection* sender, v13::Connection* receiver, 
                      const std::vector<uint8_t>& data);
    bool verify_connection_security(v13::Connection* connection);
    
    // Statistics and monitoring
    struct TestStatistics {
        std::atomic<uint32_t> handshakes_completed{0};
        std::atomic<uint32_t> handshakes_failed{0};
        std::atomic<uint64_t> bytes_transferred{0};
        std::atomic<uint32_t> errors_encountered{0};
        std::atomic<uint32_t> packets_sent{0};
        std::atomic<uint32_t> packets_received{0};
    };
    
    TestStatistics& get_statistics() { return stats_; }
    void reset_statistics();
    
    // Error injection and testing
    void inject_transport_error(bool enable);
    void simulate_network_failure(std::chrono::milliseconds duration);
    void simulate_packet_loss(double rate);
    
private:
    TestEnvironmentConfig config_;
    TestCertificates::CertificateFiles cert_files_;
    
    // Contexts and crypto providers
    std::unique_ptr<v13::Context> client_context_;
    std::unique_ptr<v13::Context> server_context_;
    std::unique_ptr<v13::crypto::CryptoProvider> crypto_provider_;
    
    // Transport layer
    std::unique_ptr<MockTransport> client_transport_;
    std::unique_ptr<MockTransport> server_transport_;
    
    // Statistics
    TestStatistics stats_;
    
    // State
    bool setup_completed_ = false;
    
    // Helper methods
    void setup_crypto_providers();
    void setup_certificates();
    void setup_transport_layer();
    void configure_connection_callbacks(v13::Connection* connection, bool is_client);
};

/**
 * Data Generation Utilities
 */
class TestDataGenerator {
public:
    // Generate test data patterns
    static std::vector<uint8_t> generate_sequential_data(size_t size);
    static std::vector<uint8_t> generate_random_data(size_t size);
    static std::vector<uint8_t> generate_pattern_data(size_t size, uint8_t pattern);
    
    // Generate realistic DTLS test scenarios
    static std::vector<uint8_t> generate_handshake_message(uint8_t msg_type, size_t size);
    static std::vector<uint8_t> generate_application_data(size_t size);
    static std::vector<uint8_t> generate_large_payload(size_t size); // For fragmentation testing
    
    // Protocol-specific data
    static std::vector<uint8_t> generate_client_hello();
    static std::vector<uint8_t> generate_server_hello();
    static std::vector<uint8_t> generate_certificate_message();
    static std::vector<uint8_t> generate_finished_message();
};

/**
 * Test Validators and Assertions  
 */
class DTLSTestValidators {
public:
    // Connection state validation
    static void validate_connection_established(v13::Connection* connection);
    static void validate_connection_secure(v13::Connection* connection);
    static void validate_connection_encrypted(v13::Connection* connection);
    
    // Protocol validation
    static void validate_cipher_suite_negotiation(v13::Connection* client, v13::Connection* server);
    static void validate_key_material(v13::Connection* connection);
    static void validate_security_parameters(v13::Connection* connection);
    
    // Data integrity validation
    static void validate_data_integrity(const std::vector<uint8_t>& sent, 
                                       const std::vector<uint8_t>& received);
    static void validate_message_authentication(v13::Connection* connection);
    
    // Performance validation
    static void validate_handshake_performance(std::chrono::milliseconds duration);
    static void validate_throughput_performance(size_t bytes, std::chrono::milliseconds duration);
    static void validate_latency_performance(std::chrono::microseconds latency);
};

/**
 * Concurrent Test Utilities
 */
class ConcurrentTestRunner {
public:
    using TestFunction = std::function<bool()>;
    
    // Run multiple tests concurrently
    static bool run_concurrent_tests(const std::vector<TestFunction>& tests, 
                                   size_t max_threads = std::thread::hardware_concurrency());
    
    // Stress testing utilities
    static bool run_stress_test(TestFunction test, size_t iterations, 
                              std::chrono::milliseconds duration);
    
    // Load testing utilities  
    static bool run_load_test(TestFunction test, size_t concurrent_instances, 
                            size_t total_operations);
};

/**
 * Error Simulation Utilities
 */
class ErrorSimulator {
public:
    enum class ErrorType {
        NETWORK_TIMEOUT,
        PACKET_CORRUPTION,
        CRYPTO_FAILURE,
        MEMORY_EXHAUSTION,
        PROTOCOL_VIOLATION,
        CERTIFICATE_ERROR
    };
    
    // Error injection
    static void inject_error(ErrorType type, double probability = 1.0);
    static void clear_error_injection();
    
    // Network error simulation
    static void simulate_network_partition(std::chrono::milliseconds duration);
    static void simulate_high_latency(std::chrono::milliseconds latency);
    static void simulate_bandwidth_limitation(uint32_t kbps);
    
    // Protocol error simulation
    static void simulate_malformed_packet();
    static void simulate_replay_attack();
    static void simulate_man_in_the_middle();
};

/**
 * Performance Measurement Utilities
 */
class PerformanceMeasurement {
public:
    struct Metrics {
        std::chrono::microseconds handshake_time{0};
        std::chrono::microseconds data_transfer_time{0};
        double throughput_mbps = 0.0;
        double latency_ms = 0.0;
        size_t memory_usage_bytes = 0;
        double cpu_usage_percent = 0.0;
    };
    
    // Measurement utilities
    static Metrics measure_handshake_performance(std::function<bool()> handshake_func);
    static Metrics measure_throughput(std::function<bool()> transfer_func, size_t bytes);
    static Metrics measure_latency(std::function<bool()> operation_func);
    
    // Resource monitoring
    static size_t get_memory_usage();
    static double get_cpu_usage();
    
    // Benchmark comparison
    static bool compare_performance(const Metrics& measured, const Metrics& baseline, 
                                  double tolerance = 0.1);
};

/**
 * Test Macros for common DTLS test patterns
 */
#define EXPECT_DTLS_OK(result) \
    EXPECT_TRUE((result).is_ok()) << "DTLS error: " << (result).error_message()

#define ASSERT_DTLS_OK(result) \
    ASSERT_TRUE((result).is_ok()) << "DTLS error: " << (result).error_message()

#define EXPECT_HANDSHAKE_SUCCESS(client, server) \
    EXPECT_TRUE(DTLSTestEnvironment::perform_handshake((client), (server))) \
    << "Handshake failed between client and server"

#define EXPECT_DATA_TRANSFER_SUCCESS(sender, receiver, data) \
    EXPECT_TRUE(DTLSTestEnvironment::transfer_data((sender), (receiver), (data))) \
    << "Data transfer failed"

#define EXPECT_CONNECTION_SECURE(connection) \
    DTLSTestValidators::validate_connection_secure((connection))

} // namespace test
} // namespace dtls

#endif // DTLS_TEST_UTILITIES_H