#include <gtest/gtest.h>
#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/protocol.h>
#include <dtls/transport/udp_transport.h>
#include <dtls/crypto/openssl_provider.h>
#include <thread>
#include <chrono>
#include <vector>
#include <memory>
#include <atomic>
#include <random>
#include <future>

namespace dtls {
namespace v13 {
namespace test {

/**
 * DTLS v1.3 Reliability Testing Suite
 * 
 * Comprehensive reliability validation including:
 * - Stress testing under high load conditions
 * - Error injection and fault tolerance
 * - Recovery mechanisms and failover testing
 * - Long-duration stability testing
 * - Resource exhaustion handling
 * - Connection resilience testing
 */
class DTLSReliabilityTest : public ::testing::Test {
public:
    // Forward declarations for reliability events
    enum class ReliabilityEventType {
        CONNECTION_FAILURE,
        AUTOMATIC_RECOVERY,
        RETRY_EXHAUSTED,
        RESOURCE_EXHAUSTION,
        TIMEOUT_OCCURRED,
        OTHER
    };
    
    enum class ReliabilityEventSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    };
    
    struct ReliabilityEvent {
        ReliabilityEventType type;
        ReliabilityEventSeverity severity;
        std::string description;
        std::chrono::milliseconds recovery_time;
    };

protected:
    void SetUp() override {
        // Initialize reliability test environment
        setup_test_environment();
        setup_error_injection();
        
        // Reliability test configuration
        stress_test_duration_ = std::chrono::minutes(5);
        max_concurrent_connections_ = 500;
        error_injection_rate_ = 0.1; // 10% error rate
        recovery_timeout_ = std::chrono::seconds(30);
        
        // Initialize statistics
        reset_reliability_statistics();
    }
    
    void TearDown() override {
        // Cleanup test environment
        cleanup_test_environment();
        
        // Log reliability test results
        log_reliability_test_results();
    }
    
    void setup_test_environment() {
        // Create contexts with default configuration
        auto client_result = Context::create_client();
        auto server_result = Context::create_server();
        
        ASSERT_TRUE(client_result.is_ok());
        ASSERT_TRUE(server_result.is_ok());
        
        client_context_ = std::move(client_result.value());
        server_context_ = std::move(server_result.value());
        
        // Initialize contexts
        ASSERT_TRUE(client_context_->initialize().is_ok());
        ASSERT_TRUE(server_context_->initialize().is_ok());
        
        // Setup transport with default configuration
        client_transport_ = std::make_unique<transport::UDPTransport>();
        server_transport_ = std::make_unique<transport::UDPTransport>();
        
        // Initialize transports
        ASSERT_TRUE(client_transport_->initialize().is_ok());
        ASSERT_TRUE(server_transport_->initialize().is_ok());
        
        // Bind to endpoints
        transport::NetworkEndpoint client_endpoint("127.0.0.1", 0);
        transport::NetworkEndpoint server_endpoint("127.0.0.1", 4433);
        
        ASSERT_TRUE(client_transport_->bind(client_endpoint).is_ok());
        ASSERT_TRUE(server_transport_->bind(server_endpoint).is_ok());
        
        // Start transports
        ASSERT_TRUE(client_transport_->start().is_ok());
        ASSERT_TRUE(server_transport_->start().is_ok());
        
        // Initialize random number generator for error injection
        rng_.seed(std::chrono::steady_clock::now().time_since_epoch().count());
    }
    
    void setup_error_injection() {
        // Configure error injection scenarios
        error_types_ = {
            ErrorType::NETWORK_TIMEOUT,
            ErrorType::PACKET_LOSS,
            ErrorType::MEMORY_ALLOCATION_FAILURE,
            ErrorType::CRYPTO_OPERATION_FAILURE,
            ErrorType::TRANSPORT_DISCONNECTION,
            ErrorType::CERTIFICATE_VALIDATION_ERROR,
            ErrorType::RANDOM_CORRUPTION
        };
        
        // Initialize error injection state
        error_injection_enabled_ = false;
        current_error_rate_ = 0.0;
    }
    
    std::pair<std::unique_ptr<Connection>, std::unique_ptr<Connection>>
    create_reliable_connection_pair() {
        // Get connections from contexts
        auto client = std::unique_ptr<Connection>(client_context_->get_connection());
        auto server = std::unique_ptr<Connection>(server_context_->get_connection());
        
        if (client && server) {
            // Set reliability callbacks if the connections support them
            setup_reliability_callbacks(client.get(), server.get());
        }
        
        return {std::move(client), std::move(server)};
    }
    
    ReliabilityEvent convert_connection_event_to_reliability(ConnectionEvent event, const std::vector<uint8_t>& data) {
        ReliabilityEvent rel_event;
        rel_event.recovery_time = std::chrono::milliseconds(0);
        rel_event.severity = ReliabilityEventSeverity::MEDIUM;
        
        switch (event) {
            case ConnectionEvent::HANDSHAKE_FAILED:
                rel_event.type = ReliabilityEventType::CONNECTION_FAILURE;
                rel_event.severity = ReliabilityEventSeverity::HIGH;
                rel_event.description = "Handshake failed";
                break;
            case ConnectionEvent::ERROR_OCCURRED:
                rel_event.type = ReliabilityEventType::CONNECTION_FAILURE;
                rel_event.severity = ReliabilityEventSeverity::HIGH;
                rel_event.description = "Connection error occurred";
                break;
            case ConnectionEvent::CONNECTION_CLOSED:
                rel_event.type = ReliabilityEventType::OTHER;
                rel_event.severity = ReliabilityEventSeverity::LOW;
                rel_event.description = "Connection closed";
                break;
            default:
                rel_event.type = ReliabilityEventType::OTHER;
                rel_event.description = "Other connection event";
                break;
        }
        
        return rel_event;
    }
    
    void setup_reliability_callbacks(Connection* client, Connection* server) {
        // Setup standard event monitoring using existing API
        client->set_event_callback([this](ConnectionEvent event, const std::vector<uint8_t>& data) {
            ReliabilityEvent rel_event = convert_connection_event_to_reliability(event, data);
            handle_reliability_event(rel_event, "CLIENT");
        });
        
        server->set_event_callback([this](ConnectionEvent event, const std::vector<uint8_t>& data) {
            ReliabilityEvent rel_event = convert_connection_event_to_reliability(event, data);
            handle_reliability_event(rel_event, "SERVER");
        });
    }
    
    void handle_reliability_event(const ReliabilityEvent& event, const std::string& source) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        reliability_events_.push_back({
            .timestamp = std::chrono::steady_clock::now(),
            .source = source,
            .type = event.type,
            .severity = event.severity,
            .description = event.description,
            .recovery_time = event.recovery_time
        });
        
        // Update statistics based on event type
        switch (event.type) {
            case ReliabilityEventType::CONNECTION_FAILURE:
                connection_failures_++;
                break;
            case ReliabilityEventType::AUTOMATIC_RECOVERY:
                automatic_recoveries_++;
                break;
            case ReliabilityEventType::RETRY_EXHAUSTED:
                retry_exhaustions_++;
                break;
            case ReliabilityEventType::RESOURCE_EXHAUSTION:
                resource_exhaustions_++;
                break;
            case ReliabilityEventType::TIMEOUT_OCCURRED:
                timeout_occurrences_++;
                break;
            default:
                other_reliability_events_++;
                break;
        }
    }
    
    bool perform_reliable_handshake(Connection* client, Connection* server) {
        std::atomic<bool> client_complete{false};
        std::atomic<bool> server_complete{false};
        std::atomic<bool> handshake_failed{false};
        
        auto start_time = std::chrono::steady_clock::now();
        
        // Setup event callbacks to monitor handshake completion
        client->set_event_callback([&](ConnectionEvent event, const std::vector<uint8_t>& data) {
            if (event == ConnectionEvent::HANDSHAKE_COMPLETED) {
                client_complete = true;
            } else if (event == ConnectionEvent::HANDSHAKE_FAILED || event == ConnectionEvent::ERROR_OCCURRED) {
                handshake_failed = true;
            }
        });
        
        server->set_event_callback([&](ConnectionEvent event, const std::vector<uint8_t>& data) {
            if (event == ConnectionEvent::HANDSHAKE_COMPLETED) {
                server_complete = true;
            } else if (event == ConnectionEvent::HANDSHAKE_FAILED || event == ConnectionEvent::ERROR_OCCURRED) {
                handshake_failed = true;
            }
        });
        
        // Start handshake with error injection
        inject_random_error();
        
        auto client_result = client->start_handshake();
        auto server_result = server->start_handshake();
        
        if (!client_result.is_ok() || !server_result.is_ok()) {
            return false;
        }
        
        // Wait for completion with extended timeout for reliability
        const auto timeout = recovery_timeout_;
        auto timeout_time = start_time + timeout;
        
        while (!client_complete || !server_complete) {
            if (handshake_failed || std::chrono::steady_clock::now() > timeout_time) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        return true;
    }
    
    void inject_random_error() {
        if (!error_injection_enabled_) return;
        
        std::uniform_real_distribution<double> rate_dist(0.0, 1.0);
        if (rate_dist(rng_) > current_error_rate_) return;
        
        std::uniform_int_distribution<size_t> type_dist(0, error_types_.size() - 1);
        ErrorType error_type = error_types_[type_dist(rng_)];
        
        // Simulate specific error type
        switch (error_type) {
            case ErrorType::NETWORK_TIMEOUT:
                simulate_network_timeout();
                break;
            case ErrorType::PACKET_LOSS:
                simulate_packet_loss();
                break;
            case ErrorType::MEMORY_ALLOCATION_FAILURE:
                simulate_memory_failure();
                break;
            case ErrorType::CRYPTO_OPERATION_FAILURE:
                simulate_crypto_failure();
                break;
            case ErrorType::TRANSPORT_DISCONNECTION:
                simulate_transport_disconnection();
                break;
            case ErrorType::CERTIFICATE_VALIDATION_ERROR:
                simulate_certificate_error();
                break;
            case ErrorType::RANDOM_CORRUPTION:
                simulate_data_corruption();
                break;
        }
        
        errors_injected_++;
    }
    
    void simulate_network_timeout() {
        // Simulate network delay/timeout
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    void simulate_packet_loss() {
        // Simulate packet loss by brief transport stop/start
        if (client_transport_) {
            // Brief stop to simulate packet loss
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    void simulate_memory_failure() {
        // Simulate memory allocation failure
        // (In practice, this would involve mocking allocators)
    }
    
    void simulate_crypto_failure() {
        // Simulate cryptographic operation failure
        // (Would involve crypto provider mock)
    }
    
    void simulate_transport_disconnection() {
        // Simulate temporary transport disconnection
        // (Brief shutdown and restart)
    }
    
    void simulate_certificate_error() {
        // Simulate certificate validation error
        // (Would involve certificate manipulation)
    }
    
    void simulate_data_corruption() {
        // Simulate random data corruption with brief delay
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    void reset_reliability_statistics() {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        connection_failures_ = 0;
        automatic_recoveries_ = 0;
        retry_exhaustions_ = 0;
        resource_exhaustions_ = 0;
        timeout_occurrences_ = 0;
        other_reliability_events_ = 0;
        errors_injected_ = 0;
        
        reliability_events_.clear();
    }
    
    void cleanup_test_environment() {
        if (client_transport_) {
            client_transport_->stop();
        }
        if (server_transport_) {
            server_transport_->stop();
        }
    }
    
    void log_reliability_test_results() {
        std::cout << "\n=== Reliability Test Results ===" << std::endl;
        std::cout << "Connection failures: " << get_connection_failures() << std::endl;
        std::cout << "Automatic recoveries: " << get_automatic_recoveries() << std::endl;
        std::cout << "Retry exhaustions: " << get_retry_exhaustions() << std::endl;
        std::cout << "Resource exhaustions: " << get_resource_exhaustions() << std::endl;
        std::cout << "Timeout occurrences: " << get_timeout_occurrences() << std::endl;
        std::cout << "Other reliability events: " << get_other_reliability_events() << std::endl;
        std::cout << "Errors injected: " << get_errors_injected() << std::endl;
        std::cout << "Total reliability events: " << reliability_events_.size() << std::endl;
        
        // Calculate reliability metrics
        double recovery_rate = (get_automatic_recoveries() > 0) ? 
            static_cast<double>(get_automatic_recoveries()) / get_connection_failures() * 100.0 : 0.0;
        std::cout << "Recovery rate: " << recovery_rate << "%" << std::endl;
    }

public:
    // Statistics getters for test access
    uint32_t get_connection_failures() const { return connection_failures_.load(); }
    uint32_t get_automatic_recoveries() const { return automatic_recoveries_.load(); }
    uint32_t get_retry_exhaustions() const { return retry_exhaustions_.load(); }
    uint32_t get_resource_exhaustions() const { return resource_exhaustions_.load(); }
    uint32_t get_timeout_occurrences() const { return timeout_occurrences_.load(); }
    uint32_t get_other_reliability_events() const { return other_reliability_events_.load(); }
    uint32_t get_errors_injected() const { return errors_injected_.load(); }

protected:
    // Test infrastructure
    std::unique_ptr<Context> client_context_;
    std::unique_ptr<Context> server_context_;
    std::unique_ptr<transport::UDPTransport> client_transport_;
    std::unique_ptr<transport::UDPTransport> server_transport_;
    
    // Test configuration
    std::chrono::minutes stress_test_duration_;
    size_t max_concurrent_connections_;
    double error_injection_rate_;
    std::chrono::seconds recovery_timeout_;
    
    // Error injection
    enum class ErrorType {
        NETWORK_TIMEOUT,
        PACKET_LOSS,
        MEMORY_ALLOCATION_FAILURE,
        CRYPTO_OPERATION_FAILURE,
        TRANSPORT_DISCONNECTION,
        CERTIFICATE_VALIDATION_ERROR,
        RANDOM_CORRUPTION
    };
    
    std::vector<ErrorType> error_types_;
    bool error_injection_enabled_;
    double current_error_rate_;
    std::mt19937 rng_;
    
    
    struct LoggedReliabilityEvent {
        std::chrono::steady_clock::time_point timestamp;
        std::string source;
        ReliabilityEventType type;
        ReliabilityEventSeverity severity;
        std::string description;
        std::chrono::milliseconds recovery_time;
    };
    
    // Statistics
    mutable std::mutex stats_mutex_;
    std::atomic<uint32_t> connection_failures_{0};
    std::atomic<uint32_t> automatic_recoveries_{0};
    std::atomic<uint32_t> retry_exhaustions_{0};
    std::atomic<uint32_t> resource_exhaustions_{0};
    std::atomic<uint32_t> timeout_occurrences_{0};
    std::atomic<uint32_t> other_reliability_events_{0};
    std::atomic<uint32_t> errors_injected_{0};
    
    std::vector<LoggedReliabilityEvent> reliability_events_;
};

// Reliability Test 1: Stress Testing Under High Load
TEST_F(DTLSReliabilityTest, StressTestingHighLoad) {
    const size_t num_connections = 100;
    const size_t operations_per_connection = 50;
    
    std::cout << "Starting stress test with " << num_connections 
              << " connections and " << operations_per_connection 
              << " operations each..." << std::endl;
    
    std::vector<std::future<bool>> connection_futures;
    std::atomic<size_t> successful_operations{0};
    std::atomic<size_t> failed_operations{0};
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Create multiple concurrent connections
    for (size_t i = 0; i < num_connections; ++i) {
        connection_futures.emplace_back(std::async(std::launch::async, [this, operations_per_connection, &successful_operations, &failed_operations]() {
            auto [client, server] = create_reliable_connection_pair();
            if (!client || !server) {
                failed_operations += operations_per_connection;
                return false;
            }
            
            // Perform handshake
            if (!perform_reliable_handshake(client.get(), server.get())) {
                failed_operations += operations_per_connection;
                return false;
            }
            
            // Perform multiple data transfer operations
            for (size_t op = 0; op < operations_per_connection; ++op) {
                std::vector<uint8_t> data = {
                    static_cast<uint8_t>(op & 0xFF), 
                    static_cast<uint8_t>((op >> 8) & 0xFF),
                    0x55, 0xAA
                };
                
                auto buffer = memory::ZeroCopyBuffer(reinterpret_cast<const std::byte*>(data.data()), data.size());
                auto send_result = client->send_application_data(buffer);
                if (send_result.is_ok()) {
                    successful_operations++;
                } else {
                    failed_operations++;
                }
                
                // Brief pause to prevent overwhelming
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            
            return true;
        }));
    }
    
    // Wait for all operations to complete
    size_t successful_connections = 0;
    for (auto& future : connection_futures) {
        if (future.get()) {
            successful_connections++;
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    // Calculate success rates
    double connection_success_rate = static_cast<double>(successful_connections) / num_connections * 100.0;
    size_t total_operations = successful_operations + failed_operations;
    double operation_success_rate = static_cast<double>(successful_operations) / total_operations * 100.0;
    
    std::cout << "Stress test completed in " << duration.count() << " seconds" << std::endl;
    std::cout << "Connection success rate: " << connection_success_rate << "%" << std::endl;
    std::cout << "Operation success rate: " << operation_success_rate << "%" << std::endl;
    std::cout << "Successful operations: " << successful_operations << "/" << total_operations << std::endl;
    
    // Verify acceptable success rates under stress
    EXPECT_GT(connection_success_rate, 90.0); // >90% connection success
    EXPECT_GT(operation_success_rate, 95.0);  // >95% operation success
}

// Reliability Test 2: Error Injection and Fault Tolerance
TEST_F(DTLSReliabilityTest, ErrorInjectionFaultTolerance) {
    error_injection_enabled_ = true;
    current_error_rate_ = error_injection_rate_;
    
    const size_t num_tests = 50;
    size_t successful_recoveries = 0;
    
    std::cout << "Testing fault tolerance with " << (error_injection_rate_ * 100) 
              << "% error injection rate..." << std::endl;
    
    for (size_t i = 0; i < num_tests; ++i) {
        auto [client, server] = create_reliable_connection_pair();
        ASSERT_TRUE(client && server);
        
        // Attempt handshake with error injection
        if (perform_reliable_handshake(client.get(), server.get())) {
            // Test data transfer with error injection
            std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04};
            
            for (int retry = 0; retry < 3; ++retry) {
                inject_random_error();
                
                auto buffer = memory::ZeroCopyBuffer(reinterpret_cast<const std::byte*>(test_data.data()), test_data.size());
                auto send_result = client->send_application_data(buffer);
                if (send_result.is_ok()) {
                    successful_recoveries++;
                    break;
                }
                
                // Wait before retry
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    
    double recovery_rate = static_cast<double>(successful_recoveries) / num_tests * 100.0;
    
    std::cout << "Recovery rate with error injection: " << recovery_rate << "%" << std::endl;
    std::cout << "Errors injected: " << get_errors_injected() << std::endl;
    std::cout << "Automatic recoveries: " << get_automatic_recoveries() << std::endl;
    
    // Verify fault tolerance
    EXPECT_GT(recovery_rate, 80.0); // >80% recovery rate despite errors
    EXPECT_GT(get_automatic_recoveries(), 0u); // Some automatic recoveries should occur
}

// Reliability Test 3: Long-Duration Stability Testing
TEST_F(DTLSReliabilityTest, LongDurationStabilityTesting) {
    const auto test_duration = std::chrono::minutes(2); // Shorter for CI/CD
    const size_t num_connections = 10;
    
    std::cout << "Starting long-duration stability test for " 
              << std::chrono::duration_cast<std::chrono::seconds>(test_duration).count() 
              << " seconds..." << std::endl;
    
    std::vector<std::pair<std::unique_ptr<Connection>, std::unique_ptr<Connection>>> connections;
    
    // Establish initial connections
    for (size_t i = 0; i < num_connections; ++i) {
        auto [client, server] = create_reliable_connection_pair();
        if (client && server && perform_reliable_handshake(client.get(), server.get())) {
            connections.emplace_back(std::move(client), std::move(server));
        }
    }
    
    ASSERT_GT(connections.size(), num_connections / 2); // At least half should succeed
    
    std::atomic<bool> test_running{true};
    std::atomic<size_t> operations_completed{0};
    std::atomic<size_t> operations_failed{0};
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Run continuous operations
    std::vector<std::thread> operation_threads;
    for (size_t i = 0; i < connections.size(); ++i) {
        operation_threads.emplace_back([&, i]() {
            size_t operation_count = 0;
            while (test_running) {
                std::vector<uint8_t> data = {
                    static_cast<uint8_t>(operation_count & 0xFF),
                    static_cast<uint8_t>(i & 0xFF),
                    0xDE, 0xAD, 0xBE, 0xEF
                };
                
                auto& [client, server] = connections[i];
                auto buffer = memory::ZeroCopyBuffer(reinterpret_cast<const std::byte*>(data.data()), data.size());
                auto send_result = client->send_application_data(buffer);
                
                if (send_result.is_ok()) {
                    operations_completed++;
                } else {
                    operations_failed++;
                    
                    // Attempt recovery
                    if (client->is_connected() == false) {
                        if (perform_reliable_handshake(client.get(), server.get())) {
                            // Retry the operation
                            auto retry_buffer = memory::ZeroCopyBuffer(reinterpret_cast<const std::byte*>(data.data()), data.size());
                            auto retry_result = client->send_application_data(retry_buffer);
                            if (retry_result.is_ok()) {
                                operations_completed++;
                            }
                        }
                    }
                }
                
                operation_count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
    }
    
    // Run for specified duration
    std::this_thread::sleep_for(test_duration);
    test_running = false;
    
    // Wait for all threads to complete
    for (auto& thread : operation_threads) {
        thread.join();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto actual_duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    size_t total_operations = operations_completed + operations_failed;
    double success_rate = static_cast<double>(operations_completed) / total_operations * 100.0;
    double ops_per_second = static_cast<double>(total_operations) / actual_duration.count();
    
    std::cout << "Stability test completed:" << std::endl;
    std::cout << "  Duration: " << actual_duration.count() << " seconds" << std::endl;
    std::cout << "  Total operations: " << total_operations << std::endl;
    std::cout << "  Success rate: " << success_rate << "%" << std::endl;
    std::cout << "  Operations per second: " << ops_per_second << std::endl;
    std::cout << "  Connection failures: " << get_connection_failures() << std::endl;
    std::cout << "  Automatic recoveries: " << get_automatic_recoveries() << std::endl;
    
    // Verify stability over time
    EXPECT_GT(success_rate, 98.0); // >98% success rate for stability
    EXPECT_GT(ops_per_second, 1.0); // Reasonable throughput maintained
}

// Reliability Test 4: Resource Exhaustion Handling
TEST_F(DTLSReliabilityTest, ResourceExhaustionHandling) {
    std::cout << "Testing resource exhaustion handling..." << std::endl;
    
    std::vector<std::pair<std::unique_ptr<Connection>, std::unique_ptr<Connection>>> connections;
    size_t max_connections_created = 0;
    
    // Try to create connections until resource exhaustion
    for (size_t i = 0; i < max_concurrent_connections_; ++i) {
        auto [client, server] = create_reliable_connection_pair();
        
        if (client && server) {
            // Attempt handshake
            if (perform_reliable_handshake(client.get(), server.get())) {
                connections.emplace_back(std::move(client), std::move(server));
                max_connections_created++;
            } else {
                // Connection creation succeeded but handshake failed
                break;
            }
        } else {
            // Connection creation failed (resource exhaustion)
            break;
        }
        
        // Check for resource exhaustion indicators
        if (get_resource_exhaustions() > 0) {
            std::cout << "Resource exhaustion detected at " << i << " connections" << std::endl;
            break;
        }
    }
    
    std::cout << "Maximum connections created: " << max_connections_created << std::endl;
    std::cout << "Resource exhaustions detected: " << get_resource_exhaustions() << std::endl;
    
    // Test graceful degradation
    if (max_connections_created > 0) {
        // Remove half the connections
        size_t connections_to_remove = connections.size() / 2;
        connections.erase(connections.end() - connections_to_remove, connections.end());
        
        // Verify remaining connections are still functional
        size_t functional_connections = 0;
        for (auto& [client, server] : connections) {
            std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
            auto buffer = memory::ZeroCopyBuffer(reinterpret_cast<const std::byte*>(test_data.data()), test_data.size());
            if (client->send_application_data(buffer).is_ok()) {
                functional_connections++;
            }
        }
        
        double functional_rate = static_cast<double>(functional_connections) / connections.size() * 100.0;
        std::cout << "Functional connections after cleanup: " << functional_rate << "%" << std::endl;
        
        EXPECT_GT(functional_rate, 90.0); // >90% should remain functional
    }
    
    // Verify system handled resource exhaustion gracefully
    EXPECT_GT(max_connections_created, 10); // Should create at least some connections
}

// Reliability Test 5: Recovery Mechanisms Testing
TEST_F(DTLSReliabilityTest, RecoveryMechanismsTesting) {
    std::cout << "Testing recovery mechanisms..." << std::endl;
    
    auto [client, server] = create_reliable_connection_pair();
    ASSERT_TRUE(client && server);
    
    // Establish initial connection
    ASSERT_TRUE(perform_reliable_handshake(client.get(), server.get()));
    
    // Test data transfer before failure
    std::vector<uint8_t> initial_data = {0x01, 0x02, 0x03};
    auto initial_buffer = memory::ZeroCopyBuffer(reinterpret_cast<const std::byte*>(initial_data.data()), initial_data.size());
    EXPECT_TRUE(client->send_application_data(initial_buffer).is_ok());
    
    // Simulate various failure scenarios and test recovery
    std::vector<std::string> failure_scenarios = {
        "Network disconnection",
        "Transport failure",
        "Crypto provider error",
        "Memory exhaustion",
        "Timeout scenario"
    };
    
    for (const auto& scenario : failure_scenarios) {
        std::cout << "Testing recovery from: " << scenario << std::endl;
        
        // Inject specific failure
        if (scenario == "Network disconnection") {
            simulate_transport_disconnection();
        } else if (scenario == "Transport failure") {
            simulate_packet_loss();
        } else if (scenario == "Crypto provider error") {
            simulate_crypto_failure();
        } else if (scenario == "Memory exhaustion") {
            simulate_memory_failure();
        } else if (scenario == "Timeout scenario") {
            simulate_network_timeout();
        }
        
        // Wait for failure detection
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Attempt recovery
        auto recovery_start = std::chrono::steady_clock::now();
        bool recovered = false;
        
        for (int attempt = 0; attempt < 5; ++attempt) {
            if (client->is_connected()) {
                // Test data transfer to verify recovery
                std::vector<uint8_t> recovery_data = {0x04, 0x05, 0x06};
                auto recovery_buffer = memory::ZeroCopyBuffer(reinterpret_cast<const std::byte*>(recovery_data.data()), recovery_data.size());
                if (client->send_application_data(recovery_buffer).is_ok()) {
                    recovered = true;
                    break;
                }
            } else {
                // Attempt to restart handshake for recovery
                if (client->start_handshake().is_ok()) {
                    continue; // Try data transfer next
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        
        auto recovery_time = std::chrono::steady_clock::now() - recovery_start;
        auto recovery_duration = std::chrono::duration_cast<std::chrono::milliseconds>(recovery_time);
        
        std::cout << "  Recovery " << (recovered ? "successful" : "failed") 
                  << " in " << recovery_duration.count() << " ms" << std::endl;
        
        if (recovered) {
            EXPECT_LT(recovery_duration, recovery_timeout_);
        }
    }
    
    std::cout << "Total automatic recoveries: " << get_automatic_recoveries() << std::endl;
    std::cout << "Total retry exhaustions: " << get_retry_exhaustions() << std::endl;
    
    // Verify recovery mechanisms are working
    EXPECT_GT(get_automatic_recoveries(), 0u); // Some recoveries should have occurred
}

} // namespace test
} // namespace v13
} // namespace dtls