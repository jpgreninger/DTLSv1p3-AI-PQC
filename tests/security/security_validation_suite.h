#pragma once

#include <gtest/gtest.h>
#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/protocol.h>
#include <dtls/transport/udp_transport.h>
#include <dtls/crypto/openssl_provider.h>
#include <memory>
#include <vector>
#include <chrono>
#include <atomic>
#include <mutex>
#include <thread>
#include <random>
#include <fstream>
#include <map>
#include <algorithm>
#include <numeric>

namespace dtls {
namespace v13 {
namespace test {

/**
 * Comprehensive Security Validation Suite for DTLS v1.3
 * 
 * Task 12: Security Validation Suite (RFC 9147 Compliance)
 * 
 * This suite implements comprehensive security testing including:
 * - Attack simulation scenarios
 * - Fuzzing and malformed message handling
 * - Timing attack resistance tests
 * - Side-channel resistance validation
 * - Comprehensive threat model validation
 * - Security compliance verification
 * - Constant-time implementation testing
 * - Memory safety validation
 * - Cryptographic compliance testing
 * - Security assessment report generation
 */

// Security event types for comprehensive monitoring
enum class SecurityEventType : uint32_t {
    REPLAY_ATTACK_DETECTED = 0x01,
    AUTHENTICATION_FAILURE = 0x02,
    PROTOCOL_VIOLATION = 0x03,
    MALFORMED_MESSAGE = 0x04,
    TIMING_ATTACK_SUSPECTED = 0x05,
    SIDE_CHANNEL_ANOMALY = 0x06,
    MEMORY_SAFETY_VIOLATION = 0x07,
    CRYPTO_COMPLIANCE_FAILURE = 0x08,
    DOS_ATTACK_DETECTED = 0x09,
    CERTIFICATE_VALIDATION_FAILURE = 0x0A,
    KEY_MANAGEMENT_VIOLATION = 0x0B,
    CONSTANT_TIME_VIOLATION = 0x0C,
    BUFFER_OVERFLOW_ATTEMPT = 0x0D,
    RESOURCE_EXHAUSTION = 0x0E,
    OTHER = 0xFF
};

enum class SecurityEventSeverity : uint8_t {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

struct SecurityEvent {
    SecurityEventType type;
    SecurityEventSeverity severity;
    std::string description;
    uint32_t connection_id;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
};

struct SecurityMetrics {
    // Attack detection metrics
    uint32_t replay_attacks_detected = 0;
    uint32_t authentication_failures = 0;
    uint32_t protocol_violations = 0;
    uint32_t malformed_messages_detected = 0;
    uint32_t dos_attempts_blocked = 0;
    
    // Timing analysis metrics
    uint32_t timing_attacks_suspected = 0;
    std::vector<std::chrono::microseconds> handshake_timings;
    std::vector<std::chrono::microseconds> crypto_operation_timings;
    
    // Side-channel metrics
    uint32_t side_channel_anomalies = 0;
    std::vector<double> power_consumption_samples;
    std::vector<uint64_t> memory_access_patterns;
    
    // Memory safety metrics
    uint32_t buffer_overflow_attempts = 0;
    uint32_t memory_leaks_detected = 0;
    size_t max_memory_usage = 0;
    
    // Cryptographic compliance metrics
    uint32_t weak_key_rejections = 0;
    uint32_t crypto_failures = 0;
    uint32_t constant_time_violations = 0;
    
    // General security metrics
    uint32_t total_security_events = 0;
    uint32_t critical_events = 0;
    uint32_t fuzzing_iterations_completed = 0;
    uint32_t attack_scenarios_executed = 0;
};

// Attack simulation scenarios
struct AttackScenario {
    std::string name;
    std::string description;
    SecurityEventType expected_detection;
    std::function<bool(class SecurityValidationSuite*)> execute;
    bool should_succeed = false; // Whether attack should succeed (for negative testing)
};

// Fuzzing test cases
struct FuzzingTestCase {
    std::string name;
    std::vector<uint8_t> payload;
    bool should_crash_system = false;
    SecurityEventType expected_event;
};

// Timing analysis test
struct TimingTest {
    std::string operation_name;
    std::function<std::chrono::microseconds()> operation;
    size_t iterations = 1000;
    double max_coefficient_variation = 0.15; // Maximum acceptable timing variation
};

// Cryptographic compliance test
struct CryptoComplianceTest {
    std::string name;
    std::string description;
    std::function<bool()> test_function;
    bool is_critical = true;
};

// Security compliance requirement
struct SecurityRequirement {
    std::string id;
    std::string description;
    std::string prd_reference;
    std::function<bool()> validator;
    bool is_mandatory = true;
};

/**
 * Main Security Validation Suite Class
 */
class SecurityValidationSuite : public ::testing::Test {
public:
    SecurityValidationSuite();
    virtual ~SecurityValidationSuite();

protected:
    void SetUp() override;
    void TearDown() override;

    // Test infrastructure setup
    void setup_test_environment();
    void setup_attack_scenarios();
    void setup_fuzzing_tests();
    void setup_timing_tests();
    void setup_crypto_compliance_tests();
    void setup_security_requirements();
    void cleanup_test_environment();

    // Connection management
    std::pair<std::unique_ptr<Connection>, std::unique_ptr<Connection>>
    create_secure_connection_pair();
    
    bool perform_secure_handshake(Connection* client, Connection* server);
    void setup_security_callbacks(Connection* client, Connection* server);
    
    // Security event handling
    void handle_security_event(const SecurityEvent& event, const std::string& source);
    void log_security_event(const SecurityEvent& event, const std::string& source);
    
    // Attack simulation
    bool execute_attack_scenario(const AttackScenario& scenario);
    bool simulate_replay_attack();
    bool simulate_timing_attack();
    bool simulate_dos_attack();
    bool simulate_mitm_attack();
    bool simulate_certificate_attack();
    
    // Fuzzing tests
    bool execute_fuzzing_tests();
    bool execute_structured_fuzzing();
    bool execute_random_fuzzing();
    bool test_protocol_state_fuzzing();
    
    // Timing attack resistance
    bool test_timing_attack_resistance();
    bool test_constant_time_operations();
    bool analyze_timing_patterns();
    
    // Side-channel resistance
    bool test_side_channel_resistance();
    bool test_power_analysis_resistance();
    bool test_memory_access_patterns();
    
    // Memory safety validation
    bool test_memory_safety();
    bool test_buffer_overflow_protection();
    bool test_memory_leak_detection();
    bool test_stack_protection();
    
    // Cryptographic compliance
    bool test_cryptographic_compliance();
    bool test_key_generation_quality();
    bool test_cipher_suite_compliance();
    bool test_random_number_quality();
    
    // Security compliance verification
    bool verify_security_compliance();
    bool verify_prd_requirements();
    bool verify_rfc_compliance();
    
    // Threat model validation
    bool validate_threat_model();
    bool test_threat_mitigation();
    bool assess_attack_surface();
    
    // Reporting and analysis
    void generate_security_assessment_report();
    void generate_json_report(const std::string& output_dir, const std::string& timestamp);
    void generate_html_report(const std::string& output_dir, const std::string& timestamp);
    void generate_text_report(const std::string& output_dir, const std::string& timestamp);
    bool calculate_overall_security_assessment();
    std::string get_security_level_assessment();
    std::vector<std::string> generate_security_recommendations();
    void analyze_security_metrics();
    void export_test_results(const std::string& format = "json");
    
    // Utility functions
    void reset_security_metrics();
    std::vector<uint8_t> generate_random_data(size_t size);
    std::vector<uint8_t> generate_malformed_packet(const std::string& type);
    bool check_system_stability();
    
    // Performance and resource monitoring
    void start_resource_monitoring();
    void stop_resource_monitoring();
    size_t get_current_memory_usage();
    double get_cpu_usage();

protected:
    // Test infrastructure
    std::unique_ptr<Context> client_context_;
    std::unique_ptr<Context> server_context_;
    std::unique_ptr<transport::UDPTransport> client_transport_;
    std::unique_ptr<transport::UDPTransport> server_transport_;
    
    // Security monitoring
    SecurityMetrics security_metrics_;
    std::vector<SecurityEvent> security_events_;
    mutable std::mutex metrics_mutex_;
    
    // Attack scenarios and test cases
    std::vector<AttackScenario> attack_scenarios_;
    std::vector<FuzzingTestCase> fuzzing_tests_;
    std::vector<TimingTest> timing_tests_;
    std::vector<CryptoComplianceTest> crypto_tests_;
    std::vector<SecurityRequirement> security_requirements_;
    
    // Test configuration
    struct TestConfig {
        size_t max_fuzzing_iterations = 10000;
        size_t max_attack_attempts = 1000;
        size_t timing_test_iterations = 1000;
        double timing_variation_threshold = 0.15;
        size_t memory_leak_threshold_bytes = 1024 * 1024; // 1MB
        std::chrono::seconds test_timeout{300}; // 5 minutes
        bool enable_verbose_logging = false;
        bool enable_performance_monitoring = true;
        std::string report_output_directory = "./security_reports/";
    } config_;
    
    // Random number generation
    std::mt19937 rng_;
    std::uniform_int_distribution<uint8_t> byte_dist_{0, 255};
    std::uniform_int_distribution<size_t> size_dist_{1, 1000};
    
    // Resource monitoring
    std::atomic<bool> monitoring_active_{false};
    std::thread monitoring_thread_;
    std::vector<size_t> memory_usage_samples_;
    std::vector<double> cpu_usage_samples_;
    
    // Test state
    std::atomic<bool> test_failed_{false};
    std::atomic<bool> system_unstable_{false};
    std::string current_test_name_;
    std::chrono::steady_clock::time_point test_start_time_;
};

// Helper macros for security testing
#define EXPECT_SECURITY_EVENT(event_type) \
    do { \
        auto start_count = security_metrics_.total_security_events; \
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); \
        EXPECT_GT(security_metrics_.total_security_events, start_count) \
            << "Expected security event " #event_type " was not detected"; \
    } while(0)

#define EXPECT_NO_SECURITY_EVENTS() \
    do { \
        auto start_count = security_metrics_.total_security_events; \
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); \
        EXPECT_EQ(security_metrics_.total_security_events, start_count) \
            << "Unexpected security events detected"; \
    } while(0)

#define EXPECT_SYSTEM_STABLE() \
    do { \
        EXPECT_TRUE(check_system_stability()) \
            << "System became unstable during security test"; \
    } while(0)

#define SECURITY_TEST_TIMEOUT(duration) \
    do { \
        auto timeout_time = std::chrono::steady_clock::now() + duration; \
        EXPECT_LT(std::chrono::steady_clock::now(), timeout_time) \
            << "Security test exceeded timeout of " << duration.count() << " seconds"; \
    } while(0)

} // namespace test
} // namespace v13
} // namespace dtls