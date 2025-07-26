/*
 * DTLS v1.3 Interoperability Test Framework
 * Task 9: Comprehensive external implementation testing
 */

#pragma once

#include "interop_config.h"
#include <dtls/connection.h>
#include <dtls/crypto/provider.h>
#include <dtls/protocol/dtls_records.h>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <functional>
#include <atomic>

namespace dtls::v13::test::interop {

/**
 * External DTLS implementation types
 */
enum class ExternalImplementation {
    OPENSSL_3_0,
    OPENSSL_3_1,
    WOLFSSL_5_6,
    GNUTLS_3_7,
    GNUTLS_3_8,
    BOTAN_3_0,
    MBEDTLS_3_4
};

/**
 * Test scenario types
 */
enum class TestScenario {
    BASIC_HANDSHAKE,
    CIPHER_SUITE_NEGOTIATION,
    KEY_UPDATE,
    CONNECTION_ID,
    EARLY_DATA,
    RESUMPTION,
    CLIENT_AUTH,
    LARGE_DATA_TRANSFER,
    FRAGMENTATION,
    RETRANSMISSION,
    ERROR_HANDLING
};

/**
 * Implementation role in test
 */
enum class TestRole {
    CLIENT,
    SERVER
};

/**
 * Test execution mode
 */
enum class TestMode {
    DIRECT_LINK,     // Direct library linking
    SUBPROCESS,      // Separate process execution
    DOCKER_CONTAINER // Docker container isolation
};

/**
 * Test result information
 */
struct InteropTestResult {
    bool success;
    std::string error_message;
    std::chrono::milliseconds duration;
    size_t bytes_transferred;
    uint16_t negotiated_cipher_suite;
    protocol::ProtocolVersion negotiated_version;
    std::vector<std::string> warnings;
    std::map<std::string, std::string> metadata;
    
    InteropTestResult() 
        : success(false), duration(0), bytes_transferred(0), 
          negotiated_cipher_suite(0), negotiated_version(protocol::ProtocolVersion::DTLS_1_3) {}
};

/**
 * Test configuration
 */
struct InteropTestConfig {
    ExternalImplementation external_impl;
    TestScenario scenario;
    TestRole our_role;
    TestMode mode;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> named_groups;
    std::vector<std::string> extensions;
    uint16_t port;
    std::chrono::milliseconds timeout;
    size_t test_data_size;
    bool verify_certificates;
    std::string test_description;
    
    InteropTestConfig() 
        : external_impl(ExternalImplementation::OPENSSL_3_0),
          scenario(TestScenario::BASIC_HANDSHAKE),
          our_role(TestRole::CLIENT),
          mode(TestMode::DIRECT_LINK),
          port(DTLS_INTEROP_DEFAULT_PORT_BASE),
          timeout(std::chrono::milliseconds(DTLS_INTEROP_DEFAULT_TIMEOUT_MS)),
          test_data_size(1024),
          verify_certificates(false) {}
};

/**
 * External implementation interface
 */
class ExternalImplementationRunner {
public:
    virtual ~ExternalImplementationRunner() = default;
    
    virtual bool initialize(const InteropTestConfig& config) = 0;
    virtual bool start_server(uint16_t port) = 0;
    virtual bool start_client(const std::string& host, uint16_t port) = 0;
    virtual bool send_data(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> receive_data(size_t max_size) = 0;
    virtual bool perform_handshake() = 0;
    virtual bool perform_key_update() = 0;
    virtual InteropTestResult get_test_result() = 0;
    virtual void cleanup() = 0;
    
    virtual std::string get_implementation_name() const = 0;
    virtual std::string get_version() const = 0;
};

/**
 * Test harness for coordinating interoperability tests
 */
class InteropTestHarness {
public:
    InteropTestHarness();
    ~InteropTestHarness();
    
    // Test execution
    InteropTestResult run_test(const InteropTestConfig& config);
    std::vector<InteropTestResult> run_test_matrix(
        const std::vector<ExternalImplementation>& implementations,
        const std::vector<TestScenario>& scenarios);
    
    // Configuration
    void set_our_crypto_provider(std::unique_ptr<crypto::CryptoProvider> provider);
    void set_certificate_files(const std::string& cert_file, const std::string& key_file);
    void set_ca_certificate_file(const std::string& ca_file);
    void enable_debug_logging(bool enable);
    
    // External implementation management
    void register_external_implementation(
        ExternalImplementation impl, 
        std::unique_ptr<ExternalImplementationRunner> runner);
    bool is_implementation_available(ExternalImplementation impl) const;
    
    // Test result analysis
    void generate_compatibility_matrix();
    void generate_performance_report();
    void export_results_to_json(const std::string& filename);
    
private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

/**
 * RFC 9147 compliance validator
 */
class RFC9147ComplianceValidator {
public:
    RFC9147ComplianceValidator();
    ~RFC9147ComplianceValidator();
    
    // Test vector validation
    bool validate_handshake_messages(const std::vector<uint8_t>& handshake_data);
    bool validate_record_layer_processing(const protocol::DTLSPlaintext& plaintext);
    bool validate_cipher_suite_selection(uint16_t negotiated_suite, 
                                       const std::vector<uint16_t>& offered_suites);
    bool validate_key_derivation(const std::vector<uint8_t>& derived_key,
                                const std::vector<uint8_t>& expected_key);
    
    // Protocol compliance checks
    bool validate_version_negotiation(protocol::ProtocolVersion negotiated,
                                    protocol::ProtocolVersion min_supported,
                                    protocol::ProtocolVersion max_supported);
    bool validate_extension_processing(const std::vector<std::string>& extensions);
    bool validate_sequence_number_handling(uint64_t sequence_number);
    bool validate_anti_replay_protection(const std::vector<uint64_t>& received_sequences);
    
    // Generate compliance report
    std::string generate_compliance_report();
    
private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

/**
 * Automated regression testing manager
 */
class InteropRegressionTester {
public:
    InteropRegressionTester();
    ~InteropRegressionTester();
    
    // Baseline management
    bool save_baseline_results(const std::vector<InteropTestResult>& results,
                              const std::string& baseline_name);
    bool load_baseline_results(const std::string& baseline_name,
                              std::vector<InteropTestResult>& results);
    
    // Regression detection
    std::vector<std::string> detect_regressions(
        const std::vector<InteropTestResult>& current_results,
        const std::vector<InteropTestResult>& baseline_results);
    
    // Performance regression
    std::vector<std::string> detect_performance_regressions(
        const std::vector<InteropTestResult>& current_results,
        const std::vector<InteropTestResult>& baseline_results,
        double threshold_percent = 10.0);
    
    // CI/CD integration
    bool generate_ci_report(const std::vector<InteropTestResult>& results,
                           const std::string& output_file);
    bool check_regression_thresholds(const std::vector<InteropTestResult>& results);
    
private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

/**
 * Utility functions for interoperability testing
 */
namespace utils {

// Implementation detection
std::vector<ExternalImplementation> detect_available_implementations();
std::string implementation_to_string(ExternalImplementation impl);
ExternalImplementation string_to_implementation(const std::string& str);

// Test scenario helpers
std::string scenario_to_string(TestScenario scenario);
std::vector<TestScenario> get_all_test_scenarios();
std::vector<TestScenario> get_quick_test_scenarios();

// Docker helpers
#ifdef DTLS_INTEROP_DOCKER_AVAILABLE
bool start_docker_container(const std::string& image_name, 
                           const std::string& container_name,
                           uint16_t port);
bool stop_docker_container(const std::string& container_name);
bool is_docker_container_running(const std::string& container_name);
#endif

// Performance measurement
class PerformanceTimer {
public:
    void start();
    void stop();
    std::chrono::milliseconds elapsed() const;
    void reset();
    
private:
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    bool running_ = false;
};

// Data generation for testing
std::vector<uint8_t> generate_test_data(size_t size, uint8_t pattern = 0);
std::vector<uint8_t> generate_random_test_data(size_t size);
bool verify_test_data(const std::vector<uint8_t>& received,
                     const std::vector<uint8_t>& expected);

} // namespace utils

} // namespace dtls::v13::test::interop