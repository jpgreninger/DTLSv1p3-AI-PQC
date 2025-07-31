#ifndef DTLS_TESTBENCH_H
#define DTLS_TESTBENCH_H

#include "dtls_systemc_types.h"
#include "crypto_provider_tlm.h"
#include "record_layer_tlm.h"
#include "message_layer_tlm.h"
#include "dtls_channels.h"
#include <systemc>
#include <vector>
#include <memory>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * SystemC Testbench for DTLS TLM Components
 * 
 * Comprehensive testbench that verifies the functionality and
 * performance of all DTLS TLM components in an integrated system.
 */
SC_MODULE(DTLSSystemTestbench) {
public:
    // Test control signals
    sc_signal<bool> test_enable{"test_enable"};
    sc_signal<bool> system_reset{"system_reset"};
    sc_signal<uint32_t> test_scenario{"test_scenario"};
    
    // Configuration signals
    sc_signal<bool> hardware_acceleration_enable{"hw_accel_enable"};
    sc_signal<uint32_t> max_fragment_size{"max_fragment_size"};
    sc_signal<bool> connection_id_enabled{"connection_id_enabled"};
    sc_signal<uint32_t> current_cipher_suite{"current_cipher_suite"};
    
    // Network simulation signals
    sc_signal<double> packet_loss_probability{"packet_loss_probability"};
    sc_signal<sc_time> network_latency{"network_latency"};
    sc_signal<double> bandwidth_mbps{"bandwidth_mbps"};
    
    // System status monitoring
    sc_signal<bool> system_ready{"system_ready"};
    sc_signal<uint32_t> system_utilization{"system_utilization"};
    sc_signal<bool> test_passed{"test_passed"};
    sc_signal<uint32_t> test_errors{"test_errors"};
    
    /**
     * Test scenario definitions
     */
    enum class TestScenario {
        BASIC_CRYPTO_OPERATIONS = 1,
        RECORD_LAYER_PROTECTION = 2,
        MESSAGE_FRAGMENTATION = 3,
        HANDSHAKE_FLIGHT_MANAGEMENT = 4,
        FULL_DTLS_HANDSHAKE = 5,
        PERFORMANCE_STRESS_TEST = 6,
        NETWORK_CONDITIONS_TEST = 7,
        SECURITY_VALIDATION_TEST = 8,
        COMPREHENSIVE_SYSTEM_TEST = 9
    };
    
    /**
     * Test results structure  
     */
    struct TestResults {
        uint32_t tests_run{0};
        uint32_t tests_passed{0};
        uint32_t tests_failed{0};
        
        sc_time total_test_time{0, SC_NS};
        sc_time average_test_time{0, SC_NS};
        
        // Performance metrics
        double crypto_throughput_mhz{0.0};
        double record_throughput_mbps{0.0};
        double message_throughput_mps{0.0};
        
        // Quality metrics
        double security_effectiveness{0.0};
        double reliability_ratio{0.0};
        uint32_t security_violations_detected{0};
        
        std::vector<std::string> error_messages;
        std::vector<std::string> performance_warnings;
    };
    
    // Constructor
    DTLSSystemTestbench(sc_module_name name);
    
    // Test execution methods
    void run_all_tests();
    void run_test_scenario(TestScenario scenario);
    void run_custom_test(const std::string& test_name);
    
    // Test results
    TestResults get_test_results() const;
    void print_test_summary() const;
    void generate_test_report(const std::string& filename) const;

private:
    // Component instances under test
    std::unique_ptr<CryptoProviderTLM> crypto_provider_;
    std::unique_ptr<HardwareAcceleratedCryptoTLM> hw_crypto_provider_;
    std::unique_ptr<RecordLayerSecuritySystemTLM> record_layer_system_;
    std::unique_ptr<MessageLayerSystemTLM> message_layer_system_;
    std::unique_ptr<DTLSInterconnectBus> interconnect_bus_;
    
    // Communication channels
    std::unique_ptr<CryptoOperationChannel> crypto_channel_;
    std::unique_ptr<RecordOperationChannel> record_channel_;
    std::unique_ptr<MessageOperationChannel> message_channel_;
    std::unique_ptr<TransportChannel> transport_channel_;
    
    // Test state
    TestResults test_results_;
    mutable std::mutex test_results_mutex_;
    std::vector<std::function<bool()>> test_functions_;
    
    // SystemC processes
    void test_orchestrator_process();
    void system_monitor_process();
    void performance_monitor_process();
    void test_timeout_process();
    
    // Individual test implementations
    bool test_basic_crypto_operations();
    bool test_record_layer_protection();
    bool test_message_fragmentation();
    bool test_handshake_flight_management();
    bool test_full_dtls_handshake();
    bool test_performance_stress();
    bool test_network_conditions();
    bool test_security_validation();
    bool test_comprehensive_system();
    
    // Test utilities
    void setup_test_environment();
    void cleanup_test_environment();
    void configure_system_for_test(TestScenario scenario);
    bool verify_test_results(TestScenario scenario);
    
    // Performance validation
    bool validate_crypto_performance();
    bool validate_record_layer_performance();
    bool validate_message_layer_performance();
    bool validate_overall_system_performance();
    
    // Security validation
    bool validate_crypto_security();
    bool validate_anti_replay_protection();
    bool validate_epoch_management();
    bool validate_connection_id_security();
    
    // Stress testing
    void generate_crypto_load(uint32_t operation_count);
    void generate_record_layer_load(uint32_t record_count);
    void generate_message_layer_load(uint32_t message_count);
    void simulate_network_stress();
    
    // Test data generation
    crypto_transaction create_test_crypto_transaction(crypto_transaction::operation_type op);
    record_transaction create_test_record_transaction(record_transaction::operation_type op);
    message_transaction create_test_message_transaction(message_transaction::operation_type op);
    transport_transaction create_test_transport_transaction();
    
    // Verification helpers
    bool verify_crypto_operation_result(const crypto_transaction& trans);
    bool verify_record_protection_result(const record_transaction& trans);
    bool verify_message_operation_result(const message_transaction& trans);
    bool verify_system_security_state();
    
    // Error handling and reporting
    void record_test_error(const std::string& error_message);
    void record_performance_warning(const std::string& warning_message);
    void update_test_statistics(bool test_passed, sc_time test_duration);
    
    SC_HAS_PROCESS(DTLSSystemTestbench);
};

/**
 * DTLS Performance Benchmark Suite
 * 
 * Specialized testbench for performance characterization
 * and benchmarking of DTLS TLM components.
 */
SC_MODULE(DTLSPerformanceBenchmark) {
public:
    // Benchmark control
    sc_in<bool> benchmark_enable;
    sc_in<uint32_t> benchmark_duration_sec;
    sc_in<uint32_t> load_intensity_percent;
    
    // Performance results
    sc_out<double> crypto_ops_per_second;
    sc_out<double> record_throughput_mbps;
    sc_out<double> message_throughput_mps;
    sc_out<sc_time> average_latency;
    sc_out<uint32_t> system_utilization_percent;
    
    /**
     * Benchmark configuration
     */
    struct BenchmarkConfig {
        uint32_t crypto_operation_mix[7] = {20, 20, 15, 15, 10, 10, 10}; // Percentages for each op type
        uint32_t record_operation_mix[2] = {50, 50}; // Protect/Unprotect percentages
        uint32_t message_size_distribution[4] = {25, 35, 25, 15}; // Small/Medium/Large/XLarge
        bool enable_hardware_acceleration{true};
        bool enable_network_simulation{true};
        bool enable_security_features{true};
    };
    
    /**
     * Benchmark results
     */
    struct BenchmarkResults {
        // Throughput metrics
        double crypto_operations_per_second{0.0};
        double record_protection_mbps{0.0};
        double message_processing_mps{0.0};
        
        // Latency metrics
        sc_time crypto_average_latency{0, SC_NS};
        sc_time record_average_latency{0, SC_NS};
        sc_time message_average_latency{0, SC_NS};
        sc_time end_to_end_latency{0, SC_NS};
        
        // Resource utilization
        double cpu_utilization_percent{0.0};
        double memory_utilization_percent{0.0};
        double bus_utilization_percent{0.0};
        
        // Quality metrics
        double security_overhead_percent{0.0};
        double reliability_effectiveness{0.0};
        uint32_t total_operations_processed{0};
        uint32_t failed_operations{0};
    };
    
    // Constructor
    DTLSPerformanceBenchmark(sc_module_name name, const BenchmarkConfig& config = BenchmarkConfig{});
    
    // Benchmark execution
    void run_benchmark();
    void run_throughput_benchmark();
    void run_latency_benchmark();
    void run_scalability_benchmark();
    void run_stress_benchmark();
    
    // Results and reporting
    BenchmarkResults get_benchmark_results() const;
    void print_benchmark_summary() const;
    void export_results_csv(const std::string& filename) const;

private:
    // Benchmark configuration
    BenchmarkConfig config_;
    
    // System under test (references to testbench components)
    CryptoProviderTLM* crypto_provider_;
    RecordLayerTLM* record_layer_;
    MessageLayerTLM* message_layer_;
    
    // Benchmark state
    BenchmarkResults results_;
    mutable std::mutex results_mutex_;
    
    // SystemC processes
    void benchmark_orchestrator_process();
    void load_generator_process();
    void performance_collector_process();
    void results_analyzer_process();
    
    // Load generation
    void generate_crypto_workload();
    void generate_record_workload();
    void generate_message_workload();
    void generate_mixed_workload();
    
    // Performance measurement
    void measure_throughput_performance();
    void measure_latency_performance();
    void measure_resource_utilization();
    void calculate_benchmark_metrics();
    
    SC_HAS_PROCESS(DTLSPerformanceBenchmark);
};

/**
 * DTLS Security Validation Suite
 * 
 * Specialized testbench for security verification and
 * vulnerability testing of DTLS TLM components.
 */
SC_MODULE(DTLSSecurityValidator) {
public:
    // Validation control
    sc_in<bool> validation_enable;
    sc_in<uint32_t> security_level;
    sc_in<bool> enable_attack_simulation;
    
    // Security status
    sc_out<bool> security_validation_passed;
    sc_out<uint32_t> vulnerabilities_detected;
    sc_out<uint32_t> attack_attempts_blocked;
    sc_out<double> security_effectiveness_ratio;
    
    /**
     * Security test categories
     */
    enum class SecurityTestCategory {
        CRYPTO_VALIDATION,
        ANTI_REPLAY_TESTING,
        EPOCH_SECURITY,
        CONNECTION_ID_SECURITY,
        TIMING_ATTACK_RESISTANCE,
        SIDE_CHANNEL_RESISTANCE,
        PROTOCOL_COMPLIANCE
    };
    
    /**
     * Security validation results
     */
    struct SecurityValidationResults {
        bool overall_security_passed{false};
        uint32_t total_tests_run{0};
        uint32_t security_tests_passed{0};
        uint32_t vulnerabilities_found{0};
        uint32_t attack_attempts{0};
        uint32_t attacks_blocked{0};
        
        double crypto_security_score{0.0};
        double protocol_security_score{0.0};
        double implementation_security_score{0.0};
        double overall_security_score{0.0};
        
        std::vector<std::string> security_issues;
        std::vector<std::string> recommendations;
    };
    
    // Constructor
    DTLSSecurityValidator(sc_module_name name);
    
    // Security validation methods
    void run_security_validation();
    void run_category_tests(SecurityTestCategory category);
    void simulate_security_attacks();
    
    // Results and reporting
    SecurityValidationResults get_validation_results() const;
    void print_security_report() const;
    void generate_security_compliance_report(const std::string& filename) const;

private:
    // Security test implementations
    bool test_crypto_operations_security();
    bool test_anti_replay_protection();
    bool test_epoch_management_security();
    bool test_connection_id_security();
    bool test_timing_attack_resistance();
    bool test_side_channel_resistance();
    bool test_protocol_compliance();
    
    // Attack simulations
    void simulate_replay_attacks();
    void simulate_timing_attacks();
    void simulate_cryptographic_attacks();
    void simulate_protocol_attacks();
    
    // Validation state
    SecurityValidationResults validation_results_;
    mutable std::mutex validation_mutex_;
    
    // SystemC processes
    void security_validation_process();
    void attack_simulation_process();
    void security_monitoring_process();
    
    SC_HAS_PROCESS(DTLSSecurityValidator);
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_TESTBENCH_H