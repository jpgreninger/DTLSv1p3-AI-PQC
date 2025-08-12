#ifndef SYSTEMC_TEST_FRAMEWORK_H
#define SYSTEMC_TEST_FRAMEWORK_H

#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_target_socket.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <map>
#include <chrono>
#include <fstream>
#include <sstream>

// DTLS SystemC includes
#include "dtls_systemc_types.h"
#include "dtls_tlm_extensions.h"
#include "dtls_protocol_stack.h"
#include "dtls_timing_models.h"
#include "dtls_testbench.h"

namespace dtls {
namespace systemc {
namespace test {

using namespace ::sc_core;
using namespace ::tlm;
using namespace dtls::v13::systemc_tlm;

/**
 * SystemC Test Framework Base Class
 * 
 * Provides common infrastructure for all SystemC DTLS tests including:
 * - Test setup/teardown management
 * - Performance measurement and correlation
 * - Test data generation and validation
 * - Results collection and reporting
 * - Timing analysis and validation
 */
class SystemCTestFramework : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize SystemC environment
        initialize_systemc_environment();
        
        // Setup performance measurement
        setup_performance_measurement();
        
        // Initialize test data generators
        setup_test_data_generation();
        
        // Setup result collection
        setup_result_collection();
        
        // Reset test statistics
        reset_test_statistics();
        
        test_start_time_ = std::chrono::high_resolution_clock::now();
    }
    
    void TearDown() override {
        test_end_time_ = std::chrono::high_resolution_clock::now();
        
        // Stop SystemC simulation gracefully
        if (sc_get_status() == SC_RUNNING) {
            sc_stop();
        }
        
        // Collect final performance metrics
        collect_performance_metrics();
        
        // Generate test report
        generate_test_report();
        
        // Cleanup resources
        cleanup_test_resources();
    }

public:
    /**
     * Test Configuration Structure
     */
    struct TestConfig {
        // Simulation parameters
        sc_time simulation_duration{1, SC_SEC};
        sc_time clock_period{10, SC_NS};
        bool enable_tracing{false};
        std::string trace_filename{"test_trace.vcd"};
        
        // Performance parameters
        bool enable_performance_measurement{true};
        double timing_tolerance_percent{5.0};
        bool correlate_with_real_timing{true};
        
        // Test data parameters
        size_t test_data_size{1024};
        size_t num_test_transactions{100};
        uint32_t random_seed{12345};
        
        // Connection parameters
        uint32_t max_connections{10};
        bool enable_hardware_acceleration{false};
        uint16_t mtu_size{1500};
        
        // Logging parameters
        bool enable_detailed_logging{false};
        std::string log_filename{"systemc_test.log"};
    };

protected:
    TestConfig config_;
    
    // Performance measurement
    std::chrono::high_resolution_clock::time_point test_start_time_;
    std::chrono::high_resolution_clock::time_point test_end_time_;
    
    // Test statistics
    struct TestStatistics {
        uint64_t total_transactions{0};
        uint64_t successful_transactions{0};
        uint64_t failed_transactions{0};
        uint64_t total_bytes_processed{0};
        
        // Timing statistics
        sc_time total_simulation_time{SC_ZERO_TIME};
        sc_time average_transaction_time{SC_ZERO_TIME};
        sc_time min_transaction_time{SC_ZERO_TIME};
        sc_time max_transaction_time{SC_ZERO_TIME};
        
        // Performance statistics
        double average_throughput_mbps{0.0};
        double cpu_utilization_percent{0.0};
        uint64_t memory_usage_bytes{0};
        
        // Error statistics
        std::map<std::string, uint32_t> error_counts;
        std::vector<std::string> error_messages;
    } statistics_;

    // Test trace file
    sc_trace_file* trace_file_{nullptr};
    
    // Test log stream
    std::unique_ptr<std::ofstream> log_stream_;

protected:
    /**
     * Initialize SystemC Environment
     */
    void initialize_systemc_environment() {
        // Setup SystemC time resolution
        sc_set_time_resolution(1, SC_PS);
        
        // Initialize tracing if enabled
        if (config_.enable_tracing) {
            trace_file_ = sc_create_vcd_trace_file(config_.trace_filename.c_str());
        }
        
        // Initialize logging if enabled
        if (config_.enable_detailed_logging) {
            log_stream_ = std::make_unique<std::ofstream>(config_.log_filename);
        }
    }
    
    /**
     * Setup Performance Measurement Infrastructure
     */
    void setup_performance_measurement() {
        // Initialize performance counters
        statistics_ = TestStatistics{};
        
        // Setup timing measurement points
        if (config_.enable_performance_measurement) {
            // Performance measurement setup will be extended in derived classes
        }
    }
    
    /**
     * Setup Test Data Generation
     */
    void setup_test_data_generation() {
        // Initialize random number generator with seed
        std::srand(config_.random_seed);
        
        // Generate test vectors
        generate_test_vectors();
    }
    
    /**
     * Generate Test Vectors
     */
    void generate_test_vectors() {
        // Generate various test data patterns
        test_vectors_.clear();
        
        // Pattern 1: Sequential data
        std::vector<uint8_t> sequential_data(config_.test_data_size);
        std::iota(sequential_data.begin(), sequential_data.end(), 0);
        test_vectors_["sequential"] = sequential_data;
        
        // Pattern 2: Random data
        std::vector<uint8_t> random_data(config_.test_data_size);
        std::generate(random_data.begin(), random_data.end(), 
                     []() { return static_cast<uint8_t>(std::rand() & 0xFF); });
        test_vectors_["random"] = random_data;
        
        // Pattern 3: All zeros
        std::vector<uint8_t> zero_data(config_.test_data_size, 0);
        test_vectors_["zeros"] = zero_data;
        
        // Pattern 4: All ones
        std::vector<uint8_t> ones_data(config_.test_data_size, 0xFF);
        test_vectors_["ones"] = ones_data;
        
        // Pattern 5: Alternating pattern
        std::vector<uint8_t> alternating_data(config_.test_data_size);
        for (size_t i = 0; i < config_.test_data_size; ++i) {
            alternating_data[i] = (i % 2) ? 0xAA : 0x55;
        }
        test_vectors_["alternating"] = alternating_data;
    }
    
    /**
     * Setup Result Collection
     */
    void setup_result_collection() {
        // Initialize result collection structures
        test_results_.clear();
        performance_samples_.clear();
    }
    
    /**
     * Reset Test Statistics
     */
    void reset_test_statistics() {
        statistics_ = TestStatistics{};
        statistics_.min_transaction_time = sc_time(std::numeric_limits<double>::max(), SC_SEC);
    }
    
    /**
     * Collect Performance Metrics
     */
    void collect_performance_metrics() {
        auto test_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            test_end_time_ - test_start_time_);
        
        // Calculate throughput
        if (test_duration.count() > 0) {
            double duration_seconds = test_duration.count() / 1e6;
            double bytes_per_second = statistics_.total_bytes_processed / duration_seconds;
            statistics_.average_throughput_mbps = bytes_per_second * 8 / 1e6; // Convert to Mbps
        }
        
        // Calculate average transaction time
        if (statistics_.total_transactions > 0) {
            statistics_.average_transaction_time = 
                statistics_.total_simulation_time / statistics_.total_transactions;
        }
    }
    
    /**
     * Generate Test Report
     */
    void generate_test_report() {
        std::stringstream report;
        
        report << "=== SystemC DTLS Test Report ===" << std::endl;
        report << "Test Duration: " 
               << std::chrono::duration_cast<std::chrono::milliseconds>(
                   test_end_time_ - test_start_time_).count() << " ms" << std::endl;
        report << "Total Transactions: " << statistics_.total_transactions << std::endl;
        report << "Successful Transactions: " << statistics_.successful_transactions << std::endl;
        report << "Failed Transactions: " << statistics_.failed_transactions << std::endl;
        report << "Total Bytes Processed: " << statistics_.total_bytes_processed << std::endl;
        report << "Average Throughput: " << statistics_.average_throughput_mbps << " Mbps" << std::endl;
        report << "Average Transaction Time: " << statistics_.average_transaction_time << std::endl;
        report << "Min Transaction Time: " << statistics_.min_transaction_time << std::endl;
        report << "Max Transaction Time: " << statistics_.max_transaction_time << std::endl;
        report << "CPU Utilization: " << statistics_.cpu_utilization_percent << "%" << std::endl;
        report << "Memory Usage: " << statistics_.memory_usage_bytes << " bytes" << std::endl;
        
        if (!statistics_.error_counts.empty()) {
            report << "\nError Summary:" << std::endl;
            for (const auto& [error_type, count] : statistics_.error_counts) {
                report << "  " << error_type << ": " << count << std::endl;
            }
        }
        
        report << "=================================" << std::endl;
        
        if (log_stream_) {
            *log_stream_ << report.str();
        }
        
        std::cout << report.str();
    }
    
    /**
     * Cleanup Test Resources
     */
    void cleanup_test_resources() {
        // Close trace file
        if (trace_file_) {
            sc_close_vcd_trace_file(trace_file_);
            trace_file_ = nullptr;
        }
        
        // Close log stream
        if (log_stream_) {
            log_stream_->close();
            log_stream_.reset();
        }
    }

protected:
    // Test data and results
    std::map<std::string, std::vector<uint8_t>> test_vectors_;
    std::map<std::string, std::vector<double>> test_results_;
    std::vector<std::pair<sc_time, double>> performance_samples_;

public:
    /**
     * Utility Functions for Test Implementation
     */
    
    /**
     * Create TLM Generic Payload with DTLS Extension
     */
    std::unique_ptr<tlm_generic_payload> create_dtls_payload(
        const std::vector<uint8_t>& data,
        dtls_extension::MessageType msg_type = dtls_extension::MessageType::APPLICATION_DATA) {
        
        auto payload = std::make_unique<tlm_generic_payload>();
        auto extension = new dtls_extension();
        
        // Setup basic payload
        payload->set_data_ptr(const_cast<unsigned char*>(data.data()));
        payload->set_data_length(data.size());
        payload->set_streaming_width(data.size());
        payload->set_byte_enable_ptr(nullptr);
        payload->set_byte_enable_length(0);
        payload->set_command(tlm::TLM_WRITE_COMMAND);
        payload->set_address(0);
        
        // Setup DTLS extension
        extension->message_type = msg_type;
        extension->connection_id = generate_connection_id();
        extension->sequence_number = generate_sequence_number();
        extension->processing_start_time = sc_time_stamp();
        
        payload->set_extension(extension);
        
        return payload;
    }
    
    /**
     * Validate TLM Transaction Timing
     */
    bool validate_transaction_timing(const sc_time& measured_time, 
                                   const sc_time& expected_time) {
        double tolerance = config_.timing_tolerance_percent / 100.0;
        double expected_time_double = expected_time.to_seconds();
        double measured_time_double = measured_time.to_seconds();
        
        double lower_bound = expected_time_double * (1.0 - tolerance);
        double upper_bound = expected_time_double * (1.0 + tolerance);
        
        return (measured_time_double >= lower_bound && measured_time_double <= upper_bound);
    }
    
    /**
     * Record Performance Sample
     */
    void record_performance_sample(double value) {
        performance_samples_.emplace_back(sc_time_stamp(), value);
    }
    
    /**
     * Update Transaction Statistics
     */
    void update_transaction_statistics(const sc_time& processing_time, 
                                     size_t bytes_processed, 
                                     bool success) {
        statistics_.total_transactions++;
        if (success) {
            statistics_.successful_transactions++;
        } else {
            statistics_.failed_transactions++;
        }
        
        statistics_.total_bytes_processed += bytes_processed;
        statistics_.total_simulation_time += processing_time;
        
        if (processing_time < statistics_.min_transaction_time) {
            statistics_.min_transaction_time = processing_time;
        }
        if (processing_time > statistics_.max_transaction_time) {
            statistics_.max_transaction_time = processing_time;
        }
    }
    
    /**
     * Add Trace Signals
     */
    template<typename T>
    void add_trace_signal(const sc_signal<T>& signal, const std::string& name) {
        if (trace_file_) {
            sc_trace(trace_file_, signal, name);
        }
    }

private:
    /**
     * Generate Unique Connection ID
     */
    uint32_t generate_connection_id() {
        static uint32_t connection_counter = 1000;
        return connection_counter++;
    }
    
    /**
     * Generate Sequence Number
     */
    uint64_t generate_sequence_number() {
        static uint64_t sequence_counter = 0;
        return sequence_counter++;
    }
};

/**
 * TLM Transaction Monitor
 * 
 * Monitors TLM transactions for testing and validation
 */
template<typename MODULE>
class TLMTransactionMonitor : public sc_module {
public:
    // TLM sockets for monitoring
    tlm_utils::simple_target_socket<TLMTransactionMonitor> monitor_socket;
    
    // Events for synchronization
    sc_event transaction_started;
    sc_event transaction_completed;
    
    // Statistics
    struct MonitorStats {
        uint32_t total_transactions{0};
        uint32_t read_transactions{0};
        uint32_t write_transactions{0};
        uint64_t total_bytes{0};
        sc_time total_processing_time{SC_ZERO_TIME};
        std::vector<sc_time> transaction_times;
    } stats;

    SC_CTOR(TLMTransactionMonitor) : monitor_socket("monitor_socket") {
        monitor_socket.register_b_transport(this, &TLMTransactionMonitor::b_transport);
        monitor_socket.register_nb_transport_fw(this, &TLMTransactionMonitor::nb_transport_fw);
    }

private:
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
        sc_time start_time = sc_time_stamp();
        transaction_started.notify();
        
        // Monitor transaction
        monitor_transaction(trans);
        
        // Forward to target (if connected to actual target)
        // This would be configured based on test setup
        
        sc_time processing_time = sc_time_stamp() - start_time + delay;
        stats.transaction_times.push_back(processing_time);
        stats.total_processing_time += processing_time;
        
        transaction_completed.notify();
    }
    
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans,
                                      tlm::tlm_phase& phase,
                                      sc_time& delay) {
        // Monitor non-blocking transaction
        monitor_transaction(trans);
        
        // Forward or handle based on test setup
        return tlm::TLM_COMPLETED;
    }
    
    void monitor_transaction(tlm::tlm_generic_payload& trans) {
        stats.total_transactions++;
        stats.total_bytes += trans.get_data_length();
        
        if (trans.get_command() == tlm::TLM_READ_COMMAND) {
            stats.read_transactions++;
        } else if (trans.get_command() == tlm::TLM_WRITE_COMMAND) {
            stats.write_transactions++;
        }
        
        // Extract and validate DTLS extension if present
        dtls_extension* ext = trans.get_extension<dtls_extension>();
        if (ext) {
            // Validate extension data
            validate_dtls_extension(*ext);
        }
    }
    
    void validate_dtls_extension(const dtls_extension& ext) {
        // Validation logic for DTLS-specific TLM extension
        // This would be customized based on test requirements
    }
};

} // namespace test
} // namespace systemc
} // namespace dtls

#endif // SYSTEMC_TEST_FRAMEWORK_H