#include <systemc>
#include <gtest/gtest.h>
#include <dtls_timing_models.h>
#include <dtls_protocol_stack.h>
#include <dtls_testbench.h>

#include <chrono>
#include <vector>
#include <memory>
#include <fstream>
#include <map>
#include <cmath>

namespace dtls {
namespace systemc {
namespace test {

/**
 * SystemC Timing Validation Test Suite
 * 
 * Validates timing model accuracy against real measurements:
 * - Cryptographic operation timing correlation
 * - Network latency and bandwidth modeling
 * - Memory access pattern timing
 * - Performance correlation analysis
 * - Timing accuracy within specified tolerances
 */
class SystemCTimingValidationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize timing validation environment
        setup_timing_models();
        setup_measurement_framework();
        setup_validation_benchmarks();
        
        // Reset timing statistics
        reset_timing_statistics();
    }
    
    void TearDown() override {
        // Stop SystemC simulation
        sc_core::sc_stop();
        
        // Generate timing validation report
        generate_timing_report();
        
        // Log timing validation results
        log_timing_validation_results();
    }
    
    void setup_timing_models() {
        // Create timing model instances
        crypto_timing_ = std::make_unique<crypto_timing_model>("crypto_timing");
        network_timing_ = std::make_unique<network_timing_model>("network_timing");
        memory_timing_ = std::make_unique<memory_timing_model>("memory_timing");
        
        // Create testbench for timing measurement
        timing_testbench_ = std::make_unique<dtls_testbench>("timing_testbench");
        
        // Connect timing models to testbench
        timing_testbench_->crypto_timing_port.bind(crypto_timing_->timing_export);
        timing_testbench_->network_timing_port.bind(network_timing_->timing_export);
        timing_testbench_->memory_timing_port.bind(memory_timing_->timing_export);
        
        // Configure simulation parameters
        simulation_clock_period_ = sc_core::sc_time(10, sc_core::SC_NS); // 100 MHz
        measurement_duration_ = sc_core::sc_time(100, sc_core::SC_MS);
        
        std::cout << "Timing models initialized" << std::endl;
    }
    
    void setup_measurement_framework() {
        // Initialize real-world timing measurements
        setup_crypto_benchmarks();
        setup_network_benchmarks();
        setup_memory_benchmarks();
        
        // Set timing accuracy thresholds
        crypto_timing_tolerance_ = 0.15; // 15% tolerance for crypto operations
        network_timing_tolerance_ = 0.20; // 20% tolerance for network operations
        memory_timing_tolerance_ = 0.10; // 10% tolerance for memory operations
        
        std::cout << "Measurement framework initialized" << std::endl;
    }
    
    void setup_crypto_benchmarks() {
        // Real-world crypto operation timings (measured values in microseconds)
        crypto_benchmarks_ = {
            {"AES_128_GCM_ENCRYPT_1KB", 12.5},
            {"AES_128_GCM_DECRYPT_1KB", 13.2},
            {"AES_256_GCM_ENCRYPT_1KB", 15.8},
            {"AES_256_GCM_DECRYPT_1KB", 16.4},
            {"CHACHA20_POLY1305_ENCRYPT_1KB", 18.3},
            {"CHACHA20_POLY1305_DECRYPT_1KB", 18.7},
            {"ECDSA_P256_SIGN", 95.2},
            {"ECDSA_P256_VERIFY", 145.6},
            {"ECDH_P256_KEYGEN", 78.4},
            {"ECDH_P256_COMPUTE", 82.1},
            {"HKDF_EXPAND_32_BYTES", 2.8},
            {"HKDF_EXTRACT_32_BYTES", 3.1},
            {"SHA256_HASH_1KB", 4.2},
            {"SHA384_HASH_1KB", 5.8}
        };
    }
    
    void setup_network_benchmarks() {
        // Real-world network operation timings (in microseconds)
        network_benchmarks_ = {
            {"UDP_SEND_64_BYTES", 15.0},
            {"UDP_SEND_1KB", 25.0},
            {"UDP_SEND_16KB", 180.0},
            {"UDP_RECEIVE_64_BYTES", 12.0},
            {"UDP_RECEIVE_1KB", 22.0},
            {"UDP_RECEIVE_16KB", 165.0},
            {"LOCALHOST_RTT", 50.0},
            {"LAN_RTT_1MS", 1000.0},
            {"WAN_RTT_50MS", 50000.0},
            {"PACKET_LOSS_DETECTION", 100.0},
            {"CONGESTION_BACKOFF", 200.0}
        };
    }
    
    void setup_memory_benchmarks() {
        // Real-world memory operation timings (in nanoseconds)
        memory_benchmarks_ = {
            {"L1_CACHE_HIT_READ", 1.0},
            {"L1_CACHE_HIT_WRITE", 1.2},
            {"L2_CACHE_HIT_READ", 3.5},
            {"L2_CACHE_HIT_WRITE", 4.0},
            {"L3_CACHE_HIT_READ", 12.0},
            {"L3_CACHE_HIT_WRITE", 15.0},
            {"DRAM_READ", 60.0},
            {"DRAM_WRITE", 65.0},
            {"MEMORY_COPY_1KB", 150.0},
            {"MEMORY_COPY_16KB", 2200.0},
            {"MEMORY_ALLOCATION_SMALL", 25.0},
            {"MEMORY_ALLOCATION_LARGE", 80.0}
        };
    }
    
    void setup_validation_benchmarks() {
        // Create validation test scenarios
        validation_scenarios_ = {
            {"dtls_handshake_full", {
                .crypto_ops = {"ECDH_P256_KEYGEN", "ECDH_P256_COMPUTE", "ECDSA_P256_SIGN", "ECDSA_P256_VERIFY", "HKDF_EXPAND_32_BYTES"},
                .network_ops = {"UDP_SEND_1KB", "UDP_RECEIVE_1KB", "LOCALHOST_RTT"},
                .memory_ops = {"MEMORY_COPY_1KB", "L2_CACHE_HIT_READ", "DRAM_WRITE"},
                .expected_total_us = 450.0
            }},
            {"dtls_data_transfer_1kb", {
                .crypto_ops = {"AES_128_GCM_ENCRYPT_1KB"},
                .network_ops = {"UDP_SEND_1KB", "UDP_RECEIVE_1KB"},
                .memory_ops = {"MEMORY_COPY_1KB", "L1_CACHE_HIT_READ"},
                .expected_total_us = 65.0
            }},
            {"dtls_key_update", {
                .crypto_ops = {"HKDF_EXPAND_32_BYTES", "HKDF_EXTRACT_32_BYTES"},
                .network_ops = {"UDP_SEND_64_BYTES", "UDP_RECEIVE_64_BYTES"},
                .memory_ops = {"MEMORY_ALLOCATION_SMALL", "L2_CACHE_HIT_WRITE"},
                .expected_total_us = 40.0
            }}
        };
    }
    
    bool validate_crypto_timing() {
        std::cout << "Validating crypto timing models..." << std::endl;
        
        bool all_valid = true;
        
        for (const auto& [operation, expected_time_us] : crypto_benchmarks_) {
            // Simulate crypto operation in SystemC
            auto systemc_time = simulate_crypto_operation(operation);
            
            // Convert to microseconds for comparison
            double systemc_time_us = systemc_time.to_seconds() * 1e6;
            
            // Calculate timing accuracy
            double accuracy = calculate_timing_accuracy(expected_time_us, systemc_time_us);
            bool within_tolerance = accuracy <= crypto_timing_tolerance_;
            
            // Store results
            timing_results_[operation] = {
                .expected_us = expected_time_us,
                .measured_us = systemc_time_us,
                .accuracy = accuracy,
                .within_tolerance = within_tolerance
            };
            
            if (within_tolerance) {
                crypto_timing_passes_++;
            } else {
                crypto_timing_failures_++;
                all_valid = false;
            }
            
            std::cout << "  " << operation << ": Expected " << expected_time_us 
                      << "μs, SystemC " << systemc_time_us << "μs, Accuracy " 
                      << (accuracy * 100) << "% " << (within_tolerance ? "PASS" : "FAIL") << std::endl;
        }
        
        return all_valid;
    }
    
    bool validate_network_timing() {
        std::cout << "Validating network timing models..." << std::endl;
        
        bool all_valid = true;
        
        for (const auto& [operation, expected_time_us] : network_benchmarks_) {
            // Simulate network operation in SystemC
            auto systemc_time = simulate_network_operation(operation);
            
            // Convert to microseconds for comparison
            double systemc_time_us = systemc_time.to_seconds() * 1e6;
            
            // Calculate timing accuracy
            double accuracy = calculate_timing_accuracy(expected_time_us, systemc_time_us);
            bool within_tolerance = accuracy <= network_timing_tolerance_;
            
            // Store results
            timing_results_[operation] = {
                .expected_us = expected_time_us,
                .measured_us = systemc_time_us,
                .accuracy = accuracy,
                .within_tolerance = within_tolerance
            };
            
            if (within_tolerance) {
                network_timing_passes_++;
            } else {
                network_timing_failures_++;
                all_valid = false;
            }
            
            std::cout << "  " << operation << ": Expected " << expected_time_us 
                      << "μs, SystemC " << systemc_time_us << "μs, Accuracy " 
                      << (accuracy * 100) << "% " << (within_tolerance ? "PASS" : "FAIL") << std::endl;
        }
        
        return all_valid;
    }
    
    bool validate_memory_timing() {
        std::cout << "Validating memory timing models..." << std::endl;
        
        bool all_valid = true;
        
        for (const auto& [operation, expected_time_ns] : memory_benchmarks_) {
            // Simulate memory operation in SystemC
            auto systemc_time = simulate_memory_operation(operation);
            
            // Convert to nanoseconds for comparison
            double systemc_time_ns = systemc_time.to_seconds() * 1e9;
            
            // Calculate timing accuracy
            double accuracy = calculate_timing_accuracy(expected_time_ns, systemc_time_ns);
            bool within_tolerance = accuracy <= memory_timing_tolerance_;
            
            // Store results
            timing_results_[operation] = {
                .expected_us = expected_time_ns / 1000.0, // Convert to μs for storage
                .measured_us = systemc_time_ns / 1000.0,
                .accuracy = accuracy,
                .within_tolerance = within_tolerance
            };
            
            if (within_tolerance) {
                memory_timing_passes_++;
            } else {
                memory_timing_failures_++;
                all_valid = false;
            }
            
            std::cout << "  " << operation << ": Expected " << expected_time_ns 
                      << "ns, SystemC " << systemc_time_ns << "ns, Accuracy " 
                      << (accuracy * 100) << "% " << (within_tolerance ? "PASS" : "FAIL") << std::endl;
        }
        
        return all_valid;
    }
    
    bool validate_end_to_end_timing() {
        std::cout << "Validating end-to-end timing scenarios..." << std::endl;
        
        bool all_valid = true;
        
        for (const auto& [scenario_name, scenario] : validation_scenarios_) {
            // Simulate complete scenario
            auto systemc_time = simulate_end_to_end_scenario(scenario_name, scenario);
            
            // Convert to microseconds for comparison
            double systemc_time_us = systemc_time.to_seconds() * 1e6;
            
            // Calculate timing accuracy
            double accuracy = calculate_timing_accuracy(scenario.expected_total_us, systemc_time_us);
            bool within_tolerance = accuracy <= 0.25; // 25% tolerance for end-to-end scenarios
            
            // Store results
            timing_results_[scenario_name] = {
                .expected_us = scenario.expected_total_us,
                .measured_us = systemc_time_us,
                .accuracy = accuracy,
                .within_tolerance = within_tolerance
            };
            
            if (within_tolerance) {
                end_to_end_timing_passes_++;
            } else {
                end_to_end_timing_failures_++;
                all_valid = false;
            }
            
            std::cout << "  " << scenario_name << ": Expected " << scenario.expected_total_us 
                      << "μs, SystemC " << systemc_time_us << "μs, Accuracy " 
                      << (accuracy * 100) << "% " << (within_tolerance ? "PASS" : "FAIL") << std::endl;
        }
        
        return all_valid;
    }
    
    sc_core::sc_time simulate_crypto_operation(const std::string& operation) {
        // Start simulation
        sc_core::sc_start(sc_core::SC_ZERO_TIME);
        
        auto start_time = sc_core::sc_time_stamp();
        
        // Trigger crypto operation based on type
        if (operation.find("AES") != std::string::npos) {
            crypto_timing_->simulate_aes_operation(1024); // 1KB
        } else if (operation.find("CHACHA20") != std::string::npos) {
            crypto_timing_->simulate_chacha20_operation(1024);
        } else if (operation.find("ECDSA") != std::string::npos) {
            crypto_timing_->simulate_ecdsa_operation();
        } else if (operation.find("ECDH") != std::string::npos) {
            crypto_timing_->simulate_ecdh_operation();
        } else if (operation.find("HKDF") != std::string::npos) {
            crypto_timing_->simulate_hkdf_operation(32);
        } else if (operation.find("SHA") != std::string::npos) {
            crypto_timing_->simulate_hash_operation(1024);
        }
        
        // Wait for operation completion
        sc_core::sc_start(sc_core::sc_time(1, sc_core::SC_MS));
        
        auto end_time = sc_core::sc_time_stamp();
        return end_time - start_time;
    }
    
    sc_core::sc_time simulate_network_operation(const std::string& operation) {
        sc_core::sc_start(sc_core::SC_ZERO_TIME);
        
        auto start_time = sc_core::sc_time_stamp();
        
        // Trigger network operation based on type
        if (operation.find("UDP_SEND") != std::string::npos) {
            size_t size = extract_size_from_operation(operation);
            network_timing_->simulate_udp_send(size);
        } else if (operation.find("UDP_RECEIVE") != std::string::npos) {
            size_t size = extract_size_from_operation(operation);
            network_timing_->simulate_udp_receive(size);
        } else if (operation.find("RTT") != std::string::npos) {
            network_timing_->simulate_rtt_measurement();
        } else if (operation.find("PACKET_LOSS") != std::string::npos) {
            network_timing_->simulate_packet_loss_detection();
        } else if (operation.find("CONGESTION") != std::string::npos) {
            network_timing_->simulate_congestion_backoff();
        }
        
        sc_core::sc_start(sc_core::sc_time(10, sc_core::SC_MS));
        
        auto end_time = sc_core::sc_time_stamp();
        return end_time - start_time;
    }
    
    sc_core::sc_time simulate_memory_operation(const std::string& operation) {
        sc_core::sc_start(sc_core::SC_ZERO_TIME);
        
        auto start_time = sc_core::sc_time_stamp();
        
        // Trigger memory operation based on type
        if (operation.find("L1_CACHE") != std::string::npos) {
            memory_timing_->simulate_l1_cache_access();
        } else if (operation.find("L2_CACHE") != std::string::npos) {
            memory_timing_->simulate_l2_cache_access();
        } else if (operation.find("L3_CACHE") != std::string::npos) {
            memory_timing_->simulate_l3_cache_access();
        } else if (operation.find("DRAM") != std::string::npos) {
            memory_timing_->simulate_dram_access();
        } else if (operation.find("MEMORY_COPY") != std::string::npos) {
            size_t size = extract_size_from_operation(operation);
            memory_timing_->simulate_memory_copy(size);
        } else if (operation.find("MEMORY_ALLOCATION") != std::string::npos) {
            size_t size = operation.find("LARGE") != std::string::npos ? 4096 : 64;
            memory_timing_->simulate_memory_allocation(size);
        }
        
        sc_core::sc_start(sc_core::sc_time(1, sc_core::SC_US));
        
        auto end_time = sc_core::sc_time_stamp();
        return end_time - start_time;
    }
    
    sc_core::sc_time simulate_end_to_end_scenario(const std::string& scenario_name, 
                                                 const ValidationScenario& scenario) {
        sc_core::sc_start(sc_core::SC_ZERO_TIME);
        
        auto start_time = sc_core::sc_time_stamp();
        
        // Simulate crypto operations
        for (const auto& crypto_op : scenario.crypto_ops) {
            simulate_crypto_operation(crypto_op);
        }
        
        // Simulate network operations
        for (const auto& network_op : scenario.network_ops) {
            simulate_network_operation(network_op);
        }
        
        // Simulate memory operations
        for (const auto& memory_op : scenario.memory_ops) {
            simulate_memory_operation(memory_op);
        }
        
        sc_core::sc_start(sc_core::sc_time(1, sc_core::SC_MS));
        
        auto end_time = sc_core::sc_time_stamp();
        return end_time - start_time;
    }
    
    size_t extract_size_from_operation(const std::string& operation) {
        if (operation.find("64_BYTES") != std::string::npos) return 64;
        if (operation.find("1KB") != std::string::npos) return 1024;
        if (operation.find("16KB") != std::string::npos) return 16384;
        return 1024; // Default
    }
    
    double calculate_timing_accuracy(double expected, double measured) {
        if (expected == 0.0) return 1.0; // Avoid division by zero
        return std::abs(expected - measured) / expected;
    }
    
    void reset_timing_statistics() {
        crypto_timing_passes_ = 0;
        crypto_timing_failures_ = 0;
        network_timing_passes_ = 0;
        network_timing_failures_ = 0;
        memory_timing_passes_ = 0;
        memory_timing_failures_ = 0;
        end_to_end_timing_passes_ = 0;
        end_to_end_timing_failures_ = 0;
        
        timing_results_.clear();
    }
    
    void generate_timing_report() {
        std::ofstream report("timing_validation_report.csv");
        report << "Operation,Expected_us,Measured_us,Accuracy_Percent,Within_Tolerance\n";
        
        for (const auto& [operation, result] : timing_results_) {
            report << operation << "," 
                   << result.expected_us << ","
                   << result.measured_us << ","
                   << (result.accuracy * 100) << ","
                   << (result.within_tolerance ? "YES" : "NO") << "\n";
        }
        
        report.close();
        std::cout << "Timing validation report generated: timing_validation_report.csv" << std::endl;
    }
    
    void log_timing_validation_results() {
        std::cout << "\n=== Timing Validation Results ===" << std::endl;
        std::cout << "Crypto timing - Passes: " << crypto_timing_passes_ 
                  << ", Failures: " << crypto_timing_failures_ << std::endl;
        std::cout << "Network timing - Passes: " << network_timing_passes_ 
                  << ", Failures: " << network_timing_failures_ << std::endl;
        std::cout << "Memory timing - Passes: " << memory_timing_passes_ 
                  << ", Failures: " << memory_timing_failures_ << std::endl;
        std::cout << "End-to-end timing - Passes: " << end_to_end_timing_passes_ 
                  << ", Failures: " << end_to_end_timing_failures_ << std::endl;
        
        uint32_t total_passes = crypto_timing_passes_ + network_timing_passes_ + 
                               memory_timing_passes_ + end_to_end_timing_passes_;
        uint32_t total_failures = crypto_timing_failures_ + network_timing_failures_ + 
                                  memory_timing_failures_ + end_to_end_timing_failures_;
        
        if (total_passes + total_failures > 0) {
            double overall_accuracy = static_cast<double>(total_passes) / 
                                     (total_passes + total_failures) * 100.0;
            std::cout << "Overall timing accuracy: " << overall_accuracy << "%" << std::endl;
        }
    }

protected:
    // SystemC timing components
    std::unique_ptr<crypto_timing_model> crypto_timing_;
    std::unique_ptr<network_timing_model> network_timing_;
    std::unique_ptr<memory_timing_model> memory_timing_;
    std::unique_ptr<dtls_testbench> timing_testbench_;
    
    // Simulation parameters
    sc_core::sc_time simulation_clock_period_;
    sc_core::sc_time measurement_duration_;
    
    // Timing tolerances
    double crypto_timing_tolerance_;
    double network_timing_tolerance_;
    double memory_timing_tolerance_;
    
    // Benchmark data
    std::map<std::string, double> crypto_benchmarks_;
    std::map<std::string, double> network_benchmarks_;
    std::map<std::string, double> memory_benchmarks_;
    
    // Validation scenarios
    struct ValidationScenario {
        std::vector<std::string> crypto_ops;
        std::vector<std::string> network_ops;
        std::vector<std::string> memory_ops;
        double expected_total_us;
    };
    
    std::map<std::string, ValidationScenario> validation_scenarios_;
    
    // Results tracking
    struct TimingResult {
        double expected_us;
        double measured_us;
        double accuracy;
        bool within_tolerance;
    };
    
    std::map<std::string, TimingResult> timing_results_;
    
    // Statistics
    std::atomic<uint32_t> crypto_timing_passes_{0};
    std::atomic<uint32_t> crypto_timing_failures_{0};
    std::atomic<uint32_t> network_timing_passes_{0};
    std::atomic<uint32_t> network_timing_failures_{0};
    std::atomic<uint32_t> memory_timing_passes_{0};
    std::atomic<uint32_t> memory_timing_failures_{0};
    std::atomic<uint32_t> end_to_end_timing_passes_{0};
    std::atomic<uint32_t> end_to_end_timing_failures_{0};
};

// Timing Validation Test 1: Crypto Timing Accuracy
TEST_F(SystemCTimingValidationTest, CryptoTimingAccuracy) {
    EXPECT_TRUE(validate_crypto_timing());
}

// Timing Validation Test 2: Network Timing Accuracy
TEST_F(SystemCTimingValidationTest, NetworkTimingAccuracy) {
    EXPECT_TRUE(validate_network_timing());
}

// Timing Validation Test 3: Memory Timing Accuracy
TEST_F(SystemCTimingValidationTest, MemoryTimingAccuracy) {
    EXPECT_TRUE(validate_memory_timing());
}

// Timing Validation Test 4: End-to-End Scenario Timing
TEST_F(SystemCTimingValidationTest, EndToEndScenarioTiming) {
    EXPECT_TRUE(validate_end_to_end_timing());
}

} // namespace test
} // namespace systemc
} // namespace dtls