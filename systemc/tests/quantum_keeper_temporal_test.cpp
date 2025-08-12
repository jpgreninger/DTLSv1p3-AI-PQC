/**
 * Quantum Keeper and Temporal Decoupling Test for DTLS v1.3 SystemC Implementation
 * 
 * Comprehensive testing of SystemC quantum keeper and temporal decoupling mechanisms:
 * - Quantum keeper functionality and timing annotation management
 * - Temporal decoupling accuracy under different quantum sizes
 * - Synchronization point validation and quantum boundary behavior
 * - Timing annotation propagation through quantum boundaries
 * - Performance vs. accuracy trade-offs analysis
 * - Real-time constraint handling in temporal decoupling scenarios
 * - Multi-process synchronization and temporal coordination
 * - DTLS protocol timing accuracy under quantum-based simulation
 */

#include "systemc_test_framework.h"
#include "dtls_tlm_extensions.h"
#include "dtls_protocol_stack.h"
#include "dtls_timing_models.h"
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <chrono>
#include <map>
#include <queue>
#include <random>

using namespace dtls::systemc::test;
using namespace dtls::v13::systemc_tlm;

/**
 * Quantum Keeper Test Module
 * 
 * Tests quantum keeper functionality and temporal decoupling behavior
 */
SC_MODULE(QuantumKeeperTestModule) {
public:
    // TLM interfaces for testing
    tlm_utils::simple_target_socket<QuantumKeeperTestModule> target_socket;
    tlm_utils::simple_initiator_socket<QuantumKeeperTestModule> initiator_socket;
    
    // Test control and monitoring
    sc_in<bool> test_enable{"test_enable"};
    sc_in<sc_time> quantum_size{"quantum_size"};
    sc_out<bool> test_complete{"test_complete"};
    sc_out<bool> quantum_test_passed{"quantum_test_passed"};
    
    // Detailed test results
    sc_signal<bool> quantum_keeper_basic_passed{"quantum_keeper_basic_passed"};
    sc_signal<bool> temporal_decoupling_passed{"temporal_decoupling_passed"};
    sc_signal<bool> synchronization_passed{"synchronization_passed"};
    sc_signal<bool> timing_accuracy_passed{"timing_accuracy_passed"};
    sc_signal<bool> boundary_behavior_passed{"boundary_behavior_passed"};
    sc_signal<bool> performance_analysis_passed{"performance_analysis_passed"};
    
    // Performance monitoring
    sc_signal<sc_time> simulation_start_time{"simulation_start_time"};
    sc_signal<sc_time> simulation_end_time{"simulation_end_time"};
    sc_signal<sc_time> total_simulation_time{"total_simulation_time"};
    sc_signal<uint32_t> quantum_sync_count{"quantum_sync_count"};
    sc_signal<uint32_t> transactions_processed{"transactions_processed"};
    sc_signal<double> timing_accuracy_percentage{"timing_accuracy_percentage"};

private:
    // Quantum keeper instance
    tlm_utils::tlm_quantumkeeper quantum_keeper;
    
    // Test state tracking
    struct QuantumTestState {
        uint32_t sync_points{0};
        uint32_t transactions{0};
        std::vector<sc_time> quantum_sync_times;
        std::vector<sc_time> transaction_times;
        std::vector<double> timing_errors;
        sc_time accumulated_delay{SC_ZERO_TIME};
        bool all_tests_passed{true};
        std::vector<std::string> test_results;
    } test_state;
    
    // Test configuration
    struct QuantumTestConfig {
        sc_time default_quantum{100, SC_NS};
        sc_time min_quantum{10, SC_NS};
        sc_time max_quantum{1, SC_MS};
        double timing_tolerance_percent{5.0};
        size_t num_test_transactions{100};
        size_t num_quantum_sizes{5};
    } config;
    
    // Random number generator for test data
    std::mt19937 rng{12345};

    SC_CTOR(QuantumKeeperTestModule) 
        : target_socket("target_socket")
        , initiator_socket("initiator_socket") {
        
        // Initialize quantum keeper
        quantum_keeper.set_global_quantum(config.default_quantum);
        quantum_keeper.reset();
        
        // Register TLM callbacks
        target_socket.register_b_transport(this, &QuantumKeeperTestModule::b_transport);
        
        // Initialize signals
        test_complete.write(false);
        quantum_test_passed.write(false);
        quantum_sync_count.write(0);
        transactions_processed.write(0);
        timing_accuracy_percentage.write(0.0);
        
        SC_THREAD(quantum_test_controller);
        sensitive << test_enable.pos();
        
        SC_THREAD(quantum_monitor_process);
        
        SC_THREAD(transaction_generator_process);
    }

    void b_transport(tlm_generic_payload& trans, sc_time& delay) {
        // Handle incoming transactions with quantum keeper management
        dtls_extension* ext = trans.get_extension<dtls_extension>();
        if (!ext) {
            trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
            return;
        }
        
        // Record transaction timing
        sc_time transaction_start = sc_time_stamp();
        test_state.transaction_times.push_back(transaction_start);
        
        // Simulate DTLS processing with timing annotation
        sc_time processing_time = calculate_dtls_processing_time(*ext);
        
        // Use quantum keeper for temporal decoupling
        quantum_keeper.inc(processing_time);
        delay += processing_time;
        
        // Check if quantum boundary is reached
        if (quantum_keeper.need_sync()) {
            test_state.sync_points++;
            test_state.quantum_sync_times.push_back(sc_time_stamp());
            quantum_keeper.sync();
        }
        
        // Update extension with processing time
        ext->add_crypto_time(processing_time * 0.7);
        ext->add_network_time(processing_time * 0.2);
        ext->add_memory_time(processing_time * 0.1);
        
        test_state.transactions++;
        test_state.accumulated_delay += processing_time;
        
        trans.set_response_status(TLM_OK_RESPONSE);
    }

    void quantum_test_controller() {
        while (true) {
            wait(test_enable.posedge_event());
            
            if (test_enable.read()) {
                run_comprehensive_quantum_tests();
                
                // Update output signals
                quantum_test_passed.write(test_state.all_tests_passed);
                quantum_sync_count.write(test_state.sync_points);
                transactions_processed.write(test_state.transactions);
                
                // Calculate timing accuracy percentage
                double accuracy = calculate_timing_accuracy();
                timing_accuracy_percentage.write(accuracy);
                
                test_complete.write(true);
                wait(sc_time(10, SC_NS));
                test_complete.write(false);
            }
        }
    }

    void run_comprehensive_quantum_tests() {
        test_state = QuantumTestState{}; // Reset state
        simulation_start_time.write(sc_time_stamp());
        
        std::cout << "Starting Quantum Keeper and Temporal Decoupling Tests" << std::endl;
        
        // Test 1: Basic quantum keeper functionality
        test_basic_quantum_keeper_functionality();
        
        // Test 2: Temporal decoupling accuracy
        test_temporal_decoupling_accuracy();
        
        // Test 3: Synchronization point validation
        test_synchronization_point_validation();
        
        // Test 4: Timing accuracy under different quantum sizes
        test_timing_accuracy_different_quantums();
        
        // Test 5: Quantum boundary behavior
        test_quantum_boundary_behavior();
        
        // Test 6: Performance analysis
        test_performance_analysis();
        
        simulation_end_time.write(sc_time_stamp());
        total_simulation_time.write(simulation_end_time.read() - simulation_start_time.read());
        
        std::cout << "Quantum Keeper Tests: " << (test_state.all_tests_passed ? "PASSED" : "FAILED") << std::endl;
        std::cout << "Total transactions: " << test_state.transactions << std::endl;
        std::cout << "Synchronization points: " << test_state.sync_points << std::endl;
        std::cout << "Timing accuracy: " << calculate_timing_accuracy() << "%" << std::endl;
        
        for (const auto& result : test_state.test_results) {
            std::cout << "  - " << result << std::endl;
        }
    }

    void test_basic_quantum_keeper_functionality() {
        try {
            // Test quantum keeper initialization and basic operations
            sc_time original_quantum = quantum_keeper.get_global_quantum();
            sc_time test_quantum(500, SC_NS);
            
            // Set new quantum size
            quantum_keeper.set_global_quantum(test_quantum);
            
            if (quantum_keeper.get_global_quantum() != test_quantum) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Quantum size setting failed");
                quantum_keeper_basic_passed.write(false);
                return;
            }
            
            // Test quantum keeper reset
            quantum_keeper.reset();
            sc_time local_time = quantum_keeper.get_local_time();
            
            if (local_time != sc_time(SC_ZERO_TIME)) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Quantum keeper reset failed");
                quantum_keeper_basic_passed.write(false);
                return;
            }
            
            // Test time increment and sync need detection
            sc_time increment_time(400, SC_NS);
            quantum_keeper.inc(increment_time);
            
            if (quantum_keeper.need_sync()) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Premature sync need detection");
                quantum_keeper_basic_passed.write(false);
                return;
            }
            
            // Add more time to trigger sync need
            quantum_keeper.inc(sc_time(200, SC_NS));
            
            if (!quantum_keeper.need_sync()) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Sync need not detected when expected");
                quantum_keeper_basic_passed.write(false);
                return;
            }
            
            // Perform sync
            quantum_keeper.sync();
            
            if (quantum_keeper.need_sync()) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Sync did not clear sync need");
                quantum_keeper_basic_passed.write(false);
                return;
            }
            
            // Restore original quantum
            quantum_keeper.set_global_quantum(original_quantum);
            quantum_keeper.reset();
            
            test_state.test_results.push_back("Basic quantum keeper functionality test passed");
            quantum_keeper_basic_passed.write(true);
            
        } catch (const std::exception& e) {
            test_state.all_tests_passed = false;
            test_state.test_results.push_back(std::string("Basic quantum test exception: ") + e.what());
            quantum_keeper_basic_passed.write(false);
        }
    }

    void test_temporal_decoupling_accuracy() {
        try {
            // Test temporal decoupling with DTLS protocol operations
            std::vector<sc_time> quantum_sizes = {
                sc_time(10, SC_NS),
                sc_time(100, SC_NS),
                sc_time(1, SC_US),
                sc_time(10, SC_US),
                sc_time(100, SC_US)
            };
            
            std::map<sc_time, double> accuracy_results;
            
            for (const auto& quantum_size : quantum_sizes) {
                quantum_keeper.set_global_quantum(quantum_size);
                quantum_keeper.reset();
                
                // Create test transactions with known expected timing
                std::vector<dtls_transaction> test_transactions;
                std::vector<sc_time> expected_times;
                
                for (size_t i = 0; i < 20; ++i) {
                    std::vector<uint8_t> data(256 + i * 64, 0xAA);
                    dtls_transaction trans(data);
                    
                    dtls_extension* ext = trans.get_extension();
                    ext->cipher_suite = 0x1301;
                    ext->message_type = MessageType::APPLICATION_DATA;
                    ext->connection_id = 0x10000 + i;
                    ext->sequence_number = i;
                    ext->start_timing();
                    
                    sc_time expected = calculate_dtls_processing_time(*ext);
                    expected_times.push_back(expected);
                    test_transactions.push_back(std::move(trans));
                }
                
                // Process transactions through quantum keeper
                std::vector<sc_time> actual_times;
                sc_time start_time = sc_time_stamp();
                
                for (size_t i = 0; i < test_transactions.size(); ++i) {
                    tlm_generic_payload& payload = test_transactions[i].get_payload();
                    sc_time delay(SC_ZERO_TIME);
                    
                    sc_time before_trans = sc_time_stamp();
                    b_transport(payload, delay);
                    sc_time after_trans = sc_time_stamp();
                    
                    actual_times.push_back(delay);
                    
                    // Small delay between transactions
                    wait(sc_time(1, SC_NS));
                }
                
                // Calculate timing accuracy for this quantum size
                double accuracy = calculate_transaction_accuracy(expected_times, actual_times);
                accuracy_results[quantum_size] = accuracy;
            }
            
            // Validate that smaller quantum sizes provide better accuracy
            bool accuracy_trend_correct = true;
            auto prev_accuracy = accuracy_results.begin();
            
            for (auto it = std::next(accuracy_results.begin()); it != accuracy_results.end(); ++it) {
                if (it->second < prev_accuracy->second - 10.0) { // Allow some tolerance
                    accuracy_trend_correct = false;
                    break;
                }
                prev_accuracy = it;
            }
            
            if (!accuracy_trend_correct) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Temporal decoupling accuracy trend incorrect");
                temporal_decoupling_passed.write(false);
            } else {
                test_state.test_results.push_back("Temporal decoupling accuracy test passed");
                temporal_decoupling_passed.write(true);
            }
            
            // Log accuracy results
            for (const auto& result : accuracy_results) {
                std::cout << "Quantum " << result.first.to_string() 
                         << ": " << result.second << "% accuracy" << std::endl;
            }
            
        } catch (const std::exception& e) {
            test_state.all_tests_passed = false;
            test_state.test_results.push_back(std::string("Temporal decoupling exception: ") + e.what());
            temporal_decoupling_passed.write(false);
        }
    }

    void test_synchronization_point_validation() {
        try {
            // Test synchronization point behavior with multiple processes
            sc_time test_quantum(200, SC_NS);
            quantum_keeper.set_global_quantum(test_quantum);
            quantum_keeper.reset();
            
            size_t initial_sync_points = test_state.sync_points;
            
            // Create transactions that will force multiple synchronization points
            for (size_t i = 0; i < 10; ++i) {
                std::vector<uint8_t> data(512, 0xBB);
                dtls_transaction trans(data);
                
                dtls_extension* ext = trans.get_extension();
                ext->cipher_suite = 0x1301;
                ext->message_type = MessageType::HANDSHAKE;
                ext->handshake_type = HandshakeType::CLIENT_HELLO;
                ext->start_timing();
                
                tlm_generic_payload& payload = trans.get_payload();
                sc_time delay(SC_ZERO_TIME);
                
                // This should trigger multiple sync points due to processing time
                b_transport(payload, delay);
                
                wait(sc_time(5, SC_NS)); // Brief delay between transactions
            }
            
            size_t sync_points_created = test_state.sync_points - initial_sync_points;
            
            if (sync_points_created == 0) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("No synchronization points created during test");
                synchronization_passed.write(false);
            } else if (sync_points_created > 50) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Too many synchronization points created (inefficient)");
                synchronization_passed.write(false);
            } else {
                test_state.test_results.push_back("Synchronization point validation passed (" + 
                                                 std::to_string(sync_points_created) + " sync points)");
                synchronization_passed.write(true);
            }
            
        } catch (const std::exception& e) {
            test_state.all_tests_passed = false;
            test_state.test_results.push_back(std::string("Synchronization test exception: ") + e.what());
            synchronization_passed.write(false);
        }
    }

    void test_timing_accuracy_different_quantums() {
        try {
            std::vector<sc_time> quantum_test_sizes = {
                sc_time(1, SC_NS),    // Very fine granularity
                sc_time(10, SC_NS),   // Fine granularity  
                sc_time(100, SC_NS),  // Medium granularity
                sc_time(1, SC_US),    // Coarse granularity
                sc_time(10, SC_US)    // Very coarse granularity
            };
            
            std::map<sc_time, std::vector<double>> timing_errors_by_quantum;
            
            // Reference timing without quantum keeper (ideal case)
            std::vector<sc_time> reference_times = generate_reference_timing();
            
            for (const auto& quantum_size : quantum_test_sizes) {
                quantum_keeper.set_global_quantum(quantum_size);
                quantum_keeper.reset();
                
                std::vector<sc_time> measured_times;
                
                // Process reference transactions with current quantum size
                for (size_t i = 0; i < reference_times.size() && i < 20; ++i) {
                    std::vector<uint8_t> data(256, 0xCC);
                    dtls_transaction trans(data);
                    
                    dtls_extension* ext = trans.get_extension();
                    ext->cipher_suite = 0x1301;
                    ext->message_type = MessageType::APPLICATION_DATA;
                    ext->start_timing();
                    
                    tlm_generic_payload& payload = trans.get_payload();
                    sc_time delay(SC_ZERO_TIME);
                    
                    b_transport(payload, delay);
                    measured_times.push_back(ext->get_total_processing_time());
                    
                    wait(sc_time(2, SC_NS));
                }
                
                // Calculate timing errors for this quantum size
                std::vector<double> errors;
                for (size_t i = 0; i < std::min(reference_times.size(), measured_times.size()); ++i) {
                    double error_percent = std::abs(measured_times[i].value() - reference_times[i].value()) * 100.0 / reference_times[i].value();
                    errors.push_back(error_percent);
                    test_state.timing_errors.push_back(error_percent);
                }
                
                timing_errors_by_quantum[quantum_size] = errors;
            }
            
            // Validate timing accuracy results
            bool timing_accuracy_acceptable = true;
            for (const auto& quantum_errors : timing_errors_by_quantum) {
                double avg_error = 0.0;
                for (double error : quantum_errors.second) {
                    avg_error += error;
                }
                avg_error /= quantum_errors.second.size();
                
                // Fine granularity should have better accuracy
                if (quantum_errors.first <= sc_time(100, SC_NS) && avg_error > 20.0) {
                    timing_accuracy_acceptable = false;
                    break;
                }
            }
            
            if (timing_accuracy_acceptable) {
                test_state.test_results.push_back("Timing accuracy test passed for different quantum sizes");
                timing_accuracy_passed.write(true);
            } else {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Timing accuracy test failed - errors too high");
                timing_accuracy_passed.write(false);
            }
            
        } catch (const std::exception& e) {
            test_state.all_tests_passed = false;
            test_state.test_results.push_back(std::string("Timing accuracy test exception: ") + e.what());
            timing_accuracy_passed.write(false);
        }
    }

    void test_quantum_boundary_behavior() {
        try {
            // Test behavior at quantum boundaries
            sc_time test_quantum(100, SC_NS);
            quantum_keeper.set_global_quantum(test_quantum);
            quantum_keeper.reset();
            
            // Create transaction that will exactly hit quantum boundary
            std::vector<uint8_t> data(128, 0xDD);
            dtls_transaction trans(data);
            
            dtls_extension* ext = trans.get_extension();
            ext->cipher_suite = 0x1301;
            ext->message_type = MessageType::APPLICATION_DATA;
            
            // Manually control quantum keeper to test boundary behavior
            sc_time processing_time(50, SC_NS);
            quantum_keeper.inc(processing_time);
            
            bool sync_needed_before = quantum_keeper.need_sync();
            
            // Add exactly enough time to hit boundary
            quantum_keeper.inc(sc_time(50, SC_NS));
            bool sync_needed_at_boundary = quantum_keeper.need_sync();
            
            // Add a small amount more
            quantum_keeper.inc(sc_time(1, SC_NS));
            bool sync_needed_after = quantum_keeper.need_sync();
            
            // Validate boundary behavior
            if (sync_needed_before) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Premature sync need before quantum boundary");
                boundary_behavior_passed.write(false);
            } else if (!sync_needed_at_boundary) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Sync not needed at quantum boundary");
                boundary_behavior_passed.write(false);
            } else if (!sync_needed_after) {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Sync not needed after quantum boundary");
                boundary_behavior_passed.write(false);
            } else {
                test_state.test_results.push_back("Quantum boundary behavior test passed");
                boundary_behavior_passed.write(true);
            }
            
        } catch (const std::exception& e) {
            test_state.all_tests_passed = false;
            test_state.test_results.push_back(std::string("Boundary behavior test exception: ") + e.what());
            boundary_behavior_passed.write(false);
        }
    }

    void test_performance_analysis() {
        try {
            // Compare simulation performance with different quantum sizes
            std::vector<sc_time> performance_quantums = {
                sc_time(1, SC_NS),
                sc_time(100, SC_NS),
                sc_time(10, SC_US)
            };
            
            std::map<sc_time, double> performance_metrics;
            
            for (const auto& quantum_size : performance_quantums) {
                quantum_keeper.set_global_quantum(quantum_size);
                quantum_keeper.reset();
                
                auto real_start = std::chrono::high_resolution_clock::now();
                
                // Process a fixed number of transactions
                for (size_t i = 0; i < 50; ++i) {
                    std::vector<uint8_t> data(512, 0xEE);
                    dtls_transaction trans(data);
                    
                    dtls_extension* ext = trans.get_extension();
                    ext->cipher_suite = 0x1301;
                    ext->message_type = MessageType::APPLICATION_DATA;
                    ext->sequence_number = i;
                    
                    tlm_generic_payload& payload = trans.get_payload();
                    sc_time delay(SC_ZERO_TIME);
                    
                    b_transport(payload, delay);
                    
                    wait(sc_time(1, SC_NS));
                }
                
                auto real_end = std::chrono::high_resolution_clock::now();
                double real_time_ms = std::chrono::duration<double, std::milli>(real_end - real_start).count();
                
                performance_metrics[quantum_size] = real_time_ms;
            }
            
            // Validate performance trends (larger quantums should be faster)
            bool performance_trend_correct = true;
            double prev_time = 0.0;
            
            for (const auto& perf : performance_metrics) {
                if (prev_time > 0.0 && perf.second > prev_time * 5.0) {
                    // Allow some variation, but very large increases indicate issues
                    performance_trend_correct = false;
                }
                prev_time = perf.second;
                
                std::cout << "Quantum " << perf.first.to_string() 
                         << ": " << perf.second << " ms execution time" << std::endl;
            }
            
            if (performance_trend_correct) {
                test_state.test_results.push_back("Performance analysis test passed");
                performance_analysis_passed.write(true);
            } else {
                test_state.all_tests_passed = false;
                test_state.test_results.push_back("Performance analysis failed - unexpected timing");
                performance_analysis_passed.write(false);
            }
            
        } catch (const std::exception& e) {
            test_state.all_tests_passed = false;
            test_state.test_results.push_back(std::string("Performance analysis exception: ") + e.what());
            performance_analysis_passed.write(false);
        }
    }

    void quantum_monitor_process() {
        while (true) {
            wait(sc_time(1, SC_US)); // Monitor every microsecond
            
            // Monitor quantum keeper state
            if (quantum_keeper.need_sync()) {
                // This sync was not handled by b_transport
                test_state.sync_points++;
                quantum_keeper.sync();
            }
        }
    }

    void transaction_generator_process() {
        while (true) {
            wait(sc_time(10, SC_US)); // Generate transactions periodically
            
            if (test_enable.read()) {
                // Generate background transactions to test quantum keeper under load
                std::vector<uint8_t> bg_data(128, 0xFF);
                dtls_transaction bg_trans(bg_data);
                
                dtls_extension* ext = bg_trans.get_extension();
                ext->cipher_suite = 0x1302;
                ext->message_type = MessageType::APPLICATION_DATA;
                
                tlm_generic_payload& payload = bg_trans.get_payload();
                sc_time delay(SC_ZERO_TIME);
                
                // Process through quantum keeper
                b_transport(payload, delay);
            }
        }
    }

    sc_time calculate_dtls_processing_time(const dtls_extension& ext) {
        sc_time base_time(100, SC_NS); // Base processing time
        
        // Adjust based on cipher suite
        switch (ext.cipher_suite) {
            case 0x1301: // AES-128-GCM
                base_time = sc_time(50, SC_NS);
                break;
            case 0x1302: // AES-256-GCM  
                base_time = sc_time(75, SC_NS);
                break;
            case 0x1303: // ChaCha20-Poly1305
                base_time = sc_time(60, SC_NS);
                break;
            default:
                base_time = sc_time(100, SC_NS);
                break;
        }
        
        // Adjust based on message type
        if (ext.message_type == MessageType::HANDSHAKE) {
            base_time = base_time * 3; // Handshake operations are more expensive
            
            if (ext.handshake_type == HandshakeType::CERTIFICATE_VERIFY) {
                base_time = base_time + sc_time(2, SC_US); // Signature operations
            }
        }
        
        return base_time;
    }

    double calculate_timing_accuracy() {
        if (test_state.timing_errors.empty()) {
            return 100.0; // Perfect accuracy if no errors recorded
        }
        
        double total_error = 0.0;
        for (double error : test_state.timing_errors) {
            total_error += error;
        }
        
        double avg_error = total_error / test_state.timing_errors.size();
        return std::max(0.0, 100.0 - avg_error);
    }

    double calculate_transaction_accuracy(const std::vector<sc_time>& expected, const std::vector<sc_time>& actual) {
        if (expected.size() != actual.size() || expected.empty()) {
            return 0.0;
        }
        
        double total_error = 0.0;
        for (size_t i = 0; i < expected.size(); ++i) {
            double error_percent = std::abs(actual[i].value() - expected[i].value()) * 100.0 / expected[i].value();
            total_error += error_percent;
        }
        
        double avg_error = total_error / expected.size();
        return std::max(0.0, 100.0 - avg_error);
    }

    std::vector<sc_time> generate_reference_timing() {
        std::vector<sc_time> reference;
        
        // Generate expected timing for standard DTLS operations
        reference.push_back(sc_time(50, SC_NS));   // AES-128 encrypt small
        reference.push_back(sc_time(75, SC_NS));   // AES-256 encrypt small
        reference.push_back(sc_time(100, SC_NS));  // AES-128 encrypt medium
        reference.push_back(sc_time(150, SC_NS));  // AES-256 encrypt medium
        reference.push_back(sc_time(200, SC_NS));  // Handshake processing
        reference.push_back(sc_time(2, SC_US));    // Certificate verify
        reference.push_back(sc_time(60, SC_NS));   // ChaCha20 encrypt
        reference.push_back(sc_time(80, SC_NS));   // Hash operation
        
        return reference;
    }
};

/**
 * Multi-Process Temporal Coordination Test Module
 * 
 * Tests synchronization between multiple SystemC processes using quantum keeper
 */
SC_MODULE(MultiProcessTemporalTest) {
public:
    sc_in<bool> test_enable{"test_enable"};
    sc_out<bool> coordination_test_passed{"coordination_test_passed"};
    sc_out<uint32_t> process_sync_count{"process_sync_count"};
    
    // Inter-process communication channels
    sc_fifo<dtls_transaction> process_a_to_b{"process_a_to_b"};
    sc_fifo<dtls_transaction> process_b_to_a{"process_b_to_a"};
    
    sc_signal<bool> process_a_ready{"process_a_ready"};
    sc_signal<bool> process_b_ready{"process_b_ready"};
    sc_signal<uint32_t> coordination_errors{"coordination_errors"};

private:
    tlm_utils::tlm_quantumkeeper qk_process_a;
    tlm_utils::tlm_quantumkeeper qk_process_b;
    
    uint32_t sync_count{0};
    uint32_t error_count{0};
    bool test_passed{true};

    SC_CTOR(MultiProcessTemporalTest) {
        // Initialize quantum keepers for both processes
        qk_process_a.set_global_quantum(sc_time(200, SC_NS));
        qk_process_b.set_global_quantum(sc_time(200, SC_NS));
        
        coordination_test_passed.write(true);
        process_sync_count.write(0);
        coordination_errors.write(0);
        
        SC_THREAD(process_a_thread);
        SC_THREAD(process_b_thread);
        SC_THREAD(coordination_monitor);
        
        sensitive << test_enable;
    }

    void process_a_thread() {
        while (true) {
            wait(test_enable.posedge_event());
            
            if (test_enable.read()) {
                process_a_ready.write(true);
                
                for (int i = 0; i < 20; ++i) {
                    // Create transaction
                    std::vector<uint8_t> data(256, 0xA0 + i % 16);
                    dtls_transaction trans(data);
                    
                    dtls_extension* ext = trans.get_extension();
                    ext->connection_id = 0xA0000000 + i;
                    ext->sequence_number = i;
                    ext->message_type = MessageType::APPLICATION_DATA;
                    
                    // Process with quantum keeper A
                    qk_process_a.inc(sc_time(50, SC_NS));
                    
                    if (qk_process_a.need_sync()) {
                        sync_count++;
                        qk_process_a.sync();
                    }
                    
                    // Send to process B
                    process_a_to_b.write(trans);
                    
                    // Wait for response from B
                    if (process_b_to_a.num_available() > 0) {
                        dtls_transaction response = process_b_to_a.read();
                        // Validate response timing
                        validate_response_timing(response, i);
                    }
                    
                    wait(sc_time(10, SC_NS));
                }
                
                process_a_ready.write(false);
            }
        }
    }

    void process_b_thread() {
        while (true) {
            wait(test_enable.posedge_event());
            
            if (test_enable.read()) {
                process_b_ready.write(true);
                
                while (test_enable.read()) {
                    if (process_a_to_b.num_available() > 0) {
                        dtls_transaction request = process_a_to_b.read();
                        
                        // Process request with quantum keeper B
                        qk_process_b.inc(sc_time(75, SC_NS));
                        
                        if (qk_process_b.need_sync()) {
                            sync_count++;
                            qk_process_b.sync();
                        }
                        
                        // Modify and send back
                        dtls_extension* ext = request.get_extension();
                        ext->connection_id = 0xB0000000 + ext->sequence_number;
                        ext->add_crypto_time(sc_time(75, SC_NS));
                        
                        process_b_to_a.write(request);
                    }
                    
                    wait(sc_time(5, SC_NS));
                }
                
                process_b_ready.write(false);
            }
        }
    }

    void coordination_monitor() {
        while (true) {
            wait(sc_time(100, SC_NS));
            
            if (test_enable.read()) {
                // Monitor for coordination errors
                process_sync_count.write(sync_count);
                coordination_errors.write(error_count);
                coordination_test_passed.write(test_passed && error_count == 0);
            }
        }
    }

    void validate_response_timing(const dtls_transaction& response, int sequence) {
        const dtls_extension* ext = response.get_extension();
        
        // Validate timing consistency
        sc_time total_time = ext->get_total_processing_time();
        
        if (total_time < sc_time(50, SC_NS) || total_time > sc_time(500, SC_NS)) {
            error_count++;
            test_passed = false;
        }
    }
};

/**
 * Main test class for Quantum Keeper and Temporal Decoupling Testing
 */
class QuantumKeeperTemporalTest : public SystemCTestFramework {
protected:
    void SetUp() override {
        SystemCTestFramework::SetUp();
        
        // Configure test for quantum keeper validation
        config_.simulation_duration = sc_time(50, SC_MS);
        config_.enable_tracing = true;
        config_.trace_filename = "quantum_keeper_test.vcd";
        config_.enable_performance_measurement = true;
        
        // Create test modules
        quantum_test_module = std::make_unique<QuantumKeeperTestModule>("QuantumTestModule");
        multi_process_test = std::make_unique<MultiProcessTemporalTest>("MultiProcessTest");
        
        // Create control signals
        test_enable_signal = std::make_unique<sc_signal<bool>>("test_enable");
        quantum_size_signal = std::make_unique<sc_signal<sc_time>>("quantum_size");
        
        test_complete_signal = std::make_unique<sc_signal<bool>>("test_complete");
        quantum_test_passed_signal = std::make_unique<sc_signal<bool>>("quantum_test_passed");
        coordination_test_passed_signal = std::make_unique<sc_signal<bool>>("coordination_test_passed");
        
        sync_count_signal = std::make_unique<sc_signal<uint32_t>>("sync_count");
        transactions_signal = std::make_unique<sc_signal<uint32_t>>("transactions");
        timing_accuracy_signal = std::make_unique<sc_signal<double>>("timing_accuracy");
        
        // Connect quantum test module
        quantum_test_module->test_enable(*test_enable_signal);
        quantum_test_module->quantum_size(*quantum_size_signal);
        quantum_test_module->test_complete(*test_complete_signal);
        quantum_test_module->quantum_test_passed(*quantum_test_passed_signal);
        quantum_test_module->quantum_sync_count(*sync_count_signal);
        quantum_test_module->transactions_processed(*transactions_signal);
        quantum_test_module->timing_accuracy_percentage(*timing_accuracy_signal);
        
        // Connect multi-process test module
        multi_process_test->test_enable(*test_enable_signal);
        multi_process_test->coordination_test_passed(*coordination_test_passed_signal);
        
        // Set default quantum size
        quantum_size_signal->write(sc_time(100, SC_NS));
    }

private:
    std::unique_ptr<QuantumKeeperTestModule> quantum_test_module;
    std::unique_ptr<MultiProcessTemporalTest> multi_process_test;
    
    std::unique_ptr<sc_signal<bool>> test_enable_signal;
    std::unique_ptr<sc_signal<sc_time>> quantum_size_signal;
    std::unique_ptr<sc_signal<bool>> test_complete_signal;
    std::unique_ptr<sc_signal<bool>> quantum_test_passed_signal;
    std::unique_ptr<sc_signal<bool>> coordination_test_passed_signal;
    std::unique_ptr<sc_signal<uint32_t>> sync_count_signal;
    std::unique_ptr<sc_signal<uint32_t>> transactions_signal;
    std::unique_ptr<sc_signal<double>> timing_accuracy_signal;
};

/**
 * Test: Basic Quantum Keeper Functionality
 * 
 * Validate basic quantum keeper operations and temporal decoupling
 */
TEST_F(QuantumKeeperTemporalTest, BasicQuantumKeeperFunctionality) {
    // Start quantum keeper tests
    test_enable_signal->write(true);
    wait(sc_time(10, SC_NS));
    test_enable_signal->write(false);
    
    // Wait for test completion
    while (!test_complete_signal->read()) {
        sc_start(sc_time(1, SC_MS));
    }
    
    // Validate results
    EXPECT_TRUE(quantum_test_passed_signal->read()) 
        << "Quantum keeper functionality test failed";
    
    uint32_t sync_count = sync_count_signal->read();
    uint32_t transactions = transactions_signal->read();
    double timing_accuracy = timing_accuracy_signal->read();
    
    std::cout << "Quantum Keeper Test Results:" << std::endl;
    std::cout << "  Synchronization points: " << sync_count << std::endl;
    std::cout << "  Transactions processed: " << transactions << std::endl;
    std::cout << "  Timing accuracy: " << timing_accuracy << "%" << std::endl;
    
    EXPECT_GT(sync_count, 0) << "No synchronization points created";
    EXPECT_GT(transactions, 50) << "Insufficient transactions processed";
    EXPECT_GT(timing_accuracy, 70.0) << "Timing accuracy below acceptable threshold";
}

/**
 * Test: Multi-Process Temporal Coordination
 * 
 * Validate temporal coordination between multiple SystemC processes
 */
TEST_F(QuantumKeeperTemporalTest, MultiProcessTemporalCoordination) {
    // Start multi-process coordination test
    test_enable_signal->write(true);
    wait(sc_time(10, SC_NS));
    
    // Let test run for longer duration
    sc_start(sc_time(10, SC_MS));
    
    test_enable_signal->write(false);
    
    // Validate coordination results
    EXPECT_TRUE(coordination_test_passed_signal->read()) 
        << "Multi-process temporal coordination failed";
}

/**
 * Test: Quantum Size Impact Analysis
 * 
 * Test different quantum sizes and their impact on timing accuracy
 */
TEST_F(QuantumKeeperTemporalTest, QuantumSizeImpactAnalysis) {
    std::vector<sc_time> test_quantums = {
        sc_time(10, SC_NS),
        sc_time(100, SC_NS),
        sc_time(1, SC_US),
        sc_time(10, SC_US)
    };
    
    std::map<sc_time, double> accuracy_results;
    
    for (const auto& quantum : test_quantums) {
        // Set quantum size
        quantum_size_signal->write(quantum);
        
        // Run test
        test_enable_signal->write(true);
        wait(sc_time(10, SC_NS));
        test_enable_signal->write(false);
        
        // Wait for completion
        while (!test_complete_signal->read()) {
            sc_start(sc_time(1, SC_MS));
        }
        
        // Record results
        double accuracy = timing_accuracy_signal->read();
        accuracy_results[quantum] = accuracy;
        
        std::cout << "Quantum " << quantum.to_string() 
                 << ": " << accuracy << "% accuracy" << std::endl;
        
        // Reset for next test
        wait(sc_time(100, SC_NS));
    }
    
    // Validate that all quantum sizes produced acceptable results
    for (const auto& result : accuracy_results) {
        EXPECT_GT(result.second, 50.0) 
            << "Unacceptable timing accuracy for quantum " << result.first.to_string();
    }
}

/**
 * SystemC main function for standalone testing
 */
int sc_main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}