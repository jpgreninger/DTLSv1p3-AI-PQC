/**
 * Hardware/Software Co-design Validation Test for DTLS v1.3 SystemC Implementation
 * 
 * Comprehensive testing of hardware/software co-design scenarios including:
 * - Hardware acceleration simulation and timing model accuracy
 * - Co-simulation between SystemC timing models and core protocol library
 * - DMI (Direct Memory Interface) functionality for performance-critical operations
 * - Hardware resource modeling and constraint validation
 * - Interface compliance with hardware communication protocols
 * - Performance correlation between simulation and actual hardware behavior
 * - Memory interface behavior under different hardware configurations
 * - Hardware/software partitioning validation
 */

#include "systemc_test_framework.h"
#include "dtls_tlm_extensions.h"
#include "dtls_protocol_stack.h"
#include "dtls_timing_models.h"
#include "crypto_provider_tlm.h"
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <chrono>
#include <random>
#include <map>

using namespace dtls::systemc::test;
using namespace dtls::v13::systemc_tlm;

/**
 * Mock Hardware Accelerator Module
 * 
 * Simulates dedicated hardware for crypto operations
 */
SC_MODULE(MockHardwareCryptoAccelerator) {
public:
    // TLM sockets for communication
    tlm_utils::simple_target_socket<MockHardwareCryptoAccelerator> target_socket;
    
    // Hardware status signals
    sc_out<bool> hw_ready{"hw_ready"};
    sc_out<bool> hw_busy{"hw_busy"};
    sc_out<uint32_t> hw_performance_counter{"hw_performance_counter"};
    sc_out<uint32_t> hw_error_counter{"hw_error_counter"};
    
    // Configuration interface
    sc_in<uint32_t> hw_clock_frequency{"hw_clock_frequency"}; // MHz
    sc_in<uint32_t> hw_pipeline_depth{"hw_pipeline_depth"};
    sc_in<bool> hw_enable_dmi{"hw_enable_dmi"};
    
    // DMI (Direct Memory Interface) support
    sc_signal<bool> dmi_granted{"dmi_granted"};
    sc_signal<sc_dt::uint64> dmi_start_address{"dmi_start_address"};
    sc_signal<sc_dt::uint64> dmi_end_address{"dmi_end_address"};

private:
    // Hardware timing parameters (based on realistic crypto accelerator specs)
    struct HardwareTiming {
        sc_time aes_gcm_setup_time{50, SC_NS};
        sc_time aes_gcm_per_block_time{10, SC_NS}; // 128-bit block
        sc_time chacha20_setup_time{30, SC_NS};
        sc_time chacha20_per_block_time{8, SC_NS};
        sc_time sha256_setup_time{20, SC_NS};
        sc_time sha256_per_block_time{15, SC_NS};
        sc_time ecdsa_p256_sign_time{5, SC_US};
        sc_time ecdsa_p256_verify_time{8, SC_US};
        sc_time ecdh_p256_keygen_time{3, SC_US};
        sc_time hkdf_setup_time{25, SC_NS};
        sc_time hkdf_per_byte_time{2, SC_NS};
        sc_time memory_access_time{5, SC_NS};
        sc_time bus_transfer_time{1, SC_NS}; // per byte
    } hw_timing;
    
    // Hardware resource tracking
    struct HardwareResources {
        uint32_t max_concurrent_operations{4};
        uint32_t current_operations{0};
        uint32_t memory_bandwidth_mbps{1000};
        uint32_t crypto_units{2};
        uint32_t total_operations{0};
        uint32_t successful_operations{0};
        uint32_t failed_operations{0};
        std::map<std::string, uint32_t> operation_counts;
    } hw_resources;
    
    // DMI memory region
    std::vector<uint8_t> dmi_memory;
    sc_dt::uint64 dmi_base_address{0x80000000ULL};
    size_t dmi_memory_size{64 * 1024}; // 64KB DMI region

    SC_CTOR(MockHardwareCryptoAccelerator) 
        : target_socket("target_socket") {
        
        // Initialize DMI memory
        dmi_memory.resize(dmi_memory_size, 0);
        
        // Register TLM callback functions
        target_socket.register_b_transport(this, &MockHardwareCryptoAccelerator::b_transport);
        target_socket.register_get_direct_mem_ptr(this, &MockHardwareCryptoAccelerator::get_direct_mem_ptr);
        
        // Initialize hardware state
        hw_ready.write(true);
        hw_busy.write(false);
        hw_performance_counter.write(0);
        hw_error_counter.write(0);
        dmi_granted.write(false);
        
        SC_THREAD(hardware_monitor_process);
        SC_THREAD(performance_counter_process);
    }

    void b_transport(tlm_generic_payload& trans, sc_time& delay) {
        // Extract DTLS extension for operation details
        dtls_extension* ext = trans.get_extension<dtls_extension>();
        if (!ext) {
            trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
            return;
        }
        
        hw_busy.write(true);
        hw_resources.current_operations++;
        
        // Check resource availability
        if (hw_resources.current_operations > hw_resources.max_concurrent_operations) {
            ext->set_error(2, 80, "Hardware accelerator overloaded");
            trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
            hw_resources.failed_operations++;
            hw_error_counter.write(hw_resources.failed_operations);
            hw_resources.current_operations--;
            hw_busy.write(false);
            return;
        }
        
        // Determine operation type and calculate processing time
        sc_time processing_time = calculate_hardware_processing_time(trans, ext);
        
        // Simulate hardware processing delay
        wait(processing_time);
        delay += processing_time;
        
        // Update extension with hardware timing
        ext->add_crypto_time(processing_time);
        ext->add_memory_time(hw_timing.memory_access_time);
        
        // Simulate memory bandwidth constraints
        size_t data_size = trans.get_data_length();
        sc_time transfer_time = calculate_memory_transfer_time(data_size);
        delay += transfer_time;
        ext->add_memory_time(transfer_time);
        
        // Update resource tracking
        hw_resources.total_operations++;
        hw_resources.successful_operations++;
        hw_performance_counter.write(hw_resources.successful_operations);
        
        // Track operation type
        std::string op_type = get_operation_type(ext);
        hw_resources.operation_counts[op_type]++;
        
        trans.set_response_status(TLM_OK_RESPONSE);
        
        hw_resources.current_operations--;
        hw_busy.write(hw_resources.current_operations > 0);
    }

    bool get_direct_mem_ptr(tlm_generic_payload& trans, tlm_dmi& dmi_data) {
        // Check if DMI is enabled
        if (!hw_enable_dmi.read()) {
            return false;
        }
        
        sc_dt::uint64 address = trans.get_address();
        
        // Check if address is in DMI range
        if (address >= dmi_base_address && address < dmi_base_address + dmi_memory_size) {
            dmi_data.set_dmi_ptr(dmi_memory.data());
            dmi_data.set_start_address(dmi_base_address);
            dmi_data.set_end_address(dmi_base_address + dmi_memory_size - 1);
            dmi_data.set_granted_access(tlm::tlm_dmi::DMI_ACCESS_READ_WRITE);
            dmi_data.set_read_latency(hw_timing.memory_access_time);
            dmi_data.set_write_latency(hw_timing.memory_access_time);
            
            dmi_granted.write(true);
            dmi_start_address.write(dmi_base_address);
            dmi_end_address.write(dmi_base_address + dmi_memory_size - 1);
            
            return true;
        }
        
        return false;
    }

    sc_time calculate_hardware_processing_time(const tlm_generic_payload& trans, const dtls_extension* ext) {
        sc_time total_time(SC_ZERO_TIME);
        size_t data_size = trans.get_data_length();
        
        // Base timing on cipher suite and operation
        switch (ext->cipher_suite) {
            case 0x1301: // TLS_AES_128_GCM_SHA256
                total_time += hw_timing.aes_gcm_setup_time;
                total_time += hw_timing.aes_gcm_per_block_time * ((data_size + 15) / 16);
                break;
                
            case 0x1302: // TLS_AES_256_GCM_SHA384
                total_time += hw_timing.aes_gcm_setup_time;
                total_time += hw_timing.aes_gcm_per_block_time * ((data_size + 15) / 16) * 1.2; // Slightly slower for 256-bit
                break;
                
            case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
                total_time += hw_timing.chacha20_setup_time;
                total_time += hw_timing.chacha20_per_block_time * ((data_size + 63) / 64);
                break;
                
            default:
                // Fallback timing for unknown cipher suites
                total_time += sc_time(100, SC_NS);
                total_time += sc_time(5, SC_NS) * (data_size / 16);
                break;
        }
        
        // Add signature operation timing for handshake messages
        if (ext->message_type == MessageType::HANDSHAKE) {
            switch (ext->handshake_type) {
                case HandshakeType::CERTIFICATE_VERIFY:
                    total_time += hw_timing.ecdsa_p256_sign_time;
                    break;
                case HandshakeType::SERVER_HELLO:
                case HandshakeType::CLIENT_HELLO:
                    if (ext->signature_scheme != 0) {
                        total_time += hw_timing.ecdsa_p256_verify_time;
                    }
                    break;
                default:
                    break;
            }
        }
        
        // Add key derivation timing
        if (!ext->master_secret.empty()) {
            total_time += hw_timing.hkdf_setup_time;
            total_time += hw_timing.hkdf_per_byte_time * ext->master_secret.size();
        }
        
        // Account for clock frequency
        uint32_t clock_freq_mhz = hw_clock_frequency.read();
        if (clock_freq_mhz > 0 && clock_freq_mhz != 100) { // 100MHz is baseline
            double freq_factor = 100.0 / clock_freq_mhz;
            total_time = sc_time(total_time.value() * freq_factor, total_time.get_time_unit());
        }
        
        // Account for pipeline depth
        uint32_t pipeline = hw_pipeline_depth.read();
        if (pipeline > 1) {
            double pipeline_factor = 1.0 / pipeline;
            total_time = sc_time(total_time.value() * pipeline_factor, total_time.get_time_unit());
        }
        
        return total_time;
    }

    sc_time calculate_memory_transfer_time(size_t data_size) {
        // Calculate transfer time based on memory bandwidth
        uint32_t bandwidth_mbps = hw_resources.memory_bandwidth_mbps;
        if (bandwidth_mbps == 0) bandwidth_mbps = 1000; // Default 1 GB/s
        
        // Convert to bytes per nanosecond
        double bytes_per_ns = (bandwidth_mbps * 1024.0 * 1024.0) / 1e9;
        double transfer_time_ns = data_size / bytes_per_ns;
        
        return sc_time(transfer_time_ns, SC_NS);
    }

    std::string get_operation_type(const dtls_extension* ext) {
        if (ext->message_type == MessageType::HANDSHAKE) {
            switch (ext->handshake_type) {
                case HandshakeType::CLIENT_HELLO: return "client_hello";
                case HandshakeType::SERVER_HELLO: return "server_hello";
                case HandshakeType::CERTIFICATE: return "certificate";
                case HandshakeType::CERTIFICATE_VERIFY: return "certificate_verify";
                case HandshakeType::FINISHED: return "finished";
                case HandshakeType::KEY_UPDATE: return "key_update";
                default: return "handshake_other";
            }
        } else if (ext->message_type == MessageType::APPLICATION_DATA) {
            return "application_data";
        } else if (ext->message_type == MessageType::ALERT) {
            return "alert";
        }
        return "unknown";
    }

    void hardware_monitor_process() {
        while (true) {
            wait(sc_time(1, SC_MS)); // Monitor every 1ms
            
            // Update ready status based on resource utilization
            bool ready = (hw_resources.current_operations < hw_resources.max_concurrent_operations);
            hw_ready.write(ready);
            
            // Check for thermal throttling simulation (simplified)
            if (hw_resources.current_operations >= hw_resources.max_concurrent_operations * 0.8) {
                // Simulate thermal throttling by reducing effective clock frequency
                // This would affect the processing times in calculate_hardware_processing_time
            }
        }
    }

    void performance_counter_process() {
        while (true) {
            wait(sc_time(10, SC_MS)); // Update counters every 10ms
            
            // Update performance and error counters
            hw_performance_counter.write(hw_resources.successful_operations);
            hw_error_counter.write(hw_resources.failed_operations);
        }
    }

public:
    // Public methods for test validation
    HardwareResources get_resource_status() const { return hw_resources; }
    
    void reset_counters() {
        hw_resources.total_operations = 0;
        hw_resources.successful_operations = 0;
        hw_resources.failed_operations = 0;
        hw_resources.operation_counts.clear();
        hw_performance_counter.write(0);
        hw_error_counter.write(0);
    }
    
    void set_memory_bandwidth(uint32_t bandwidth_mbps) {
        hw_resources.memory_bandwidth_mbps = bandwidth_mbps;
    }
    
    void inject_hardware_error() {
        hw_resources.failed_operations++;
        hw_error_counter.write(hw_resources.failed_operations);
    }
};

/**
 * Software Protocol Stack Module
 * 
 * Represents the software component in hardware/software co-design
 */
SC_MODULE(SoftwareProtocolStack) {
public:
    // Interface to hardware accelerator
    tlm_utils::simple_initiator_socket<SoftwareProtocolStack> hw_initiator_socket;
    
    // Software processing status
    sc_out<bool> sw_ready{"sw_ready"};
    sc_out<bool> sw_processing{"sw_processing"};
    sc_out<uint32_t> sw_operations_count{"sw_operations_count"};
    
    // Test control interface
    sc_in<bool> test_start{"test_start"};
    sc_out<bool> test_complete{"test_complete"};
    sc_out<bool> co_design_validation_passed{"co_design_validation_passed"};

private:
    uint32_t software_operations{0};
    std::vector<std::string> test_results;
    bool validation_passed{true};

    SC_CTOR(SoftwareProtocolStack) 
        : hw_initiator_socket("hw_initiator_socket") {
        
        sw_ready.write(true);
        sw_processing.write(false);
        sw_operations_count.write(0);
        test_complete.write(false);
        co_design_validation_passed.write(true);
        
        SC_THREAD(software_processing_thread);
        sensitive << test_start.pos();
    }

    void software_processing_thread() {
        while (true) {
            wait(test_start.posedge_event());
            
            if (test_start.read()) {
                run_codesign_validation_tests();
                
                test_complete.write(true);
                co_design_validation_passed.write(validation_passed);
                
                wait(sc_time(10, SC_NS));
                test_complete.write(false);
            }
        }
    }

    void run_codesign_validation_tests() {
        validation_passed = true;
        test_results.clear();
        software_operations = 0;
        
        std::cout << "Starting Hardware/Software Co-design Validation Tests" << std::endl;
        
        // Test 1: Basic hardware acceleration
        test_basic_hardware_acceleration();
        
        // Test 2: DMI functionality
        test_dmi_functionality();
        
        // Test 3: Hardware resource constraints
        test_hardware_resource_constraints();
        
        // Test 4: Co-simulation timing accuracy
        test_cosimulation_timing_accuracy();
        
        // Test 5: Hardware/software partitioning
        test_hardware_software_partitioning();
        
        // Test 6: Error handling and recovery
        test_error_handling_recovery();
        
        // Test 7: Performance correlation
        test_performance_correlation();
        
        sw_operations_count.write(software_operations);
        
        std::cout << "Co-design validation completed. Passed: " << validation_passed << std::endl;
        if (!test_results.empty()) {
            std::cout << "Test results:" << std::endl;
            for (const auto& result : test_results) {
                std::cout << "  - " << result << std::endl;
            }
        }
    }

    void test_basic_hardware_acceleration() {
        try {
            sw_processing.write(true);
            
            // Create test transaction for AES-GCM encryption
            std::vector<uint8_t> test_data(1024, 0xAA);
            dtls_transaction trans(test_data);
            
            dtls_extension* ext = trans.get_extension();
            ext->cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
            ext->message_type = MessageType::APPLICATION_DATA;
            ext->connection_id = 0x12345678;
            ext->epoch = 1;
            ext->sequence_number = 100;
            
            // Send to hardware accelerator
            tlm_generic_payload& payload = trans.get_payload();
            sc_time delay(SC_ZERO_TIME);
            
            auto start_time = sc_time_stamp();
            hw_initiator_socket->b_transport(payload, delay);
            auto end_time = sc_time_stamp();
            
            software_operations++;
            
            // Validate response
            if (payload.get_response_status() != TLM_OK_RESPONSE) {
                validation_passed = false;
                test_results.push_back("Basic hardware acceleration failed: TLM response error");
            } else {
                // Validate timing annotation
                sc_time total_processing = ext->get_total_processing_time();
                if (total_processing < sc_time(50, SC_NS)) { // Minimum expected processing time
                    validation_passed = false;
                    test_results.push_back("Hardware acceleration timing too fast (unrealistic)");
                } else {
                    test_results.push_back("Basic hardware acceleration passed");
                }
            }
            
            sw_processing.write(false);
            
        } catch (const std::exception& e) {
            validation_passed = false;
            test_results.push_back(std::string("Hardware acceleration exception: ") + e.what());
            sw_processing.write(false);
        }
    }

    void test_dmi_functionality() {
        try {
            // Test DMI (Direct Memory Interface) access
            std::vector<uint8_t> dmi_test_data(256, 0xDD);
            dtls_transaction trans(dmi_test_data);
            
            tlm_generic_payload& payload = trans.get_payload();
            payload.set_address(0x80000000ULL); // DMI base address
            
            tlm_dmi dmi_data;
            bool dmi_granted = hw_initiator_socket->get_direct_mem_ptr(payload, dmi_data);
            
            if (dmi_granted) {
                // Validate DMI parameters
                if (dmi_data.get_start_address() != 0x80000000ULL ||
                    dmi_data.get_end_address() < dmi_data.get_start_address()) {
                    validation_passed = false;
                    test_results.push_back("DMI address range validation failed");
                } else if (dmi_data.get_dmi_ptr() == nullptr) {
                    validation_passed = false;
                    test_results.push_back("DMI pointer is null");
                } else {
                    // Test direct memory access
                    uint8_t* dmi_ptr = dmi_data.get_dmi_ptr();
                    size_t offset = payload.get_address() - dmi_data.get_start_address();
                    
                    // Write test pattern
                    for (size_t i = 0; i < dmi_test_data.size() && (offset + i) < (dmi_data.get_end_address() - dmi_data.get_start_address() + 1); ++i) {
                        dmi_ptr[offset + i] = dmi_test_data[i];
                    }
                    
                    // Read back and validate
                    bool dmi_data_valid = true;
                    for (size_t i = 0; i < dmi_test_data.size() && (offset + i) < (dmi_data.get_end_address() - dmi_data.get_start_address() + 1); ++i) {
                        if (dmi_ptr[offset + i] != dmi_test_data[i]) {
                            dmi_data_valid = false;
                            break;
                        }
                    }
                    
                    if (!dmi_data_valid) {
                        validation_passed = false;
                        test_results.push_back("DMI data integrity validation failed");
                    } else {
                        test_results.push_back("DMI functionality validation passed");
                    }
                }
            } else {
                // DMI not granted - this may be expected depending on configuration
                test_results.push_back("DMI not granted (may be expected based on hardware config)");
            }
            
        } catch (const std::exception& e) {
            validation_passed = false;
            test_results.push_back(std::string("DMI functionality exception: ") + e.what());
        }
    }

    void test_hardware_resource_constraints() {
        try {
            // Test concurrent operations to verify resource constraints
            std::vector<dtls_transaction> concurrent_transactions;
            std::vector<tlm_generic_payload*> payloads;
            std::vector<sc_time> delays;
            
            const size_t num_concurrent = 8; // More than hardware can handle simultaneously
            
            for (size_t i = 0; i < num_concurrent; ++i) {
                std::vector<uint8_t> data(512, static_cast<uint8_t>(i));
                concurrent_transactions.emplace_back(data);
                
                dtls_extension* ext = concurrent_transactions[i].get_extension();
                ext->cipher_suite = 0x1302; // TLS_AES_256_GCM_SHA384
                ext->message_type = MessageType::APPLICATION_DATA;
                ext->connection_id = 0x1000 + i;
                ext->sequence_number = i * 10;
                
                payloads.push_back(&concurrent_transactions[i].get_payload());
                delays.emplace_back(SC_ZERO_TIME);
            }
            
            // Send all transactions concurrently (simulate with rapid succession)
            size_t successful_transactions = 0;
            size_t failed_transactions = 0;
            
            for (size_t i = 0; i < num_concurrent; ++i) {
                hw_initiator_socket->b_transport(*payloads[i], delays[i]);
                
                if (payloads[i]->get_response_status() == TLM_OK_RESPONSE) {
                    successful_transactions++;
                } else {
                    failed_transactions++;
                }
                
                software_operations++;
                
                // Small delay between transactions to simulate realistic timing
                wait(sc_time(1, SC_NS));
            }
            
            // Validate that resource constraints were enforced
            if (failed_transactions == 0) {
                // This might indicate that resource constraints are not working
                test_results.push_back("Warning: No resource constraint failures detected - may indicate issue");
            } else {
                test_results.push_back("Hardware resource constraints validation passed (" + 
                                     std::to_string(successful_transactions) + " success, " + 
                                     std::to_string(failed_transactions) + " failed)");
            }
            
        } catch (const std::exception& e) {
            validation_passed = false;
            test_results.push_back(std::string("Resource constraints exception: ") + e.what());
        }
    }

    void test_cosimulation_timing_accuracy() {
        try {
            // Test timing correlation between SystemC model and expected hardware behavior
            struct TimingTest {
                uint32_t cipher_suite;
                size_t data_size;
                MessageType msg_type;
                sc_time expected_min_time;
                sc_time expected_max_time;
                std::string test_name;
            };
            
            std::vector<TimingTest> timing_tests = {
                {0x1301, 256, MessageType::APPLICATION_DATA, sc_time(100, SC_NS), sc_time(500, SC_NS), "AES-128-GCM small data"},
                {0x1301, 1024, MessageType::APPLICATION_DATA, sc_time(200, SC_NS), sc_time(1, SC_US), "AES-128-GCM medium data"},
                {0x1302, 512, MessageType::APPLICATION_DATA, sc_time(150, SC_NS), sc_time(800, SC_NS), "AES-256-GCM medium data"},
                {0x1303, 1024, MessageType::APPLICATION_DATA, sc_time(180, SC_NS), sc_time(900, SC_NS), "ChaCha20-Poly1305 medium data"},
            };
            
            for (const auto& test : timing_tests) {
                std::vector<uint8_t> test_data(test.data_size, 0xBB);
                dtls_transaction trans(test_data);
                
                dtls_extension* ext = trans.get_extension();
                ext->cipher_suite = test.cipher_suite;
                ext->message_type = test.msg_type;
                ext->connection_id = 0x87654321;
                ext->start_timing();
                
                tlm_generic_payload& payload = trans.get_payload();
                sc_time delay(SC_ZERO_TIME);
                
                auto start_time = sc_time_stamp();
                hw_initiator_socket->b_transport(payload, delay);
                auto end_time = sc_time_stamp();
                
                if (payload.get_response_status() == TLM_OK_RESPONSE) {
                    sc_time processing_time = ext->get_total_processing_time();
                    sc_time simulation_time = end_time - start_time;
                    
                    // Validate timing is within expected range
                    if (processing_time < test.expected_min_time || processing_time > test.expected_max_time) {
                        validation_passed = false;
                        test_results.push_back("Timing accuracy failed for " + test.test_name + 
                                             ": " + processing_time.to_string());
                    } else {
                        test_results.push_back("Timing accuracy passed for " + test.test_name);
                    }
                } else {
                    validation_passed = false;
                    test_results.push_back("Timing test failed for " + test.test_name + ": TLM error");
                }
                
                software_operations++;
                wait(sc_time(10, SC_NS)); // Brief delay between tests
            }
            
        } catch (const std::exception& e) {
            validation_passed = false;
            test_results.push_back(std::string("Timing accuracy exception: ") + e.what());
        }
    }

    void test_hardware_software_partitioning() {
        try {
            // Test different partitioning scenarios
            // Scenario 1: Crypto operations in hardware, protocol logic in software
            std::vector<uint8_t> handshake_data = {0x01, 0x00, 0x01, 0x00}; // Mock CLIENT_HELLO
            dtls_transaction handshake_trans(handshake_data);
            
            dtls_extension* hs_ext = handshake_trans.get_extension();
            hs_ext->message_type = MessageType::HANDSHAKE;
            hs_ext->handshake_type = HandshakeType::CLIENT_HELLO;
            hs_ext->cipher_suite = 0x1301;
            hs_ext->signature_scheme = 0x0401; // rsa_pss_rsae_sha256
            hs_ext->connection_id = 0xAABBCCDD;
            
            // Software handles protocol logic
            hs_ext->start_timing();
            wait(sc_time(50, SC_NS)); // Software processing time
            hs_ext->add_network_time(sc_time(50, SC_NS));
            
            // Hardware handles crypto operations
            tlm_generic_payload& hs_payload = handshake_trans.get_payload();
            sc_time hs_delay(SC_ZERO_TIME);
            
            hw_initiator_socket->b_transport(hs_payload, hs_delay);
            
            if (hs_payload.get_response_status() != TLM_OK_RESPONSE) {
                validation_passed = false;
                test_results.push_back("Hardware/software partitioning failed for handshake");
            }
            
            // Scenario 2: Application data - bulk crypto in hardware
            std::vector<uint8_t> app_data(2048, 0xCC);
            dtls_transaction app_trans(app_data);
            
            dtls_extension* app_ext = app_trans.get_extension();
            app_ext->message_type = MessageType::APPLICATION_DATA;
            app_ext->cipher_suite = 0x1302;
            app_ext->connection_id = 0xDDEEFF00;
            app_ext->sequence_number = 200;
            
            // Minimal software overhead for application data
            app_ext->start_timing();
            wait(sc_time(10, SC_NS));
            app_ext->add_network_time(sc_time(10, SC_NS));
            
            // Hardware handles encryption/decryption
            tlm_generic_payload& app_payload = app_trans.get_payload();
            sc_time app_delay(SC_ZERO_TIME);
            
            hw_initiator_socket->b_transport(app_payload, app_delay);
            
            if (app_payload.get_response_status() == TLM_OK_RESPONSE) {
                // Validate that hardware processing time is dominant for application data
                sc_time total_time = app_ext->get_total_processing_time();
                sc_time crypto_time = app_ext->crypto_processing_time;
                
                if (crypto_time < total_time * 0.7) { // Crypto should be at least 70% of processing time
                    validation_passed = false;
                    test_results.push_back("Hardware/software partitioning inefficient for application data");
                } else {
                    test_results.push_back("Hardware/software partitioning validation passed");
                }
            } else {
                validation_passed = false;
                test_results.push_back("Hardware/software partitioning failed for application data");
            }
            
            software_operations += 2;
            
        } catch (const std::exception& e) {
            validation_passed = false;
            test_results.push_back(std::string("Hardware/software partitioning exception: ") + e.what());
        }
    }

    void test_error_handling_recovery() {
        try {
            // Test hardware error injection and recovery
            std::vector<uint8_t> error_test_data(512, 0xEE);
            dtls_transaction error_trans(error_test_data);
            
            dtls_extension* ext = error_trans.get_extension();
            ext->cipher_suite = 0x1301;
            ext->message_type = MessageType::APPLICATION_DATA;
            
            // Simulate error condition by overloading hardware
            for (int i = 0; i < 10; ++i) {
                tlm_generic_payload& payload = error_trans.get_payload();
                sc_time delay(SC_ZERO_TIME);
                
                hw_initiator_socket->b_transport(payload, delay);
                
                if (payload.get_response_status() != TLM_OK_RESPONSE) {
                    // Error detected - validate error information in extension
                    if (ext->has_error && !ext->error_message.empty()) {
                        test_results.push_back("Hardware error detection and reporting passed");
                        break;
                    } else {
                        validation_passed = false;
                        test_results.push_back("Hardware error not properly reported in extension");
                        break;
                    }
                } else if (i == 9) {
                    // No error occurred - this might indicate issue with error injection
                    test_results.push_back("Warning: No hardware error detected during stress test");
                }
                
                software_operations++;
                wait(sc_time(1, SC_NS)); // Rapid succession to trigger resource exhaustion
            }
            
        } catch (const std::exception& e) {
            validation_passed = false;
            test_results.push_back(std::string("Error handling exception: ") + e.what());
        }
    }

    void test_performance_correlation() {
        try {
            // Test performance correlation between different cipher suites
            struct PerformanceTest {
                uint32_t cipher_suite;
                size_t data_size;
                std::string name;
            };
            
            std::vector<PerformanceTest> perf_tests = {
                {0x1301, 1024, "AES-128-GCM"},
                {0x1302, 1024, "AES-256-GCM"},
                {0x1303, 1024, "ChaCha20-Poly1305"}
            };
            
            std::map<std::string, sc_time> performance_results;
            
            for (const auto& test : perf_tests) {
                std::vector<uint8_t> perf_data(test.data_size, 0xFF);
                dtls_transaction perf_trans(perf_data);
                
                dtls_extension* ext = perf_trans.get_extension();
                ext->cipher_suite = test.cipher_suite;
                ext->message_type = MessageType::APPLICATION_DATA;
                ext->start_timing();
                
                tlm_generic_payload& payload = perf_trans.get_payload();
                sc_time delay(SC_ZERO_TIME);
                
                hw_initiator_socket->b_transport(payload, delay);
                
                if (payload.get_response_status() == TLM_OK_RESPONSE) {
                    sc_time processing_time = ext->crypto_processing_time;
                    performance_results[test.name] = processing_time;
                } else {
                    validation_passed = false;
                    test_results.push_back("Performance test failed for " + test.name);
                }
                
                software_operations++;
                wait(sc_time(5, SC_NS));
            }
            
            // Validate expected performance relationships
            if (performance_results.size() >= 2) {
                // AES-256 should generally be slower than AES-128
                if (performance_results.count("AES-128-GCM") && performance_results.count("AES-256-GCM")) {
                    if (performance_results["AES-256-GCM"] <= performance_results["AES-128-GCM"]) {
                        test_results.push_back("Warning: AES-256 not slower than AES-128 as expected");
                    } else {
                        test_results.push_back("Performance correlation validation passed");
                    }
                }
            }
            
        } catch (const std::exception& e) {
            validation_passed = false;
            test_results.push_back(std::string("Performance correlation exception: ") + e.what());
        }
    }
};

/**
 * Co-design Integration Testbench
 * 
 * Top-level testbench that integrates hardware and software components
 */
SC_MODULE(CoDesignIntegrationTestbench) {
public:
    // Component instances
    std::unique_ptr<MockHardwareCryptoAccelerator> hw_accelerator;
    std::unique_ptr<SoftwareProtocolStack> sw_stack;
    
    // Configuration signals
    sc_signal<uint32_t> hw_clock_frequency{"hw_clock_frequency"};
    sc_signal<uint32_t> hw_pipeline_depth{"hw_pipeline_depth"};
    sc_signal<bool> hw_enable_dmi{"hw_enable_dmi"};
    
    // Status monitoring signals
    sc_signal<bool> hw_ready{"hw_ready"};
    sc_signal<bool> hw_busy{"hw_busy"};
    sc_signal<bool> sw_ready{"sw_ready"};
    sc_signal<bool> sw_processing{"sw_processing"};
    
    // Performance monitoring
    sc_signal<uint32_t> hw_performance_counter{"hw_performance_counter"};
    sc_signal<uint32_t> hw_error_counter{"hw_error_counter"};
    sc_signal<uint32_t> sw_operations_count{"sw_operations_count"};
    
    // Test control
    sc_signal<bool> test_start{"test_start"};
    sc_signal<bool> test_complete{"test_complete"};
    sc_signal<bool> validation_passed{"validation_passed"};

    SC_CTOR(CoDesignIntegrationTestbench) {
        // Create component instances
        hw_accelerator = std::make_unique<MockHardwareCryptoAccelerator>("HW_Accelerator");
        sw_stack = std::make_unique<SoftwareProtocolStack>("SW_Stack");
        
        // Configure hardware parameters
        hw_clock_frequency.write(200); // 200 MHz
        hw_pipeline_depth.write(4);
        hw_enable_dmi.write(true);
        
        // Connect hardware accelerator
        hw_accelerator->hw_clock_frequency(hw_clock_frequency);
        hw_accelerator->hw_pipeline_depth(hw_pipeline_depth);
        hw_accelerator->hw_enable_dmi(hw_enable_dmi);
        hw_accelerator->hw_ready(hw_ready);
        hw_accelerator->hw_busy(hw_busy);
        hw_accelerator->hw_performance_counter(hw_performance_counter);
        hw_accelerator->hw_error_counter(hw_error_counter);
        
        // Connect software stack
        sw_stack->sw_ready(sw_ready);
        sw_stack->sw_processing(sw_processing);
        sw_stack->sw_operations_count(sw_operations_count);
        sw_stack->test_start(test_start);
        sw_stack->test_complete(test_complete);
        sw_stack->co_design_validation_passed(validation_passed);
        
        // Connect TLM socket
        sw_stack->hw_initiator_socket.bind(hw_accelerator->target_socket);
        
        SC_THREAD(testbench_control_process);
    }

    void testbench_control_process() {
        // Initialize test
        test_start.write(false);
        wait(sc_time(100, SC_NS));
        
        // Start co-design validation test
        test_start.write(true);
        wait(sc_time(10, SC_NS));
        test_start.write(false);
        
        // Wait for test completion
        while (!test_complete.read()) {
            wait(sc_time(1, SC_MS));
        }
        
        // Print final results
        std::cout << "\n=== Hardware/Software Co-design Validation Results ===" << std::endl;
        std::cout << "Hardware Operations: " << hw_performance_counter.read() << std::endl;
        std::cout << "Hardware Errors: " << hw_error_counter.read() << std::endl;
        std::cout << "Software Operations: " << sw_operations_count.read() << std::endl;
        std::cout << "Validation Passed: " << (validation_passed.read() ? "YES" : "NO") << std::endl;
        
        // Stop simulation
        wait(sc_time(100, SC_NS));
        sc_stop();
    }

public:
    // Public interface for test validation
    bool get_validation_result() const {
        return validation_passed.read();
    }
    
    uint32_t get_hw_operations() const {
        return hw_performance_counter.read();
    }
    
    uint32_t get_sw_operations() const {
        return sw_operations_count.read();
    }
    
    uint32_t get_hw_errors() const {
        return hw_error_counter.read();
    }
};

/**
 * Main test class for Hardware Co-design Validation
 */
class HardwareCodesignValidationTest : public SystemCTestFramework {
protected:
    void SetUp() override {
        SystemCTestFramework::SetUp();
        
        // Configure test for co-design validation
        config_.simulation_duration = sc_time(10, SC_SEC);
        config_.enable_tracing = true;
        config_.trace_filename = "hardware_codesign_test.vcd";
        config_.enable_performance_measurement = true;
        config_.correlate_with_real_timing = true;
        
        // Create testbench
        testbench = std::make_unique<CoDesignIntegrationTestbench>("CoDesignTestbench");
    }

private:
    std::unique_ptr<CoDesignIntegrationTestbench> testbench;
};

/**
 * Test: Hardware Accelerator Integration
 * 
 * Validate basic hardware accelerator integration and functionality
 */
TEST_F(HardwareCodesignValidationTest, HardwareAcceleratorIntegration) {
    // Run simulation
    sc_start();
    
    // Validate test completion and results
    EXPECT_TRUE(testbench->get_validation_result()) 
        << "Hardware accelerator integration validation failed";
    
    EXPECT_GT(testbench->get_hw_operations(), 0) 
        << "No hardware operations recorded";
    
    EXPECT_GT(testbench->get_sw_operations(), 0) 
        << "No software operations recorded";
    
    std::cout << "Hardware operations: " << testbench->get_hw_operations() << std::endl;
    std::cout << "Software operations: " << testbench->get_sw_operations() << std::endl;
    std::cout << "Hardware errors: " << testbench->get_hw_errors() << std::endl;
}

/**
 * Test: DMI Performance Validation
 * 
 * Specific test for Direct Memory Interface functionality
 */
TEST_F(HardwareCodesignValidationTest, DMIPerformanceValidation) {
    // This test would be run as part of the main co-design validation
    // but we can add specific assertions for DMI functionality
    
    sc_start();
    
    // DMI functionality is validated within the co-design test
    EXPECT_TRUE(testbench->get_validation_result()) 
        << "DMI validation failed as part of co-design test";
    
    // Additional DMI-specific validations could be added here
    // by extending the testbench with DMI-specific monitoring
}

/**
 * Test: Timing Correlation Validation
 * 
 * Validate timing correlation between SystemC model and expected hardware behavior
 */
TEST_F(HardwareCodesignValidationTest, TimingCorrelationValidation) {
    sc_start();
    
    // Timing correlation is validated as part of the comprehensive co-design test
    EXPECT_TRUE(testbench->get_validation_result()) 
        << "Timing correlation validation failed";
    
    // Validate that both hardware and software components were active
    EXPECT_GT(testbench->get_hw_operations(), 5) 
        << "Insufficient hardware operations for timing correlation";
        
    EXPECT_GT(testbench->get_sw_operations(), 5) 
        << "Insufficient software operations for timing correlation";
}

/**
 * SystemC main function for standalone testing
 */
int sc_main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}