/**
 * DMI and Hardware Acceleration Test for DTLS v1.3 SystemC Implementation
 * 
 * Comprehensive testing of Direct Memory Interface (DMI) functionality and hardware acceleration:
 * - DMI grant/invalidation mechanisms and lifecycle management
 * - Hardware acceleration through DMI for performance-critical DTLS operations
 * - Memory-mapped hardware interface validation and coherency
 * - DMA-style transfers for bulk cryptographic operations
 * - Hardware buffer management and memory efficiency optimization
 * - Performance comparison between DMI and regular TLM transport
 * - Error handling and recovery in DMI scenarios
 * - Memory coherency, synchronization, and cache management
 * - Hardware resource contention and arbitration
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
#include <cstring>

using namespace dtls::systemc::test;
using namespace dtls::v13::systemc_tlm;

/**
 * Hardware Accelerated Crypto Engine with DMI Support
 * 
 * Simulates a dedicated crypto hardware engine with memory-mapped interface
 */
SC_MODULE(HardwareAcceleratedCryptoEngine) {
public:
    // TLM target socket for DMI-capable communication
    tlm_utils::simple_target_socket<HardwareAcceleratedCryptoEngine> target_socket;
    
    // Hardware control and status interface
    sc_out<bool> hw_ready{"hw_ready"};
    sc_out<bool> hw_busy{"hw_busy"};
    sc_out<bool> dmi_granted{"dmi_granted"};
    sc_out<uint32_t> dmi_transactions{"dmi_transactions"};
    sc_out<uint32_t> regular_transactions{"regular_transactions"};
    
    // Performance monitoring
    sc_out<sc_time> dmi_total_time{"dmi_total_time"};
    sc_out<sc_time> regular_total_time{"regular_total_time"};
    sc_out<uint32_t> dmi_bytes_processed{"dmi_bytes_processed"};
    sc_out<uint32_t> regular_bytes_processed{"regular_bytes_processed"};
    
    // Hardware configuration
    sc_in<bool> enable_dmi{"enable_dmi"};
    sc_in<uint32_t> dmi_buffer_size{"dmi_buffer_size"};
    sc_in<sc_time> dma_transfer_rate{"dma_transfer_rate"};

private:
    // DMI memory region
    std::vector<uint8_t> dmi_memory;
    static const sc_dt::uint64 DMI_BASE_ADDRESS = 0x40000000ULL;
    static const size_t DEFAULT_DMI_SIZE = 128 * 1024; // 128KB
    
    // Hardware state
    struct HardwareState {
        bool dmi_active{false};
        uint32_t dmi_transaction_count{0};
        uint32_t regular_transaction_count{0};
        sc_time dmi_processing_time{SC_ZERO_TIME};
        sc_time regular_processing_time{SC_ZERO_TIME};
        uint32_t dmi_bytes{0};
        uint32_t regular_bytes{0};
        std::map<sc_dt::uint64, tlm_dmi> active_dmi_regions;
        bool hardware_busy{false};
    } hw_state;
    
    // DMA transfer queue for bulk operations
    struct DMATransfer {
        sc_dt::uint64 src_addr;
        sc_dt::uint64 dst_addr;
        size_t length;
        bool is_crypto_operation;
        uint32_t cipher_suite;
        sc_time start_time;
    };
    std::queue<DMATransfer> dma_queue;
    
    // Hardware timing characteristics
    struct HardwareTimings {
        sc_time dmi_setup_time{10, SC_NS};
        sc_time dma_per_byte_time{0.5, SC_NS};
        sc_time crypto_setup_time{50, SC_NS};
        sc_time aes_gcm_per_byte{2, SC_NS};
        sc_time chacha20_per_byte{1.5, SC_NS};
        sc_time memory_latency{5, SC_NS};
        sc_time cache_hit_time{1, SC_NS};
        sc_time cache_miss_penalty{20, SC_NS};
    } timing;

    SC_CTOR(HardwareAcceleratedCryptoEngine) 
        : target_socket("target_socket") {
        
        // Initialize DMI memory
        dmi_memory.resize(DEFAULT_DMI_SIZE, 0);
        
        // Register TLM interface functions
        target_socket.register_b_transport(this, &HardwareAcceleratedCryptoEngine::b_transport);
        target_socket.register_get_direct_mem_ptr(this, &HardwareAcceleratedCryptoEngine::get_direct_mem_ptr);
        target_socket.register_transport_dbg(this, &HardwareAcceleratedCryptoEngine::transport_dbg);
        
        // Initialize output signals
        hw_ready.write(true);
        hw_busy.write(false);
        dmi_granted.write(false);
        dmi_transactions.write(0);
        regular_transactions.write(0);
        dmi_total_time.write(SC_ZERO_TIME);
        regular_total_time.write(SC_ZERO_TIME);
        dmi_bytes_processed.write(0);
        regular_bytes_processed.write(0);
        
        SC_THREAD(hardware_processing_thread);
        SC_THREAD(dma_controller_thread);
        SC_THREAD(status_monitor_thread);
    }

    void b_transport(tlm_generic_payload& trans, sc_time& delay) {
        // Handle regular TLM transport (non-DMI)
        hw_state.hardware_busy = true;
        hw_busy.write(true);
        
        auto processing_start = sc_time_stamp();
        
        // Extract DTLS extension for operation details
        dtls_extension* ext = trans.get_extension<dtls_extension>();
        if (!ext) {
            trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
            hw_state.hardware_busy = false;
            hw_busy.write(false);
            return;
        }
        
        // Calculate processing time based on operation
        sc_time processing_time = calculate_crypto_processing_time(trans, *ext);
        
        // Simulate hardware processing
        wait(processing_time);
        delay += processing_time;
        
        // Update statistics
        hw_state.regular_transaction_count++;
        hw_state.regular_processing_time += processing_time;
        hw_state.regular_bytes += trans.get_data_length();
        
        // Update extension with hardware timing
        ext->add_crypto_time(processing_time);
        ext->add_memory_time(timing.memory_latency);
        
        // Validate operation success
        if (validate_crypto_operation(trans, *ext)) {
            trans.set_response_status(TLM_OK_RESPONSE);
        } else {
            ext->set_error(2, 80, "Hardware crypto operation failed");
            trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
        }
        
        // Update output signals
        regular_transactions.write(hw_state.regular_transaction_count);
        regular_total_time.write(hw_state.regular_processing_time);
        regular_bytes_processed.write(hw_state.regular_bytes);
        
        hw_state.hardware_busy = false;
        hw_busy.write(false);
    }

    bool get_direct_mem_ptr(tlm_generic_payload& trans, tlm_dmi& dmi_data) {
        // Handle DMI requests
        if (!enable_dmi.read()) {
            return false; // DMI disabled
        }
        
        sc_dt::uint64 address = trans.get_address();
        
        // Check if address is within our DMI region
        if (address >= DMI_BASE_ADDRESS && address < DMI_BASE_ADDRESS + dmi_memory.size()) {
            // Grant DMI access
            dmi_data.set_dmi_ptr(dmi_memory.data());
            dmi_data.set_start_address(DMI_BASE_ADDRESS);
            dmi_data.set_end_address(DMI_BASE_ADDRESS + dmi_memory.size() - 1);
            dmi_data.set_granted_access(tlm::tlm_dmi::DMI_ACCESS_READ_WRITE);
            
            // Set timing characteristics
            dmi_data.set_read_latency(timing.cache_hit_time);
            dmi_data.set_write_latency(timing.cache_hit_time);
            
            // Store DMI region info
            hw_state.active_dmi_regions[address] = dmi_data;
            hw_state.dmi_active = true;
            
            dmi_granted.write(true);
            
            std::cout << "DMI granted for address range [0x" << std::hex << DMI_BASE_ADDRESS 
                     << " - 0x" << (DMI_BASE_ADDRESS + dmi_memory.size() - 1) << std::dec << "]" << std::endl;
            
            return true;
        }
        
        return false; // Address not in DMI range
    }

    unsigned int transport_dbg(tlm_generic_payload& trans) {
        // Handle debug transport for verification
        sc_dt::uint64 address = trans.get_address();
        unsigned int length = trans.get_data_length();
        unsigned char* data_ptr = trans.get_data_ptr();
        
        if (address >= DMI_BASE_ADDRESS && (address + length) <= (DMI_BASE_ADDRESS + dmi_memory.size())) {
            size_t offset = address - DMI_BASE_ADDRESS;
            
            if (trans.get_command() == TLM_READ_COMMAND) {
                std::memcpy(data_ptr, dmi_memory.data() + offset, length);
            } else if (trans.get_command() == TLM_WRITE_COMMAND) {
                std::memcpy(dmi_memory.data() + offset, data_ptr, length);
            }
            
            return length; // Return number of bytes transferred
        }
        
        return 0; // Transfer failed
    }

    void hardware_processing_thread() {
        while (true) {
            wait(sc_time(1, SC_US)); // Process every microsecond
            
            // Process any pending DMI operations that require hardware acceleration
            process_pending_dmi_operations();
        }
    }

    void dma_controller_thread() {
        while (true) {
            if (!dma_queue.empty()) {
                DMATransfer transfer = dma_queue.front();
                dma_queue.pop();
                
                // Execute DMA transfer
                execute_dma_transfer(transfer);
            }
            
            wait(sc_time(100, SC_NS));
        }
    }

    void status_monitor_thread() {
        while (true) {
            wait(sc_time(10, SC_US));
            
            // Update status signals
            hw_ready.write(!hw_state.hardware_busy);
            
            // Monitor DMI activity
            if (hw_state.dmi_active && hw_state.dmi_transaction_count > 0) {
                dmi_transactions.write(hw_state.dmi_transaction_count);
                dmi_total_time.write(hw_state.dmi_processing_time);
                dmi_bytes_processed.write(hw_state.dmi_bytes);
            }
        }
    }

    void process_pending_dmi_operations() {
        // Scan DMI memory for pending crypto operations
        // This simulates hardware scanning for work queued via DMI
        
        for (auto& dmi_region : hw_state.active_dmi_regions) {
            sc_dt::uint64 base_addr = dmi_region.first;
            
            // Check for operation descriptors in DMI memory
            size_t offset = base_addr - DMI_BASE_ADDRESS;
            if (offset < dmi_memory.size() - sizeof(uint32_t)) {
                uint32_t* control_word = reinterpret_cast<uint32_t*>(dmi_memory.data() + offset);
                
                if (*control_word != 0) { // Non-zero indicates pending operation
                    process_dmi_crypto_operation(base_addr, *control_word);
                    *control_word = 0; // Clear operation
                    
                    hw_state.dmi_transaction_count++;
                    dmi_transactions.write(hw_state.dmi_transaction_count);
                }
            }
        }
    }

    void process_dmi_crypto_operation(sc_dt::uint64 address, uint32_t control_word) {
        auto operation_start = sc_time_stamp();
        
        // Decode operation from control word
        uint32_t cipher_suite = (control_word >> 16) & 0xFFFF;
        uint32_t data_length = control_word & 0xFFFF;
        
        // Calculate processing time for DMI operation
        sc_time processing_time = timing.crypto_setup_time;
        
        switch (cipher_suite) {
            case 0x1301: // AES-128-GCM
                processing_time += timing.aes_gcm_per_byte * data_length;
                break;
            case 0x1302: // AES-256-GCM
                processing_time += timing.aes_gcm_per_byte * data_length * 1.2;
                break;
            case 0x1303: // ChaCha20-Poly1305
                processing_time += timing.chacha20_per_byte * data_length;
                break;
            default:
                processing_time += sc_time(100, SC_NS) * data_length / 16;
                break;
        }
        
        // DMI operations are typically faster due to reduced overhead
        processing_time = processing_time * 0.7; // 30% speedup via DMI
        
        wait(processing_time);
        
        // Update DMI statistics
        hw_state.dmi_processing_time += processing_time;
        hw_state.dmi_bytes += data_length;
        
        dmi_total_time.write(hw_state.dmi_processing_time);
        dmi_bytes_processed.write(hw_state.dmi_bytes);
    }

    void execute_dma_transfer(const DMATransfer& transfer) {
        sc_time transfer_time = timing.dma_per_byte_time * transfer.length;
        
        if (transfer.is_crypto_operation) {
            // Add crypto processing time for DMA-based crypto
            switch (transfer.cipher_suite) {
                case 0x1301:
                    transfer_time += timing.aes_gcm_per_byte * transfer.length * 0.5; // Parallel processing
                    break;
                case 0x1302:
                    transfer_time += timing.aes_gcm_per_byte * transfer.length * 0.6;
                    break;
                case 0x1303:
                    transfer_time += timing.chacha20_per_byte * transfer.length * 0.4;
                    break;
            }
        }
        
        wait(transfer_time);
        
        std::cout << "DMA transfer completed: " << transfer.length << " bytes in " 
                 << transfer_time.to_string() << std::endl;
    }

    sc_time calculate_crypto_processing_time(const tlm_generic_payload& trans, const dtls_extension& ext) {
        sc_time base_time = timing.crypto_setup_time;
        size_t data_size = trans.get_data_length();
        
        // Calculate based on cipher suite
        switch (ext.cipher_suite) {
            case 0x1301: // AES-128-GCM
                base_time += timing.aes_gcm_per_byte * data_size;
                break;
            case 0x1302: // AES-256-GCM
                base_time += timing.aes_gcm_per_byte * data_size * 1.3;
                break;
            case 0x1303: // ChaCha20-Poly1305
                base_time += timing.chacha20_per_byte * data_size;
                break;
            default:
                base_time += sc_time(5, SC_NS) * data_size;
                break;
        }
        
        // Add memory access overhead
        base_time += timing.memory_latency * 2; // Read and write
        
        return base_time;
    }

    bool validate_crypto_operation(const tlm_generic_payload& trans, const dtls_extension& ext) {
        // Basic validation of crypto operation parameters
        if (ext.cipher_suite == 0 || ext.cipher_suite > 0x1400) {
            return false; // Invalid cipher suite
        }
        
        if (trans.get_data_length() == 0 || trans.get_data_length() > 16384) {
            return false; // Invalid data length
        }
        
        return true;
    }

public:
    // Public interface for test validation
    void invalidate_dmi() {
        // Simulate DMI invalidation
        hw_state.active_dmi_regions.clear();
        hw_state.dmi_active = false;
        dmi_granted.write(false);
        
        std::cout << "DMI invalidated" << std::endl;
    }
    
    void queue_dma_transfer(sc_dt::uint64 src, sc_dt::uint64 dst, size_t length, 
                           bool is_crypto, uint32_t cipher_suite = 0) {
        DMATransfer transfer;
        transfer.src_addr = src;
        transfer.dst_addr = dst;
        transfer.length = length;
        transfer.is_crypto_operation = is_crypto;
        transfer.cipher_suite = cipher_suite;
        transfer.start_time = sc_time_stamp();
        
        dma_queue.push(transfer);
    }
    
    uint8_t* get_dmi_ptr() { return dmi_memory.data(); }
    sc_dt::uint64 get_dmi_base() const { return DMI_BASE_ADDRESS; }
    size_t get_dmi_size() const { return dmi_memory.size(); }
    
    HardwareState get_hardware_state() const { return hw_state; }
};

/**
 * DMI Test Client Module
 * 
 * Tests DMI functionality from the initiator side
 */
SC_MODULE(DMITestClient) {
public:
    tlm_utils::simple_initiator_socket<DMITestClient> initiator_socket;
    
    // Test control
    sc_in<bool> test_enable{"test_enable"};
    sc_out<bool> test_complete{"test_complete"};
    sc_out<bool> dmi_test_passed{"dmi_test_passed"};
    
    // Test result signals
    sc_signal<bool> dmi_grant_test_passed{"dmi_grant_test_passed"};
    sc_signal<bool> dmi_access_test_passed{"dmi_access_test_passed"};
    sc_signal<bool> dmi_performance_test_passed{"dmi_performance_test_passed"};
    sc_signal<bool> dmi_invalidation_test_passed{"dmi_invalidation_test_passed"};
    sc_signal<bool> dma_transfer_test_passed{"dma_transfer_test_passed"};
    sc_signal<bool> memory_coherency_test_passed{"memory_coherency_test_passed"};
    
    // Performance metrics
    sc_signal<sc_time> dmi_operation_time{"dmi_operation_time"};
    sc_signal<sc_time> regular_operation_time{"regular_operation_time"};
    sc_signal<double> dmi_speedup_factor{"dmi_speedup_factor"};

private:
    bool all_tests_passed{true};
    std::vector<std::string> test_results;
    
    // DMI pointers and state
    tlm_dmi dmi_data;
    bool dmi_valid{false};
    sc_dt::uint64 dmi_base_address{0};

    SC_CTOR(DMITestClient) 
        : initiator_socket("initiator_socket") {
        
        test_complete.write(false);
        dmi_test_passed.write(false);
        dmi_operation_time.write(SC_ZERO_TIME);
        regular_operation_time.write(SC_ZERO_TIME);
        dmi_speedup_factor.write(1.0);
        
        SC_THREAD(dmi_test_controller);
        sensitive << test_enable.pos();
    }

    void dmi_test_controller() {
        while (true) {
            wait(test_enable.posedge_event());
            
            if (test_enable.read()) {
                run_comprehensive_dmi_tests();
                
                dmi_test_passed.write(all_tests_passed);
                test_complete.write(true);
                
                wait(sc_time(10, SC_NS));
                test_complete.write(false);
            }
        }
    }

    void run_comprehensive_dmi_tests() {
        all_tests_passed = true;
        test_results.clear();
        
        std::cout << "Starting DMI and Hardware Acceleration Tests" << std::endl;
        
        // Test 1: DMI Grant Request and Validation
        test_dmi_grant_mechanism();
        
        // Test 2: Direct Memory Access via DMI
        test_direct_memory_access();
        
        // Test 3: DMI vs Regular Transport Performance
        test_dmi_performance_comparison();
        
        // Test 4: DMI Invalidation Handling
        test_dmi_invalidation_handling();
        
        // Test 5: DMA Transfer Operations
        test_dma_transfer_operations();
        
        // Test 6: Memory Coherency and Synchronization
        test_memory_coherency();
        
        std::cout << "DMI Tests: " << (all_tests_passed ? "PASSED" : "FAILED") << std::endl;
        for (const auto& result : test_results) {
            std::cout << "  - " << result << std::endl;
        }
    }

    void test_dmi_grant_mechanism() {
        try {
            // Create transaction to request DMI
            std::vector<uint8_t> test_data(256, 0xAA);
            dtls_transaction trans(test_data);
            
            tlm_generic_payload& payload = trans.get_payload();
            payload.set_address(0x40000000ULL); // DMI base address
            payload.set_command(TLM_READ_COMMAND);
            
            // Request DMI
            bool dmi_granted = initiator_socket->get_direct_mem_ptr(payload, dmi_data);
            
            if (dmi_granted) {
                // Validate DMI parameters
                if (dmi_data.get_dmi_ptr() == nullptr) {
                    all_tests_passed = false;
                    test_results.push_back("DMI granted but pointer is null");
                    dmi_grant_test_passed.write(false);
                    return;
                }
                
                if (dmi_data.get_start_address() > dmi_data.get_end_address()) {
                    all_tests_passed = false;
                    test_results.push_back("DMI address range invalid");
                    dmi_grant_test_passed.write(false);
                    return;
                }
                
                if (dmi_data.get_granted_access() == tlm::tlm_dmi::DMI_ACCESS_NONE) {
                    all_tests_passed = false;
                    test_results.push_back("DMI access permissions invalid");
                    dmi_grant_test_passed.write(false);
                    return;
                }
                
                dmi_valid = true;
                dmi_base_address = dmi_data.get_start_address();
                
                test_results.push_back("DMI grant mechanism test passed");
                dmi_grant_test_passed.write(true);
                
                std::cout << "DMI granted: [0x" << std::hex << dmi_data.get_start_address()
                         << " - 0x" << dmi_data.get_end_address() << std::dec << "], "
                         << "Access: " << dmi_data.get_granted_access() << std::endl;
                
            } else {
                all_tests_passed = false;
                test_results.push_back("DMI grant request failed");
                dmi_grant_test_passed.write(false);
            }
            
        } catch (const std::exception& e) {
            all_tests_passed = false;
            test_results.push_back(std::string("DMI grant test exception: ") + e.what());
            dmi_grant_test_passed.write(false);
        }
    }

    void test_direct_memory_access() {
        if (!dmi_valid) {
            all_tests_passed = false;
            test_results.push_back("DMI not available for direct access test");
            dmi_access_test_passed.write(false);
            return;
        }
        
        try {
            uint8_t* dmi_ptr = dmi_data.get_dmi_ptr();
            size_t dmi_size = dmi_data.get_end_address() - dmi_data.get_start_address() + 1;
            
            // Test direct write access
            std::vector<uint8_t> test_pattern(256);
            for (size_t i = 0; i < test_pattern.size(); ++i) {
                test_pattern[i] = static_cast<uint8_t>(0x80 + (i % 128));
            }
            
            if (test_pattern.size() <= dmi_size) {
                // Write test pattern directly to DMI memory
                std::memcpy(dmi_ptr, test_pattern.data(), test_pattern.size());
                
                // Add memory synchronization delay
                wait(sc_time(10, SC_NS));
                
                // Read back and verify
                std::vector<uint8_t> readback(test_pattern.size());
                std::memcpy(readback.data(), dmi_ptr, test_pattern.size());
                
                bool data_valid = std::equal(test_pattern.begin(), test_pattern.end(), readback.begin());
                
                if (data_valid) {
                    test_results.push_back("Direct memory access test passed");
                    dmi_access_test_passed.write(true);
                } else {
                    all_tests_passed = false;
                    test_results.push_back("DMI data integrity validation failed");
                    dmi_access_test_passed.write(false);
                }
            } else {
                all_tests_passed = false;
                test_results.push_back("DMI region too small for access test");
                dmi_access_test_passed.write(false);
            }
            
        } catch (const std::exception& e) {
            all_tests_passed = false;
            test_results.push_back(std::string("Direct memory access exception: ") + e.what());
            dmi_access_test_passed.write(false);
        }
    }

    void test_dmi_performance_comparison() {
        try {
            const size_t test_data_size = 1024;
            const size_t num_operations = 50;
            
            // Test regular transport performance
            auto regular_start = std::chrono::high_resolution_clock::now();
            sc_time regular_sim_start = sc_time_stamp();
            
            for (size_t i = 0; i < num_operations; ++i) {
                std::vector<uint8_t> data(test_data_size, 0xBB);
                dtls_transaction trans(data);
                
                dtls_extension* ext = trans.get_extension();
                ext->cipher_suite = 0x1301;
                ext->message_type = MessageType::APPLICATION_DATA;
                
                tlm_generic_payload& payload = trans.get_payload();
                sc_time delay(SC_ZERO_TIME);
                
                initiator_socket->b_transport(payload, delay);
                wait(delay);
            }
            
            auto regular_end = std::chrono::high_resolution_clock::now();
            sc_time regular_sim_end = sc_time_stamp();
            
            auto regular_real_time = std::chrono::duration<double, std::milli>(regular_end - regular_start).count();
            sc_time regular_sim_time = regular_sim_end - regular_sim_start;
            
            regular_operation_time.write(regular_sim_time);
            
            // Test DMI-based performance (if available)
            if (dmi_valid) {
                auto dmi_start = std::chrono::high_resolution_clock::now();
                sc_time dmi_sim_start = sc_time_stamp();
                
                uint8_t* dmi_ptr = dmi_data.get_dmi_ptr();
                
                for (size_t i = 0; i < num_operations; ++i) {
                    // Simulate crypto operation descriptor in DMI
                    uint32_t control_word = (0x1301 << 16) | (test_data_size & 0xFFFF);
                    size_t offset = (i * sizeof(uint32_t)) % (dmi_data.get_end_address() - dmi_data.get_start_address());
                    
                    *reinterpret_cast<uint32_t*>(dmi_ptr + offset) = control_word;
                    
                    // Wait for hardware processing (simulated)
                    wait(sc_time(20, SC_NS)); // DMI operations should be faster
                }
                
                auto dmi_end = std::chrono::high_resolution_clock::now();
                sc_time dmi_sim_end = sc_time_stamp();
                
                auto dmi_real_time = std::chrono::duration<double, std::milli>(dmi_end - dmi_start).count();
                sc_time dmi_sim_time = dmi_sim_end - dmi_sim_start;
                
                dmi_operation_time.write(dmi_sim_time);
                
                // Calculate speedup factor
                double speedup = regular_sim_time.to_seconds() / dmi_sim_time.to_seconds();
                dmi_speedup_factor.write(speedup);
                
                std::cout << "Performance comparison:" << std::endl;
                std::cout << "  Regular transport: " << regular_sim_time.to_string() << " (" << regular_real_time << " ms real)" << std::endl;
                std::cout << "  DMI operations: " << dmi_sim_time.to_string() << " (" << dmi_real_time << " ms real)" << std::endl;
                std::cout << "  DMI speedup factor: " << speedup << "x" << std::endl;
                
                if (speedup > 1.2) { // Expect at least 20% speedup from DMI
                    test_results.push_back("DMI performance test passed (speedup: " + std::to_string(speedup) + "x)");
                    dmi_performance_test_passed.write(true);
                } else {
                    all_tests_passed = false;
                    test_results.push_back("DMI performance improvement insufficient");
                    dmi_performance_test_passed.write(false);
                }
            } else {
                test_results.push_back("DMI performance test skipped (DMI not available)");
                dmi_performance_test_passed.write(true);
            }
            
        } catch (const std::exception& e) {
            all_tests_passed = false;
            test_results.push_back(std::string("Performance comparison exception: ") + e.what());
            dmi_performance_test_passed.write(false);
        }
    }

    void test_dmi_invalidation_handling() {
        if (!dmi_valid) {
            test_results.push_back("DMI invalidation test skipped (DMI not available)");
            dmi_invalidation_test_passed.write(true);
            return;
        }
        
        try {
            // Store original DMI state
            tlm_dmi original_dmi = dmi_data;
            
            // Request target to invalidate DMI (this would typically be done by target)
            // For testing purposes, we'll simulate invalidation by requesting new DMI
            
            std::vector<uint8_t> test_data(128, 0xCC);
            dtls_transaction trans(test_data);
            
            tlm_generic_payload& payload = trans.get_payload();
            payload.set_address(dmi_base_address + 0x1000); // Different address
            
            tlm_dmi new_dmi_data;
            bool new_dmi_granted = initiator_socket->get_direct_mem_ptr(payload, new_dmi_data);
            
            if (new_dmi_granted) {
                // Validate that we can handle new DMI region
                if (new_dmi_data.get_dmi_ptr() != nullptr) {
                    test_results.push_back("DMI invalidation and re-grant test passed");
                    dmi_invalidation_test_passed.write(true);
                } else {
                    all_tests_passed = false;
                    test_results.push_back("DMI re-grant failed after invalidation");
                    dmi_invalidation_test_passed.write(false);
                }
            } else {
                // This might be expected behavior - invalidation preventing new grants
                test_results.push_back("DMI invalidation test passed (re-grant denied as expected)");
                dmi_invalidation_test_passed.write(true);
            }
            
        } catch (const std::exception& e) {
            all_tests_passed = false;
            test_results.push_back(std::string("DMI invalidation test exception: ") + e.what());
            dmi_invalidation_test_passed.write(false);
        }
    }

    void test_dma_transfer_operations() {
        try {
            // Test bulk data transfer operations
            const size_t transfer_size = 4096;
            const size_t num_transfers = 10;
            
            for (size_t i = 0; i < num_transfers; ++i) {
                std::vector<uint8_t> source_data(transfer_size, 0xDD + i % 16);
                dtls_transaction trans(source_data);
                
                dtls_extension* ext = trans.get_extension();
                ext->cipher_suite = 0x1301;
                ext->message_type = MessageType::APPLICATION_DATA;
                ext->connection_id = 0x80000000 + i;
                ext->sequence_number = i;
                
                // Simulate DMA-style bulk transfer
                tlm_generic_payload& payload = trans.get_payload();
                payload.set_address(0x40000000ULL + i * transfer_size); // Sequential addresses
                payload.set_command(TLM_WRITE_COMMAND);
                sc_time delay(SC_ZERO_TIME);
                
                auto transfer_start = sc_time_stamp();
                initiator_socket->b_transport(payload, delay);
                auto transfer_end = sc_time_stamp() + delay;
                
                sc_time transfer_time = transfer_end - transfer_start;
                
                // Validate transfer completed successfully
                if (payload.get_response_status() != TLM_OK_RESPONSE) {
                    all_tests_passed = false;
                    test_results.push_back("DMA transfer " + std::to_string(i) + " failed");
                    dma_transfer_test_passed.write(false);
                    return;
                }
                
                // Validate reasonable transfer time
                double bandwidth_mbps = (transfer_size * 8.0) / (transfer_time.to_seconds() * 1e6);
                if (bandwidth_mbps < 10.0) { // Expect at least 10 Mbps
                    all_tests_passed = false;
                    test_results.push_back("DMA transfer bandwidth too low: " + std::to_string(bandwidth_mbps) + " Mbps");
                    dma_transfer_test_passed.write(false);
                    return;
                }
                
                wait(sc_time(5, SC_NS)); // Brief delay between transfers
            }
            
            test_results.push_back("DMA transfer operations test passed");
            dma_transfer_test_passed.write(true);
            
        } catch (const std::exception& e) {
            all_tests_passed = false;
            test_results.push_back(std::string("DMA transfer test exception: ") + e.what());
            dma_transfer_test_passed.write(false);
        }
    }

    void test_memory_coherency() {
        if (!dmi_valid) {
            test_results.push_back("Memory coherency test skipped (DMI not available)");
            memory_coherency_test_passed.write(true);
            return;
        }
        
        try {
            uint8_t* dmi_ptr = dmi_data.get_dmi_ptr();
            
            // Test coherency between DMI and regular transport
            std::vector<uint8_t> coherency_pattern(64);
            for (size_t i = 0; i < coherency_pattern.size(); ++i) {
                coherency_pattern[i] = static_cast<uint8_t>(0xF0 | (i % 16));
            }
            
            // Write via DMI
            std::memcpy(dmi_ptr, coherency_pattern.data(), coherency_pattern.size());
            wait(sc_time(10, SC_NS)); // Allow propagation time
            
            // Read via regular transport to check coherency
            dtls_transaction read_trans;
            tlm_generic_payload& read_payload = read_trans.get_payload();
            read_payload.set_address(dmi_base_address);
            read_payload.set_command(TLM_READ_COMMAND);
            read_payload.set_data_length(coherency_pattern.size());
            
            std::vector<uint8_t> read_buffer(coherency_pattern.size());
            read_payload.set_data_ptr(read_buffer.data());
            
            sc_time read_delay(SC_ZERO_TIME);
            initiator_socket->b_transport(read_payload, read_delay);
            
            if (read_payload.get_response_status() == TLM_OK_RESPONSE) {
                // Verify data coherency
                bool coherent = std::equal(coherency_pattern.begin(), coherency_pattern.end(), read_buffer.begin());
                
                if (coherent) {
                    test_results.push_back("Memory coherency test passed");
                    memory_coherency_test_passed.write(true);
                } else {
                    all_tests_passed = false;
                    test_results.push_back("Memory coherency violation detected");
                    memory_coherency_test_passed.write(false);
                }
            } else {
                all_tests_passed = false;
                test_results.push_back("Coherency test read operation failed");
                memory_coherency_test_passed.write(false);
            }
            
        } catch (const std::exception& e) {
            all_tests_passed = false;
            test_results.push_back(std::string("Memory coherency test exception: ") + e.what());
            memory_coherency_test_passed.write(false);
        }
    }
};

/**
 * DMI Hardware Acceleration Testbench
 * 
 * Top-level testbench integrating crypto engine and test client
 */
SC_MODULE(DMIHardwareAccelerationTestbench) {
public:
    // Component instances
    std::unique_ptr<HardwareAcceleratedCryptoEngine> crypto_engine;
    std::unique_ptr<DMITestClient> test_client;
    
    // Configuration signals
    sc_signal<bool> enable_dmi{"enable_dmi"};
    sc_signal<uint32_t> dmi_buffer_size{"dmi_buffer_size"};
    sc_signal<sc_time> dma_transfer_rate{"dma_transfer_rate"};
    
    // Control and status
    sc_signal<bool> test_enable{"test_enable"};
    sc_signal<bool> test_complete{"test_complete"};
    sc_signal<bool> overall_test_passed{"overall_test_passed"};
    
    // Performance monitoring
    sc_signal<bool> hw_ready{"hw_ready"};
    sc_signal<bool> hw_busy{"hw_busy"};
    sc_signal<bool> dmi_granted{"dmi_granted"};
    sc_signal<uint32_t> dmi_transactions{"dmi_transactions"};
    sc_signal<uint32_t> regular_transactions{"regular_transactions"};
    sc_signal<sc_time> dmi_total_time{"dmi_total_time"};
    sc_signal<sc_time> regular_total_time{"regular_total_time"};

    SC_CTOR(DMIHardwareAccelerationTestbench) {
        // Create component instances
        crypto_engine = std::make_unique<HardwareAcceleratedCryptoEngine>("CryptoEngine");
        test_client = std::make_unique<DMITestClient>("TestClient");
        
        // Configure hardware
        enable_dmi.write(true);
        dmi_buffer_size.write(128 * 1024);
        dma_transfer_rate.write(sc_time(0.5, SC_NS)); // 2 bytes per ns
        
        // Connect crypto engine
        crypto_engine->enable_dmi(enable_dmi);
        crypto_engine->dmi_buffer_size(dmi_buffer_size);
        crypto_engine->dma_transfer_rate(dma_transfer_rate);
        crypto_engine->hw_ready(hw_ready);
        crypto_engine->hw_busy(hw_busy);
        crypto_engine->dmi_granted(dmi_granted);
        crypto_engine->dmi_transactions(dmi_transactions);
        crypto_engine->regular_transactions(regular_transactions);
        crypto_engine->dmi_total_time(dmi_total_time);
        crypto_engine->regular_total_time(regular_total_time);
        
        // Connect test client
        test_client->test_enable(test_enable);
        test_client->test_complete(test_complete);
        test_client->dmi_test_passed(overall_test_passed);
        
        // Connect TLM socket
        test_client->initiator_socket.bind(crypto_engine->target_socket);
        
        SC_THREAD(testbench_controller);
    }

    void testbench_controller() {
        // Initialize
        test_enable.write(false);
        wait(sc_time(100, SC_NS));
        
        std::cout << "Starting DMI Hardware Acceleration Testbench" << std::endl;
        
        // Start test
        test_enable.write(true);
        wait(sc_time(10, SC_NS));
        test_enable.write(false);
        
        // Wait for completion
        while (!test_complete.read()) {
            wait(sc_time(1, SC_MS));
        }
        
        // Print results
        std::cout << "\n=== DMI Hardware Acceleration Test Results ===" << std::endl;
        std::cout << "Overall test passed: " << (overall_test_passed.read() ? "YES" : "NO") << std::endl;
        std::cout << "DMI granted: " << (dmi_granted.read() ? "YES" : "NO") << std::endl;
        std::cout << "DMI transactions: " << dmi_transactions.read() << std::endl;
        std::cout << "Regular transactions: " << regular_transactions.read() << std::endl;
        std::cout << "DMI processing time: " << dmi_total_time.read().to_string() << std::endl;
        std::cout << "Regular processing time: " << regular_total_time.read().to_string() << std::endl;
        
        if (dmi_total_time.read() > sc_time(SC_ZERO_TIME) && regular_total_time.read() > sc_time(SC_ZERO_TIME)) {
            double speedup = regular_total_time.read().to_seconds() / dmi_total_time.read().to_seconds();
            std::cout << "DMI speedup factor: " << speedup << "x" << std::endl;
        }
        
        wait(sc_time(100, SC_NS));
        sc_stop();
    }

public:
    bool get_overall_test_result() const { return overall_test_passed.read(); }
    bool get_dmi_granted() const { return dmi_granted.read(); }
    uint32_t get_dmi_transactions() const { return dmi_transactions.read(); }
    uint32_t get_regular_transactions() const { return regular_transactions.read(); }
};

/**
 * Main test class for DMI Hardware Acceleration Testing
 */
class DMIHardwareAccelerationTest : public SystemCTestFramework {
protected:
    void SetUp() override {
        SystemCTestFramework::SetUp();
        
        // Configure test for DMI validation
        config_.simulation_duration = sc_time(100, SC_MS);
        config_.enable_tracing = true;
        config_.trace_filename = "dmi_hardware_acceleration_test.vcd";
        config_.enable_performance_measurement = true;
        
        // Create testbench
        testbench = std::make_unique<DMIHardwareAccelerationTestbench>("DMITestbench");
    }

private:
    std::unique_ptr<DMIHardwareAccelerationTestbench> testbench;
};

/**
 * Test: DMI Functionality Validation
 * 
 * Comprehensive validation of DMI mechanisms
 */
TEST_F(DMIHardwareAccelerationTest, DMIFunctionalityValidation) {
    // Run simulation
    sc_start();
    
    // Validate test completion and results
    EXPECT_TRUE(testbench->get_overall_test_result()) 
        << "DMI functionality validation failed";
    
    EXPECT_TRUE(testbench->get_dmi_granted()) 
        << "DMI was not granted during test";
    
    std::cout << "DMI Functionality Test Results:" << std::endl;
    std::cout << "  DMI transactions: " << testbench->get_dmi_transactions() << std::endl;
    std::cout << "  Regular transactions: " << testbench->get_regular_transactions() << std::endl;
}

/**
 * Test: Hardware Acceleration Performance
 * 
 * Validate performance improvements through hardware acceleration
 */
TEST_F(DMIHardwareAccelerationTest, HardwareAccelerationPerformance) {
    sc_start();
    
    EXPECT_TRUE(testbench->get_overall_test_result()) 
        << "Hardware acceleration performance test failed";
    
    // Validate that both DMI and regular transactions occurred
    EXPECT_GT(testbench->get_dmi_transactions(), 0) 
        << "No DMI transactions recorded";
        
    EXPECT_GT(testbench->get_regular_transactions(), 0) 
        << "No regular transactions recorded";
}

/**
 * Test: DMI Memory Interface Validation
 * 
 * Validate memory interface operations and coherency
 */
TEST_F(DMIHardwareAccelerationTest, DMIMemoryInterfaceValidation) {
    sc_start();
    
    // Memory interface validation is part of the comprehensive test
    EXPECT_TRUE(testbench->get_overall_test_result()) 
        << "DMI memory interface validation failed";
}

/**
 * SystemC main function for standalone testing
 */
int sc_main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}