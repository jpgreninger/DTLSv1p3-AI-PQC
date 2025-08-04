#include "dtls_protocol_stack.h"
#include "dtls_testbench.h"
#include <systemc>
#include <tlm.h>
#include <iostream>
#include <vector>

using namespace sc_core;
using namespace dtls::v13::systemc_tlm;

SC_MODULE(integration_test) {
    // Test infrastructure
    sc_clock clock;
    sc_signal<bool> reset;
    sc_signal<bool> test_complete;
    sc_signal<bool> enable_stack;
    sc_signal<uint32_t> max_connections;
    sc_signal<bool> hardware_acceleration_enabled;
    sc_signal<uint16_t> mtu_size;
    
    // Protocol stack under test
    dtls_protocol_stack* protocol_stack;
    
    // Test client and server interfaces
    tlm_utils::simple_initiator_socket<integration_test> client_socket;
    tlm_utils::simple_initiator_socket<integration_test> server_socket;
    
    // Test statistics
    struct TestResults {
        uint32_t handshakes_attempted{0};
        uint32_t handshakes_successful{0};
        uint32_t data_transfers_attempted{0};
        uint32_t data_transfers_successful{0};
        uint64_t total_bytes_sent{0};
        uint64_t total_bytes_received{0};
        sc_time total_test_time{0, SC_NS};
        bool test_passed{false};
    } results;
    
    SC_CTOR(integration_test) 
        : clock("clock", 10, SC_NS)
        , reset("reset")
        , test_complete("test_complete")
        , enable_stack("enable_stack")
        , max_connections("max_connections")
        , hardware_acceleration_enabled("hardware_acceleration_enabled")
        , mtu_size("mtu_size")
        , client_socket("client_socket")
        , server_socket("server_socket")
    {
        // Create protocol stack
        protocol_stack = new dtls_protocol_stack("dtls_stack");
        
        // Connect configuration signals
        protocol_stack->enable_stack(enable_stack);
        protocol_stack->max_connections(max_connections);
        protocol_stack->hardware_acceleration_enabled(hardware_acceleration_enabled);
        protocol_stack->mtu_size(mtu_size);
        
        // Connect TLM sockets
        client_socket.bind(protocol_stack->application_target_socket);
        
        // Initialize configuration signals
        enable_stack.write(true);
        max_connections.write(100);
        hardware_acceleration_enabled.write(false);
        mtu_size.write(1500);
        
        // Register test processes
        SC_THREAD(run_basic_handshake_test);
        SC_THREAD(run_data_transfer_test);
        SC_THREAD(run_multiple_connections_test);
        SC_THREAD(run_performance_test);
        SC_THREAD(run_error_handling_test);
        SC_THREAD(monitor_protocol_stack);
        SC_THREAD(test_completion_monitor);
        
        std::cout << "Integration Test initialized" << std::endl;
    }
    
    ~integration_test() {
        delete protocol_stack;
    }
    
    void run_basic_handshake_test() {
        wait(100, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting basic handshake test" << std::endl;
        
        // Simulate ClientHello message
        std::string client_hello = "DTLS_CLIENT_HELLO_v1.3";
        
        tlm::tlm_generic_payload trans;
        sc_time delay = SC_ZERO_TIME;
        
        trans.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(client_hello.c_str())));
        trans.set_data_length(client_hello.length());
        trans.set_command(tlm::TLM_WRITE_COMMAND);
        trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        // Add DTLS extension for handshake
        dtls_extension ext;
        ext.message_type = dtls_extension::HANDSHAKE;
        ext.handshake_type = dtls_extension::CLIENT_HELLO;
        ext.connection_id = 1;
        ext.epoch = 0;
        ext.sequence_number = 0;
        ext.is_fragmented = false;
        ext.priority = dtls_extension::HIGH;
        
        trans.set_extension(&ext);
        
        results.handshakes_attempted++;
        
        // Send ClientHello
        client_socket->b_transport(trans, delay);
        
        if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
            results.handshakes_successful++;
            std::cout << "[" << sc_time_stamp() << "] Basic handshake test PASSED" << std::endl;
        } else {
            std::cout << "[" << sc_time_stamp() << "] Basic handshake test FAILED" << std::endl;
        }
        
        wait(100, SC_NS);
    }
    
    void run_data_transfer_test() {
        wait(300, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting data transfer test" << std::endl;
        
        // Test application data transfer after handshake
        const size_t test_data_sizes[] = {64, 256, 1024, 4096};
        const size_t num_tests = sizeof(test_data_sizes) / sizeof(test_data_sizes[0]);
        
        for (size_t i = 0; i < num_tests; ++i) {
            size_t data_size = test_data_sizes[i];
            std::vector<unsigned char> test_data(data_size);
            
            // Initialize test data
            for (size_t j = 0; j < data_size; ++j) {
                test_data[j] = static_cast<unsigned char>((j + i) & 0xFF);
            }
            
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(test_data.data());
            trans.set_data_length(data_size);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            // Add DTLS extension for application data
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 1;
            ext.epoch = 1; // Post-handshake epoch
            ext.sequence_number = i + 1;
            ext.priority = dtls_extension::NORMAL;
            
            trans.set_extension(&ext);
            
            results.data_transfers_attempted++;
            
            // Send application data
            client_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
                results.data_transfers_successful++;
                results.total_bytes_sent += data_size;
                std::cout << "[" << sc_time_stamp() << "] Data transfer test " << i+1 
                          << " PASSED (" << data_size << " bytes)" << std::endl;
            } else {
                std::cout << "[" << sc_time_stamp() << "] Data transfer test " << i+1 
                          << " FAILED (" << data_size << " bytes)" << std::endl;
            }
            
            wait(50, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Data transfer test suite completed" << std::endl;
    }
    
    void run_multiple_connections_test() {
        wait(600, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting multiple connections test" << std::endl;
        
        const uint32_t num_connections = 5;
        
        for (uint32_t conn_id = 10; conn_id < 10 + num_connections; ++conn_id) {
            // Create handshake for each connection
            std::string handshake_msg = "DTLS_HANDSHAKE_CONN_" + std::to_string(conn_id);
            
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(handshake_msg.c_str())));
            trans.set_data_length(handshake_msg.length());
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::HANDSHAKE;
            ext.handshake_type = dtls_extension::CLIENT_HELLO;
            ext.connection_id = conn_id;
            ext.epoch = 0;
            ext.sequence_number = 0;
            ext.priority = dtls_extension::NORMAL;
            
            trans.set_extension(&ext);
            
            client_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
                std::cout << "[" << sc_time_stamp() << "] Connection " << conn_id 
                          << " established successfully" << std::endl;
            } else {
                std::cout << "[" << sc_time_stamp() << "] Connection " << conn_id 
                          << " failed to establish" << std::endl;
            }
            
            wait(40, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Multiple connections test completed" << std::endl;
    }
    
    void run_performance_test() {
        wait(900, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting performance test" << std::endl;
        
        sc_time start_time = sc_time_stamp();
        const size_t num_transactions = 100;
        const size_t data_size = 512;
        
        std::vector<unsigned char> perf_data(data_size, 0xAA);
        
        for (size_t i = 0; i < num_transactions; ++i) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(perf_data.data());
            trans.set_data_length(data_size);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 1;
            ext.epoch = 1;
            ext.sequence_number = i + 100;
            ext.priority = dtls_extension::NORMAL;
            
            trans.set_extension(&ext);
            
            client_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
                results.total_bytes_sent += data_size;
            }
            
            // Small delay to prevent overwhelming the system
            if (i % 10 == 0) {
                wait(5, SC_NS);
            }
        }
        
        sc_time end_time = sc_time_stamp();
        sc_time test_duration = end_time - start_time;
        
        double throughput_mbps = (results.total_bytes_sent * 8.0) / 
                                (test_duration.to_seconds() * 1024.0 * 1024.0);
        
        std::cout << "[" << sc_time_stamp() << "] Performance test completed:" << std::endl;
        std::cout << "  Test duration: " << test_duration << std::endl;
        std::cout << "  Total bytes: " << results.total_bytes_sent << std::endl;
        std::cout << "  Throughput: " << throughput_mbps << " Mbps" << std::endl;
    }
    
    void run_error_handling_test() {
        wait(1200, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting error handling test" << std::endl;
        
        // Test various error conditions
        
        // Test 1: Invalid data length
        tlm::tlm_generic_payload trans1;
        sc_time delay = SC_ZERO_TIME;
        
        trans1.set_data_ptr(nullptr);
        trans1.set_data_length(0);
        trans1.set_command(tlm::TLM_WRITE_COMMAND);
        trans1.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        client_socket->b_transport(trans1, delay);
        
        if (trans1.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE) {
            std::cout << "[" << sc_time_stamp() << "] Error handling test 1 PASSED - null data rejected" << std::endl;
        } else {
            std::cout << "[" << sc_time_stamp() << "] Error handling test 1 FAILED - null data accepted" << std::endl;
        }
        
        wait(50, SC_NS);
        
        // Test 2: Invalid connection ID
        std::string error_data = "INVALID_CONNECTION_TEST";
        tlm::tlm_generic_payload trans2;
        
        trans2.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(error_data.c_str())));
        trans2.set_data_length(error_data.length());
        trans2.set_command(tlm::TLM_WRITE_COMMAND);
        trans2.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        dtls_extension ext;
        ext.message_type = dtls_extension::APPLICATION_DATA;
        ext.connection_id = 0xFFFFFFFF; // Invalid connection ID
        ext.epoch = 1;
        ext.sequence_number = 9999;
        ext.has_error = false;
        
        trans2.set_extension(&ext);
        
        client_socket->b_transport(trans2, delay);
        
        if (ext.has_error || trans2.get_response_status() != tlm::TLM_OK_RESPONSE) {
            std::cout << "[" << sc_time_stamp() << "] Error handling test 2 PASSED - invalid connection rejected" << std::endl;
        } else {
            std::cout << "[" << sc_time_stamp() << "] Error handling test 2 FAILED - invalid connection accepted" << std::endl;
        }
        
        std::cout << "[" << sc_time_stamp() << "] Error handling test suite completed" << std::endl;
    }
    
    void monitor_protocol_stack() {
        while (true) {
            wait(200, SC_NS);
            
            // Monitor protocol stack status and performance
            auto stats = protocol_stack->get_statistics();
            
            if (sc_time_stamp() > sc_time(1000, SC_NS)) {
                std::cout << "[" << sc_time_stamp() << "] Protocol Stack Status:" << std::endl;
                std::cout << "  Active connections: " << stats.active_connections << std::endl;
                std::cout << "  Successful handshakes: " << stats.successful_handshakes << std::endl;
                std::cout << "  Total application bytes: " << stats.total_application_bytes << std::endl;
                std::cout << "  Protocol overhead: " << stats.overhead_percentage << "%" << std::endl;
            }
        }
    }
    
    void test_completion_monitor() {
        wait(1500, SC_NS);
        
        // Evaluate test results
        bool all_tests_passed = true;
        
        if (results.handshakes_successful < results.handshakes_attempted) {
            all_tests_passed = false;
            std::cout << "FAIL: Not all handshakes successful (" 
                      << results.handshakes_successful << "/" << results.handshakes_attempted << ")" << std::endl;
        }
        
        if (results.data_transfers_successful < results.data_transfers_attempted) {
            all_tests_passed = false;
            std::cout << "FAIL: Not all data transfers successful (" 
                      << results.data_transfers_successful << "/" << results.data_transfers_attempted << ")" << std::endl;
        }
        
        results.test_passed = all_tests_passed;
        results.total_test_time = sc_time_stamp();
        
        std::cout << "\n======= INTEGRATION TEST RESULTS =======" << std::endl;
        std::cout << "Overall result: " << (all_tests_passed ? "PASSED" : "FAILED") << std::endl;
        std::cout << "Test duration: " << results.total_test_time << std::endl;
        std::cout << "Handshakes: " << results.handshakes_successful << "/" << results.handshakes_attempted << std::endl;
        std::cout << "Data transfers: " << results.data_transfers_successful << "/" << results.data_transfers_attempted << std::endl;
        std::cout << "Total bytes transferred: " << results.total_bytes_sent << std::endl;
        std::cout << "=========================================" << std::endl;
        
        test_complete.write(true);
        sc_stop();
    }
};

int sc_main(int argc, char* argv[]) {
    // Create integration test
    integration_test test("integration_test");
    
    // Run simulation
    std::cout << "Starting DTLS v1.3 integration test simulation..." << std::endl;
    sc_start();
    
    std::cout << "Integration test simulation completed" << std::endl;
    return 0;
}