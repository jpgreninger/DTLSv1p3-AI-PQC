#include "record_layer_tlm.h"
#include "dtls_testbench.h"
#include <systemc>
#include <tlm.h>
#include <iostream>

using namespace sc_core;
using namespace dtls::v13::systemc_tlm;

SC_MODULE(record_layer_test) {
    // Test signals
    sc_clock clock;
    sc_signal<bool> reset;
    sc_signal<bool> test_complete;

    // Record layer under test
    RecordLayerTLM* record_layer;
    
    // TLM sockets for testing
    tlm_utils::simple_initiator_socket<record_layer_test> test_initiator_socket;
    
    // Test data
    unsigned char test_data[1024];
    size_t test_data_size;
    
    SC_CTOR(record_layer_test) 
        : clock("clock", 10, SC_NS)
        , reset("reset")
        , test_complete("test_complete")
        , test_initiator_socket("test_initiator_socket")
    {
        // Create record layer instance
        record_layer = new RecordLayerTLM("record_layer_under_test");
        
        // Connect sockets
        test_initiator_socket.bind(record_layer->target_socket);
        
        // Initialize test data
        setup_test_data();
        
        // Register test processes
        SC_THREAD(run_protection_test);
        SC_THREAD(run_unprotection_test);
        SC_THREAD(run_sequence_number_test);
        SC_THREAD(run_anti_replay_test);
        SC_THREAD(monitor_test_progress);
        
        std::cout << "Record Layer Test initialized" << std::endl;
    }
    
    ~record_layer_test() {
        delete record_layer;
    }
    
    void setup_test_data() {
        test_data_size = 256;
        for (size_t i = 0; i < test_data_size; ++i) {
            test_data[i] = static_cast<unsigned char>(i & 0xFF);
        }
    }
    
    void run_protection_test() {
        wait(100, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting record protection test" << std::endl;
        
        // Create TLM transaction
        tlm::tlm_generic_payload trans;
        sc_time delay = SC_ZERO_TIME;
        
        // Setup transaction for record protection
        trans.set_data_ptr(test_data);
        trans.set_data_length(test_data_size);
        trans.set_command(tlm::TLM_WRITE_COMMAND);
        trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        // Add record extension
        record_extension ext;
        ext.operation = record_extension::PROTECT_RECORD;
        ext.epoch = 1;
        ext.sequence_number = 0x12345678;
        
        trans.set_extension(&ext);
        
        // Execute transaction
        test_initiator_socket->b_transport(trans, delay);
        
        // Verify result
        if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
            std::cout << "[" << sc_time_stamp() << "] Record protection test PASSED" << std::endl;
        } else {
            std::cout << "[" << sc_time_stamp() << "] Record protection test FAILED" << std::endl;
        }
        
        wait(50, SC_NS);
    }
    
    void run_unprotection_test() {
        wait(200, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting record unprotection test" << std::endl;
        
        // Create TLM transaction for unprotection
        tlm::tlm_generic_payload trans;
        sc_time delay = SC_ZERO_TIME;
        
        // Setup protected record data
        trans.set_data_ptr(test_data);
        trans.set_data_length(test_data_size);
        trans.set_command(tlm::TLM_READ_COMMAND);
        trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        // Add record extension
        record_extension ext;
        ext.operation = record_extension::UNPROTECT_RECORD;
        ext.epoch = 1;
        ext.sequence_number = 0x12345678;
        
        trans.set_extension(&ext);
        
        // Execute transaction
        test_initiator_socket->b_transport(trans, delay);
        
        // Verify result
        if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
            std::cout << "[" << sc_time_stamp() << "] Record unprotection test PASSED" << std::endl;
        } else {
            std::cout << "[" << sc_time_stamp() << "] Record unprotection test FAILED" << std::endl;
        }
        
        wait(50, SC_NS);
    }
    
    void run_sequence_number_test() {
        wait(300, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting sequence number test" << std::endl;
        
        // Test sequence number generation and validation
        for (uint32_t i = 0; i < 10; ++i) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(test_data);
            trans.set_data_length(64);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            record_extension ext;
            ext.operation = record_extension::SEQUENCE_NUMBER_GEN;
            ext.epoch = 1;
            ext.sequence_number = i;
            
            trans.set_extension(&ext);
            
            test_initiator_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() != tlm::TLM_OK_RESPONSE) {
                std::cout << "[" << sc_time_stamp() << "] Sequence number test FAILED at iteration " << i << std::endl;
                return;
            }
            
            wait(10, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Sequence number test PASSED" << std::endl;
    }
    
    void run_anti_replay_test() {
        wait(400, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting anti-replay test" << std::endl;
        
        // Test replay detection with duplicate sequence numbers
        uint64_t duplicate_seq = 0x123456;
        
        for (int attempt = 0; attempt < 2; ++attempt) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(test_data);
            trans.set_data_length(128);
            trans.set_command(tlm::TLM_READ_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            record_extension ext;
            ext.operation = record_extension::ANTI_REPLAY_CHECK;
            ext.epoch = 1;
            ext.sequence_number = duplicate_seq;
            ext.replay_detected = false;
            
            trans.set_extension(&ext);
            
            test_initiator_socket->b_transport(trans, delay);
            
            if (attempt == 0) {
                // First attempt should succeed
                if (trans.get_response_status() != tlm::TLM_OK_RESPONSE || ext.replay_detected) {
                    std::cout << "[" << sc_time_stamp() << "] Anti-replay test FAILED - first packet rejected" << std::endl;
                    return;
                }
            } else {
                // Second attempt should detect replay
                if (!ext.replay_detected) {
                    std::cout << "[" << sc_time_stamp() << "] Anti-replay test FAILED - replay not detected" << std::endl;
                    return;
                }
            }
            
            wait(20, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Anti-replay test PASSED" << std::endl;
    }
    
    void monitor_test_progress() {
        wait(1000, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Record layer test suite completed" << std::endl;
        test_complete.write(true);
        sc_stop();
    }
};

int sc_main(int argc, char* argv[]) {
    // Create test module
    record_layer_test test("record_layer_test");
    
    // Run simulation
    std::cout << "Starting record layer test simulation..." << std::endl;
    sc_start();
    
    std::cout << "Record layer test simulation completed" << std::endl;
    return 0;
}