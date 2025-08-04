#include "message_layer_tlm.h"
#include "dtls_testbench.h"
#include <systemc>
#include <tlm.h>
#include <iostream>

using namespace sc_core;
using namespace dtls::v13::systemc_tlm;

SC_MODULE(message_layer_test) {
    // Test signals
    sc_clock clock;
    sc_signal<bool> reset;
    sc_signal<bool> test_complete;

    // Message layer under test
    MessageLayerTLM* message_layer;
    
    // TLM sockets for testing
    tlm_utils::simple_initiator_socket<message_layer_test> test_initiator_socket;
    
    // Test data
    unsigned char large_message[4096];
    unsigned char fragment_buffer[1024];
    size_t large_message_size;
    
    SC_CTOR(message_layer_test) 
        : clock("clock", 10, SC_NS)
        , reset("reset")
        , test_complete("test_complete")
        , test_initiator_socket("test_initiator_socket")
    {
        // Create message layer instance
        message_layer = new MessageLayerTLM("message_layer_under_test");
        
        // Connect sockets
        test_initiator_socket.bind(message_layer->target_socket);
        
        // Initialize test data
        setup_test_data();
        
        // Register test processes
        SC_THREAD(run_fragmentation_test);
        SC_THREAD(run_reassembly_test);
        SC_THREAD(run_flight_management_test);
        SC_THREAD(run_retransmission_test);
        SC_THREAD(monitor_test_progress);
        
        std::cout << "Message Layer Test initialized" << std::endl;
    }
    
    ~message_layer_test() {
        delete message_layer;
    }
    
    void setup_test_data() {
        large_message_size = 3000; // Larger than typical MTU
        for (size_t i = 0; i < large_message_size; ++i) {
            large_message[i] = static_cast<unsigned char>((i * 13 + 7) & 0xFF);
        }
    }
    
    void run_fragmentation_test() {
        wait(100, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting message fragmentation test" << std::endl;
        
        // Create TLM transaction for large message
        tlm::tlm_generic_payload trans;
        sc_time delay = SC_ZERO_TIME;
        
        trans.set_data_ptr(large_message);
        trans.set_data_length(large_message_size);
        trans.set_command(tlm::TLM_WRITE_COMMAND);
        trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        // Add message extension for fragmentation
        message_extension ext;
        ext.operation = message_extension::FRAGMENT_MESSAGE;
        ext.message_sequence = 1;
        ext.max_fragment_size = 1200; // Typical MTU size
        ext.fragment_count = 0;
        ext.message_complete = false;
        
        trans.set_extension(&ext);
        
        // Execute fragmentation
        test_initiator_socket->b_transport(trans, delay);
        
        // Verify fragmentation result
        if (trans.get_response_status() == tlm::TLM_OK_RESPONSE && ext.fragment_count > 1) {
            std::cout << "[" << sc_time_stamp() << "] Message fragmentation test PASSED - " 
                      << ext.fragment_count << " fragments created" << std::endl;
        } else {
            std::cout << "[" << sc_time_stamp() << "] Message fragmentation test FAILED" << std::endl;
        }
        
        wait(50, SC_NS);
    }
    
    void run_reassembly_test() {
        wait(200, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting message reassembly test" << std::endl;
        
        // Simulate receiving fragments and reassembling
        const size_t fragment_size = 800;
        const size_t num_fragments = 4;
        uint32_t message_seq = 2;
        
        for (size_t frag_num = 0; frag_num < num_fragments; ++frag_num) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            // Prepare fragment data
            size_t offset = frag_num * fragment_size;
            size_t current_size = std::min(fragment_size, large_message_size - offset);
            
            trans.set_data_ptr(large_message + offset);
            trans.set_data_length(current_size);
            trans.set_command(tlm::TLM_READ_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            message_extension ext;
            ext.operation = message_extension::RECEIVE_FRAGMENT;
            ext.message_sequence = message_seq;
            ext.fragment_offset = offset;
            ext.fragment_length = current_size;
            ext.message_length = large_message_size;
            ext.message_complete = (frag_num == num_fragments - 1);
            ext.reassembly_progress = ((frag_num + 1) * 100) / num_fragments;
            
            trans.set_extension(&ext);
            
            // Process fragment
            test_initiator_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() != tlm::TLM_OK_RESPONSE) {
                std::cout << "[" << sc_time_stamp() << "] Message reassembly test FAILED at fragment " 
                          << frag_num << std::endl;
                return;
            }
            
            wait(20, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Message reassembly test PASSED" << std::endl;
    }
    
    void run_flight_management_test() {
        wait(400, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting flight management test" << std::endl;
        
        // Test different handshake flight types
        const char* flight_names[] = {"ClientHello", "ServerHello", "Certificate", "Finished"};
        const int num_flights = sizeof(flight_names) / sizeof(flight_names[0]);
        
        for (int flight = 0; flight < num_flights; ++flight) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            // Create flight message
            std::string flight_data = std::string("DTLS_") + flight_names[flight] + "_Message";
            
            trans.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(flight_data.c_str())));
            trans.set_data_length(flight_data.length());
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            message_extension ext;
            ext.operation = message_extension::SEND_FLIGHT;
            ext.flight_type_value = flight;
            ext.message_sequence = flight + 10;
            ext.retransmission_count = 0;
            
            trans.set_extension(&ext);
            
            // Send flight
            test_initiator_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() != tlm::TLM_OK_RESPONSE) {
                std::cout << "[" << sc_time_stamp() << "] Flight management test FAILED for " 
                          << flight_names[flight] << std::endl;
                return;
            }
            
            wait(30, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Flight management test PASSED" << std::endl;
    }
    
    void run_retransmission_test() {
        wait(600, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting retransmission test" << std::endl;
        
        // Test retransmission logic
        tlm::tlm_generic_payload trans;
        sc_time delay = SC_ZERO_TIME;
        
        std::string retry_message = "DTLS_Retransmission_Test_Message";
        
        trans.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(retry_message.c_str())));
        trans.set_data_length(retry_message.length());
        trans.set_command(tlm::TLM_WRITE_COMMAND);
        trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        message_extension ext;
        ext.operation = message_extension::RETRANSMIT_FLIGHT;
        ext.flight_type_value = 1; // ServerHello flight
        ext.message_sequence = 15;
        ext.retransmission_count = 0;
        
        trans.set_extension(&ext);
        
        // Simulate multiple retransmission attempts
        const int max_retries = 3;
        for (int retry = 0; retry < max_retries; ++retry) {
            ext.retransmission_count = retry;
            
            test_initiator_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() != tlm::TLM_OK_RESPONSE) {
                std::cout << "[" << sc_time_stamp() << "] Retransmission test FAILED at retry " 
                          << retry << std::endl;
                return;
            }
            
            wait(40, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Retransmission test PASSED" << std::endl;
    }
    
    void monitor_test_progress() {
        wait(1200, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Message layer test suite completed" << std::endl;
        test_complete.write(true);
        sc_stop();
    }
};

int sc_main(int argc, char* argv[]) {
    // Create test module
    message_layer_test test("message_layer_test");
    
    // Run simulation
    std::cout << "Starting message layer test simulation..." << std::endl;
    sc_start();
    
    std::cout << "Message layer test simulation completed" << std::endl;
    return 0;
}