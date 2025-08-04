#include "dtls_protocol_stack.h"
#include "dtls_testbench.h"
#include <systemc>
#include <tlm.h>
#include <iostream>
#include <vector>
#include <random>

using namespace sc_core;
using namespace dtls::v13::systemc_tlm;

SC_MODULE(security_test) {
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
    
    // Security test interface
    tlm_utils::simple_initiator_socket<security_test> security_socket;
    
    // Attack simulation components
    std::mt19937 random_generator;
    std::uniform_int_distribution<uint32_t> random_uint32;
    std::uniform_int_distribution<uint8_t> random_byte;
    
    // Security test results
    struct SecurityTestResults {
        uint32_t replay_attacks_attempted{0};
        uint32_t replay_attacks_blocked{0};
        uint32_t invalid_packets_sent{0};
        uint32_t invalid_packets_rejected{0};
        uint32_t dos_attacks_attempted{0};
        uint32_t dos_attacks_mitigated{0};
        uint32_t malformed_messages_sent{0};
        uint32_t malformed_messages_rejected{0};
        uint32_t sequence_attacks_attempted{0};
        uint32_t sequence_attacks_blocked{0};
        bool overall_security_passed{false};
        
        void print_results() {
            std::cout << "\n======= SECURITY TEST RESULTS =======" << std::endl;
            std::cout << "Replay attack protection: " << replay_attacks_blocked 
                      << "/" << replay_attacks_attempted << std::endl;
            std::cout << "Invalid packet rejection: " << invalid_packets_rejected 
                      << "/" << invalid_packets_sent << std::endl;
            std::cout << "DoS attack mitigation: " << dos_attacks_mitigated 
                      << "/" << dos_attacks_attempted << std::endl;
            std::cout << "Malformed message rejection: " << malformed_messages_rejected 
                      << "/" << malformed_messages_sent << std::endl;
            std::cout << "Sequence attack protection: " << sequence_attacks_blocked 
                      << "/" << sequence_attacks_attempted << std::endl;
            std::cout << "Overall security test: " << (overall_security_passed ? "PASSED" : "FAILED") << std::endl;
            std::cout << "=======================================" << std::endl;
        }
    } results;
    
    SC_CTOR(security_test) 
        : clock("clock", 10, SC_NS)
        , reset("reset")
        , test_complete("test_complete")
        , enable_stack("enable_stack")
        , max_connections("max_connections")
        , hardware_acceleration_enabled("hardware_acceleration_enabled")
        , mtu_size("mtu_size")
        , security_socket("security_socket")
        , random_generator(12345) // Fixed seed for reproducible tests
        , random_uint32(0, 0xFFFFFFFF)
        , random_byte(0, 255)
    {
        // Create protocol stack
        protocol_stack = new dtls_protocol_stack("dtls_stack");
        
        // Connect configuration signals
        protocol_stack->enable_stack(enable_stack);
        protocol_stack->max_connections(max_connections);
        protocol_stack->hardware_acceleration_enabled(hardware_acceleration_enabled);
        protocol_stack->mtu_size(mtu_size);
        
        // Connect TLM socket
        security_socket.bind(protocol_stack->application_target_socket);
        
        // Configure for security testing
        enable_stack.write(true);
        max_connections.write(100);
        hardware_acceleration_enabled.write(false);
        mtu_size.write(1500);
        
        // Register security test processes
        SC_THREAD(run_replay_attack_test);
        SC_THREAD(run_invalid_packet_test);
        SC_THREAD(run_dos_attack_test);
        SC_THREAD(run_malformed_message_test);
        SC_THREAD(run_sequence_number_attack_test);
        SC_THREAD(run_connection_hijack_test);
        SC_THREAD(run_timing_attack_test);
        SC_THREAD(security_test_manager);
        
        std::cout << "Security Test Suite initialized" << std::endl;
    }
    
    ~security_test() {
        delete protocol_stack;
    }
    
    void run_replay_attack_test() {
        wait(100, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting replay attack test" << std::endl;
        
        // First, send a legitimate packet
        std::vector<unsigned char> legitimate_data(256);
        for (size_t i = 0; i < legitimate_data.size(); ++i) {
            legitimate_data[i] = static_cast<unsigned char>(i & 0xFF);
        }
        
        tlm::tlm_generic_payload legitimate_trans;
        sc_time delay = SC_ZERO_TIME;
        
        legitimate_trans.set_data_ptr(legitimate_data.data());
        legitimate_trans.set_data_length(legitimate_data.size());
        legitimate_trans.set_command(tlm::TLM_WRITE_COMMAND);
        legitimate_trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        dtls_extension legitimate_ext;
        legitimate_ext.message_type = dtls_extension::APPLICATION_DATA;
        legitimate_ext.connection_id = 1;
        legitimate_ext.epoch = 1;
        legitimate_ext.sequence_number = 12345;
        
        legitimate_trans.set_extension(&legitimate_ext);
        
        // Send legitimate packet
        security_socket->b_transport(legitimate_trans, delay);
        
        wait(50, SC_NS);
        
        // Now attempt replay attacks with the same sequence number
        const uint32_t num_replay_attempts = 10;
        
        for (uint32_t attempt = 0; attempt < num_replay_attempts; ++attempt) {
            tlm::tlm_generic_payload replay_trans;
            sc_time replay_delay = SC_ZERO_TIME;
            
            replay_trans.set_data_ptr(legitimate_data.data());
            replay_trans.set_data_length(legitimate_data.size());
            replay_trans.set_command(tlm::TLM_WRITE_COMMAND);
            replay_trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension replay_ext;
            replay_ext.message_type = dtls_extension::APPLICATION_DATA;
            replay_ext.connection_id = 1;
            replay_ext.epoch = 1;
            replay_ext.sequence_number = 12345; // Same sequence number (replay)
            replay_ext.replay_detected = false;
            
            replay_trans.set_extension(&replay_ext);
            
            results.replay_attacks_attempted++;
            
            security_socket->b_transport(replay_trans, replay_delay);
            
            // Check if replay was detected and blocked
            if (replay_ext.replay_detected || 
                replay_trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE) {
                results.replay_attacks_blocked++;
                std::cout << "[" << sc_time_stamp() << "] Replay attack " << attempt+1 
                          << " successfully blocked" << std::endl;
            } else {
                std::cout << "[" << sc_time_stamp() << "] WARNING: Replay attack " << attempt+1 
                          << " was NOT blocked" << std::endl;
            }
            
            wait(20, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Replay attack test completed: " 
                  << results.replay_attacks_blocked << "/" << results.replay_attacks_attempted 
                  << " attacks blocked" << std::endl;
    }
    
    void run_invalid_packet_test() {
        wait(500, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting invalid packet test" << std::endl;
        
        // Test various invalid packet scenarios
        
        // Test 1: NULL data pointer
        {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(nullptr);
            trans.set_data_length(100);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            results.invalid_packets_sent++;
            security_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE) {
                results.invalid_packets_rejected++;
            }
        }
        
        // Test 2: Zero length packet
        {
            unsigned char dummy = 0;
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(&dummy);
            trans.set_data_length(0);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            results.invalid_packets_sent++;
            security_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE) {
                results.invalid_packets_rejected++;
            }
        }
        
        // Test 3: Oversized packet
        {
            std::vector<unsigned char> oversized_data(100000); // Way too large
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(oversized_data.data());
            trans.set_data_length(oversized_data.size());
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 0xFFFFFFFF; // Invalid connection ID
            ext.epoch = 999;
            ext.sequence_number = 0;
            
            trans.set_extension(&ext);
            
            results.invalid_packets_sent++;
            security_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE || ext.has_error) {
                results.invalid_packets_rejected++;
            }
        }
        
        // Test 4: Invalid connection ID
        {
            std::vector<unsigned char> test_data(128, 0xAA);
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(test_data.data());
            trans.set_data_length(test_data.size());
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 0xDEADBEEF; // Non-existent connection
            ext.epoch = 1;
            ext.sequence_number = 1000;
            ext.has_error = false;
            
            trans.set_extension(&ext);
            
            results.invalid_packets_sent++;
            security_socket->b_transport(trans, delay);
            
            if (trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE || ext.has_error) {
                results.invalid_packets_rejected++;
            }
        }
        
        std::cout << "[" << sc_time_stamp() << "] Invalid packet test completed: " 
                  << results.invalid_packets_rejected << "/" << results.invalid_packets_sent 
                  << " invalid packets rejected" << std::endl;
    }
    
    void run_dos_attack_test() {
        wait(800, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting DoS attack test" << std::endl;
        
        // Simulate various DoS attack patterns
        
        // Attack 1: Connection flooding
        {
            const uint32_t flood_attempts = 200; // Try to exceed connection limit
            
            for (uint32_t i = 0; i < flood_attempts; ++i) {
                std::string handshake = "DOS_FLOOD_HANDSHAKE_" + std::to_string(i);
                
                tlm::tlm_generic_payload trans;
                sc_time delay = SC_ZERO_TIME;
                
                trans.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(handshake.c_str())));
                trans.set_data_length(handshake.length());
                trans.set_command(tlm::TLM_WRITE_COMMAND);
                trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
                
                dtls_extension ext;
                ext.message_type = dtls_extension::HANDSHAKE;
                ext.handshake_type = dtls_extension::CLIENT_HELLO;
                ext.connection_id = 1000 + i;
                ext.epoch = 0;
                ext.sequence_number = 0;
                ext.has_error = false;
                
                trans.set_extension(&ext);
                
                results.dos_attacks_attempted++;
                
                security_socket->b_transport(trans, delay);
                
                // Check if the system started rejecting connections (DoS protection)
                if (i > 100 && (trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE || ext.has_error)) {
                    results.dos_attacks_mitigated++;
                }
                
                // Minimal delay to simulate rapid requests
                wait(1, SC_NS);
            }
        }
        
        // Attack 2: Packet flooding on existing connection
        {
            const uint32_t packet_flood_count = 1000;
            std::vector<unsigned char> flood_data(64, 0xBB);
            
            for (uint32_t i = 0; i < packet_flood_count; ++i) {
                tlm::tlm_generic_payload trans;
                sc_time delay = SC_ZERO_TIME;
                
                trans.set_data_ptr(flood_data.data());
                trans.set_data_length(flood_data.size());
                trans.set_command(tlm::TLM_WRITE_COMMAND);
                trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
                
                dtls_extension ext;
                ext.message_type = dtls_extension::APPLICATION_DATA;
                ext.connection_id = 1;
                ext.epoch = 1;
                ext.sequence_number = i + 50000;
                ext.has_error = false;
                
                trans.set_extension(&ext);
                
                results.dos_attacks_attempted++;
                
                security_socket->b_transport(trans, delay);
                
                // Check if rate limiting kicked in
                if (i > 500 && (trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE || ext.has_error)) {
                    results.dos_attacks_mitigated++;
                }
                
                // No delay for maximum flooding effect
            }
        }
        
        std::cout << "[" << sc_time_stamp() << "] DoS attack test completed: " 
                  << results.dos_attacks_mitigated << "/" << results.dos_attacks_attempted 
                  << " attacks mitigated" << std::endl;
    }
    
    void run_malformed_message_test() {
        wait(1200, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting malformed message test" << std::endl;
        
        // Test various malformed message scenarios
        
        const uint32_t num_malformed_tests = 20;
        
        for (uint32_t test_idx = 0; test_idx < num_malformed_tests; ++test_idx) {
            // Generate random malformed data
            size_t data_size = 50 + (test_idx * 10);
            std::vector<unsigned char> malformed_data(data_size);
            
            for (size_t i = 0; i < data_size; ++i) {
                malformed_data[i] = random_byte(random_generator);
            }
            
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(malformed_data.data());
            trans.set_data_length(data_size);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            // Randomize extension fields to create malformed scenarios
            ext.message_type = static_cast<dtls_extension::MessageType>(random_byte(random_generator) % 5);
            ext.handshake_type = static_cast<dtls_extension::HandshakeType>(random_byte(random_generator) % 12);
            ext.connection_id = random_uint32(random_generator);
            ext.epoch = random_uint32(random_generator) % 10;
            ext.sequence_number = random_uint32(random_generator);
            ext.is_fragmented = (random_byte(random_generator) % 2) == 1;
            ext.fragment_offset = random_uint32(random_generator);
            ext.fragment_length = random_uint32(random_generator) % 1000;
            ext.message_length = random_uint32(random_generator) % 10000;
            ext.has_error = false;
            
            trans.set_extension(&ext);
            
            results.malformed_messages_sent++;
            
            security_socket->b_transport(trans, delay);
            
            // Check if malformed message was properly rejected
            if (trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE || ext.has_error) {
                results.malformed_messages_rejected++;
                std::cout << "[" << sc_time_stamp() << "] Malformed message " << test_idx+1 
                          << " properly rejected" << std::endl;
            } else {
                std::cout << "[" << sc_time_stamp() << "] WARNING: Malformed message " << test_idx+1 
                          << " was NOT rejected" << std::endl;
            }
            
            wait(10, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Malformed message test completed: " 
                  << results.malformed_messages_rejected << "/" << results.malformed_messages_sent 
                  << " malformed messages rejected" << std::endl;
    }
    
    void run_sequence_number_attack_test() {
        wait(1500, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting sequence number attack test" << std::endl;
        
        std::vector<unsigned char> seq_data(128, 0xCC);
        
        // Test 1: Out-of-order sequence numbers
        uint64_t sequence_numbers[] = {100, 50, 200, 75, 300, 25, 150};
        size_t num_sequences = sizeof(sequence_numbers) / sizeof(sequence_numbers[0]);
        
        for (size_t i = 0; i < num_sequences; ++i) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(seq_data.data());
            trans.set_data_length(seq_data.size());
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 2;
            ext.epoch = 1;
            ext.sequence_number = sequence_numbers[i];
            ext.replay_detected = false;
            ext.has_error = false;
            
            trans.set_extension(&ext);
            
            results.sequence_attacks_attempted++;
            
            security_socket->b_transport(trans, delay);
            
            // Check if out-of-order detection worked
            if (i > 2 && (ext.replay_detected || ext.has_error || 
                         trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE)) {
                results.sequence_attacks_blocked++;
            }
            
            wait(15, SC_NS);
        }
        
        // Test 2: Sequence number rollover attack
        uint64_t rollover_sequences[] = {0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000001};
        size_t num_rollover = sizeof(rollover_sequences) / sizeof(rollover_sequences[0]);
        
        for (size_t i = 0; i < num_rollover; ++i) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(seq_data.data());
            trans.set_data_length(seq_data.size());
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 3;
            ext.epoch = 1;
            ext.sequence_number = rollover_sequences[i];
            ext.replay_detected = false;
            ext.has_error = false;
            
            trans.set_extension(&ext);
            
            results.sequence_attacks_attempted++;
            
            security_socket->b_transport(trans, delay);
            
            // Rollover should be handled gracefully, not rejected
            if (trans.get_response_status() == tlm::TLM_OK_RESPONSE && !ext.has_error) {
                results.sequence_attacks_blocked++;
            }
            
            wait(20, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Sequence number attack test completed: " 
                  << results.sequence_attacks_blocked << "/" << results.sequence_attacks_attempted 
                  << " attacks properly handled" << std::endl;
    }
    
    void run_connection_hijack_test() {
        wait(1800, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting connection hijack test" << std::endl;
        
        // Establish a legitimate connection first
        std::string legitimate_handshake = "LEGITIMATE_CONNECTION";
        
        tlm::tlm_generic_payload legit_trans;
        sc_time delay = SC_ZERO_TIME;
        
        legit_trans.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(legitimate_handshake.c_str())));
        legit_trans.set_data_length(legitimate_handshake.length());
        legit_trans.set_command(tlm::TLM_WRITE_COMMAND);
        legit_trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
        
        dtls_extension legit_ext;
        legit_ext.message_type = dtls_extension::HANDSHAKE;
        legit_ext.handshake_type = dtls_extension::CLIENT_HELLO;
        legit_ext.connection_id = 5;
        legit_ext.epoch = 0;
        legit_ext.sequence_number = 0;
        
        legit_trans.set_extension(&legit_ext);
        
        security_socket->b_transport(legit_trans, delay);
        
        wait(50, SC_NS);
        
        // Now attempt to hijack the connection with different epochs/keys
        std::vector<unsigned char> hijack_data(256, 0xDD);
        
        for (uint32_t epoch = 0; epoch < 5; ++epoch) {
            tlm::tlm_generic_payload hijack_trans;
            sc_time hijack_delay = SC_ZERO_TIME;
            
            hijack_trans.set_data_ptr(hijack_data.data());
            hijack_trans.set_data_length(hijack_data.size());
            hijack_trans.set_command(tlm::TLM_WRITE_COMMAND);
            hijack_trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension hijack_ext;
            hijack_ext.message_type = dtls_extension::APPLICATION_DATA;
            hijack_ext.connection_id = 5; // Same connection ID
            hijack_ext.epoch = epoch;
            hijack_ext.sequence_number = 1000 + epoch;
            hijack_ext.has_error = false;
            
            hijack_trans.set_extension(&hijack_ext);
            
            security_socket->b_transport(hijack_trans, hijack_delay);
            
            // Invalid epochs should be rejected
            if (epoch != 1 && (hijack_trans.get_response_status() == tlm::TLM_GENERIC_ERROR_RESPONSE || 
                              hijack_ext.has_error)) {
                std::cout << "[" << sc_time_stamp() << "] Connection hijack attempt with epoch " 
                          << epoch << " properly blocked" << std::endl;
            }
            
            wait(25, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Connection hijack test completed" << std::endl;
    }
    
    void run_timing_attack_test() {
        wait(2000, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting timing attack test" << std::endl;
        
        // Test for timing side-channels in authentication
        std::vector<sc_time> auth_times;
        std::vector<unsigned char> auth_data(128);
        
        const uint32_t num_timing_tests = 50;
        
        for (uint32_t i = 0; i < num_timing_tests; ++i) {
            // Vary the authentication data
            for (size_t j = 0; j < auth_data.size(); ++j) {
                auth_data[j] = static_cast<unsigned char>((i + j) & 0xFF);
            }
            
            sc_time start_time = sc_time_stamp();
            
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(auth_data.data());
            trans.set_data_length(auth_data.size());
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::HANDSHAKE;
            ext.handshake_type = dtls_extension::CERTIFICATE_VERIFY;
            ext.connection_id = 6;
            ext.epoch = 0;
            ext.sequence_number = i;
            
            trans.set_extension(&ext);
            
            security_socket->b_transport(trans, delay);
            
            sc_time end_time = sc_time_stamp();
            auth_times.push_back(end_time - start_time + delay);
            
            wait(10, SC_NS);
        }
        
        // Analyze timing variations
        if (!auth_times.empty()) {
            sc_time min_time = *std::min_element(auth_times.begin(), auth_times.end());
            sc_time max_time = *std::max_element(auth_times.begin(), auth_times.end());
            sc_time time_variance = max_time - min_time;
            
            std::cout << "[" << sc_time_stamp() << "] Timing attack analysis:" << std::endl;
            std::cout << "  Min auth time: " << min_time << std::endl;
            std::cout << "  Max auth time: " << max_time << std::endl;
            std::cout << "  Time variance: " << time_variance << std::endl;
            
            // Large timing variations could indicate vulnerability
            if (time_variance > sc_time(1000, SC_NS)) {
                std::cout << "  WARNING: Large timing variations detected - potential side-channel" << std::endl;
            } else {
                std::cout << "  Timing appears consistent - good protection against timing attacks" << std::endl;
            }
        }
        
        std::cout << "[" << sc_time_stamp() << "] Timing attack test completed" << std::endl;
    }
    
    void security_test_manager() {
        wait(2500, SC_NS);
        
        // Evaluate overall security test results
        bool security_passed = true;
        
        // Check replay protection (should block most replays)
        double replay_protection_rate = (static_cast<double>(results.replay_attacks_blocked) / 
                                       std::max(1u, results.replay_attacks_attempted)) * 100.0;
        if (replay_protection_rate < 80.0) {
            security_passed = false;
            std::cout << "SECURITY FAIL: Insufficient replay protection (" 
                      << replay_protection_rate << "%)" << std::endl;
        }
        
        // Check invalid packet rejection (should reject all invalid packets)
        double invalid_rejection_rate = (static_cast<double>(results.invalid_packets_rejected) / 
                                       std::max(1u, results.invalid_packets_sent)) * 100.0;
        if (invalid_rejection_rate < 95.0) {
            security_passed = false;
            std::cout << "SECURITY FAIL: Insufficient invalid packet rejection (" 
                      << invalid_rejection_rate << "%)" << std::endl;
        }
        
        // Check DoS mitigation (should mitigate some attacks under load)
        double dos_mitigation_rate = (static_cast<double>(results.dos_attacks_mitigated) / 
                                    std::max(1u, results.dos_attacks_attempted)) * 100.0;
        if (dos_mitigation_rate < 20.0) {
            security_passed = false;
            std::cout << "SECURITY FAIL: Insufficient DoS protection (" 
                      << dos_mitigation_rate << "%)" << std::endl;
        }
        
        // Check malformed message rejection (should reject most malformed messages)
        double malformed_rejection_rate = (static_cast<double>(results.malformed_messages_rejected) / 
                                         std::max(1u, results.malformed_messages_sent)) * 100.0;
        if (malformed_rejection_rate < 70.0) {
            security_passed = false;
            std::cout << "SECURITY FAIL: Insufficient malformed message rejection (" 
                      << malformed_rejection_rate << "%)" << std::endl;
        }
        
        results.overall_security_passed = security_passed;
        results.print_results();
        
        test_complete.write(true);
        sc_stop();
    }
};

int sc_main(int argc, char* argv[]) {
    // Create security test
    security_test test("security_test");
    
    // Run simulation
    std::cout << "Starting DTLS v1.3 security test simulation..." << std::endl;
    sc_start();
    
    std::cout << "Security test simulation completed" << std::endl;
    return 0;
}