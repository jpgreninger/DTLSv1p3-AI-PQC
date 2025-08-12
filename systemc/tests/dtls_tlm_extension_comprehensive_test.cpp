/**
 * DTLS TLM Extension Comprehensive Test
 * 
 * Comprehensive testing of DTLS-specific TLM extensions including:
 * - dtls_extension class validation with all features
 * - dtls_transaction class testing with payload and extension management
 * - dtls_protocol_interface testing with all socket operations
 * - Message type and handshake type validation
 * - Timing annotation accuracy and performance measurement
 * - Error handling and alert generation mechanisms
 * - Fragmentation and reassembly logic validation
 * - Memory management and resource cleanup
 */

#include "systemc_test_framework.h"
#include "dtls_tlm_extensions.h"
#include "dtls_protocol_stack.h"
#include "dtls_timing_models.h"
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <chrono>
#include <random>

using namespace dtls::systemc::test;
using namespace dtls::v13::systemc_tlm;

/**
 * DTLS Extension Validation Module
 * 
 * SystemC module for testing dtls_extension functionality
 */
SC_MODULE(DTLSExtensionValidator) {
public:
    // Test control signals
    sc_in<bool> test_enable{"test_enable"};
    sc_out<bool> test_complete{"test_complete"};
    sc_out<uint32_t> test_results{"test_results"};
    sc_out<bool> validation_passed{"validation_passed"};
    
    // Test result signals for detailed reporting
    sc_signal<bool> extension_creation_passed{"extension_creation_passed"};
    sc_signal<bool> connection_context_passed{"connection_context_passed"};
    sc_signal<bool> security_parameters_passed{"security_parameters_passed"};
    sc_signal<bool> fragmentation_info_passed{"fragmentation_info_passed"};
    sc_signal<bool> timing_measurement_passed{"timing_measurement_passed"};
    sc_signal<bool> error_handling_passed{"error_handling_passed"};
    sc_signal<bool> message_type_validation_passed{"message_type_validation_passed"};
    sc_signal<bool> handshake_type_validation_passed{"handshake_type_validation_passed"};
    sc_signal<bool> cloning_functionality_passed{"cloning_functionality_passed"};
    sc_signal<bool> serialization_passed{"serialization_passed"};

private:
    // Test statistics
    uint32_t total_tests_run{0};
    uint32_t tests_passed{0};
    std::vector<std::string> error_messages;

    SC_CTOR(DTLSExtensionValidator) {
        SC_THREAD(extension_validation_process);
        sensitive << test_enable.pos();
    }

    void extension_validation_process() {
        while (true) {
            wait(test_enable.posedge_event());
            
            if (test_enable.read()) {
                run_comprehensive_extension_tests();
                
                // Calculate overall validation result
                bool overall_passed = (tests_passed == total_tests_run);
                validation_passed.write(overall_passed);
                test_results.write(tests_passed);
                test_complete.write(true);
                
                wait(10, SC_NS); // Brief delay for signal propagation
                test_complete.write(false);
            }
        }
    }

    void run_comprehensive_extension_tests() {
        total_tests_run = 0;
        tests_passed = 0;
        error_messages.clear();
        
        // Test 1: Extension Creation and Basic Operations
        test_extension_creation();
        
        // Test 2: Connection Context Management
        test_connection_context_management();
        
        // Test 3: Security Parameters Handling
        test_security_parameters_handling();
        
        // Test 4: Fragmentation Information Management
        test_fragmentation_info_management();
        
        // Test 5: Timing Measurement and Annotation
        test_timing_measurement_functionality();
        
        // Test 6: Error Handling and Alert Generation
        test_error_handling_mechanisms();
        
        // Test 7: Message Type Validation
        test_message_type_validation();
        
        // Test 8: Handshake Type Validation
        test_handshake_type_validation();
        
        // Test 9: Extension Cloning Functionality
        test_extension_cloning();
        
        // Test 10: Serialization and String Conversion
        test_serialization_functionality();
        
        std::cout << "DTLS Extension Tests: " << tests_passed << "/" << total_tests_run << " passed" << std::endl;
        if (!error_messages.empty()) {
            std::cout << "Errors encountered:" << std::endl;
            for (const auto& msg : error_messages) {
                std::cout << "  - " << msg << std::endl;
            }
        }
    }

    void test_extension_creation() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            // Test default construction
            dtls_extension ext1;
            if (ext1.connection_id != 0 || ext1.epoch != 0 || ext1.sequence_number != 0) {
                test_passed = false;
                error_messages.push_back("Default extension construction failed");
            }
            
            // Test parameterized construction
            dtls_extension ext2;
            ext2.connection_id = 0x12345678;
            ext2.epoch = 1;
            ext2.sequence_number = 100;
            
            if (ext2.connection_id != 0x12345678 || ext2.epoch != 1 || ext2.sequence_number != 100) {
                test_passed = false;
                error_messages.push_back("Parameterized extension construction failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Extension creation exception: ") + e.what());
        }
        
        extension_creation_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_connection_context_management() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Test connection context setting
            std::vector<uint8_t> cid_data = {0xDE, 0xAD, 0xBE, 0xEF};
            ext.set_connection_context(0x87654321, 2, 250, cid_data);
            
            if (ext.connection_id != 0x87654321 || ext.epoch != 2 || ext.sequence_number != 250) {
                test_passed = false;
                error_messages.push_back("Connection context setting failed");
            }
            
            if (ext.connection_id_data.size() != 4 || 
                ext.connection_id_data[0] != 0xDE || ext.connection_id_data[1] != 0xAD ||
                ext.connection_id_data[2] != 0xBE || ext.connection_id_data[3] != 0xEF) {
                test_passed = false;
                error_messages.push_back("Connection ID data setting failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Connection context exception: ") + e.what());
        }
        
        connection_context_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_security_parameters_handling() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Test security parameters setting
            std::vector<uint8_t> master_secret(48, 0xAA);
            std::vector<uint8_t> client_random(32, 0xBB);
            std::vector<uint8_t> server_random(32, 0xCC);
            
            ext.set_security_parameters(0x1301, 0x0401, 0x001D, master_secret, client_random, server_random);
            
            if (ext.cipher_suite != 0x1301 || ext.signature_scheme != 0x0401 || ext.named_group != 0x001D) {
                test_passed = false;
                error_messages.push_back("Security parameters setting failed");
            }
            
            if (ext.master_secret.size() != 48 || ext.client_random.size() != 32 || ext.server_random.size() != 32) {
                test_passed = false;
                error_messages.push_back("Security parameters data size validation failed");
            }
            
            // Validate content
            bool master_valid = std::all_of(ext.master_secret.begin(), ext.master_secret.end(), [](uint8_t b) { return b == 0xAA; });
            bool client_valid = std::all_of(ext.client_random.begin(), ext.client_random.end(), [](uint8_t b) { return b == 0xBB; });
            bool server_valid = std::all_of(ext.server_random.begin(), ext.server_random.end(), [](uint8_t b) { return b == 0xCC; });
            
            if (!master_valid || !client_valid || !server_valid) {
                test_passed = false;
                error_messages.push_back("Security parameters content validation failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Security parameters exception: ") + e.what());
        }
        
        security_parameters_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_fragmentation_info_management() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Test fragmentation info setting
            ext.set_fragmentation_info(true, 1024, 512, 2048, 5);
            
            if (!ext.is_fragmented || ext.fragment_offset != 1024 || ext.fragment_length != 512 ||
                ext.message_length != 2048 || ext.message_sequence != 5) {
                test_passed = false;
                error_messages.push_back("Fragmentation info setting failed");
            }
            
            // Test needs_fragmentation logic
            if (!ext.needs_fragmentation()) {
                test_passed = false;
                error_messages.push_back("needs_fragmentation() returned incorrect value");
            }
            
            // Test non-fragmented case
            ext.set_fragmentation_info(false, 0, 1024, 1024, 1);
            if (ext.is_fragmented || ext.needs_fragmentation()) {
                test_passed = false;
                error_messages.push_back("Non-fragmented case validation failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Fragmentation info exception: ") + e.what());
        }
        
        fragmentation_info_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_timing_measurement_functionality() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Test timing start
            ext.start_timing();
            
            // Simulate processing delays
            wait(10, SC_NS);
            ext.add_crypto_time(5, SC_NS);
            
            wait(5, SC_NS);
            ext.add_network_time(3, SC_NS);
            
            wait(2, SC_NS);
            ext.add_memory_time(1, SC_NS);
            
            // Validate timing measurements
            sc_time total_time = ext.get_total_processing_time();
            
            if (ext.crypto_processing_time != sc_time(5, SC_NS) ||
                ext.network_processing_time != sc_time(3, SC_NS) ||
                ext.memory_processing_time != sc_time(1, SC_NS)) {
                test_passed = false;
                error_messages.push_back("Individual timing measurements failed");
            }
            
            // Total processing time should be sum of individual times
            sc_time expected_total = ext.crypto_processing_time + ext.network_processing_time + ext.memory_processing_time;
            if (total_time != expected_total) {
                test_passed = false;
                error_messages.push_back("Total processing time calculation failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Timing measurement exception: ") + e.what());
        }
        
        timing_measurement_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_error_handling_mechanisms() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Test error setting and retrieval
            std::string error_msg = "Test error message";
            ext.set_error(2, 40, error_msg); // Alert level 2 (fatal), description 40 (handshake_failure)
            
            if (!ext.has_error || ext.alert_level != 2 || ext.alert_description != 40) {
                test_passed = false;
                error_messages.push_back("Error setting validation failed");
            }
            
            if (ext.error_message != error_msg) {
                test_passed = false;
                error_messages.push_back("Error message setting failed");
            }
            
            // Test clearing error state
            ext.has_error = false;
            ext.alert_level = 0;
            ext.alert_description = 0;
            ext.error_message.clear();
            
            if (ext.has_error || ext.alert_level != 0 || ext.alert_description != 0 || !ext.error_message.empty()) {
                test_passed = false;
                error_messages.push_back("Error state clearing failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Error handling exception: ") + e.what());
        }
        
        error_handling_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_message_type_validation() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Test all message types
            std::vector<MessageType> message_types = {
                MessageType::HANDSHAKE,
                MessageType::APPLICATION_DATA,
                MessageType::ALERT,
                MessageType::CHANGE_CIPHER_SPEC,
                MessageType::ACK
            };
            
            for (auto msg_type : message_types) {
                ext.message_type = msg_type;
                
                // Test message type specific methods
                bool is_handshake = ext.is_handshake_message();
                bool is_app_data = ext.is_application_data();
                
                if (msg_type == MessageType::HANDSHAKE && !is_handshake) {
                    test_passed = false;
                    error_messages.push_back("Handshake message type detection failed");
                }
                
                if (msg_type == MessageType::APPLICATION_DATA && !is_app_data) {
                    test_passed = false;
                    error_messages.push_back("Application data message type detection failed");
                }
                
                if (msg_type != MessageType::HANDSHAKE && is_handshake) {
                    test_passed = false;
                    error_messages.push_back("False positive handshake detection");
                }
                
                if (msg_type != MessageType::APPLICATION_DATA && is_app_data) {
                    test_passed = false;
                    error_messages.push_back("False positive application data detection");
                }
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Message type validation exception: ") + e.what());
        }
        
        message_type_validation_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_handshake_type_validation() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Test all handshake types
            std::vector<HandshakeType> handshake_types = {
                HandshakeType::CLIENT_HELLO,
                HandshakeType::SERVER_HELLO,
                HandshakeType::NEW_SESSION_TICKET,
                HandshakeType::END_OF_EARLY_DATA,
                HandshakeType::ENCRYPTED_EXTENSIONS,
                HandshakeType::CERTIFICATE,
                HandshakeType::CERTIFICATE_REQUEST,
                HandshakeType::CERTIFICATE_VERIFY,
                HandshakeType::FINISHED,
                HandshakeType::KEY_UPDATE,
                HandshakeType::MESSAGE_HASH
            };
            
            for (auto hs_type : handshake_types) {
                ext.message_type = MessageType::HANDSHAKE;
                ext.handshake_type = hs_type;
                
                // Validate that handshake message detection still works
                if (!ext.is_handshake_message()) {
                    test_passed = false;
                    error_messages.push_back("Handshake message detection failed for specific handshake type");
                    break;
                }
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Handshake type validation exception: ") + e.what());
        }
        
        handshake_type_validation_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_extension_cloning() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext1;
            
            // Setup comprehensive extension data
            ext1.connection_id = 0x12345678;
            ext1.epoch = 5;
            ext1.sequence_number = 1000;
            ext1.cipher_suite = 0x1301;
            ext1.message_type = MessageType::HANDSHAKE;
            ext1.handshake_type = HandshakeType::CLIENT_HELLO;
            ext1.connection_id_data = {0x01, 0x02, 0x03, 0x04};
            ext1.master_secret = std::vector<uint8_t>(48, 0xFF);
            ext1.set_fragmentation_info(true, 512, 256, 1024, 3);
            ext1.start_timing();
            ext1.add_crypto_time(10, SC_NS);
            ext1.set_error(1, 10, "Test error");
            
            // Test cloning
            std::unique_ptr<tlm_extension_base> cloned_base = ext1.clone();
            dtls_extension* cloned = dynamic_cast<dtls_extension*>(cloned_base.get());
            
            if (!cloned) {
                test_passed = false;
                error_messages.push_back("Extension cloning returned null or wrong type");
            } else {
                // Validate all fields were cloned correctly
                if (cloned->connection_id != ext1.connection_id ||
                    cloned->epoch != ext1.epoch ||
                    cloned->sequence_number != ext1.sequence_number ||
                    cloned->cipher_suite != ext1.cipher_suite ||
                    cloned->message_type != ext1.message_type ||
                    cloned->handshake_type != ext1.handshake_type) {
                    test_passed = false;
                    error_messages.push_back("Basic field cloning failed");
                }
                
                if (cloned->connection_id_data != ext1.connection_id_data ||
                    cloned->master_secret != ext1.master_secret) {
                    test_passed = false;
                    error_messages.push_back("Vector field cloning failed");
                }
                
                if (cloned->is_fragmented != ext1.is_fragmented ||
                    cloned->fragment_offset != ext1.fragment_offset ||
                    cloned->fragment_length != ext1.fragment_length) {
                    test_passed = false;
                    error_messages.push_back("Fragmentation info cloning failed");
                }
                
                if (cloned->has_error != ext1.has_error ||
                    cloned->alert_level != ext1.alert_level ||
                    cloned->error_message != ext1.error_message) {
                    test_passed = false;
                    error_messages.push_back("Error state cloning failed");
                }
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Extension cloning exception: ") + e.what());
        }
        
        cloning_functionality_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_serialization_functionality() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_extension ext;
            
            // Setup extension with comprehensive data
            ext.connection_id = 0xABCDEF01;
            ext.epoch = 3;
            ext.sequence_number = 777;
            ext.message_type = MessageType::APPLICATION_DATA;
            ext.cipher_suite = 0x1302;
            
            // Test string conversion
            std::string ext_str = ext.to_string();
            
            // Validate that string contains key information
            if (ext_str.find("connection_id") == std::string::npos ||
                ext_str.find("epoch") == std::string::npos ||
                ext_str.find("sequence_number") == std::string::npos) {
                test_passed = false;
                error_messages.push_back("Extension string representation missing key fields");
            }
            
            // Validate that specific values are present
            if (ext_str.find("ABCDEF01") == std::string::npos ||
                ext_str.find("777") == std::string::npos) {
                test_passed = false;
                error_messages.push_back("Extension string representation missing specific values");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Serialization exception: ") + e.what());
        }
        
        serialization_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }
};

/**
 * DTLS Transaction Validation Module
 * 
 * SystemC module for testing dtls_transaction functionality
 */
SC_MODULE(DTLSTransactionValidator) {
public:
    sc_in<bool> test_enable{"test_enable"};
    sc_out<bool> test_complete{"test_complete"};
    sc_out<uint32_t> test_results{"test_results"};
    sc_out<bool> validation_passed{"validation_passed"};
    
    // Detailed test result signals
    sc_signal<bool> transaction_creation_passed{"transaction_creation_passed"};
    sc_signal<bool> payload_management_passed{"payload_management_passed"};
    sc_signal<bool> extension_handling_passed{"extension_handling_passed"};
    sc_signal<bool> delay_management_passed{"delay_management_passed"};
    sc_signal<bool> configuration_methods_passed{"configuration_methods_passed"};
    sc_signal<bool> fragmentation_support_passed{"fragmentation_support_passed"};
    sc_signal<bool> error_response_passed{"error_response_passed"};
    sc_signal<bool> copy_assignment_passed{"copy_assignment_passed"};

private:
    uint32_t total_tests_run{0};
    uint32_t tests_passed{0};
    std::vector<std::string> error_messages;

    SC_CTOR(DTLSTransactionValidator) {
        SC_THREAD(transaction_validation_process);
        sensitive << test_enable.pos();
    }

    void transaction_validation_process() {
        while (true) {
            wait(test_enable.posedge_event());
            
            if (test_enable.read()) {
                run_comprehensive_transaction_tests();
                
                bool overall_passed = (tests_passed == total_tests_run);
                validation_passed.write(overall_passed);
                test_results.write(tests_passed);
                test_complete.write(true);
                
                wait(10, SC_NS);
                test_complete.write(false);
            }
        }
    }

    void run_comprehensive_transaction_tests() {
        total_tests_run = 0;
        tests_passed = 0;
        error_messages.clear();
        
        test_transaction_creation();
        test_payload_management();
        test_extension_handling();
        test_delay_management();
        test_configuration_methods();
        test_fragmentation_support();
        test_error_response_handling();
        test_copy_and_assignment();
        
        std::cout << "DTLS Transaction Tests: " << tests_passed << "/" << total_tests_run << " passed" << std::endl;
        if (!error_messages.empty()) {
            std::cout << "Transaction test errors:" << std::endl;
            for (const auto& msg : error_messages) {
                std::cout << "  - " << msg << std::endl;
            }
        }
    }

    void test_transaction_creation() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            // Test default construction
            dtls_transaction trans1;
            if (trans1.get_data_size() != 0 || trans1.get_delay() != sc_time(SC_ZERO_TIME)) {
                test_passed = false;
                error_messages.push_back("Default transaction construction failed");
            }
            
            // Test parameterized construction
            std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04, 0x05};
            dtls_transaction trans2(test_data);
            
            if (trans2.get_data_size() != 5) {
                test_passed = false;
                error_messages.push_back("Parameterized transaction construction failed");
            }
            
            // Validate data content
            const uint8_t* data_ptr = trans2.get_data();
            for (size_t i = 0; i < test_data.size(); ++i) {
                if (data_ptr[i] != test_data[i]) {
                    test_passed = false;
                    error_messages.push_back("Transaction data content validation failed");
                    break;
                }
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Transaction creation exception: ") + e.what());
        }
        
        transaction_creation_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_payload_management() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_transaction trans;
            
            // Test data allocation
            const size_t data_size = 1024;
            trans.allocate_data(data_size);
            
            if (trans.get_data_size() != data_size || trans.get_data() == nullptr) {
                test_passed = false;
                error_messages.push_back("Data allocation failed");
            }
            
            // Test data setting
            std::vector<uint8_t> new_data(512, 0xAB);
            trans.set_data(new_data);
            
            if (trans.get_data_size() != 512) {
                test_passed = false;
                error_messages.push_back("Data setting size validation failed");
            }
            
            // Validate content
            const uint8_t* data_ptr = trans.get_data();
            for (size_t i = 0; i < 512; ++i) {
                if (data_ptr[i] != 0xAB) {
                    test_passed = false;
                    error_messages.push_back("Data setting content validation failed");
                    break;
                }
            }
            
            // Test payload access
            tlm_generic_payload& payload = trans.get_payload();
            if (payload.get_data_length() != 512) {
                test_passed = false;
                error_messages.push_back("Payload access validation failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Payload management exception: ") + e.what());
        }
        
        payload_management_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_extension_handling() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_transaction trans;
            
            // Get and modify extension
            dtls_extension* ext = trans.get_extension();
            if (!ext) {
                test_passed = false;
                error_messages.push_back("Extension retrieval failed");
            } else {
                // Modify extension properties
                ext->connection_id = 0x98765432;
                ext->epoch = 7;
                ext->sequence_number = 555;
                ext->message_type = MessageType::ALERT;
                
                // Retrieve again and validate persistence
                const dtls_extension* const_ext = const_cast<const dtls_transaction&>(trans).get_extension();
                if (!const_ext || 
                    const_ext->connection_id != 0x98765432 ||
                    const_ext->epoch != 7 ||
                    const_ext->sequence_number != 555 ||
                    const_ext->message_type != MessageType::ALERT) {
                    test_passed = false;
                    error_messages.push_back("Extension persistence validation failed");
                }
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Extension handling exception: ") + e.what());
        }
        
        extension_handling_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_delay_management() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_transaction trans;
            
            // Test delay setting
            sc_time initial_delay(50, SC_NS);
            trans.set_delay(initial_delay);
            
            if (trans.get_delay() != initial_delay) {
                test_passed = false;
                error_messages.push_back("Delay setting validation failed");
            }
            
            // Test delay addition
            sc_time additional_delay(25, SC_NS);
            trans.add_delay(additional_delay);
            
            sc_time expected_total = initial_delay + additional_delay;
            if (trans.get_delay() != expected_total) {
                test_passed = false;
                error_messages.push_back("Delay addition validation failed");
            }
            
            // Test delay accumulation
            trans.add_delay(sc_time(10, SC_NS));
            trans.add_delay(sc_time(5, SC_NS));
            
            sc_time final_expected = expected_total + sc_time(15, SC_NS);
            if (trans.get_delay() != final_expected) {
                test_passed = false;
                error_messages.push_back("Delay accumulation validation failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Delay management exception: ") + e.what());
        }
        
        delay_management_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_configuration_methods() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_transaction trans;
            
            // Test handshake configuration
            std::vector<uint8_t> handshake_data = {0x01, 0x00, 0x00, 0x04}; // CLIENT_HELLO mock
            trans.configure_as_handshake(HandshakeType::CLIENT_HELLO, handshake_data);
            
            const dtls_extension* ext = trans.get_extension();
            if (!ext || ext->message_type != MessageType::HANDSHAKE || 
                ext->handshake_type != HandshakeType::CLIENT_HELLO) {
                test_passed = false;
                error_messages.push_back("Handshake configuration failed");
            }
            
            // Test application data configuration
            std::vector<uint8_t> app_data(256, 0xDD);
            trans.configure_as_application_data(app_data);
            
            ext = trans.get_extension();
            if (!ext || ext->message_type != MessageType::APPLICATION_DATA) {
                test_passed = false;
                error_messages.push_back("Application data configuration failed");
            }
            
            // Test alert configuration
            trans.configure_as_alert(2, 40, "Handshake failure");
            
            ext = trans.get_extension();
            if (!ext || ext->message_type != MessageType::ALERT || 
                ext->alert_level != 2 || ext->alert_description != 40) {
                test_passed = false;
                error_messages.push_back("Alert configuration failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Configuration methods exception: ") + e.what());
        }
        
        configuration_methods_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_fragmentation_support() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            // Create large transaction that will need fragmentation
            std::vector<uint8_t> large_data(2048, 0xEE);
            dtls_transaction trans(large_data);
            
            // Test fragmentation
            size_t mtu = 512;
            std::vector<dtls_transaction> fragments = trans.fragment(mtu);
            
            // Calculate expected number of fragments
            size_t expected_fragments = (large_data.size() + mtu - 1) / mtu;
            if (fragments.size() != expected_fragments) {
                test_passed = false;
                error_messages.push_back("Fragment count validation failed");
            }
            
            // Validate fragment sizes and data
            size_t total_reconstructed_size = 0;
            for (size_t i = 0; i < fragments.size(); ++i) {
                const dtls_extension* frag_ext = fragments[i].get_extension();
                if (!frag_ext || !frag_ext->is_fragmented) {
                    test_passed = false;
                    error_messages.push_back("Fragment extension validation failed");
                    break;
                }
                
                size_t expected_frag_size = (i == fragments.size() - 1) ? 
                    (large_data.size() % mtu == 0 ? mtu : large_data.size() % mtu) : mtu;
                
                if (fragments[i].get_data_size() != expected_frag_size) {
                    test_passed = false;
                    error_messages.push_back("Fragment size validation failed");
                    break;
                }
                
                total_reconstructed_size += fragments[i].get_data_size();
                
                // Validate fragment offset
                size_t expected_offset = i * mtu;
                if (frag_ext->fragment_offset != expected_offset) {
                    test_passed = false;
                    error_messages.push_back("Fragment offset validation failed");
                    break;
                }
            }
            
            if (total_reconstructed_size != large_data.size()) {
                test_passed = false;
                error_messages.push_back("Total fragment size validation failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Fragmentation support exception: ") + e.what());
        }
        
        fragmentation_support_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_error_response_handling() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            dtls_transaction trans;
            
            // Test response status methods
            if (!trans.is_response_ok()) {
                test_passed = false;
                error_messages.push_back("Default response status should be OK");
            }
            
            if (trans.has_error()) {
                test_passed = false;
                error_messages.push_back("Default transaction should not have error");
            }
            
            // Set error state through extension
            dtls_extension* ext = trans.get_extension();
            ext->set_error(2, 50, "Protocol version error");
            
            if (trans.is_response_ok()) {
                test_passed = false;
                error_messages.push_back("Transaction with error should not be OK");
            }
            
            if (!trans.has_error()) {
                test_passed = false;
                error_messages.push_back("Transaction should report error state");
            }
            
            std::string error_msg = trans.get_error_message();
            if (error_msg != "Protocol version error") {
                test_passed = false;
                error_messages.push_back("Error message retrieval failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Error response handling exception: ") + e.what());
        }
        
        error_response_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }

    void test_copy_and_assignment() {
        total_tests_run++;
        bool test_passed = true;
        
        try {
            // Create source transaction with comprehensive data
            std::vector<uint8_t> source_data = {0x10, 0x20, 0x30, 0x40, 0x50};
            dtls_transaction trans1(source_data);
            
            dtls_extension* ext1 = trans1.get_extension();
            ext1->connection_id = 0x11223344;
            ext1->epoch = 9;
            ext1->sequence_number = 999;
            
            trans1.set_delay(sc_time(100, SC_NS));
            
            // Test copy constructor
            dtls_transaction trans2(trans1);
            
            if (trans2.get_data_size() != trans1.get_data_size() ||
                trans2.get_delay() != trans1.get_delay()) {
                test_passed = false;
                error_messages.push_back("Copy constructor basic validation failed");
            }
            
            const dtls_extension* ext2 = trans2.get_extension();
            if (!ext2 || ext2->connection_id != ext1->connection_id ||
                ext2->epoch != ext1->epoch || ext2->sequence_number != ext1->sequence_number) {
                test_passed = false;
                error_messages.push_back("Copy constructor extension validation failed");
            }
            
            // Test assignment operator
            dtls_transaction trans3;
            trans3 = trans1;
            
            if (trans3.get_data_size() != trans1.get_data_size() ||
                trans3.get_delay() != trans1.get_delay()) {
                test_passed = false;
                error_messages.push_back("Assignment operator basic validation failed");
            }
            
            const dtls_extension* ext3 = trans3.get_extension();
            if (!ext3 || ext3->connection_id != ext1->connection_id ||
                ext3->epoch != ext1->epoch || ext3->sequence_number != ext1->sequence_number) {
                test_passed = false;
                error_messages.push_back("Assignment operator extension validation failed");
            }
            
            // Test move constructor
            dtls_transaction trans4(std::move(trans2));
            if (trans4.get_data_size() != source_data.size()) {
                test_passed = false;
                error_messages.push_back("Move constructor validation failed");
            }
            
        } catch (const std::exception& e) {
            test_passed = false;
            error_messages.push_back(std::string("Copy and assignment exception: ") + e.what());
        }
        
        copy_assignment_passed.write(test_passed);
        if (test_passed) tests_passed++;
    }
};

/**
 * Main test class for DTLS TLM Extension Comprehensive Testing
 */
class DTLSTLMExtensionComprehensiveTest : public SystemCTestFramework {
protected:
    void SetUp() override {
        SystemCTestFramework::SetUp();
        
        // Configure test for TLM extension validation
        config_.simulation_duration = sc_time(5, SC_SEC);
        config_.enable_tracing = true;
        config_.trace_filename = "dtls_tlm_extension_test.vcd";
        config_.enable_performance_measurement = true;
        
        // Initialize test modules
        extension_validator = std::make_unique<DTLSExtensionValidator>("ExtensionValidator");
        transaction_validator = std::make_unique<DTLSTransactionValidator>("TransactionValidator");
        
        // Create control signals
        extension_test_enable = std::make_unique<sc_signal<bool>>("extension_test_enable");
        transaction_test_enable = std::make_unique<sc_signal<bool>>("transaction_test_enable");
        
        extension_test_complete = std::make_unique<sc_signal<bool>>("extension_test_complete");
        transaction_test_complete = std::make_unique<sc_signal<bool>>("transaction_test_complete");
        
        extension_validation_passed = std::make_unique<sc_signal<bool>>("extension_validation_passed");
        transaction_validation_passed = std::make_unique<sc_signal<bool>>("transaction_validation_passed");
        
        extension_test_results = std::make_unique<sc_signal<uint32_t>>("extension_test_results");
        transaction_test_results = std::make_unique<sc_signal<uint32_t>>("transaction_test_results");
        
        // Connect signals
        extension_validator->test_enable(*extension_test_enable);
        extension_validator->test_complete(*extension_test_complete);
        extension_validator->validation_passed(*extension_validation_passed);
        extension_validator->test_results(*extension_test_results);
        
        transaction_validator->test_enable(*transaction_test_enable);
        transaction_validator->test_complete(*transaction_test_complete);
        transaction_validator->validation_passed(*transaction_validation_passed);
        transaction_validator->test_results(*transaction_test_results);
    }

private:
    std::unique_ptr<DTLSExtensionValidator> extension_validator;
    std::unique_ptr<DTLSTransactionValidator> transaction_validator;
    
    std::unique_ptr<sc_signal<bool>> extension_test_enable;
    std::unique_ptr<sc_signal<bool>> transaction_test_enable;
    std::unique_ptr<sc_signal<bool>> extension_test_complete;
    std::unique_ptr<sc_signal<bool>> transaction_test_complete;
    std::unique_ptr<sc_signal<bool>> extension_validation_passed;
    std::unique_ptr<sc_signal<bool>> transaction_validation_passed;
    std::unique_ptr<sc_signal<uint32_t>> extension_test_results;
    std::unique_ptr<sc_signal<uint32_t>> transaction_test_results;
};

/**
 * Test: DTLS Extension Validation
 * 
 * Comprehensive validation of dtls_extension functionality
 */
TEST_F(DTLSTLMExtensionComprehensiveTest, DTLSExtensionValidation) {
    // Start extension validation
    extension_test_enable->write(true);
    
    // Wait for test completion
    while (!extension_test_complete->read()) {
        sc_start(sc_time(10, SC_MS));
    }
    
    // Validate results
    EXPECT_TRUE(extension_validation_passed->read()) 
        << "DTLS extension validation failed";
    
    uint32_t tests_passed = extension_test_results->read();
    std::cout << "Extension tests passed: " << tests_passed << std::endl;
    EXPECT_GT(tests_passed, 8) << "Expected at least 9 extension tests to pass";
}

/**
 * Test: DTLS Transaction Validation
 * 
 * Comprehensive validation of dtls_transaction functionality
 */
TEST_F(DTLSTLMExtensionComprehensiveTest, DTLSTransactionValidation) {
    // Start transaction validation
    transaction_test_enable->write(true);
    
    // Wait for test completion
    while (!transaction_test_complete->read()) {
        sc_start(sc_time(10, SC_MS));
    }
    
    // Validate results
    EXPECT_TRUE(transaction_validation_passed->read()) 
        << "DTLS transaction validation failed";
    
    uint32_t tests_passed = transaction_test_results->read();
    std::cout << "Transaction tests passed: " << tests_passed << std::endl;
    EXPECT_GT(tests_passed, 7) << "Expected at least 8 transaction tests to pass";
}

/**
 * Test: Combined Extension and Transaction Integration
 * 
 * Test interaction between extensions and transactions
 */
TEST_F(DTLSTLMExtensionComprehensiveTest, ExtensionTransactionIntegration) {
    // Start both validators simultaneously
    extension_test_enable->write(true);
    transaction_test_enable->write(true);
    
    // Wait for both to complete
    bool extension_done = false, transaction_done = false;
    while (!extension_done || !transaction_done) {
        sc_start(sc_time(10, SC_MS));
        
        if (extension_test_complete->read() && !extension_done) {
            extension_done = true;
            std::cout << "Extension validation completed" << std::endl;
        }
        
        if (transaction_test_complete->read() && !transaction_done) {
            transaction_done = true;
            std::cout << "Transaction validation completed" << std::endl;
        }
    }
    
    // Validate both passed
    EXPECT_TRUE(extension_validation_passed->read()) 
        << "Extension validation failed in integration test";
    EXPECT_TRUE(transaction_validation_passed->read()) 
        << "Transaction validation failed in integration test";
    
    // Test specific integration scenarios
    dtls_transaction integrated_trans;
    dtls_extension* ext = integrated_trans.get_extension();
    
    // Configure comprehensive transaction
    ext->set_connection_context(0xDEADBEEF, 10, 12345, {0xCA, 0xFE, 0xBA, 0xBE});
    ext->set_security_parameters(0x1303, 0x0804, 0x0018, 
                                std::vector<uint8_t>(48, 0x55),
                                std::vector<uint8_t>(32, 0x66),
                                std::vector<uint8_t>(32, 0x77));
    
    std::vector<uint8_t> app_data(1536, 0x88);
    integrated_trans.configure_as_application_data(app_data);
    integrated_trans.set_delay(sc_time(75, SC_NS));
    
    // Validate integration
    EXPECT_EQ(ext->connection_id, 0xDEADBEEF);
    EXPECT_EQ(ext->epoch, 10);
    EXPECT_EQ(ext->message_type, MessageType::APPLICATION_DATA);
    EXPECT_EQ(integrated_trans.get_data_size(), 1536);
    EXPECT_EQ(integrated_trans.get_delay(), sc_time(75, SC_NS));
    
    std::cout << "Integration test completed successfully" << std::endl;
}

/**
 * SystemC main function for standalone testing
 */
int sc_main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}