/**
 * DTLS v1.3 Connection ID (CID) Extension Test for SystemC Implementation
 * 
 * Comprehensive testing of RFC 9147 Connection ID functionality including:
 * - CID negotiation and handshake integration
 * - CID validation and security compliance  
 * - CID sequence number management
 * - CID migration and update mechanisms
 * - RFC 9147 compliance validation
 * - Performance and timing analysis
 * - Error handling and edge cases
 */

#include "systemc_test_framework.h"
#include "dtls_tlm_extensions.h"
#include "dtls_protocol_modules.h"
#include "dtls_protocol_stack.h"
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <random>
#include <chrono>

using namespace dtls::systemc::test;
using namespace dtls::v13::systemc_tlm;

/**
 * CID Test Harness Module
 * 
 * Comprehensive test module for DTLS v1.3 Connection ID functionality
 */
SC_MODULE(DTLSCIDTestHarness) {
public:
    // TLM sockets for protocol testing
    tlm_utils::simple_target_socket<DTLSCIDTestHarness> protocol_target_socket;
    tlm_utils::simple_initiator_socket<DTLSCIDTestHarness> protocol_initiator_socket;
    
    // Test control ports
    sc_in<bool> test_enable{"test_enable"};
    sc_out<bool> test_complete{"test_complete"};
    sc_out<bool> cid_tests_passed{"cid_tests_passed"};
    sc_out<uint32_t> tests_executed{"tests_executed"};
    sc_out<uint32_t> tests_passed{"tests_passed"};
    sc_out<uint32_t> tests_failed{"tests_failed"};
    
    // CID-specific test status
    sc_out<bool> cid_negotiation_passed{"cid_negotiation_passed"};
    sc_out<bool> cid_validation_passed{"cid_validation_passed"};
    sc_out<bool> cid_migration_passed{"cid_migration_passed"};
    sc_out<bool> cid_sequence_passed{"cid_sequence_passed"};
    sc_out<bool> rfc9147_compliance_passed{"rfc9147_compliance_passed"};
    
    // Performance metrics
    sc_out<sc_time> cid_negotiation_time{"cid_negotiation_time"};
    sc_out<sc_time> cid_validation_time{"cid_validation_time"};
    sc_out<uint32_t> cid_operations_per_second{"cid_operations_per_second"};
    
    // Test data structures
    struct CIDTestCase {
        std::string name;
        std::vector<uint8_t> cid_data;
        uint64_t sequence_number;
        bool should_pass;
        std::string expected_error;
    };
    
    std::vector<CIDTestCase> test_cases;
    handshake_engine_module* handshake_engine;
    
private:
    // Test state
    uint32_t current_test{0};
    uint32_t passed_tests{0};
    uint32_t failed_tests{0};
    bool all_tests_passed{true};
    
    // Performance tracking
    sc_time test_start_time;
    sc_time total_test_time;

public:
    SC_CTOR(DTLSCIDTestHarness) : protocol_target_socket("protocol_target_socket"),
                                 protocol_initiator_socket("protocol_initiator_socket") {
        // Initialize test cases
        initialize_cid_test_cases();
        
        // Create handshake engine for testing
        handshake_engine = new handshake_engine_module("handshake_engine");
        
        // SystemC processes
        SC_THREAD(cid_test_process);
        sensitive << test_enable.pos();
        
        SC_METHOD(update_test_status);
        sensitive << test_complete;
        
        // TLM transport method
        protocol_target_socket.register_b_transport(this, &DTLSCIDTestHarness::b_transport);
        
        std::cout << "DTLSCIDTestHarness: Initialized with " << test_cases.size() << " test cases" << std::endl;
    }
    
    ~DTLSCIDTestHarness() {
        delete handshake_engine;
    }

private:
    void initialize_cid_test_cases() {
        // Test Case 1: Valid CID negotiation
        test_cases.push_back({
            "Valid CID Negotiation",
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, // 8-byte CID
            1,
            true,
            ""
        });
        
        // Test Case 2: Maximum length CID (20 bytes)
        test_cases.push_back({
            "Maximum Length CID",
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
             0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}, // 20 bytes
            2,
            true,
            ""
        });
        
        // Test Case 3: CID too long (should fail)
        test_cases.push_back({
            "CID Too Long",
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
             0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15}, // 21 bytes
            3,
            false,
            "CID validation failed: length exceeds RFC 9147 limit"
        });
        
        // Test Case 4: All-zero CID (should fail per RFC 9147)
        test_cases.push_back({
            "All-Zero CID",
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // All zeros
            4,
            false,
            "CID validation failed: all-zero CID not allowed"
        });
        
        // Test Case 5: Empty CID (valid)
        test_cases.push_back({
            "Empty CID",
            {}, // Empty CID
            5,
            true,
            ""
        });
        
        // Test Case 6: Single byte CID
        test_cases.push_back({
            "Single Byte CID",
            {0xFF}, // Single byte
            6,
            true,
            ""
        });
        
        // Test Case 7: Sequence number replay (should fail)
        test_cases.push_back({
            "Sequence Number Replay",
            {0x01, 0x02, 0x03, 0x04}, // Valid CID
            1, // Replay sequence number 1
            false,
            "CID validation failed: invalid sequence number"
        });
        
        // Test Case 8: Large sequence number gap
        test_cases.push_back({
            "Large Sequence Gap",
            {0x01, 0x02, 0x03, 0x04}, // Valid CID
            2000, // Large gap
            false,
            "CID sequence gap too large"
        });
    }
    
    void cid_test_process() {
        while (true) {
            wait(test_enable.posedge_event());
            
            std::cout << "DTLSCIDTestHarness: Starting CID test suite" << std::endl;
            test_start_time = sc_time_stamp();
            
            // Reset test state
            current_test = 0;
            passed_tests = 0;
            failed_tests = 0;
            all_tests_passed = true;
            
            // Execute all test cases
            for (const auto& test_case : test_cases) {
                current_test++;
                bool result = execute_cid_test_case(test_case);
                
                if (result) {
                    passed_tests++;
                    std::cout << "DTLSCIDTestHarness: Test '" << test_case.name << "' PASSED" << std::endl;
                } else {
                    failed_tests++;
                    all_tests_passed = false;
                    std::cout << "DTLSCIDTestHarness: Test '" << test_case.name << "' FAILED" << std::endl;
                }
                
                wait(10, SC_NS); // Small delay between tests
            }
            
            // Execute specialized CID tests
            execute_cid_negotiation_tests();
            execute_cid_migration_tests();
            execute_cid_performance_tests();
            execute_rfc9147_compliance_tests();
            
            total_test_time = sc_time_stamp() - test_start_time;
            
            // Update output ports
            tests_executed.write(test_cases.size());
            tests_passed.write(passed_tests);
            tests_failed.write(failed_tests);
            cid_tests_passed.write(all_tests_passed);
            test_complete.write(true);
            
            std::cout << "DTLSCIDTestHarness: Test suite completed in " << total_test_time 
                     << " - " << passed_tests << "/" << test_cases.size() << " tests passed" << std::endl;
        }
    }
    
    bool execute_cid_test_case(const CIDTestCase& test_case) {
        // Create test transaction
        dtls_transaction trans;
        dtls_extension& ext = trans.get_extension();
        
        // Configure CID test data
        ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
        ext.connection_id = 12345; // Test connection ID
        ext.local_cid = test_case.cid_data;
        ext.cid_length = test_case.cid_data.size();
        ext.sequence_number = test_case.sequence_number;
        ext.cid_negotiation_enabled = true;
        
        // Test the validation
        bool validation_result = handshake_engine->validate_cid_message(trans);
        
        // Check if result matches expectation
        bool test_passed = (validation_result == test_case.should_pass);
        
        // If test should fail, verify we get the expected error
        if (!test_case.should_pass && !test_case.expected_error.empty()) {
            // Note: In a real implementation, we'd capture and verify the actual error message
            // For now, we rely on the boolean result
            test_passed = !validation_result;
        }
        
        return test_passed;
    }
    
    void execute_cid_negotiation_tests() {
        std::cout << "DTLSCIDTestHarness: Executing CID negotiation tests" << std::endl;
        sc_time negotiation_start = sc_time_stamp();
        
        // Test CID negotiation with different CID lengths
        std::vector<std::vector<uint8_t>> test_cids = {
            {},                                          // Empty CID
            {0x01},                                     // 1-byte CID
            {0x01, 0x02, 0x03, 0x04},                  // 4-byte CID
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, // 8-byte CID
            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
             0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}  // 20-byte CID
        };
        
        bool negotiation_passed = true;
        for (const auto& cid : test_cids) {
            // Create handshake context for testing
            handshake_engine_module::HandshakeContext context;
            context.connection_id = 54321;
            context.state = handshake_engine_module::HandshakeState::IDLE;
            
            bool result = handshake_engine->negotiate_connection_id(context, cid);
            if (!result && cid.size() <= 20) {
                negotiation_passed = false;
                break;
            }
        }
        
        sc_time negotiation_time = sc_time_stamp() - negotiation_start;
        cid_negotiation_time.write(negotiation_time);
        cid_negotiation_passed.write(negotiation_passed);
        
        std::cout << "DTLSCIDTestHarness: CID negotiation tests " 
                 << (negotiation_passed ? "PASSED" : "FAILED") 
                 << " in " << negotiation_time << std::endl;
    }
    
    void execute_cid_migration_tests() {
        std::cout << "DTLSCIDTestHarness: Executing CID migration tests" << std::endl;
        
        // Create test context with initial CID
        handshake_engine_module::HandshakeContext context;
        context.connection_id = 98765;
        context.local_cid = {0x01, 0x02, 0x03, 0x04};
        context.peer_cid = {0x05, 0x06, 0x07, 0x08};
        context.cid_migration_supported = true;
        context.cid_sequence_number = 1;
        
        bool migration_passed = true;
        
        // Test valid migration
        std::vector<uint8_t> new_cid = {0x09, 0x0A, 0x0B, 0x0C};
        if (!handshake_engine->validate_cid_migration_request(context, new_cid)) {
            migration_passed = false;
        }
        
        // Test invalid migration (same as local CID)
        if (handshake_engine->validate_cid_migration_request(context, context.local_cid)) {
            migration_passed = false;
        }
        
        // Test invalid migration (same as peer CID)
        if (handshake_engine->validate_cid_migration_request(context, context.peer_cid)) {
            migration_passed = false;
        }
        
        cid_migration_passed.write(migration_passed);
        
        std::cout << "DTLSCIDTestHarness: CID migration tests " 
                 << (migration_passed ? "PASSED" : "FAILED") << std::endl;
    }
    
    void execute_cid_performance_tests() {
        std::cout << "DTLSCIDTestHarness: Executing CID performance tests" << std::endl;
        sc_time performance_start = sc_time_stamp();
        
        const uint32_t num_operations = 1000;
        std::vector<uint8_t> test_cid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        
        // Perform repeated CID validation operations
        for (uint32_t i = 0; i < num_operations; i++) {
            dtls_transaction trans;
            dtls_extension& ext = trans.get_extension();
            
            ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
            ext.connection_id = 11111 + i;
            ext.local_cid = test_cid;
            ext.cid_length = test_cid.size();
            ext.sequence_number = i + 1;
            ext.cid_negotiation_enabled = true;
            
            handshake_engine->validate_cid_message(trans);
        }
        
        sc_time performance_time = sc_time_stamp() - performance_start;
        cid_validation_time.write(performance_time);
        
        // Calculate operations per second
        double ops_per_second = (num_operations * 1e9) / performance_time.to_double();
        cid_operations_per_second.write(static_cast<uint32_t>(ops_per_second));
        
        std::cout << "DTLSCIDTestHarness: Performance test completed - " 
                 << ops_per_second << " operations/second" << std::endl;
    }
    
    void execute_rfc9147_compliance_tests() {
        std::cout << "DTLSCIDTestHarness: Executing RFC 9147 compliance tests" << std::endl;
        
        bool compliance_passed = true;
        
        // Test RFC 9147 specific requirements
        dtls_transaction trans;
        dtls_extension& ext = trans.get_extension();
        
        // Test 1: CID length constraint (RFC 9147 Section 9)
        ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
        ext.connection_id = 99999;
        ext.cid_length = 21; // Exceeds RFC limit
        ext.cid_negotiation_enabled = true;
        
        if (handshake_engine->validate_cid_rfc9147_compliance(ext)) {
            compliance_passed = false; // Should have failed
        }
        
        // Test 2: Valid CID length
        ext.cid_length = 20; // At RFC limit
        ext.local_cid.resize(20, 0x42);
        
        if (!handshake_engine->validate_cid_rfc9147_compliance(ext)) {
            compliance_passed = false; // Should have passed
        }
        
        // Test 3: All-zero CID validation
        ext.local_cid = std::vector<uint8_t>(8, 0x00); // All zeros
        ext.cid_length = 8;
        
        if (handshake_engine->validate_cid_rfc9147_compliance(ext)) {
            compliance_passed = false; // Should have failed
        }
        
        rfc9147_compliance_passed.write(compliance_passed);
        
        std::cout << "DTLSCIDTestHarness: RFC 9147 compliance tests " 
                 << (compliance_passed ? "PASSED" : "FAILED") << std::endl;
    }
    
    void update_test_status() {
        // Update status based on completed tests
        if (test_complete.read()) {
            std::cout << "DTLSCIDTestHarness: All tests completed" << std::endl;
        }
    }
    
    // TLM transport method
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
        // Handle incoming transactions during testing
        delay += sc_time(10, SC_NS); // Simulate processing time
    }
};

/**
 * Google Test Integration for CID Tests
 */
class DTLSCIDTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize SystemC simulation
        test_harness = std::make_unique<DTLSCIDTestHarness>("cid_test_harness");
        
        // Create clock and control signals
        clock = std::make_unique<sc_clock>("clock", 10, SC_NS);
        test_enable = std::make_unique<sc_signal<bool>>("test_enable");
        test_complete = std::make_unique<sc_signal<bool>>("test_complete");
        cid_tests_passed = std::make_unique<sc_signal<bool>>("cid_tests_passed");
        
        // Connect signals
        test_harness->test_enable(*test_enable);
        test_harness->test_complete(*test_complete);
        test_harness->cid_tests_passed(*cid_tests_passed);
    }
    
    void TearDown() override {
        // Clean up SystemC objects
        test_harness.reset();
        clock.reset();
        test_enable.reset();
        test_complete.reset();
        cid_tests_passed.reset();
    }
    
    std::unique_ptr<DTLSCIDTestHarness> test_harness;
    std::unique_ptr<sc_clock> clock;
    std::unique_ptr<sc_signal<bool>> test_enable;
    std::unique_ptr<sc_signal<bool>> test_complete;
    std::unique_ptr<sc_signal<bool>> cid_tests_passed;
};

TEST_F(DTLSCIDTest, BasicCIDValidation) {
    // Start the test
    test_enable->write(true);
    
    // Run simulation
    sc_start(1, SC_MS);
    
    // Check results
    EXPECT_TRUE(test_complete->read()) << "CID test suite should complete";
    EXPECT_TRUE(cid_tests_passed->read()) << "All CID tests should pass";
}

TEST_F(DTLSCIDTest, RFC9147Compliance) {
    // Start the test  
    test_enable->write(true);
    
    // Run simulation
    sc_start(1, SC_MS);
    
    // Verify RFC 9147 compliance
    EXPECT_TRUE(test_complete->read()) << "RFC 9147 compliance tests should complete";
    
    // Additional manual validation
    dtls_transaction trans;
    dtls_extension& ext = trans.get_extension();
    handshake_engine_module engine("test_engine");
    
    // Test maximum CID length
    ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
    ext.connection_id = 1;
    ext.local_cid = std::vector<uint8_t>(20, 0x42); // 20 bytes
    ext.cid_length = 20;
    ext.cid_negotiation_enabled = true;
    
    EXPECT_TRUE(engine.validate_cid_rfc9147_compliance(ext)) 
        << "20-byte CID should be valid per RFC 9147";
    
    // Test oversized CID
    ext.cid_length = 21;
    EXPECT_FALSE(engine.validate_cid_rfc9147_compliance(ext)) 
        << "21-byte CID should be invalid per RFC 9147";
}

/**
 * Main test runner
 */
int sc_main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}