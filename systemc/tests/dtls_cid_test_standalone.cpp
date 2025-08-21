/**
 * Standalone DTLS v1.3 Connection ID (CID) Test for SystemC Implementation
 * 
 * Simplified test that focuses purely on CID functionality without
 * depending on the problematic testbench infrastructure.
 */

#include <systemc>
#include <gtest/gtest.h>
#include "dtls_protocol_modules.h"
#include "dtls_tlm_extensions.h"
#include <vector>
#include <iostream>

using namespace dtls::v13::systemc_tlm;
using namespace sc_core;

/**
 * Standalone CID Test Class
 */
class DTLSCIDStandaloneTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create handshake engine for testing
        handshake_engine = std::make_unique<handshake_engine_module>("test_handshake_engine");
    }
    
    void TearDown() override {
        handshake_engine.reset();
    }
    
    std::unique_ptr<handshake_engine_module> handshake_engine;
};

TEST_F(DTLSCIDStandaloneTest, BasicCIDValidation) {
    // Test basic CID validation functionality
    dtls_transaction trans;
    dtls_extension& ext = trans.get_extension();
    
    // Configure valid CID transaction
    ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
    ext.connection_id = 12345;
    ext.local_cid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    ext.cid_length = 8;
    ext.sequence_number = 1;
    ext.cid_negotiation_enabled = true;
    
    // Test validation
    bool result = handshake_engine->validate_cid_message(trans);
    EXPECT_TRUE(result) << "Valid CID message should pass validation";
}

TEST_F(DTLSCIDStandaloneTest, CIDLengthValidation) {
    dtls_transaction trans;
    dtls_extension& ext = trans.get_extension();
    
    // Test maximum valid length (20 bytes)
    ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
    ext.connection_id = 12345;
    ext.local_cid.resize(20, 0x42);
    ext.cid_length = 20;
    ext.sequence_number = 1;
    ext.cid_negotiation_enabled = true;
    
    bool result = handshake_engine->validate_cid_rfc9147_compliance(ext);
    EXPECT_TRUE(result) << "20-byte CID should be valid per RFC 9147";
    
    // Test invalid length (21 bytes)
    ext.cid_length = 21;
    result = handshake_engine->validate_cid_rfc9147_compliance(ext);
    EXPECT_FALSE(result) << "21-byte CID should be invalid per RFC 9147";
}

TEST_F(DTLSCIDStandaloneTest, AllZeroCIDValidation) {
    dtls_transaction trans;
    dtls_extension& ext = trans.get_extension();
    
    // Test all-zero CID (should be invalid per RFC 9147)
    ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
    ext.connection_id = 12345;
    ext.local_cid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ext.cid_length = 8;
    ext.sequence_number = 1;
    ext.cid_negotiation_enabled = true;
    
    bool result = handshake_engine->validate_cid_rfc9147_compliance(ext);
    EXPECT_FALSE(result) << "All-zero CID should be invalid per RFC 9147";
}

TEST_F(DTLSCIDStandaloneTest, EmptyCIDValidation) {
    dtls_transaction trans;
    dtls_extension& ext = trans.get_extension();
    
    // Test empty CID (should be valid)
    ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
    ext.connection_id = 12345;
    ext.local_cid = {};
    ext.cid_length = 0;
    ext.sequence_number = 1;
    ext.cid_negotiation_enabled = true;
    
    bool result = handshake_engine->validate_cid_rfc9147_compliance(ext);
    EXPECT_TRUE(result) << "Empty CID should be valid";
}

TEST_F(DTLSCIDStandaloneTest, CIDNegotiation) {
    // Test CID negotiation with different lengths
    std::vector<std::vector<uint8_t>> test_cids = {
        {},                                          // Empty CID
        {0x01},                                     // 1-byte CID
        {0x01, 0x02, 0x03, 0x04},                  // 4-byte CID
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, // 8-byte CID
    };
    
    for (const auto& cid : test_cids) {
        handshake_engine_module::HandshakeContext context;
        context.connection_id = 54321;
        context.state = handshake_engine_module::HandshakeState::IDLE;
        
        bool result = handshake_engine->negotiate_connection_id(context, cid);
        EXPECT_TRUE(result) << "CID negotiation should succeed for CID of length " << cid.size();
        
        if (result) {
            EXPECT_EQ(context.local_cid, cid) << "Local CID should be set correctly";
            EXPECT_TRUE(context.cid_negotiation_requested) << "CID negotiation should be marked as requested";
        }
    }
}

TEST_F(DTLSCIDStandaloneTest, CIDSequenceNumberUpdate) {
    handshake_engine_module::HandshakeContext context;
    context.connection_id = 98765;
    context.cid_sequence_number = 5;
    
    std::vector<uint8_t> new_cid = {0x09, 0x0A, 0x0B, 0x0C};
    
    // Test valid sequence number update
    bool result = handshake_engine->update_active_cid(context, 6, new_cid);
    EXPECT_TRUE(result) << "CID update with higher sequence number should succeed";
    EXPECT_EQ(context.cid_sequence_number, 6) << "Sequence number should be updated";
    EXPECT_EQ(context.peer_cid, new_cid) << "Peer CID should be updated";
    
    // Test invalid sequence number (replay)
    result = handshake_engine->update_active_cid(context, 5, new_cid);
    EXPECT_FALSE(result) << "CID update with lower sequence number should fail";
}

TEST_F(DTLSCIDStandaloneTest, RFC9147ComplianceChecks) {
    dtls_transaction trans;
    dtls_extension& ext = trans.get_extension();
    
    // Test various RFC 9147 compliance scenarios
    ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
    ext.connection_id = 99999;
    ext.cid_negotiation_enabled = true;
    
    // Test 1: Valid configurations
    for (uint8_t len = 0; len <= 20; len++) {
        ext.local_cid.clear();
        ext.local_cid.resize(len, 0x42);
        ext.cid_length = len;
        
        bool result = handshake_engine->validate_cid_rfc9147_compliance(ext);
        if (len == 0 || (len > 0 && len <= 20)) {
            EXPECT_TRUE(result) << "CID length " << (int)len << " should be valid per RFC 9147";
        }
    }
    
    // Test 2: Invalid length
    ext.cid_length = 25;
    bool result = handshake_engine->validate_cid_rfc9147_compliance(ext);
    EXPECT_FALSE(result) << "CID length 25 should be invalid per RFC 9147";
}

/**
 * Performance test to ensure CID operations are efficient
 */
TEST_F(DTLSCIDStandaloneTest, CIDPerformance) {
    const int num_operations = 1000;
    std::vector<uint8_t> test_cid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_operations; i++) {
        dtls_transaction trans;
        dtls_extension& ext = trans.get_extension();
        
        ext.handshake_type = dtls_extension::HandshakeType::NEW_CONNECTION_ID;
        ext.connection_id = 10000 + i;
        ext.local_cid = test_cid;
        ext.cid_length = test_cid.size();
        ext.sequence_number = i + 1;
        ext.cid_negotiation_enabled = true;
        
        bool result = handshake_engine->validate_cid_message(trans);
        EXPECT_TRUE(result) << "CID validation should succeed for operation " << i;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    std::cout << "CID Performance Test: " << num_operations << " operations in " 
              << duration.count() << " microseconds" << std::endl;
    std::cout << "Average: " << (duration.count() / num_operations) << " microseconds per operation" << std::endl;
    
    // Performance requirement: should complete 1000 operations in under 100ms
    EXPECT_LT(duration.count(), 100000) << "CID operations should be efficient";
}

/**
 * Main test runner
 */
int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    
    // Initialize SystemC (required for SystemC modules)
    sc_report_handler::set_actions(SC_ID_MORE_THAN_ONE_SIGNAL_DRIVER_, SC_DO_NOTHING);
    
    std::cout << "Starting DTLS CID Standalone Tests" << std::endl;
    
    int result = RUN_ALL_TESTS();
    
    std::cout << "DTLS CID Standalone Tests Completed" << std::endl;
    
    return result;
}