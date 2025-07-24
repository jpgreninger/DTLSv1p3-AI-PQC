/**
 * Basic Crypto Provider SystemC TLM Test
 * 
 * This test demonstrates the basic functionality of the crypto provider
 * TLM model and validates its performance characteristics.
 */

#include "crypto_provider_tlm.h"
#include "dtls_channels.h"
#include <systemc>
#include <iostream>
#include <vector>

using namespace dtls::v13::systemc_tlm;
using namespace sc_core;

/**
 * Test stimulus generator for crypto operations
 */
SC_MODULE(CryptoTestStimulus) {
public:
    // TLM initiator socket
    tlm_utils::simple_initiator_socket<CryptoTestStimulus, 32, dtls_protocol_types> initiator_socket;
    
    // Test control
    sc_in<bool> test_enable;
    sc_out<bool> test_complete;
    sc_out<uint32_t> operations_completed;
    
    // Constructor
    CryptoTestStimulus(sc_module_name name) 
        : sc_module(name)
        , initiator_socket("initiator_socket")
        , test_enable("test_enable")
        , test_complete("test_complete")
        , operations_completed("operations_completed")
        , completed_ops_(0)
    {
        SC_THREAD(test_process);
    }

private:
    uint32_t completed_ops_;
    
    void test_process() {
        // Wait for test enable
        wait(test_enable.posedge_event());
        
        std::cout << "Starting crypto provider test at " << sc_time_stamp() << std::endl;
        
        // Test different crypto operations
        test_encryption_operations();
        test_signature_operations();
        test_key_derivation_operations();
        test_random_generation();
        test_hash_operations();
        
        std::cout << "Crypto provider test completed at " << sc_time_stamp() << std::endl;
        std::cout << "Total operations completed: " << completed_ops_ << std::endl;
        
        operations_completed.write(completed_ops_);
        test_complete.write(true);
    }
    
    void test_encryption_operations() {
        std::cout << "Testing encryption operations..." << std::endl;
        
        // Test AES-GCM encryption
        crypto_transaction encrypt_trans(crypto_transaction::ENCRYPT);
        encrypt_trans.transaction_id = utils::generate_transaction_id();
        encrypt_trans.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        
        // Create test data
        std::string test_data = "Hello, DTLS v1.3 SystemC TLM!";
        encrypt_trans.input_data.assign(test_data.begin(), test_data.end());
        
        // Create key material (16 bytes for AES-128)
        encrypt_trans.key_material.resize(16);
        std::fill(encrypt_trans.key_material.begin(), encrypt_trans.key_material.end(), 0xAB);
        
        // Create nonce (12 bytes for GCM)
        encrypt_trans.nonce.resize(12);
        std::fill(encrypt_trans.nonce.begin(), encrypt_trans.nonce.end(), 0xCD);
        
        // Perform encryption
        perform_crypto_operation(encrypt_trans);
        
        if (encrypt_trans.response_status) {
            std::cout << "  Encryption successful, output size: " 
                      << encrypt_trans.output_data.size() << " bytes" << std::endl;
            completed_ops_++;
            
            // Test decryption
            crypto_transaction decrypt_trans(crypto_transaction::DECRYPT);
            decrypt_trans.transaction_id = utils::generate_transaction_id();
            decrypt_trans.cipher_suite = encrypt_trans.cipher_suite;
            decrypt_trans.input_data = encrypt_trans.output_data;
            decrypt_trans.key_material = encrypt_trans.key_material;
            decrypt_trans.nonce = encrypt_trans.nonce;
            decrypt_trans.auth_tag = encrypt_trans.auth_tag;
            
            perform_crypto_operation(decrypt_trans);
            
            if (decrypt_trans.response_status) {
                std::cout << "  Decryption successful, output size: " 
                          << decrypt_trans.output_data.size() << " bytes" << std::endl;
                completed_ops_++;
            } else {
                std::cout << "  Decryption failed: " << decrypt_trans.error_message << std::endl;
            }
        } else {
            std::cout << "  Encryption failed: " << encrypt_trans.error_message << std::endl;
        }
    }
    
    void test_signature_operations() {
        std::cout << "Testing signature operations..." << std::endl;
        
        // Test ECDSA signing
        crypto_transaction sign_trans(crypto_transaction::SIGN);
        sign_trans.transaction_id = utils::generate_transaction_id();
        sign_trans.signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
        
        // Create test message to sign
        std::string message = "DTLS v1.3 certificate verify";
        sign_trans.input_data.assign(message.begin(), message.end());
        
        // Create private key material (simplified)
        sign_trans.key_material.resize(32);
        std::fill(sign_trans.key_material.begin(), sign_trans.key_material.end(), 0xEF);
        
        // Perform signing
        perform_crypto_operation(sign_trans);
        
        if (sign_trans.response_status) {
            std::cout << "  Signing successful, signature size: " 
                      << sign_trans.output_data.size() << " bytes" << std::endl;
            completed_ops_++;
            
            // Test signature verification
            crypto_transaction verify_trans(crypto_transaction::VERIFY);
            verify_trans.transaction_id = utils::generate_transaction_id();
            verify_trans.signature_scheme = sign_trans.signature_scheme;
            verify_trans.input_data = sign_trans.input_data;
            verify_trans.output_data = sign_trans.output_data; // Signature
            verify_trans.key_material.resize(64); // Public key (simplified)
            std::fill(verify_trans.key_material.begin(), verify_trans.key_material.end(), 0xFE);
            
            perform_crypto_operation(verify_trans);
            
            if (verify_trans.response_status) {
                std::cout << "  Signature verification successful" << std::endl;
                completed_ops_++;
            } else {
                std::cout << "  Signature verification failed: " << verify_trans.error_message << std::endl;
            }
        } else {
            std::cout << "  Signing failed: " << sign_trans.error_message << std::endl;
        }
    }
    
    void test_key_derivation_operations() {
        std::cout << "Testing key derivation operations..." << std::endl;
        
        crypto_transaction derive_trans(crypto_transaction::KEY_DERIVE);
        derive_trans.transaction_id = utils::generate_transaction_id();
        derive_trans.hash_algorithm = HashAlgorithm::SHA256;
        
        // Create master secret
        derive_trans.key_material.resize(48);
        std::fill(derive_trans.key_material.begin(), derive_trans.key_material.end(), 0x12);
        
        perform_crypto_operation(derive_trans);
        
        if (derive_trans.response_status) {
            std::cout << "  Key derivation successful, derived key size: " 
                      << derive_trans.output_data.size() << " bytes" << std::endl;
            completed_ops_++;
        } else {
            std::cout << "  Key derivation failed: " << derive_trans.error_message << std::endl;
        }
    }
    
    void test_random_generation() {
        std::cout << "Testing random generation..." << std::endl;
        
        crypto_transaction random_trans(crypto_transaction::RANDOM_GENERATE);
        random_trans.transaction_id = utils::generate_transaction_id();
        
        // Request 32 bytes of random data
        random_trans.input_data.push_back(32);
        
        perform_crypto_operation(random_trans);
        
        if (random_trans.response_status) {
            std::cout << "  Random generation successful, generated " 
                      << random_trans.output_data.size() << " bytes" << std::endl;
            completed_ops_++;
        } else {
            std::cout << "  Random generation failed: " << random_trans.error_message << std::endl;
        }
    }
    
    void test_hash_operations() {
        std::cout << "Testing hash operations..." << std::endl;
        
        crypto_transaction hash_trans(crypto_transaction::HASH_COMPUTE);
        hash_trans.transaction_id = utils::generate_transaction_id();
        hash_trans.hash_algorithm = HashAlgorithm::SHA256;
        
        // Create test data to hash
        std::string data = "DTLS v1.3 handshake messages";
        hash_trans.input_data.assign(data.begin(), data.end());
        
        perform_crypto_operation(hash_trans);
        
        if (hash_trans.response_status) {
            std::cout << "  Hash computation successful, hash size: " 
                      << hash_trans.output_data.size() << " bytes" << std::endl;
            completed_ops_++;
        } else {
            std::cout << "  Hash computation failed: " << hash_trans.error_message << std::endl;
        }
    }
    
    void perform_crypto_operation(crypto_transaction& trans) {
        // Create TLM payload
        tlm::tlm_generic_payload payload;
        payload.set_data_ptr(reinterpret_cast<unsigned char*>(&trans));
        payload.set_data_length(sizeof(crypto_transaction));
        payload.set_streaming_width(sizeof(crypto_transaction));
        payload.set_byte_enable_ptr(nullptr);
        payload.set_byte_enable_length(0);
        payload.set_command(tlm::TLM_WRITE_COMMAND);
        payload.set_address(0);
        
        sc_time delay = SC_ZERO_TIME;
        
        // Make blocking transport call
        initiator_socket->b_transport(payload, delay);
        
        // Wait for the processing delay
        wait(delay);
        
        // Check response
        if (payload.get_response_status() != tlm::TLM_OK_RESPONSE) {
            trans.response_status = false;
            trans.error_message = "TLM transport failed";
        }
    }
    
    SC_HAS_PROCESS(CryptoTestStimulus);
};

/**
 * Test monitor for collecting results
 */
SC_MODULE(CryptoTestMonitor) {
public:
    // Test results
    sc_in<bool> test_complete;
    sc_in<uint32_t> operations_completed;
    
    // Constructor
    CryptoTestMonitor(sc_module_name name)
        : sc_module(name)
        , test_complete("test_complete")
        , operations_completed("operations_completed")
    {
        SC_METHOD(monitor_process);
        sensitive << test_complete.pos();
    }

private:
    void monitor_process() {
        if (test_complete.read()) {
            uint32_t ops = operations_completed.read();
            std::cout << "\n=== Test Results ===" << std::endl;
            std::cout << "Operations completed: " << ops << std::endl;
            std::cout << "Test duration: " << sc_time_stamp() << std::endl;
            
            if (ops >= 5) {
                std::cout << "Test PASSED" << std::endl;
            } else {
                std::cout << "Test FAILED" << std::endl;
            }
            std::cout << "===================" << std::endl;
        }
    }
};

/**
 * Top-level test module
 */
SC_MODULE(BasicCryptoTest) {
public:
    // Component instances
    CryptoProviderTLM crypto_provider;
    CryptoTestStimulus test_stimulus;
    CryptoTestMonitor test_monitor;
    
    // Signals
    sc_signal<bool> test_enable{"test_enable"};
    sc_signal<bool> test_complete{"test_complete"};
    sc_signal<uint32_t> operations_completed{"operations_completed"};
    
    // Constructor
    BasicCryptoTest(sc_module_name name)
        : sc_module(name)
        , crypto_provider("crypto_provider", false) // No hardware acceleration for basic test
        , test_stimulus("test_stimulus")
        , test_monitor("test_monitor")
    {
        // Connect components
        test_stimulus.initiator_socket.bind(crypto_provider.target_socket);
        
        // Connect signals
        test_stimulus.test_enable(test_enable);
        test_stimulus.test_complete(test_complete);
        test_stimulus.operations_completed(operations_completed);
        
        test_monitor.test_complete(test_complete);
        test_monitor.operations_completed(operations_completed);
        
        SC_THREAD(test_control_process);
    }

private:
    void test_control_process() {
        // Wait for initial setup
        wait(10, SC_NS);
        
        // Start the test
        test_enable.write(true);
        
        // Wait for test completion or timeout
        sc_time timeout = sc_time(10, SC_SEC);
        wait(test_complete.posedge_event() | sc_time(timeout));
        
        if (!test_complete.read()) {
            std::cout << "Test TIMEOUT after " << timeout << std::endl;
        }
        
        // Allow some time for final statistics
        wait(100, SC_NS);
        
        // Print crypto provider statistics
        auto stats = crypto_provider.get_statistics();
        std::cout << "\n=== Crypto Provider Statistics ===" << std::endl;
        std::cout << "Total operations: " << stats.total_operations << std::endl;
        std::cout << "Successful operations: " << stats.successful_operations << std::endl;
        std::cout << "Failed operations: " << stats.failed_operations << std::endl;
        std::cout << "Encryption operations: " << stats.encryption_operations << std::endl;
        std::cout << "Signature operations: " << stats.signature_operations << std::endl;
        std::cout << "Key derivation operations: " << stats.key_derivation_operations << std::endl;
        std::cout << "Random generation operations: " << stats.random_generation_operations << std::endl;
        std::cout << "Hash operations: " << stats.hash_operations << std::endl;
        std::cout << "Average processing time: " << stats.average_processing_time << std::endl;
        std::cout << "==================================" << std::endl;
        
        // Stop simulation
        sc_stop();
    }
    
    SC_HAS_PROCESS(BasicCryptoTest);
};

int sc_main(int argc, char* argv[]) {
    // Create and run the test
    BasicCryptoTest test("basic_crypto_test");
    
    // Set up tracing if desired
    sc_trace_file* trace_file = nullptr;
    if (argc > 1 && std::string(argv[1]) == "--trace") {
        trace_file = sc_create_vcd_trace_file("basic_crypto_test");
        sc_trace(trace_file, test.test_enable, "test_enable");
        sc_trace(trace_file, test.test_complete, "test_complete");
        sc_trace(trace_file, test.operations_completed, "operations_completed");
    }
    
    // Run simulation
    std::cout << "Starting DTLS SystemC Crypto Provider Test" << std::endl;
    sc_start();
    
    // Clean up tracing
    if (trace_file) {
        sc_close_vcd_trace_file(trace_file);
        std::cout << "Trace file 'basic_crypto_test.vcd' generated" << std::endl;
    }
    
    return 0;
}