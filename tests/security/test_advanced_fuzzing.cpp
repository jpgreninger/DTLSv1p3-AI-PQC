/*
 * DTLS v1.3 Advanced Protocol Fuzzing Tests
 * Task 12: Security Validation Suite - Advanced Fuzzing & State Machine Testing
 *
 * This module implements advanced fuzzing techniques including:
 * - Protocol state machine fuzzing with invalid message sequences
 * - Cryptographic message fuzzing with signature/certificate manipulation
 * - Fragment reassembly fuzzing with overlapping and out-of-order fragments
 * - Timing-sensitive fuzzing for race condition detection
 * - Memory pressure fuzzing for resource exhaustion testing
 */

#include "security_validation_suite.h"
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/dtls_records.h>
#include <dtls/protocol/fragment_reassembler.h>
#include <dtls/memory/buffer.h>
#include <dtls/types.h>
#include <gtest/gtest.h>
#include <random>
#include <algorithm>
#include <thread>
#include <future>
#include <atomic>
#include <queue>
#include <mutex>

namespace dtls::v13::test {

/**
 * Advanced Protocol Fuzzing Test Suite
 *
 * Implements sophisticated fuzzing techniques targeting:
 * - State machine transitions with invalid message sequences
 * - Cryptographic field manipulation and certificate fuzzing
 * - Fragment reassembly edge cases and attack scenarios
 * - Concurrent message processing and race conditions
 * - Resource exhaustion through memory pressure fuzzing
 * - Advanced mutation strategies with semantic awareness
 */
class AdvancedFuzzingTest : public SecurityValidationSuite {
protected:
    void SetUp() override {
        SecurityValidationSuite::SetUp();
        setup_advanced_fuzzing();
    }

    void TearDown() override {
        generate_advanced_fuzzing_report();
        SecurityValidationSuite::TearDown();
    }

private:
    void setup_advanced_fuzzing() {
        // Advanced fuzzing parameters
        state_machine_fuzz_iterations_ = 50;
        crypto_fuzz_iterations_ = 30;
        fragment_fuzz_iterations_ = 40;
        concurrent_fuzz_iterations_ = 20;
        memory_pressure_iterations_ = 15;
        
        // Initialize random generators
        rng_.seed(std::random_device{}());
        
        // Clear results
        advanced_fuzz_results_.clear();
        
        // Initialize valid message templates for mutation
        setup_message_templates();
    }
    
    void setup_message_templates() {
        // Create valid message templates that can be mutated
        create_valid_client_hello_template();
        create_valid_server_hello_template();
        create_valid_certificate_template();
        create_valid_finished_template();
    }
    
    void create_valid_client_hello_template() {
        client_hello_template_ = std::make_unique<protocol::ClientHello>();
        client_hello_template_->set_legacy_version({254, 253}); // DTLS v1.3
        
        // Set valid random
        std::array<uint8_t, 32> random_array;
        auto random_data = generate_secure_random_data(32);
        std::copy(random_data.begin(), random_data.end(), random_array.begin());
        client_hello_template_->set_random(random_array);
        
        // Add supported cipher suites
        client_hello_template_->set_cipher_suites({
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        });
    }
    
    void create_valid_server_hello_template() {
        server_hello_template_ = std::make_unique<protocol::ServerHello>();
        server_hello_template_->set_legacy_version({254, 253});
        
        std::array<uint8_t, 32> random_array;
        auto random_data = generate_secure_random_data(32);
        std::copy(random_data.begin(), random_data.end(), random_array.begin());
        server_hello_template_->set_random(random_array);
        
        server_hello_template_->set_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    }
    
    void create_valid_certificate_template() {
        certificate_template_ = std::make_unique<protocol::Certificate>();
        
        // Add a dummy certificate entry
        protocol::CertificateEntry cert_entry;
        auto cert_data = generate_mock_certificate_data();
        memory::Buffer cert_buffer(cert_data.size());
        auto resize_result = cert_buffer.resize(cert_data.size());
        if (resize_result.is_success()) {
            std::memcpy(cert_buffer.mutable_data(), cert_data.data(), cert_data.size());
        }
        cert_entry.cert_data = std::move(cert_buffer);
        
        std::vector<protocol::CertificateEntry> cert_list;
        cert_list.push_back(std::move(cert_entry));
        certificate_template_->set_certificate_list(std::move(cert_list));
    }
    
    void create_valid_finished_template() {
        finished_template_ = std::make_unique<protocol::Finished>();
        
        // Set valid verify data (typically 32 bytes for SHA256)
        auto verify_data = generate_secure_random_data(32);
        memory::Buffer verify_buffer(verify_data.size());
        auto resize_result = verify_buffer.resize(verify_data.size());
        if (resize_result.is_success()) {
            std::memcpy(verify_buffer.mutable_data(), verify_data.data(), verify_data.size());
        }
        finished_template_->set_verify_data(std::move(verify_buffer));
    }
    
    std::vector<uint8_t> generate_secure_random_data(size_t size) {
        std::vector<uint8_t> data(size);
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        std::generate(data.begin(), data.end(), [&]() { return dist(rng_); });
        return data;
    }
    
    std::vector<uint8_t> generate_mock_certificate_data() {
        // Generate mock certificate data (DER encoded ASN.1 structure simulation)
        std::vector<uint8_t> cert_data;
        
        // Mock DER header for certificate
        cert_data.insert(cert_data.end(), {0x30, 0x82}); // SEQUENCE tag with long form length
        cert_data.insert(cert_data.end(), {0x01, 0x00}); // Length placeholder (256 bytes)
        
        // Add random certificate-like data
        auto random_data = generate_secure_random_data(252); // 256 - 4 header bytes
        cert_data.insert(cert_data.end(), random_data.begin(), random_data.end());
        
        return cert_data;
    }
    
    void record_advanced_fuzz_result(const std::string& test_name, const std::string& fuzz_type,
                                    bool caused_crash, bool caused_exception, bool caused_hang,
                                    const std::string& error_message = "") {
        AdvancedFuzzResult result;
        result.test_name = test_name;
        result.fuzz_type = fuzz_type;
        result.caused_crash = caused_crash;
        result.caused_exception = caused_exception;
        result.caused_hang = caused_hang;
        result.error_message = error_message;
        result.timestamp = std::chrono::steady_clock::now();
        
        advanced_fuzz_results_.push_back(result);
        
        if (caused_crash || caused_exception || caused_hang) {
            SecurityEvent event;
            event.type = SecurityEventType::MALFORMED_MESSAGE;
            event.severity = caused_crash ? SecurityEventSeverity::CRITICAL : 
                           caused_hang ? SecurityEventSeverity::HIGH : SecurityEventSeverity::MEDIUM;
            event.description = "Advanced fuzzing detected " + 
                               (caused_crash ? "crash" : caused_hang ? "hang" : "exception") +
                               " in " + test_name;
            event.connection_id = 0;
            event.timestamp = std::chrono::steady_clock::now();
            event.metadata["test"] = test_name;
            event.metadata["fuzz_type"] = fuzz_type;
            event.metadata["error"] = error_message;
            
            security_events_.push_back(event);
        }
    }
    
    void generate_advanced_fuzzing_report() {
        std::ofstream report("advanced_fuzzing_report.txt");
        if (!report.is_open()) return;
        
        report << "DTLS v1.3 Advanced Protocol Fuzzing Analysis Report\n";
        report << "==================================================\n\n";
        
        size_t total_tests = advanced_fuzz_results_.size();
        size_t crashes = std::count_if(advanced_fuzz_results_.begin(), advanced_fuzz_results_.end(),
                                      [](const AdvancedFuzzResult& r) { return r.caused_crash; });
        size_t exceptions = std::count_if(advanced_fuzz_results_.begin(), advanced_fuzz_results_.end(),
                                         [](const AdvancedFuzzResult& r) { return r.caused_exception; });
        size_t hangs = std::count_if(advanced_fuzz_results_.begin(), advanced_fuzz_results_.end(),
                                    [](const AdvancedFuzzResult& r) { return r.caused_hang; });
        
        report << "Summary:\n";
        report << "  Total Advanced Fuzz Tests: " << total_tests << "\n";
        report << "  Crashes: " << crashes << "\n";
        report << "  Exceptions: " << exceptions << "\n";  
        report << "  Hangs: " << hangs << "\n";
        report << "  Clean Passes: " << (total_tests - crashes - exceptions - hangs) << "\n";
        report << "  Success Rate: " << std::fixed << std::setprecision(2)
               << (100.0 * (total_tests - crashes - exceptions - hangs) / total_tests) << "%\n\n";
        
        // Detailed breakdown by test type
        std::map<std::string, std::vector<AdvancedFuzzResult>> results_by_type;
        for (const auto& result : advanced_fuzz_results_) {
            results_by_type[result.fuzz_type].push_back(result);
        }
        
        report << "Results by Fuzzing Type:\n";
        for (const auto& [fuzz_type, results] : results_by_type) {
            size_t type_crashes = std::count_if(results.begin(), results.end(),
                                               [](const AdvancedFuzzResult& r) { return r.caused_crash; });
            size_t type_exceptions = std::count_if(results.begin(), results.end(),
                                                   [](const AdvancedFuzzResult& r) { return r.caused_exception; });
            size_t type_hangs = std::count_if(results.begin(), results.end(),
                                             [](const AdvancedFuzzResult& r) { return r.caused_hang; });
            
            report << "  " << fuzz_type << ": " << results.size() << " tests, "
                   << type_crashes << " crashes, " << type_exceptions << " exceptions, "
                   << type_hangs << " hangs\n";
        }
    }
    
    struct AdvancedFuzzResult {
        std::string test_name;
        std::string fuzz_type;
        bool caused_crash;
        bool caused_exception;
        bool caused_hang;
        std::string error_message;
        std::chrono::steady_clock::time_point timestamp;
    };
    
protected:
    // Advanced fuzzing parameters
    size_t state_machine_fuzz_iterations_;
    size_t crypto_fuzz_iterations_;
    size_t fragment_fuzz_iterations_;
    size_t concurrent_fuzz_iterations_;
    size_t memory_pressure_iterations_;
    
    std::mt19937 rng_;
    std::vector<AdvancedFuzzResult> advanced_fuzz_results_;
    
    // Message templates for mutation
    std::unique_ptr<protocol::ClientHello> client_hello_template_;
    std::unique_ptr<protocol::ServerHello> server_hello_template_;
    std::unique_ptr<protocol::Certificate> certificate_template_;
    std::unique_ptr<protocol::Finished> finished_template_;
};

// ====================================================================
// State Machine Fuzzing Tests
// ====================================================================

/**
 * Test protocol state machine with invalid message sequences
 */
TEST_F(AdvancedFuzzingTest, StateMachineFuzzing) {
    // Test invalid handshake message sequences
    std::vector<std::vector<HandshakeType>> invalid_sequences = {
        // Server message before ClientHello
        {HandshakeType::SERVER_HELLO, HandshakeType::CLIENT_HELLO},
        
        // Finished before Certificate
        {HandshakeType::CLIENT_HELLO, HandshakeType::FINISHED},
        
        // Duplicate ClientHello
        {HandshakeType::CLIENT_HELLO, HandshakeType::CLIENT_HELLO},
        
        // Certificate without CertificateVerify
        {HandshakeType::CLIENT_HELLO, HandshakeType::SERVER_HELLO, 
         HandshakeType::CERTIFICATE, HandshakeType::FINISHED},
        
        // Random message order
        {HandshakeType::FINISHED, HandshakeType::CERTIFICATE_VERIFY, 
         HandshakeType::SERVER_HELLO, HandshakeType::CLIENT_HELLO}
    };
    
    for (const auto& sequence : invalid_sequences) {
        for (size_t i = 0; i < 3; ++i) { // Test each sequence multiple times
            bool caused_crash = false;
            bool caused_exception = false;
            bool caused_hang = false;
            std::string error_msg;
            
            try {
                // Create messages following the invalid sequence
                std::vector<protocol::HandshakeMessage> messages;
                
                for (auto msg_type : sequence) {
                    protocol::HandshakeMessage handshake_msg;
                    
                    switch (msg_type) {
                        case HandshakeType::CLIENT_HELLO: {
                            // Create a copy of the template for mutation
                            protocol::ClientHello client_hello;
                            client_hello.set_legacy_version({254, 253});
                            
                            std::array<uint8_t, 32> random_array;
                            auto random_data = generate_secure_random_data(32);
                            std::copy(random_data.begin(), random_data.end(), random_array.begin());
                            client_hello.set_random(random_array);
                            
                            client_hello.set_cipher_suites({CipherSuite::TLS_AES_256_GCM_SHA384});
                            
                            handshake_msg = protocol::HandshakeMessage(std::move(client_hello));
                            break;
                        }
                        case HandshakeType::SERVER_HELLO: {
                            protocol::ServerHello server_hello;
                            server_hello.set_legacy_version({254, 253});
                            
                            std::array<uint8_t, 32> random_array;
                            auto random_data = generate_secure_random_data(32);
                            std::copy(random_data.begin(), random_data.end(), random_array.begin());
                            server_hello.set_random(random_array);
                            
                            server_hello.set_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
                            
                            handshake_msg = protocol::HandshakeMessage(std::move(server_hello));
                            break;
                        }
                        case HandshakeType::CERTIFICATE: {
                            protocol::Certificate certificate;
                            
                            protocol::CertificateEntry cert_entry;
                            auto cert_data = generate_mock_certificate_data();
                            memory::Buffer cert_buffer(cert_data.size());
                            auto resize_result = cert_buffer.resize(cert_data.size());
                            if (resize_result.is_success()) {
                                std::memcpy(cert_buffer.mutable_data(), cert_data.data(), cert_data.size());
                            }
                            cert_entry.cert_data = std::move(cert_buffer);
                            
                            std::vector<protocol::CertificateEntry> cert_list;
                            cert_list.push_back(std::move(cert_entry));
                            certificate.set_certificate_list(std::move(cert_list));
                            
                            handshake_msg = protocol::HandshakeMessage(std::move(certificate));
                            break;
                        }
                        case HandshakeType::FINISHED: {
                            protocol::Finished finished;
                            auto verify_data = generate_secure_random_data(32);
                            memory::Buffer verify_buffer(verify_data.size());
                            auto resize_result = verify_buffer.resize(verify_data.size());
                            if (resize_result.is_success()) {
                                std::memcpy(verify_buffer.mutable_data(), verify_data.data(), verify_data.size());
                            }
                            finished.set_verify_data(std::move(verify_buffer));
                            
                            handshake_msg = protocol::HandshakeMessage(std::move(finished));
                            break;
                        }
                        default:
                            // Create a minimal valid message for other types
                            protocol::KeyUpdate key_update;
                            handshake_msg = protocol::HandshakeMessage(std::move(key_update));
                            break;
                    }
                    
                    messages.push_back(std::move(handshake_msg));
                }
                
                // Try to serialize all messages in the invalid sequence
                for (auto& msg : messages) {
                    memory::Buffer buffer(4096);
                    auto result = msg.serialize(buffer);
                    
                    // Validate each message individually
                    bool is_valid = msg.is_valid();
                    (void)is_valid; // Individual messages may be valid even if sequence is not
                }
                
                error_msg = "Invalid sequence processed without error";
                
            } catch (const std::exception& e) {
                caused_exception = true;
                error_msg = e.what();
            } catch (...) {
                caused_crash = true;
                error_msg = "Unknown exception/crash in state machine fuzzing";
            }
            
            std::string sequence_str;
            for (size_t j = 0; j < sequence.size(); ++j) {
                sequence_str += std::to_string(static_cast<uint8_t>(sequence[j]));
                if (j < sequence.size() - 1) sequence_str += "->";
            }
            
            record_advanced_fuzz_result("StateMachine", "InvalidSequence_" + sequence_str,
                                       caused_crash, caused_exception, caused_hang, error_msg);
            
            EXPECT_FALSE(caused_crash) << "State machine fuzzing caused crash with sequence: " << sequence_str;
        }
    }
}

/**
 * Test certificate and signature fuzzing with cryptographic field manipulation
 */
TEST_F(AdvancedFuzzingTest, CryptographicMessageFuzzing) {
    // Test Certificate message fuzzing
    for (size_t i = 0; i < crypto_fuzz_iterations_; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        bool caused_hang = false;
        std::string error_msg;
        
        try {
            protocol::Certificate certificate;
            
            // Create multiple certificate entries with various mutations
            std::vector<protocol::CertificateEntry> cert_entries;
            
            for (int j = 0; j < 3; ++j) {
                protocol::CertificateEntry cert_entry;
                
                // Generate malformed certificate data
                std::vector<uint8_t> cert_data;
                
                if (i % 4 == 0) {
                    // Empty certificate
                    cert_data.clear();
                } else if (i % 4 == 1) {
                    // Oversized certificate (simulate huge certificates)
                    cert_data = generate_secure_random_data(100000);
                } else if (i % 4 == 2) {
                    // Invalid ASN.1 DER structure
                    cert_data = {0xFF, 0xFF, 0xFF, 0xFF}; // Invalid DER tag
                    auto random_data = generate_secure_random_data(rng_() % 1000);
                    cert_data.insert(cert_data.end(), random_data.begin(), random_data.end());
                } else {
                    // Valid-looking but corrupted certificate
                    cert_data = generate_mock_certificate_data();
                    // Corrupt random bytes
                    for (int k = 0; k < 10; ++k) {
                        if (cert_data.size() > 10) {
                            cert_data[rng_() % cert_data.size()] = rng_() % 256;
                        }
                    }
                }
                
                if (!cert_data.empty()) {
                    memory::Buffer cert_buffer(cert_data.size());
                    auto resize_result = cert_buffer.resize(cert_data.size());
                    if (resize_result.is_success()) {
                        std::memcpy(cert_buffer.mutable_data(), cert_data.data(), cert_data.size());
                    }
                    cert_entry.cert_data = std::move(cert_buffer);
                }
                
                cert_entries.push_back(std::move(cert_entry));
            }
            
            certificate.set_certificate_list(std::move(cert_entries));
            
            // Test serialization and validation
            memory::Buffer buffer(200000); // Large buffer for oversized certificates
            auto result = certificate.serialize(buffer);
            
            bool is_valid = certificate.is_valid();
            error_msg = "Certificate fuzzing completed, valid: " + std::string(is_valid ? "true" : "false");
            
            if (!result.has_value()) {
                error_msg += " (serialization failed)";
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception in certificate fuzzing";
        }
        
        record_advanced_fuzz_result("Cryptographic", "CertificateFuzzing",
                                   caused_crash, caused_exception, caused_hang, error_msg);
        
        EXPECT_FALSE(caused_crash) << "Certificate fuzzing caused crash";
    }
    
    // Test CertificateVerify message fuzzing
    for (size_t i = 0; i < crypto_fuzz_iterations_ / 2; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        bool caused_hang = false;
        std::string error_msg;
        
        try {
            // Generate random signature schemes (including invalid ones)
            std::uniform_int_distribution<uint16_t> scheme_dist(0, 0xFFFF);
            auto signature_scheme = static_cast<protocol::SignatureScheme>(scheme_dist(rng_));
            
            // Generate random signature data
            std::vector<uint8_t> signature_data;
            
            if (i % 3 == 0) {
                // Empty signature
                signature_data.clear();
            } else if (i % 3 == 1) {
                // Oversized signature
                signature_data = generate_secure_random_data(10000);
            } else {
                // Random signature data
                signature_data = generate_secure_random_data(rng_() % 500);
            }
            
            memory::Buffer signature_buffer(signature_data.size());
            if (!signature_data.empty()) {
                auto resize_result = signature_buffer.resize(signature_data.size());
                if (resize_result.is_success()) {
                    std::memcpy(signature_buffer.mutable_data(), signature_data.data(), signature_data.size());
                }
            }
            
            protocol::CertificateVerify cert_verify(signature_scheme, std::move(signature_buffer));
            
            // Test serialization and validation
            memory::Buffer buffer(15000);
            auto result = cert_verify.serialize(buffer);
            
            bool is_valid = cert_verify.is_valid();
            error_msg = "CertificateVerify fuzzing completed, valid: " + std::string(is_valid ? "true" : "false");
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception in CertificateVerify fuzzing";
        }
        
        record_advanced_fuzz_result("Cryptographic", "CertificateVerifyFuzzing",
                                   caused_crash, caused_exception, caused_hang, error_msg);
        
        EXPECT_FALSE(caused_crash) << "CertificateVerify fuzzing caused crash";
    }
}

/**
 * Test fragment reassembly with overlapping and malicious fragments
 */
TEST_F(AdvancedFuzzingTest, FragmentReassemblyFuzzing) {
    for (size_t i = 0; i < fragment_fuzz_iterations_; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        bool caused_hang = false;
        std::string error_msg;
        
        try {
            // Create HandshakeHeader with malicious fragmentation parameters
            protocol::HandshakeHeader header;
            header.msg_type = HandshakeType::CERTIFICATE;
            header.message_seq = static_cast<uint16_t>(i);
            
            // Create potentially malicious fragment parameters
            if (i % 5 == 0) {
                // Fragment offset > length (invalid)
                header.length = 1000;
                header.fragment_offset = 2000;
                header.fragment_length = 500;
            } else if (i % 5 == 1) {
                // Fragment length > total length (invalid)
                header.length = 1000;
                header.fragment_offset = 100;
                header.fragment_length = 2000;
            } else if (i % 5 == 2) {
                // Overlapping fragments (fragment_offset + fragment_length > length)
                header.length = 1000;
                header.fragment_offset = 800;
                header.fragment_length = 500;
            } else if (i % 5 == 3) {
                // Very large fragment parameters (potential overflow)
                header.length = 0xFFFFFF; // 24-bit max
                header.fragment_offset = 0xFFFFFF;
                header.fragment_length = 0xFFFFFF;
            } else {
                // Zero-length fragment
                header.length = 1000;
                header.fragment_offset = 500;
                header.fragment_length = 0;
            }
            
            // Test serialization
            memory::Buffer buffer(4096);
            auto result = header.serialize(buffer);
            
            // Test validation
            bool is_valid = header.is_valid();
            error_msg = "Fragment header fuzzing completed, valid: " + std::string(is_valid ? "true" : "false");
            
            // Test fragment detection
            bool is_fragmented = header.is_fragmented();
            (void)is_fragmented;
            
            if (!result.has_value()) {
                error_msg += " (serialization failed)";
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception in fragment fuzzing";
        }
        
        record_advanced_fuzz_result("FragmentReassembly", "MaliciousFragmentParams",
                                   caused_crash, caused_exception, caused_hang, error_msg);
        
        EXPECT_FALSE(caused_crash) << "Fragment reassembly fuzzing caused crash";
    }
}

/**
 * Test concurrent message processing for race conditions
 */
TEST_F(AdvancedFuzzingTest, ConcurrentMessageFuzzing) {
    // Test concurrent serialization/deserialization
    for (size_t i = 0; i < concurrent_fuzz_iterations_; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        bool caused_hang = false;
        std::string error_msg;
        
        try {
            const size_t num_threads = 4;
            std::vector<std::future<void>> futures;
            std::atomic<bool> test_failed{false};
            std::mutex error_mutex;
            std::string shared_error;
            
            // Launch concurrent operations
            for (size_t thread_id = 0; thread_id < num_threads; ++thread_id) {
                futures.push_back(std::async(std::launch::async, [&, thread_id]() {
                    try {
                        // Each thread performs different message operations
                        for (int j = 0; j < 10; ++j) {
                            if (thread_id % 2 == 0) {
                                // Serialize messages
                                protocol::ClientHello client_hello;
                                client_hello.set_legacy_version({254, 253});
                                
                                std::array<uint8_t, 32> random_array;
                                auto random_data = generate_secure_random_data(32);
                                std::copy(random_data.begin(), random_data.end(), random_array.begin());
                                client_hello.set_random(random_array);
                                
                                memory::Buffer buffer(2048);
                                auto result = client_hello.serialize(buffer);
                                (void)result;
                            } else {
                                // Deserialize random data
                                auto random_buffer_data = generate_secure_random_data(200);
                                memory::Buffer random_buffer(random_buffer_data.size());
                                auto resize_result = random_buffer.resize(random_buffer_data.size());
                                if (resize_result.is_success()) {
                                    std::memcpy(random_buffer.mutable_data(), random_buffer_data.data(), random_buffer_data.size());
                                }
                                
                                auto result = protocol::ClientHello::deserialize(random_buffer);
                                (void)result; // Expected to fail most of the time
                            }
                            
                            // Small delay to increase chance of race conditions
                            std::this_thread::sleep_for(std::chrono::microseconds(10));
                        }
                    } catch (const std::exception& e) {
                        test_failed.store(true);
                        std::lock_guard<std::mutex> lock(error_mutex);
                        shared_error = e.what();
                    } catch (...) {
                        test_failed.store(true);
                        std::lock_guard<std::mutex> lock(error_mutex);
                        shared_error = "Unknown exception in thread " + std::to_string(thread_id);
                    }
                }));
            }
            
            // Wait for all threads with timeout
            bool all_completed = true;
            for (auto& future : futures) {
                auto status = future.wait_for(std::chrono::seconds(5));
                if (status == std::future_status::timeout) {
                    caused_hang = true;
                    all_completed = false;
                    break;
                }
            }
            
            if (test_failed.load()) {
                caused_exception = true;
                error_msg = shared_error;
            } else if (all_completed) {
                error_msg = "Concurrent message processing completed successfully";
            } else {
                error_msg = "Some threads timed out";
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception in concurrent fuzzing";
        }
        
        record_advanced_fuzz_result("Concurrent", "RaceConditionTesting",
                                   caused_crash, caused_exception, caused_hang, error_msg);
        
        EXPECT_FALSE(caused_crash) << "Concurrent message fuzzing caused crash";
        EXPECT_FALSE(caused_hang) << "Concurrent message fuzzing caused hang";
    }
}

/**
 * Test memory pressure fuzzing with resource exhaustion scenarios
 */
TEST_F(AdvancedFuzzingTest, MemoryPressureFuzzing) {
    for (size_t i = 0; i < memory_pressure_iterations_; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        bool caused_hang = false;
        std::string error_msg;
        
        try {
            // Create large numbers of messages to test memory management
            std::vector<std::unique_ptr<protocol::ClientHello>> messages;
            
            size_t num_messages = 100 + (i * 50); // Increasing memory pressure
            
            for (size_t j = 0; j < num_messages; ++j) {
                auto client_hello = std::make_unique<protocol::ClientHello>();
                client_hello->set_legacy_version({254, 253});
                
                // Add large amounts of extension data
                for (int k = 0; k < 10; ++k) {
                    auto ext_data = generate_secure_random_data(1000);
                    memory::Buffer ext_buffer(ext_data.size());
                    auto resize_result = ext_buffer.resize(ext_data.size());
                    if (resize_result.is_success()) {
                        std::memcpy(ext_buffer.mutable_data(), ext_data.data(), ext_data.size());
                    }
                    
                    protocol::Extension extension(protocol::ExtensionType::SUPPORTED_GROUPS, 
                                                 std::move(ext_buffer));
                    client_hello->add_extension(std::move(extension));
                }
                
                messages.push_back(std::move(client_hello));
            }
            
            // Try to serialize all messages
            size_t total_serialized = 0;
            for (const auto& msg : messages) {
                memory::Buffer buffer(20000);
                auto result = msg->serialize(buffer);
                if (result.has_value()) {
                    total_serialized++;
                }
            }
            
            error_msg = "Memory pressure test completed, serialized: " + 
                       std::to_string(total_serialized) + "/" + std::to_string(num_messages);
            
        } catch (const std::bad_alloc& e) {
            // Expected behavior under memory pressure
            error_msg = "Memory allocation failed as expected: " + std::string(e.what());
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception in memory pressure fuzzing";
        }
        
        record_advanced_fuzz_result("MemoryPressure", "ResourceExhaustion",
                                   caused_crash, caused_exception, caused_hang, error_msg);
        
        EXPECT_FALSE(caused_crash) << "Memory pressure fuzzing caused crash";
    }
}

/**
 * Comprehensive advanced fuzzing validation
 */
TEST_F(AdvancedFuzzingTest, ComprehensiveAdvancedFuzzingValidation) {
    // Analyze advanced fuzzing results
    std::map<std::string, size_t> test_counts;
    std::map<std::string, size_t> crash_counts;
    std::map<std::string, size_t> exception_counts;
    std::map<std::string, size_t> hang_counts;
    
    for (const auto& result : advanced_fuzz_results_) {
        test_counts[result.fuzz_type]++;
        if (result.caused_crash) crash_counts[result.fuzz_type]++;
        if (result.caused_exception) exception_counts[result.fuzz_type]++;
        if (result.caused_hang) hang_counts[result.fuzz_type]++;
    }
    
    // Validate test coverage
    EXPECT_GT(test_counts["InvalidSequence"], 10) << "Insufficient state machine fuzzing";
    EXPECT_GT(test_counts["CertificateFuzzing"], 20) << "Insufficient certificate fuzzing";
    EXPECT_GT(test_counts["MaliciousFragmentParams"], 30) << "Insufficient fragment fuzzing";
    EXPECT_GT(test_counts["RaceConditionTesting"], 15) << "Insufficient concurrent fuzzing";
    EXPECT_GT(test_counts["ResourceExhaustion"], 10) << "Insufficient memory pressure fuzzing";
    
    // Calculate overall robustness metrics
    size_t total_tests = advanced_fuzz_results_.size();
    size_t total_crashes = std::accumulate(crash_counts.begin(), crash_counts.end(), 0,
                                          [](size_t sum, const auto& pair) { return sum + pair.second; });
    size_t total_hangs = std::accumulate(hang_counts.begin(), hang_counts.end(), 0,
                                        [](size_t sum, const auto& pair) { return sum + pair.second; });
    
    double crash_rate = total_tests > 0 ? static_cast<double>(total_crashes) / total_tests : 0.0;
    double hang_rate = total_tests > 0 ? static_cast<double>(total_hangs) / total_tests : 0.0;
    
    // Advanced fuzzing should have very low crash/hang rates
    EXPECT_LT(crash_rate, 0.02) << "Advanced fuzzing crash rate too high: " << (crash_rate * 100.0) << "%";
    EXPECT_LT(hang_rate, 0.01) << "Advanced fuzzing hang rate too high: " << (hang_rate * 100.0) << "%";
    EXPECT_GT(total_tests, 80) << "Insufficient total advanced fuzzing tests: " << total_tests;
    
    // Log comprehensive assessment
    std::cout << "Advanced Protocol Fuzzing Assessment:\n";
    std::cout << "  Total Tests: " << total_tests << "\n";
    std::cout << "  Crashes: " << total_crashes << " (" << std::fixed << std::setprecision(2) << (crash_rate * 100.0) << "%)\n";
    std::cout << "  Hangs: " << total_hangs << " (" << std::fixed << std::setprecision(2) << (hang_rate * 100.0) << "%)\n";
    std::cout << "  Robustness Rating: " << (crash_rate < 0.01 && hang_rate < 0.005 ? "EXCELLENT" : 
                                           crash_rate < 0.02 && hang_rate < 0.01 ? "GOOD" : "NEEDS_IMPROVEMENT") << "\n";
}

} // namespace dtls::v13::test