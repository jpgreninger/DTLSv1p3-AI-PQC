/*
 * DTLS v1.3 Protocol Message Fuzzing Tests  
 * Task 12: Security Validation Suite - Protocol Fuzzing
 *
 * This module implements comprehensive protocol message fuzzing tests
 * to validate DTLS v1.3 implementation robustness against malformed,
 * corrupted, and adversarially-crafted protocol messages.
 */

#include "security_validation_suite.h"
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/dtls_records.h>
#include <dtls/memory/buffer.h>
#include <dtls/types.h>
#include <gtest/gtest.h>
#include <random>
#include <algorithm>
#include <limits>
#include <fstream>
#include <iomanip>

namespace dtls::v13::test {

/**
 * Comprehensive Protocol Message Fuzzing Test Suite
 * 
 * Implements systematic fuzzing of DTLS v1.3 protocol messages including:
 * - Handshake message fuzzing with invalid field values
 * - Record layer fuzzing with corrupted headers and payloads  
 * - Extension fuzzing with malformed extension data
 * - Length field manipulation and boundary condition testing
 * - Random mutation testing for robustness validation
 * - Protocol state machine fuzzing with invalid message sequences
 */
class ProtocolFuzzingTest : public SecurityValidationSuite {
protected:
    void SetUp() override {
        SecurityValidationSuite::SetUp();
        setup_fuzzing_environment();
    }
    
    void TearDown() override {
        generate_fuzzing_report();
        SecurityValidationSuite::TearDown();
    }
    
private:
    void setup_fuzzing_environment() {
        // Initialize fuzzing parameters
        fuzz_iterations_ = 1000;
        max_mutation_size_ = 16384;
        mutation_probability_ = 0.1;
        
        // Setup random number generators
        rng_.seed(std::random_device{}());
        
        // Initialize fuzz results tracking
        fuzz_results_.clear();
    }
    
    // ====================================================================
    // Fuzzing Utility Functions
    // ====================================================================
    
    /**
     * Generate random data of specified size
     */
    std::vector<uint8_t> generate_random_data(size_t size) {
        std::vector<uint8_t> data(size);
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        std::generate(data.begin(), data.end(), [&]() { return dist(rng_); });
        return data;
    }
    
    /**
     * Generate random data with specific patterns for edge case testing
     */
    std::vector<uint8_t> generate_pattern_data(size_t size, uint8_t pattern) {
        return std::vector<uint8_t>(size, pattern);
    }
    
    /**
     * Mutate existing buffer data randomly
     */
    void mutate_buffer(std::vector<uint8_t>& buffer) {
        if (buffer.empty()) return;
        
        std::uniform_real_distribution<double> mutation_dist(0.0, 1.0);
        std::uniform_int_distribution<size_t> index_dist(0, buffer.size() - 1);
        std::uniform_int_distribution<uint8_t> value_dist(0, 255);
        
        for (auto& byte : buffer) {
            if (mutation_dist(rng_) < mutation_probability_) {
                byte = value_dist(rng_);
            }
        }
    }
    
    /**
     * Create invalid length fields for testing boundary conditions
     */
    std::vector<uint16_t> generate_invalid_lengths() {
        return {
            0,                          // Zero length
            1,                          // Too small
            0xFFFF,                    // Maximum uint16_t
            0x4001,                    // Just over max fragment length (16384)
            0x8000,                    // Large value
            static_cast<uint16_t>(-1), // Wraparound value
        };
    }
    
    /**
     * Create invalid protocol versions for testing
     */
    std::vector<ProtocolVersion> generate_invalid_versions() {
        return {
            {0x00, 0x00},    // Invalid version
            {0xFF, 0xFF},    // Maximum values
            {0x03, 0x03},    // TLS 1.2 version (wrong protocol)
            {0x03, 0x04},    // TLS 1.3 version (wrong protocol)
            {0xFE, 0xFF},    // Invalid DTLS version
            {0x01, 0x00},    // Very old version
        };
    }
    
    /**
     * Record fuzz test result
     */
    void record_fuzz_result(const std::string& test_name, const std::string& mutation_type, 
                           bool caused_crash, bool caused_exception, const std::string& error_message = "") {
        FuzzResult result;
        result.test_name = test_name;
        result.mutation_type = mutation_type;
        result.caused_crash = caused_crash;
        result.caused_exception = caused_exception;
        result.error_message = error_message;
        result.timestamp = std::chrono::steady_clock::now();
        
        fuzz_results_.push_back(result);
        
        // Record security event if crash or exception occurred
        if (caused_crash || caused_exception) {
            SecurityEvent event;
            event.type = SecurityEventType::MALFORMED_MESSAGE;
            event.severity = caused_crash ? SecurityEventSeverity::CRITICAL : SecurityEventSeverity::HIGH;
            event.description = "Fuzzing test triggered " + (caused_crash ? "crash" : "exception") + 
                               " in " + test_name + " with " + mutation_type;
            event.connection_id = 0;
            event.timestamp = std::chrono::steady_clock::now();
            event.metadata["test"] = test_name;
            event.metadata["mutation"] = mutation_type;
            event.metadata["error"] = error_message;
            
            security_events_.push_back(event);
        }
    }
    
    /**
     * Generate comprehensive fuzzing report
     */
    void generate_fuzzing_report() {
        std::ofstream report("protocol_fuzzing_report.txt");
        if (!report.is_open()) return;
        
        report << "DTLS v1.3 Protocol Message Fuzzing Analysis Report\n";
        report << "==================================================\n\n";
        
        size_t total_tests = fuzz_results_.size();
        size_t crashes = std::count_if(fuzz_results_.begin(), fuzz_results_.end(), 
                                      [](const FuzzResult& r) { return r.caused_crash; });
        size_t exceptions = std::count_if(fuzz_results_.begin(), fuzz_results_.end(),
                                         [](const FuzzResult& r) { return r.caused_exception; });
        
        report << "Summary:\n";
        report << "  Total Fuzz Tests: " << total_tests << "\n";
        report << "  Crashes Triggered: " << crashes << "\n";
        report << "  Exceptions Triggered: " << exceptions << "\n";
        report << "  Clean Passes: " << (total_tests - crashes - exceptions) << "\n";
        report << "  Success Rate: " << std::fixed << std::setprecision(2) 
               << (100.0 * (total_tests - crashes - exceptions) / total_tests) << "%\n\n";
        
        // Detailed results by test category
        std::map<std::string, std::vector<FuzzResult>> results_by_test;
        for (const auto& result : fuzz_results_) {
            results_by_test[result.test_name].push_back(result);
        }
        
        for (const auto& [test_name, results] : results_by_test) {
            size_t test_crashes = std::count_if(results.begin(), results.end(),
                                               [](const FuzzResult& r) { return r.caused_crash; });
            size_t test_exceptions = std::count_if(results.begin(), results.end(),
                                                   [](const FuzzResult& r) { return r.caused_exception; });
            
            report << test_name << ":\n";
            report << "  Tests: " << results.size() << ", Crashes: " << test_crashes 
                   << ", Exceptions: " << test_exceptions << "\n";
            
            if (test_crashes > 0 || test_exceptions > 0) {
                for (const auto& result : results) {
                    if (result.caused_crash || result.caused_exception) {
                        report << "  - " << result.mutation_type << ": " 
                               << (result.caused_crash ? "CRASH" : "EXCEPTION") 
                               << " (" << result.error_message << ")\n";
                    }
                }
            }
            report << "\n";
        }
    }
    
    // ====================================================================
    // Test Helper Structures
    // ====================================================================
    
    struct FuzzResult {
        std::string test_name;
        std::string mutation_type;
        bool caused_crash;
        bool caused_exception;
        std::string error_message;
        std::chrono::steady_clock::time_point timestamp;
    };
    
protected:
    // Fuzzing parameters
    size_t fuzz_iterations_;
    size_t max_mutation_size_;
    double mutation_probability_;
    std::mt19937 rng_;
    
    // Fuzzing results tracking
    std::vector<FuzzResult> fuzz_results_;
};

// ====================================================================
// Handshake Message Fuzzing Tests
// ====================================================================

/**
 * Test ClientHello message fuzzing with various malformed inputs
 */
TEST_F(ProtocolFuzzingTest, ClientHelloFuzzing) {
    // Test invalid protocol versions
    for (const auto& invalid_version : generate_invalid_versions()) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            protocol::ClientHello client_hello;
            client_hello.set_legacy_version(invalid_version);
            
            // Try to serialize the invalid message
            memory::Buffer buffer(1024);
            auto result = client_hello.serialize(buffer);
            
            // Serialization should either succeed (gracefully handling invalid data)
            // or fail with a proper error (no crash)
            if (!result.has_value()) {
                error_msg = "Serialization failed as expected";
            }
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("ClientHello", "InvalidProtocolVersion", caused_crash, caused_exception, error_msg);
        
        // Test should not crash - either succeed or fail gracefully
        EXPECT_FALSE(caused_crash) << "ClientHello fuzzing with invalid version caused crash";
    }
    
    // Test with oversized random data
    for (size_t i = 0; i < 10; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            protocol::ClientHello client_hello;
            
            // Generate oversized session ID (should be <= 32 bytes for DTLS)
            auto oversized_session_id = generate_random_data(256);
            memory::Buffer session_buffer(oversized_session_id.size());
            auto resize_result = session_buffer.resize(oversized_session_id.size());
            if (resize_result.is_success()) {
                std::memcpy(session_buffer.mutable_data(), oversized_session_id.data(), oversized_session_id.size());
                client_hello.set_legacy_session_id(std::move(session_buffer));
            }
            
            memory::Buffer buffer(4096);
            auto result = client_hello.serialize(buffer);
            
            if (!result.has_value()) {
                error_msg = "Serialization rejected oversized session ID";
            }
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("ClientHello", "OversizedSessionId", caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "ClientHello fuzzing with oversized session ID caused crash";
    }
    
    // Test with random cipher suites including invalid ones
    for (size_t i = 0; i < 20; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            protocol::ClientHello client_hello;
            
            // Generate random cipher suites with potentially invalid values
            std::vector<CipherSuite> random_suites;
            std::uniform_int_distribution<uint16_t> suite_dist(0, 0xFFFF);
            
            for (int j = 0; j < 50; ++j) {  // Large number of cipher suites
                random_suites.push_back(static_cast<CipherSuite>(suite_dist(rng_)));
            }
            
            client_hello.set_cipher_suites(std::move(random_suites));
            
            memory::Buffer buffer(4096);
            auto result = client_hello.serialize(buffer);
            
            if (!result.has_value()) {
                error_msg = "Serialization handled invalid cipher suites";
            }
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("ClientHello", "RandomCipherSuites", caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "ClientHello fuzzing with random cipher suites caused crash";
    }
}

/**
 * Test Extension fuzzing with malformed extension data
 */
TEST_F(ProtocolFuzzingTest, ExtensionFuzzing) {
    // Test with invalid extension types and random data
    for (size_t i = 0; i < 50; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            // Generate random extension type
            std::uniform_int_distribution<uint16_t> type_dist(0, 0xFFFF);
            auto ext_type = static_cast<protocol::ExtensionType>(type_dist(rng_));
            
            // Generate random extension data (could be oversized or malformed)
            auto random_data = generate_random_data(rng_() % 1024);
            memory::Buffer ext_buffer(random_data.size());
            auto resize_result = ext_buffer.resize(random_data.size());
            if (resize_result.is_success()) {
                std::memcpy(ext_buffer.mutable_data(), random_data.data(), random_data.size());
            }
            
            protocol::Extension extension(ext_type, std::move(ext_buffer));
            
            // Test serialization
            memory::Buffer serialize_buffer(2048);
            auto result = extension.serialize(serialize_buffer);
            
            // Test deserialization of the serialized data
            if (result.has_value()) {
                auto deserialize_result = protocol::Extension::deserialize(serialize_buffer);
                if (!deserialize_result.has_value()) {
                    error_msg = "Deserialization failed on serialized extension";
                }
            } else {
                error_msg = "Serialization failed on random extension";
            }
            
            // Test validation
            bool is_valid = extension.is_valid();
            (void)is_valid; // May be false for random data, that's expected
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("Extension", "RandomExtensionData", caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "Extension fuzzing with random data caused crash";
    }
    
    // Test with extreme extension data sizes
    std::vector<size_t> extreme_sizes = {0, 1, 65535, 100000};
    
    for (size_t size : extreme_sizes) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            auto ext_type = protocol::ExtensionType::SUPPORTED_GROUPS;
            auto data = generate_random_data(size);
            
            memory::Buffer ext_buffer(data.size());
            if (data.size() > 0) {
                auto resize_result = ext_buffer.resize(data.size());
                if (resize_result.is_success()) {
                    std::memcpy(ext_buffer.mutable_data(), data.data(), data.size());
                }
            }
            
            protocol::Extension extension(ext_type, std::move(ext_buffer));
            
            memory::Buffer serialize_buffer(size + 1024);
            auto result = extension.serialize(serialize_buffer);
            
            if (!result.has_value()) {
                error_msg = "Serialization handled extreme size (" + std::to_string(size) + ")";
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("Extension", "ExtremeSize_" + std::to_string(size), 
                          caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "Extension fuzzing with size " << size << " caused crash";
    }
}

/**
 * Test record layer fuzzing with corrupted headers and payloads
 */
TEST_F(ProtocolFuzzingTest, RecordLayerFuzzing) {
    // Test DTLSPlaintext fuzzing with invalid fields
    for (size_t i = 0; i < 30; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            protocol::DTLSPlaintext plaintext;
            
            // Set random/invalid values
            std::uniform_int_distribution<uint8_t> content_dist(0, 255);
            plaintext.set_type(static_cast<ContentType>(content_dist(rng_)));
            
            // Invalid version
            auto invalid_versions = generate_invalid_versions();
            std::uniform_int_distribution<size_t> version_dist(0, invalid_versions.size() - 1);
            plaintext.set_version(invalid_versions[version_dist(rng_)]);
            
            // Random epoch
            std::uniform_int_distribution<uint16_t> epoch_dist(0, 0xFFFF);
            plaintext.set_epoch(epoch_dist(rng_));
            
            // Random sequence number (could be very large)
            std::uniform_int_distribution<uint64_t> seq_dist(0, 0xFFFFFFFFFFFFULL);
            protocol::SequenceNumber48 seq_num(seq_dist(rng_));
            plaintext.set_sequence_number(seq_num);
            
            // Random fragment data (could be oversized)
            auto fragment_data = generate_random_data(rng_() % 20000); // Could exceed max fragment
            memory::Buffer fragment_buffer(fragment_data.size());
            if (fragment_data.size() > 0) {
                auto resize_result = fragment_buffer.resize(fragment_data.size());
                if (resize_result.is_success()) {
                    std::memcpy(fragment_buffer.mutable_data(), fragment_data.data(), fragment_data.size());
                }
            }
            plaintext.set_fragment(std::move(fragment_buffer));
            
            // Test serialization
            memory::Buffer serialize_buffer(25000);
            auto result = plaintext.serialize(serialize_buffer);
            
            // Test validation  
            bool is_valid = plaintext.is_valid();
            (void)is_valid; // May be false, that's expected
            
            if (!result.has_value()) {
                error_msg = "Serialization handled malformed DTLSPlaintext";
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("DTLSPlaintext", "RandomFields", caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "DTLSPlaintext fuzzing with random fields caused crash";
    }
    
    // Test deserialization fuzzing with corrupted buffers
    for (size_t i = 0; i < 50; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            // Create a buffer with random data that might look like a valid DTLS record header
            auto buffer_data = generate_random_data(50 + (rng_() % 1000));
            memory::Buffer fuzz_buffer(buffer_data.size());
            auto resize_result = fuzz_buffer.resize(buffer_data.size());
            if (resize_result.is_success()) {
                std::memcpy(fuzz_buffer.mutable_data(), buffer_data.data(), buffer_data.size());
            }
            
            // Try to deserialize the random buffer
            auto result = protocol::DTLSPlaintext::deserialize(fuzz_buffer);
            
            if (!result.has_value()) {
                error_msg = "Deserialization properly rejected random buffer";
            } else {
                // If deserialization succeeded, try to validate the result
                bool is_valid = result.value().is_valid();
                error_msg = "Deserialization succeeded, valid: " + std::string(is_valid ? "true" : "false");
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("DTLSPlaintext", "DeserializationFuzzing", caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "DTLSPlaintext deserialization fuzzing caused crash";
    }
}

/**
 * Test length field manipulation fuzzing
 */
TEST_F(ProtocolFuzzingTest, LengthFieldFuzzing) {
    // Test handshake header length field manipulation
    for (size_t i = 0; i < 20; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            protocol::HandshakeHeader header;
            header.msg_type = HandshakeType::CLIENT_HELLO;
            header.message_seq = 0;
            header.fragment_offset = 0;
            
            // Set inconsistent length values
            auto invalid_lengths = generate_invalid_lengths();
            std::uniform_int_distribution<size_t> len_dist(0, invalid_lengths.size() - 1);
            
            header.length = static_cast<uint32_t>(invalid_lengths[len_dist(rng_)]);
            header.fragment_length = static_cast<uint32_t>(invalid_lengths[len_dist(rng_)]);
            
            // Make length and fragment_length inconsistent
            if (rng_() % 2) {
                header.fragment_length = header.length + 1000;
            }
            
            memory::Buffer buffer(4096);
            auto result = header.serialize(buffer);
            
            // Test validation
            bool is_valid = header.is_valid();
            (void)is_valid; // Expected to be false for malformed headers
            
            if (!result.has_value()) {
                error_msg = "Serialization handled invalid length fields";
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("HandshakeHeader", "LengthFieldManipulation", caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "Handshake header length manipulation caused crash";
    }
}

/**
 * Test random buffer mutation fuzzing
 */
TEST_F(ProtocolFuzzingTest, RandomMutationFuzzing) {
    // Create a valid ClientHello and then randomly mutate its serialized form
    for (size_t i = 0; i < 25; ++i) {
        bool caused_crash = false;
        bool caused_exception = false;
        std::string error_msg;
        
        try {
            // Create a valid ClientHello
            protocol::ClientHello client_hello;
            client_hello.set_legacy_version({254, 253}); // DTLS v1.3
            
            // Set valid random data
            std::array<uint8_t, 32> random_array;
            auto random_vec = generate_random_data(32);
            std::copy(random_vec.begin(), random_vec.end(), random_array.begin());
            client_hello.set_random(random_array);
            
            // Add some cipher suites
            client_hello.set_cipher_suites({CipherSuite::TLS_AES_256_GCM_SHA384, 
                                           CipherSuite::TLS_AES_128_GCM_SHA256});
            
            // Serialize to get valid data
            memory::Buffer valid_buffer(2048);
            auto serialize_result = client_hello.serialize(valid_buffer);
            
            if (serialize_result.has_value()) {
                // Convert to vector for mutation
                std::vector<uint8_t> buffer_vec(serialize_result.value());
                for (size_t j = 0; j < serialize_result.value(); ++j) {
                    buffer_vec[j] = valid_buffer.data()[j];
                }
                
                // Randomly mutate the buffer
                mutate_buffer(buffer_vec);
                
                // Put back into buffer
                memory::Buffer mutated_buffer(buffer_vec.size());
                auto resize_result = mutated_buffer.resize(buffer_vec.size());
                if (resize_result.is_success()) {
                    std::memcpy(mutated_buffer.mutable_data(), buffer_vec.data(), buffer_vec.size());
                }
                
                // Try to deserialize the mutated buffer
                auto deserialize_result = protocol::ClientHello::deserialize(mutated_buffer);
                
                if (!deserialize_result.has_value()) {
                    error_msg = "Deserialization properly rejected mutated buffer";
                } else {
                    // Validate the deserialized result
                    bool is_valid = deserialize_result.value().is_valid();
                    error_msg = "Deserialization of mutated buffer succeeded, valid: " + 
                               std::string(is_valid ? "true" : "false");
                }
            } else {
                error_msg = "Initial valid serialization failed";
            }
            
        } catch (const std::exception& e) {
            caused_exception = true;
            error_msg = e.what();
        } catch (...) {
            caused_crash = true;
            error_msg = "Unknown exception/crash";
        }
        
        record_fuzz_result("ClientHello", "RandomMutation", caused_crash, caused_exception, error_msg);
        EXPECT_FALSE(caused_crash) << "Random mutation fuzzing caused crash";
    }
}

/**
 * Comprehensive fuzzing validation test
 */
TEST_F(ProtocolFuzzingTest, ComprehensiveFuzzingValidation) {
    // Count total fuzzing tests performed
    std::map<std::string, size_t> test_counts;
    std::map<std::string, size_t> crash_counts;
    std::map<std::string, size_t> exception_counts;
    
    for (const auto& result : fuzz_results_) {
        test_counts[result.test_name]++;
        if (result.caused_crash) {
            crash_counts[result.test_name]++;
        }
        if (result.caused_exception) {
            exception_counts[result.test_name]++;
        }
    }
    
    // Validate that we performed comprehensive fuzzing
    EXPECT_GT(test_counts["ClientHello"], 20) << "Insufficient ClientHello fuzzing tests";
    EXPECT_GT(test_counts["Extension"], 40) << "Insufficient Extension fuzzing tests"; 
    EXPECT_GT(test_counts["DTLSPlaintext"], 60) << "Insufficient DTLSPlaintext fuzzing tests";
    EXPECT_GT(test_counts["HandshakeHeader"], 15) << "Insufficient HandshakeHeader fuzzing tests";
    
    // Validate overall robustness - crashes should be rare
    size_t total_crashes = 0;
    for (const auto& [test_name, crashes] : crash_counts) {
        total_crashes += crashes;
    }
    
    size_t total_tests = fuzz_results_.size();
    double crash_rate = static_cast<double>(total_crashes) / total_tests;
    
    EXPECT_LT(crash_rate, 0.05) << "Crash rate too high: " << (crash_rate * 100.0) << "%";
    EXPECT_GT(total_tests, 100) << "Insufficient total fuzzing tests performed: " << total_tests;
    
    // Log final fuzzing assessment
    std::cout << "Protocol Fuzzing Assessment:\n";
    std::cout << "  Total Tests: " << total_tests << "\n";
    std::cout << "  Total Crashes: " << total_crashes << "\n";
    std::cout << "  Crash Rate: " << std::fixed << std::setprecision(2) << (crash_rate * 100.0) << "%\n";
    std::cout << "  Robustness: " << (crash_rate < 0.05 ? "EXCELLENT" : crash_rate < 0.1 ? "GOOD" : "NEEDS_IMPROVEMENT") << "\n";
}

} // namespace dtls::v13::test