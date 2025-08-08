/**
 * @file test_message_fuzzing.cpp
 * @brief Comprehensive DTLS v1.3 Protocol Message Fuzzing Tests
 * 
 * This file implements structure-aware fuzzing tests for all DTLS v1.3 protocol messages
 * including handshake messages, record layer structures, and extensions. The fuzzing
 * approach focuses on finding robustness issues, memory safety violations, and protocol
 * compliance edge cases.
 * 
 * @author DTLS v1.3 Implementation Team
 * @date 2025
 */

#include <gtest/gtest.h>
#include <random>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <map>
#include <iomanip>

// DTLS v1.3 Headers
#include "dtls/protocol/handshake.h"
#include "dtls/protocol/dtls_records.h"
#include "dtls/protocol/cookie.h"
#include "dtls/types.h"
#include "dtls/error.h"
#include "security_validation_suite.h"

using namespace dtls::v13::protocol;
using namespace dtls::v13;

namespace dtls::v13::test {

/**
 * @class MessageFuzzingTest
 * @brief Advanced protocol message fuzzing test suite
 * 
 * Implements structure-aware fuzzing techniques to test protocol message
 * robustness, including boundary condition testing, malformed message
 * handling, and serialization/deserialization safety.
 */
class MessageFuzzingTest : public SecurityValidationSuite {
protected:
    void SetUp() override {
        SecurityValidationSuite::SetUp();
        setup_fuzzing_infrastructure();
    }
    
    void TearDown() override {
        generate_comprehensive_report();
        SecurityValidationSuite::TearDown();
    }

    // Core fuzzing infrastructure methods
    void setup_fuzzing_infrastructure() {
        // Initialize fuzzing parameters
        fuzz_iterations_ = 2000;
        max_message_size_ = 65535;
        mutation_probability_ = 0.15;
        
        // Setup secure random generation
        rng_.seed(std::random_device{}());
        
        // Initialize result tracking
        fuzz_results_.clear();
        vulnerability_findings_.clear();
    }

    // ====================================================================
    // Fuzzing Utility Methods
    // ====================================================================
    
    /**
     * Generate cryptographically secure random data
     */
    memory::Buffer generate_secure_random(size_t size) {
        memory::Buffer buffer(size);
        auto resize_result = buffer.resize(size);
        if (resize_result.is_success()) {
            std::uniform_int_distribution<uint8_t> dist(0, 255);
            std::byte* data = buffer.mutable_data();
            for (size_t i = 0; i < size; ++i) {
                data[i] = static_cast<std::byte>(dist(rng_));
            }
        }
        return buffer;
    }
    
    /**
     * Generate pattern-based data for boundary testing
     */
    memory::Buffer generate_pattern_data(size_t size, uint8_t pattern) {
        memory::Buffer buffer(size);
        auto resize_result = buffer.resize(size);
        if (resize_result.is_success()) {
            std::memset(buffer.mutable_data(), pattern, size);
        }
        return buffer;
    }
    
    /**
     * Apply intelligent mutations to existing data
     */
    void intelligent_mutate(memory::Buffer& buffer, int mutation_type) {
        if (buffer.size() == 0) return;
        
        std::uniform_real_distribution<double> mutation_dist(0.0, 1.0);
        std::uniform_int_distribution<size_t> index_dist(0, buffer.size() - 1);
        
        MutationType type = static_cast<MutationType>(mutation_type);
        switch (type) {
            case MutationType::RANDOM_BYTE:
                apply_random_byte_mutations(buffer, mutation_dist);
                break;
            case MutationType::BIT_FLIP:
                apply_bit_flip_mutations(buffer, mutation_dist);
                break;
            case MutationType::BOUNDARY_VALUES:
                apply_boundary_value_mutations(buffer);
                break;
            case MutationType::LENGTH_MANIPULATION:
                apply_length_manipulation(buffer);
                break;
        }
    }
    
    void apply_random_byte_mutations(memory::Buffer& buffer, 
                                   std::uniform_real_distribution<double>& dist) {
        std::uniform_int_distribution<uint8_t> value_dist(0, 255);
        std::byte* data = buffer.mutable_data();
        for (size_t i = 0; i < buffer.size(); ++i) {
            if (dist(rng_) < mutation_probability_) {
                data[i] = static_cast<std::byte>(value_dist(rng_));
            }
        }
    }
    
    void apply_bit_flip_mutations(memory::Buffer& buffer,
                                 std::uniform_real_distribution<double>& dist) {
        std::uniform_int_distribution<uint8_t> bit_dist(0, 7);
        std::byte* data = buffer.mutable_data();
        for (size_t i = 0; i < buffer.size(); ++i) {
            if (dist(rng_) < mutation_probability_ / 8.0) {
                uint8_t bit_pos = bit_dist(rng_);
                data[i] ^= static_cast<std::byte>(1 << bit_pos);
            }
        }
    }
    
    void apply_boundary_value_mutations(memory::Buffer& buffer) {
        if (buffer.size() == 0) return;
        
        std::vector<uint8_t> boundary_values = {
            0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF
        };
        
        std::uniform_int_distribution<size_t> pos_dist(0, buffer.size() - 1);
        std::uniform_int_distribution<size_t> val_dist(0, boundary_values.size() - 1);
        
        size_t mutation_count = 1 + (rng_() % 5);
        std::byte* data = buffer.mutable_data();
        for (size_t i = 0; i < mutation_count; ++i) {
            size_t pos = pos_dist(rng_);
            data[pos] = static_cast<std::byte>(boundary_values[val_dist(rng_)]);
        }
    }
    
    void apply_length_manipulation(memory::Buffer& buffer) {
        // Manipulate length fields if they exist in the first few bytes
        if (buffer.size() >= 4) {
            std::uniform_int_distribution<uint8_t> action_dist(0, 3);
            uint8_t action = action_dist(rng_);
            std::byte* data = buffer.mutable_data();
            
            switch (action) {
                case 0: // Zero out length
                    data[2] = static_cast<std::byte>(0x00);
                    data[3] = static_cast<std::byte>(0x00);
                    break;
                case 1: // Maximum length
                    data[2] = static_cast<std::byte>(0xFF);
                    data[3] = static_cast<std::byte>(0xFF);
                    break;
                case 2: // Inconsistent length
                    data[2] = static_cast<std::byte>(buffer.size() >> 8);
                    data[3] = static_cast<std::byte>((buffer.size() * 2) & 0xFF);
                    break;
                case 3: // Random length
                    data[2] = static_cast<std::byte>(rng_() & 0xFF);
                    data[3] = static_cast<std::byte>(rng_() & 0xFF);
                    break;
            }
        }
    }
    
    /**
     * Record fuzzing result with detailed analysis
     */
    void record_fuzzing_result(const std::string& test_name, const std::string& mutation_type,
                              bool caused_crash, bool caused_exception, bool found_vulnerability,
                              const std::string& error_message = "", const std::string& details = "") {
        FuzzingResult result;
        result.test_name = test_name;
        result.mutation_type = mutation_type;
        result.caused_crash = caused_crash;
        result.caused_exception = caused_exception;
        result.found_vulnerability = found_vulnerability;
        result.error_message = error_message;
        result.additional_details = details;
        result.timestamp = std::chrono::steady_clock::now();
        
        fuzz_results_.push_back(result);
        
        // Track potential vulnerabilities
        if (found_vulnerability || caused_crash) {
            VulnerabilityFinding finding;
            finding.severity = caused_crash ? VulnerabilitySeverity::CRITICAL : VulnerabilitySeverity::HIGH;
            finding.category = categorize_vulnerability(test_name, mutation_type);
            finding.description = generate_vulnerability_description(test_name, mutation_type, error_message);
            finding.reproduction_steps = generate_reproduction_steps(test_name, mutation_type);
            finding.timestamp = result.timestamp;
            
            vulnerability_findings_.push_back(finding);
        }
    }
    
    /**
     * Generate comprehensive fuzzing analysis report
     */
    void generate_comprehensive_report() {
        std::ofstream report("dtls_message_fuzzing_report.txt");
        if (!report.is_open()) return;
        
        report << "DTLS v1.3 Protocol Message Fuzzing Analysis Report\n";
        report << "==================================================\n\n";
        
        generate_executive_summary(report);
        generate_detailed_findings(report);
        generate_vulnerability_analysis(report);
        generate_recommendations(report);
    }
    
    void generate_executive_summary(std::ofstream& report) {
        size_t total_tests = fuzz_results_.size();
        size_t crashes = count_results_by_type([](const FuzzingResult& r) { return r.caused_crash; });
        size_t exceptions = count_results_by_type([](const FuzzingResult& r) { return r.caused_exception; });
        size_t vulnerabilities = vulnerability_findings_.size();
        
        report << "Executive Summary:\n";
        report << "==================\n";
        report << "Total Fuzzing Tests: " << total_tests << "\n";
        report << "Crashes Detected: " << crashes << "\n";
        report << "Exceptions Caught: " << exceptions << "\n";
        report << "Vulnerabilities Found: " << vulnerabilities << "\n";
        report << "Success Rate: " << std::fixed << std::setprecision(2) 
               << (100.0 * (total_tests - crashes - exceptions) / total_tests) << "%\n\n";
    }
    
    void generate_detailed_findings(std::ofstream& report) {
        report << "Detailed Test Results by Category:\n";
        report << "==================================\n";
        
        std::map<std::string, std::vector<FuzzingResult>> results_by_test;
        for (const auto& result : fuzz_results_) {
            results_by_test[result.test_name].push_back(result);
        }
        
        for (const auto& [test_name, results] : results_by_test) {
            report << "\n" << test_name << ":\n";
            report << "  Total Tests: " << results.size() << "\n";
            
            size_t test_crashes = std::count_if(results.begin(), results.end(),
                                               [](const FuzzingResult& r) { return r.caused_crash; });
            size_t test_exceptions = std::count_if(results.begin(), results.end(),
                                                   [](const FuzzingResult& r) { return r.caused_exception; });
            size_t test_vulnerabilities = std::count_if(results.begin(), results.end(),
                                                        [](const FuzzingResult& r) { return r.found_vulnerability; });
            
            report << "  Crashes: " << test_crashes << "\n";
            report << "  Exceptions: " << test_exceptions << "\n";
            report << "  Vulnerabilities: " << test_vulnerabilities << "\n";
            
            double success_rate = 100.0 * (results.size() - test_crashes - test_exceptions) / results.size();
            report << "  Success Rate: " << std::fixed << std::setprecision(2) << success_rate << "%\n";
        }
    }
    
    void generate_vulnerability_analysis(std::ofstream& report) {
        if (vulnerability_findings_.empty()) {
            report << "\nVulnerability Analysis: No vulnerabilities detected.\n";
            return;
        }
        
        report << "\nVulnerability Analysis:\n";
        report << "======================\n";
        
        std::map<VulnerabilityCategory, size_t> vuln_by_category;
        std::map<VulnerabilitySeverity, size_t> vuln_by_severity;
        
        for (const auto& finding : vulnerability_findings_) {
            vuln_by_category[finding.category]++;
            vuln_by_severity[finding.severity]++;
        }
        
        report << "By Category:\n";
        for (const auto& [category, count] : vuln_by_category) {
            report << "  " << vulnerability_category_to_string(category) << ": " << count << "\n";
        }
        
        report << "\nBy Severity:\n";
        for (const auto& [severity, count] : vuln_by_severity) {
            report << "  " << vulnerability_severity_to_string(severity) << ": " << count << "\n";
        }
    }
    
    void generate_recommendations(std::ofstream& report) {
        report << "\nRecommendations:\n";
        report << "===============\n";
        report << "1. Enhance input validation for protocol messages\n";
        report << "2. Implement additional boundary checks for length fields\n";
        report << "3. Add fuzzing tests to continuous integration pipeline\n";
        report << "4. Consider implementing protocol message sanitization\n";
        report << "5. Regular security audits of message parsing code\n";
    }

    // ====================================================================
    // Support Enums and Structures
    // ====================================================================
    
    enum class MutationType {
        RANDOM_BYTE,
        BIT_FLIP,
        BOUNDARY_VALUES,
        LENGTH_MANIPULATION
    };
    
    enum class VulnerabilitySeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    };
    
    enum class VulnerabilityCategory {
        MEMORY_SAFETY,
        PROTOCOL_COMPLIANCE,
        INPUT_VALIDATION,
        DENIAL_OF_SERVICE,
        INFORMATION_DISCLOSURE
    };
    
    struct FuzzingResult {
        std::string test_name;
        std::string mutation_type;
        bool caused_crash = false;
        bool caused_exception = false;
        bool found_vulnerability = false;
        std::string error_message;
        std::string additional_details;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    struct VulnerabilityFinding {
        VulnerabilitySeverity severity;
        VulnerabilityCategory category;
        std::string description;
        std::string reproduction_steps;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    // Helper methods
    template<typename Predicate>
    size_t count_results_by_type(Predicate pred) const {
        return std::count_if(fuzz_results_.begin(), fuzz_results_.end(), pred);
    }
    
    VulnerabilityCategory categorize_vulnerability(const std::string& test_name, 
                                                  const std::string& /* mutation_type */) const {
        if (test_name.find("Memory") != std::string::npos) {
            return VulnerabilityCategory::MEMORY_SAFETY;
        } else if (test_name.find("Protocol") != std::string::npos) {
            return VulnerabilityCategory::PROTOCOL_COMPLIANCE;
        } else if (test_name.find("Input") != std::string::npos || 
                   test_name.find("Validation") != std::string::npos) {
            return VulnerabilityCategory::INPUT_VALIDATION;
        } else if (test_name.find("DoS") != std::string::npos) {
            return VulnerabilityCategory::DENIAL_OF_SERVICE;
        } else {
            return VulnerabilityCategory::INFORMATION_DISCLOSURE;
        }
    }
    
    std::string generate_vulnerability_description(const std::string& test_name,
                                                  const std::string& mutation_type,
                                                  const std::string& error_message) const {
        return "Vulnerability in " + test_name + " with " + mutation_type + 
               " mutation: " + error_message;
    }
    
    std::string generate_reproduction_steps(const std::string& test_name,
                                           const std::string& mutation_type) const {
        return "Run " + test_name + " with " + mutation_type + " mutation type";
    }
    
    std::string vulnerability_category_to_string(VulnerabilityCategory category) const {
        switch (category) {
            case VulnerabilityCategory::MEMORY_SAFETY: return "Memory Safety";
            case VulnerabilityCategory::PROTOCOL_COMPLIANCE: return "Protocol Compliance";
            case VulnerabilityCategory::INPUT_VALIDATION: return "Input Validation";
            case VulnerabilityCategory::DENIAL_OF_SERVICE: return "Denial of Service";
            case VulnerabilityCategory::INFORMATION_DISCLOSURE: return "Information Disclosure";
            default: return "Unknown";
        }
    }
    
    std::string vulnerability_severity_to_string(VulnerabilitySeverity severity) const {
        switch (severity) {
            case VulnerabilitySeverity::LOW: return "Low";
            case VulnerabilitySeverity::MEDIUM: return "Medium";
            case VulnerabilitySeverity::HIGH: return "High";
            case VulnerabilitySeverity::CRITICAL: return "Critical";
            default: return "Unknown";
        }
    }

    // Specialized fuzzing methods for different message types
    void apply_clienthello_mutations(ClientHello& hello, const std::string& category, size_t iteration);
    void test_server_hello_fuzzing(const std::string& test_name, size_t iteration);
    void test_hello_retry_request_fuzzing(const std::string& test_name, size_t iteration);
    void test_dtls_plaintext_fuzzing(const std::string& test_name, size_t iteration);
    void test_dtls_ciphertext_fuzzing(const std::string& test_name, size_t iteration);
    void test_extension_fuzzing(const std::string& test_name, protocol::ExtensionType type, size_t iteration);
    void test_certificate_message_fuzzing(const std::string& test_name, size_t iteration);
    void test_handshake_fragmentation_fuzzing(const std::string& test_name, size_t iteration);

protected:
    // Fuzzing configuration
    size_t fuzz_iterations_;
    size_t max_message_size_;
    double mutation_probability_;
    std::mt19937 rng_;
    
    // Results tracking
    std::vector<FuzzingResult> fuzz_results_;
    std::vector<VulnerabilityFinding> vulnerability_findings_;
};

// ====================================================================
// Protocol Message Fuzzing Tests
// ====================================================================

/**
 * Test ClientHello message fuzzing with structure-aware mutations
 */
TEST_F(MessageFuzzingTest, FuzzClientHelloMessages) {
    const std::string test_name = "ClientHello_Fuzzing";
    
    for (size_t iteration = 0; iteration < fuzz_iterations_ / 10; ++iteration) {
        try {
            // Create baseline valid ClientHello
            ClientHello client_hello;
            client_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(0xFEFD)); // DTLS 1.2
            
            // Generate random 32-byte array
            auto random_buffer = generate_secure_random(32);
            std::array<uint8_t, 32> random_array;
            if (random_buffer.size() >= 32) {
                std::memcpy(random_array.data(), random_buffer.data(), 32);
            } else {
                std::fill(random_array.begin(), random_array.end(), 0);
            }
            client_hello.set_random(random_array);
            
            client_hello.set_legacy_session_id(generate_secure_random(32));
            client_hello.set_cookie(generate_secure_random(16));
            
            std::vector<CipherSuite> cipher_suites = {
                CipherSuite::TLS_AES_128_GCM_SHA256, 
                CipherSuite::TLS_AES_256_GCM_SHA384, 
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256
            };
            client_hello.set_cipher_suites(std::move(cipher_suites));
            
            // Test various mutation categories
            std::vector<std::string> mutation_categories = {
                "random_field_corruption", "boundary_value_injection",
                "oversized_fields", "undersized_fields", "invalid_combinations"
            };
            
            for (const auto& category : mutation_categories) {
                // Create a new ClientHello by copying values (classes are move-only)
                ClientHello fuzz_hello;
                fuzz_hello.set_legacy_version(client_hello.legacy_version());
                fuzz_hello.set_random(client_hello.random());
                fuzz_hello.set_legacy_session_id(memory::Buffer(client_hello.legacy_session_id().data(), client_hello.legacy_session_id().size()));
                fuzz_hello.set_cookie(memory::Buffer(client_hello.cookie().data(), client_hello.cookie().size()));
                fuzz_hello.set_cipher_suites(client_hello.cipher_suites());
                bool caused_crash = false, caused_exception = false, found_vulnerability = false;
                std::string error_msg, details;
                
                try {
                    apply_clienthello_mutations(fuzz_hello, category, iteration);
                    
                    // Test serialization safety
                    memory::Buffer serialized_data(4096); // Pre-allocate buffer
                    auto serialize_result = fuzz_hello.serialize(serialized_data);
                    
                    if (serialize_result.is_success()) {
                        // Apply post-serialization mutations
                        if (category == "random_field_corruption") {
                            intelligent_mutate(serialized_data, static_cast<int>(MutationType::RANDOM_BYTE));
                        } else if (category == "boundary_value_injection") {
                            intelligent_mutate(serialized_data, static_cast<int>(MutationType::BOUNDARY_VALUES));
                        }
                        
                        // Test deserialization robustness
                        auto deserialize_result = ClientHello::deserialize(serialized_data, 0);
                        
                        if (deserialize_result.is_success()) {
                            ClientHello deserialized_hello = std::move(deserialize_result.value());
                            
                            // Test validation logic
                            bool is_valid = deserialized_hello.is_valid();
                            
                            // Check for unexpected validation passes
                            if (is_valid && category != "random_field_corruption") {
                                found_vulnerability = true;
                                details = "Malformed message passed validation";
                            }
                        }
                    }
                    
                } catch (const std::bad_alloc& e) {
                    caused_crash = true;
                    error_msg = "Memory allocation failure: " + std::string(e.what());
                } catch (const std::exception& e) {
                    caused_exception = true;
                    error_msg = e.what();
                }
                
                record_fuzzing_result(test_name, category, caused_crash, caused_exception, 
                                    found_vulnerability, error_msg, details);
            }
            
        } catch (const std::exception& e) {
            record_fuzzing_result(test_name, "general_failure", false, true, false, e.what());
        }
    }
}

/**
 * Test ServerHello and HelloRetryRequest message fuzzing
 */
TEST_F(MessageFuzzingTest, FuzzServerHelloMessages) {
    const std::string test_name = "ServerHello_HelloRetryRequest_Fuzzing";
    
    for (size_t iteration = 0; iteration < fuzz_iterations_ / 10; ++iteration) {
        try {
            // Test both ServerHello and HelloRetryRequest
            test_server_hello_fuzzing(test_name, iteration);
            test_hello_retry_request_fuzzing(test_name, iteration);
            
        } catch (const std::exception& e) {
            record_fuzzing_result(test_name, "general_failure", false, true, false, e.what());
        }
    }
}

/**
 * Test DTLS record layer fuzzing (DTLSPlaintext and DTLSCiphertext)
 */
TEST_F(MessageFuzzingTest, FuzzDTLSRecordLayer) {
    const std::string test_name = "DTLS_Record_Layer_Fuzzing";
    
    for (size_t iteration = 0; iteration < fuzz_iterations_ / 5; ++iteration) {
        try {
            test_dtls_plaintext_fuzzing(test_name, iteration);
            test_dtls_ciphertext_fuzzing(test_name, iteration);
            
        } catch (const std::exception& e) {
            record_fuzzing_result(test_name, "general_failure", false, true, false, e.what());
        }
    }
}

/**
 * Test extension fuzzing with comprehensive coverage
 */
TEST_F(MessageFuzzingTest, FuzzProtocolExtensions) {
    const std::string test_name = "Protocol_Extensions_Fuzzing";
    
    std::vector<protocol::ExtensionType> critical_extensions = {
        protocol::ExtensionType::SUPPORTED_VERSIONS, protocol::ExtensionType::COOKIE, protocol::ExtensionType::KEY_SHARE,
        protocol::ExtensionType::SIGNATURE_ALGORITHMS, protocol::ExtensionType::SUPPORTED_GROUPS,
        protocol::ExtensionType::PRE_SHARED_KEY, protocol::ExtensionType::EARLY_DATA
    };
    
    for (size_t iteration = 0; iteration < fuzz_iterations_ / 20; ++iteration) {
        try {
            for (auto ext_type : critical_extensions) {
                test_extension_fuzzing(test_name, ext_type, iteration);
            }
            
        } catch (const std::exception& e) {
            record_fuzzing_result(test_name, "general_failure", false, true, false, e.what());
        }
    }
}

/**
 * Test certificate chain fuzzing
 */
TEST_F(MessageFuzzingTest, FuzzCertificateChain) {
    const std::string test_name = "Certificate_Chain_Fuzzing";
    
    for (size_t iteration = 0; iteration < fuzz_iterations_ / 15; ++iteration) {
        try {
            test_certificate_message_fuzzing(test_name, iteration);
            
        } catch (const std::exception& e) {
            record_fuzzing_result(test_name, "general_failure", false, true, false, e.what());
        }
    }
}

/**
 * Test handshake message fragmentation edge cases
 */
TEST_F(MessageFuzzingTest, FuzzMessageFragmentation) {
    const std::string test_name = "Message_Fragmentation_Fuzzing";
    
    for (size_t iteration = 0; iteration < fuzz_iterations_ / 25; ++iteration) {
        try {
            test_handshake_fragmentation_fuzzing(test_name, iteration);
            
        } catch (const std::exception& e) {
            record_fuzzing_result(test_name, "general_failure", false, true, false, e.what());
        }
    }
}

// ====================================================================
// Implementation of Specialized Fuzzing Methods
// ====================================================================

void MessageFuzzingTest::apply_clienthello_mutations(ClientHello& hello, 
                                                    const std::string& category, 
                                                    size_t iteration) {
    if (category == "random_field_corruption") {
        // Corrupt random field with various patterns
        auto corrupted_random_buffer = generate_secure_random(32);
        intelligent_mutate(corrupted_random_buffer, static_cast<int>(MutationType::RANDOM_BYTE));
        
        std::array<uint8_t, 32> corrupted_random;
        if (corrupted_random_buffer.size() >= 32) {
            std::memcpy(corrupted_random.data(), corrupted_random_buffer.data(), 32);
        } else {
            std::fill(corrupted_random.begin(), corrupted_random.end(), 0);
        }
        hello.set_random(corrupted_random);
        
    } else if (category == "boundary_value_injection") {
        // Test boundary values in various fields
        if (iteration % 4 == 0) {
            hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(0x0000)); // Minimum version
        } else if (iteration % 4 == 1) {
            hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(0xFFFF)); // Maximum version
        } else if (iteration % 4 == 2) {
            hello.set_cookie(memory::Buffer()); // Empty cookie
        } else {
            hello.set_cipher_suites(std::vector<CipherSuite>()); // Empty cipher suites
        }
        
    } else if (category == "oversized_fields") {
        // Test with oversized fields
        if (iteration % 3 == 0) {
            // Random field is always 32 bytes, so we can't oversized it directly
            // Instead, we'll create normal random and corrupt it
            auto random_buffer = generate_secure_random(32);
            std::array<uint8_t, 32> random_array;
            if (random_buffer.size() >= 32) {
                std::memcpy(random_array.data(), random_buffer.data(), 32);
            }
            hello.set_random(random_array);
        } else if (iteration % 3 == 1) {
            hello.set_cookie(generate_secure_random(1024)); // Oversized cookie  
        } else {
            hello.set_legacy_session_id(generate_secure_random(256)); // Oversized session ID
        }
        
    } else if (category == "undersized_fields") {
        // Test with undersized fields
        if (iteration % 3 == 0) {
            // Random field is always 32 bytes, create array with partial data
            auto random_buffer = generate_secure_random(16);
            std::array<uint8_t, 32> random_array;
            std::fill(random_array.begin(), random_array.end(), 0);
            if (random_buffer.size() >= 16) {
                std::memcpy(random_array.data(), random_buffer.data(), 16);
            }
            hello.set_random(random_array);
        } else if (iteration % 3 == 1) {
            hello.set_cookie(generate_secure_random(1)); // Minimal cookie
        } else {
            hello.set_legacy_session_id(memory::Buffer()); // Empty session ID
        }
        
    } else if (category == "invalid_combinations") {
        // Test invalid field combinations
        hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(0x0304)); // TLS 1.3 version in DTLS
        
        std::vector<CipherSuite> invalid_suites = {
            static_cast<CipherSuite>(0x0000), 
            static_cast<CipherSuite>(0xFFFF)
        }; // Invalid cipher suites
        hello.set_cipher_suites(std::move(invalid_suites));
        
        // Add conflicting extensions
        Extension invalid_ext1(protocol::ExtensionType::EARLY_DATA, generate_secure_random(100));
        hello.add_extension(std::move(invalid_ext1));
        
        Extension invalid_ext2(protocol::ExtensionType::EARLY_DATA, generate_secure_random(50)); // Duplicate extension
        hello.add_extension(std::move(invalid_ext2));
    }
}

void MessageFuzzingTest::test_server_hello_fuzzing(const std::string& test_name, size_t iteration) {
    bool caused_crash = false, caused_exception = false, found_vulnerability = false;
    std::string error_msg, details;
    
    try {
        ServerHello server_hello;
        server_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(0xFEFD));
        
        auto random_buffer = generate_secure_random(32);
        std::array<uint8_t, 32> random_array;
        if (random_buffer.size() >= 32) {
            std::memcpy(random_array.data(), random_buffer.data(), 32);
        } else {
            std::fill(random_array.begin(), random_array.end(), 0);
        }
        server_hello.set_random(random_array);
        
        server_hello.set_legacy_session_id_echo(generate_secure_random(32));
        server_hello.set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
        
        // Apply various mutation strategies
        std::string mutation_type = "ServerHello_";
        if (iteration % 5 == 0) {
            // Test with invalid cipher suite
            server_hello.set_cipher_suite(static_cast<CipherSuite>(0x0000));
            mutation_type += "invalid_cipher_suite";
        } else if (iteration % 5 == 1) {
            // Test with corrupted random
            auto corrupted_random_buffer = generate_secure_random(32);
            intelligent_mutate(corrupted_random_buffer, static_cast<int>(MutationType::BIT_FLIP));
            std::array<uint8_t, 32> corrupted_random;
            if (corrupted_random_buffer.size() >= 32) {
                std::memcpy(corrupted_random.data(), corrupted_random_buffer.data(), 32);
            }
            server_hello.set_random(corrupted_random);
            mutation_type += "corrupted_random";
        } else if (iteration % 5 == 2) {
            // Test with mismatched session ID echo
            server_hello.set_legacy_session_id_echo(generate_secure_random(64));
            mutation_type += "oversized_session_id";
        } else if (iteration % 5 == 3) {
            // Test with invalid version
            server_hello.set_legacy_version(static_cast<protocol::ProtocolVersion>(0x0304));
            mutation_type += "invalid_version";
        } else {
            // Test with malformed extensions
            Extension malformed_ext(static_cast<protocol::ExtensionType>(0xFFFF), generate_secure_random(1024)); // Reduced size
            server_hello.add_extension(std::move(malformed_ext));
            mutation_type += "malformed_extension";
        }
        
        // Test serialization/deserialization safety
        memory::Buffer serialized_data(4096);
        auto serialize_result = server_hello.serialize(serialized_data);
        
        if (serialize_result.is_success()) {
            auto deserialize_result = ServerHello::deserialize(serialized_data, 0);
            
            if (deserialize_result.is_success()) {
                ServerHello deserialized = std::move(deserialize_result.value());
                bool is_valid = deserialized.is_valid();
                // Check for validation bypass
                if (is_valid && mutation_type.find("invalid") != std::string::npos) {
                    found_vulnerability = true;
                    details = "Invalid ServerHello passed validation";
                }
            }
        }
        
    } catch (const std::bad_alloc& e) {
        caused_crash = true;
        error_msg = "Memory allocation failure: " + std::string(e.what());
    } catch (const std::exception& e) {
        caused_exception = true;
        error_msg = e.what();
    }
    
    record_fuzzing_result(test_name, "ServerHello_mutation", caused_crash, 
                         caused_exception, found_vulnerability, error_msg, details);
}

void MessageFuzzingTest::test_hello_retry_request_fuzzing(const std::string& test_name, size_t iteration) {
    bool caused_crash = false, caused_exception = false, found_vulnerability = false;
    std::string error_msg, details;
    std::string mutation_type = "HelloRetryRequest_";
    
    try {
        HelloRetryRequest hrr;
        hrr.set_legacy_version(static_cast<protocol::ProtocolVersion>(0xFEFD));
        hrr.set_legacy_session_id_echo(generate_secure_random(32));
        hrr.set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
        if (iteration % 4 == 0) {
            // Test with oversized cookie
            auto oversized_cookie = generate_secure_random(512);
            hrr.set_cookie(oversized_cookie);
            mutation_type += "oversized_cookie";
        } else if (iteration % 4 == 1) {
            // Test with invalid selected group
            hrr.set_selected_group(static_cast<protocol::NamedGroup>(0xFFFF));
            mutation_type += "invalid_group";
        } else if (iteration % 4 == 2) {
            // Test with wrong random (HelloRetryRequest has special random handling)
            // Cannot directly set random as it's managed by the HelloRetryRequest class
            mutation_type += "wrong_random";
        } else {
            // Test with conflicting extensions
            hrr.set_cookie(generate_secure_random(64));
            hrr.set_selected_group(protocol::NamedGroup::X25519);
            // Add conflicting extension
            Extension conflict_ext(protocol::ExtensionType::KEY_SHARE, generate_secure_random(100));
            hrr.add_extension(std::move(conflict_ext));
            mutation_type += "conflicting_extensions";
        }
        
        // Test HRR-specific validation
        memory::Buffer serialized_data(4096);
        auto serialize_result = hrr.serialize(serialized_data);
        
        if (serialize_result.is_success()) {
            auto deserialize_result = HelloRetryRequest::deserialize(serialized_data, 0);
            
            if (deserialize_result.is_success()) {
                HelloRetryRequest deserialized = std::move(deserialize_result.value());
                bool is_valid = deserialized.is_valid();
                bool has_hrr_random = HelloRetryRequest::is_hello_retry_request_random(deserialized.random());
                
                // Check for HRR-specific validation issues
                if (is_valid && !has_hrr_random && mutation_type.find("wrong_random") != std::string::npos) {
                    found_vulnerability = true;
                    details = "HelloRetryRequest with non-HRR random passed validation";
                }
            }
        }
        
    } catch (const std::bad_alloc& e) {
        caused_crash = true;
        error_msg = "Memory allocation failure: " + std::string(e.what());
    } catch (const std::exception& e) {
        caused_exception = true;
        error_msg = e.what();
    }
    
    record_fuzzing_result(test_name, mutation_type, caused_crash, 
                         caused_exception, found_vulnerability, error_msg, details);
}

void MessageFuzzingTest::test_dtls_plaintext_fuzzing(const std::string& test_name, size_t iteration) {
    bool caused_crash = false, caused_exception = false, found_vulnerability = false;
    std::string error_msg, details;
    std::string mutation_type = "DTLSPlaintext_";
    
    try {
        DTLSPlaintext plaintext;
        plaintext.set_type(protocol::ContentType::HANDSHAKE);
        plaintext.set_version(static_cast<protocol::ProtocolVersion>(0xFEFD));
        plaintext.set_epoch(1);
        plaintext.set_sequence_number(SequenceNumber48(iteration));
        
        // Test various mutation strategies
        if (iteration % 6 == 0) {
            // Test with invalid content type
            plaintext.set_type(static_cast<protocol::ContentType>(255));
            mutation_type += "invalid_content_type";
        } else if (iteration % 6 == 1) {
            // Test with version mismatch
            plaintext.set_version(static_cast<protocol::ProtocolVersion>(0x0304)); // TLS version
            mutation_type += "version_mismatch";
        } else if (iteration % 6 == 2) {
            // Test with oversized fragment
            auto oversized_fragment = generate_secure_random(DTLSPlaintext::MAX_FRAGMENT_LENGTH + 100);
            plaintext.set_fragment(std::move(oversized_fragment));
            mutation_type += "oversized_fragment";
        } else if (iteration % 6 == 3) {
            // Test with sequence number overflow
            plaintext.set_sequence_number(SequenceNumber48(0xFFFFFFFFFFFFULL));
            mutation_type += "sequence_overflow";
        } else if (iteration % 6 == 4) {
            // Test with invalid epoch
            plaintext.set_epoch(UINT16_MAX);
            auto fragment = generate_secure_random(1024);
            plaintext.set_fragment(std::move(fragment));
            mutation_type += "invalid_epoch";
        } else {
            // Test with corrupted fragment data
            auto fragment = generate_secure_random(512);
            intelligent_mutate(fragment, static_cast<int>(MutationType::RANDOM_BYTE));
            plaintext.set_fragment(std::move(fragment));
            mutation_type += "corrupted_fragment";
        }
        
        // Test record validation and serialization
        bool is_valid_before = plaintext.is_valid();
        
        memory::Buffer serialized_data(4096);
        auto serialize_result = plaintext.serialize(serialized_data);
        
        if (serialize_result.is_success()) {
            // Apply post-serialization mutations
            if (iteration % 3 == 0) {
                intelligent_mutate(serialized_data, static_cast<int>(MutationType::LENGTH_MANIPULATION));
            }
            
            auto deserialize_result = DTLSPlaintext::deserialize(serialized_data, 0);
            
            if (deserialize_result.is_success()) {
                DTLSPlaintext deserialized = std::move(deserialize_result.value());
                bool is_valid_after = deserialized.is_valid();
                
                // Check for validation inconsistencies
                if (is_valid_before != is_valid_after) {
                    found_vulnerability = true;
                    details = "Validation inconsistency detected";
                }
            }
        }
        
    } catch (const std::bad_alloc& e) {
        caused_crash = true;
        error_msg = "Memory allocation failure: " + std::string(e.what());
    } catch (const std::exception& e) {
        caused_exception = true;
        error_msg = e.what();
    }
    
    record_fuzzing_result(test_name, mutation_type, caused_crash, 
                         caused_exception, found_vulnerability, error_msg, details);
}

void MessageFuzzingTest::test_dtls_ciphertext_fuzzing(const std::string& test_name, size_t iteration) {
    bool caused_crash = false, caused_exception = false, found_vulnerability = false;
    std::string error_msg, details;
    std::string mutation_type = "DTLSCiphertext_";
    
    try {
        DTLSCiphertext ciphertext;
        ciphertext.set_type(protocol::ContentType::APPLICATION_DATA);
        ciphertext.set_version(static_cast<protocol::ProtocolVersion>(0xFEFD));
        ciphertext.set_epoch(1);
        
        if (iteration % 5 == 0) {
            // Test with corrupted encrypted sequence number
            SequenceNumber48 corrupted_seq(iteration);
            ciphertext.set_encrypted_sequence_number(corrupted_seq);
            mutation_type += "corrupted_sequence";
        } else if (iteration % 5 == 1) {
            // Test with oversized connection ID
            auto oversized_cid = generate_secure_random(DTLSCiphertext::MAX_CONNECTION_ID_LENGTH + 10);
            std::vector<uint8_t> cid_vector;
            cid_vector.reserve(oversized_cid.size());
            for (size_t i = 0; i < oversized_cid.size(); ++i) {
                cid_vector.push_back(static_cast<uint8_t>(oversized_cid.data()[i]));
            }
            ciphertext.set_connection_id(cid_vector);
            mutation_type += "oversized_connection_id";
        } else if (iteration % 5 == 2) {
            // Test with malformed encrypted record
            auto malformed_record = generate_secure_random(DTLSCiphertext::MAX_ENCRYPTED_RECORD_LENGTH + 100);
            intelligent_mutate(malformed_record, static_cast<int>(MutationType::BOUNDARY_VALUES));
            ciphertext.set_encrypted_record(std::move(malformed_record));
            mutation_type += "malformed_encrypted_record";
        } else if (iteration % 5 == 3) {
            // Test with inconsistent connection ID length
            auto cid = generate_secure_random(10);
            std::vector<uint8_t> cid_vector;
            cid_vector.reserve(cid.size());
            for (size_t i = 0; i < cid.size(); ++i) {
                cid_vector.push_back(static_cast<uint8_t>(cid.data()[i]));
            }
            ciphertext.set_connection_id(cid_vector);
            mutation_type += "inconsistent_cid_length";
        } else {
            // Test with empty encrypted record
            ciphertext.set_encrypted_record(memory::Buffer());
            mutation_type += "empty_encrypted_record";
        }
        
        // Test ciphertext validation and processing
        bool is_valid_before = ciphertext.is_valid();
        
        memory::Buffer serialized_data(4096);
        auto serialize_result = ciphertext.serialize(serialized_data);
        
        if (serialize_result.is_success()) {
            auto deserialize_result = DTLSCiphertext::deserialize(serialized_data, 0);
            
            if (deserialize_result.is_success()) {
                DTLSCiphertext deserialized = std::move(deserialize_result.value());
                bool is_valid_after = deserialized.is_valid();
                bool has_cid = deserialized.has_cid();
                
                // Use the variables to avoid warnings
                (void)is_valid_before;
                (void)is_valid_after;
                
                // Check various properties for consistency
                if (has_cid && deserialized.get_connection_id_length() == 0) {
                    found_vulnerability = true;
                    details = "Connection ID flag set but length is zero";
                }
            }
        }
        
    } catch (const std::bad_alloc& e) {
        caused_crash = true;
        error_msg = "Memory allocation failure: " + std::string(e.what());
    } catch (const std::exception& e) {
        caused_exception = true;
        error_msg = e.what();
    }
    
    record_fuzzing_result(test_name, mutation_type, caused_crash, 
                         caused_exception, found_vulnerability, error_msg, details);
}

void MessageFuzzingTest::test_extension_fuzzing(const std::string& test_name, 
                                               protocol::ExtensionType type, size_t iteration) {
    bool caused_crash = false, caused_exception = false, found_vulnerability = false;
    std::string error_msg, details;
    std::string mutation_type = "Extension_" + std::to_string(static_cast<int>(type));
    
    try {
        Extension extension;
        extension.type = type;
        
        // Generate extension-specific test data
        if (iteration % 7 == 0) {
            // Test with empty data
            extension.data = memory::Buffer();
            mutation_type += "_empty_data";
        } else if (iteration % 7 == 1) {
            // Test with minimal data
            extension.data = generate_secure_random(1);
            mutation_type += "_minimal_data";
        } else if (iteration % 7 == 2) {
            // Test with maximum size data (reduced for practicality)
            extension.data = generate_secure_random(1024);
            mutation_type += "_maximum_data";
        } else if (iteration % 7 == 3) {
            // Test with pattern data (all zeros)
            extension.data = generate_pattern_data(100, 0x00);
            mutation_type += "_zero_pattern";
        } else if (iteration % 7 == 4) {
            // Test with pattern data (all ones)
            extension.data = generate_pattern_data(100, 0xFF);
            mutation_type += "_one_pattern";
        } else if (iteration % 7 == 5) {
            // Test with corrupted data
            extension.data = generate_secure_random(256);
            intelligent_mutate(extension.data, static_cast<int>(MutationType::RANDOM_BYTE));
            mutation_type += "_corrupted_data";
        } else {
            // Test with boundary value mutations
            extension.data = generate_secure_random(128);
            intelligent_mutate(extension.data, static_cast<int>(MutationType::BOUNDARY_VALUES));
            mutation_type += "_boundary_values";
        }
        
        // Test extension validation and processing
        bool is_valid_before = extension.is_valid();
        (void)is_valid_before; // Avoid unused variable warning
        
        memory::Buffer serialized_data(4096);
        auto serialize_result = extension.serialize(serialized_data);
        
        if (serialize_result.is_success()) {
            auto deserialize_result = Extension::deserialize(serialized_data, 0);
            
            if (deserialize_result.is_success()) {
                Extension deserialized = std::move(deserialize_result.value());
                bool is_valid_after = deserialized.is_valid();
                
                // Test equality operations for consistency
                bool equals_test = (extension == deserialized);
                bool not_equals_test = (extension != deserialized);
                
                // Check for logical inconsistencies
                if (equals_test && not_equals_test) {
                    found_vulnerability = true;
                    details = "Equality operator logical inconsistency";
                }
                
                // Check for validation bypass with specific extension types
                if (type == protocol::ExtensionType::EARLY_DATA && extension.data.size() == 0 && is_valid_after) {
                    found_vulnerability = true;
                    details = "Empty early data extension passed validation";
                }
            }
        }
        
    } catch (const std::bad_alloc& e) {
        caused_crash = true;
        error_msg = "Memory allocation failure: " + std::string(e.what());
    } catch (const std::exception& e) {
        caused_exception = true;
        error_msg = e.what();
    }
    
    record_fuzzing_result(test_name, mutation_type, caused_crash, 
                         caused_exception, found_vulnerability, error_msg, details);
}

void MessageFuzzingTest::test_certificate_message_fuzzing(const std::string& test_name, size_t iteration) {
    bool caused_crash = false, caused_exception = false, found_vulnerability = false;
    std::string error_msg, details;
    std::string mutation_type = "Certificate_";
    
    try {
        Certificate certificate;
        
        if (iteration % 6 == 0) {
            // Test with oversized certificate request context
            auto oversized_context = generate_secure_random(1024);
            certificate.set_certificate_request_context(std::move(oversized_context));
            mutation_type += "oversized_context";
        } else if (iteration % 6 == 1) {
            // Test with empty certificate list
            certificate.set_certificate_list(std::vector<CertificateEntry>());
            mutation_type += "empty_certificate_list";
        } else if (iteration % 6 == 2) {
            // Test with oversized certificate chain (reduced size for practicality)
            for (size_t i = 0; i < 10; ++i) {
                CertificateEntry entry;
                entry.cert_data = generate_secure_random(1024);
                certificate.add_certificate(std::move(entry));
            }
            mutation_type += "oversized_chain";
        } else if (iteration % 6 == 3) {
            // Test with corrupted certificate data
            CertificateEntry entry;
            entry.cert_data = generate_secure_random(2048);
            intelligent_mutate(entry.cert_data, static_cast<int>(MutationType::RANDOM_BYTE));
            certificate.add_certificate(std::move(entry));
            mutation_type += "corrupted_certificate";
        } else if (iteration % 6 == 4) {
            // Test with malformed extensions in certificate entry
            CertificateEntry entry;
            entry.cert_data = generate_secure_random(1024);
            
            Extension malformed_ext(static_cast<protocol::ExtensionType>(0xFFFF), generate_secure_random(1024));
            entry.extensions.push_back(std::move(malformed_ext));
            
            certificate.add_certificate(std::move(entry));
            mutation_type += "malformed_extensions";
        } else {
            // Test with inconsistent certificate entry data
            CertificateEntry entry;
            entry.cert_data = memory::Buffer(); // Empty certificate data
            
            // But add extensions anyway
            Extension ext(protocol::ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP, generate_secure_random(64));
            entry.extensions.push_back(std::move(ext));
            
            certificate.add_certificate(std::move(entry));
            mutation_type += "inconsistent_entry";
        }
        
        // Test certificate validation
        bool is_valid = certificate.is_valid();
        
        memory::Buffer serialized_data(8192);
        auto serialize_result = certificate.serialize(serialized_data);
        
        if (serialize_result.is_success()) {
            auto deserialize_result = Certificate::deserialize(serialized_data, 0);
            
            if (deserialize_result.is_success()) {
                Certificate deserialized = std::move(deserialize_result.value());
                bool deserialized_valid = deserialized.is_valid();
                // Check certificate list and context without unused variable warnings
                (void)deserialized.certificate_list();
                (void)deserialized.certificate_request_context();
                
                // Check for validation consistency
                if (is_valid != deserialized_valid) {
                    found_vulnerability = true;
                    details = "Certificate validation inconsistency after serialization";
                }
            }
        }
        
    } catch (const std::bad_alloc& e) {
        caused_crash = true;
        error_msg = "Memory allocation failure: " + std::string(e.what());
    } catch (const std::exception& e) {
        caused_exception = true;
        error_msg = e.what();
    }
    
    record_fuzzing_result(test_name, mutation_type, caused_crash, 
                         caused_exception, found_vulnerability, error_msg, details);
}

void MessageFuzzingTest::test_handshake_fragmentation_fuzzing(const std::string& test_name, size_t iteration) {
    bool caused_crash = false, caused_exception = false, found_vulnerability = false;
    std::string error_msg, details;
    std::string mutation_type = "Fragmentation_";
    
    try {
        HandshakeHeader header;
        header.msg_type = static_cast<HandshakeType>(1); // ClientHello
        header.length = 1024 + (iteration % 4096);
        header.message_seq = static_cast<uint16_t>(iteration % 65536);
        
        // Test various fragmentation edge cases
        if (iteration % 8 == 0) {
            // Fragment beyond message boundary
            header.fragment_offset = header.length + 100;
            header.fragment_length = 200;
            mutation_type += "beyond_boundary";
        } else if (iteration % 8 == 1) {
            // Zero-length fragment at non-zero offset
            header.fragment_offset = 100;
            header.fragment_length = 0;
            mutation_type += "zero_length_fragment";
        } else if (iteration % 8 == 2) {
            // Fragment that would overflow
            header.fragment_offset = header.length - 10;
            header.fragment_length = 100;
            mutation_type += "fragment_overflow";
        } else if (iteration % 8 == 3) {
            // Maximum fragment length
            header.fragment_offset = 0;
            header.fragment_length = UINT32_MAX;
            mutation_type += "maximum_fragment_length";
        } else if (iteration % 8 == 4) {
            // Inconsistent message length and fragment
            header.length = 100;
            header.fragment_offset = 0;
            header.fragment_length = 200; // Larger than message
            mutation_type += "inconsistent_lengths";
        } else if (iteration % 8 == 5) {
            // Fragment at exact boundary
            header.fragment_offset = header.length;
            header.fragment_length = 1;
            mutation_type += "exact_boundary";
        } else if (iteration % 8 == 6) {
            // Large offset with small fragment
            header.fragment_offset = header.length - 1;
            header.fragment_length = 1;
            mutation_type += "boundary_fragment";
        } else {
            // Complete message with wrong fragmentation flags
            header.fragment_offset = 0;
            header.fragment_length = header.length;
            // This should be a complete message but we'll test edge cases
            mutation_type += "complete_message";
        }
        
        // Test fragmentation validation
        bool is_valid = header.is_valid();
        bool is_fragmented = header.is_fragmented();
        
        memory::Buffer serialized_data(HandshakeHeader::SERIALIZED_SIZE);
        auto serialize_result = header.serialize(serialized_data);
        
        if (serialize_result.is_success()) {
            auto deserialize_result = HandshakeHeader::deserialize(serialized_data, 0);
            
            if (deserialize_result.is_success()) {
                HandshakeHeader deserialized = std::move(deserialize_result.value());
                bool deserialized_valid = deserialized.is_valid();
                bool deserialized_fragmented = deserialized.is_fragmented();
                (void)deserialized_valid; // Avoid unused variable warning
                
                // Check for fragmentation logic consistency
                if (is_fragmented != deserialized_fragmented) {
                    found_vulnerability = true;
                    details = "Fragmentation flag inconsistency after serialization";
                }
                
                // Check for invalid fragmentation that passes validation
                if (header.fragment_offset > header.length && is_valid) {
                    found_vulnerability = true;
                    details = "Invalid fragmentation passed validation";
                }
            }
        }
        
    } catch (const std::bad_alloc& e) {
        caused_crash = true;
        error_msg = "Memory allocation failure: " + std::string(e.what());
    } catch (const std::exception& e) {
        caused_exception = true;
        error_msg = e.what();
    }
    
    record_fuzzing_result(test_name, mutation_type, caused_crash, 
                         caused_exception, found_vulnerability, error_msg, details);
}

} // namespace dtls::v13::test