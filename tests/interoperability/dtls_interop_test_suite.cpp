/*
 * DTLS v1.3 Interoperability Test Suite
 * Task 9: Comprehensive external implementation testing
 */

#include <gtest/gtest.h>
#include "interop_test_framework.h"
#include "openssl_interop_tests.h"
#include "interop_config.h"
#include <iostream>
#include <memory>
#include <vector>

using namespace dtls::v13::test::interop;

class DTLSInteroperabilityTestSuite : public ::testing::Test {
protected:
    void SetUp() override {
        harness_ = std::make_unique<InteropTestHarness>();
        harness_->enable_debug_logging(true);
        
        // Register available external implementations
        register_available_implementations();
        
        // Setup test environment
        setup_test_certificates();
    }
    
    void TearDown() override {
        // Generate final reports
        if (harness_) {
            harness_->generate_compatibility_matrix();
            harness_->generate_performance_report();
            harness_->export_results_to_json("interop_test_results.json");
        }
    }
    
    void register_available_implementations() {
#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE
        auto openssl_runner = std::make_unique<OpenSSLImplementationRunner>();
        harness_->register_external_implementation(
            ExternalImplementation::OPENSSL_3_0, 
            std::move(openssl_runner));
        std::cout << "Registered OpenSSL implementation" << std::endl;
#endif
        
        // Add other implementations when available
        // harness_->register_external_implementation(ExternalImplementation::WOLFSSL_5_6, ...);
        // harness_->register_external_implementation(ExternalImplementation::GNUTLS_3_7, ...);
    }
    
    void setup_test_certificates() {
        // In a real implementation, setup proper test certificates
        harness_->set_certificate_files("test-cert.pem", "test-key.pem");
        harness_->set_ca_certificate_file("test-ca.pem");
    }
    
protected:
    std::unique_ptr<InteropTestHarness> harness_;
};

// ============================================================================
// Quick Interoperability Tests
// ============================================================================

TEST_F(DTLSInteroperabilityTestSuite, QuickOpenSSLCompatibilityCheck) {
#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE
    std::cout << "Running quick OpenSSL compatibility check..." << std::endl;
    
    if (!harness_->is_implementation_available(ExternalImplementation::OPENSSL_3_0)) {
        GTEST_SKIP() << "OpenSSL implementation not available";
    }
    
    // Test basic handshake in both directions
    auto configs = OpenSSLTestScenarios::get_basic_test_configs();
    
    int successful_tests = 0;
    int total_tests = 0;
    
    for (const auto& config : configs) {
        total_tests++;
        auto result = harness_->run_test(config);
        
        if (result.success) {
            successful_tests++;
            std::cout << "✓ " << config.test_description << std::endl;
        } else {
            std::cout << "✗ " << config.test_description << " - " << result.error_message << std::endl;
        }
    }
    
    double success_rate = static_cast<double>(successful_tests) / total_tests * 100.0;
    std::cout << "OpenSSL Quick Test Success Rate: " << success_rate << "%" << std::endl;
    
    // Require at least 80% success for basic compatibility
    EXPECT_GE(success_rate, 80.0) << "OpenSSL basic compatibility below threshold";
    EXPECT_GT(successful_tests, 0) << "No successful OpenSSL tests";
#else
    GTEST_SKIP() << "OpenSSL support not compiled in";
#endif
}

// ============================================================================
// Comprehensive Interoperability Tests
// ============================================================================

TEST_F(DTLSInteroperabilityTestSuite, OpenSSLCipherSuiteNegotiation) {
#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE
    std::cout << "Testing OpenSSL cipher suite negotiation..." << std::endl;
    
    if (!harness_->is_implementation_available(ExternalImplementation::OPENSSL_3_0)) {
        GTEST_SKIP() << "OpenSSL implementation not available";
    }
    
    auto configs = OpenSSLTestScenarios::get_cipher_suite_test_configs();
    
    std::map<uint16_t, int> successful_negotiations;
    std::map<uint16_t, int> total_negotiations;
    
    for (const auto& config : configs) {
        for (uint16_t cipher : config.cipher_suites) {
            total_negotiations[cipher]++;
            
            auto result = harness_->run_test(config);
            if (result.success && result.negotiated_cipher_suite == cipher) {
                successful_negotiations[cipher]++;
            }
        }
    }
    
    // Verify cipher suite negotiation worked
    for (const auto& [cipher, total] : total_negotiations) {
        int successful = successful_negotiations[cipher];
        double rate = static_cast<double>(successful) / total * 100.0;
        
        std::cout << "Cipher 0x" << std::hex << cipher << std::dec 
                  << ": " << successful << "/" << total << " (" << rate << "%)" << std::endl;
        
        // Each cipher suite should work in at least one direction
        EXPECT_GT(successful, 0) << "Cipher suite 0x" << std::hex << cipher << " never negotiated";
    }
#else
    GTEST_SKIP() << "OpenSSL support not compiled in";
#endif
}

TEST_F(DTLSInteroperabilityTestSuite, OpenSSLLargeDataTransfer) {
#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE
    std::cout << "Testing OpenSSL large data transfer..." << std::endl;
    
    if (!harness_->is_implementation_available(ExternalImplementation::OPENSSL_3_0)) {
        GTEST_SKIP() << "OpenSSL implementation not available";
    }
    
    auto configs = OpenSSLTestScenarios::get_large_data_test_configs();
    
    std::map<size_t, bool> data_size_results;
    
    for (const auto& config : configs) {
        auto result = harness_->run_test(config);
        
        if (result.success) {
            data_size_results[config.test_data_size] = true;
            std::cout << "✓ Successfully transferred " << config.test_data_size << " bytes" << std::endl;
        } else {
            std::cout << "✗ Failed to transfer " << config.test_data_size << " bytes: " 
                      << result.error_message << std::endl;
            
            // Only mark as failed if we haven't succeeded with this size yet
            if (data_size_results.find(config.test_data_size) == data_size_results.end()) {
                data_size_results[config.test_data_size] = false;
            }
        }
    }
    
    // Verify we can transfer reasonable data sizes
    EXPECT_TRUE(data_size_results[1024]) << "Failed to transfer 1KB data";
    EXPECT_TRUE(data_size_results[4096]) << "Failed to transfer 4KB data";
    
    // Larger sizes are nice to have but not required
    if (data_size_results[16384]) {
        std::cout << "✓ Large data transfer (16KB) supported" << std::endl;
    }
#else
    GTEST_SKIP() << "OpenSSL support not compiled in";
#endif
}

// ============================================================================
// Performance Interoperability Tests
// ============================================================================

TEST_F(DTLSInteroperabilityTestSuite, OpenSSLPerformanceBenchmark) {
#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE
    std::cout << "Running OpenSSL performance benchmark..." << std::endl;
    
    if (!harness_->is_implementation_available(ExternalImplementation::OPENSSL_3_0)) {
        GTEST_SKIP() << "OpenSSL implementation not available";
    }
    
    // Test handshake performance
    InteropTestConfig config = OpenSSLTestScenarios::create_basic_handshake_config(TestRole::CLIENT);
    
    const int num_iterations = 10;
    std::vector<std::chrono::milliseconds> handshake_times;
    
    for (int i = 0; i < num_iterations; ++i) {
        config.test_description = "OpenSSL Performance Test " + std::to_string(i + 1);
        auto result = harness_->run_test(config);
        
        if (result.success) {
            handshake_times.push_back(result.duration);
        }
    }
    
    if (!handshake_times.empty()) {
        auto total_time = std::accumulate(handshake_times.begin(), handshake_times.end(), 
                                        std::chrono::milliseconds(0));
        auto avg_time = total_time / handshake_times.size();
        
        auto min_time = *std::min_element(handshake_times.begin(), handshake_times.end());
        auto max_time = *std::max_element(handshake_times.begin(), handshake_times.end());
        
        std::cout << "OpenSSL Handshake Performance:" << std::endl;
        std::cout << "  Successful handshakes: " << handshake_times.size() << "/" << num_iterations << std::endl;
        std::cout << "  Average time: " << avg_time.count() << "ms" << std::endl;
        std::cout << "  Min time: " << min_time.count() << "ms" << std::endl;
        std::cout << "  Max time: " << max_time.count() << "ms" << std::endl;
        
        // Performance expectations (adjust based on requirements)
        EXPECT_LT(avg_time.count(), 5000) << "Average handshake time too slow";
        EXPECT_GE(handshake_times.size(), num_iterations * 0.8) << "Too many handshake failures";
    } else {
        FAIL() << "No successful handshakes in performance test";
    }
#else
    GTEST_SKIP() << "OpenSSL support not compiled in";
#endif
}

// ============================================================================
// Comprehensive Test Matrix
// ============================================================================

TEST_F(DTLSInteroperabilityTestSuite, ComprehensiveCompatibilityMatrix) {
    std::cout << "Running comprehensive compatibility matrix test..." << std::endl;
    
    auto available_implementations = utils::detect_available_implementations();
    if (available_implementations.empty()) {
        GTEST_SKIP() << "No external implementations available for testing";
    }
    
    auto quick_scenarios = utils::get_quick_test_scenarios();
    
    auto results = harness_->run_test_matrix(available_implementations, quick_scenarios);
    
    // Analyze results
    int total_tests = results.size();
    int successful_tests = 0;
    
    for (const auto& result : results) {
        if (result.success) {
            successful_tests++;
        }
    }
    
    double overall_success_rate = static_cast<double>(successful_tests) / total_tests * 100.0;
    
    std::cout << "Comprehensive Test Results:" << std::endl;
    std::cout << "  Total tests: " << total_tests << std::endl;
    std::cout << "  Successful: " << successful_tests << std::endl;
    std::cout << "  Overall success rate: " << overall_success_rate << "%" << std::endl;
    
    // Overall compatibility expectations
    EXPECT_GT(successful_tests, 0) << "No successful interoperability tests";
    EXPECT_GE(overall_success_rate, 70.0) << "Overall compatibility rate below acceptable threshold";
    
    // Log detailed results for analysis
    for (const auto& result : results) {
        std::cout << (result.success ? "✓" : "✗") << " " << result.test_description;
        if (!result.success) {
            std::cout << " - " << result.error_message;
        }
        std::cout << std::endl;
    }
}

// ============================================================================
// RFC 9147 Compliance Tests
// ============================================================================

TEST_F(DTLSInteroperabilityTestSuite, RFC9147ComplianceValidation) {
    std::cout << "Running RFC 9147 compliance validation..." << std::endl;
    
    RFC9147ComplianceValidator validator;
    
    // Test protocol version negotiation
    bool version_negotiation_ok = validator.validate_version_negotiation(
        protocol::ProtocolVersion::DTLS_1_3,
        protocol::ProtocolVersion::DTLS_1_2,
        protocol::ProtocolVersion::DTLS_1_3);
    
    EXPECT_TRUE(version_negotiation_ok) << "Version negotiation compliance failed";
    
    // Test cipher suite selection
    std::vector<uint16_t> offered_suites = {0x1301, 0x1302, 0x1303};
    bool cipher_selection_ok = validator.validate_cipher_suite_selection(0x1301, offered_suites);
    
    EXPECT_TRUE(cipher_selection_ok) << "Cipher suite selection compliance failed";
    
    // Test extension processing
    std::vector<std::string> extensions = {"supported_versions", "key_share", "signature_algorithms"};
    bool extension_processing_ok = validator.validate_extension_processing(extensions);
    
    EXPECT_TRUE(extension_processing_ok) << "Extension processing compliance failed";
    
    // Test anti-replay protection
    std::vector<uint64_t> sequence_numbers = {1, 2, 3, 5, 6}; // Missing 4
    bool anti_replay_ok = validator.validate_anti_replay_protection(sequence_numbers);
    
    EXPECT_TRUE(anti_replay_ok) << "Anti-replay protection compliance failed";
    
    // Generate compliance report
    std::string compliance_report = validator.generate_compliance_report();
    std::cout << "RFC 9147 Compliance Report:" << std::endl;
    std::cout << compliance_report << std::endl;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "DTLS v1.3 Interoperability Test Suite" << std::endl;
    std::cout << "======================================" << std::endl;
    
    // Print available implementations
    auto available_impls = utils::detect_available_implementations();
    std::cout << "Available external implementations:" << std::endl;
    for (auto impl : available_impls) {
        std::cout << "  - " << utils::implementation_to_string(impl) << std::endl;
    }
    
    if (available_impls.empty()) {
        std::cout << "WARNING: No external implementations detected!" << std::endl;
        std::cout << "Some tests will be skipped." << std::endl;
    }
    
    std::cout << std::endl;
    
    return RUN_ALL_TESTS();
}