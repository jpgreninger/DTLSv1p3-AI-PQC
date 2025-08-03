/*
 * RFC 9147 DTLS v1.3 Compliance Validator
 * Task 9: RFC compliance validation and test vector verification
 */

#include "interop_test_framework.h"
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/dtls_records.h>
#include <sstream>
#include <algorithm>
#include <set>

namespace dtls::v13::test::interop {

// ============================================================================
// RFC9147ComplianceValidator Implementation
// ============================================================================

struct RFC9147ComplianceValidator::Impl {
    std::vector<std::string> compliance_issues;
    std::vector<std::string> warnings;
    std::map<std::string, bool> test_results;
    
    void add_issue(const std::string& category, const std::string& issue) {
        compliance_issues.push_back(category + ": " + issue);
        test_results[category] = false;
    }
    
    void add_warning(const std::string& category, const std::string& warning) {
        warnings.push_back(category + ": " + warning);
    }
    
    void set_test_passed(const std::string& category) {
        test_results[category] = true;
    }
    
    bool is_category_passed(const std::string& category) const {
        auto it = test_results.find(category);
        return it != test_results.end() && it->second;
    }
};

RFC9147ComplianceValidator::RFC9147ComplianceValidator() 
    : pimpl_(std::make_unique<Impl>()) {}

RFC9147ComplianceValidator::~RFC9147ComplianceValidator() = default;

bool RFC9147ComplianceValidator::validate_handshake_messages(const std::vector<uint8_t>& handshake_data) {
    const std::string category = "Handshake Messages";
    
    if (handshake_data.empty()) {
        pimpl_->add_issue(category, "Empty handshake data");
        return false;
    }
    
    // Basic handshake message format validation
    if (handshake_data.size() < protocol::HandshakeHeader::SERIALIZED_SIZE) {
        pimpl_->add_issue(category, "Handshake data too short for header");
        return false;
    }
    
    try {
        // Parse handshake header
        protocol::HandshakeHeader header;
        memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(handshake_data.data()), handshake_data.size());
        auto parse_result = header.deserialize(buffer, 0);
        
        if (!parse_result.is_ok()) {
            pimpl_->add_issue(category, "Failed to parse handshake header");
            return false;
        }
        
        // Validate header fields
        if (!header.is_valid()) {
            pimpl_->add_issue(category, "Invalid handshake header");
            return false;
        }
        
        // Check message length consistency
        if (header.length + protocol::HandshakeHeader::SERIALIZED_SIZE > handshake_data.size()) {
            pimpl_->add_issue(category, "Handshake message length exceeds data size");
            return false;
        }
        
        // Validate fragmentation fields
        if (header.fragment_offset + header.fragment_length > header.length) {
            pimpl_->add_issue(category, "Invalid fragmentation parameters");
            return false;
        }
        
        pimpl_->set_test_passed(category);
        return true;
        
    } catch (const std::exception& e) {
        pimpl_->add_issue(category, std::string("Exception during validation: ") + e.what());
        return false;
    }
}

bool RFC9147ComplianceValidator::validate_record_layer_processing(const protocol::DTLSPlaintext& plaintext) {
    const std::string category = "Record Layer";
    
    // Validate DTLSPlaintext structure according to RFC 9147 Section 4.1.1
    if (!plaintext.is_valid()) {
        pimpl_->add_issue(category, "Invalid DTLSPlaintext structure");
        return false;
    }
    
    // Check content type
    auto content_type = plaintext.get_type();
    if (content_type != protocol::ContentType::HANDSHAKE && 
        content_type != protocol::ContentType::APPLICATION_DATA &&
        content_type != protocol::ContentType::ALERT) {
        pimpl_->add_issue(category, "Invalid content type");
        return false;
    }
    
    // Check protocol version
    auto version = plaintext.get_version();
    if (version != protocol::ProtocolVersion::DTLS_1_3) {
        pimpl_->add_warning(category, "Protocol version is not DTLS 1.3");
    }
    
    // Check epoch
    auto epoch = plaintext.get_epoch();
    if (epoch > 65535) {
        pimpl_->add_issue(category, "Epoch value out of range");
        return false;
    }
    
    // Check sequence number (48-bit limit)
    auto sequence_number = plaintext.get_sequence_number();
    const uint64_t max_sequence = (1ULL << 48) - 1;
    if (sequence_number > max_sequence) {
        pimpl_->add_issue(category, "Sequence number exceeds 48-bit limit");
        return false;
    }
    
    // Check fragment length
    auto fragment_length = plaintext.get_length();
    if (fragment_length > protocol::DTLSPlaintext::MAX_FRAGMENT_LENGTH) {
        pimpl_->add_issue(category, "Fragment length exceeds maximum");
        return false;
    }
    
    // Verify fragment size matches actual data
    const auto& fragment = plaintext.get_fragment();
    if (fragment.size() != fragment_length) {
        pimpl_->add_issue(category, "Fragment length mismatch");
        return false;
    }
    
    pimpl_->set_test_passed(category);
    return true;
}

bool RFC9147ComplianceValidator::validate_cipher_suite_selection(uint16_t negotiated_suite, 
                                                               const std::vector<uint16_t>& offered_suites) {
    const std::string category = "Cipher Suite Negotiation";
    
    // Check if negotiated cipher suite was in the offered list
    if (std::find(offered_suites.begin(), offered_suites.end(), negotiated_suite) == offered_suites.end()) {
        pimpl_->add_issue(category, "Negotiated cipher suite not in offered list");
        return false;
    }
    
    // Validate that the negotiated suite is a valid DTLS v1.3 cipher suite
    std::set<uint16_t> valid_dtls13_suites = {
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0x1304, // TLS_AES_128_CCM_SHA256
        0x1305  // TLS_AES_128_CCM_8_SHA256
    };
    
    if (valid_dtls13_suites.find(negotiated_suite) == valid_dtls13_suites.end()) {
        pimpl_->add_issue(category, "Negotiated cipher suite not valid for DTLS v1.3");
        return false;
    }
    
    // Check preference order (server should prefer stronger suites)
    std::vector<uint16_t> preference_order = {0x1302, 0x1301, 0x1303, 0x1304, 0x1305};
    
    bool found_stronger = false;
    for (uint16_t preferred : preference_order) {
        if (preferred == negotiated_suite) {
            break;
        }
        if (std::find(offered_suites.begin(), offered_suites.end(), preferred) != offered_suites.end()) {
            found_stronger = true;
            break;
        }
    }
    
    if (found_stronger) {
        pimpl_->add_warning(category, "Stronger cipher suite was available but not selected");
    }
    
    pimpl_->set_test_passed(category);
    return true;
}

bool RFC9147ComplianceValidator::validate_key_derivation(const std::vector<uint8_t>& derived_key,
                                                       const std::vector<uint8_t>& expected_key) {
    const std::string category = "Key Derivation";
    
    if (derived_key.empty()) {
        pimpl_->add_issue(category, "Derived key is empty");
        return false;
    }
    
    if (expected_key.empty()) {
        pimpl_->add_warning(category, "No expected key provided for comparison");
        pimpl_->set_test_passed(category);
        return true;
    }
    
    if (derived_key.size() != expected_key.size()) {
        pimpl_->add_issue(category, "Derived key length mismatch");
        return false;
    }
    
    if (derived_key != expected_key) {
        pimpl_->add_issue(category, "Derived key does not match expected value");
        return false;
    }
    
    pimpl_->set_test_passed(category);
    return true;
}

bool RFC9147ComplianceValidator::validate_version_negotiation(protocol::ProtocolVersion negotiated,
                                                            protocol::ProtocolVersion min_supported,
                                                            protocol::ProtocolVersion max_supported) {
    const std::string category = "Version Negotiation";
    
    // Check that negotiated version is within supported range
    if (negotiated < min_supported || negotiated > max_supported) {
        pimpl_->add_issue(category, "Negotiated version outside supported range");
        return false;
    }
    
    // For DTLS v1.3 compliance, verify that DTLS 1.3 is preferred when available
    if (max_supported >= protocol::ProtocolVersion::DTLS_1_3 && 
        negotiated != protocol::ProtocolVersion::DTLS_1_3) {
        pimpl_->add_warning(category, "DTLS 1.3 supported but not negotiated");
    }
    
    // Validate that only supported versions are used
    std::set<protocol::ProtocolVersion> valid_versions = {
        protocol::ProtocolVersion::DTLS_1_0,
        protocol::ProtocolVersion::DTLS_1_2,
        protocol::ProtocolVersion::DTLS_1_3
    };
    
    if (valid_versions.find(negotiated) == valid_versions.end()) {
        pimpl_->add_issue(category, "Invalid DTLS version negotiated");
        return false;
    }
    
    pimpl_->set_test_passed(category);
    return true;
}

bool RFC9147ComplianceValidator::validate_extension_processing(const std::vector<std::string>& extensions) {
    const std::string category = "Extension Processing";
    
    // Check for mandatory DTLS v1.3 extensions
    std::set<std::string> mandatory_extensions = {
        "supported_versions",
        "key_share",
        "signature_algorithms"
    };
    
    std::set<std::string> extension_set(extensions.begin(), extensions.end());
    
    for (const auto& mandatory : mandatory_extensions) {
        if (extension_set.find(mandatory) == extension_set.end()) {
            pimpl_->add_issue(category, "Missing mandatory extension: " + mandatory);
            return false;
        }
    }
    
    // Check for recommended extensions
    std::vector<std::string> recommended_extensions = {
        "server_name",
        "supported_groups",
        "signature_algorithms_cert"
    };
    
    for (const auto& recommended : recommended_extensions) {
        if (extension_set.find(recommended) == extension_set.end()) {
            pimpl_->add_warning(category, "Missing recommended extension: " + recommended);
        }
    }
    
    // Validate extension combinations
    if (extension_set.find("early_data") != extension_set.end()) {
        if (extension_set.find("pre_shared_key") == extension_set.end()) {
            pimpl_->add_issue(category, "early_data extension requires pre_shared_key");
            return false;
        }
    }
    
    pimpl_->set_test_passed(category);
    return true;
}

bool RFC9147ComplianceValidator::validate_sequence_number_handling(uint64_t sequence_number) {
    const std::string category = "Sequence Number Handling";
    
    // Check 48-bit sequence number limit (RFC 9147 Section 4.1.1)
    const uint64_t max_sequence = (1ULL << 48) - 1;
    if (sequence_number > max_sequence) {
        pimpl_->add_issue(category, "Sequence number exceeds 48-bit limit");
        return false;
    }
    
    // Check for sequence number near overflow
    const uint64_t overflow_warning_threshold = max_sequence - 1000000; // Warn at 1M before overflow
    if (sequence_number > overflow_warning_threshold) {
        pimpl_->add_warning(category, "Sequence number approaching overflow limit");
    }
    
    pimpl_->set_test_passed(category);
    return true;
}

bool RFC9147ComplianceValidator::validate_anti_replay_protection(const std::vector<uint64_t>& received_sequences) {
    const std::string category = "Anti-Replay Protection";
    
    if (received_sequences.empty()) {
        pimpl_->add_warning(category, "No sequence numbers to validate");
        pimpl_->set_test_passed(category);
        return true;
    }
    
    // Check for duplicate sequence numbers
    std::set<uint64_t> unique_sequences(received_sequences.begin(), received_sequences.end());
    if (unique_sequences.size() != received_sequences.size()) {
        pimpl_->add_issue(category, "Duplicate sequence numbers detected");
        return false;
    }
    
    // Check sequence number ordering and gaps
    auto sorted_sequences = received_sequences;
    std::sort(sorted_sequences.begin(), sorted_sequences.end());
    
    for (size_t i = 1; i < sorted_sequences.size(); ++i) {
        uint64_t gap = sorted_sequences[i] - sorted_sequences[i-1];
        
        // Large gaps might indicate issues with anti-replay window
        if (gap > 1000) {
            pimpl_->add_warning(category, "Large sequence number gap detected: " + std::to_string(gap));
        }
    }
    
    // Validate that all sequence numbers are within valid range
    for (uint64_t seq : received_sequences) {
        if (!validate_sequence_number_handling(seq)) {
            return false;
        }
    }
    
    pimpl_->set_test_passed(category);
    return true;
}

std::string RFC9147ComplianceValidator::generate_compliance_report() {
    std::ostringstream report;
    
    report << "RFC 9147 DTLS v1.3 Compliance Report\n";
    report << "=====================================\n\n";
    
    // Summary
    int total_categories = pimpl_->test_results.size();
    int passed_categories = 0;
    
    for (const auto& [category, passed] : pimpl_->test_results) {
        if (passed) {
            passed_categories++;
        }
    }
    
    double compliance_rate = total_categories > 0 ? (double)passed_categories / total_categories * 100.0 : 0.0;
    
    report << "Summary:\n";
    report << "  Total test categories: " << total_categories << "\n";
    report << "  Passed categories: " << passed_categories << "\n";
    report << "  Compliance rate: " << compliance_rate << "%\n\n";
    
    // Detailed results
    report << "Detailed Results:\n";
    for (const auto& [category, passed] : pimpl_->test_results) {
        report << "  " << (passed ? "✓" : "✗") << " " << category << "\n";
    }
    report << "\n";
    
    // Issues
    if (!pimpl_->compliance_issues.empty()) {
        report << "Compliance Issues:\n";
        for (const auto& issue : pimpl_->compliance_issues) {
            report << "  ✗ " << issue << "\n";
        }
        report << "\n";
    }
    
    // Warnings
    if (!pimpl_->warnings.empty()) {
        report << "Warnings:\n";
        for (const auto& warning : pimpl_->warnings) {
            report << "  ⚠ " << warning << "\n";
        }
        report << "\n";
    }
    
    // Recommendations
    report << "Recommendations:\n";
    if (compliance_rate < 100.0) {
        report << "  - Address compliance issues listed above\n";
        report << "  - Review RFC 9147 requirements for failed categories\n";
    }
    
    if (!pimpl_->warnings.empty()) {
        report << "  - Consider addressing warnings for better compatibility\n";
    }
    
    if (compliance_rate >= 90.0) {
        report << "  - Excellent compliance! Consider additional testing scenarios\n";
    } else if (compliance_rate >= 70.0) {
        report << "  - Good compliance level, focus on remaining issues\n";
    } else {
        report << "  - Significant compliance issues need attention\n";
    }
    
    return report.str();
}

} // namespace dtls::v13::test::interop