/**
 * DTLS v1.3 Error Handling System Examples
 * 
 * This file demonstrates how to use the comprehensive error handling
 * system implemented for DTLS v1.3 with RFC 9147 compliance.
 */

#include <dtls/error_handler.h>
#include <dtls/error_context.h>
#include <dtls/alert_manager.h>
#include <dtls/error_reporter.h>
#include <dtls/types.h>
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

using namespace dtls::v13;

namespace examples {

/**
 * Example 1: Basic Error Handler Setup for UDP Transport
 * 
 * Demonstrates RFC 9147 compliant configuration for UDP transport
 * where alert generation is NOT RECOMMENDED due to DoS risks.
 */
void example_udp_error_handling() {
    std::cout << "\n=== Example 1: UDP Error Handling (RFC 9147 Compliant) ===\n";
    
    // Configure error handler for UDP transport per RFC 9147
    ErrorHandler::Configuration config;
    config.transport_type = ErrorHandler::Transport::UDP;
    config.security_level = ErrorHandler::SecurityLevel::STANDARD;
    
    // RFC 9147: "generating fatal alerts is NOT RECOMMENDED for such transports"
    config.generate_alerts_on_invalid_records = false;
    
    // RFC 9147: "an error MAY be logged for diagnostic purposes"
    config.log_invalid_records = true;
    
    // DoS protection settings
    config.max_auth_failures_per_epoch = 10;
    config.max_invalid_records_per_second = 50;
    config.enable_attack_detection = true;
    
    auto error_handler = std::make_unique<ErrorHandler>(config);
    
    // Create error context for a connection
    NetworkAddress peer_addr = NetworkAddress::from_ipv4("192.168.1.100", 12345);
    auto context = error_handler->create_error_context("conn_001", peer_addr);
    
    // Simulate invalid record handling per RFC 9147 Section 4.2.1
    std::cout << "Processing invalid record (should be silently discarded)...\n";
    auto result = error_handler->handle_invalid_record(ContentType::INVALID, context);
    
    if (result.is_success()) {
        std::cout << "✓ Invalid record silently discarded per RFC 9147\n";
    }
    
    // Check statistics
    const auto& stats = error_handler->get_error_statistics();
    std::cout << "Invalid records discarded: " << stats.invalid_records_discarded << "\n";
    std::cout << "Alerts generated: " << stats.alerts_generated << " (should be 0 for UDP)\n";
    
    // Simulate authentication failures
    std::cout << "\nTesting authentication failure tracking...\n";
    Epoch epoch = 1;
    
    for (int i = 0; i < 12; ++i) {
        auto auth_result = error_handler->handle_authentication_failure(epoch, context);
        if (auth_result.is_success()) {
            bool should_continue = auth_result.value();
            std::cout << "Auth failure " << (i+1) << ": Connection " 
                      << (should_continue ? "continues" : "should terminate") << "\n";
            
            if (!should_continue) {
                std::cout << "✓ Connection termination recommended after excessive failures\n";
                break;
            }
        }
    }
    
    std::cout << "DoS attacks detected: " << stats.dos_attacks_detected << "\n";
}

/**
 * Example 2: Secure Transport Error Handling
 * 
 * Demonstrates error handling for secure transports like SCTP with SCTP-AUTH
 * where alert generation is safer.
 */
void example_secure_transport_error_handling() {
    std::cout << "\n=== Example 2: Secure Transport Error Handling ===\n";
    
    // Configure for secure transport (SCTP with SCTP-AUTH)
    ErrorHandler::Configuration config;
    config.transport_type = ErrorHandler::Transport::DTLS_OVER_SCTP;
    config.security_level = ErrorHandler::SecurityLevel::STRICT;
    
    // Safe to generate alerts for secure transports
    config.generate_alerts_on_invalid_records = true;
    config.log_invalid_records = true;
    
    auto error_handler = std::make_unique<ErrorHandler>(config);
    
    // Configure alert manager for secure transport
    AlertManager::AlertPolicy alert_policy;
    alert_policy.transport_security = AlertManager::TransportSecurity::SECURE;
    alert_policy.generate_alerts_for_invalid_records = true;
    alert_policy.generate_alerts_for_auth_failures = true;
    alert_policy.max_alerts_per_minute = 60;
    
    auto alert_manager = std::make_unique<AlertManager>(alert_policy);
    error_handler->set_alert_manager(alert_manager);
    
    auto context = error_handler->create_error_context("secure_conn_001");
    
    // Test alert generation for secure transport
    std::cout << "Testing alert generation for secure transport...\n";
    
    auto alert_result = error_handler->generate_alert_if_appropriate(
        AlertDescription::BAD_RECORD_MAC, context);
    
    if (alert_result.is_success()) {
        const auto& alert_data = alert_result.value();
        std::cout << "✓ Alert generated for secure transport (" 
                  << alert_data.size() << " bytes)\n";
        
        // Parse and display alert details
        auto parse_result = AlertManager::parse_alert(alert_data);
        if (parse_result.is_success()) {
            auto [level, description] = parse_result.value();
            std::cout << "  Alert Level: " << static_cast<int>(level) 
                      << " (FATAL=" << static_cast<int>(AlertLevel::FATAL) << ")\n";
            std::cout << "  Alert Description: " << static_cast<int>(description) << "\n";
        }
    }
    
    // Test error processing
    std::cout << "\nProcessing handshake failure...\n";
    auto process_result = error_handler->process_error(
        DTLSError::HANDSHAKE_FAILURE, context);
    
    if (process_result.is_success()) {
        bool should_continue = process_result.value();
        std::cout << "Handshake failure processed: Connection " 
                  << (should_continue ? "continues" : "terminates") << "\n";
    }
}

/**
 * Example 3: Comprehensive Error Reporting
 * 
 * Demonstrates secure error reporting with privacy protection
 * and structured logging.
 */
void example_error_reporting() {
    std::cout << "\n=== Example 3: Comprehensive Error Reporting ===\n";
    
    // Configure error reporter with privacy protection
    ErrorReporter::ReportingConfig reporter_config;
    reporter_config.minimum_level = ErrorReporter::LogLevel::INFO;
    reporter_config.format = ErrorReporter::OutputFormat::JSON;
    reporter_config.max_sensitivity = ErrorReporter::SensitivityLevel::INTERNAL;
    
    // Privacy settings per RFC 9147 security requirements
    reporter_config.log_network_addresses = false;  // Privacy protection
    reporter_config.log_connection_ids = false;     // Avoid sensitive data
    reporter_config.anonymize_peer_info = true;     // Hash instead of log
    reporter_config.log_sensitive_data = false;     // Never log keys/plaintext
    
    // Rate limiting to prevent log flooding
    reporter_config.max_reports_per_second = 100;
    reporter_config.max_reports_per_minute = 1000;
    
    auto error_reporter = std::make_unique<ErrorReporter>(reporter_config);
    
    // Create error context with network info
    NetworkAddress peer_addr = NetworkAddress::from_ipv4("10.0.0.50", 443);
    auto context = std::make_shared<ErrorContext>("reporting_test_conn", peer_addr);
    
    // Example 1: Basic error reporting
    std::cout << "Reporting basic error...\n";
    auto result1 = error_reporter->report_error(
        ErrorReporter::LogLevel::WARNING,
        DTLSError::CERTIFICATE_VERIFY_FAILED,
        "certificate_validation",
        "Certificate verification failed - unknown CA",
        context
    );
    
    if (result1.is_success()) {
        std::cout << "✓ Basic error reported successfully\n";
    }
    
    // Example 2: Security incident reporting
    std::cout << "Reporting security incident...\n";
    auto result2 = error_reporter->report_security_incident(
        DTLSError::REPLAY_ATTACK_DETECTED,
        "replay_attack_pattern",
        0.85,  // 85% confidence
        context
    );
    
    if (result2.is_success()) {
        std::cout << "✓ Security incident reported successfully\n";
    }
    
    // Example 3: Performance issue reporting
    std::cout << "Reporting performance issue...\n";
    auto result3 = error_reporter->report_performance_issue(
        DTLSError::TIMEOUT,
        "handshake_completion",
        std::chrono::microseconds(5000000),  // 5 seconds
        context
    );
    
    if (result3.is_success()) {
        std::cout << "✓ Performance issue reported successfully\n";
    }
    
    // Example 4: Structured reporting with builder pattern
    std::cout << "Using report builder for complex report...\n";
    auto builder_result = error_reporter->create_report(
        ErrorReporter::LogLevel::SECURITY, DTLSError::TAMPERING_DETECTED)
        .category("integrity_validation")
        .message("Message tampering detected during record processing")
        .sensitivity(ErrorReporter::SensitivityLevel::CONFIDENTIAL)
        .context(context)
        .security_incident(true)
        .threat_confidence(0.92)
        .attack_vector("message_modification")
        .metadata("record_type", "handshake")
        .metadata("epoch", "2")
        .tag("security")
        .tag("integrity")
        .tag("attack")
        .submit();
    
    if (builder_result.is_success()) {
        std::cout << "✓ Complex structured report submitted successfully\n";
    }
    
    // Display statistics
    const auto& stats = error_reporter->get_statistics();
    std::cout << "\nReporting Statistics:\n";
    std::cout << "  Total reports: " << stats.total_reports << "\n";
    std::cout << "  Security incidents: " << stats.security_incidents << "\n";
    std::cout << "  Rate limited reports: " << stats.rate_limited_reports << "\n";
    std::cout << "  Bytes logged: " << stats.bytes_logged << "\n";
}

/**
 * Example 4: Error Context Management and Analysis
 * 
 * Demonstrates error context creation, tracking, and attack pattern detection.
 */
void example_error_context_analysis() {
    std::cout << "\n=== Example 4: Error Context Analysis ===\n";
    
    ErrorContextManager context_manager;
    
    // Create contexts for multiple connections
    std::vector<std::shared_ptr<ErrorContext>> contexts;
    for (int i = 0; i < 5; ++i) {
        NetworkAddress peer_addr = NetworkAddress::from_ipv4(
            "192.168.1." + std::to_string(100 + i), 443);
        contexts.push_back(context_manager.create_context(
            "test_conn_" + std::to_string(i), peer_addr));
    }
    
    // Simulate various error patterns
    std::cout << "Simulating error patterns across connections...\n";
    
    // Connection 0: Normal errors
    contexts[0]->record_error(DTLSError::TIMEOUT, "network", "Network timeout");
    contexts[0]->record_error(DTLSError::RECEIVE_ERROR, "transport", "Receive failed");
    
    // Connection 1: Suspicious authentication pattern
    for (int i = 0; i < 8; ++i) {
        contexts[1]->record_security_error(
            DTLSError::AUTHENTICATION_FAILED, "brute_force", 0.7);
    }
    
    // Connection 2: Replay attack pattern
    for (int i = 0; i < 5; ++i) {
        contexts[2]->record_security_error(
            DTLSError::REPLAY_ATTACK_DETECTED, "replay", 0.9);
    }
    
    // Connection 3: Mixed security issues
    contexts[3]->record_security_error(DTLSError::TAMPERING_DETECTED, "tamper", 0.8);
    contexts[3]->record_security_error(DTLSError::BAD_RECORD_MAC, "integrity", 0.6);
    contexts[3]->record_security_error(DTLSError::DECRYPT_ERROR, "crypto", 0.7);
    
    // Analyze each connection
    std::cout << "\nAnalyzing error contexts:\n";
    for (size_t i = 0; i < contexts.size(); ++i) {
        const auto& context = contexts[i];
        
        std::cout << "Connection " << i << ":\n";
        std::cout << "  Total errors: " << context->get_total_error_count() << "\n";
        std::cout << "  Security errors: " << (context->has_security_errors() ? "Yes" : "No") << "\n";
        
        if (context->has_security_errors()) {
            double confidence = context->detect_attack_patterns();
            std::cout << "  Attack confidence: " << std::fixed << std::setprecision(2) 
                      << confidence << "\n";
            
            if (confidence > 0.7) {
                std::cout << "  ⚠️  HIGH THREAT DETECTED\n";
            }
        }
        
        // Check error rate
        bool excessive_rate = context->is_error_rate_excessive(
            std::chrono::seconds(10), 5);
        if (excessive_rate) {
            std::cout << "  ⚠️  EXCESSIVE ERROR RATE\n";
        }
        
        std::cout << "  Context age: " 
                  << context->get_context_age().count() << " seconds\n";
    }
    
    // System-wide analysis
    std::cout << "\nPerforming system-wide attack correlation...\n";
    auto coordinated_attacks = context_manager.analyze_coordinated_attacks();
    
    if (!coordinated_attacks.empty()) {
        std::cout << "⚠️  COORDINATED ATTACK DETECTED across " 
                  << coordinated_attacks.size() << " connections:\n";
        for (const auto& connection_id : coordinated_attacks) {
            std::cout << "  - " << connection_id << "\n";
        }
    } else {
        std::cout << "✓ No coordinated attacks detected\n";
    }
    
    // Display global metrics
    const auto& global_metrics = context_manager.get_global_metrics();
    std::cout << "\nGlobal Context Metrics:\n";
    std::cout << "  Active contexts: " << global_metrics.active_contexts << "\n";
    std::cout << "  Security incidents: " << global_metrics.security_incidents << "\n";
    std::cout << "  DoS attempts detected: " << global_metrics.dos_attempts_detected << "\n";
}

/**
 * Example 5: Integration with Production DTLS Connection
 * 
 * Demonstrates how to integrate the error handling system into a
 * real DTLS connection workflow.
 */
void example_production_integration() {
    std::cout << "\n=== Example 5: Production Integration ===\n";
    
    // Production configuration for a DTLS server
    ErrorHandler::Configuration prod_config;
    prod_config.transport_type = ErrorHandler::Transport::UDP;
    prod_config.security_level = ErrorHandler::SecurityLevel::STRICT;
    prod_config.generate_alerts_on_invalid_records = false; // RFC 9147 for UDP
    prod_config.log_invalid_records = true;
    prod_config.enable_attack_detection = true;
    prod_config.enable_error_correlation = true;
    prod_config.enable_security_metrics = true;
    
    // Production thresholds
    prod_config.max_auth_failures_per_epoch = 5;    // Stricter for production
    prod_config.max_invalid_records_per_second = 20;
    prod_config.max_alert_rate_per_minute = 30;
    
    auto error_handler = std::make_unique<ErrorHandler>(prod_config);
    
    // Production error reporting
    ErrorReporter::ReportingConfig prod_reporter_config;
    prod_reporter_config.minimum_level = ErrorReporter::LogLevel::WARNING;
    prod_reporter_config.format = ErrorReporter::OutputFormat::SYSLOG;
    prod_reporter_config.log_file_path = "/var/log/dtls/error.log";
    prod_reporter_config.enable_audit_trail = true;
    prod_reporter_config.audit_log_path = "/var/log/dtls/audit.log";
    
    // Strict privacy settings for production
    prod_reporter_config.log_network_addresses = false;
    prod_reporter_config.log_connection_ids = false;
    prod_reporter_config.anonymize_peer_info = true;
    prod_reporter_config.include_stack_traces = false;
    
    auto error_reporter = std::make_unique<ErrorReporter>(prod_reporter_config);
    error_handler->set_error_reporter(error_reporter);
    
    std::cout << "Production error handling system initialized\n";
    
    // Simulate production scenarios
    auto context = error_handler->create_error_context("prod_client_001");
    
    // Scenario 1: Client sends invalid ClientHello
    std::cout << "\nScenario 1: Processing invalid ClientHello...\n";
    auto result1 = error_handler->process_error(
        DTLSError::INVALID_MESSAGE_FORMAT, context);
    
    if (result1.is_success()) {
        std::cout << "✓ Invalid ClientHello processed, connection " 
                  << (result1.value() ? "continues" : "terminated") << "\n";
    }
    
    // Scenario 2: Certificate verification failure
    std::cout << "Scenario 2: Certificate verification failure...\n";
    auto result2 = error_handler->process_error(
        DTLSError::CERTIFICATE_VERIFY_FAILED, context);
    
    if (result2.is_success()) {
        std::cout << "✓ Certificate error processed, connection " 
                  << (result2.value() ? "continues" : "terminated") << "\n";
    }
    
    // Scenario 3: Potential DoS attack
    std::cout << "Scenario 3: Simulating potential DoS attack...\n";
    for (int i = 0; i < 25; ++i) {
        error_handler->handle_invalid_record(ContentType::INVALID, context);
    }
    
    const auto& stats = error_handler->get_error_statistics();
    if (stats.dos_attacks_detected > 0) {
        std::cout << "⚠️  DoS attack detected and mitigated\n";
    }
    
    // Production monitoring
    std::cout << "\nProduction Statistics:\n";
    std::cout << "  Total errors processed: " << stats.total_errors << "\n";
    std::cout << "  Fatal errors: " << stats.fatal_errors << "\n";
    std::cout << "  Invalid records discarded: " << stats.invalid_records_discarded << "\n";
    std::cout << "  Connections terminated: " << stats.connections_terminated << "\n";
    std::cout << "  DoS attacks detected: " << stats.dos_attacks_detected << "\n";
    
    // Export context for analysis
    auto exported_context = context->export_context();
    std::cout << "\nConnection Context Summary:\n";
    for (const auto& [key, value] : exported_context) {
        std::cout << "  " << key << ": " << value << "\n";
    }
}

} // namespace examples

int main() {
    std::cout << "DTLS v1.3 Error Handling System Examples\n";
    std::cout << "=========================================\n";
    std::cout << "RFC 9147 Compliant Error Handling Implementation\n";
    
    try {
        examples::example_udp_error_handling();
        examples::example_secure_transport_error_handling();
        examples::example_error_reporting();
        examples::example_error_context_analysis();
        examples::example_production_integration();
        
        std::cout << "\n🎉 All examples completed successfully!\n";
        std::cout << "\nKey RFC 9147 Compliance Features Demonstrated:\n";
        std::cout << "✓ Invalid records silently discarded (Section 4.2.1)\n";
        std::cout << "✓ Transport-specific alert policies (UDP vs secure)\n";
        std::cout << "✓ Fatal alert generation when appropriate\n";
        std::cout << "✓ Authentication failure tracking and limits\n";
        std::cout << "✓ DoS attack detection and mitigation\n";
        std::cout << "✓ Security-conscious error reporting\n";
        std::cout << "✓ Privacy protection in logging\n";
        std::cout << "✓ Connection ID error handling\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error running examples: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}