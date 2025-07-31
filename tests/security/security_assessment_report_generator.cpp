#include "security_validation_suite.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace dtls {
namespace v13 {
namespace test {

/**
 * Security Assessment Report Generator Implementation
 * 
 * Generates comprehensive security assessment reports in multiple formats
 * including JSON, HTML, and plain text for security validation results.
 */

void SecurityValidationSuite::generate_security_assessment_report() {
    std::cout << "\n=== Generating Security Assessment Report ===" << std::endl;
    
    // Create output directory if it doesn't exist
    std::string output_dir = config_.report_output_directory;
    
    // Generate timestamp for report
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream timestamp_ss;
    timestamp_ss << std::put_time(std::localtime(&time_t_now), "%Y%m%d_%H%M%S");
    std::string timestamp = timestamp_ss.str();
    
    // Generate reports in multiple formats
    generate_json_report(output_dir, timestamp);
    generate_html_report(output_dir, timestamp);
    generate_text_report(output_dir, timestamp);
    
    std::cout << "Security assessment reports generated in: " << output_dir << std::endl;
}

void SecurityValidationSuite::generate_json_report(const std::string& output_dir, const std::string& timestamp) {
    std::string filename = output_dir + "security_assessment_" + timestamp + ".json";
    std::ofstream json_file(filename);
    
    if (!json_file.is_open()) {
        std::cerr << "Failed to create JSON report file: " << filename << std::endl;
        return;
    }
    
    json_file << "{\n";
    json_file << "  \"security_assessment_report\": {\n";
    json_file << "    \"metadata\": {\n";
    json_file << "      \"test_suite\": \"DTLS v1.3 Security Validation Suite\",\n";
    json_file << "      \"version\": \"1.0\",\n";
    json_file << "      \"timestamp\": \"" << timestamp << "\",\n";
    json_file << "      \"test_duration_ms\": " << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - test_start_time_).count() << ",\n";
    json_file << "      \"rfc_compliance\": \"RFC 9147 - DTLS v1.3\"\n";
    json_file << "    },\n";
    
    // Security metrics
    json_file << "    \"security_metrics\": {\n";
    json_file << "      \"total_security_events\": " << security_metrics_.total_security_events << ",\n";
    json_file << "      \"critical_events\": " << security_metrics_.critical_events << ",\n";
    json_file << "      \"replay_attacks_detected\": " << security_metrics_.replay_attacks_detected << ",\n";
    json_file << "      \"authentication_failures\": " << security_metrics_.authentication_failures << ",\n";
    json_file << "      \"protocol_violations\": " << security_metrics_.protocol_violations << ",\n";
    json_file << "      \"malformed_messages_detected\": " << security_metrics_.malformed_messages_detected << ",\n";
    json_file << "      \"dos_attempts_blocked\": " << security_metrics_.dos_attempts_blocked << ",\n";
    json_file << "      \"timing_attacks_suspected\": " << security_metrics_.timing_attacks_suspected << ",\n";
    json_file << "      \"side_channel_anomalies\": " << security_metrics_.side_channel_anomalies << ",\n";
    json_file << "      \"buffer_overflow_attempts\": " << security_metrics_.buffer_overflow_attempts << ",\n";
    json_file << "      \"memory_leaks_detected\": " << security_metrics_.memory_leaks_detected << ",\n";
    json_file << "      \"crypto_failures\": " << security_metrics_.crypto_failures << ",\n";
    json_file << "      \"constant_time_violations\": " << security_metrics_.constant_time_violations << ",\n";
    json_file << "      \"attack_scenarios_executed\": " << security_metrics_.attack_scenarios_executed << ",\n";
    json_file << "      \"fuzzing_iterations_completed\": " << security_metrics_.fuzzing_iterations_completed << ",\n";
    json_file << "      \"max_memory_usage_bytes\": " << security_metrics_.max_memory_usage << "\n";
    json_file << "    },\n";
    
    // Timing analysis
    if (!security_metrics_.handshake_timings.empty()) {
        auto min_time = *std::min_element(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end());
        auto max_time = *std::max_element(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end());
        auto total_time = std::accumulate(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end(),
                                        std::chrono::microseconds{0});
        auto avg_time = total_time / security_metrics_.handshake_timings.size();
        
        json_file << "    \"timing_analysis\": {\n";
        json_file << "      \"handshake_timings\": {\n";
        json_file << "        \"min_microseconds\": " << min_time.count() << ",\n";
        json_file << "        \"max_microseconds\": " << max_time.count() << ",\n";
        json_file << "        \"avg_microseconds\": " << avg_time.count() << ",\n";
        json_file << "        \"sample_count\": " << security_metrics_.handshake_timings.size() << "\n";
        json_file << "      }\n";
        json_file << "    },\n";
    }
    
    // Security events
    json_file << "    \"security_events\": [\n";
    for (size_t i = 0; i < security_events_.size(); ++i) {
        const auto& event = security_events_[i];
        json_file << "      {\n";
        json_file << "        \"type\": " << static_cast<uint32_t>(event.type) << ",\n";
        json_file << "        \"severity\": " << static_cast<uint32_t>(event.severity) << ",\n";
        json_file << "        \"description\": \"" << event.description << "\",\n";
        json_file << "        \"connection_id\": " << event.connection_id << ",\n";
        json_file << "        \"timestamp_ms\": " << std::chrono::duration_cast<std::chrono::milliseconds>(
            event.timestamp.time_since_epoch()).count() << "\n";
        json_file << "      }";
        if (i < security_events_.size() - 1) json_file << ",";
        json_file << "\n";
    }
    json_file << "    ],\n";
    
    // Assessment summary
    bool overall_pass = calculate_overall_security_assessment();
    json_file << "    \"assessment_summary\": {\n";
    json_file << "      \"overall_result\": \"" << (overall_pass ? "PASS" : "FAIL") << "\",\n";
    json_file << "      \"security_level\": \"" << get_security_level_assessment() << "\",\n";
    json_file << "      \"recommendations\": [\n";
    
    auto recommendations = generate_security_recommendations();
    for (size_t i = 0; i < recommendations.size(); ++i) {
        json_file << "        \"" << recommendations[i] << "\"";
        if (i < recommendations.size() - 1) json_file << ",";
        json_file << "\n";
    }
    
    json_file << "      ],\n";
    json_file << "      \"compliance_status\": {\n";
    json_file << "        \"rfc_9147_compliant\": " << (security_metrics_.crypto_failures == 0 ? "true" : "false") << ",\n";
    json_file << "        \"security_requirements_met\": " << (security_metrics_.critical_events == 0 ? "true" : "false") << ",\n";
    json_file << "        \"production_ready\": " << (overall_pass ? "true" : "false") << "\n";
    json_file << "      }\n";
    json_file << "    }\n";
    json_file << "  }\n";
    json_file << "}\n";
    
    json_file.close();
    std::cout << "JSON report generated: " << filename << std::endl;
}

void SecurityValidationSuite::generate_html_report(const std::string& output_dir, const std::string& timestamp) {
    std::string filename = output_dir + "security_assessment_" + timestamp + ".html";
    std::ofstream html_file(filename);
    
    if (!html_file.is_open()) {
        std::cerr << "Failed to create HTML report file: " << filename << std::endl;
        return;
    }
    
    html_file << "<!DOCTYPE html>\n";
    html_file << "<html lang=\"en\">\n";
    html_file << "<head>\n";
    html_file << "    <meta charset=\"UTF-8\">\n";
    html_file << "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html_file << "    <title>DTLS v1.3 Security Assessment Report</title>\n";
    html_file << "    <style>\n";
    html_file << "        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }\n";
    html_file << "        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n";
    html_file << "        h1 { color: #333; border-bottom: 3px solid #007acc; padding-bottom: 10px; }\n";
    html_file << "        h2 { color: #555; border-bottom: 1px solid #ddd; padding-bottom: 5px; }\n";
    html_file << "        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }\n";
    html_file << "        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc; }\n";
    html_file << "        .metric-value { font-size: 24px; font-weight: bold; color: #007acc; }\n";
    html_file << "        .status-pass { color: #28a745; font-weight: bold; }\n";
    html_file << "        .status-fail { color: #dc3545; font-weight: bold; }\n";
    html_file << "        .status-warning { color: #ffc107; font-weight: bold; }\n";
    html_file << "        table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n";
    html_file << "        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n";
    html_file << "        th { background-color: #f8f9fa; font-weight: bold; }\n";
    html_file << "        .summary-box { background: #e9f4ff; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #007acc; }\n";
    html_file << "        .recommendation { background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; border-left: 3px solid #ffc107; }\n";
    html_file << "    </style>\n";
    html_file << "</head>\n";
    html_file << "<body>\n";
    html_file << "    <div class=\"container\">\n";
    
    // Header
    html_file << "        <h1>DTLS v1.3 Security Assessment Report</h1>\n";
    html_file << "        <p><strong>Generated:</strong> " << timestamp << "</p>\n";
    html_file << "        <p><strong>Test Suite:</strong> Comprehensive Security Validation Suite</p>\n";
    html_file << "        <p><strong>RFC Compliance:</strong> RFC 9147 - DTLS v1.3</p>\n";
    
    // Overall assessment
    bool overall_pass = calculate_overall_security_assessment();
    std::string security_level = get_security_level_assessment();
    
    html_file << "        <div class=\"summary-box\">\n";
    html_file << "            <h2>Overall Assessment</h2>\n";
    html_file << "            <p><strong>Result:</strong> <span class=\"" 
              << (overall_pass ? "status-pass" : "status-fail") << "\">" 
              << (overall_pass ? "PASS" : "FAIL") << "</span></p>\n";
    html_file << "            <p><strong>Security Level:</strong> <span class=\"status-pass\">" << security_level << "</span></p>\n";
    html_file << "            <p><strong>RFC 9147 Compliance:</strong> <span class=\"" 
              << (security_metrics_.crypto_failures == 0 ? "status-pass" : "status-fail") << "\">" 
              << (security_metrics_.crypto_failures == 0 ? "COMPLIANT" : "NON-COMPLIANT") << "</span></p>\n";
    html_file << "        </div>\n";
    
    // Security metrics
    html_file << "        <h2>Security Metrics</h2>\n";
    html_file << "        <div class=\"metric-grid\">\n";
    
    html_file << "            <div class=\"metric-card\">\n";
    html_file << "                <div class=\"metric-value\">" << security_metrics_.total_security_events << "</div>\n";
    html_file << "                <div>Total Security Events</div>\n";
    html_file << "            </div>\n";
    
    html_file << "            <div class=\"metric-card\">\n";
    html_file << "                <div class=\"metric-value\">" << security_metrics_.critical_events << "</div>\n";
    html_file << "                <div>Critical Events</div>\n";
    html_file << "            </div>\n";
    
    html_file << "            <div class=\"metric-card\">\n";
    html_file << "                <div class=\"metric-value\">" << security_metrics_.attack_scenarios_executed << "</div>\n";
    html_file << "                <div>Attack Scenarios Tested</div>\n";
    html_file << "            </div>\n";
    
    html_file << "            <div class=\"metric-card\">\n";
    html_file << "                <div class=\"metric-value\">" << security_metrics_.fuzzing_iterations_completed << "</div>\n";
    html_file << "                <div>Fuzzing Iterations</div>\n";
    html_file << "            </div>\n";
    
    html_file << "            <div class=\"metric-card\">\n";
    html_file << "                <div class=\"metric-value\">" << security_metrics_.replay_attacks_detected << "</div>\n";
    html_file << "                <div>Replay Attacks Detected</div>\n";
    html_file << "            </div>\n";
    
    html_file << "            <div class=\"metric-card\">\n";
    html_file << "                <div class=\"metric-value\">" << security_metrics_.dos_attempts_blocked << "</div>\n";
    html_file << "                <div>DoS Attempts Blocked</div>\n";
    html_file << "            </div>\n";
    
    html_file << "        </div>\n";
    
    // Test results table
    html_file << "        <h2>Test Results Summary</h2>\n";
    html_file << "        <table>\n";
    html_file << "            <tr><th>Test Category</th><th>Status</th><th>Details</th></tr>\n";
    
    html_file << "            <tr><td>Attack Simulation</td><td><span class=\"" 
              << (security_metrics_.attack_scenarios_executed > 0 ? "status-pass" : "status-fail") << "\">"
              << (security_metrics_.attack_scenarios_executed > 0 ? "PASS" : "FAIL") << "</span></td>"
              << "<td>" << security_metrics_.attack_scenarios_executed << " scenarios executed</td></tr>\n";
    
    html_file << "            <tr><td>Fuzzing Tests</td><td><span class=\"" 
              << (security_metrics_.fuzzing_iterations_completed >= 1000 ? "status-pass" : "status-fail") << "\">"
              << (security_metrics_.fuzzing_iterations_completed >= 1000 ? "PASS" : "FAIL") << "</span></td>"
              << "<td>" << security_metrics_.fuzzing_iterations_completed << " iterations completed</td></tr>\n";
    
    html_file << "            <tr><td>Memory Safety</td><td><span class=\"" 
              << (security_metrics_.memory_leaks_detected == 0 ? "status-pass" : "status-fail") << "\">"
              << (security_metrics_.memory_leaks_detected == 0 ? "PASS" : "FAIL") << "</span></td>"
              << "<td>" << security_metrics_.memory_leaks_detected << " leaks detected</td></tr>\n";
    
    html_file << "            <tr><td>Cryptographic Compliance</td><td><span class=\"" 
              << (security_metrics_.crypto_failures == 0 ? "status-pass" : "status-fail") << "\">"
              << (security_metrics_.crypto_failures == 0 ? "PASS" : "FAIL") << "</span></td>"
              << "<td>" << security_metrics_.crypto_failures << " failures detected</td></tr>\n";
    
    html_file << "            <tr><td>Timing Attack Resistance</td><td><span class=\"" 
              << (security_metrics_.timing_attacks_suspected <= 1 ? "status-pass" : "status-warning") << "\">"
              << (security_metrics_.timing_attacks_suspected <= 1 ? "PASS" : "WARNING") << "</span></td>"
              << "<td>" << security_metrics_.timing_attacks_suspected << " potential vulnerabilities</td></tr>\n";
    
    html_file << "        </table>\n";
    
    // Recommendations
    auto recommendations = generate_security_recommendations();
    if (!recommendations.empty()) {
        html_file << "        <h2>Security Recommendations</h2>\n";
        for (const auto& rec : recommendations) {
            html_file << "        <div class=\"recommendation\">" << rec << "</div>\n";
        }
    }
    
    // Timing analysis
    if (!security_metrics_.handshake_timings.empty()) {
        auto min_time = *std::min_element(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end());
        auto max_time = *std::max_element(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end());
        auto total_time = std::accumulate(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end(),
                                        std::chrono::microseconds{0});
        auto avg_time = total_time / security_metrics_.handshake_timings.size();
        
        html_file << "        <h2>Timing Analysis</h2>\n";
        html_file << "        <table>\n";
        html_file << "            <tr><th>Metric</th><th>Value (μs)</th></tr>\n";
        html_file << "            <tr><td>Minimum Handshake Time</td><td>" << min_time.count() << "</td></tr>\n";
        html_file << "            <tr><td>Maximum Handshake Time</td><td>" << max_time.count() << "</td></tr>\n";
        html_file << "            <tr><td>Average Handshake Time</td><td>" << avg_time.count() << "</td></tr>\n";
        html_file << "            <tr><td>Sample Count</td><td>" << security_metrics_.handshake_timings.size() << "</td></tr>\n";
        html_file << "        </table>\n";
    }
    
    html_file << "    </div>\n";
    html_file << "</body>\n";
    html_file << "</html>\n";
    
    html_file.close();
    std::cout << "HTML report generated: " << filename << std::endl;
}

void SecurityValidationSuite::generate_text_report(const std::string& output_dir, const std::string& timestamp) {
    std::string filename = output_dir + "security_assessment_" + timestamp + ".txt";
    std::ofstream text_file(filename);
    
    if (!text_file.is_open()) {
        std::cerr << "Failed to create text report file: " << filename << std::endl;
        return;
    }
    
    text_file << "========================================\n";
    text_file << "DTLS v1.3 SECURITY ASSESSMENT REPORT\n";
    text_file << "========================================\n\n";
    
    text_file << "Generated: " << timestamp << "\n";
    text_file << "Test Suite: Comprehensive Security Validation Suite\n";
    text_file << "RFC Compliance: RFC 9147 - DTLS v1.3\n";
    text_file << "Test Duration: " << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - test_start_time_).count() << " ms\n\n";
    
    // Overall assessment
    bool overall_pass = calculate_overall_security_assessment();
    std::string security_level = get_security_level_assessment();
    
    text_file << "OVERALL ASSESSMENT\n";
    text_file << "==================\n";
    text_file << "Result: " << (overall_pass ? "PASS" : "FAIL") << "\n";
    text_file << "Security Level: " << security_level << "\n";
    text_file << "RFC 9147 Compliance: " << (security_metrics_.crypto_failures == 0 ? "COMPLIANT" : "NON-COMPLIANT") << "\n";
    text_file << "Production Ready: " << (overall_pass ? "YES" : "NO") << "\n\n";
    
    // Security metrics
    text_file << "SECURITY METRICS\n";
    text_file << "================\n";
    text_file << "Total Security Events: " << security_metrics_.total_security_events << "\n";
    text_file << "Critical Events: " << security_metrics_.critical_events << "\n";
    text_file << "Attack Scenarios Executed: " << security_metrics_.attack_scenarios_executed << "\n";
    text_file << "Fuzzing Iterations Completed: " << security_metrics_.fuzzing_iterations_completed << "\n";
    text_file << "Replay Attacks Detected: " << security_metrics_.replay_attacks_detected << "\n";
    text_file << "Authentication Failures: " << security_metrics_.authentication_failures << "\n";
    text_file << "Protocol Violations: " << security_metrics_.protocol_violations << "\n";
    text_file << "Malformed Messages Detected: " << security_metrics_.malformed_messages_detected << "\n";
    text_file << "DoS Attempts Blocked: " << security_metrics_.dos_attempts_blocked << "\n";
    text_file << "Timing Attacks Suspected: " << security_metrics_.timing_attacks_suspected << "\n";
    text_file << "Side-Channel Anomalies: " << security_metrics_.side_channel_anomalies << "\n";
    text_file << "Buffer Overflow Attempts: " << security_metrics_.buffer_overflow_attempts << "\n";
    text_file << "Memory Leaks Detected: " << security_metrics_.memory_leaks_detected << "\n";
    text_file << "Crypto Compliance Failures: " << security_metrics_.crypto_failures << "\n";
    text_file << "Constant-Time Violations: " << security_metrics_.constant_time_violations << "\n";
    text_file << "Max Memory Usage: " << (security_metrics_.max_memory_usage / 1024 / 1024) << " MB\n\n";
    
    // Test results
    text_file << "TEST RESULTS SUMMARY\n";
    text_file << "====================\n";
    text_file << "Attack Simulation: " << (security_metrics_.attack_scenarios_executed > 0 ? "PASS" : "FAIL") << "\n";
    text_file << "Fuzzing Tests: " << (security_metrics_.fuzzing_iterations_completed >= 1000 ? "PASS" : "FAIL") << "\n";
    text_file << "Memory Safety: " << (security_metrics_.memory_leaks_detected == 0 ? "PASS" : "FAIL") << "\n";
    text_file << "Cryptographic Compliance: " << (security_metrics_.crypto_failures == 0 ? "PASS" : "FAIL") << "\n";
    text_file << "Timing Attack Resistance: " << (security_metrics_.timing_attacks_suspected <= 1 ? "PASS" : "WARNING") << "\n";
    text_file << "Side-Channel Resistance: " << (security_metrics_.side_channel_anomalies <= 1 ? "PASS" : "WARNING") << "\n\n";
    
    // Timing analysis
    if (!security_metrics_.handshake_timings.empty()) {
        auto min_time = *std::min_element(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end());
        auto max_time = *std::max_element(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end());
        auto total_time = std::accumulate(security_metrics_.handshake_timings.begin(), 
                                        security_metrics_.handshake_timings.end(),
                                        std::chrono::microseconds{0});
        auto avg_time = total_time / security_metrics_.handshake_timings.size();
        
        text_file << "TIMING ANALYSIS\n";
        text_file << "===============\n";
        text_file << "Handshake Timing Statistics:\n";
        text_file << "  Minimum: " << min_time.count() << " μs\n";
        text_file << "  Maximum: " << max_time.count() << " μs\n";
        text_file << "  Average: " << avg_time.count() << " μs\n";
        text_file << "  Sample Count: " << security_metrics_.handshake_timings.size() << "\n\n";
    }
    
    // Recommendations
    auto recommendations = generate_security_recommendations();
    if (!recommendations.empty()) {
        text_file << "SECURITY RECOMMENDATIONS\n";
        text_file << "=========================\n";
        for (size_t i = 0; i < recommendations.size(); ++i) {
            text_file << (i + 1) << ". " << recommendations[i] << "\n";
        }
        text_file << "\n";
    }
    
    // Security events summary
    if (!security_events_.empty()) {
        text_file << "SECURITY EVENTS SUMMARY\n";
        text_file << "=======================\n";
        
        std::map<SecurityEventType, size_t> event_counts;
        for (const auto& event : security_events_) {
            event_counts[event.type]++;
        }
        
        for (const auto& [type, count] : event_counts) {
            text_file << "Event Type " << static_cast<uint32_t>(type) << ": " << count << " occurrences\n";
        }
        text_file << "\n";
    }
    
    text_file << "========================================\n";
    text_file << "END OF SECURITY ASSESSMENT REPORT\n";
    text_file << "========================================\n";
    
    text_file.close();
    std::cout << "Text report generated: " << filename << std::endl;
}

bool SecurityValidationSuite::calculate_overall_security_assessment() {
    // Define criteria for overall security assessment
    bool no_critical_events = (security_metrics_.critical_events == 0);
    bool no_memory_leaks = (security_metrics_.memory_leaks_detected == 0);
    bool crypto_compliant = (security_metrics_.crypto_failures == 0);
    bool timing_secure = (security_metrics_.timing_attacks_suspected <= 1);
    bool side_channel_secure = (security_metrics_.side_channel_anomalies <= 1);
    bool attacks_tested = (security_metrics_.attack_scenarios_executed > 0);
    bool fuzzing_completed = (security_metrics_.fuzzing_iterations_completed >= 1000);
    bool buffer_overflow_protected = (security_metrics_.buffer_overflow_attempts > 0); // Should have blocked attempts
    
    return no_critical_events && no_memory_leaks && crypto_compliant && 
           timing_secure && side_channel_secure && attacks_tested && 
           fuzzing_completed && buffer_overflow_protected;
}

std::string SecurityValidationSuite::get_security_level_assessment() {
    int security_score = 0;
    
    // Score based on various security factors
    if (security_metrics_.critical_events == 0) security_score += 20;
    if (security_metrics_.memory_leaks_detected == 0) security_score += 15;
    if (security_metrics_.crypto_failures == 0) security_score += 20;
    if (security_metrics_.timing_attacks_suspected == 0) security_score += 15;
    if (security_metrics_.side_channel_anomalies == 0) security_score += 10;
    if (security_metrics_.attack_scenarios_executed >= 5) security_score += 10;
    if (security_metrics_.fuzzing_iterations_completed >= 5000) security_score += 10;
    
    if (security_score >= 90) return "EXCELLENT";
    else if (security_score >= 80) return "GOOD";
    else if (security_score >= 70) return "ACCEPTABLE";
    else if (security_score >= 60) return "NEEDS_IMPROVEMENT";
    else return "POOR";
}

std::vector<std::string> SecurityValidationSuite::generate_security_recommendations() {
    std::vector<std::string> recommendations;
    
    if (security_metrics_.critical_events > 0) {
        recommendations.push_back("CRITICAL: Address all critical security events before production deployment");
    }
    
    if (security_metrics_.memory_leaks_detected > 0) {
        recommendations.push_back("Fix detected memory leaks to prevent resource exhaustion attacks");
    }
    
    if (security_metrics_.crypto_failures > 0) {
        recommendations.push_back("Resolve cryptographic compliance failures to ensure RFC 9147 compliance");
    }
    
    if (security_metrics_.timing_attacks_suspected > 1) {
        recommendations.push_back("Implement constant-time algorithms to prevent timing attacks");
    }
    
    if (security_metrics_.side_channel_anomalies > 1) {
        recommendations.push_back("Review and harden implementations against side-channel attacks");
    }
    
    if (security_metrics_.constant_time_violations > 0) {
        recommendations.push_back("Ensure all cryptographic operations are implemented in constant time");
    }
    
    if (security_metrics_.fuzzing_iterations_completed < 5000) {
        recommendations.push_back("Increase fuzzing test coverage for better input validation testing");
    }
    
    if (security_metrics_.attack_scenarios_executed < 5) {
        recommendations.push_back("Expand attack simulation testing to cover more threat scenarios");
    }
    
    // Always include general recommendations
    recommendations.push_back("Regularly update cryptographic libraries and dependencies");
    recommendations.push_back("Implement comprehensive logging and monitoring in production");
    recommendations.push_back("Conduct periodic security audits and penetration testing");
    recommendations.push_back("Establish incident response procedures for security events");
    
    return recommendations;
}

} // namespace test
} // namespace v13
} // namespace dtls