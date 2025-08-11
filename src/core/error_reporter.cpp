#include <dtls/error_reporter.h>
#include <dtls/error_context.h>
#include <iostream>
#include <chrono>
#include <sstream>

namespace dtls {
namespace v13 {

ErrorReporter::ErrorReporter() : config_{} {
    stats_.start_time = std::chrono::steady_clock::now();
    rate_limit_.second_start = std::chrono::steady_clock::now();
    rate_limit_.minute_start = std::chrono::steady_clock::now();
}

ErrorReporter::ErrorReporter(const ReportingConfig& config) : config_(config) {
    stats_.start_time = std::chrono::steady_clock::now();
    rate_limit_.second_start = std::chrono::steady_clock::now();
    rate_limit_.minute_start = std::chrono::steady_clock::now();
}

ErrorReporter::~ErrorReporter() = default;

Result<void> ErrorReporter::report_error(LogLevel level,
                                        DTLSError error,
                                        const std::string& category,
                                        const std::string& message,
                                        std::shared_ptr<ErrorContext> context) {
    // Check minimum log level
    if (level < config_.minimum_level) {
        return make_result();
    }
    
    // Check rate limits and update counters atomically
    uint32_t max_per_second, max_per_minute;
    {
        // Get config values under lock
        std::lock_guard<std::mutex> config_lock(config_mutex_);
        max_per_second = config_.max_reports_per_second;
        max_per_minute = config_.max_reports_per_minute;
    }
    
    {
        std::lock_guard<std::mutex> lock(rate_limit_.reset_mutex);
        
        auto now = std::chrono::steady_clock::now();
        
        // Reset counters if time window has passed
        if (now - rate_limit_.second_start >= std::chrono::seconds(1)) {
            rate_limit_.reports_this_second = 0;
            rate_limit_.second_start = now;
        }
        
        if (now - rate_limit_.minute_start >= std::chrono::minutes(1)) {
            rate_limit_.reports_this_minute = 0;
            rate_limit_.minute_start = now;
        }
        
        // Check limits BEFORE incrementing
        if (rate_limit_.reports_this_second >= max_per_second ||
            rate_limit_.reports_this_minute >= max_per_minute) {
            stats_.rate_limited_reports++;
            return make_error<void>(DTLSError::RATE_LIMITED);
        }
        
        // Update counters
        rate_limit_.reports_this_second++;
        rate_limit_.reports_this_minute++;
    }
    
    // Create error report
    ErrorReport report(level, error, message);
    report.category = category;
    report.sensitivity = SensitivityLevel::INTERNAL;
    
    // Add context information if available
    if (context) {
        report.connection_context = anonymize_connection_id(
            context->get_connection_info().connection_id_hash);
    }
    
    // Update statistics
    update_statistics(report);
    
    // Write the report
    auto result = write_report(report);
    if (!result.is_success()) {
        stats_.failed_reports++;
        return result;
    }
    
    stats_.total_reports++;
    return make_result();
}

Result<void> ErrorReporter::report_security_incident(DTLSError error,
                                                    const std::string& incident_type,
                                                    double confidence,
                                                    std::shared_ptr<ErrorContext> context) {
    // Security incidents are always logged regardless of rate limits
    ErrorReport report(LogLevel::SECURITY, error, incident_type);
    report.category = "security";
    report.sensitivity = SensitivityLevel::CONFIDENTIAL;
    report.is_security_incident = true;
    report.threat_confidence = confidence;
    report.attack_vector = incident_type;
    
    // Add context information if available
    if (context) {
        report.connection_context = anonymize_connection_id(
            context->get_connection_info().connection_id_hash);
    }
    
    // Update statistics
    update_statistics(report);
    stats_.security_incidents++;
    stats_.total_reports++;
    
    // Write the report
    auto result = write_report(report);
    if (!result.is_success()) {
        stats_.failed_reports++;
        return result;
    }
    
    return make_result();
}

Result<void> ErrorReporter::update_configuration(const ReportingConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    return make_result();
}

std::string ErrorReporter::error_to_safe_description(DTLSError error) {
    // Return safe, non-sensitive descriptions
    switch (error) {
        case DTLSError::SUCCESS: return "Operation completed successfully";
        case DTLSError::DECRYPT_ERROR: return "Decryption operation failed";
        case DTLSError::HANDSHAKE_FAILURE: return "Handshake process failed";
        case DTLSError::CERTIFICATE_VERIFY_FAILED: return "Certificate verification failed";
        case DTLSError::TIMEOUT: return "Operation timed out";
        case DTLSError::CONNECTION_CLOSED: return "Connection was closed";
        case DTLSError::AUTHENTICATION_FAILED: return "Authentication failed";
        case DTLSError::INVALID_PARAMETER: return "Invalid parameter provided";
        default: return "DTLS operation error occurred";
    }
}

std::string ErrorReporter::anonymize_connection_id(const std::string& connection_id) {
    // Simple hash-based anonymization - could be improved with proper crypto
    std::hash<std::string> hasher;
    return std::to_string(hasher(connection_id));
}

// Private method implementations

bool ErrorReporter::is_rate_limited() {
    std::lock_guard<std::mutex> lock(rate_limit_.reset_mutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Reset counters if time window has passed
    if (now - rate_limit_.second_start >= std::chrono::seconds(1)) {
        rate_limit_.reports_this_second = 0;
        rate_limit_.second_start = now;
    }
    
    if (now - rate_limit_.minute_start >= std::chrono::minutes(1)) {
        rate_limit_.reports_this_minute = 0;
        rate_limit_.minute_start = now;
    }
    
    // Check limits (must check BEFORE incrementing counters)
    bool is_limited = (rate_limit_.reports_this_second >= config_.max_reports_per_second) ||
                      (rate_limit_.reports_this_minute >= config_.max_reports_per_minute);
    
    // Debug output for testing
    #ifdef DEBUG_RATE_LIMITING
    if (rate_limit_.reports_this_second >= 3) {
        std::cerr << "[RATE LIMIT DEBUG] reports_this_second=" << rate_limit_.reports_this_second.load()
                  << ", max_per_second=" << config_.max_reports_per_second 
                  << ", is_limited=" << is_limited << std::endl;
    }
    #endif
    
    return is_limited;
}

void ErrorReporter::update_rate_counters() {
    std::lock_guard<std::mutex> lock(rate_limit_.reset_mutex);
    rate_limit_.reports_this_second++;
    rate_limit_.reports_this_minute++;
}

Result<void> ErrorReporter::write_report(const ErrorReport& report) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    // Format and write to stderr for now (could be enhanced with file output)
    std::string formatted = format_report(report);
    std::cerr << formatted << std::endl;
    
    stats_.bytes_logged += formatted.length();
    return make_result();
}

std::string ErrorReporter::format_report(const ErrorReport& report) const {
    std::ostringstream oss;
    
    if (config_.format == OutputFormat::JSON) {
        oss << "{\"level\":\"" << log_level_to_string(report.level) << "\""
            << ",\"error\":" << static_cast<int>(report.error_code)
            << ",\"category\":\"" << report.category << "\""
            << ",\"message\":\"" << report.message << "\"";
        
        if (report.is_security_incident) {
            oss << ",\"security_incident\":true"
                << ",\"threat_confidence\":" << report.threat_confidence
                << ",\"attack_vector\":\"" << report.attack_vector << "\"";
        }
        
        oss << "}";
    } else {
        // Human readable format
        oss << "[" << report.category << "] Error " << static_cast<int>(report.error_code) 
            << ": " << report.message;
        
        if (report.is_security_incident) {
            oss << " (SECURITY: " << report.attack_vector 
                << ", confidence: " << report.threat_confidence << ")";
        }
    }
    
    return oss.str();
}

void ErrorReporter::update_statistics(const ErrorReport& report) {
    // Update level-specific counters
    size_t level_index = static_cast<size_t>(report.level);
    if (level_index < 6) {
        stats_.reports_by_level[level_index]++;
    }
}

std::string ErrorReporter::log_level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        case LogLevel::SECURITY: return "SECURITY";
        default: return "UNKNOWN";
    }
}

} // namespace v13
} // namespace dtls