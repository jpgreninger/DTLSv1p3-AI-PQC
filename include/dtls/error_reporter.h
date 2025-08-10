#ifndef DTLS_ERROR_REPORTER_H
#define DTLS_ERROR_REPORTER_H

#include <dtls/config.h>
#include <dtls/error.h>
#include <dtls/result.h>
#include <dtls/types.h>
#include <dtls/error_context.h>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <functional>
#include <fstream>
#include <sstream>
#include <atomic>
#include <mutex>

namespace dtls {
namespace v13 {

/**
 * ErrorReporter provides secure diagnostic and logging capabilities
 * that maintain RFC 9147 compliance and security requirements:
 * 
 * 1. Never log sensitive cryptographic material (keys, plaintext, etc.)
 * 2. Optionally anonymize network addresses for privacy
 * 3. Provide structured logging for security analysis
 * 4. Support multiple output formats (JSON, syslog, custom)
 * 5. Rate limiting to prevent log flooding attacks
 * 6. Secure log rotation and retention policies
 */
class DTLS_API ErrorReporter {
public:
    enum class LogLevel {
        DEBUG,      // Detailed diagnostic information
        INFO,       // General operational information
        WARNING,    // Warning conditions, non-fatal errors
        ERROR,      // Error conditions, recoverable
        CRITICAL,   // Critical errors, may affect service
        SECURITY    // Security-relevant events, always logged
    };
    
    enum class OutputFormat {
        HUMAN_READABLE,  // Human-friendly text format
        JSON,            // Structured JSON format
        SYSLOG,          // Standard syslog format
        STRUCTURED,      // Custom structured format
        CSV              // CSV format for analysis tools
    };
    
    enum class SensitivityLevel {
        PUBLIC,          // Safe to log without restrictions
        INTERNAL,        // Internal use only, no sensitive data
        CONFIDENTIAL,    // May contain business-sensitive information
        RESTRICTED       // Contains security-sensitive information
    };
    
    struct ReportingConfig {
        LogLevel minimum_level = LogLevel::WARNING;
        OutputFormat format = OutputFormat::HUMAN_READABLE;
        SensitivityLevel max_sensitivity = SensitivityLevel::INTERNAL;
        
        // Privacy and security settings
        bool log_network_addresses = false;         // Privacy consideration
        bool log_connection_ids = false;            // May be sensitive
        bool log_message_contents = false;          // Generally should be false
        bool anonymize_peer_info = true;           // Hash instead of log directly
        bool include_stack_traces = false;         // May leak sensitive info
        
        // Rate limiting and resource protection
        uint32_t max_reports_per_second = 100;
        uint32_t max_reports_per_minute = 1000;
        size_t max_log_entry_size = 4096;
        size_t max_total_log_size = 100 * 1024 * 1024; // 100MB
        
        // Log rotation and retention
        std::chrono::hours log_retention_hours{24 * 7}; // 7 days default
        size_t max_log_files = 10;
        bool auto_rotate_logs = true;
        
        // Output configuration
        std::string log_file_path;                 // Empty = stdout
        std::string log_file_prefix = "dtls_error";
        bool use_utc_timestamps = true;
        bool include_microseconds = true;
        
        // Security audit trail
        bool enable_audit_trail = true;
        std::string audit_log_path;               // Separate audit log
        bool sign_audit_entries = false;         // Cryptographic signatures
        
        // Integration hooks
        std::string syslog_facility = "daemon";
        std::string syslog_identity = "dtls";
    };
    
    struct ErrorReport {
        LogLevel level;
        DTLSError error_code;
        std::string category;                     // e.g., "handshake", "crypto"
        std::string message;                      // Non-sensitive description
        std::chrono::system_clock::time_point timestamp;
        SensitivityLevel sensitivity;
        
        // Context information (privacy-filtered)
        std::string connection_context;          // Hashed or anonymized
        std::string thread_id;
        std::string component;                   // Which component reported
        
        // Structured data for analysis
        std::unordered_map<std::string, std::string> metadata;
        std::vector<std::string> tags;          // Searchable tags
        
        // Security context
        bool is_security_incident;
        double threat_confidence;               // 0.0 to 1.0
        std::string attack_vector;             // If applicable
        
        // Performance context
        std::optional<std::chrono::microseconds> operation_duration;
        std::optional<size_t> bytes_processed;
        
        ErrorReport(LogLevel lvl, DTLSError error, const std::string& msg)
            : level(lvl)
            , error_code(error)
            , message(msg)
            , timestamp(std::chrono::system_clock::now())
            , sensitivity(SensitivityLevel::INTERNAL)
            , is_security_incident(false)
            , threat_confidence(0.0) {}
    };
    
    // Custom reporter callback type
    using ReporterCallback = std::function<void(const ErrorReport&)>;
    
    ErrorReporter();
    explicit ErrorReporter(const ReportingConfig& config);
    ~ErrorReporter();
    
    // Non-copyable but moveable
    ErrorReporter(const ErrorReporter&) = delete;
    ErrorReporter& operator=(const ErrorReporter&) = delete;
    ErrorReporter(ErrorReporter&&) = default;
    ErrorReporter& operator=(ErrorReporter&&) = default;
    
    // Primary reporting interface
    
    /**
     * Report an error with full context
     * @param level Log level for the report
     * @param error DTLS error code
     * @param category Error category
     * @param message Descriptive message (no sensitive data)
     * @param context Error context for additional information
     * @return Result of report operation
     */
    Result<void> report_error(LogLevel level,
                             DTLSError error,
                             const std::string& category,
                             const std::string& message,
                             std::shared_ptr<ErrorContext> context = nullptr);
    
    /**
     * Report security incident with enhanced tracking
     * @param error DTLS error code
     * @param incident_type Type of security incident
     * @param confidence Confidence level (0.0 to 1.0)
     * @param context Error context
     * @return Result of report operation
     */
    Result<void> report_security_incident(DTLSError error,
                                         const std::string& incident_type,
                                         double confidence,
                                         std::shared_ptr<ErrorContext> context = nullptr);
    
    /**
     * Report performance issue
     * @param error DTLS error code
     * @param operation_name Name of slow operation
     * @param duration Time taken
     * @param context Error context
     * @return Result of report operation
     */
    Result<void> report_performance_issue(DTLSError error,
                                         const std::string& operation_name,
                                         std::chrono::microseconds duration,
                                         std::shared_ptr<ErrorContext> context = nullptr);
    
    // Structured logging interface
    
    /**
     * Create report builder for complex reports
     * @param level Log level
     * @param error DTLS error code
     * @return Report builder instance
     */
    class ReportBuilder; // Forward declaration
    ReportBuilder create_report(LogLevel level, DTLSError error);
    
    /**
     * Submit pre-built error report
     * @param report Complete error report
     * @return Result of report operation
     */
    Result<void> submit_report(const ErrorReport& report);
    
    // Configuration and management
    
    /**
     * Update reporting configuration
     * @param config New configuration
     * @return Result of configuration update
     */
    Result<void> update_configuration(const ReportingConfig& config);
    
    /**
     * Get current configuration
     * @return Current reporting configuration
     */
    const ReportingConfig& get_configuration() const { return config_; }
    
    /**
     * Add custom reporter callback
     * @param callback Custom reporting function
     */
    void add_reporter_callback(ReporterCallback callback);
    
    /**
     * Remove all custom reporter callbacks
     */
    void clear_reporter_callbacks();
    
    // Log management
    
    /**
     * Rotate log files manually
     * @return Result of rotation operation
     */
    Result<void> rotate_logs();
    
    /**
     * Clean up old log files according to retention policy
     * @return Number of files cleaned up
     */
    size_t cleanup_old_logs();
    
    /**
     * Flush all pending log entries
     * @return Result of flush operation
     */
    Result<void> flush_logs();
    
    // Statistics and monitoring
    
    struct ReportingStatistics {
        std::atomic<uint64_t> total_reports{0};
        std::atomic<uint64_t> reports_by_level[6]{0}; // One for each LogLevel
        std::atomic<uint64_t> security_incidents{0};
        std::atomic<uint64_t> rate_limited_reports{0};
        std::atomic<uint64_t> failed_reports{0};
        std::atomic<uint64_t> bytes_logged{0};
        std::chrono::steady_clock::time_point start_time;
    };
    
    /**
     * Get reporting statistics
     * @return Current statistics
     */
    const ReportingStatistics& get_statistics() const { return stats_; }
    
    /**
     * Reset reporting statistics
     */
    void reset_statistics();
    
    // Utility functions
    
    /**
     * Convert log level to string
     * @param level Log level to convert
     * @return String representation
     */
    static std::string log_level_to_string(LogLevel level);
    
    /**
     * Convert DTLS error to safe description
     * @param error DTLS error code
     * @return Safe, non-sensitive error description
     */
    static std::string error_to_safe_description(DTLSError error);
    
    /**
     * Create anonymized connection identifier
     * @param connection_id Original connection ID
     * @return Hashed/anonymized identifier
     */
    static std::string anonymize_connection_id(const std::string& connection_id);

private:
    ReportingConfig config_;
    mutable std::mutex config_mutex_;
    
    // Output streams and files
    std::unique_ptr<std::ofstream> log_file_;
    std::unique_ptr<std::ofstream> audit_file_;
    mutable std::mutex output_mutex_;
    
    // Custom reporters
    std::vector<ReporterCallback> custom_reporters_;
    mutable std::mutex reporters_mutex_;
    
    // Statistics
    mutable ReportingStatistics stats_;
    
    // Rate limiting
    struct RateLimitState {
        std::atomic<uint32_t> reports_this_second{0};
        std::atomic<uint32_t> reports_this_minute{0};
        std::chrono::steady_clock::time_point second_start;
        std::chrono::steady_clock::time_point minute_start;
        std::mutex reset_mutex;
    };
    mutable RateLimitState rate_limit_;
    
    // Internal methods
    Result<void> write_report(const ErrorReport& report);
    std::string format_report(const ErrorReport& report) const;
    std::string format_timestamp(const std::chrono::system_clock::time_point& timestamp) const;
    bool is_rate_limited();
    void update_rate_counters();
    Result<void> ensure_log_files();
    std::string filter_sensitive_data(const std::string& input) const;
    void update_statistics(const ErrorReport& report);
    Result<void> write_audit_entry(const ErrorReport& report);
};

/**
 * ReportBuilder provides fluent interface for constructing detailed error reports
 */
class DTLS_API ErrorReporter::ReportBuilder {
public:
    ReportBuilder(ErrorReporter& reporter, LogLevel level, DTLSError error);
    
    ReportBuilder& category(const std::string& cat);
    ReportBuilder& message(const std::string& msg);
    ReportBuilder& sensitivity(SensitivityLevel level);
    ReportBuilder& context(std::shared_ptr<ErrorContext> ctx);
    ReportBuilder& metadata(const std::string& key, const std::string& value);
    ReportBuilder& tag(const std::string& tag);
    ReportBuilder& security_incident(bool is_incident = true);
    ReportBuilder& threat_confidence(double confidence);
    ReportBuilder& attack_vector(const std::string& vector);
    ReportBuilder& performance_context(std::chrono::microseconds duration, 
                                     std::optional<size_t> bytes = std::nullopt);
    ReportBuilder& component(const std::string& comp);
    
    /**
     * Build and submit the error report
     * @return Result of report submission
     */
    Result<void> submit();

private:
    ErrorReporter& reporter_;
    ErrorReport report_;
};

// Convenience macros for common reporting patterns
#define DTLS_REPORT_ERROR(reporter, level, error, message) \
    do { \
        if (reporter) { \
            (reporter)->report_error((level), (error), __FUNCTION__, (message)); \
        } \
    } while(0)

#define DTLS_REPORT_SECURITY(reporter, error, incident_type, confidence) \
    do { \
        if (reporter) { \
            (reporter)->report_security_incident((error), (incident_type), (confidence)); \
        } \
    } while(0)

#define DTLS_REPORT_DEBUG(reporter, error, message) \
    DTLS_REPORT_ERROR(reporter, dtls::v13::ErrorReporter::LogLevel::DEBUG, error, message)

#define DTLS_REPORT_WARNING(reporter, error, message) \
    DTLS_REPORT_ERROR(reporter, dtls::v13::ErrorReporter::LogLevel::WARNING, error, message)

} // namespace v13
} // namespace dtls

#endif // DTLS_ERROR_REPORTER_H