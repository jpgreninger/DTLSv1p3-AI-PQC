#ifndef DTLS_ERROR_HANDLER_H
#define DTLS_ERROR_HANDLER_H

#include <dtls/config.h>
#include <dtls/error.h>
#include <dtls/result.h>
#include <dtls/types.h>
#include <memory>
#include <functional>
#include <chrono>
#include <string>
#include <atomic>
#include <mutex>

namespace dtls {
namespace v13 {

// Forward declarations
class ErrorContext;
class AlertManager;
class ErrorReporter;

/**
 * RFC 9147 Error Handling Consistency
 * 
 * This class provides centralized error handling that ensures consistency
 * across all DTLS protocol layers according to RFC 9147 requirements:
 * 
 * 1. Invalid records SHOULD be silently discarded
 * 2. Error MAY be logged for diagnostic purposes
 * 3. Fatal alerts MUST be generated to prevent probing attacks
 * 4. For UDP transports, generating fatal alerts is NOT RECOMMENDED (DoS risk)
 * 5. Security-conscious error handling that doesn't leak sensitive information
 */
class DTLS_API ErrorHandler {
public:
    enum class Transport {
        UDP,              // Susceptible to spoofing - avoid alerts
        DTLS_OVER_SCTP,   // SCTP-AUTH provides security - alerts safer
        DTLS_OVER_TCP,    // Reliable transport - alerts safer
        CUSTOM            // User-defined transport security
    };
    
    enum class SecurityLevel {
        MINIMAL,    // Basic error handling, minimal logging
        STANDARD,   // RFC 9147 compliant handling
        STRICT,     // Enhanced security with detailed monitoring
        PARANOID    // Maximum security, extensive validation
    };
    
    struct Configuration {
        Transport transport_type = Transport::UDP;
        SecurityLevel security_level = SecurityLevel::STANDARD;
        
        // Alert generation policy
        bool generate_alerts_on_invalid_records = false;  // RFC 9147 recommends false for UDP
        bool log_invalid_records = true;                  // For diagnostics
        
        // DoS protection thresholds
        uint32_t max_auth_failures_per_epoch = 10;       // Per RFC 9147
        uint32_t max_invalid_records_per_second = 100;
        uint32_t max_alert_rate_per_minute = 60;
        
        // Error context retention
        std::chrono::seconds error_context_lifetime{300}; // 5 minutes
        size_t max_error_contexts = 1000;
        
        // Security monitoring
        bool enable_attack_detection = true;
        bool enable_error_correlation = true;
        bool enable_security_metrics = true;
        
        // Logging configuration  
        bool log_sensitive_data = false;  // Never log keys, plaintext, etc.
        bool log_network_addresses = false; // Privacy consideration
        uint32_t max_log_message_length = 512;
    };

    ErrorHandler();
    explicit ErrorHandler(const Configuration& config);
    ~ErrorHandler();
    
    // Non-copyable but moveable
    ErrorHandler(const ErrorHandler&) = delete;
    ErrorHandler& operator=(const ErrorHandler&) = delete;
    ErrorHandler(ErrorHandler&&) = default;
    ErrorHandler& operator=(ErrorHandler&&) = default;
    
    // Core error processing functions
    
    /**
     * Process a DTLS error according to RFC 9147 requirements
     * @param error The error that occurred
     * @param context Additional error context (optional)
     * @return Result indicating if connection should continue or terminate
     */
    Result<bool> process_error(DTLSError error, 
                              std::shared_ptr<ErrorContext> context = nullptr);
    
    /**
     * Handle invalid record according to RFC 9147 Section 4.2.1
     * "In general, invalid records SHOULD be silently discarded"
     * @param record_type The type of invalid record
     * @param context Error context for diagnostics
     * @return Result indicating action taken
     */
    Result<void> handle_invalid_record(ContentType record_type,
                                      std::shared_ptr<ErrorContext> context);
    
    /**
     * Process authentication failure with DoS protection
     * RFC 9147: "track records that fail authentication"
     * @param epoch The epoch of the failed record
     * @param context Error context
     * @return Result indicating if connection should be closed
     */
    Result<bool> handle_authentication_failure(Epoch epoch,
                                              std::shared_ptr<ErrorContext> context);
    
    /**
     * Generate alert if appropriate based on transport and security policy
     * @param alert_desc The alert to potentially generate
     * @param context Error context
     * @return Result containing alert data if alert should be sent
     */
    Result<std::vector<uint8_t>> generate_alert_if_appropriate(
        AlertDescription alert_desc,
        std::shared_ptr<ErrorContext> context);
    
    /**
     * Check if error should terminate the connection
     * @param error The error to evaluate  
     * @return true if connection should terminate
     */
    bool should_terminate_connection(DTLSError error) const;
    
    /**
     * Check if operation should be retried
     * @param error The error that occurred
     * @param retry_count Current retry attempt
     * @return true if retry is recommended
     */
    bool should_retry_operation(DTLSError error, uint32_t retry_count) const;
    
    // Error context management
    
    /**
     * Create error context for tracking error details
     * @param connection_id Optional connection identifier
     * @param endpoint_address Optional peer address
     * @return Shared pointer to error context
     */
    std::shared_ptr<ErrorContext> create_error_context(
        const std::string& connection_id = "",
        const NetworkAddress& endpoint_address = NetworkAddress{});
    
    /**
     * Associate error context with current thread (for async operations)
     * @param context Error context to associate
     */
    void set_thread_error_context(std::shared_ptr<ErrorContext> context);
    
    /**
     * Get error context for current thread
     * @return Current thread's error context or nullptr
     */
    std::shared_ptr<ErrorContext> get_thread_error_context() const;
    
    // Configuration and monitoring
    
    /**
     * Update error handler configuration
     * @param config New configuration
     * @return Result of configuration update
     */
    Result<void> update_configuration(const Configuration& config);
    
    /**
     * Get current configuration
     * @return Current error handler configuration
     */
    const Configuration& get_configuration() const { return config_; }
    
    /**
     * Get error statistics for monitoring
     * @return Error statistics structure
     */
    struct ErrorStats {
        std::atomic<uint64_t> total_errors{0};
        std::atomic<uint64_t> fatal_errors{0};
        std::atomic<uint64_t> retryable_errors{0};
        std::atomic<uint64_t> invalid_records_discarded{0};
        std::atomic<uint64_t> authentication_failures{0};
        std::atomic<uint64_t> alerts_generated{0};
        std::atomic<uint64_t> connections_terminated{0};
        std::atomic<uint64_t> dos_attacks_detected{0};
        std::chrono::steady_clock::time_point start_time;
    };
    
    const ErrorStats& get_error_statistics() const { return stats_; }
    
    /**
     * Reset error statistics
     */
    void reset_statistics();
    
    // Alert management integration
    
    /**
     * Set alert manager for alert processing
     * @param alert_manager Shared pointer to alert manager
     */
    void set_alert_manager(std::shared_ptr<AlertManager> alert_manager);
    
    /**
     * Set error reporter for logging and diagnostics  
     * @param error_reporter Shared pointer to error reporter
     */
    void set_error_reporter(std::shared_ptr<ErrorReporter> error_reporter);

private:
    Configuration config_;
    mutable std::mutex config_mutex_;
    
    // Component integration
    std::shared_ptr<AlertManager> alert_manager_;
    std::shared_ptr<ErrorReporter> error_reporter_;
    
    // Statistics and monitoring
    mutable ErrorStats stats_;
    
    // DoS protection state
    struct DoSState {
        std::atomic<uint32_t> auth_failures_this_epoch{0};
        std::atomic<uint32_t> invalid_records_this_second{0};
        std::atomic<uint32_t> alerts_this_minute{0};
        std::chrono::steady_clock::time_point last_second_reset;
        std::chrono::steady_clock::time_point last_minute_reset;
        std::mutex reset_mutex;
    };
    mutable DoSState dos_state_;
    
    // Error context storage
    mutable std::mutex context_mutex_;
    std::unordered_map<std::string, std::weak_ptr<ErrorContext>> error_contexts_;
    
    // Thread-local error context
    static thread_local std::weak_ptr<ErrorContext> thread_error_context_;
    
    // Internal helper methods
    bool is_transport_secure() const;
    bool should_generate_alert_for_error(DTLSError error) const;
    bool is_security_relevant_error(DTLSError error) const;
    void update_dos_counters();
    void cleanup_expired_contexts();
    Result<void> log_error_securely(DTLSError error, 
                                   std::shared_ptr<ErrorContext> context);
};

} // namespace v13
} // namespace dtls

#endif // DTLS_ERROR_HANDLER_H