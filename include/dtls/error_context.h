#ifndef DTLS_ERROR_CONTEXT_H
#define DTLS_ERROR_CONTEXT_H

#include <dtls/config.h>
#include <dtls/error.h>
#include <dtls/types.h>
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <atomic>
#include <mutex>

namespace dtls {
namespace v13 {

/**
 * ErrorContext provides detailed context information for error tracking
 * and diagnostics while maintaining security and privacy requirements.
 * 
 * This class enables:
 * 1. Secure error correlation and pattern detection
 * 2. DoS attack detection through error rate monitoring
 * 3. Diagnostic information collection without sensitive data leakage
 * 4. Per-connection error state tracking
 * 5. Audit trail for security analysis
 */
class DTLS_API ErrorContext {
public:
    struct ErrorEvent {
        DTLSError error_code;
        std::chrono::steady_clock::time_point timestamp;
        std::string category;           // e.g., "handshake", "record", "crypto"
        std::string description;        // Non-sensitive description
        uint32_t sequence_number;       // For ordering events
        bool is_fatal;
        bool is_security_relevant;
        
        // Network context (if logging enabled)
        bool has_network_context;
        std::string source_address_hash; // Hash instead of actual address
        uint16_t source_port;            // Port numbers are less sensitive
        
        ErrorEvent(DTLSError error, const std::string& cat, const std::string& desc)
            : error_code(error)
            , timestamp(std::chrono::steady_clock::now())
            , category(cat)
            , description(desc)
            , sequence_number(0)
            , is_fatal(false)
            , is_security_relevant(false)
            , has_network_context(false)
            , source_port(0) {}
    };
    
    struct ConnectionInfo {
        std::string connection_id_hash;  // Hashed connection ID for privacy
        ConnectionState current_state;
        Epoch current_epoch;
        std::chrono::steady_clock::time_point connection_start;
        std::atomic<uint64_t> total_errors{0};
        std::atomic<uint64_t> fatal_errors{0};
        std::atomic<uint64_t> security_errors{0};
    };
    
    struct SecurityMetrics {
        std::atomic<uint32_t> authentication_failures{0};
        std::atomic<uint32_t> record_integrity_failures{0};
        std::atomic<uint32_t> replay_detections{0};
        std::atomic<uint32_t> tampering_detections{0};
        std::atomic<uint32_t> suspicious_patterns{0};
        std::chrono::steady_clock::time_point first_security_event;
        std::chrono::steady_clock::time_point last_security_event;
    };
    
    explicit ErrorContext(const std::string& connection_id = "",
                         const NetworkAddress& peer_address = NetworkAddress{});
    
    ~ErrorContext() = default;
    
    // Non-copyable but moveable
    ErrorContext(const ErrorContext&) = delete;
    ErrorContext& operator=(const ErrorContext&) = delete;
    ErrorContext(ErrorContext&&) = default;
    ErrorContext& operator=(ErrorContext&&) = default;
    
    // Error event recording
    
    /**
     * Record an error event with context
     * @param error The error that occurred
     * @param category Error category (handshake, record, crypto, etc.)
     * @param description Non-sensitive description
     * @param is_security_relevant Whether this error has security implications
     * @return Sequence number of the recorded event
     */
    uint32_t record_error(DTLSError error,
                         const std::string& category,
                         const std::string& description,
                         bool is_security_relevant = false);
    
    /**
     * Record a security-relevant error with enhanced tracking
     * @param error The security error
     * @param attack_type Type of potential attack (replay, tamper, etc.)
     * @param confidence Confidence level (0.0 to 1.0)
     * @return Sequence number of the recorded event
     */
    uint32_t record_security_error(DTLSError error,
                                  const std::string& attack_type,
                                  double confidence);
    
    /**
     * Update connection state context
     * @param state New connection state
     * @param epoch New epoch (optional)
     */
    void update_connection_state(ConnectionState state, 
                                std::optional<Epoch> epoch = std::nullopt);
    
    /**
     * Add network context if address logging is enabled
     * @param address Peer network address
     * @param is_logging_enabled Whether to actually record the address
     */
    void set_network_context(const NetworkAddress& address, 
                           bool is_logging_enabled = false);
    
    // Error pattern analysis
    
    /**
     * Check if error rate exceeds threshold for potential DoS
     * @param time_window Time window to check
     * @param max_errors Maximum errors allowed in window
     * @return true if threshold exceeded
     */
    bool is_error_rate_excessive(std::chrono::seconds time_window,
                                uint32_t max_errors) const;
    
    /**
     * Detect suspicious error patterns that might indicate attacks
     * @return Confidence score (0.0 to 1.0) of attack likelihood
     */
    double detect_attack_patterns() const;
    
    /**
     * Get recent errors within time window
     * @param time_window Time window to search
     * @return Vector of recent error events
     */
    std::vector<ErrorEvent> get_recent_errors(
        std::chrono::seconds time_window) const;
    
    /**
     * Get errors by category
     * @param category Error category to filter by
     * @param max_events Maximum events to return (0 = all)
     * @return Vector of matching error events
     */
    std::vector<ErrorEvent> get_errors_by_category(
        const std::string& category,
        size_t max_events = 0) const;
    
    // Context information access
    
    /**
     * Get connection information
     * @return Current connection info
     */
    const ConnectionInfo& get_connection_info() const { return connection_info_; }
    
    /**
     * Get security metrics
     * @return Current security metrics
     */
    const SecurityMetrics& get_security_metrics() const { return security_metrics_; }
    
    /**
     * Get total error count
     * @return Total number of errors recorded
     */
    uint64_t get_total_error_count() const;
    
    /**
     * Get error count by severity
     * @param fatal_only If true, return only fatal error count
     * @return Error count
     */
    uint64_t get_error_count(bool fatal_only = false) const;
    
    /**
     * Check if context has security-relevant errors
     * @return true if security errors have been recorded
     */
    bool has_security_errors() const;
    
    /**
     * Get context age since creation
     * @return Duration since context creation
     */
    std::chrono::seconds get_context_age() const;
    
    // Context management
    
    /**
     * Clear all error history (for privacy/memory management)
     * @param keep_connection_info Whether to preserve connection info
     */
    void clear_history(bool keep_connection_info = true);
    
    /**
     * Export context for audit/analysis (without sensitive data)
     * @return JSON-serializable map of context data
     */
    std::unordered_map<std::string, std::string> export_context() const;
    
    /**
     * Generate secure hash of context for correlation
     * @return SHA-256 hash of context (hex encoded)
     */
    std::string generate_context_hash() const;
    
    /**
     * Check if context should be expired
     * @param max_age Maximum age before expiration
     * @param max_events Maximum events before expiration
     * @return true if context should be expired
     */
    bool should_expire(std::chrono::seconds max_age, 
                      size_t max_events) const;

private:
    mutable std::mutex mutex_;
    
    // Core identification
    std::string context_id_;
    std::chrono::steady_clock::time_point creation_time_;
    std::atomic<uint32_t> next_sequence_number_{1};
    
    // Error event storage
    std::vector<ErrorEvent> error_events_;
    size_t max_events_;  // Configurable limit to prevent unbounded growth
    
    // Connection and security tracking
    ConnectionInfo connection_info_;
    SecurityMetrics security_metrics_;
    
    // Network context (hashed for privacy)
    bool has_network_context_;
    std::string peer_address_hash_;
    uint16_t peer_port_;
    
    // Helper methods
    void update_security_metrics(DTLSError error);
    void cleanup_old_events();
    std::string hash_string(const std::string& input) const;
    void ensure_event_limit();
    double calculate_attack_confidence() const;
};

/**
 * ErrorContextManager manages multiple error contexts and provides
 * system-wide error correlation and analysis capabilities
 */
class DTLS_API ErrorContextManager {
public:
    struct GlobalMetrics {
        std::atomic<uint64_t> total_contexts{0};
        std::atomic<uint64_t> active_contexts{0};
        std::atomic<uint64_t> expired_contexts{0};
        std::atomic<uint64_t> security_incidents{0};
        std::atomic<uint64_t> dos_attempts_detected{0};
        std::chrono::steady_clock::time_point start_time;
    };
    
    ErrorContextManager();
    ~ErrorContextManager();
    
    /**
     * Create new error context
     * @param connection_id Connection identifier
     * @param peer_address Peer network address
     * @return Shared pointer to error context
     */
    std::shared_ptr<ErrorContext> create_context(
        const std::string& connection_id,
        const NetworkAddress& peer_address = NetworkAddress{});
    
    /**
     * Get existing error context
     * @param connection_id Connection identifier
     * @return Shared pointer to error context or nullptr if not found
     */
    std::shared_ptr<ErrorContext> get_context(const std::string& connection_id);
    
    /**
     * Remove error context
     * @param connection_id Connection identifier
     */
    void remove_context(const std::string& connection_id);
    
    /**
     * Perform system-wide attack correlation analysis
     * @return Vector of potentially coordinated attacks
     */
    std::vector<std::string> analyze_coordinated_attacks();
    
    /**
     * Clean up expired contexts
     * @param max_age Maximum context age
     * @param max_events Maximum events per context
     * @return Number of contexts cleaned up
     */
    size_t cleanup_expired_contexts(std::chrono::seconds max_age,
                                   size_t max_events);
    
    /**
     * Get global error metrics
     * @return Global metrics structure
     */
    const GlobalMetrics& get_global_metrics() const { return global_metrics_; }

private:
    mutable std::mutex contexts_mutex_;
    std::unordered_map<std::string, std::weak_ptr<ErrorContext>> contexts_;
    GlobalMetrics global_metrics_;
    
    void update_global_metrics();
};

} // namespace v13
} // namespace dtls

#endif // DTLS_ERROR_CONTEXT_H