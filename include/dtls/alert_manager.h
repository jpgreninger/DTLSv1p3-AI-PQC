#ifndef DTLS_ALERT_MANAGER_H
#define DTLS_ALERT_MANAGER_H

#include <dtls/config.h>
#include <dtls/error.h>
#include <dtls/result.h>
#include <dtls/types.h>
#include <dtls/error_context.h>
#include <vector>
#include <memory>
#include <chrono>
#include <atomic>
#include <mutex>
#include <functional>

namespace dtls {
namespace v13 {

/**
 * AlertManager handles DTLS alert generation and processing according to RFC 9147
 * 
 * Key RFC 9147 requirements:
 * 1. "Invalid records SHOULD be silently discarded"
 * 2. "If alerts are generated, they MUST be fatal alerts to prevent probing attacks"
 * 3. "For UDP transports, generating fatal alerts is NOT RECOMMENDED due to DoS risks"
 * 4. "Alert messages are not retransmitted at all"
 * 5. "Implementations SHOULD detect persistent bad messages and terminate connection"
 * 6. "Alerts are not reliably transmitted; implementations SHOULD NOT depend on them"
 */
class DTLS_API AlertManager {
public:
    enum class TransportSecurity {
        INSECURE,     // UDP or other forgeable transport
        SECURE,       // SCTP with SCTP-AUTH, or other authenticated transport
        UNKNOWN       // Security level unknown
    };
    
    struct AlertPolicy {
        TransportSecurity transport_security = TransportSecurity::INSECURE;
        
        // Alert generation rules per RFC 9147
        bool generate_alerts_for_invalid_records = false;  // NOT RECOMMENDED for UDP
        bool generate_alerts_for_auth_failures = false;    // NOT RECOMMENDED for UDP
        bool generate_alerts_for_protocol_errors = true;   // Generally safe
        
        // Rate limiting to prevent DoS amplification
        uint32_t max_alerts_per_minute = 10;
        uint32_t max_alerts_per_connection = 50;
        
        // Alert reliability (RFC 9147: alerts are not reliably transmitted)
        bool attempt_alert_retransmission = false;  // RFC 9147 says "not retransmitted at all"
        std::chrono::milliseconds alert_timeout{1000};
        
        // Security enhancements
        bool randomize_alert_timing = true;        // Prevent timing attacks
        bool bundle_similar_alerts = true;        // Reduce alert flood
        std::chrono::milliseconds alert_delay_min{10};
        std::chrono::milliseconds alert_delay_max{100};
    };
    
    struct AlertMessage {
        AlertLevel level;
        AlertDescription description;
        std::chrono::steady_clock::time_point timestamp;
        std::string connection_id;
        uint32_t alert_sequence;  // For tracking/deduplication
        bool is_generated_locally;
        
        // Security context
        bool is_security_critical;
        double threat_confidence;  // 0.0 to 1.0
        std::string threat_category;
        
        AlertMessage(AlertLevel lvl, AlertDescription desc, const std::string& conn_id)
            : level(lvl)
            , description(desc)
            , timestamp(std::chrono::steady_clock::now())
            , connection_id(conn_id)
            , alert_sequence(0)
            , is_generated_locally(true)
            , is_security_critical(false)
            , threat_confidence(0.0) {}
    };
    
    // Alert handler callback type
    using AlertHandler = std::function<Result<void>(const AlertMessage&, const std::vector<uint8_t>&)>;
    
    AlertManager();
    explicit AlertManager(const AlertPolicy& policy);
    ~AlertManager();
    
    // Non-copyable but moveable
    AlertManager(const AlertManager&) = delete;
    AlertManager& operator=(const AlertManager&) = delete;
    AlertManager(AlertManager&&) = default;
    AlertManager& operator=(AlertManager&&) = default;
    
    // Alert generation (RFC 9147 compliant)
    
    /**
     * Generate alert for error according to RFC 9147 policy
     * @param error DTLS error that occurred
     * @param context Error context for decision making
     * @return Result containing alert data if alert should be sent
     */
    Result<std::optional<std::vector<uint8_t>>> generate_alert_for_error(
        DTLSError error,
        std::shared_ptr<ErrorContext> context);
    
    /**
     * Generate specific alert with policy enforcement
     * @param level Alert level (WARNING or FATAL)
     * @param description Alert description
     * @param connection_id Connection identifier
     * @param context Error context
     * @return Result containing alert data if alert should be sent
     */
    Result<std::optional<std::vector<uint8_t>>> generate_alert(
        AlertLevel level,
        AlertDescription description,
        const std::string& connection_id,
        std::shared_ptr<ErrorContext> context = nullptr);
    
    /**
     * Handle invalid record according to RFC 9147 Section 4.2.1
     * "In general, invalid records SHOULD be silently discarded"
     * @param record_type Type of invalid record
     * @param connection_id Connection identifier
     * @param context Error context
     * @return Result indicating action taken (usually silent discard)
     */
    Result<void> handle_invalid_record(
        ContentType record_type,
        const std::string& connection_id,
        std::shared_ptr<ErrorContext> context);
    
    /**
     * Process received alert message
     * @param alert_data Raw alert message data
     * @param connection_id Connection identifier
     * @param context Error context
     * @return Result containing parsed alert information
     */
    Result<AlertMessage> process_received_alert(
        const std::vector<uint8_t>& alert_data,
        const std::string& connection_id,
        std::shared_ptr<ErrorContext> context = nullptr);
    
    // Alert policy and configuration
    
    /**
     * Update alert policy
     * @param policy New alert policy
     * @return Result of policy update
     */
    Result<void> update_policy(const AlertPolicy& policy);
    
    /**
     * Get current alert policy
     * @return Current policy configuration
     */
    const AlertPolicy& get_policy() const { return policy_; }
    
    /**
     * Set alert handler for outgoing alerts
     * @param handler Alert handling function
     */
    void set_alert_handler(AlertHandler handler);
    
    // Security and monitoring
    
    /**
     * Check if connection should be terminated due to persistent errors
     * RFC 9147: "Implementations SHOULD detect when a peer is persistently 
     * sending bad messages and terminate the local connection state"
     * @param connection_id Connection to check
     * @param context Error context
     * @return true if connection should be terminated
     */
    bool should_terminate_connection(const std::string& connection_id,
                                   std::shared_ptr<ErrorContext> context);
    
    /**
     * Detect potential DoS attacks through alert patterns
     * @param time_window Time window for analysis
     * @return Confidence score of DoS attack (0.0 to 1.0)
     */
    double detect_dos_attack(std::chrono::minutes time_window = std::chrono::minutes(1));
    
    struct AlertStatistics {
        std::atomic<uint64_t> alerts_generated{0};
        std::atomic<uint64_t> alerts_received{0};
        std::atomic<uint64_t> alerts_suppressed{0};      // Due to rate limiting
        std::atomic<uint64_t> invalid_records_silenced{0}; // Per RFC 9147
        std::atomic<uint64_t> fatal_alerts_generated{0};
        std::atomic<uint64_t> warning_alerts_generated{0};
        std::atomic<uint64_t> connections_terminated{0};
        std::atomic<uint64_t> potential_dos_attempts{0};
        std::chrono::steady_clock::time_point start_time;
    };
    
    /**
     * Get alert statistics
     * @return Current alert statistics
     */
    const AlertStatistics& get_statistics() const { return stats_; }
    
    /**
     * Reset alert statistics
     */
    void reset_statistics();
    
    // Alert serialization/deserialization
    
    /**
     * Serialize alert message to wire format
     * @param level Alert level
     * @param description Alert description
     * @return Serialized alert data
     */
    static std::vector<uint8_t> serialize_alert(AlertLevel level, 
                                               AlertDescription description);
    
    /**
     * Parse alert message from wire format
     * @param alert_data Raw alert data
     * @return Parsed alert level and description
     */
    static Result<std::pair<AlertLevel, AlertDescription>> parse_alert(
        const std::vector<uint8_t>& alert_data);

private:
    AlertPolicy policy_;
    mutable std::mutex policy_mutex_;
    
    AlertHandler alert_handler_;
    std::mutex handler_mutex_;
    
    // Statistics and monitoring
    mutable AlertStatistics stats_;
    
    // Rate limiting state
    struct RateLimitState {
        std::atomic<uint32_t> alerts_this_minute{0};
        std::chrono::steady_clock::time_point minute_start;
        std::mutex reset_mutex;
        
        // Per-connection rate limiting
        std::mutex connection_mutex;
        std::unordered_map<std::string, uint32_t> connection_alert_counts;
    };
    mutable RateLimitState rate_limit_state_;
    
    // Alert deduplication and bundling
    struct AlertBundling {
        std::mutex mutex;
        std::unordered_map<std::string, std::vector<AlertMessage>> pending_alerts;
        std::chrono::steady_clock::time_point last_bundle_time;
    };
    mutable AlertBundling bundling_;
    
    // Internal helper methods
    bool should_generate_alert_for_transport(AlertLevel level) const;
    bool is_rate_limited(const std::string& connection_id);
    void update_rate_limit_counters();
    std::chrono::milliseconds calculate_alert_delay() const;
    Result<void> send_alert_with_handler(const AlertMessage& alert,
                                        const std::vector<uint8_t>& alert_data);
    void update_statistics(const AlertMessage& alert);
    bool is_security_critical_alert(AlertDescription description) const;
    double calculate_threat_confidence(DTLSError error,
                                      std::shared_ptr<ErrorContext> context) const;
};

/**
 * AlertBuilder provides a fluent interface for constructing complex alerts
 * with proper security context and RFC 9147 compliance
 */
class DTLS_API AlertBuilder {
public:
    AlertBuilder(AlertManager& manager, const std::string& connection_id);
    
    AlertBuilder& level(AlertLevel lvl);
    AlertBuilder& description(AlertDescription desc);
    AlertBuilder& error_context(std::shared_ptr<ErrorContext> ctx);
    AlertBuilder& security_critical(bool critical = true);
    AlertBuilder& threat_confidence(double confidence);
    AlertBuilder& threat_category(const std::string& category);
    
    /**
     * Build and potentially send the alert according to policy
     * @return Result containing alert data if alert was generated
     */
    Result<std::optional<std::vector<uint8_t>>> build();

private:
    AlertManager& manager_;
    std::string connection_id_;
    AlertLevel level_ = AlertLevel::FATAL;
    AlertDescription description_ = AlertDescription::INTERNAL_ERROR;
    std::shared_ptr<ErrorContext> context_;
    bool security_critical_ = false;
    double threat_confidence_ = 0.0;
    std::string threat_category_;
};

} // namespace v13
} // namespace dtls

#endif // DTLS_ALERT_MANAGER_H