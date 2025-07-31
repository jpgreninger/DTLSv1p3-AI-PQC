#pragma once

/**
 * @file metrics_system.h
 * @brief Comprehensive metrics and monitoring system for DTLS v1.3
 * 
 * Provides extensive monitoring capabilities including performance metrics,
 * security metrics, connection health, system diagnostics, and alerting.
 */

#include "dtls/types.h"
#include "dtls/error.h"
#include "dtls/result.h"
#include <memory>
#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>
#include <atomic>

namespace dtls {
namespace v13 {
namespace monitoring {

/**
 * @brief Metric types enumeration
 */
enum class MetricType {
    COUNTER,      // Monotonically increasing value
    GAUGE,        // Instantaneous value that can go up or down
    HISTOGRAM,    // Distribution of values with buckets
    SUMMARY,      // Distribution with quantiles
    TIMER         // Time-based measurements
};

/**
 * @brief Metric value variant
 */
struct MetricValue {
    union {
        uint64_t counter_value;
        double gauge_value;
        struct {
            double sum;
            uint64_t count;
            std::vector<uint64_t>* bucket_counts; // For histogram
        } distribution;
        std::chrono::microseconds timer_value;
    };
    MetricType type;
    
    MetricValue() : counter_value(0), type(MetricType::COUNTER) {}
    explicit MetricValue(uint64_t value) : counter_value(value), type(MetricType::COUNTER) {}
    explicit MetricValue(double value) : gauge_value(value), type(MetricType::GAUGE) {}
    explicit MetricValue(std::chrono::microseconds value) : timer_value(value), type(MetricType::TIMER) {}
};

/**
 * @brief Metric metadata
 */
struct MetricMetadata {
    std::string name;
    std::string description;
    std::string unit;
    MetricType type;
    std::unordered_map<std::string, std::string> labels;
    std::chrono::steady_clock::time_point last_updated;
    
    MetricMetadata() = default;
    MetricMetadata(const std::string& name, const std::string& desc, MetricType type)
        : name(name), description(desc), type(type), last_updated(std::chrono::steady_clock::now()) {}
};

/**
 * @brief Performance metrics structure
 */
struct PerformanceMetrics {
    // Connection metrics
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> failed_connections{0};
    std::atomic<uint64_t> connection_timeouts{0};
    
    // Handshake metrics
    std::atomic<uint64_t> handshakes_initiated{0};
    std::atomic<uint64_t> handshakes_completed{0};
    std::atomic<uint64_t> handshakes_failed{0};
    std::atomic<uint64_t> handshake_retransmissions{0};
    
    // Data transfer metrics
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> records_sent{0};
    std::atomic<uint64_t> records_received{0};
    std::atomic<uint64_t> application_data_bytes{0};
    
    // Crypto metrics
    std::atomic<uint64_t> encrypt_operations{0};
    std::atomic<uint64_t> decrypt_operations{0};
    std::atomic<uint64_t> key_derivations{0};
    std::atomic<uint64_t> signature_verifications{0};
    
    // Error metrics
    std::atomic<uint64_t> protocol_errors{0};
    std::atomic<uint64_t> crypto_errors{0};
    std::atomic<uint64_t> network_errors{0};
    std::atomic<uint64_t> memory_errors{0};
    
    // Timing metrics (stored as microseconds)
    std::atomic<uint64_t> avg_handshake_time_us{0};
    std::atomic<uint64_t> avg_encrypt_time_us{0};
    std::atomic<uint64_t> avg_decrypt_time_us{0};
    std::atomic<uint64_t> avg_round_trip_time_us{0};
    
    void reset() {
        total_connections = 0;
        active_connections = 0;
        failed_connections = 0;
        connection_timeouts = 0;
        handshakes_initiated = 0;
        handshakes_completed = 0;
        handshakes_failed = 0;
        handshake_retransmissions = 0;
        bytes_sent = 0;
        bytes_received = 0;
        records_sent = 0;
        records_received = 0;
        application_data_bytes = 0;
        encrypt_operations = 0;
        decrypt_operations = 0;
        key_derivations = 0;
        signature_verifications = 0;
        protocol_errors = 0;
        crypto_errors = 0;
        network_errors = 0;
        memory_errors = 0;
        avg_handshake_time_us = 0;
        avg_encrypt_time_us = 0;
        avg_decrypt_time_us = 0;
        avg_round_trip_time_us = 0;
    }
};

/**
 * @brief Security metrics structure
 */
struct SecurityMetrics {
    // Authentication metrics
    std::atomic<uint64_t> successful_authentications{0};
    std::atomic<uint64_t> failed_authentications{0};
    std::atomic<uint64_t> certificate_validations{0};
    std::atomic<uint64_t> certificate_validation_failures{0};
    
    // Attack detection metrics
    std::atomic<uint64_t> replay_attacks_detected{0};
    std::atomic<uint64_t> tampering_attempts_detected{0};
    std::atomic<uint64_t> dos_attempts_detected{0};
    std::atomic<uint64_t> suspicious_connections{0};
    
    // Cipher suite usage
    std::unordered_map<uint16_t, std::atomic<uint64_t>> cipher_suite_usage;
    std::unordered_map<uint16_t, std::atomic<uint64_t>> protocol_version_usage;
    
    // Key management
    std::atomic<uint64_t> key_updates{0};
    std::atomic<uint64_t> session_resumptions{0};
    std::atomic<uint64_t> early_data_attempts{0};
    std::atomic<uint64_t> early_data_rejections{0};
    
    void reset() {
        successful_authentications = 0;
        failed_authentications = 0;
        certificate_validations = 0;
        certificate_validation_failures = 0;
        replay_attacks_detected = 0;
        tampering_attempts_detected = 0;
        dos_attempts_detected = 0;
        suspicious_connections = 0;
        cipher_suite_usage.clear();
        protocol_version_usage.clear();
        key_updates = 0;
        session_resumptions = 0;
        early_data_attempts = 0;
        early_data_rejections = 0;
    }
};

/**
 * @brief Resource metrics structure
 */
struct ResourceMetrics {
    // Memory metrics
    std::atomic<uint64_t> memory_allocated_bytes{0};
    std::atomic<uint64_t> memory_peak_usage_bytes{0};
    std::atomic<uint64_t> buffer_pool_usage{0};
    std::atomic<uint64_t> memory_allocations{0};
    std::atomic<uint64_t> memory_deallocations{0};
    
    // CPU metrics
    std::atomic<double> cpu_usage_percent{0.0};
    std::atomic<uint64_t> context_switches{0};
    
    // Network metrics
    std::atomic<uint64_t> socket_count{0};
    std::atomic<uint64_t> network_interfaces_used{0};
    std::atomic<uint64_t> bandwidth_utilization_bps{0};
    
    // Thread metrics
    std::atomic<uint32_t> active_threads{0};
    std::atomic<uint32_t> thread_pool_size{0};
    std::atomic<uint64_t> tasks_queued{0};
    std::atomic<uint64_t> tasks_completed{0};
    
    void reset() {
        memory_allocated_bytes = 0;
        memory_peak_usage_bytes = 0;
        buffer_pool_usage = 0;
        memory_allocations = 0;
        memory_deallocations = 0;
        cpu_usage_percent = 0.0;
        context_switches = 0;
        socket_count = 0;
        network_interfaces_used = 0;
        bandwidth_utilization_bps = 0;
        active_threads = 0;
        thread_pool_size = 0;
        tasks_queued = 0;
        tasks_completed = 0;
    }
};

/**
 * @brief Alert severity levels
 */
enum class AlertSeverity {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

/**
 * @brief Alert condition
 */
struct AlertCondition {
    std::string metric_name;
    enum class Operator {
        GREATER_THAN,
        LESS_THAN,
        EQUALS,
        NOT_EQUALS,
        RATE_INCREASE,
        RATE_DECREASE
    } operator_type;
    double threshold_value;
    std::chrono::seconds evaluation_window{60};
    AlertSeverity severity;
    std::string message_template;
    bool enabled = true;
    
    AlertCondition() = default;
    AlertCondition(const std::string& metric, Operator op, double threshold, AlertSeverity sev)
        : metric_name(metric), operator_type(op), threshold_value(threshold), severity(sev) {}
};

/**
 * @brief Alert instance
 */
struct Alert {
    std::string id;
    AlertCondition condition;
    std::chrono::steady_clock::time_point triggered_time;
    std::chrono::steady_clock::time_point resolved_time;
    double actual_value;
    std::string formatted_message;
    bool active = true;
    uint32_t trigger_count = 1;
    
    bool is_active() const { return active; }
    std::chrono::duration<double> get_duration() const {
        auto end_time = active ? std::chrono::steady_clock::now() : resolved_time;
        return end_time - triggered_time;
    }
};

/**
 * @brief Metrics collector interface
 */
class DTLS_API MetricsCollector {
public:
    virtual ~MetricsCollector() = default;

    /**
     * @brief Start metrics collection
     */
    virtual Result<void> start_collection() = 0;

    /**
     * @brief Stop metrics collection
     */
    virtual Result<void> stop_collection() = 0;

    /**
     * @brief Record counter metric
     */
    virtual void record_counter(const std::string& name, uint64_t value = 1,
                               const std::unordered_map<std::string, std::string>& labels = {}) = 0;

    /**
     * @brief Record gauge metric
     */
    virtual void record_gauge(const std::string& name, double value,
                             const std::unordered_map<std::string, std::string>& labels = {}) = 0;

    /**
     * @brief Record timer metric
     */
    virtual void record_timer(const std::string& name, std::chrono::microseconds duration,
                             const std::unordered_map<std::string, std::string>& labels = {}) = 0;

    /**
     * @brief Record histogram value
     */
    virtual void record_histogram(const std::string& name, double value,
                                 const std::unordered_map<std::string, std::string>& labels = {}) = 0;

    /**
     * @brief Get all collected metrics
     */
    virtual std::unordered_map<std::string, MetricValue> get_metrics() const = 0;

    /**
     * @brief Get metric metadata
     */
    virtual std::vector<MetricMetadata> get_metric_metadata() const = 0;

    /**
     * @brief Reset all metrics
     */
    virtual void reset_metrics() = 0;
};

/**
 * @brief Performance monitor
 */
class DTLS_API PerformanceMonitor {
public:
    virtual ~PerformanceMonitor() = default;

    /**
     * @brief Get current performance metrics
     */
    virtual PerformanceMetrics get_performance_metrics() const = 0;

    /**
     * @brief Record connection event
     */
    virtual void record_connection_event(const std::string& event_type,
                                       std::chrono::microseconds duration = std::chrono::microseconds(0)) = 0;

    /**
     * @brief Record handshake event
     */
    virtual void record_handshake_event(const std::string& event_type,
                                      std::chrono::microseconds duration = std::chrono::microseconds(0)) = 0;

    /**
     * @brief Record crypto operation
     */
    virtual void record_crypto_operation(const std::string& operation_type,
                                       std::chrono::microseconds duration = std::chrono::microseconds(0)) = 0;

    /**
     * @brief Record data transfer
     */
    virtual void record_data_transfer(size_t bytes_sent, size_t bytes_received) = 0;

    /**
     * @brief Record error
     */
    virtual void record_error(const std::string& error_type) = 0;

    /**
     * @brief Get performance report
     */
    virtual std::string generate_performance_report() const = 0;

    /**
     * @brief Reset performance metrics
     */
    virtual void reset_performance_metrics() = 0;
};

/**
 * @brief Security monitor
 */
class DTLS_API SecurityMonitor {
public:
    virtual ~SecurityMonitor() = default;

    /**
     * @brief Get current security metrics
     */
    virtual SecurityMetrics get_security_metrics() const = 0;

    /**
     * @brief Record authentication event
     */
    virtual void record_authentication_event(bool successful, const std::string& details = "") = 0;

    /**
     * @brief Record potential security threat
     */
    virtual void record_security_threat(const std::string& threat_type, AlertSeverity severity,
                                      const std::string& source_info = "") = 0;

    /**
     * @brief Record cipher suite usage
     */
    virtual void record_cipher_suite_usage(uint16_t cipher_suite) = 0;

    /**
     * @brief Record protocol version usage
     */
    virtual void record_protocol_version_usage(uint16_t protocol_version) = 0;

    /**
     * @brief Get security report
     */
    virtual std::string generate_security_report() const = 0;

    /**
     * @brief Check for security anomalies
     */
    virtual std::vector<Alert> check_security_anomalies() const = 0;

    /**
     * @brief Reset security metrics
     */
    virtual void reset_security_metrics() = 0;
};

/**
 * @brief Resource monitor
 */
class DTLS_API ResourceMonitor {
public:
    virtual ~ResourceMonitor() = default;

    /**
     * @brief Get current resource metrics
     */
    virtual ResourceMetrics get_resource_metrics() const = 0;

    /**
     * @brief Update memory usage
     */
    virtual void update_memory_usage(size_t allocated_bytes, size_t peak_usage) = 0;

    /**
     * @brief Update CPU usage
     */
    virtual void update_cpu_usage(double cpu_percent) = 0;

    /**
     * @brief Update network usage
     */
    virtual void update_network_usage(uint64_t bandwidth_bps) = 0;

    /**
     * @brief Update thread metrics
     */
    virtual void update_thread_metrics(uint32_t active_threads, uint64_t queued_tasks) = 0;

    /**
     * @brief Get resource report
     */
    virtual std::string generate_resource_report() const = 0;

    /**
     * @brief Check resource limits
     */
    virtual std::vector<Alert> check_resource_limits() const = 0;

    /**
     * @brief Reset resource metrics
     */
    virtual void reset_resource_metrics() = 0;
};

/**
 * @brief Alert manager
 */
class DTLS_API AlertManager {
public:
    virtual ~AlertManager() = default;

    /**
     * @brief Add alert condition
     */
    virtual Result<std::string> add_alert_condition(const AlertCondition& condition) = 0;

    /**
     * @brief Remove alert condition
     */
    virtual Result<void> remove_alert_condition(const std::string& condition_id) = 0;

    /**
     * @brief Update alert condition
     */
    virtual Result<void> update_alert_condition(const std::string& condition_id,
                                               const AlertCondition& condition) = 0;

    /**
     * @brief Evaluate all alert conditions
     */
    virtual std::vector<Alert> evaluate_conditions() = 0;

    /**
     * @brief Get active alerts
     */
    virtual std::vector<Alert> get_active_alerts() const = 0;

    /**
     * @brief Get alert history
     */
    virtual std::vector<Alert> get_alert_history(
        std::chrono::steady_clock::time_point since = std::chrono::steady_clock::time_point::min()) const = 0;

    /**
     * @brief Register alert callback
     */
    virtual void register_alert_callback(
        std::function<void(const Alert&)> on_alert_triggered,
        std::function<void(const Alert&)> on_alert_resolved = nullptr) = 0;

    /**
     * @brief Resolve alert manually
     */
    virtual Result<void> resolve_alert(const std::string& alert_id) = 0;

    /**
     * @brief Clear alert history
     */
    virtual void clear_alert_history() = 0;
};

/**
 * @brief Metrics exporter interface
 */
class DTLS_API MetricsExporter {
public:
    virtual ~MetricsExporter() = default;

    /**
     * @brief Export metrics in Prometheus format
     */
    virtual std::string export_prometheus() const = 0;

    /**
     * @brief Export metrics in JSON format
     */
    virtual std::string export_json() const = 0;

    /**
     * @brief Export metrics in InfluxDB line protocol
     */
    virtual std::string export_influxdb() const = 0;

    /**
     * @brief Export metrics in custom format
     */
    virtual std::string export_custom(const std::string& format_name) const = 0;

    /**
     * @brief Set export configuration
     */
    virtual Result<void> configure_export(const std::unordered_map<std::string, std::string>& config) = 0;
};

/**
 * @brief Comprehensive monitoring system
 */
class DTLS_API MonitoringSystem {
public:
    /**
     * @brief Create monitoring system
     */
    static std::unique_ptr<MonitoringSystem> create();

    virtual ~MonitoringSystem() = default;

    /**
     * @brief Initialize monitoring system
     */
    virtual Result<void> initialize() = 0;

    /**
     * @brief Shutdown monitoring system
     */
    virtual Result<void> shutdown() = 0;

    /**
     * @brief Get metrics collector
     */
    virtual std::shared_ptr<MetricsCollector> get_metrics_collector() = 0;

    /**
     * @brief Get performance monitor
     */
    virtual std::shared_ptr<PerformanceMonitor> get_performance_monitor() = 0;

    /**
     * @brief Get security monitor
     */
    virtual std::shared_ptr<SecurityMonitor> get_security_monitor() = 0;

    /**
     * @brief Get resource monitor
     */
    virtual std::shared_ptr<ResourceMonitor> get_resource_monitor() = 0;

    /**
     * @brief Get alert manager
     */
    virtual std::shared_ptr<AlertManager> get_alert_manager() = 0;

    /**
     * @brief Get metrics exporter
     */
    virtual std::shared_ptr<MetricsExporter> get_metrics_exporter() = 0;

    /**
     * @brief Configure monitoring
     */
    virtual Result<void> configure(const std::unordered_map<std::string, std::string>& config) = 0;

    /**
     * @brief Generate comprehensive monitoring report
     */
    virtual std::string generate_comprehensive_report() const = 0;

    /**
     * @brief Get system health score (0.0 to 1.0)
     */
    virtual double get_system_health_score() const = 0;

    /**
     * @brief Reset all monitoring data
     */
    virtual void reset_all_metrics() = 0;
};

/**
 * @brief Scoped timer for automatic duration measurement
 */
class DTLS_API ScopedTimer {
public:
    ScopedTimer(const std::shared_ptr<MetricsCollector>& collector,
               const std::string& metric_name,
               const std::unordered_map<std::string, std::string>& labels = {});

    ~ScopedTimer();

    /**
     * @brief Get elapsed time
     */
    std::chrono::microseconds get_elapsed() const;

    /**
     * @brief Stop timer manually (before destruction)
     */
    void stop();

private:
    std::shared_ptr<MetricsCollector> collector_;
    std::string metric_name_;
    std::unordered_map<std::string, std::string> labels_;
    std::chrono::steady_clock::time_point start_time_;
    bool stopped_;
};

/**
 * @brief Macro for easy scoped timing
 */
#define DTLS_SCOPED_TIMER(collector, name) \
    dtls::v13::monitoring::ScopedTimer _timer(collector, name)

#define DTLS_SCOPED_TIMER_WITH_LABELS(collector, name, labels) \
    dtls::v13::monitoring::ScopedTimer _timer(collector, name, labels)

} // namespace monitoring
} // namespace v13
} // namespace dtls