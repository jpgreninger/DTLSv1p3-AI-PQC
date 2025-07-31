/**
 * @file metrics_system.cpp
 * @brief Implementation of comprehensive metrics and monitoring system
 */

#include "dtls/monitoring/metrics_system.h"
#include "dtls/core/result.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <unordered_set>
#include <queue>

namespace dtls {
namespace v13 {
namespace monitoring {

namespace {

/**
 * @brief Generate unique alert ID
 */
std::string generate_alert_id() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::steady_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    return "alert_" + std::to_string(timestamp) + "_" + std::to_string(counter.fetch_add(1));
}

/**
 * @brief Format duration for human readability
 */
std::string format_duration(std::chrono::microseconds duration) {
    auto us = duration.count();
    if (us < 1000) {
        return std::to_string(us) + "μs";
    } else if (us < 1000000) {
        return std::to_string(us / 1000) + "ms";
    } else {
        return std::to_string(us / 1000000) + "s";
    }
}

/**
 * @brief Format bytes for human readability
 */
std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        unit_index++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit_index];
    return oss.str();
}

} // anonymous namespace

/**
 * @brief Metrics collector implementation
 */
class MetricsCollectorImpl : public MetricsCollector {
private:
    mutable std::mutex metrics_mutex_;
    std::unordered_map<std::string, MetricValue> metrics_;
    std::unordered_map<std::string, MetricMetadata> metadata_;
    std::atomic<bool> collecting_{false};

public:
    Result<void> start_collection() override {
        collecting_.store(true);
        return make_success();
    }

    Result<void> stop_collection() override {
        collecting_.store(false);
        return make_success();
    }

    void record_counter(const std::string& name, uint64_t value,
                       const std::unordered_map<std::string, std::string>& labels) override {
        if (!collecting_.load()) return;

        std::lock_guard<std::mutex> lock(metrics_mutex_);
        std::string full_name = build_metric_name(name, labels);
        
        auto& metric = metrics_[full_name];
        if (metric.type == MetricType::COUNTER) {
            metric.counter_value += value;
        } else {
            metric = MetricValue(value);
        }
        
        // Update metadata
        if (metadata_.find(full_name) == metadata_.end()) {
            metadata_[full_name] = MetricMetadata(full_name, "Counter metric", MetricType::COUNTER);
            metadata_[full_name].labels = labels;
        }
        metadata_[full_name].last_updated = std::chrono::steady_clock::now();
    }

    void record_gauge(const std::string& name, double value,
                     const std::unordered_map<std::string, std::string>& labels) override {
        if (!collecting_.load()) return;

        std::lock_guard<std::mutex> lock(metrics_mutex_);
        std::string full_name = build_metric_name(name, labels);
        
        metrics_[full_name] = MetricValue(value);
        
        // Update metadata
        if (metadata_.find(full_name) == metadata_.end()) {
            metadata_[full_name] = MetricMetadata(full_name, "Gauge metric", MetricType::GAUGE);
            metadata_[full_name].labels = labels;
        }
        metadata_[full_name].last_updated = std::chrono::steady_clock::now();
    }

    void record_timer(const std::string& name, std::chrono::microseconds duration,
                     const std::unordered_map<std::string, std::string>& labels) override {
        if (!collecting_.load()) return;

        std::lock_guard<std::mutex> lock(metrics_mutex_);
        std::string full_name = build_metric_name(name, labels);
        
        metrics_[full_name] = MetricValue(duration);
        
        // Update metadata
        if (metadata_.find(full_name) == metadata_.end()) {
            metadata_[full_name] = MetricMetadata(full_name, "Timer metric", MetricType::TIMER);
            metadata_[full_name].unit = "microseconds";
            metadata_[full_name].labels = labels;
        }
        metadata_[full_name].last_updated = std::chrono::steady_clock::now();
    }

    void record_histogram(const std::string& name, double value,
                         const std::unordered_map<std::string, std::string>& labels) override {
        if (!collecting_.load()) return;

        std::lock_guard<std::mutex> lock(metrics_mutex_);
        std::string full_name = build_metric_name(name, labels);
        
        auto& metric = metrics_[full_name];
        if (metric.type == MetricType::HISTOGRAM) {
            metric.distribution.sum += value;
            metric.distribution.count++;
        } else {
            metric.type = MetricType::HISTOGRAM;
            metric.distribution.sum = value;
            metric.distribution.count = 1;
            metric.distribution.bucket_counts = new std::vector<uint64_t>(10, 0); // 10 buckets
        }
        
        // Update metadata
        if (metadata_.find(full_name) == metadata_.end()) {
            metadata_[full_name] = MetricMetadata(full_name, "Histogram metric", MetricType::HISTOGRAM);
            metadata_[full_name].labels = labels;
        }
        metadata_[full_name].last_updated = std::chrono::steady_clock::now();
    }

    std::unordered_map<std::string, MetricValue> get_metrics() const override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        return metrics_;
    }

    std::vector<MetricMetadata> get_metric_metadata() const override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        std::vector<MetricMetadata> metadata_vec;
        for (const auto& [name, metadata] : metadata_) {
            metadata_vec.push_back(metadata);
        }
        return metadata_vec;
    }

    void reset_metrics() override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        // Clean up histogram bucket pointers
        for (auto& [name, metric] : metrics_) {
            if (metric.type == MetricType::HISTOGRAM && metric.distribution.bucket_counts) {
                delete metric.distribution.bucket_counts;
            }
        }
        metrics_.clear();
        metadata_.clear();
    }

private:
    std::string build_metric_name(const std::string& base_name,
                                 const std::unordered_map<std::string, std::string>& labels) {
        if (labels.empty()) {
            return base_name;
        }
        
        std::string full_name = base_name + "{";
        bool first = true;
        for (const auto& [key, value] : labels) {
            if (!first) full_name += ",";
            full_name += key + "=\"" + value + "\"";
            first = false;
        }
        full_name += "}";
        return full_name;
    }
};

/**
 * @brief Performance monitor implementation
 */
class PerformanceMonitorImpl : public PerformanceMonitor {
private:
    mutable std::mutex metrics_mutex_;
    PerformanceMetrics metrics_;
    std::shared_ptr<MetricsCollector> collector_;

public:
    explicit PerformanceMonitorImpl(const std::shared_ptr<MetricsCollector>& collector)
        : collector_(collector) {}

    PerformanceMetrics get_performance_metrics() const override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        return metrics_;
    }

    void record_connection_event(const std::string& event_type,
                                std::chrono::microseconds duration) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (event_type == "connection_initiated") {
            metrics_.total_connections.fetch_add(1);
            collector_->record_counter("dtls_connections_total", 1, {{"type", "initiated"}});
        } else if (event_type == "connection_established") {
            metrics_.active_connections.fetch_add(1);
            collector_->record_counter("dtls_connections_total", 1, {{"type", "established"}});
            collector_->record_gauge("dtls_active_connections", metrics_.active_connections.load());
        } else if (event_type == "connection_failed") {
            metrics_.failed_connections.fetch_add(1);
            collector_->record_counter("dtls_connections_total", 1, {{"type", "failed"}});
        } else if (event_type == "connection_timeout") {
            metrics_.connection_timeouts.fetch_add(1);
            collector_->record_counter("dtls_connection_timeouts_total", 1);
        } else if (event_type == "connection_closed") {
            if (metrics_.active_connections.load() > 0) {
                metrics_.active_connections.fetch_sub(1);
            }
            collector_->record_gauge("dtls_active_connections", metrics_.active_connections.load());
        }
        
        if (duration.count() > 0) {
            collector_->record_timer("dtls_connection_duration", duration, {{"event", event_type}});
        }
    }

    void record_handshake_event(const std::string& event_type,
                               std::chrono::microseconds duration) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (event_type == "handshake_initiated") {
            metrics_.handshakes_initiated.fetch_add(1);
            collector_->record_counter("dtls_handshakes_total", 1, {{"type", "initiated"}});
        } else if (event_type == "handshake_completed") {
            metrics_.handshakes_completed.fetch_add(1);
            collector_->record_counter("dtls_handshakes_total", 1, {{"type", "completed"}});
            
            if (duration.count() > 0) {
                // Update rolling average
                uint64_t current_avg = metrics_.avg_handshake_time_us.load();
                uint64_t new_avg = (current_avg + duration.count()) / 2;
                metrics_.avg_handshake_time_us.store(new_avg);
                
                collector_->record_timer("dtls_handshake_duration", duration);
            }
        } else if (event_type == "handshake_failed") {
            metrics_.handshakes_failed.fetch_add(1);
            collector_->record_counter("dtls_handshakes_total", 1, {{"type", "failed"}});
        } else if (event_type == "handshake_retransmission") {
            metrics_.handshake_retransmissions.fetch_add(1);
            collector_->record_counter("dtls_handshake_retransmissions_total", 1);
        }
    }

    void record_crypto_operation(const std::string& operation_type,
                                std::chrono::microseconds duration) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (operation_type == "encrypt") {
            metrics_.encrypt_operations.fetch_add(1);
            collector_->record_counter("dtls_crypto_operations_total", 1, {{"type", "encrypt"}});
            
            if (duration.count() > 0) {
                uint64_t current_avg = metrics_.avg_encrypt_time_us.load();
                uint64_t new_avg = (current_avg + duration.count()) / 2;
                metrics_.avg_encrypt_time_us.store(new_avg);
            }
        } else if (operation_type == "decrypt") {
            metrics_.decrypt_operations.fetch_add(1);
            collector_->record_counter("dtls_crypto_operations_total", 1, {{"type", "decrypt"}});
            
            if (duration.count() > 0) {
                uint64_t current_avg = metrics_.avg_decrypt_time_us.load();
                uint64_t new_avg = (current_avg + duration.count()) / 2;
                metrics_.avg_decrypt_time_us.store(new_avg);
            }
        } else if (operation_type == "key_derivation") {
            metrics_.key_derivations.fetch_add(1);
            collector_->record_counter("dtls_crypto_operations_total", 1, {{"type", "key_derivation"}});
        } else if (operation_type == "signature_verification") {
            metrics_.signature_verifications.fetch_add(1);
            collector_->record_counter("dtls_crypto_operations_total", 1, {{"type", "signature_verification"}});
        }
        
        if (duration.count() > 0) {
            collector_->record_timer("dtls_crypto_operation_duration", duration, {{"operation", operation_type}});
        }
    }

    void record_data_transfer(size_t bytes_sent, size_t bytes_received) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (bytes_sent > 0) {
            metrics_.bytes_sent.fetch_add(bytes_sent);
            metrics_.records_sent.fetch_add(1);
            collector_->record_counter("dtls_bytes_total", bytes_sent, {{"direction", "sent"}});
            collector_->record_counter("dtls_records_total", 1, {{"direction", "sent"}});
        }
        
        if (bytes_received > 0) {
            metrics_.bytes_received.fetch_add(bytes_received);
            metrics_.records_received.fetch_add(1);
            collector_->record_counter("dtls_bytes_total", bytes_received, {{"direction", "received"}});
            collector_->record_counter("dtls_records_total", 1, {{"direction", "received"}});
        }
    }

    void record_error(const std::string& error_type) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (error_type == "protocol_error") {
            metrics_.protocol_errors.fetch_add(1);
        } else if (error_type == "crypto_error") {
            metrics_.crypto_errors.fetch_add(1);
        } else if (error_type == "network_error") {
            metrics_.network_errors.fetch_add(1);
        } else if (error_type == "memory_error") {
            metrics_.memory_errors.fetch_add(1);
        }
        
        collector_->record_counter("dtls_errors_total", 1, {{"type", error_type}});
    }

    std::string generate_performance_report() const override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        std::ostringstream report;
        report << "DTLS Performance Report\n";
        report << "======================\n\n";
        
        // Connection metrics
        report << "Connection Metrics:\n";
        report << "  Total Connections: " << metrics_.total_connections.load() << "\n";
        report << "  Active Connections: " << metrics_.active_connections.load() << "\n";
        report << "  Failed Connections: " << metrics_.failed_connections.load() << "\n";
        report << "  Connection Timeouts: " << metrics_.connection_timeouts.load() << "\n\n";
        
        // Handshake metrics
        report << "Handshake Metrics:\n";
        report << "  Handshakes Initiated: " << metrics_.handshakes_initiated.load() << "\n";
        report << "  Handshakes Completed: " << metrics_.handshakes_completed.load() << "\n";
        report << "  Handshakes Failed: " << metrics_.handshakes_failed.load() << "\n";
        report << "  Handshake Retransmissions: " << metrics_.handshake_retransmissions.load() << "\n";
        report << "  Average Handshake Time: " << format_duration(std::chrono::microseconds(metrics_.avg_handshake_time_us.load())) << "\n\n";
        
        // Data transfer metrics
        report << "Data Transfer Metrics:\n";
        report << "  Bytes Sent: " << format_bytes(metrics_.bytes_sent.load()) << "\n";
        report << "  Bytes Received: " << format_bytes(metrics_.bytes_received.load()) << "\n";
        report << "  Records Sent: " << metrics_.records_sent.load() << "\n";
        report << "  Records Received: " << metrics_.records_received.load() << "\n\n";
        
        // Crypto metrics
        report << "Cryptographic Metrics:\n";
        report << "  Encrypt Operations: " << metrics_.encrypt_operations.load() << "\n";
        report << "  Decrypt Operations: " << metrics_.decrypt_operations.load() << "\n";
        report << "  Key Derivations: " << metrics_.key_derivations.load() << "\n";
        report << "  Signature Verifications: " << metrics_.signature_verifications.load() << "\n";
        report << "  Average Encrypt Time: " << format_duration(std::chrono::microseconds(metrics_.avg_encrypt_time_us.load())) << "\n";
        report << "  Average Decrypt Time: " << format_duration(std::chrono::microseconds(metrics_.avg_decrypt_time_us.load())) << "\n\n";
        
        // Error metrics
        report << "Error Metrics:\n";
        report << "  Protocol Errors: " << metrics_.protocol_errors.load() << "\n";
        report << "  Crypto Errors: " << metrics_.crypto_errors.load() << "\n";
        report << "  Network Errors: " << metrics_.network_errors.load() << "\n";
        report << "  Memory Errors: " << metrics_.memory_errors.load() << "\n";
        
        return report.str();
    }

    void reset_performance_metrics() override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_.reset();
    }
};

/**
 * @brief Security monitor implementation
 */
class SecurityMonitorImpl : public SecurityMonitor {
private:
    mutable std::mutex metrics_mutex_;
    SecurityMetrics metrics_;
    std::shared_ptr<MetricsCollector> collector_;

public:
    explicit SecurityMonitorImpl(const std::shared_ptr<MetricsCollector>& collector)
        : collector_(collector) {}

    SecurityMetrics get_security_metrics() const override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        return metrics_;
    }

    void record_authentication_event(bool successful, const std::string& details) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (successful) {
            metrics_.successful_authentications.fetch_add(1);
            collector_->record_counter("dtls_authentications_total", 1, {{"result", "success"}});
        } else {
            metrics_.failed_authentications.fetch_add(1);
            collector_->record_counter("dtls_authentications_total", 1, {{"result", "failure"}});
        }
    }

    void record_security_threat(const std::string& threat_type, AlertSeverity severity,
                               const std::string& source_info) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (threat_type == "replay_attack") {
            metrics_.replay_attacks_detected.fetch_add(1);
        } else if (threat_type == "tampering_attempt") {
            metrics_.tampering_attempts_detected.fetch_add(1);
        } else if (threat_type == "dos_attempt") {
            metrics_.dos_attempts_detected.fetch_add(1);
        } else if (threat_type == "suspicious_connection") {
            metrics_.suspicious_connections.fetch_add(1);
        }
        
        std::string severity_str;
        switch (severity) {
            case AlertSeverity::INFO: severity_str = "info"; break;
            case AlertSeverity::WARNING: severity_str = "warning"; break;
            case AlertSeverity::ERROR: severity_str = "error"; break;
            case AlertSeverity::CRITICAL: severity_str = "critical"; break;
        }
        
        collector_->record_counter("dtls_security_threats_total", 1, 
                                 {{"type", threat_type}, {"severity", severity_str}});
    }

    void record_cipher_suite_usage(uint16_t cipher_suite) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        metrics_.cipher_suite_usage[cipher_suite].fetch_add(1);
        collector_->record_counter("dtls_cipher_suite_usage_total", 1, 
                                 {{"cipher_suite", std::to_string(cipher_suite)}});
    }

    void record_protocol_version_usage(uint16_t protocol_version) override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        metrics_.protocol_version_usage[protocol_version].fetch_add(1);
        collector_->record_counter("dtls_protocol_version_usage_total", 1,
                                 {{"version", std::to_string(protocol_version)}});
    }

    std::string generate_security_report() const override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        std::ostringstream report;
        report << "DTLS Security Report\n";
        report << "====================\n\n";
        
        // Authentication metrics
        report << "Authentication Metrics:\n";
        report << "  Successful Authentications: " << metrics_.successful_authentications.load() << "\n";
        report << "  Failed Authentications: " << metrics_.failed_authentications.load() << "\n";
        
        uint64_t total_auth = metrics_.successful_authentications.load() + metrics_.failed_authentications.load();
        if (total_auth > 0) {
            double success_rate = static_cast<double>(metrics_.successful_authentications.load()) / total_auth * 100.0;
            report << "  Authentication Success Rate: " << std::fixed << std::setprecision(2) << success_rate << "%\n";
        }
        report << "\n";
        
        // Threat detection
        report << "Threat Detection:\n";
        report << "  Replay Attacks Detected: " << metrics_.replay_attacks_detected.load() << "\n";
        report << "  Tampering Attempts Detected: " << metrics_.tampering_attempts_detected.load() << "\n";
        report << "  DoS Attempts Detected: " << metrics_.dos_attempts_detected.load() << "\n";
        report << "  Suspicious Connections: " << metrics_.suspicious_connections.load() << "\n\n";
        
        // Cipher suite usage
        report << "Cipher Suite Usage:\n";
        for (const auto& [suite, count] : metrics_.cipher_suite_usage) {
            report << "  Suite 0x" << std::hex << suite << std::dec << ": " << count.load() << " uses\n";
        }
        report << "\n";
        
        // Protocol version usage
        report << "Protocol Version Usage:\n";
        for (const auto& [version, count] : metrics_.protocol_version_usage) {
            report << "  Version 0x" << std::hex << version << std::dec << ": " << count.load() << " uses\n";
        }
        
        return report.str();
    }

    std::vector<Alert> check_security_anomalies() const override {
        std::vector<Alert> alerts;
        
        // Check for high authentication failure rate
        uint64_t total_auth = metrics_.successful_authentications.load() + metrics_.failed_authentications.load();
        if (total_auth > 100) { // Only check if we have sufficient data
            double failure_rate = static_cast<double>(metrics_.failed_authentications.load()) / total_auth;
            if (failure_rate > 0.1) { // More than 10% failure rate
                Alert alert;
                alert.id = generate_alert_id();
                alert.condition.metric_name = "authentication_failure_rate";
                alert.condition.severity = AlertSeverity::WARNING;
                alert.triggered_time = std::chrono::steady_clock::now();
                alert.actual_value = failure_rate * 100.0;
                alert.formatted_message = "High authentication failure rate: " + 
                                        std::to_string(alert.actual_value) + "%";
                alerts.push_back(alert);
            }
        }
        
        // Check for security threats
        uint64_t total_threats = metrics_.replay_attacks_detected.load() + 
                               metrics_.tampering_attempts_detected.load() + 
                               metrics_.dos_attempts_detected.load();
        if (total_threats > 0) {
            Alert alert;
            alert.id = generate_alert_id();
            alert.condition.metric_name = "security_threats";
            alert.condition.severity = AlertSeverity::ERROR;
            alert.triggered_time = std::chrono::steady_clock::now();
            alert.actual_value = static_cast<double>(total_threats);
            alert.formatted_message = "Security threats detected: " + std::to_string(total_threats) + " incidents";
            alerts.push_back(alert);
        }
        
        return alerts;
    }

    void reset_security_metrics() override {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_.reset();
    }
};

/**
 * @brief Alert manager implementation
 */
class AlertManagerImpl : public AlertManager {
private:
    mutable std::mutex alerts_mutex_;
    std::unordered_map<std::string, AlertCondition> conditions_;
    std::vector<Alert> active_alerts_;
    std::vector<Alert> alert_history_;
    std::vector<std::function<void(const Alert&)>> alert_callbacks_;
    std::vector<std::function<void(const Alert&)>> resolve_callbacks_;
    
    std::shared_ptr<MetricsCollector> collector_;

public:
    explicit AlertManagerImpl(const std::shared_ptr<MetricsCollector>& collector)
        : collector_(collector) {}

    Result<std::string> add_alert_condition(const AlertCondition& condition) override {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        
        std::string condition_id = "condition_" + std::to_string(conditions_.size());
        conditions_[condition_id] = condition;
        
        return make_result(condition_id);
    }

    Result<void> remove_alert_condition(const std::string& condition_id) override {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        
        auto it = conditions_.find(condition_id);
        if (it != conditions_.end()) {
            conditions_.erase(it);
            return make_success();
        }
        
        return make_error_void(DTLSError::INVALID_PARAMETER);
    }

    Result<void> update_alert_condition(const std::string& condition_id,
                                       const AlertCondition& condition) override {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        
        auto it = conditions_.find(condition_id);
        if (it != conditions_.end()) {
            it->second = condition;
            return make_success();
        }
        
        return make_error_void(DTLSError::INVALID_PARAMETER);
    }

    std::vector<Alert> evaluate_conditions() override {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        std::vector<Alert> new_alerts;
        
        auto metrics = collector_->get_metrics();
        
        for (const auto& [condition_id, condition] : conditions_) {
            if (!condition.enabled) continue;
            
            auto metric_it = metrics.find(condition.metric_name);
            if (metric_it == metrics.end()) continue;
            
            double current_value = extract_metric_value(metric_it->second);
            bool should_alert = evaluate_condition(condition, current_value);
            
            if (should_alert) {
                // Check if alert is already active
                auto existing_alert = std::find_if(active_alerts_.begin(), active_alerts_.end(),
                    [&condition_id](const Alert& alert) {
                        return alert.condition.metric_name == condition_id;
                    });
                
                if (existing_alert == active_alerts_.end()) {
                    // Create new alert
                    Alert new_alert;
                    new_alert.id = generate_alert_id();
                    new_alert.condition = condition;
                    new_alert.triggered_time = std::chrono::steady_clock::now();
                    new_alert.actual_value = current_value;
                    new_alert.formatted_message = format_alert_message(condition, current_value);
                    
                    active_alerts_.push_back(new_alert);
                    alert_history_.push_back(new_alert);
                    new_alerts.push_back(new_alert);
                    
                    // Notify callbacks
                    for (const auto& callback : alert_callbacks_) {
                        try {
                            callback(new_alert);
                        } catch (...) {
                            // Ignore callback exceptions
                        }
                    }
                }
            }
        }
        
        return new_alerts;
    }

    std::vector<Alert> get_active_alerts() const override {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        return active_alerts_;
    }

    std::vector<Alert> get_alert_history(
        std::chrono::steady_clock::time_point since) const override {
        
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        
        if (since == std::chrono::steady_clock::time_point::min()) {
            return alert_history_;
        }
        
        std::vector<Alert> filtered_history;
        for (const auto& alert : alert_history_) {
            if (alert.triggered_time >= since) {
                filtered_history.push_back(alert);
            }
        }
        
        return filtered_history;
    }

    void register_alert_callback(
        std::function<void(const Alert&)> on_alert_triggered,
        std::function<void(const Alert&)> on_alert_resolved) override {
        
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        
        if (on_alert_triggered) {
            alert_callbacks_.push_back(std::move(on_alert_triggered));
        }
        if (on_alert_resolved) {
            resolve_callbacks_.push_back(std::move(on_alert_resolved));
        }
    }

    Result<void> resolve_alert(const std::string& alert_id) override {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        
        auto it = std::find_if(active_alerts_.begin(), active_alerts_.end(),
            [&alert_id](Alert& alert) {
                return alert.id == alert_id;
            });
        
        if (it != active_alerts_.end()) {
            it->active = false;
            it->resolved_time = std::chrono::steady_clock::now();
            
            // Notify resolve callbacks
            for (const auto& callback : resolve_callbacks_) {
                try {
                    callback(*it);
                } catch (...) {
                    // Ignore callback exceptions
                }
            }
            
            // Update history
            auto history_it = std::find_if(alert_history_.begin(), alert_history_.end(),
                [&alert_id](Alert& alert) {
                    return alert.id == alert_id;
                });
            if (history_it != alert_history_.end()) {
                *history_it = *it;
            }
            
            active_alerts_.erase(it);
            return make_success();
        }
        
        return make_error_void(DTLSError::INVALID_PARAMETER);
    }

    void clear_alert_history() override {
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        alert_history_.clear();
    }

private:
    double extract_metric_value(const MetricValue& metric) {
        switch (metric.type) {
            case MetricType::COUNTER:
                return static_cast<double>(metric.counter_value);
            case MetricType::GAUGE:
                return metric.gauge_value;
            case MetricType::TIMER:
                return static_cast<double>(metric.timer_value.count());
            case MetricType::HISTOGRAM:
                return metric.distribution.count > 0 ? 
                       metric.distribution.sum / metric.distribution.count : 0.0;
            default:
                return 0.0;
        }
    }

    bool evaluate_condition(const AlertCondition& condition, double current_value) {
        switch (condition.operator_type) {
            case AlertCondition::Operator::GREATER_THAN:
                return current_value > condition.threshold_value;
            case AlertCondition::Operator::LESS_THAN:
                return current_value < condition.threshold_value;
            case AlertCondition::Operator::EQUALS:
                return std::abs(current_value - condition.threshold_value) < 0.001;
            case AlertCondition::Operator::NOT_EQUALS:
                return std::abs(current_value - condition.threshold_value) >= 0.001;
            case AlertCondition::Operator::RATE_INCREASE:
            case AlertCondition::Operator::RATE_DECREASE:
                // TODO: Implement rate-based conditions
                return false;
            default:
                return false;
        }
    }

    std::string format_alert_message(const AlertCondition& condition, double actual_value) {
        if (!condition.message_template.empty()) {
            // TODO: Template variable substitution
            return condition.message_template;
        }
        
        return "Alert: " + condition.metric_name + " value " + std::to_string(actual_value) +
               " exceeds threshold " + std::to_string(condition.threshold_value);
    }
};

/**
 * @brief Metrics exporter implementation
 */
class MetricsExporterImpl : public MetricsExporter {
private:
    std::shared_ptr<MetricsCollector> collector_;
    std::unordered_map<std::string, std::string> export_config_;

public:
    explicit MetricsExporterImpl(const std::shared_ptr<MetricsCollector>& collector)
        : collector_(collector) {}

    std::string export_prometheus() const override {
        auto metrics = collector_->get_metrics();
        auto metadata = collector_->get_metric_metadata();
        
        std::ostringstream output;
        
        for (const auto& meta : metadata) {
            // Add metric help and type comments
            output << "# HELP " << meta.name << " " << meta.description << "\n";
            output << "# TYPE " << meta.name << " ";
            
            switch (meta.type) {
                case MetricType::COUNTER:
                    output << "counter\n";
                    break;
                case MetricType::GAUGE:
                    output << "gauge\n";
                    break;
                case MetricType::HISTOGRAM:
                    output << "histogram\n";
                    break;
                case MetricType::SUMMARY:
                    output << "summary\n";
                    break;
                case MetricType::TIMER:
                    output << "gauge\n";
                    break;
            }
            
            // Add metric value
            auto metric_it = metrics.find(meta.name);
            if (metric_it != metrics.end()) {
                output << meta.name << " ";
                
                switch (metric_it->second.type) {
                    case MetricType::COUNTER:
                        output << metric_it->second.counter_value;
                        break;
                    case MetricType::GAUGE:
                        output << metric_it->second.gauge_value;
                        break;
                    case MetricType::TIMER:
                        output << metric_it->second.timer_value.count();
                        break;
                    case MetricType::HISTOGRAM:
                        output << metric_it->second.distribution.sum;
                        break;
                    default:
                        output << "0";
                        break;
                }
                
                output << " " << std::chrono::duration_cast<std::chrono::milliseconds>(
                    meta.last_updated.time_since_epoch()).count() << "\n";
            }
            
            output << "\n";
        }
        
        return output.str();
    }

    std::string export_json() const override {
        auto metrics = collector_->get_metrics();
        auto metadata = collector_->get_metric_metadata();
        
        std::ostringstream output;
        output << "{\n";
        output << "  \"metrics\": {\n";
        
        bool first = true;
        for (const auto& [name, value] : metrics) {
            if (!first) output << ",\n";
            
            output << "    \"" << name << "\": {";
            output << "\"type\": \"" << static_cast<int>(value.type) << "\", ";
            output << "\"value\": ";
            
            switch (value.type) {
                case MetricType::COUNTER:
                    output << value.counter_value;
                    break;
                case MetricType::GAUGE:
                    output << value.gauge_value;
                    break;
                case MetricType::TIMER:
                    output << value.timer_value.count();
                    break;
                case MetricType::HISTOGRAM:
                    output << value.distribution.sum;
                    break;
                default:
                    output << "0";
                    break;
            }
            
            output << "}";
            first = false;
        }
        
        output << "\n  }\n";
        output << "}\n";
        
        return output.str();
    }

    std::string export_influxdb() const override {
        auto metrics = collector_->get_metrics();
        
        std::ostringstream output;
        auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        for (const auto& [name, value] : metrics) {
            output << "dtls_" << name << " value=";
            
            switch (value.type) {
                case MetricType::COUNTER:
                    output << value.counter_value << "i";
                    break;
                case MetricType::GAUGE:
                    output << value.gauge_value;
                    break;
                case MetricType::TIMER:
                    output << value.timer_value.count() << "i";
                    break;
                case MetricType::HISTOGRAM:
                    output << value.distribution.sum;
                    break;
                default:
                    output << "0";
                    break;
            }
            
            output << " " << now << "\n";
        }
        
        return output.str();
    }

    std::string export_custom(const std::string& format_name) const override {
        // TODO: Implement custom format support
        return export_json();
    }

    Result<void> configure_export(const std::unordered_map<std::string, std::string>& config) override {
        export_config_ = config;
        return make_success();
    }
};

/**
 * @brief Monitoring system implementation
 */
class MonitoringSystemImpl : public MonitoringSystem {
private:
    std::shared_ptr<MetricsCollector> metrics_collector_;
    std::shared_ptr<PerformanceMonitor> performance_monitor_;
    std::shared_ptr<SecurityMonitor> security_monitor_;
    std::shared_ptr<ResourceMonitor> resource_monitor_;
    std::shared_ptr<AlertManager> alert_manager_;
    std::shared_ptr<MetricsExporter> metrics_exporter_;
    
    std::atomic<bool> running_{false};
    std::thread monitoring_thread_;

public:
    MonitoringSystemImpl() {
        metrics_collector_ = std::make_shared<MetricsCollectorImpl>();
        performance_monitor_ = std::make_shared<PerformanceMonitorImpl>(metrics_collector_);
        security_monitor_ = std::make_shared<SecurityMonitorImpl>(metrics_collector_);
        // resource_monitor_ would be implemented similarly
        alert_manager_ = std::make_shared<AlertManagerImpl>(metrics_collector_);
        metrics_exporter_ = std::make_shared<MetricsExporterImpl>(metrics_collector_);
    }

    Result<void> initialize() override {
        auto result = metrics_collector_->start_collection();
        if (!result) return result;
        
        // Add default alert conditions
        add_default_alert_conditions();
        
        // Start monitoring thread
        running_.store(true);
        monitoring_thread_ = std::thread([this]() {
            while (running_.load()) {
                alert_manager_->evaluate_conditions();
                std::this_thread::sleep_for(std::chrono::seconds(10));
            }
        });
        
        return make_success();
    }

    Result<void> shutdown() override {
        running_.store(false);
        
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
        
        return metrics_collector_->stop_collection();
    }

    std::shared_ptr<MetricsCollector> get_metrics_collector() override {
        return metrics_collector_;
    }

    std::shared_ptr<PerformanceMonitor> get_performance_monitor() override {
        return performance_monitor_;
    }

    std::shared_ptr<SecurityMonitor> get_security_monitor() override {
        return security_monitor_;
    }

    std::shared_ptr<ResourceMonitor> get_resource_monitor() override {
        return resource_monitor_;
    }

    std::shared_ptr<AlertManager> get_alert_manager() override {
        return alert_manager_;
    }

    std::shared_ptr<MetricsExporter> get_metrics_exporter() override {
        return metrics_exporter_;
    }

    Result<void> configure(const std::unordered_map<std::string, std::string>& config) override {
        // TODO: Implement configuration
        return make_success();
    }

    std::string generate_comprehensive_report() const override {
        std::ostringstream report;
        
        report << "DTLS v1.3 Comprehensive Monitoring Report\n";
        report << "=========================================\n\n";
        
        report << performance_monitor_->generate_performance_report() << "\n";
        report << security_monitor_->generate_security_report() << "\n";
        
        if (resource_monitor_) {
            report << resource_monitor_->generate_resource_report() << "\n";
        }
        
        // Add alert summary
        auto active_alerts = alert_manager_->get_active_alerts();
        report << "Active Alerts: " << active_alerts.size() << "\n";
        for (const auto& alert : active_alerts) {
            report << "  - " << alert.formatted_message << " (triggered " << 
                     format_duration(std::chrono::duration_cast<std::chrono::microseconds>(alert.get_duration())) << " ago)\n";
        }
        
        return report.str();
    }

    double get_system_health_score() const override {
        // Calculate overall health score based on various factors
        double performance_score = 1.0;
        double security_score = 1.0;
        double alert_score = 1.0;
        
        // Factor in active alerts
        auto active_alerts = alert_manager_->get_active_alerts();
        if (!active_alerts.empty()) {
            alert_score = std::max(0.0, 1.0 - (active_alerts.size() * 0.1));
        }
        
        // TODO: Calculate performance and security scores based on metrics
        
        return (performance_score + security_score + alert_score) / 3.0;
    }

    void reset_all_metrics() override {
        metrics_collector_->reset_metrics();
        performance_monitor_->reset_performance_metrics();
        security_monitor_->reset_security_metrics();
        if (resource_monitor_) {
            resource_monitor_->reset_resource_metrics();
        }
        alert_manager_->clear_alert_history();
    }

private:
    void add_default_alert_conditions() {
        // High connection failure rate
        AlertCondition conn_failure;
        conn_failure.metric_name = "dtls_connections_total{type=\"failed\"}";
        conn_failure.operator_type = AlertCondition::Operator::GREATER_THAN;
        conn_failure.threshold_value = 10;
        conn_failure.severity = AlertSeverity::WARNING;
        conn_failure.message_template = "High connection failure rate detected";
        alert_manager_->add_alert_condition(conn_failure);
        
        // High error rate
        AlertCondition error_rate;
        error_rate.metric_name = "dtls_errors_total";
        error_rate.operator_type = AlertCondition::Operator::GREATER_THAN;
        error_rate.threshold_value = 5;
        error_rate.severity = AlertSeverity::ERROR;
        error_rate.message_template = "High error rate detected";
        alert_manager_->add_alert_condition(error_rate);
    }
};

// Factory method
std::unique_ptr<MonitoringSystem> MonitoringSystem::create() {
    return std::make_unique<MonitoringSystemImpl>();
}

// ScopedTimer implementation
ScopedTimer::ScopedTimer(const std::shared_ptr<MetricsCollector>& collector,
                        const std::string& metric_name,
                        const std::unordered_map<std::string, std::string>& labels)
    : collector_(collector)
    , metric_name_(metric_name)
    , labels_(labels)
    , start_time_(std::chrono::steady_clock::now())
    , stopped_(false) {
}

ScopedTimer::~ScopedTimer() {
    if (!stopped_) {
        stop();
    }
}

std::chrono::microseconds ScopedTimer::get_elapsed() const {
    auto end_time = stopped_ ? start_time_ : std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
}

void ScopedTimer::stop() {
    if (!stopped_) {
        auto duration = get_elapsed();
        collector_->record_timer(metric_name_, duration, labels_);
        stopped_ = true;
    }
}

} // namespace monitoring
} // namespace v13
} // namespace dtls