#include <dtls/error_handler.h>
#include <dtls/alert_manager.h>
#include <dtls/error_reporter.h>
#include <algorithm>
#include <random>

namespace dtls {
namespace v13 {

// Thread-local storage for error context
thread_local std::weak_ptr<ErrorContext> ErrorHandler::thread_error_context_;

ErrorHandler::ErrorHandler()
    : ErrorHandler(Configuration{}) {
}

ErrorHandler::ErrorHandler(const Configuration& config)
    : config_(config) {
    
    stats_.start_time = std::chrono::steady_clock::now();
    dos_state_.last_second_reset = std::chrono::steady_clock::now();
    dos_state_.last_minute_reset = std::chrono::steady_clock::now();
}

ErrorHandler::~ErrorHandler() = default;

Result<bool> ErrorHandler::process_error(DTLSError error, 
                                        std::shared_ptr<ErrorContext> context) {
    // Update statistics
    stats_.total_errors++;
    
    // Update DoS counters
    update_dos_counters();
    
    // Determine if this is a fatal error
    bool is_fatal = is_fatal_error(error);
    if (is_fatal) {
        stats_.fatal_errors++;
    } else if (is_retryable_error(error)) {
        stats_.retryable_errors++;
    }
    
    // Record error in context if available
    if (context) {
        context->record_error(error, "protocol", error_message(error), 
                             is_security_relevant_error(error));
    }
    
    // Log error securely
    auto log_result = log_error_securely(error, context);
    if (!log_result.is_success()) {
        // Logging failure shouldn't fail the operation, just note it
    }
    
    // Generate alert if appropriate
    if (alert_manager_ && should_generate_alert_for_error(error)) {
        auto alert_result = alert_manager_->generate_alert_for_error(error, context);
        if (alert_result.is_success() && alert_result.value().has_value()) {
            stats_.alerts_generated++;
        }
    }
    
    // Determine if connection should continue
    bool should_continue = !should_terminate_connection(error);
    
    if (!should_continue) {
        stats_.connections_terminated++;
    }
    
    return make_result(should_continue);
}

Result<void> ErrorHandler::handle_invalid_record(ContentType record_type,
                                                std::shared_ptr<ErrorContext> context) {
    // RFC 9147 Section 4.2.1: "In general, invalid records SHOULD be silently discarded"
    stats_.invalid_records_discarded++;
    
    // Update DoS protection counters
    {
        std::lock_guard<std::mutex> lock(dos_state_.reset_mutex);
        dos_state_.invalid_records_this_second++;
        
        // Check if we're under attack
        if (dos_state_.invalid_records_this_second > config_.max_invalid_records_per_second) {
            stats_.dos_attacks_detected++;
            
            if (error_reporter_) {
                error_reporter_->report_security_incident(
                    DTLSError::REPLAY_ATTACK_DETECTED,
                    "invalid_record_flood",
                    0.8,  // High confidence
                    context
                );
            }
        }
    }
    
    // Log for diagnostic purposes if configured
    if (config_.log_invalid_records && error_reporter_) {
        std::string category = "record_validation";
        std::string message = "Invalid record silently discarded (content_type=" + 
                             std::to_string(static_cast<int>(record_type)) + ")";
        
        error_reporter_->report_error(
            ErrorReporter::LogLevel::DEBUG,
            DTLSError::INVALID_RECORD_HEADER,
            category,
            message,
            context
        );
    }
    
    // Record in error context
    if (context) {
        context->record_error(DTLSError::INVALID_RECORD_HEADER, 
                             "record_layer", 
                             "Invalid record discarded per RFC 9147",
                             false); // Not security-relevant by itself
    }
    
    // RFC 9147: Generally should NOT generate alert for invalid records,
    // especially for UDP transport due to DoS risks
    if (config_.generate_alerts_on_invalid_records && is_transport_secure()) {
        if (alert_manager_) {
            auto alert_result = alert_manager_->handle_invalid_record(
                record_type, 
                context ? context->get_connection_info().connection_id_hash : "",
                context
            );
            (void)alert_result; // Result checked in more sophisticated implementations
            // Alert manager will apply its own policy
        }
    }
    
    return make_result();
}

Result<bool> ErrorHandler::handle_authentication_failure(Epoch epoch,
                                                        std::shared_ptr<ErrorContext> context) {
    // RFC 9147: "track records that fail authentication"
    {
        std::lock_guard<std::mutex> lock(dos_state_.reset_mutex);
        dos_state_.auth_failures_this_epoch++;
        
        // Check if authentication failures exceed threshold per epoch
        if (dos_state_.auth_failures_this_epoch > config_.max_auth_failures_per_epoch) {
            stats_.dos_attacks_detected++;
            
            // High confidence DoS/replay attack
            if (error_reporter_) {
                error_reporter_->report_security_incident(
                    DTLSError::AUTHENTICATION_FAILED,
                    "authentication_failure_flood",
                    0.9,  // Very high confidence
                    context
                );
            }
            
            // RFC 9147: "implementations SHOULD close the connection if 
            // authentication failure records exceed a specific limit"
            return make_result(false); // Connection should be closed
        }
    }
    
    // Record authentication failure
    if (context) {
        context->record_security_error(DTLSError::AUTHENTICATION_FAILED,
                                      "authentication_failure", 0.6);
    }
    
    // Log the authentication failure
    if (error_reporter_) {
        error_reporter_->report_error(
            ErrorReporter::LogLevel::WARNING,
            DTLSError::AUTHENTICATION_FAILED,
            "authentication",
            "Record authentication failed for epoch " + std::to_string(epoch),
            context
        );
    }
    
    return make_result(true); // Connection can continue for now
}

Result<std::vector<uint8_t>> ErrorHandler::generate_alert_if_appropriate(
    AlertDescription alert_desc,
    std::shared_ptr<ErrorContext> context) {
    
    // Delegate to alert manager if available
    if (alert_manager_) {
        auto result = alert_manager_->generate_alert(
            AlertLevel::FATAL,  // RFC 9147: must be fatal to prevent probing
            alert_desc,
            context ? context->get_connection_info().connection_id_hash : "",
            context
        );
        
        if (result.is_success() && result.value().has_value()) {
            return make_result(result.value().value());
        }
    }
    
    // Fallback: create alert directly if no alert manager
    if (is_transport_secure()) {
        auto alert_data = AlertManager::serialize_alert(AlertLevel::FATAL, alert_desc);
        stats_.alerts_generated++;
        return make_result(alert_data);
    }
    
    // For insecure transports (UDP), don't generate alert per RFC 9147
    return make_error<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

bool ErrorHandler::should_terminate_connection(DTLSError error) const {
    return is_fatal_error(error);
}

bool ErrorHandler::should_retry_operation(DTLSError error, uint32_t retry_count) const {
    // Don't retry indefinitely
    const uint32_t MAX_RETRIES = 3;
    if (retry_count >= MAX_RETRIES) {
        return false;
    }
    
    return is_retryable_error(error);
}

std::shared_ptr<ErrorContext> ErrorHandler::create_error_context(
    const std::string& connection_id,
    const NetworkAddress& endpoint_address) {
    
    auto context = std::make_shared<ErrorContext>(connection_id, endpoint_address);
    
    // Store weak reference for cleanup
    std::lock_guard<std::mutex> lock(context_mutex_);
    error_contexts_[connection_id] = context;
    
    return context;
}

void ErrorHandler::set_thread_error_context(std::shared_ptr<ErrorContext> context) {
    thread_error_context_ = context;
}

std::shared_ptr<ErrorContext> ErrorHandler::get_thread_error_context() const {
    return thread_error_context_.lock();
}

Result<void> ErrorHandler::update_configuration(const Configuration& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    return make_result();
}

void ErrorHandler::reset_statistics() {
    // Reset atomic counters individually
    stats_.total_errors = 0;
    stats_.fatal_errors = 0;
    stats_.retryable_errors = 0;
    stats_.invalid_records_discarded = 0;
    stats_.authentication_failures = 0;
    stats_.alerts_generated = 0;
    stats_.connections_terminated = 0;
    stats_.dos_attacks_detected = 0;
    stats_.start_time = std::chrono::steady_clock::now();
}

void ErrorHandler::set_alert_manager(std::shared_ptr<AlertManager> alert_manager) {
    alert_manager_ = alert_manager;
}

void ErrorHandler::set_error_reporter(std::shared_ptr<ErrorReporter> error_reporter) {
    error_reporter_ = error_reporter;
}

// Private helper methods

bool ErrorHandler::is_transport_secure() const {
    return config_.transport_type != Transport::UDP;
}

bool ErrorHandler::should_generate_alert_for_error(DTLSError error) const {
    // RFC 9147: For UDP, generating alerts is NOT RECOMMENDED due to DoS risks
    if (!is_transport_secure()) {
        return false;
    }
    
    // For secure transports, generate alerts for protocol violations
    switch (error) {
        case DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED:
        case DTLSError::HANDSHAKE_FAILURE:
        case DTLSError::ILLEGAL_PARAMETER:
        case DTLSError::DECODE_ERROR:
        case DTLSError::CERTIFICATE_VERIFY_FAILED:
        case DTLSError::INSUFFICIENT_SECURITY:
            return true;
        default:
            return false;
    }
}

void ErrorHandler::update_dos_counters() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(dos_state_.reset_mutex);
    
    // Reset per-second counters
    if (now - dos_state_.last_second_reset >= std::chrono::seconds(1)) {
        dos_state_.invalid_records_this_second = 0;
        dos_state_.last_second_reset = now;
    }
    
    // Reset per-minute counters  
    if (now - dos_state_.last_minute_reset >= std::chrono::minutes(1)) {
        dos_state_.alerts_this_minute = 0;
        dos_state_.last_minute_reset = now;
    }
}

void ErrorHandler::cleanup_expired_contexts() {
    std::lock_guard<std::mutex> lock(context_mutex_);
    
    for (auto it = error_contexts_.begin(); it != error_contexts_.end();) {
        if (it->second.expired()) {
            it = error_contexts_.erase(it);
        } else {
            ++it;
        }
    }
}

Result<void> ErrorHandler::log_error_securely(DTLSError error, 
                                             std::shared_ptr<ErrorContext> context) {
    if (!error_reporter_) {
        return make_result();
    }
    
    // Determine log level based on error severity
    ErrorReporter::LogLevel level;
    if (is_security_relevant_error(error)) {
        level = ErrorReporter::LogLevel::SECURITY;
    } else if (is_fatal_error(error)) {
        level = ErrorReporter::LogLevel::ERROR;
    } else if (is_retryable_error(error)) {
        level = ErrorReporter::LogLevel::WARNING;
    } else {
        level = ErrorReporter::LogLevel::INFO;
    }
    
    return error_reporter_->report_error(
        level,
        error,
        "error_handler",
        error_message(error),
        context
    );
}

bool ErrorHandler::is_security_relevant_error(DTLSError error) const {
    switch (error) {
        case DTLSError::AUTHENTICATION_FAILED:
        case DTLSError::AUTHORIZATION_FAILED:
        case DTLSError::DECRYPT_ERROR:
        case DTLSError::BAD_RECORD_MAC:
        case DTLSError::SIGNATURE_VERIFICATION_FAILED:
        case DTLSError::REPLAY_ATTACK_DETECTED:
        case DTLSError::TAMPERING_DETECTED:
        case DTLSError::SECURITY_POLICY_VIOLATION:
        case DTLSError::CERTIFICATE_VERIFY_FAILED:
        case DTLSError::CERTIFICATE_EXPIRED:
        case DTLSError::CERTIFICATE_REVOKED:
        case DTLSError::UNKNOWN_CA:
        case DTLSError::ACCESS_DENIED:
        case DTLSError::INSUFFICIENT_SECURITY:
            return true;
        default:
            return false;
    }
}

} // namespace v13
} // namespace dtls