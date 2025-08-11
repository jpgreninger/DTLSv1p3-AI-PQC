#include <dtls/error_context.h>
#include <algorithm>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

namespace dtls {
namespace v13 {

ErrorContext::ErrorContext(const std::string& connection_id,
                          const NetworkAddress& peer_address)
    : context_id_(connection_id.empty() ? generate_context_hash() : connection_id)
    , creation_time_(std::chrono::steady_clock::now())
    , max_events_(1000)  // Configurable limit
    , has_network_context_(false)
    , peer_port_(0) {
    
    // Initialize connection info
    connection_info_.connection_id_hash = hash_string(connection_id);
    connection_info_.current_state = ConnectionState::INITIAL;
    connection_info_.current_epoch = 0;
    connection_info_.connection_start = creation_time_;
    
    // Set network context if provided
    if (peer_address.family != NetworkAddress::Family::IPv4 || 
        peer_address.family != NetworkAddress::Family::IPv6) {
        set_network_context(peer_address, false);  // Don't log by default
    }
}

uint32_t ErrorContext::record_error(DTLSError error,
                                   const std::string& category,
                                   const std::string& description,
                                   bool is_security_relevant) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ErrorEvent event(error, category, description);
    event.sequence_number = next_sequence_number_++;
    event.is_fatal = is_fatal_error(error);
    event.is_security_relevant = is_security_relevant;
    
    // Add network context if available and not sensitive
    if (has_network_context_) {
        event.has_network_context = true;
        event.source_address_hash = peer_address_hash_;
        event.source_port = peer_port_;
    }
    
    error_events_.emplace_back(std::move(event));
    
    // Update connection info counters
    connection_info_.total_errors++;
    if (event.is_fatal) {
        connection_info_.fatal_errors++;
    }
    if (is_security_relevant) {
        connection_info_.security_errors++;
        update_security_metrics(error);
    }
    
    // Ensure we don't exceed memory limits
    ensure_event_limit();
    
    return event.sequence_number;
}

uint32_t ErrorContext::record_security_error(DTLSError error,
                                            const std::string& attack_type,
                                            double confidence) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ErrorEvent event(error, "security", attack_type);
    event.sequence_number = next_sequence_number_++;
    event.is_fatal = is_fatal_error(error);
    event.is_security_relevant = true;
    
    // Add network context
    if (has_network_context_) {
        event.has_network_context = true;
        event.source_address_hash = peer_address_hash_;
        event.source_port = peer_port_;
    }
    
    error_events_.emplace_back(std::move(event));
    
    // Update connection info counters
    connection_info_.total_errors++;
    if (event.is_fatal) {
        connection_info_.fatal_errors++;
    }
    connection_info_.security_errors++;
    update_security_metrics(error);
    
    // Update security metrics timestamps
    auto now = std::chrono::steady_clock::now();
    if (security_metrics_.first_security_event.time_since_epoch().count() == 0) {
        security_metrics_.first_security_event = now;
    }
    security_metrics_.last_security_event = now;
    
    ensure_event_limit();
    return event.sequence_number;
}

void ErrorContext::update_connection_state(ConnectionState state, 
                                          std::optional<Epoch> epoch) {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_info_.current_state = state;
    if (epoch.has_value()) {
        connection_info_.current_epoch = epoch.value();
    }
}

void ErrorContext::set_network_context(const NetworkAddress& address, 
                                      bool is_logging_enabled) {
    if (!is_logging_enabled) {
        // For privacy, only store hashed address
        peer_address_hash_ = hash_string(address.get_ip());
        peer_port_ = address.get_port();
        has_network_context_ = true;
    }
}

bool ErrorContext::is_error_rate_excessive(std::chrono::seconds time_window,
                                          uint32_t max_errors) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff_time = std::chrono::steady_clock::now() - time_window;
    
    uint32_t error_count = 0;
    for (const auto& event : error_events_) {
        if (event.timestamp >= cutoff_time) {
            error_count++;
            if (error_count > max_errors) {
                return true;
            }
        }
    }
    
    return false;
}

double ErrorContext::detect_attack_patterns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return calculate_attack_confidence();
}

std::vector<ErrorContext::ErrorEvent> ErrorContext::get_recent_errors(
    std::chrono::seconds time_window) const {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff_time = std::chrono::steady_clock::now() - time_window;
    std::vector<ErrorEvent> recent_errors;
    
    for (const auto& event : error_events_) {
        if (event.timestamp >= cutoff_time) {
            recent_errors.push_back(event);
        }
    }
    
    return recent_errors;
}

std::vector<ErrorContext::ErrorEvent> ErrorContext::get_errors_by_category(
    const std::string& category,
    size_t max_events) const {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ErrorEvent> matching_errors;
    
    for (const auto& event : error_events_) {
        if (event.category == category) {
            matching_errors.push_back(event);
            if (max_events > 0 && matching_errors.size() >= max_events) {
                break;
            }
        }
    }
    
    return matching_errors;
}

uint64_t ErrorContext::get_total_error_count() const {
    return connection_info_.total_errors;
}

uint64_t ErrorContext::get_error_count(bool fatal_only) const {
    return fatal_only ? connection_info_.fatal_errors.load() : 
                       connection_info_.total_errors.load();
}

bool ErrorContext::has_security_errors() const {
    return connection_info_.security_errors > 0;
}

std::chrono::seconds ErrorContext::get_context_age() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - creation_time_);
}

void ErrorContext::clear_history(bool keep_connection_info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    error_events_.clear();
    
    if (!keep_connection_info) {
        connection_info_.total_errors = 0;
        connection_info_.fatal_errors = 0;
        connection_info_.security_errors = 0;
        
        // Reset security metrics individually (atomic types cannot be assigned)
        security_metrics_.authentication_failures = 0;
        security_metrics_.record_integrity_failures = 0;
        security_metrics_.replay_detections = 0;
        security_metrics_.tampering_detections = 0;
        security_metrics_.suspicious_patterns = 0;
        security_metrics_.first_security_event = std::chrono::steady_clock::time_point{};
        security_metrics_.last_security_event = std::chrono::steady_clock::time_point{};
    }
}

std::unordered_map<std::string, std::string> ErrorContext::export_context() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::unordered_map<std::string, std::string> exported;
    
    exported["context_id"] = context_id_;
    exported["connection_state"] = std::to_string(static_cast<int>(connection_info_.current_state));
    exported["current_epoch"] = std::to_string(connection_info_.current_epoch);
    exported["total_errors"] = std::to_string(connection_info_.total_errors.load());
    exported["fatal_errors"] = std::to_string(connection_info_.fatal_errors.load());
    exported["security_errors"] = std::to_string(connection_info_.security_errors.load());
    exported["context_age_seconds"] = std::to_string(get_context_age().count());
    
    // Security metrics
    exported["auth_failures"] = std::to_string(security_metrics_.authentication_failures.load());
    exported["integrity_failures"] = std::to_string(security_metrics_.record_integrity_failures.load());
    exported["replay_detections"] = std::to_string(security_metrics_.replay_detections.load());
    exported["tampering_detections"] = std::to_string(security_metrics_.tampering_detections.load());
    exported["suspicious_patterns"] = std::to_string(security_metrics_.suspicious_patterns.load());
    
    // Attack confidence
    exported["attack_confidence"] = std::to_string(calculate_attack_confidence());
    
    return exported;
}

std::string ErrorContext::generate_context_hash() const {
    std::ostringstream oss;
    oss << context_id_ << "_" 
        << std::chrono::duration_cast<std::chrono::microseconds>(
               creation_time_.time_since_epoch()).count()
        << "_" << connection_info_.total_errors.load();
    
    return hash_string(oss.str());
}

bool ErrorContext::should_expire(std::chrono::seconds max_age, 
                                size_t max_events) const {
    return get_context_age() > max_age || get_total_error_count() > max_events;
}

// Private helper methods

void ErrorContext::update_security_metrics(DTLSError error) {
    // This assumes mutex is already held by caller
    
    switch (error) {
        case DTLSError::AUTHENTICATION_FAILED:
        case DTLSError::AUTHORIZATION_FAILED:
            security_metrics_.authentication_failures++;
            break;
            
        case DTLSError::BAD_RECORD_MAC:
        case DTLSError::DECRYPT_ERROR:
            security_metrics_.record_integrity_failures++;
            break;
            
        case DTLSError::REPLAY_ATTACK_DETECTED:
            security_metrics_.replay_detections++;
            break;
            
        case DTLSError::TAMPERING_DETECTED:
            security_metrics_.tampering_detections++;
            break;
            
        default:
            break;
    }
}

void ErrorContext::cleanup_old_events() {
    // This assumes mutex is already held by caller
    
    // Remove events older than 1 hour to prevent unbounded growth
    auto cutoff_time = std::chrono::steady_clock::now() - std::chrono::hours(1);
    
    error_events_.erase(
        std::remove_if(error_events_.begin(), error_events_.end(),
                      [cutoff_time](const ErrorEvent& event) {
                          return event.timestamp < cutoff_time;
                      }),
        error_events_.end()
    );
}

std::string ErrorContext::hash_string(const std::string& input) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return oss.str();
}

void ErrorContext::ensure_event_limit() {
    // This assumes mutex is already held by caller
    
    if (error_events_.size() > max_events_) {
        // Remove oldest events to stay under limit
        size_t events_to_remove = error_events_.size() - max_events_;
        error_events_.erase(error_events_.begin(), 
                           error_events_.begin() + events_to_remove);
    }
}

double ErrorContext::calculate_attack_confidence() const {
    // This assumes mutex is already held by caller
    
    if (error_events_.empty()) {
        return 0.0;
    }
    
    double confidence = 0.0;
    
    // Factor 1: Rate of security-relevant errors
    auto recent_security_errors = 0;
    auto cutoff_time = std::chrono::steady_clock::now() - std::chrono::minutes(5);
    
    for (const auto& event : error_events_) {
        if (event.timestamp >= cutoff_time && event.is_security_relevant) {
            recent_security_errors++;
        }
    }
    
    if (recent_security_errors > 5) {
        confidence += 0.4;  // High rate of security errors
    } else if (recent_security_errors > 2) {
        confidence += 0.2;  // Moderate rate
    } else if (recent_security_errors > 0) {
        confidence += 0.1;  // Any security error adds some confidence
    }
    
    // Factor 2: Types of security errors
    if (security_metrics_.authentication_failures > 3) {
        confidence += 0.3;
    } else if (security_metrics_.authentication_failures > 0) {
        confidence += 0.15;  // Any auth failure adds some confidence
    }
    if (security_metrics_.replay_detections > 0) {
        confidence += 0.2;
    }
    if (security_metrics_.tampering_detections > 0) {
        confidence += 0.3;
    }
    
    // Factor 3: Pattern consistency
    if (security_metrics_.authentication_failures > 0 && 
        security_metrics_.record_integrity_failures > 0) {
        confidence += 0.2;  // Multiple attack vectors
    }
    
    return std::min(confidence, 1.0);
}

// ErrorContextManager implementation

ErrorContextManager::ErrorContextManager() {
    global_metrics_.start_time = std::chrono::steady_clock::now();
}

ErrorContextManager::~ErrorContextManager() = default;

std::shared_ptr<ErrorContext> ErrorContextManager::create_context(
    const std::string& connection_id,
    const NetworkAddress& peer_address) {
    
    std::lock_guard<std::mutex> lock(contexts_mutex_);
    
    auto context = std::make_shared<ErrorContext>(connection_id, peer_address);
    contexts_[connection_id] = context;
    
    global_metrics_.total_contexts++;
    global_metrics_.active_contexts++;
    
    return context;
}

std::shared_ptr<ErrorContext> ErrorContextManager::get_context(const std::string& connection_id) {
    std::lock_guard<std::mutex> lock(contexts_mutex_);
    
    auto it = contexts_.find(connection_id);
    if (it != contexts_.end()) {
        return it->second.lock();
    }
    
    return nullptr;
}

void ErrorContextManager::remove_context(const std::string& connection_id) {
    std::lock_guard<std::mutex> lock(contexts_mutex_);
    
    auto it = contexts_.find(connection_id);
    if (it != contexts_.end()) {
        contexts_.erase(it);
        global_metrics_.active_contexts--;
    }
}

std::vector<std::string> ErrorContextManager::analyze_coordinated_attacks() {
    std::lock_guard<std::mutex> lock(contexts_mutex_);
    
    std::vector<std::string> potential_attacks;
    
    // Look for patterns across multiple connections
    std::unordered_map<std::string, int> attack_patterns;
    
    for (const auto& [connection_id, weak_context] : contexts_) {
        auto context = weak_context.lock();
        if (!context) continue;
        
        if (context->has_security_errors()) {
            double confidence = context->detect_attack_patterns();
            if (confidence > 0.7) {
                potential_attacks.push_back(connection_id);
                global_metrics_.security_incidents++;
            }
        }
    }
    
    return potential_attacks;
}

size_t ErrorContextManager::cleanup_expired_contexts(std::chrono::seconds max_age,
                                                    size_t max_events) {
    std::lock_guard<std::mutex> lock(contexts_mutex_);
    
    size_t cleaned_up = 0;
    
    for (auto it = contexts_.begin(); it != contexts_.end();) {
        auto context = it->second.lock();
        if (!context || context->should_expire(max_age, max_events)) {
            it = contexts_.erase(it);
            cleaned_up++;
            global_metrics_.expired_contexts++;
            global_metrics_.active_contexts--;
        } else {
            ++it;
        }
    }
    
    return cleaned_up;
}

void ErrorContextManager::update_global_metrics() {
    // Called when global state changes
    // Implementation would update various global counters
}

} // namespace v13
} // namespace dtls