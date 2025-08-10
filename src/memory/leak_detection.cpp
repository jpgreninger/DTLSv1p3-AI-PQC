#include <dtls/memory/leak_detection.h>
#include <dtls/error.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace dtls {
namespace v13 {
namespace memory {

// LeakDetector implementation
LeakDetector::~LeakDetector() {
    stop_periodic_detection();
}

LeakDetector& LeakDetector::instance() {
    static LeakDetector instance;
    return instance;
}

void LeakDetector::track_resource(void* resource_ptr, ResourceType type, size_t size,
                                 const std::string& allocation_site, const std::string& description) {
    if (!detection_enabled_.load() || !resource_ptr) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    
    ResourceInfo info;
    info.resource_ptr = resource_ptr;
    info.type = type;
    info.size = size;
    info.allocation_site = allocation_site;
    info.thread_id = std::this_thread::get_id();
    info.allocation_time = now;
    info.last_access_time = now;
    info.description = description;
    info.access_count = 1;
    
    {
        std::lock_guard<std::mutex> lock(resources_mutex_);
        tracked_resources_[resource_ptr] = std::move(info);
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_resources_tracked++;
        stats_.resources_by_type[static_cast<size_t>(type)]++;
    }
}

void LeakDetector::update_resource_access(void* resource_ptr) {
    if (!detection_enabled_.load() || !resource_ptr) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    auto it = tracked_resources_.find(resource_ptr);
    if (it != tracked_resources_.end()) {
        it->second.last_access_time = std::chrono::steady_clock::now();
        it->second.access_count++;
    }
}

void LeakDetector::untrack_resource(void* resource_ptr) {
    if (!resource_ptr) {
        return;
    }
    
    ResourceType type = ResourceType::OTHER;
    
    {
        std::lock_guard<std::mutex> lock(resources_mutex_);
        auto it = tracked_resources_.find(resource_ptr);
        if (it != tracked_resources_.end()) {
            type = it->second.type;
            tracked_resources_.erase(it);
        }
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (stats_.resources_by_type[static_cast<size_t>(type)] > 0) {
            stats_.resources_by_type[static_cast<size_t>(type)]--;
        }
    }
}

bool LeakDetector::is_resource_tracked(void* resource_ptr) const {
    if (!resource_ptr) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    return tracked_resources_.find(resource_ptr) != tracked_resources_.end();
}

ResourceInfo LeakDetector::get_resource_info(void* resource_ptr) const {
    if (!resource_ptr) {
        return ResourceInfo{};
    }
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    auto it = tracked_resources_.find(resource_ptr);
    return (it != tracked_resources_.end()) ? it->second : ResourceInfo{};
}

void LeakDetector::set_resource_critical(void* resource_ptr, bool critical) {
    if (!resource_ptr) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    auto it = tracked_resources_.find(resource_ptr);
    if (it != tracked_resources_.end()) {
        it->second.is_critical = critical;
    }
}

void LeakDetector::add_resource_metadata(void* resource_ptr, const std::string& key, const std::string& value) {
    if (!resource_ptr) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    auto it = tracked_resources_.find(resource_ptr);
    if (it != tracked_resources_.end()) {
        it->second.metadata[key] = value;
    }
}

Result<LeakDetector::LeakReport> LeakDetector::detect_leaks() {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!detection_enabled_.load()) {
        return Result<LeakReport>(DTLSError::NOT_INITIALIZED);
    }
    
    LeakReport report;
    report.detection_time = start_time;
    
    auto now = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    for (const auto& [ptr, info] : tracked_resources_) {
        if (is_resource_leaked(info, now)) {
            report.leaked_resources.push_back(info);
            report.total_leaked_memory += info.size;
            report.leaks_by_type[info.type]++;
            
            if (info.is_critical) {
                report.critical_leaks++;
            }
        }
    }
    
    report.total_leaks = report.leaked_resources.size();
    
    auto end_time = std::chrono::steady_clock::now();
    report.detection_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Update statistics
    update_statistics(report, report.detection_duration);
    
    return Result<LeakReport>(std::move(report));
}

Result<LeakDetector::LeakReport> LeakDetector::detect_leaks_for_type(ResourceType type) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!detection_enabled_.load()) {
        return Result<LeakReport>(DTLSError::NOT_INITIALIZED);
    }
    
    LeakReport report;
    report.detection_time = start_time;
    
    auto now = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    for (const auto& [ptr, info] : tracked_resources_) {
        if (info.type == type && is_resource_leaked(info, now)) {
            report.leaked_resources.push_back(info);
            report.total_leaked_memory += info.size;
            report.leaks_by_type[info.type]++;
            
            if (info.is_critical) {
                report.critical_leaks++;
            }
        }
    }
    
    report.total_leaks = report.leaked_resources.size();
    
    auto end_time = std::chrono::steady_clock::now();
    report.detection_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    return Result<LeakReport>(std::move(report));
}

void LeakDetector::register_cleanup_callback(ResourceType type, CleanupCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    cleanup_callbacks_[type] = callback;
}

void LeakDetector::unregister_cleanup_callback(ResourceType type) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    cleanup_callbacks_.erase(type);
}

size_t LeakDetector::cleanup_leaked_resources() {
    if (!detection_enabled_.load()) {
        return 0;
    }
    
    auto leak_report_result = detect_leaks();
    if (!leak_report_result) {
        return 0;
    }
    
    auto leak_report = *leak_report_result;
    size_t cleaned_count = 0;
    size_t cleanup_failures = 0;
    
    for (const auto& leaked_resource : leak_report.leaked_resources) {
        if (cleanup_resource(leaked_resource)) {
            cleaned_count++;
            untrack_resource(leaked_resource.resource_ptr);
        } else {
            cleanup_failures++;
        }
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_resources_cleaned += cleaned_count;
        stats_.total_cleanup_failures += cleanup_failures;
    }
    
    return cleaned_count;
}

size_t LeakDetector::cleanup_resources_of_type(ResourceType type) {
    if (!detection_enabled_.load()) {
        return 0;
    }
    
    auto leak_report_result = detect_leaks_for_type(type);
    if (!leak_report_result) {
        return 0;
    }
    
    auto leak_report = *leak_report_result;
    size_t cleaned_count = 0;
    
    for (const auto& leaked_resource : leak_report.leaked_resources) {
        if (cleanup_resource(leaked_resource)) {
            cleaned_count++;
            untrack_resource(leaked_resource.resource_ptr);
        }
    }
    
    return cleaned_count;
}

size_t LeakDetector::cleanup_old_resources(std::chrono::minutes max_age) {
    if (!detection_enabled_.load()) {
        return 0;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto cutoff_time = now - max_age;
    
    std::vector<ResourceInfo> old_resources;
    
    {
        std::lock_guard<std::mutex> lock(resources_mutex_);
        for (const auto& [ptr, info] : tracked_resources_) {
            if (info.allocation_time < cutoff_time) {
                old_resources.push_back(info);
            }
        }
    }
    
    size_t cleaned_count = 0;
    for (const auto& resource : old_resources) {
        if (cleanup_resource(resource)) {
            cleaned_count++;
            untrack_resource(resource.resource_ptr);
        }
    }
    
    return cleaned_count;
}

void LeakDetector::set_config(const LeakDetectionConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    
    // If periodic detection settings changed, restart if needed
    if (periodic_thread_running_.load()) {
        stop_periodic_detection();
        if (config.enable_periodic_checks) {
            start_periodic_detection();
        }
    }
}

LeakDetectionConfig LeakDetector::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

LeakDetector::DetectionStats LeakDetector::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void LeakDetector::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = DetectionStats{};
}

void LeakDetector::start_periodic_detection() {
    if (periodic_thread_running_.exchange(true)) {
        return; // Already running
    }
    
    periodic_thread_ = std::make_unique<std::thread>(&LeakDetector::periodic_detection_loop, this);
}

void LeakDetector::stop_periodic_detection() {
    if (!periodic_thread_running_.exchange(false)) {
        return; // Not running
    }
    
    if (periodic_thread_ && periodic_thread_->joinable()) {
        periodic_thread_->join();
    }
    periodic_thread_.reset();
}

Result<void> LeakDetector::validate_all_resources() {
    if (!detection_enabled_.load()) {
        return Result<void>(DTLSError::NOT_INITIALIZED);
    }
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    for (const auto& [ptr, info] : tracked_resources_) {
        // Basic validation - check if pointer is still valid
        // In a real implementation, this would do more sophisticated validation
        if (!ptr) {
            return Result<void>(DTLSError::INTERNAL_ERROR);
        }
        
        // Additional validation could include:
        // - Check if memory region is still allocated
        // - Validate object state
        // - Check for corruption patterns
    }
    
    return Result<void>();
}

Result<void> LeakDetector::validate_resources_of_type(ResourceType type) {
    if (!detection_enabled_.load()) {
        return Result<void>(DTLSError::NOT_INITIALIZED);
    }
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    for (const auto& [ptr, info] : tracked_resources_) {
        if (info.type == type) {
            if (!ptr) {
                return Result<void>(DTLSError::INTERNAL_ERROR);
            }
        }
    }
    
    return Result<void>();
}

std::string LeakDetector::generate_leak_report(const LeakReport& report) const {
    std::stringstream ss;
    
    ss << "=== DTLS Memory Leak Detection Report ===\n";
    ss << "Detection Time: " << std::chrono::duration_cast<std::chrono::milliseconds>(
        report.detection_time.time_since_epoch()).count() << "ms since epoch\n";
    ss << "Detection Duration: " << report.detection_duration.count() << "ms\n";
    ss << "Total Leaks: " << report.total_leaks << "\n";
    ss << "Critical Leaks: " << report.critical_leaks << "\n";
    ss << "Total Leaked Memory: " << report.total_leaked_memory << " bytes\n";
    ss << "\n";
    
    if (!report.leaks_by_type.empty()) {
        ss << "Leaks by Type:\n";
        for (const auto& [type, count] : report.leaks_by_type) {
            ss << "  " << resource_type_to_string(type) << ": " << count << "\n";
        }
        ss << "\n";
    }
    
    if (!report.leaked_resources.empty()) {
        ss << "Detailed Leak Information:\n";
        for (size_t i = 0; i < std::min(report.leaked_resources.size(), static_cast<size_t>(20)); ++i) {
            const auto& info = report.leaked_resources[i];
            ss << "  [" << (i + 1) << "] Resource: " << info.resource_ptr << "\n";
            ss << "      Type: " << resource_type_to_string(info.type) << "\n";
            ss << "      Size: " << info.size << " bytes\n";
            ss << "      Description: " << info.description << "\n";
            ss << "      Allocation Site: " << info.allocation_site << "\n";
            ss << "      Age: " << std::chrono::duration_cast<std::chrono::minutes>(
                std::chrono::steady_clock::now() - info.allocation_time).count() << " minutes\n";
            ss << "      Access Count: " << info.access_count << "\n";
            if (info.is_critical) {
                ss << "      CRITICAL RESOURCE!\n";
            }
            ss << "\n";
        }
        
        if (report.leaked_resources.size() > 20) {
            ss << "  ... and " << (report.leaked_resources.size() - 20) << " more leaks\n";
        }
    }
    
    ss << "=== End Report ===\n";
    
    return ss.str();
}

std::string LeakDetector::generate_resource_summary() const {
    std::stringstream ss;
    
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    ss << "=== DTLS Resource Summary ===\n";
    ss << "Total Tracked Resources: " << tracked_resources_.size() << "\n";
    
    // Count by type
    std::unordered_map<ResourceType, size_t> type_counts;
    std::unordered_map<ResourceType, size_t> type_sizes;
    
    for (const auto& [ptr, info] : tracked_resources_) {
        type_counts[info.type]++;
        type_sizes[info.type] += info.size;
    }
    
    ss << "\nResources by Type:\n";
    for (const auto& [type, count] : type_counts) {
        ss << "  " << resource_type_to_string(type) << ": " << count 
           << " resources, " << type_sizes[type] << " bytes\n";
    }
    
    ss << "=== End Summary ===\n";
    
    return ss.str();
}

void LeakDetector::dump_all_resources() const {
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    std::cout << "=== All Tracked Resources ===\n";
    for (const auto& [ptr, info] : tracked_resources_) {
        std::cout << "Resource: " << ptr << "\n";
        std::cout << "  Type: " << resource_type_to_string(info.type) << "\n";
        std::cout << "  Size: " << info.size << " bytes\n";
        std::cout << "  Description: " << info.description << "\n";
        std::cout << "  Allocation Site: " << info.allocation_site << "\n";
        std::cout << "  Age: " << std::chrono::duration_cast<std::chrono::minutes>(
            std::chrono::steady_clock::now() - info.allocation_time).count() << " minutes\n";
        std::cout << "\n";
    }
    std::cout << "=== End Dump ===\n";
}

void LeakDetector::periodic_detection_loop() {
    LeakDetectionConfig local_config;
    
    while (periodic_thread_running_.load()) {
        // Get current configuration
        {
            std::lock_guard<std::mutex> lock(config_mutex_);
            local_config = config_;
        }
        
        if (!local_config.enable_periodic_checks) {
            std::this_thread::sleep_for(local_config.check_interval);
            continue;
        }
        
        // Perform leak detection
        auto leak_report_result = detect_leaks();
        if (leak_report_result) {
            auto leak_report = *leak_report_result;
            
            // If automatic cleanup is enabled and we found leaks
            if (local_config.enable_automatic_cleanup && leak_report.total_leaks > 0) {
                cleanup_leaked_resources();
            }
            
            // Log critical leaks (in a real implementation, this would use proper logging)
            if (leak_report.critical_leaks > 0) {
                std::cerr << "DTLS CRITICAL MEMORY LEAKS DETECTED: " << leak_report.critical_leaks << " leaks\n";
            }
        }
        
        std::this_thread::sleep_for(local_config.check_interval);
    }
}

bool LeakDetector::is_resource_leaked(const ResourceInfo& info, std::chrono::steady_clock::time_point now) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    auto age = now - info.allocation_time;
    auto access_age = now - info.last_access_time;
    
    if (info.is_critical) {
        return age > config_.critical_resource_age;
    }
    
    // Consider a resource leaked if:
    // 1. It's older than max_resource_age AND hasn't been accessed recently
    // 2. Or if it hasn't been accessed for a very long time
    return (age > config_.max_resource_age && access_age > config_.max_resource_age / 2) ||
           access_age > config_.max_resource_age * 2;
}

bool LeakDetector::cleanup_resource(const ResourceInfo& info) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    
    auto it = cleanup_callbacks_.find(info.type);
    if (it != cleanup_callbacks_.end()) {
        try {
            return it->second(info);
        } catch (...) {
            // Cleanup callback failed
            return false;
        }
    }
    
    // No specific cleanup callback, can't clean up automatically
    return false;
}

void LeakDetector::update_statistics(const LeakReport& report, std::chrono::milliseconds detection_time) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_leaks_detected += report.total_leaks;
    stats_.last_detection_time = report.detection_time;
    stats_.detection_runs++;
    
    // Update average detection time
    if (stats_.detection_runs == 1) {
        stats_.average_detection_time = detection_time;
    } else {
        auto total_time = stats_.average_detection_time * (stats_.detection_runs - 1) + detection_time;
        stats_.average_detection_time = total_time / stats_.detection_runs;
    }
    
    // Update current resource counts
    stats_.total_resources_tracked = 0;
    for (size_t i = 0; i < sizeof(stats_.resources_by_type) / sizeof(stats_.resources_by_type[0]); ++i) {
        stats_.total_resources_tracked += stats_.resources_by_type[i];
    }
}

std::string LeakDetector::resource_type_to_string(ResourceType type) const {
    switch (type) {
        case ResourceType::BUFFER: return "BUFFER";
        case ResourceType::CONNECTION: return "CONNECTION";
        case ResourceType::CRYPTO_KEY: return "CRYPTO_KEY";
        case ResourceType::CRYPTO_CONTEXT: return "CRYPTO_CONTEXT";
        case ResourceType::SSL_SESSION: return "SSL_SESSION";
        case ResourceType::CERTIFICATE: return "CERTIFICATE";
        case ResourceType::HANDSHAKE_STATE: return "HANDSHAKE_STATE";
        case ResourceType::RECORD_LAYER_STATE: return "RECORD_LAYER_STATE";
        case ResourceType::TIMER: return "TIMER";
        case ResourceType::SOCKET: return "SOCKET";
        case ResourceType::THREAD: return "THREAD";
        case ResourceType::MEMORY_POOL: return "MEMORY_POOL";
        case ResourceType::OTHER: return "OTHER";
        default: return "UNKNOWN";
    }
}

// ResourceCleanupManager implementation
ResourceCleanupManager& ResourceCleanupManager::instance() {
    static ResourceCleanupManager instance;
    return instance;
}

size_t ResourceCleanupManager::cleanup_non_critical_resources() {
    auto& detector = LeakDetector::instance();
    auto leak_report_result = detector.detect_leaks();
    
    if (!leak_report_result) {
        return 0;
    }
    
    auto leak_report = *leak_report_result;
    size_t cleaned_count = 0;
    
    for (const auto& resource : leak_report.leaked_resources) {
        if (!resource.is_critical && should_cleanup_resource(resource, cleanup_policy_)) {
            if (detector.cleanup_resource(resource)) {
                detector.untrack_resource(resource.resource_ptr);
                cleaned_count++;
            }
        }
    }
    
    return cleaned_count;
}

size_t ResourceCleanupManager::cleanup_old_resources(std::chrono::minutes max_age) {
    return LeakDetector::instance().cleanup_old_resources(max_age);
}

size_t ResourceCleanupManager::cleanup_unused_resources(std::chrono::minutes max_idle_time) {
    auto& detector = LeakDetector::instance();
    auto now = std::chrono::steady_clock::now();
    auto cutoff_time = now - max_idle_time;
    
    std::vector<ResourceInfo> unused_resources;
    
    // This would need access to tracked resources - simplified for now
    // In reality, this would iterate through tracked resources and find unused ones
    
    return 0; // Simplified implementation
}

size_t ResourceCleanupManager::emergency_cleanup() {
    auto& detector = LeakDetector::instance();
    
    // Emergency cleanup: clean everything possible
    CleanupPolicy old_policy = cleanup_policy_;
    cleanup_policy_ = CleanupPolicy::AGGRESSIVE;
    
    size_t cleaned_count = detector.cleanup_leaked_resources();
    
    cleanup_policy_ = old_policy;
    
    return cleaned_count;
}

Result<size_t> ResourceCleanupManager::validate_and_repair_resources() {
    auto& detector = LeakDetector::instance();
    
    auto validation_result = detector.validate_all_resources();
    if (!validation_result) {
        return Result<size_t>(validation_result.error());
    }
    
    // In a full implementation, this would attempt to repair corrupted resources
    return Result<size_t>(0);
}

void ResourceCleanupManager::register_resource_created_callback(ResourceCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    creation_callbacks_.push_back(callback);
}

void ResourceCleanupManager::register_resource_destroyed_callback(ResourceCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    destruction_callbacks_.push_back(callback);
}

bool ResourceCleanupManager::should_cleanup_resource(const ResourceInfo& info, CleanupPolicy policy) const {
    auto now = std::chrono::steady_clock::now();
    auto age = now - info.allocation_time;
    auto access_age = now - info.last_access_time;
    
    switch (policy) {
        case CleanupPolicy::CONSERVATIVE:
            // Only clean obviously leaked resources (very old and unused)
            return age > std::chrono::hours(2) && access_age > std::chrono::hours(1);
            
        case CleanupPolicy::MODERATE:
            // Clean resources that seem to be leaked
            return age > std::chrono::minutes(30) && access_age > std::chrono::minutes(15);
            
        case CleanupPolicy::AGGRESSIVE:
            // Clean all old resources
            return age > std::chrono::minutes(5) || access_age > std::chrono::minutes(10);
            
        default:
            return false;
    }
}

// Utility functions implementation
void enable_leak_detection(bool enabled) {
    LeakDetector::instance().enable_detection(enabled);
}

bool is_leak_detection_enabled() {
    return LeakDetector::instance().is_detection_enabled();
}

size_t get_tracked_resource_count() {
    auto stats = LeakDetector::instance().get_statistics();
    return stats.total_resources_tracked;
}

size_t cleanup_all_leaked_resources() {
    return LeakDetector::instance().cleanup_leaked_resources();
}

std::string generate_resource_report() {
    auto& detector = LeakDetector::instance();
    auto leak_report_result = detector.detect_leaks();
    
    if (!leak_report_result) {
        return "Failed to generate resource report: " + std::to_string(static_cast<int>(leak_report_result.error()));
    }
    
    return detector.generate_leak_report(*leak_report_result);
}

void register_default_cleanup_callbacks() {
    auto& detector = LeakDetector::instance();
    
    // Register cleanup callbacks for common resource types
    
    // Buffer cleanup
    detector.register_cleanup_callback(ResourceType::BUFFER, 
        [](const ResourceInfo& info) -> bool {
            // In a real implementation, this would properly free the buffer
            // For now, just return true to indicate successful cleanup
            return true;
        });
    
    // Connection cleanup
    detector.register_cleanup_callback(ResourceType::CONNECTION,
        [](const ResourceInfo& info) -> bool {
            // Would close and cleanup connection resources
            return true;
        });
    
    // Add more default cleanup callbacks as needed
}

} // namespace memory
} // namespace v13
} // namespace dtls