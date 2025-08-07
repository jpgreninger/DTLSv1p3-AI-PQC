#include <dtls/security/resource_manager.h>
#include <algorithm>
#include <sstream>

namespace dtls {
namespace v13 {
namespace security {

// SourceResourceData methods are inline in header since they're simple

// ResourceManager implementation
ResourceManager::ResourceManager(const ResourceConfig& config)
    : config_(config)
    , last_cleanup_(std::chrono::steady_clock::now())
    , last_health_check_(std::chrono::steady_clock::now()) {
    
    stats_.last_cleanup = last_cleanup_.load();
    stats_.last_pressure_event = last_health_check_.load();
}

ResourceManager::~ResourceManager() = default;

Result<uint64_t> ResourceManager::allocate_connection_resources(
    const NetworkAddress& source_address,
    size_t memory_estimate) {
    
    std::string source_key = address_to_key(source_address);
    
    // Check if allocation would succeed
    if (!can_allocate(source_address, ResourceType::CONNECTION_SLOT, 1) ||
        !can_allocate(source_address, ResourceType::CONNECTION_MEMORY, memory_estimate)) {
        
        record_allocation_failure(ResourceResult::CONNECTION_LIMIT_EXCEEDED);
        return make_error<uint64_t>(DTLSError::RESOURCE_EXHAUSTED, 
                                      "Connection allocation would exceed limits");
    }
    
    // Generate allocation ID
    uint64_t allocation_id = generate_allocation_id();
    
    // Create allocation record
    auto allocation = std::make_unique<ResourceAllocation>(
        ResourceType::CONNECTION_SLOT, memory_estimate, source_key);
    
    // Update source data
    auto* source_data = get_or_create_source_data(source_address);
    if (!source_data) {
        record_allocation_failure(ResourceResult::RESOURCE_UNAVAILABLE);
        return make_error<uint64_t>(DTLSError::RESOURCE_EXHAUSTED, 
                                      "Cannot create source data");
    }
    
    {
        std::lock_guard<std::mutex> lock(source_data->allocation_mutex);
        source_data->total_memory += memory_estimate;
        source_data->connection_count++;
        source_data->allocation_ids.insert(allocation_id);
        source_data->last_activity = std::chrono::steady_clock::now();
    }
    
    // Update global counters
    total_allocated_memory_ += memory_estimate;
    connection_memory_ += memory_estimate;
    total_connections_++;
    
    // Store allocation
    {
        std::unique_lock<std::shared_mutex> lock(allocations_mutex_);
        allocations_[allocation_id] = std::move(allocation);
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_allocated_memory = total_allocated_memory_.load();
        stats_.connection_memory = connection_memory_.load();
        stats_.total_connections = total_connections_.load();
        stats_.active_connections++;
        if (stats_.total_allocated_memory > stats_.peak_memory_usage) {
            stats_.peak_memory_usage = stats_.total_allocated_memory;
        }
    }
    
    update_pressure_level();
    
    return make_result(allocation_id);
}

Result<uint64_t> ResourceManager::allocate_handshake_resources(
    const NetworkAddress& source_address,
    size_t memory_estimate) {
    
    std::string source_key = address_to_key(source_address);
    
    // Check if allocation would succeed
    if (!can_allocate(source_address, ResourceType::HANDSHAKE_SLOT, 1) ||
        !can_allocate(source_address, ResourceType::HANDSHAKE_MEMORY, memory_estimate)) {
        
        record_allocation_failure(ResourceResult::SOURCE_LIMIT_EXCEEDED);
        return make_error<uint64_t>(DTLSError::RESOURCE_EXHAUSTED, 
                                      "Handshake allocation would exceed limits");
    }
    
    // Generate allocation ID
    uint64_t allocation_id = generate_allocation_id();
    
    // Create allocation record
    auto allocation = std::make_unique<ResourceAllocation>(
        ResourceType::HANDSHAKE_SLOT, memory_estimate, source_key);
    
    // Update source data
    auto* source_data = get_or_create_source_data(source_address);
    if (!source_data) {
        record_allocation_failure(ResourceResult::RESOURCE_UNAVAILABLE);
        return make_error<uint64_t>(DTLSError::RESOURCE_EXHAUSTED, 
                                      "Cannot create source data");
    }
    
    {
        std::lock_guard<std::mutex> lock(source_data->allocation_mutex);
        source_data->total_memory += memory_estimate;
        source_data->handshake_count++;
        source_data->allocation_ids.insert(allocation_id);
        source_data->last_activity = std::chrono::steady_clock::now();
    }
    
    // Update global counters
    total_allocated_memory_ += memory_estimate;
    handshake_memory_ += memory_estimate;
    pending_handshakes_++;
    
    // Store allocation
    {
        std::unique_lock<std::shared_mutex> lock(allocations_mutex_);
        allocations_[allocation_id] = std::move(allocation);
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_allocated_memory = total_allocated_memory_.load();
        stats_.handshake_memory = handshake_memory_.load();
        stats_.pending_handshakes = pending_handshakes_.load();
        if (stats_.total_allocated_memory > stats_.peak_memory_usage) {
            stats_.peak_memory_usage = stats_.total_allocated_memory;
        }
    }
    
    update_pressure_level();
    
    return make_result(allocation_id);
}

Result<uint64_t> ResourceManager::allocate_buffer_memory(
    const NetworkAddress& source_address,
    size_t buffer_size) {
    
    std::string source_key = address_to_key(source_address);
    
    // Check if allocation would succeed
    if (!can_allocate(source_address, ResourceType::BUFFER_MEMORY, buffer_size)) {
        record_allocation_failure(ResourceResult::MEMORY_LIMIT_EXCEEDED);
        return make_error<uint64_t>(DTLSError::RESOURCE_EXHAUSTED, 
                                      "Buffer allocation would exceed memory limits");
    }
    
    // Generate allocation ID
    uint64_t allocation_id = generate_allocation_id();
    
    // Create allocation record
    auto allocation = std::make_unique<ResourceAllocation>(
        ResourceType::BUFFER_MEMORY, buffer_size, source_key);
    
    // Update source data
    auto* source_data = get_or_create_source_data(source_address);
    if (!source_data) {
        record_allocation_failure(ResourceResult::RESOURCE_UNAVAILABLE);
        return make_error<uint64_t>(DTLSError::RESOURCE_EXHAUSTED, 
                                      "Cannot create source data");
    }
    
    {
        std::lock_guard<std::mutex> lock(source_data->allocation_mutex);
        source_data->total_memory += buffer_size;
        source_data->buffer_memory += buffer_size;
        source_data->allocation_ids.insert(allocation_id);
        source_data->last_activity = std::chrono::steady_clock::now();
    }
    
    // Update global counters
    total_allocated_memory_ += buffer_size;
    buffer_memory_ += buffer_size;
    
    // Store allocation
    {
        std::unique_lock<std::shared_mutex> lock(allocations_mutex_);
        allocations_[allocation_id] = std::move(allocation);
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_allocated_memory = total_allocated_memory_.load();
        stats_.buffer_memory = buffer_memory_.load();
        if (stats_.total_allocated_memory > stats_.peak_memory_usage) {
            stats_.peak_memory_usage = stats_.total_allocated_memory;
        }
    }
    
    update_pressure_level();
    
    return make_result(allocation_id);
}

Result<void> ResourceManager::release_resources(uint64_t allocation_id) {
    ResourceAllocation* allocation = nullptr;
    
    {
        std::shared_lock<std::shared_mutex> lock(allocations_mutex_);
        auto it = allocations_.find(allocation_id);
        if (it == allocations_.end()) {
            return make_error<void>(DTLSError::MESSAGE_NOT_FOUND, "Allocation ID not found");
        }
        allocation = it->second.get();
    }
    
    // Update source data
    {
        std::unique_lock<std::shared_mutex> source_lock(source_data_mutex_);
        auto source_it = source_data_.find(allocation->source_key);
        if (source_it != source_data_.end()) {
            auto& source_data = source_it->second;
            std::lock_guard<std::mutex> lock(source_data->allocation_mutex);
            
            source_data->total_memory -= allocation->amount;
            source_data->allocation_ids.erase(allocation_id);
            
            switch (allocation->type) {
                case ResourceType::CONNECTION_SLOT:
                case ResourceType::CONNECTION_MEMORY:
                    if (source_data->connection_count > 0) {
                        source_data->connection_count--;
                    }
                    connection_memory_ -= allocation->amount;
                    if (stats_.active_connections > 0) {
                        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                        stats_.active_connections--;
                    }
                    break;
                case ResourceType::HANDSHAKE_SLOT:
                case ResourceType::HANDSHAKE_MEMORY:
                    if (source_data->handshake_count > 0) {
                        source_data->handshake_count--;
                    }
                    handshake_memory_ -= allocation->amount;
                    if (pending_handshakes_ > 0) {
                        pending_handshakes_--;
                    }
                    {
                        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                        stats_.completed_handshakes++;
                        stats_.pending_handshakes = pending_handshakes_.load();
                    }
                    break;
                case ResourceType::BUFFER_MEMORY:
                    source_data->buffer_memory -= allocation->amount;
                    buffer_memory_ -= allocation->amount;
                    break;
            }
        }
    }
    
    // Update global counters
    total_allocated_memory_ -= allocation->amount;
    
    // Remove allocation
    {
        std::unique_lock<std::shared_mutex> lock(allocations_mutex_);
        allocations_.erase(allocation_id);
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_allocated_memory = total_allocated_memory_.load();
        stats_.connection_memory = connection_memory_.load();
        stats_.handshake_memory = handshake_memory_.load();
        stats_.buffer_memory = buffer_memory_.load();
    }
    
    update_pressure_level();
    
    return make_result();
}

Result<void> ResourceManager::update_activity(uint64_t allocation_id) {
    std::shared_lock<std::shared_mutex> lock(allocations_mutex_);
    auto it = allocations_.find(allocation_id);
    if (it == allocations_.end()) {
        return make_error<void>(DTLSError::MESSAGE_NOT_FOUND, "Allocation ID not found");
    }
    
    it->second->last_activity = std::chrono::steady_clock::now();
    
    // Also update source data activity
    std::shared_lock<std::shared_mutex> source_lock(source_data_mutex_);
    auto source_it = source_data_.find(it->second->source_key);
    if (source_it != source_data_.end()) {
        source_it->second->last_activity = std::chrono::steady_clock::now();
    }
    
    return make_result();
}

bool ResourceManager::can_allocate(const NetworkAddress& source_address,
                                  ResourceType type,
                                  size_t amount) const {
    
    std::string source_key = address_to_key(source_address);
    
    // Check global limits first
    switch (type) {
        case ResourceType::CONNECTION_SLOT:
            if (total_connections_.load() >= config_.max_total_connections) {
                return false;
            }
            break;
        case ResourceType::HANDSHAKE_SLOT:
            if (pending_handshakes_.load() >= config_.max_pending_handshakes) {
                return false;
            }
            break;
        case ResourceType::CONNECTION_MEMORY:
        case ResourceType::HANDSHAKE_MEMORY:
        case ResourceType::BUFFER_MEMORY:
            if (total_allocated_memory_.load() + amount > config_.max_total_memory) {
                return false;
            }
            break;
    }
    
    // Check memory limits
    if (!check_memory_limits(source_key, amount)) {
        return false;
    }
    
    // Check connection limits
    if (!check_connection_limits(source_key, type)) {
        return false;
    }
    
    return true;
}

PressureLevel ResourceManager::get_pressure_level() const {
    return current_pressure_.load();
}

double ResourceManager::get_memory_usage_percentage() const {
    return static_cast<double>(total_allocated_memory_.load()) / config_.max_total_memory;
}

double ResourceManager::get_connection_usage_percentage() const {
    return static_cast<double>(total_connections_.load()) / config_.max_total_connections;
}

ResourceStats ResourceManager::get_resource_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ResourceStats stats = stats_;
    
    // Update real-time values
    stats.total_allocated_memory = total_allocated_memory_.load();
    stats.connection_memory = connection_memory_.load();
    stats.handshake_memory = handshake_memory_.load();
    stats.buffer_memory = buffer_memory_.load();
    stats.total_connections = total_connections_.load();
    stats.pending_handshakes = pending_handshakes_.load();
    stats.current_pressure = current_pressure_.load();
    
    return stats;
}

Result<ResourceManager::SourceResourceSummary> ResourceManager::get_source_usage(const NetworkAddress& source_address) const {
    std::string source_key = address_to_key(source_address);
    
    std::shared_lock<std::shared_mutex> lock(source_data_mutex_);
    auto it = source_data_.find(source_key);
    if (it == source_data_.end()) {
        return make_error<SourceResourceSummary>(DTLSError::MESSAGE_NOT_FOUND, "Source not found");
    }
    
    // Create a copyable summary from the non-copyable SourceResourceData
    SourceResourceSummary summary;
    summary.total_memory = it->second->total_memory.load();
    summary.connection_count = it->second->connection_count.load();
    summary.handshake_count = it->second->handshake_count.load();
    summary.buffer_memory = it->second->buffer_memory.load();
    summary.first_allocation = it->second->first_allocation;
    summary.last_activity = it->second->last_activity;
    
    return make_result(summary);
}

size_t ResourceManager::force_cleanup(size_t max_cleanup_count) {
    size_t cleaned = 0;
    
    if (max_cleanup_count == 0) {
        max_cleanup_count = config_.cleanup_batch_size;
    }
    
    // Cleanup expired allocations
    cleaned += cleanup_expired_allocations();
    
    if (cleaned < max_cleanup_count) {
        // Cleanup inactive sources
        cleaned += cleanup_inactive_sources();
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.cleanup_operations++;
        stats_.resources_cleaned += cleaned;
        stats_.last_cleanup = std::chrono::steady_clock::now();
    }
    
    last_cleanup_ = std::chrono::steady_clock::now();
    
    return cleaned;
}

size_t ResourceManager::cleanup_source_resources(const NetworkAddress& source_address) {
    std::string source_key = address_to_key(source_address);
    size_t cleaned = 0;
    
    std::vector<uint64_t> to_cleanup;
    
    {
        std::shared_lock<std::shared_mutex> lock(allocations_mutex_);
        for (const auto& [id, allocation] : allocations_) {
            if (allocation->source_key == source_key) {
                to_cleanup.push_back(id);
            }
        }
    }
    
    for (uint64_t id : to_cleanup) {
        if (release_resources(id).is_success()) {
            cleaned++;
        }
    }
    
    // Remove source data if empty
    {
        std::unique_lock<std::shared_mutex> lock(source_data_mutex_);
        auto it = source_data_.find(source_key);
        if (it != source_data_.end() && it->second->allocation_ids.empty()) {
            source_data_.erase(it);
        }
    }
    
    return cleaned;
}

PressureLevel ResourceManager::check_system_health() {
    auto now = std::chrono::steady_clock::now();
    
    // Only check periodically
    if (now - last_health_check_.load() < std::chrono::seconds{10}) {
        return current_pressure_.load();
    }
    
    update_pressure_level();
    
    // Trigger cleanup if under pressure
    auto pressure = current_pressure_.load();
    if (pressure >= PressureLevel::WARNING && config_.enable_auto_cleanup) {
        force_cleanup();
    }
    
    last_health_check_ = now;
    
    return pressure;
}

Result<void> ResourceManager::update_config(const ResourceConfig& new_config) {
    config_ = new_config;
    update_pressure_level();
    return make_result();
}

void ResourceManager::set_memory_monitoring(bool enabled) {
    memory_monitoring_enabled_ = enabled;
}

std::vector<NetworkAddress> ResourceManager::get_high_usage_sources(double threshold) const {
    std::vector<NetworkAddress> high_usage_sources;
    
    std::shared_lock<std::shared_mutex> lock(source_data_mutex_);
    for (const auto& [key, source_data] : source_data_) {
        double memory_usage = static_cast<double>(source_data->total_memory.load()) / 
                             config_.max_memory_per_connection;
        double connection_usage = static_cast<double>(source_data->connection_count.load()) / 
                                 config_.max_connections_per_source;
        
        if (memory_usage > threshold || connection_usage > threshold) {
            // Parse key back to NetworkAddress (simplified)
            // In a real implementation, you'd want a more robust method
            try {
                size_t colon_pos = key.find(':');
                if (colon_pos != std::string::npos) {
                    std::string ip = key.substr(0, colon_pos);
                    uint16_t port = static_cast<uint16_t>(std::stoi(key.substr(colon_pos + 1)));
                    high_usage_sources.emplace_back(ip, port);
                }
            } catch (...) {
                // Skip malformed keys
            }
        }
    }
    
    return high_usage_sources;
}

void ResourceManager::reset() {
    std::unique_lock<std::shared_mutex> allocations_lock(allocations_mutex_);
    std::unique_lock<std::shared_mutex> source_lock(source_data_mutex_);
    
    allocations_.clear();
    source_data_.clear();
    
    total_allocated_memory_ = 0;
    connection_memory_ = 0;
    handshake_memory_ = 0;
    buffer_memory_ = 0;
    total_connections_ = 0;
    pending_handshakes_ = 0;
    current_pressure_ = PressureLevel::NORMAL;
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_ = ResourceStats{};
    }
    
    next_allocation_id_ = 1;
    last_cleanup_ = std::chrono::steady_clock::now();
    last_health_check_ = last_cleanup_.load();
}

// Private helper methods
SourceResourceData* ResourceManager::get_or_create_source_data(const NetworkAddress& source_address) {
    std::string key = address_to_key(source_address);
    
    {
        std::shared_lock<std::shared_mutex> lock(source_data_mutex_);
        auto it = source_data_.find(key);
        if (it != source_data_.end()) {
            return it->second.get();
        }
    }
    
    {
        std::unique_lock<std::shared_mutex> lock(source_data_mutex_);
        // Double-check after acquiring write lock
        auto it = source_data_.find(key);
        if (it != source_data_.end()) {
            return it->second.get();
        }
        
        // Create new source data
        auto source_data = std::make_unique<SourceResourceData>();
        auto* ptr = source_data.get();
        source_data_[key] = std::move(source_data);
        return ptr;
    }
}

SourceResourceData* ResourceManager::get_source_data(const NetworkAddress& source_address) const {
    std::string key = address_to_key(source_address);
    std::shared_lock<std::shared_mutex> lock(source_data_mutex_);
    
    auto it = source_data_.find(key);
    return (it != source_data_.end()) ? it->second.get() : nullptr;
}

uint64_t ResourceManager::generate_allocation_id() {
    return next_allocation_id_++;
}

std::string ResourceManager::address_to_key(const NetworkAddress& address) const {
    std::ostringstream oss;
    oss << address.get_ip() << ":" << address.get_port();
    return oss.str();
}

bool ResourceManager::check_memory_limits(const std::string& source_key, size_t additional_memory) const {
    // Check global memory limit
    if (total_allocated_memory_.load() + additional_memory > config_.max_total_memory) {
        return false;
    }
    
    // Check per-source memory limit
    std::shared_lock<std::shared_mutex> lock(source_data_mutex_);
    auto it = source_data_.find(source_key);
    if (it != source_data_.end()) {
        size_t current_memory = it->second->total_memory.load();
        if (current_memory + additional_memory > config_.max_memory_per_connection) {
            return false;
        }
    }
    
    return true;
}

bool ResourceManager::check_connection_limits(const std::string& source_key, ResourceType type) const {
    std::shared_lock<std::shared_mutex> lock(source_data_mutex_);
    auto it = source_data_.find(source_key);
    if (it != source_data_.end()) {
        auto& source_data = it->second;
        
        switch (type) {
            case ResourceType::CONNECTION_SLOT:
            case ResourceType::CONNECTION_MEMORY:
                if (source_data->connection_count.load() >= config_.max_connections_per_source) {
                    return false;
                }
                break;
            case ResourceType::HANDSHAKE_SLOT:
            case ResourceType::HANDSHAKE_MEMORY:
                if (source_data->handshake_count.load() >= config_.max_handshakes_per_source) {
                    return false;
                }
                break;
            case ResourceType::BUFFER_MEMORY:
                // No specific connection limit for buffer memory
                break;
        }
    }
    
    return true;
}

void ResourceManager::update_pressure_level() {
    double memory_usage = get_memory_usage_percentage();
    double connection_usage = get_connection_usage_percentage();
    
    PressureLevel new_pressure = PressureLevel::NORMAL;
    
    if (memory_usage >= config_.memory_critical_threshold || 
        connection_usage >= config_.connection_critical_threshold) {
        new_pressure = PressureLevel::CRITICAL;
    } else if (memory_usage >= config_.memory_warning_threshold || 
               connection_usage >= config_.connection_warning_threshold) {
        new_pressure = PressureLevel::WARNING;
    }
    
    // Check for emergency conditions
    if (memory_usage >= 0.99 || connection_usage >= 0.99) {
        new_pressure = PressureLevel::EMERGENCY;
    }
    
    auto old_pressure = current_pressure_.exchange(new_pressure);
    
    if (new_pressure > old_pressure) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.pressure_events++;
        stats_.last_pressure_event = std::chrono::steady_clock::now();
        stats_.current_pressure = new_pressure;
    }
}

size_t ResourceManager::cleanup_expired_allocations() {
    size_t cleaned = 0;
    auto now = std::chrono::steady_clock::now();
    std::vector<uint64_t> to_cleanup;
    
    {
        std::shared_lock<std::shared_mutex> lock(allocations_mutex_);
        for (const auto& [id, allocation] : allocations_) {
            auto age = now - allocation->last_activity;
            bool should_cleanup = false;
            
            switch (allocation->type) {
                case ResourceType::CONNECTION_SLOT:
                case ResourceType::CONNECTION_MEMORY:
                    should_cleanup = age > config_.connection_timeout;
                    break;
                case ResourceType::HANDSHAKE_SLOT:
                case ResourceType::HANDSHAKE_MEMORY:
                    should_cleanup = age > config_.handshake_timeout;
                    break;
                case ResourceType::BUFFER_MEMORY:
                    should_cleanup = age > (config_.connection_timeout * 2);
                    break;
            }
            
            if (should_cleanup) {
                to_cleanup.push_back(id);
            }
        }
    }
    
    for (uint64_t id : to_cleanup) {
        if (release_resources(id).is_success()) {
            cleaned++;
        }
    }
    
    return cleaned;
}

size_t ResourceManager::cleanup_inactive_sources() {
    size_t cleaned = 0;
    auto now = std::chrono::steady_clock::now();
    auto inactive_threshold = std::chrono::hours{1};
    
    std::vector<std::string> to_cleanup;
    
    {
        std::shared_lock<std::shared_mutex> lock(source_data_mutex_);
        for (const auto& [key, source_data] : source_data_) {
            if (source_data->allocation_ids.empty() &&
                now - source_data->last_activity > inactive_threshold) {
                to_cleanup.push_back(key);
            }
        }
    }
    
    {
        std::unique_lock<std::shared_mutex> lock(source_data_mutex_);
        for (const auto& key : to_cleanup) {
            source_data_.erase(key);
            cleaned++;
        }
    }
    
    return cleaned;
}

void ResourceManager::record_allocation_failure(ResourceResult reason) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.failed_allocations++;
}

// Factory implementations
std::unique_ptr<ResourceManager> ResourceManagerFactory::create_development() {
    ResourceConfig config;
    config.max_total_memory = 1024 * 1024 * 1024;  // 1GB
    config.max_memory_per_connection = 1024 * 1024;  // 1MB
    config.max_total_connections = 50000;
    config.max_connections_per_source = 1000;
    config.max_pending_handshakes = 5000;
    return std::make_unique<ResourceManager>(config);
}

std::unique_ptr<ResourceManager> ResourceManagerFactory::create_production() {
    ResourceConfig config;
    config.max_total_memory = 256 * 1024 * 1024;  // 256MB
    config.max_memory_per_connection = 64 * 1024;  // 64KB
    config.max_total_connections = 10000;
    config.max_connections_per_source = 100;
    config.max_pending_handshakes = 1000;
    return std::make_unique<ResourceManager>(config);
}

std::unique_ptr<ResourceManager> ResourceManagerFactory::create_embedded() {
    ResourceConfig config;
    config.max_total_memory = 32 * 1024 * 1024;  // 32MB
    config.max_memory_per_connection = 8 * 1024;  // 8KB
    config.max_total_connections = 1000;
    config.max_connections_per_source = 10;
    config.max_pending_handshakes = 100;
    return std::make_unique<ResourceManager>(config);
}

std::unique_ptr<ResourceManager> ResourceManagerFactory::create_high_capacity() {
    ResourceConfig config;
    config.max_total_memory = 2ULL * 1024 * 1024 * 1024;  // 2GB
    config.max_memory_per_connection = 128 * 1024;  // 128KB
    config.max_total_connections = 100000;
    config.max_connections_per_source = 1000;
    config.max_pending_handshakes = 10000;
    return std::make_unique<ResourceManager>(config);
}

std::unique_ptr<ResourceManager> ResourceManagerFactory::create_custom(const ResourceConfig& config) {
    return std::make_unique<ResourceManager>(config);
}

// ResourceGuard implementation
ResourceGuard::ResourceGuard(ResourceManager* manager, uint64_t allocation_id)
    : manager_(manager), allocation_id_(allocation_id) {
}

ResourceGuard::~ResourceGuard() {
    release();
}

ResourceGuard::ResourceGuard(ResourceGuard&& other) noexcept
    : manager_(other.manager_), allocation_id_(other.allocation_id_) {
    other.manager_ = nullptr;
    other.allocation_id_ = 0;
}

ResourceGuard& ResourceGuard::operator=(ResourceGuard&& other) noexcept {
    if (this != &other) {
        release();
        manager_ = other.manager_;
        allocation_id_ = other.allocation_id_;
        other.manager_ = nullptr;
        other.allocation_id_ = 0;
    }
    return *this;
}

void ResourceGuard::release() {
    if (manager_ && allocation_id_ != 0) {
        manager_->release_resources(allocation_id_);
        manager_ = nullptr;
        allocation_id_ = 0;
    }
}

}  // namespace security
}  // namespace v13
}  // namespace dtls