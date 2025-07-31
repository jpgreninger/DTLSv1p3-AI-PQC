/**
 * @file advanced_connection_manager.cpp
 * @brief Implementation of advanced connection pooling and management
 */

#include "dtls/connection/advanced_connection_manager.h"
#include "dtls/core/result.h"
#include "dtls/memory/buffer.h"
#include <algorithm>
#include <random>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <unordered_set>

namespace dtls {
namespace v13 {
namespace connection {
namespace advanced {

namespace {

/**
 * @brief Generate unique connection ID
 */
std::string generate_connection_id() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::steady_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    return "conn_" + std::to_string(timestamp) + "_" + std::to_string(counter.fetch_add(1));
}

/**
 * @brief Calculate connection load based on metrics
 */
double calculate_connection_load(const ConnectionStats& stats, size_t max_concurrent) {
    if (max_concurrent == 0) return 0.0;
    
    // Simple load calculation based on active requests and recent activity
    double base_load = static_cast<double>(stats.records_sent + stats.records_received) / 1000.0;
    double time_factor = 1.0; // Could factor in recent activity
    
    return std::min(1.0, base_load * time_factor);
}

} // anonymous namespace

/**
 * @brief Managed connection implementation
 */
class ManagedConnectionImpl : public ManagedConnection {
private:
    std::string connection_id_;
    std::shared_ptr<Connection> underlying_connection_;
    std::atomic<State> state_;
    mutable std::mutex mutex_;
    ConnectionHealth health_;
    ConnectionStats stats_;
    std::chrono::steady_clock::time_point creation_time_;
    std::chrono::steady_clock::time_point last_activity_;
    std::atomic<size_t> active_requests_{0};
    transport::NetworkEndpoint current_endpoint_;

public:
    ManagedConnectionImpl(const std::shared_ptr<Connection>& connection, 
                         const transport::NetworkEndpoint& endpoint)
        : connection_id_(generate_connection_id())
        , underlying_connection_(connection)
        , state_(State::INITIALIZING)
        , creation_time_(std::chrono::steady_clock::now())
        , last_activity_(creation_time_)
        , current_endpoint_(endpoint) {
        
        health_.status = ConnectionHealth::Status::UNKNOWN;
        health_.last_health_check = creation_time_;
    }

    std::string get_connection_id() const override {
        return connection_id_;
    }

    State get_state() const override {
        return state_.load();
    }

    ConnectionHealth get_health() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return health_;
    }

    ConnectionStats get_statistics() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

    Result<void> send_data(const std::vector<uint8_t>& data) override {
        if (state_.load() != State::CONNECTED && state_.load() != State::IDLE) {
            return make_error_void(DTLSError::CONNECTION_STATE_ERROR);
        }

        active_requests_.fetch_add(1);
        state_.store(State::BUSY);
        
        // Update activity timestamp
        last_activity_ = std::chrono::steady_clock::now();
        
        // Send through underlying connection
        auto result = underlying_connection_->send(data);
        
        active_requests_.fetch_sub(1);
        if (active_requests_.load() == 0) {
            state_.store(State::IDLE);
        }
        
        // Update statistics
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (result) {
                stats_.bytes_sent += data.size();
                stats_.records_sent++;
            } else {
                stats_.protocol_errors++;
            }
        }
        
        return result;
    }

    Result<std::vector<uint8_t>> receive_data(std::chrono::milliseconds timeout) override {
        if (state_.load() != State::CONNECTED && state_.load() != State::IDLE) {
            return make_error<std::vector<uint8_t>>(DTLSError::CONNECTION_STATE_ERROR);
        }

        active_requests_.fetch_add(1);
        state_.store(State::BUSY);
        
        // Receive through underlying connection
        auto result = underlying_connection_->receive(timeout);
        
        active_requests_.fetch_sub(1);
        if (active_requests_.load() == 0) {
            state_.store(State::IDLE);
        }
        
        // Update activity timestamp and statistics
        if (result) {
            last_activity_ = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(mutex_);
            stats_.bytes_received += result.value().size();
            stats_.records_received++;
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            stats_.protocol_errors++;
        }
        
        return result;
    }

    bool is_available() const override {
        auto current_state = state_.load();
        return (current_state == State::CONNECTED || current_state == State::IDLE) &&
               health_.is_healthy() &&
               active_requests_.load() < 10; // Max concurrent requests per connection
    }

    double get_load() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return calculate_connection_load(stats_, 10);
    }

    Result<void> migrate_to(const transport::NetworkEndpoint& new_endpoint) override {
        if (state_.load() != State::CONNECTED && state_.load() != State::IDLE) {
            return make_error_void(DTLSError::CONNECTION_STATE_ERROR);
        }

        state_.store(State::MIGRATING);
        
        // Perform connection migration (simplified)
        // In a real implementation, this would involve DTLS connection migration
        current_endpoint_ = new_endpoint;
        
        state_.store(State::CONNECTED);
        return make_success();
    }

    Result<ConnectionHealth> perform_health_check() override {
        auto start_time = std::chrono::steady_clock::now();
        
        // Simple health check - send ping and measure response time
        std::vector<uint8_t> ping_data = {0x01, 0x02, 0x03, 0x04}; // Simple ping
        auto send_result = send_data(ping_data);
        
        ConnectionHealth new_health;
        new_health.last_health_check = std::chrono::steady_clock::now();
        
        if (send_result) {
            auto end_time = std::chrono::steady_clock::now();
            new_health.last_response_time = std::chrono::duration_cast<std::chrono::microseconds>(
                end_time - start_time);
            new_health.status = ConnectionHealth::Status::HEALTHY;
            new_health.consecutive_failures = 0;
            new_health.status_message = "Health check passed";
        } else {
            new_health.status = ConnectionHealth::Status::UNHEALTHY;
            new_health.consecutive_failures = health_.consecutive_failures + 1;
            new_health.status_message = "Health check failed: " + send_result.error_message();
        }
        
        // Update error rate calculation
        {
            std::lock_guard<std::mutex> lock(mutex_);
            double total_operations = stats_.records_sent + stats_.records_received;
            if (total_operations > 0) {
                new_health.error_rate = static_cast<double>(stats_.protocol_errors) / total_operations;
            }
            health_ = new_health;
        }
        
        return make_result(new_health);
    }

    Result<void> close(std::chrono::milliseconds timeout) override {
        state_.store(State::DISCONNECTING);
        
        // Close underlying connection
        auto result = underlying_connection_->close();
        
        state_.store(State::CLOSED);
        return result;
    }

    Result<void> reset() override {
        state_.store(State::INITIALIZING);
        active_requests_.store(0);
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stats_ = ConnectionStats{}; // Reset statistics
            health_.status = ConnectionHealth::Status::UNKNOWN;
            health_.consecutive_failures = 0;
        }
        
        state_.store(State::CONNECTED);
        return make_success();
    }

    // Additional methods for internal use
    void set_state(State new_state) {
        state_.store(new_state);
    }

    std::chrono::steady_clock::time_point get_last_activity() const {
        return last_activity_;
    }

    std::chrono::steady_clock::time_point get_creation_time() const {
        return creation_time_;
    }

    const transport::NetworkEndpoint& get_endpoint() const {
        return current_endpoint_;
    }
};

/**
 * @brief Load balancer implementation
 */
class LoadBalancerImpl : public LoadBalancer {
private:
    ConnectionPoolConfig::LoadBalancingStrategy strategy_;
    std::mutex mutex_;
    std::unordered_map<std::string, double> connection_weights_;
    std::atomic<size_t> round_robin_counter_{0};

public:
    explicit LoadBalancerImpl(ConnectionPoolConfig::LoadBalancingStrategy strategy)
        : strategy_(strategy) {}

    Result<std::shared_ptr<ManagedConnection>> select_connection(
        const std::vector<std::shared_ptr<ManagedConnection>>& available_connections,
        const transport::NetworkEndpoint& target_endpoint) override {
        
        if (available_connections.empty()) {
            return make_error<std::shared_ptr<ManagedConnection>>(DTLSError::CONNECTION_NOT_FOUND);
        }

        // Filter only available connections
        std::vector<std::shared_ptr<ManagedConnection>> healthy_connections;
        for (const auto& conn : available_connections) {
            if (conn->is_available()) {
                healthy_connections.push_back(conn);
            }
        }

        if (healthy_connections.empty()) {
            return make_error<std::shared_ptr<ManagedConnection>>(DTLSError::CONNECTION_NOT_FOUND);
        }

        switch (strategy_) {
            case ConnectionPoolConfig::LoadBalancingStrategy::ROUND_ROBIN:
                return select_round_robin(healthy_connections);
            
            case ConnectionPoolConfig::LoadBalancingStrategy::LEAST_CONNECTIONS:
                return select_least_connections(healthy_connections);
            
            case ConnectionPoolConfig::LoadBalancingStrategy::LEAST_RESPONSE_TIME:
                return select_least_response_time(healthy_connections);
            
            case ConnectionPoolConfig::LoadBalancingStrategy::WEIGHTED_ROUND_ROBIN:
                return select_weighted_round_robin(healthy_connections);
            
            case ConnectionPoolConfig::LoadBalancingStrategy::CONSISTENT_HASHING:
                return select_consistent_hashing(healthy_connections, target_endpoint);
            
            case ConnectionPoolConfig::LoadBalancingStrategy::ADAPTIVE:
                return select_adaptive(healthy_connections);
            
            default:
                return select_round_robin(healthy_connections);
        }
    }

    Result<void> update_weights(
        const std::unordered_map<std::string, double>& connection_weights) override {
        std::lock_guard<std::mutex> lock(mutex_);
        connection_weights_ = connection_weights;
        return make_success();
    }

    ConnectionPoolConfig::LoadBalancingStrategy get_strategy() const override {
        return strategy_;
    }

private:
    Result<std::shared_ptr<ManagedConnection>> select_round_robin(
        const std::vector<std::shared_ptr<ManagedConnection>>& connections) {
        size_t index = round_robin_counter_.fetch_add(1) % connections.size();
        return make_result(connections[index]);
    }

    Result<std::shared_ptr<ManagedConnection>> select_least_connections(
        const std::vector<std::shared_ptr<ManagedConnection>>& connections) {
        auto best_conn = std::min_element(connections.begin(), connections.end(),
            [](const auto& a, const auto& b) {
                return a->get_load() < b->get_load();
            });
        return make_result(*best_conn);
    }

    Result<std::shared_ptr<ManagedConnection>> select_least_response_time(
        const std::vector<std::shared_ptr<ManagedConnection>>& connections) {
        auto best_conn = std::min_element(connections.begin(), connections.end(),
            [](const auto& a, const auto& b) {
                auto health_a = a->get_health();
                auto health_b = b->get_health();
                return health_a.last_response_time < health_b.last_response_time;
            });
        return make_result(*best_conn);
    }

    Result<std::shared_ptr<ManagedConnection>> select_weighted_round_robin(
        const std::vector<std::shared_ptr<ManagedConnection>>& connections) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Calculate total weight
        double total_weight = 0.0;
        for (const auto& conn : connections) {
            auto it = connection_weights_.find(conn->get_connection_id());
            if (it != connection_weights_.end()) {
                total_weight += it->second;
            } else {
                total_weight += 1.0; // Default weight
            }
        }

        // Generate random value and select connection
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, total_weight);
        double random_value = dis(gen);

        double cumulative_weight = 0.0;
        for (const auto& conn : connections) {
            auto it = connection_weights_.find(conn->get_connection_id());
            double weight = (it != connection_weights_.end()) ? it->second : 1.0;
            cumulative_weight += weight;
            
            if (random_value <= cumulative_weight) {
                return make_result(conn);
            }
        }

        // Fallback to first connection
        return make_result(connections[0]);
    }

    Result<std::shared_ptr<ManagedConnection>> select_consistent_hashing(
        const std::vector<std::shared_ptr<ManagedConnection>>& connections,
        const transport::NetworkEndpoint& target_endpoint) {
        
        // Simple consistent hashing based on endpoint
        std::hash<std::string> hasher;
        size_t endpoint_hash = hasher(target_endpoint.to_string());
        size_t index = endpoint_hash % connections.size();
        
        return make_result(connections[index]);
    }

    Result<std::shared_ptr<ManagedConnection>> select_adaptive(
        const std::vector<std::shared_ptr<ManagedConnection>>& connections) {
        // Adaptive strategy combines multiple factors
        double best_score = std::numeric_limits<double>::max();
        std::shared_ptr<ManagedConnection> best_connection;

        for (const auto& conn : connections) {
            auto health = conn->get_health();
            double load = conn->get_load();
            
            // Calculate composite score (lower is better)
            double response_time_score = static_cast<double>(health.last_response_time.count()) / 1000.0;
            double load_score = load * 100.0;
            double error_score = health.error_rate * 1000.0;
            
            double composite_score = response_time_score + load_score + error_score;
            
            if (composite_score < best_score) {
                best_score = composite_score;
                best_connection = conn;
            }
        }

        if (best_connection) {
            return make_result(best_connection);
        }

        return make_result(connections[0]); // Fallback
    }
};

/**
 * @brief Connection pool implementation
 */
class ConnectionPoolImpl : public ConnectionPool {
private:
    ConnectionPoolConfig config_;
    std::unique_ptr<LoadBalancer> load_balancer_;
    
    mutable std::mutex pool_mutex_;
    std::vector<std::shared_ptr<ManagedConnectionImpl>> all_connections_;
    std::queue<std::shared_ptr<ManagedConnectionImpl>> available_connections_;
    std::unordered_set<std::shared_ptr<ManagedConnectionImpl>> active_connections_;
    
    std::atomic<bool> running_{false};
    std::thread maintenance_thread_;
    ConnectionPoolStats stats_;
    
    mutable std::mutex stats_mutex_;

public:
    explicit ConnectionPoolImpl(const ConnectionPoolConfig& config)
        : config_(config)
        , load_balancer_(AdvancedConnectionManagerFactory::create_load_balancer(config.load_balancing_strategy)) {
        
        stats_.pool_start_time = std::chrono::steady_clock::now();
    }

    ~ConnectionPoolImpl() {
        if (running_.load()) {
            shutdown(std::chrono::milliseconds(5000));
        }
    }

    Result<std::shared_ptr<ManagedConnection>> acquire_connection(
        const transport::NetworkEndpoint& endpoint,
        std::chrono::milliseconds timeout) override {
        
        std::unique_lock<std::mutex> lock(pool_mutex_);
        
        // Try to find existing connection to the same endpoint
        for (auto& conn : all_connections_) {
            if (conn->get_endpoint().to_string() == endpoint.to_string() && 
                conn->is_available()) {
                
                // Move from available to active
                remove_from_available_queue(conn);
                active_connections_.insert(conn);
                
                update_stats_on_acquire();
                return std::static_pointer_cast<ManagedConnection>(conn);
            }
        }
        
        // If no existing connection, try to get one from available pool
        if (!available_connections_.empty()) {
            auto conn = available_connections_.front();
            available_connections_.pop();
            active_connections_.insert(conn);
            
            update_stats_on_acquire();
            return std::static_pointer_cast<ManagedConnection>(conn);
        }
        
        // Create new connection if under pool limit
        if (all_connections_.size() < config_.max_pool_size) {
            auto new_conn = create_new_connection(endpoint);
            if (new_conn) {
                all_connections_.push_back(new_conn);
                active_connections_.insert(new_conn);
                
                update_stats_on_acquire();
                return std::static_pointer_cast<ManagedConnection>(new_conn);
            }
        }
        
        return make_error<std::shared_ptr<ManagedConnection>>(DTLSError::RESOURCE_UNAVAILABLE);
    }

    Result<void> release_connection(
        const std::shared_ptr<ManagedConnection>& connection) override {
        
        auto managed_conn = std::static_pointer_cast<ManagedConnectionImpl>(connection);
        
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        // Move from active to available
        active_connections_.erase(managed_conn);
        
        if (managed_conn->is_available()) {
            available_connections_.push(managed_conn);
            managed_conn->set_state(ManagedConnection::State::IDLE);
        }
        
        update_stats_on_release();
        return make_success();
    }

    ConnectionPoolStats get_statistics() const override {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        std::lock_guard<std::mutex> pool_lock(pool_mutex_);
        
        ConnectionPoolStats current_stats = stats_;
        current_stats.total_connections = all_connections_.size();
        current_stats.active_connections = active_connections_.size();
        current_stats.idle_connections = available_connections_.size();
        current_stats.last_update_time = std::chrono::steady_clock::now();
        
        // Calculate utilization
        if (config_.max_pool_size > 0) {
            current_stats.pool_utilization_ratio = 
                static_cast<double>(current_stats.total_connections) / config_.max_pool_size;
        }
        
        return current_stats;
    }

    Result<void> update_configuration(const ConnectionPoolConfig& config) override {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        config_ = config;
        return make_success();
    }

    Result<void> perform_maintenance() override {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        
        // Remove expired connections
        auto it = all_connections_.begin();
        while (it != all_connections_.end()) {
            auto& conn = *it;
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - conn->get_creation_time());
            auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
                now - conn->get_last_activity());
            
            bool should_remove = false;
            
            // Check age limit
            if (age > config_.max_connection_age) {
                should_remove = true;
            }
            
            // Check idle timeout
            if (idle_time > config_.idle_timeout && 
                conn->get_state() == ManagedConnection::State::IDLE) {
                should_remove = true;
            }
            
            // Check health
            if (!conn->get_health().is_healthy()) {
                should_remove = true;
            }
            
            if (should_remove) {
                // Remove from all containers
                active_connections_.erase(conn);
                remove_from_available_queue(conn);
                conn->close(std::chrono::milliseconds(1000));
                it = all_connections_.erase(it);
            } else {
                ++it;
            }
        }
        
        // Ensure minimum pool size
        while (all_connections_.size() < config_.min_pool_size) {
            // Create placeholder connection (would need actual endpoint)
            transport::NetworkEndpoint placeholder_endpoint;
            auto new_conn = create_new_connection(placeholder_endpoint);
            if (new_conn) {
                all_connections_.push_back(new_conn);
                available_connections_.push(new_conn);
            } else {
                break; // Failed to create connection
            }
        }
        
        return make_success();
    }

    Result<void> shutdown(std::chrono::milliseconds timeout) override {
        running_.store(false);
        
        if (maintenance_thread_.joinable()) {
            maintenance_thread_.join();
        }
        
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        // Close all connections
        for (auto& conn : all_connections_) {
            conn->close(std::chrono::milliseconds(1000));
        }
        
        all_connections_.clear();
        active_connections_.clear();
        while (!available_connections_.empty()) {
            available_connections_.pop();
        }
        
        return make_success();
    }

    std::vector<std::pair<std::string, ConnectionHealth>> get_connection_health() const override {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        std::vector<std::pair<std::string, ConnectionHealth>> health_info;
        for (const auto& conn : all_connections_) {
            health_info.emplace_back(conn->get_connection_id(), conn->get_health());
        }
        
        return health_info;
    }

private:
    std::shared_ptr<ManagedConnectionImpl> create_new_connection(
        const transport::NetworkEndpoint& endpoint) {
        
        // In a real implementation, this would create an actual DTLS connection
        // For now, create a mock connection
        auto base_connection = std::shared_ptr<Connection>{}; // Would create real connection
        
        auto managed_conn = std::make_shared<ManagedConnectionImpl>(base_connection, endpoint);
        managed_conn->set_state(ManagedConnection::State::CONNECTED);
        
        return managed_conn;
    }

    void remove_from_available_queue(const std::shared_ptr<ManagedConnectionImpl>& target) {
        std::queue<std::shared_ptr<ManagedConnectionImpl>> temp_queue;
        
        while (!available_connections_.empty()) {
            auto conn = available_connections_.front();
            available_connections_.pop();
            
            if (conn != target) {
                temp_queue.push(conn);
            }
        }
        
        available_connections_ = std::move(temp_queue);
    }

    void update_stats_on_acquire() {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.total_requests_served++;
    }

    void update_stats_on_release() {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        // Update release-related statistics
    }

    void start_maintenance_thread() {
        running_.store(true);
        maintenance_thread_ = std::thread([this]() {
            while (running_.load()) {
                std::this_thread::sleep_for(config_.pool_cleanup_interval);
                perform_maintenance();
            }
        });
    }
};

// Factory implementations
std::unique_ptr<ConnectionPool> AdvancedConnectionManagerFactory::create_connection_pool(
    const ConnectionPoolConfig& config) {
    return std::make_unique<ConnectionPoolImpl>(config);
}

std::unique_ptr<LoadBalancer> AdvancedConnectionManagerFactory::create_load_balancer(
    ConnectionPoolConfig::LoadBalancingStrategy strategy) {
    return std::make_unique<LoadBalancerImpl>(strategy);
}

std::unique_ptr<HealthMonitor> AdvancedConnectionManagerFactory::create_health_monitor(
    std::chrono::seconds check_interval) {
    // Implementation would go here
    return nullptr; // Placeholder
}

std::unique_ptr<MigrationManager> AdvancedConnectionManagerFactory::create_migration_manager() {
    // Implementation would go here
    return nullptr; // Placeholder
}

/**
 * @brief Advanced connection manager implementation
 */
class AdvancedConnectionManagerImpl : public AdvancedConnectionManager {
private:
    std::unique_ptr<ConnectionPool> connection_pool_;
    std::unique_ptr<LoadBalancer> load_balancer_;
    std::unique_ptr<HealthMonitor> health_monitor_;
    std::unique_ptr<MigrationManager> migration_manager_;
    ConnectionPoolConfig config_;
    
    // Event callbacks
    std::vector<std::function<void(const std::string&, ConnectionEvent, const std::string&)>> event_callbacks_;
    std::vector<std::function<void(const std::string&, const ConnectionHealth&)>> health_callbacks_;
    
    mutable std::mutex callbacks_mutex_;

public:
    explicit AdvancedConnectionManagerImpl(const ConnectionPoolConfig& config)
        : config_(config) {
        
        connection_pool_ = AdvancedConnectionManagerFactory::create_connection_pool(config);
        load_balancer_ = AdvancedConnectionManagerFactory::create_load_balancer(config.load_balancing_strategy);
        health_monitor_ = AdvancedConnectionManagerFactory::create_health_monitor(config.health_check_interval);
        migration_manager_ = AdvancedConnectionManagerFactory::create_migration_manager();
    }

    Result<void> initialize() override {
        // Initialize all components
        return make_success();
    }

    Result<void> shutdown(std::chrono::milliseconds timeout) override {
        auto result = connection_pool_->shutdown(timeout);
        
        if (health_monitor_) {
            health_monitor_->stop_monitoring();
        }
        
        return result;
    }

    Result<std::shared_ptr<ManagedConnection>> get_connection(
        const transport::NetworkEndpoint& endpoint,
        std::chrono::milliseconds timeout) override {
        
        return connection_pool_->acquire_connection(endpoint, timeout);
    }

    Result<void> release_connection(
        const std::shared_ptr<ManagedConnection>& connection) override {
        
        return connection_pool_->release_connection(connection);
    }

    ConnectionPoolStats get_statistics() const override {
        return connection_pool_->get_statistics();
    }

    Result<void> update_configuration(const ConnectionPoolConfig& config) override {
        config_ = config;
        return connection_pool_->update_configuration(config);
    }

    void register_event_callback(
        std::function<void(const std::string&, ConnectionEvent, const std::string&)> callback) override {
        
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        event_callbacks_.push_back(std::move(callback));
    }

    void register_health_callback(
        std::function<void(const std::string&, const ConnectionHealth&)> callback) override {
        
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        health_callbacks_.push_back(std::move(callback));
    }

    Result<std::unordered_map<std::string, ConnectionHealth>> perform_health_check() override {
        auto health_info = connection_pool_->get_connection_health();
        
        std::unordered_map<std::string, ConnectionHealth> health_map;
        for (const auto& [conn_id, health] : health_info) {
            health_map[conn_id] = health;
        }
        
        return make_result(std::move(health_map));
    }

    std::vector<std::shared_ptr<ManagedConnection>> get_all_connections() const override {
        // Would need to implement in connection pool
        return {};
    }

    Result<void> migrate_connection(
        const std::string& connection_id,
        const transport::NetworkEndpoint& new_endpoint) override {
        
        if (migration_manager_) {
            return migration_manager_->migrate_connection(connection_id, new_endpoint);
        }
        
        return make_error_void(DTLSError::OPERATION_NOT_SUPPORTED);
    }

    std::shared_ptr<ManagedConnection> get_connection_by_id(
        const std::string& connection_id) const override {
        
        // Would need to implement in connection pool
        return nullptr;
    }

    Result<void> close_connection(
        const std::string& connection_id,
        std::chrono::milliseconds timeout) override {
        
        auto connection = get_connection_by_id(connection_id);
        if (connection) {
            return connection->close(timeout);
        }
        
        return make_error_void(DTLSError::CONNECTION_NOT_FOUND);
    }

    Result<size_t> close_idle_connections() override {
        // Would implement in connection pool
        return make_result(static_cast<size_t>(0));
    }

    double get_pool_health_score() const override {
        auto stats = get_statistics();
        
        if (stats.total_connections == 0) {
            return 0.0;
        }
        
        // Calculate health score based on various factors
        double connection_health = static_cast<double>(stats.active_connections + stats.idle_connections) / 
                                 stats.total_connections;
        double success_rate = stats.connection_success_rate;
        double utilization = std::min(1.0, stats.pool_utilization_ratio);
        
        return (connection_health * 0.4 + success_rate * 0.4 + utilization * 0.2);
    }

private:
    void notify_event_callbacks(const std::string& connection_id, 
                               ConnectionEvent event, 
                               const std::string& message) {
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        for (const auto& callback : event_callbacks_) {
            try {
                callback(connection_id, event, message);
            } catch (...) {
                // Ignore callback exceptions
            }
        }
    }

    void notify_health_callbacks(const std::string& connection_id, 
                               const ConnectionHealth& health) {
        std::lock_guard<std::mutex> lock(callbacks_mutex_);
        for (const auto& callback : health_callbacks_) {
            try {
                callback(connection_id, health);
            } catch (...) {
                // Ignore callback exceptions
            }
        }
    }
};

// Factory method for AdvancedConnectionManager
std::unique_ptr<AdvancedConnectionManager> AdvancedConnectionManager::create(
    const ConnectionPoolConfig& config) {
    return std::make_unique<AdvancedConnectionManagerImpl>(config);
}

} // namespace advanced
} // namespace connection
} // namespace v13
} // namespace dtls