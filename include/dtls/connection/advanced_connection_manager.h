#pragma once

/**
 * @file advanced_connection_manager.h
 * @brief Advanced connection pooling and management for DTLS v1.3
 * 
 * Provides sophisticated connection management including connection pooling,
 * load balancing, automatic scaling, health monitoring, and connection migration.
 */

#include "dtls/types.h"
#include "dtls/error.h"
#include "dtls/result.h"
#include "dtls/connection.h"
#include "dtls/transport/udp_transport.h"
#include <memory>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <thread>
#include <atomic>

namespace dtls {
namespace v13 {
namespace connection {
namespace advanced {

/**
 * @brief Connection pool configuration
 */
struct ConnectionPoolConfig {
    // Pool sizing
    size_t initial_pool_size = 10;
    size_t max_pool_size = 1000;
    size_t min_pool_size = 5;
    
    // Connection lifecycle
    std::chrono::seconds idle_timeout{300};
    std::chrono::seconds max_connection_age{3600};
    std::chrono::seconds connection_establishment_timeout{30};
    
    // Pool management
    std::chrono::seconds health_check_interval{60};
    std::chrono::seconds pool_cleanup_interval{30};
    double pool_growth_factor = 1.5;
    double pool_shrink_factor = 0.75;
    
    // Load balancing
    enum class LoadBalancingStrategy {
        ROUND_ROBIN,
        LEAST_CONNECTIONS,
        WEIGHTED_ROUND_ROBIN,
        LEAST_RESPONSE_TIME,
        CONSISTENT_HASHING,
        ADAPTIVE
    };
    LoadBalancingStrategy load_balancing_strategy = LoadBalancingStrategy::LEAST_CONNECTIONS;
    
    // Performance tuning
    bool enable_connection_multiplexing = true;
    bool enable_connection_migration = true;
    bool enable_early_data = true;
    bool enable_session_resumption = true;
    size_t max_concurrent_handshakes = 50;
    
    // Monitoring
    bool enable_connection_metrics = true;
    bool enable_performance_monitoring = true;
    std::chrono::seconds metrics_collection_interval{10};
    
    ConnectionPoolConfig() = default;
};

/**
 * @brief Connection pool statistics
 */
struct ConnectionPoolStats {
    // Pool state
    size_t total_connections = 0;
    size_t active_connections = 0;
    size_t idle_connections = 0;
    size_t failed_connections = 0;
    size_t pending_connections = 0;
    
    // Performance metrics
    std::chrono::microseconds average_connection_time{0};
    std::chrono::microseconds average_handshake_time{0};
    double connection_success_rate = 0.0;
    double pool_utilization_ratio = 0.0;
    
    // Throughput metrics
    uint64_t total_requests_served = 0;
    uint64_t requests_per_second = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    
    // Error metrics
    uint64_t connection_failures = 0;
    uint64_t timeout_errors = 0;
    uint64_t handshake_failures = 0;
    uint64_t migration_failures = 0;
    
    // Timing
    std::chrono::steady_clock::time_point pool_start_time;
    std::chrono::steady_clock::time_point last_update_time;
    
    ConnectionPoolStats() : 
        pool_start_time(std::chrono::steady_clock::now()),
        last_update_time(std::chrono::steady_clock::now()) {}
        
    double get_uptime_seconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(now - pool_start_time).count();
    }
};

/**
 * @brief Connection health information
 */
struct ConnectionHealth {
    enum class Status {
        HEALTHY,
        DEGRADED,
        UNHEALTHY,
        UNKNOWN
    };
    
    Status status = Status::UNKNOWN;
    std::chrono::microseconds last_response_time{0};
    std::chrono::steady_clock::time_point last_health_check;
    uint32_t consecutive_failures = 0;
    double error_rate = 0.0;
    std::string status_message;
    
    bool is_healthy() const {
        return status == Status::HEALTHY;
    }
    
    bool needs_attention() const {
        return status == Status::DEGRADED || status == Status::UNHEALTHY;
    }
};

/**
 * @brief Advanced connection wrapper with enhanced capabilities
 */
class DTLS_API ManagedConnection {
public:
    /**
     * @brief Connection state enumeration
     */
    enum class State {
        INITIALIZING,
        CONNECTING,
        CONNECTED,
        IDLE,
        BUSY,
        MIGRATING,
        DISCONNECTING,
        FAILED,
        CLOSED
    };

    virtual ~ManagedConnection() = default;

    /**
     * @brief Get connection ID
     */
    virtual std::string get_connection_id() const = 0;

    /**
     * @brief Get current state
     */
    virtual State get_state() const = 0;

    /**
     * @brief Get health information
     */
    virtual ConnectionHealth get_health() const = 0;

    /**
     * @brief Get connection statistics
     */
    virtual ConnectionStats get_statistics() const = 0;

    /**
     * @brief Send data through connection
     */
    virtual Result<void> send_data(const std::vector<uint8_t>& data) = 0;

    /**
     * @brief Receive data from connection
     */
    virtual Result<std::vector<uint8_t>> receive_data(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000)
    ) = 0;

    /**
     * @brief Check if connection can handle new requests
     */
    virtual bool is_available() const = 0;

    /**
     * @brief Get connection load (0.0 to 1.0)
     */
    virtual double get_load() const = 0;

    /**
     * @brief Migrate connection to new endpoint
     */
    virtual Result<void> migrate_to(const transport::NetworkEndpoint& new_endpoint) = 0;

    /**
     * @brief Perform health check
     */
    virtual Result<ConnectionHealth> perform_health_check() = 0;

    /**
     * @brief Close connection gracefully
     */
    virtual Result<void> close(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) = 0;

    /**
     * @brief Reset connection
     */
    virtual Result<void> reset() = 0;
};

/**
 * @brief Connection pool interface
 */
class DTLS_API ConnectionPool {
public:
    virtual ~ConnectionPool() = default;

    /**
     * @brief Acquire connection from pool
     */
    virtual Result<std::shared_ptr<ManagedConnection>> acquire_connection(
        const transport::NetworkEndpoint& endpoint,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)
    ) = 0;

    /**
     * @brief Release connection back to pool
     */
    virtual Result<void> release_connection(
        const std::shared_ptr<ManagedConnection>& connection
    ) = 0;

    /**
     * @brief Get pool statistics
     */
    virtual ConnectionPoolStats get_statistics() const = 0;

    /**
     * @brief Update pool configuration
     */
    virtual Result<void> update_configuration(const ConnectionPoolConfig& config) = 0;

    /**
     * @brief Perform pool maintenance
     */
    virtual Result<void> perform_maintenance() = 0;

    /**
     * @brief Shutdown pool gracefully
     */
    virtual Result<void> shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds(30000)) = 0;

    /**
     * @brief Get health status of all connections
     */
    virtual std::vector<std::pair<std::string, ConnectionHealth>> get_connection_health() const = 0;
};

/**
 * @brief Load balancer interface
 */
class DTLS_API LoadBalancer {
public:
    virtual ~LoadBalancer() = default;

    /**
     * @brief Select best connection from available pool
     */
    virtual Result<std::shared_ptr<ManagedConnection>> select_connection(
        const std::vector<std::shared_ptr<ManagedConnection>>& available_connections,
        const transport::NetworkEndpoint& target_endpoint
    ) = 0;

    /**
     * @brief Update load balancing weights
     */
    virtual Result<void> update_weights(
        const std::unordered_map<std::string, double>& connection_weights
    ) = 0;

    /**
     * @brief Get load balancing strategy
     */
    virtual ConnectionPoolConfig::LoadBalancingStrategy get_strategy() const = 0;
};

/**
 * @brief Connection health monitor
 */
class DTLS_API HealthMonitor {
public:
    virtual ~HealthMonitor() = default;

    /**
     * @brief Start health monitoring
     */
    virtual Result<void> start_monitoring(
        const std::vector<std::shared_ptr<ManagedConnection>>& connections
    ) = 0;

    /**
     * @brief Stop health monitoring
     */
    virtual Result<void> stop_monitoring() = 0;

    /**
     * @brief Add connection to monitoring
     */
    virtual Result<void> add_connection(const std::shared_ptr<ManagedConnection>& connection) = 0;

    /**
     * @brief Remove connection from monitoring
     */
    virtual Result<void> remove_connection(const std::string& connection_id) = 0;

    /**
     * @brief Get health report for all monitored connections
     */
    virtual std::unordered_map<std::string, ConnectionHealth> get_health_report() const = 0;

    /**
     * @brief Register health change callback
     */
    virtual void register_health_callback(
        std::function<void(const std::string&, const ConnectionHealth&)> callback
    ) = 0;
};

/**
 * @brief Connection migration manager
 */
class DTLS_API MigrationManager {
public:
    virtual ~MigrationManager() = default;

    /**
     * @brief Migrate connection to new endpoint
     */
    virtual Result<void> migrate_connection(
        const std::string& connection_id,
        const transport::NetworkEndpoint& new_endpoint
    ) = 0;

    /**
     * @brief Check if migration is possible
     */
    virtual bool can_migrate_connection(const std::string& connection_id) const = 0;

    /**
     * @brief Get migration statistics
     */
    virtual struct MigrationStats {
        uint64_t successful_migrations = 0;
        uint64_t failed_migrations = 0;
        std::chrono::microseconds average_migration_time{0};
        uint64_t total_migrations = 0;
    } get_migration_statistics() const = 0;
};

/**
 * @brief Advanced connection manager factory
 */
class DTLS_API AdvancedConnectionManagerFactory {
public:
    /**
     * @brief Create connection pool
     */
    static std::unique_ptr<ConnectionPool> create_connection_pool(
        const ConnectionPoolConfig& config
    );

    /**
     * @brief Create load balancer
     */
    static std::unique_ptr<LoadBalancer> create_load_balancer(
        ConnectionPoolConfig::LoadBalancingStrategy strategy
    );

    /**
     * @brief Create health monitor
     */
    static std::unique_ptr<HealthMonitor> create_health_monitor(
        std::chrono::seconds check_interval = std::chrono::seconds(60)
    );

    /**
     * @brief Create migration manager
     */
    static std::unique_ptr<MigrationManager> create_migration_manager();
};

/**
 * @brief Advanced connection manager
 * 
 * Integrates connection pooling, load balancing, health monitoring,
 * and connection migration into a unified management system.
 */
class DTLS_API AdvancedConnectionManager {
public:
    /**
     * @brief Create advanced connection manager
     */
    static std::unique_ptr<AdvancedConnectionManager> create(
        const ConnectionPoolConfig& config
    );

    virtual ~AdvancedConnectionManager() = default;

    /**
     * @brief Initialize connection manager
     */
    virtual Result<void> initialize() = 0;

    /**
     * @brief Shutdown connection manager
     */
    virtual Result<void> shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds(30000)) = 0;

    /**
     * @brief Get or create connection to endpoint
     */
    virtual Result<std::shared_ptr<ManagedConnection>> get_connection(
        const transport::NetworkEndpoint& endpoint,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)
    ) = 0;

    /**
     * @brief Release connection
     */
    virtual Result<void> release_connection(
        const std::shared_ptr<ManagedConnection>& connection
    ) = 0;

    /**
     * @brief Get comprehensive statistics
     */
    virtual ConnectionPoolStats get_statistics() const = 0;

    /**
     * @brief Update configuration
     */
    virtual Result<void> update_configuration(const ConnectionPoolConfig& config) = 0;

    /**
     * @brief Register connection event callback
     */
    virtual void register_event_callback(
        std::function<void(const std::string&, ConnectionEvent, const std::string&)> callback
    ) = 0;

    /**
     * @brief Register health status callback
     */
    virtual void register_health_callback(
        std::function<void(const std::string&, const ConnectionHealth&)> callback
    ) = 0;

    /**
     * @brief Perform manual health check on all connections
     */
    virtual Result<std::unordered_map<std::string, ConnectionHealth>> perform_health_check() = 0;

    /**
     * @brief Get all managed connections
     */
    virtual std::vector<std::shared_ptr<ManagedConnection>> get_all_connections() const = 0;

    /**
     * @brief Force connection migration
     */
    virtual Result<void> migrate_connection(
        const std::string& connection_id,
        const transport::NetworkEndpoint& new_endpoint
    ) = 0;

    /**
     * @brief Get connection by ID
     */
    virtual std::shared_ptr<ManagedConnection> get_connection_by_id(
        const std::string& connection_id
    ) const = 0;

    /**
     * @brief Close specific connection
     */
    virtual Result<void> close_connection(
        const std::string& connection_id,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)
    ) = 0;

    /**
     * @brief Close all idle connections
     */
    virtual Result<size_t> close_idle_connections() = 0;

    /**
     * @brief Get connection pool health score (0.0 to 1.0)
     */
    virtual double get_pool_health_score() const = 0;
};

/**
 * @brief Connection metrics collector
 */
class DTLS_API ConnectionMetricsCollector {
public:
    virtual ~ConnectionMetricsCollector() = default;

    /**
     * @brief Start metrics collection
     */
    virtual Result<void> start_collection() = 0;

    /**
     * @brief Stop metrics collection
     */
    virtual Result<void> stop_collection() = 0;

    /**
     * @brief Record connection event
     */
    virtual void record_connection_event(
        const std::string& connection_id,
        ConnectionEvent event,
        std::chrono::microseconds duration = std::chrono::microseconds(0)
    ) = 0;

    /**
     * @brief Record performance metric
     */
    virtual void record_performance_metric(
        const std::string& metric_name,
        double value,
        const std::unordered_map<std::string, std::string>& tags = {}
    ) = 0;

    /**
     * @brief Get collected metrics
     */
    virtual std::unordered_map<std::string, double> get_metrics() const = 0;

    /**
     * @brief Export metrics in Prometheus format
     */
    virtual std::string export_prometheus_metrics() const = 0;

    /**
     * @brief Reset all metrics
     */
    virtual void reset_metrics() = 0;
};

} // namespace advanced
} // namespace connection
} // namespace v13
} // namespace dtls