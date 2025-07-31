#pragma once

#include <dtls/connection.h>
#include <dtls/security/dos_protection.h>
#include <dtls/result.h>
#include <dtls/types.h>

#include <memory>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>

namespace dtls {
namespace v13 {
namespace security {

/**
 * Enhanced connection manager with integrated DoS protection
 */
class DTLS_API SecureConnectionManager {
public:
    explicit SecureConnectionManager(
        std::unique_ptr<DoSProtection> dos_protection = DoSProtectionFactory::create_production()
    );
    ~SecureConnectionManager();
    
    // Non-copyable, movable
    SecureConnectionManager(const SecureConnectionManager&) = delete;
    SecureConnectionManager& operator=(const SecureConnectionManager&) = delete;
    SecureConnectionManager(SecureConnectionManager&&) noexcept = default;
    SecureConnectionManager& operator=(SecureConnectionManager&&) noexcept = default;
    
    /**
     * Create a new server connection with DoS protection
     * @param config Connection configuration
     * @param crypto_provider Cryptographic provider
     * @param client_address Client address
     * @param request_size Size of initial request (for DoS assessment)
     * @param event_callback Event callback function
     * @return Connection or error if DoS protection blocks
     */
    Result<std::unique_ptr<Connection>> create_secure_server_connection(
        const ConnectionConfig& config,
        std::unique_ptr<crypto::CryptoProvider> crypto_provider,
        const NetworkAddress& client_address,
        size_t request_size = 0,
        ConnectionEventCallback event_callback = nullptr
    );
    
    /**
     * Check if handshake attempt should be allowed
     * @param client_address Client address
     * @param handshake_size Size of handshake message
     * @return DoS protection result
     */
    DoSProtectionResult check_handshake_attempt(
        const NetworkAddress& client_address,
        size_t handshake_size = 0
    );
    
    /**
     * Record successful handshake completion
     * @param client_address Client address
     * @param connection_id Connection identifier
     */
    void record_handshake_success(
        const NetworkAddress& client_address,
        const ConnectionID& connection_id
    );
    
    /**
     * Record handshake failure
     * @param client_address Client address
     * @param failure_reason Reason for failure
     */
    void record_handshake_failure(
        const NetworkAddress& client_address,
        const std::string& failure_reason
    );
    
    /**
     * Add a connection to the manager
     * @param connection Connection to add
     * @param client_address Client address
     * @return Result of operation
     */
    Result<void> add_connection(
        std::unique_ptr<Connection> connection,
        const NetworkAddress& client_address
    );
    
    /**
     * Remove a connection from the manager
     * @param connection_id Connection ID
     * @return Result of operation
     */
    Result<void> remove_connection(const ConnectionID& connection_id);
    
    /**
     * Find connection by connection ID
     * @param connection_id Connection ID
     * @return Connection pointer or error
     */
    Result<Connection*> find_connection(const ConnectionID& connection_id);
    
    /**
     * Find connection by client address
     * @param client_address Client address
     * @return Connection pointer or error
     */
    Result<Connection*> find_connection(const NetworkAddress& client_address);
    
    /**
     * Get all active connections
     * @return Vector of connection pointers
     */
    std::vector<Connection*> get_all_connections();
    
    /**
     * Close all connections
     */
    void close_all_connections();
    
    /**
     * Get connection count
     * @return Number of active connections
     */
    size_t get_connection_count() const;
    
    /**
     * Cleanup closed connections and expired DoS protection entries
     */
    void cleanup_connections();
    
    /**
     * Record security violation
     * @param client_address Client address
     * @param violation_type Type of violation
     * @param severity Severity level
     */
    void record_security_violation(
        const NetworkAddress& client_address,
        const std::string& violation_type,
        const std::string& severity = "medium"
    );
    
    /**
     * Add source to whitelist
     * @param client_address Client address to whitelist
     */
    Result<void> add_to_whitelist(const NetworkAddress& client_address);
    
    /**
     * Remove source from whitelist
     * @param client_address Client address to remove from whitelist
     */
    Result<void> remove_from_whitelist(const NetworkAddress& client_address);
    
    /**
     * Blacklist a source address
     * @param client_address Client address to blacklist
     * @param duration Blacklist duration (0 = use default)
     */
    Result<void> blacklist_source(
        const NetworkAddress& client_address,
        std::chrono::seconds duration = std::chrono::seconds{0}
    );
    
    /**
     * Remove source from blacklist
     * @param client_address Client address to remove from blacklist
     */
    Result<void> remove_from_blacklist(const NetworkAddress& client_address);
    
    /**
     * Get DoS protection statistics
     */
    DoSProtectionStats get_dos_statistics() const;
    
    /**
     * Get rate limiting statistics
     */
    RateLimiter::OverallStats get_rate_limit_statistics() const;
    
    /**
     * Get resource management statistics
     */
    ResourceStats get_resource_statistics() const;
    
    /**
     * Get system health status
     */
    DoSProtection::SystemHealth get_system_health() const;
    
    /**
     * Get connection statistics per source
     */
    struct SourceConnectionStats {
        size_t active_connections = 0;
        size_t total_connections = 0;
        size_t failed_attempts = 0;
        size_t security_violations = 0;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_activity;
        bool is_whitelisted = false;
        bool is_blacklisted = false;
    };
    
    /**
     * Get connection statistics for a specific source
     * @param client_address Client address
     * @return Source statistics or error if not found
     */
    Result<SourceConnectionStats> get_source_statistics(const NetworkAddress& client_address) const;
    
    /**
     * Get sources with high connection counts
     * @param threshold Connection count threshold
     * @return List of addresses with high connection counts
     */
    std::vector<NetworkAddress> get_high_connection_sources(size_t threshold = 10) const;
    
    /**
     * Force system cleanup and health check
     */
    void force_cleanup_and_health_check();
    
    /**
     * Update DoS protection configuration
     * @param new_config New DoS protection configuration
     */
    Result<void> update_dos_config(const DoSProtectionConfig& new_config);
    
    /**
     * Get current DoS protection configuration
     */
    const DoSProtectionConfig& get_dos_config() const;
    
    /**
     * Enable/disable specific protection features
     */
    void enable_cpu_monitoring(bool enabled);
    void enable_proof_of_work(bool enabled);
    void enable_geoblocking(bool enabled);
    void enable_source_validation(bool enabled);

private:
    // Connection tracking structure
    struct ManagedConnection {
        std::unique_ptr<Connection> connection;
        NetworkAddress client_address;
        uint64_t resource_allocation_id;
        std::chrono::steady_clock::time_point creation_time;
        std::chrono::steady_clock::time_point last_activity;
        
        ManagedConnection(std::unique_ptr<Connection> conn, 
                         const NetworkAddress& addr, 
                         uint64_t resource_id)
            : connection(std::move(conn))
            , client_address(addr)
            , resource_allocation_id(resource_id) {
            auto now = std::chrono::steady_clock::now();
            creation_time = now;
            last_activity = now;
        }
    };
    
    // Source tracking structure
    struct SourceTracker {
        size_t active_connections = 0;
        size_t total_connections = 0;
        size_t failed_attempts = 0;
        size_t security_violations = 0;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_activity;
        std::vector<ConnectionID> connection_ids;
        mutable std::mutex connections_mutex;
        
        SourceTracker() {
            auto now = std::chrono::steady_clock::now();
            first_seen = now;
            last_activity = now;
        }
    };
    
    // Helper methods
    std::string address_to_key(const NetworkAddress& address) const;
    SourceTracker* get_or_create_source_tracker(const NetworkAddress& client_address);
    SourceTracker* get_source_tracker(const NetworkAddress& client_address) const;
    void update_source_activity(const NetworkAddress& client_address);
    void cleanup_inactive_trackers();
    ConnectionID generate_connection_id();
    
    // DoS protection
    std::unique_ptr<DoSProtection> dos_protection_;
    
    // Connection management
    std::unordered_map<ConnectionID, std::unique_ptr<ManagedConnection>> connections_;
    std::unordered_map<NetworkAddress, ConnectionID> address_to_connection_;
    mutable std::shared_mutex connections_mutex_;
    
    // Source tracking
    std::unordered_map<std::string, std::unique_ptr<SourceTracker>> source_trackers_;
    mutable std::shared_mutex source_trackers_mutex_;
    
    // Statistics and monitoring
    std::atomic<size_t> total_connection_attempts_{0};
    std::atomic<size_t> successful_connections_{0};
    std::atomic<size_t> failed_connections_{0};
    std::atomic<size_t> dos_blocked_connections_{0};
    
    // Cleanup management
    std::atomic<std::chrono::steady_clock::time_point> last_cleanup_;
    std::chrono::seconds cleanup_interval_{60};  // Cleanup every minute
    
    // Connection ID generation
    std::atomic<uint64_t> next_connection_id_{1};
};

/**
 * Factory for creating secure connection managers with different configurations
 */
class SecureConnectionManagerFactory {
public:
    /**
     * Create secure connection manager for development
     */
    static std::unique_ptr<SecureConnectionManager> create_development();
    
    /**
     * Create secure connection manager for production
     */
    static std::unique_ptr<SecureConnectionManager> create_production();
    
    /**
     * Create secure connection manager for high-security environments
     */
    static std::unique_ptr<SecureConnectionManager> create_high_security();
    
    /**
     * Create secure connection manager for embedded systems
     */
    static std::unique_ptr<SecureConnectionManager> create_embedded();
    
    /**
     * Create secure connection manager with custom DoS protection
     */
    static std::unique_ptr<SecureConnectionManager> create_custom(
        std::unique_ptr<DoSProtection> dos_protection
    );
};

}  // namespace security
}  // namespace v13
}  // namespace dtls