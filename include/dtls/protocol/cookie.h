#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory.h"
#include <cstdint>
#include <vector>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <array>

namespace dtls::v13::protocol {

// Forward declarations
struct Extension;

/**
 * Cookie Generator Configuration
 */
struct CookieConfig {
    // Cookie lifetime before expiration
    std::chrono::seconds cookie_lifetime{300}; // 5 minutes
    
    // Maximum number of outstanding cookies per client
    uint32_t max_cookies_per_client{10};
    
    // Cookie size in bytes (minimum 8, maximum 255)
    uint8_t cookie_size{32};
    
    // Enable strict cookie validation
    bool strict_validation{true};
    
    // Cookie cleanup interval
    std::chrono::seconds cleanup_interval{60}; // 1 minute
    
    CookieConfig() = default;
};

/**
 * Cookie Exchange Manager
 * 
 * Implements RFC 9147 Section 4.2.1 Cookie exchange mechanism for DoS protection.
 * Generates and validates cookies to prevent resource exhaustion attacks.
 */
class DTLS_API CookieManager {
public:
    /**
     * Client information for cookie generation
     */
    struct ClientInfo {
        std::string client_address;     // IP address
        uint16_t client_port;          // Port number
        std::vector<uint8_t> client_hello_data; // First ClientHello data
        
        ClientInfo() = default;
        ClientInfo(const std::string& addr, uint16_t port, 
                  const std::vector<uint8_t>& hello_data)
            : client_address(addr), client_port(port), client_hello_data(hello_data) {}
        
        // Generate unique client identifier
        std::string get_client_id() const;
        
        bool operator==(const ClientInfo& other) const {
            return client_address == other.client_address && 
                   client_port == other.client_port;
        }
    };
    
    /**
     * Cookie validation result
     */
    enum class CookieValidationResult {
        VALID,                  // Cookie is valid and fresh
        INVALID,               // Cookie is malformed or invalid
        EXPIRED,               // Cookie has expired
        NOT_FOUND,             // Cookie not found in tracking
        CLIENT_MISMATCH,       // Cookie doesn't match client info
        REPLAY_DETECTED        // Potential replay attack detected
    };
    
    /**
     * Constructor
     */
    CookieManager();
    explicit CookieManager(const CookieConfig& config);
    
    /**
     * Destructor
     */
    ~CookieManager();
    
    // Non-copyable, movable
    CookieManager(const CookieManager&) = delete;
    CookieManager& operator=(const CookieManager&) = delete;
    // Move operations are deleted due to mutex member
    CookieManager(CookieManager&&) = delete;
    CookieManager& operator=(CookieManager&&) = delete;
    
    /**
     * Initialize the cookie manager with a secret key
     * @param secret_key Secret key for HMAC cookie generation (32 bytes recommended)
     */
    Result<void> initialize(const memory::Buffer& secret_key);
    
    /**
     * Generate a new cookie for a client
     * @param client_info Client information for cookie binding
     * @return Generated cookie buffer
     */
    Result<memory::Buffer> generate_cookie(const ClientInfo& client_info);
    
    /**
     * Validate a received cookie
     * @param cookie Cookie to validate
     * @param client_info Client information for validation
     * @return Validation result
     */
    CookieValidationResult validate_cookie(const memory::Buffer& cookie, 
                                         const ClientInfo& client_info);
    
    /**
     * Check if a client needs a cookie (first-time connection)
     * @param client_info Client information
     * @return True if client needs to provide a cookie
     */
    bool client_needs_cookie(const ClientInfo& client_info) const;
    
    /**
     * Mark a cookie as consumed (prevents replay)
     * @param cookie Cookie to mark as consumed
     * @param client_info Client information
     */
    void consume_cookie(const memory::Buffer& cookie, const ClientInfo& client_info);
    
    /**
     * Clean up expired cookies (call periodically)
     */
    void cleanup_expired_cookies();
    
    /**
     * Get cookie manager statistics
     */
    struct Statistics {
        uint64_t cookies_generated{0};
        uint64_t cookies_validated{0};
        uint64_t cookies_expired{0};
        uint64_t validation_failures{0};
        uint64_t replay_attempts{0};
        uint32_t active_cookies{0};
        
        Statistics() = default;
    };
    
    Statistics get_statistics() const;
    
    /**
     * Reset cookie manager state
     */
    void reset();
    
    /**
     * Update configuration
     */
    void update_config(const CookieConfig& new_config);
    
    /**
     * Get current configuration
     */
    const CookieConfig& get_config() const;

private:
    /**
     * Cookie tracking entry
     */
    struct CookieEntry {
        std::chrono::steady_clock::time_point creation_time;
        std::chrono::steady_clock::time_point last_access_time;
        ClientInfo client_info;
        bool consumed{false};
        uint32_t usage_count{0};
        
        CookieEntry() = default;
        CookieEntry(const ClientInfo& info)
            : creation_time(std::chrono::steady_clock::now()),
              last_access_time(creation_time),
              client_info(info) {}
        
        bool is_expired(std::chrono::seconds lifetime) const {
            auto now = std::chrono::steady_clock::now();
            return (now - creation_time) > lifetime;
        }
    };
    
    /**
     * Generate HMAC-based cookie
     */
    Result<memory::Buffer> generate_hmac_cookie(const ClientInfo& client_info, 
                                               uint64_t timestamp) const;
    
    /**
     * Verify HMAC-based cookie
     */
    bool verify_hmac_cookie(const memory::Buffer& cookie, 
                           const ClientInfo& client_info,
                           uint64_t& timestamp) const;
    
    /**
     * Generate cookie tracking key
     */
    std::string generate_cookie_key(const memory::Buffer& cookie) const;
    
    /**
     * Check if client has too many active cookies
     */
    bool client_has_too_many_cookies(const ClientInfo& client_info) const;
    
    /**
     * Remove cookies for client
     */
    void remove_client_cookies(const ClientInfo& client_info);
    
    // Configuration
    CookieConfig config_;
    
    // HMAC secret key for cookie generation
    memory::Buffer secret_key_;
    bool initialized_{false};
    
    // Cookie tracking
    std::unordered_map<std::string, CookieEntry> active_cookies_;
    std::unordered_map<std::string, std::vector<std::string>> client_cookie_mapping_;
    
    // Client authentication tracking (client_id -> last successful validation time)
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> authenticated_clients_;
    
    // Statistics
    mutable Statistics stats_;
    
    // Last cleanup time
    std::chrono::steady_clock::time_point last_cleanup_;
    
    // Thread safety
    mutable std::mutex mutex_;
};

/**
 * Cookie Utility Functions
 */

/**
 * Extract client information from network address
 * @param address Network address string (e.g., "192.168.1.1:443")
 * @param client_hello_data ClientHello message data
 * @return ClientInfo structure
 */
DTLS_API Result<CookieManager::ClientInfo> 
extract_client_info(const std::string& address, 
                    const std::vector<uint8_t>& client_hello_data);

/**
 * Create cookie extension for HelloRetryRequest
 * @param cookie Cookie buffer to include
 * @return Extension structure
 */
DTLS_API Result<Extension> create_cookie_extension(const memory::Buffer& cookie);

/**
 * Extract cookie from extension
 * @param extension Cookie extension
 * @return Cookie buffer
 */
DTLS_API Result<memory::Buffer> extract_cookie_from_extension(const Extension& extension);

/**
 * Validate cookie format (basic checks)
 * @param cookie Cookie buffer to validate
 * @return True if cookie format is valid
 */
DTLS_API bool is_valid_cookie_format(const memory::Buffer& cookie);

/**
 * Generate test cookie (for testing purposes only)
 * @param size Cookie size in bytes
 * @return Test cookie buffer
 */
DTLS_API memory::Buffer generate_test_cookie(size_t size = 32);

} // namespace dtls::v13::protocol