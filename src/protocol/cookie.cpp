#include "dtls/protocol/cookie.h"
#include "dtls/protocol/handshake.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <numeric>

// Byte order conversion functions for systems that don't have them
#ifndef htobe64
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htobe64(x) __builtin_bswap64(x)
#define be64toh(x) __builtin_bswap64(x)
#else
#define htobe64(x) (x)
#define be64toh(x) (x)
#endif
#endif

namespace dtls::v13::protocol {

// Constants
static constexpr uint8_t COOKIE_VERSION = 0x01;
static constexpr uint32_t COOKIE_MAGIC = 0x444C5453; // "DLTS"
static constexpr size_t MIN_COOKIE_SIZE = 8;
static constexpr size_t MAX_COOKIE_SIZE = 255;
static constexpr size_t HMAC_SIZE = 32; // SHA-256 HMAC

// Cookie structure:
// [4 bytes: MAGIC] [1 byte: VERSION] [8 bytes: TIMESTAMP] [N bytes: HMAC]

// CookieManager::ClientInfo implementation
std::string CookieManager::ClientInfo::get_client_id() const {
    std::ostringstream oss;
    oss << client_address << ":" << client_port;
    return oss.str();
}

// CookieManager implementation
CookieManager::CookieManager() : CookieManager(CookieConfig{}) {}

CookieManager::CookieManager(const CookieConfig& config) 
    : config_(config), last_cleanup_(std::chrono::steady_clock::now()) {
    // Validate configuration
    if (config_.cookie_size < MIN_COOKIE_SIZE || config_.cookie_size > MAX_COOKIE_SIZE) {
        config_.cookie_size = 32; // Use default
    }
}

CookieManager::~CookieManager() = default;

// Move operations are deleted due to mutex member

Result<void> CookieManager::initialize(const memory::Buffer& secret_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (secret_key.size() < 16) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    secret_key_ = memory::Buffer(secret_key.data(), secret_key.size());
    initialized_ = true;
    
    return Result<void>();
}

Result<memory::Buffer> CookieManager::generate_cookie(const ClientInfo& client_info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return Result<memory::Buffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // Check if client has too many active cookies
    if (client_has_too_many_cookies(client_info)) {
        // Remove oldest cookies for this client
        remove_client_cookies(client_info);
    }
    
    // Generate timestamp
    auto now = std::chrono::steady_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    // Generate HMAC-based cookie
    auto cookie_result = generate_hmac_cookie(client_info, timestamp);
    if (!cookie_result.is_success()) {
        return cookie_result;
    }
    
    memory::Buffer cookie = std::move(cookie_result.value());
    
    // Track the cookie
    std::string cookie_key = generate_cookie_key(cookie);
    CookieEntry entry(client_info);
    active_cookies_[cookie_key] = entry;
    
    // Add to client mapping
    std::string client_id = client_info.get_client_id();
    client_cookie_mapping_[client_id].push_back(cookie_key);
    
    ++stats_.cookies_generated;
    stats_.active_cookies = active_cookies_.size();
    
    return Result<memory::Buffer>(std::move(cookie));
}

CookieManager::CookieValidationResult 
CookieManager::validate_cookie(const memory::Buffer& cookie, 
                              const ClientInfo& client_info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return CookieValidationResult::INVALID;
    }
    
    ++stats_.cookies_validated;
    
    // Basic format validation
    if (!is_valid_cookie_format(cookie)) {
        ++stats_.validation_failures;
        return CookieValidationResult::INVALID;
    }
    
    // Verify HMAC and extract timestamp
    uint64_t timestamp;
    if (!verify_hmac_cookie(cookie, client_info, timestamp)) {
        ++stats_.validation_failures;
        return CookieValidationResult::INVALID;
    }
    
    // Check expiration
    auto now = std::chrono::steady_clock::now();
    auto cookie_age = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count() - timestamp;
    
    if (cookie_age > config_.cookie_lifetime.count()) {
        ++stats_.cookies_expired;
        return CookieValidationResult::EXPIRED;
    }
    
    // Check if cookie is tracked and not consumed
    std::string cookie_key = generate_cookie_key(cookie);
    auto it = active_cookies_.find(cookie_key);
    
    if (it == active_cookies_.end()) {
        ++stats_.validation_failures;
        return CookieValidationResult::NOT_FOUND;
    }
    
    // Verify client information matches
    if (!(it->second.client_info == client_info)) {
        ++stats_.validation_failures;
        return CookieValidationResult::CLIENT_MISMATCH;
    }
    
    // Check for replay
    if (it->second.consumed) {
        ++stats_.replay_attempts;
        return CookieValidationResult::REPLAY_DETECTED;
    }
    
    // Update access time
    it->second.last_access_time = now;
    ++it->second.usage_count;
    
    return CookieValidationResult::VALID;
}

bool CookieManager::client_needs_cookie(const ClientInfo& client_info) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!config_.strict_validation) {
        return false; // No cookie required in non-strict mode
    }
    
    std::string client_id = client_info.get_client_id();
    auto it = client_cookie_mapping_.find(client_id);
    
    // If client has no active cookies, they need one
    if (it == client_cookie_mapping_.end() || it->second.empty()) {
        return true;
    }
    
    // Check if any cookie is valid and not consumed
    for (const auto& cookie_key : it->second) {
        auto cookie_it = active_cookies_.find(cookie_key);
        if (cookie_it != active_cookies_.end() && 
            !cookie_it->second.consumed &&
            !cookie_it->second.is_expired(config_.cookie_lifetime)) {
            return false; // Has valid cookie
        }
    }
    
    return true; // No valid cookies found
}

void CookieManager::consume_cookie(const memory::Buffer& cookie, 
                                  const ClientInfo& client_info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string cookie_key = generate_cookie_key(cookie);
    auto it = active_cookies_.find(cookie_key);
    
    if (it != active_cookies_.end()) {
        it->second.consumed = true;
        it->second.last_access_time = std::chrono::steady_clock::now();
    }
}

void CookieManager::cleanup_expired_cookies() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    // Only run cleanup if enough time has passed
    if ((now - last_cleanup_) < config_.cleanup_interval) {
        return;
    }
    
    // Remove expired cookies
    auto cookie_it = active_cookies_.begin();
    while (cookie_it != active_cookies_.end()) {
        if (cookie_it->second.is_expired(config_.cookie_lifetime)) {
            std::string client_id = cookie_it->second.client_info.get_client_id();
            
            // Remove from client mapping
            auto client_it = client_cookie_mapping_.find(client_id);
            if (client_it != client_cookie_mapping_.end()) {
                auto& cookie_list = client_it->second;
                cookie_list.erase(
                    std::remove(cookie_list.begin(), cookie_list.end(), cookie_it->first),
                    cookie_list.end());
                
                if (cookie_list.empty()) {
                    client_cookie_mapping_.erase(client_it);
                }
            }
            
            cookie_it = active_cookies_.erase(cookie_it);
        } else {
            ++cookie_it;
        }
    }
    
    stats_.active_cookies = active_cookies_.size();
    last_cleanup_ = now;
}

CookieManager::Statistics CookieManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void CookieManager::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    active_cookies_.clear();
    client_cookie_mapping_.clear();
    stats_ = Statistics{};
    last_cleanup_ = std::chrono::steady_clock::now();
}

void CookieManager::update_config(const CookieConfig& new_config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = new_config;
    
    // Validate new configuration
    if (config_.cookie_size < MIN_COOKIE_SIZE || config_.cookie_size > MAX_COOKIE_SIZE) {
        config_.cookie_size = 32; // Use default
    }
}

// Private methods
Result<memory::Buffer> CookieManager::generate_hmac_cookie(
    const ClientInfo& client_info, uint64_t timestamp) const {
    
    // Calculate required cookie size
    size_t total_size = 4 + 1 + 8 + HMAC_SIZE; // MAGIC + VERSION + TIMESTAMP + HMAC
    
    memory::Buffer cookie(total_size);
    cookie.resize(total_size);
    uint8_t* data = reinterpret_cast<uint8_t*>(cookie.mutable_data());
    size_t offset = 0;
    
    // Write magic number
    uint32_t magic_be = htonl(COOKIE_MAGIC);
    std::memcpy(data + offset, &magic_be, 4);
    offset += 4;
    
    // Write version
    data[offset] = COOKIE_VERSION;
    offset += 1;
    
    // Write timestamp
    uint64_t timestamp_be = htobe64(timestamp);
    std::memcpy(data + offset, &timestamp_be, 8);
    offset += 8;
    
    // Prepare HMAC input (everything except HMAC itself)
    std::vector<uint8_t> hmac_input;
    hmac_input.reserve(offset + client_info.client_address.size() + 2 + client_info.client_hello_data.size());
    
    // Add cookie prefix (magic + version + timestamp)
    hmac_input.insert(hmac_input.end(), data, data + offset);
    
    // Add client address
    hmac_input.insert(hmac_input.end(), 
                     client_info.client_address.begin(), 
                     client_info.client_address.end());
    
    // Add client port
    uint16_t port_be = htons(client_info.client_port);
    hmac_input.insert(hmac_input.end(), 
                     reinterpret_cast<const uint8_t*>(&port_be),
                     reinterpret_cast<const uint8_t*>(&port_be) + 2);
    
    // Add client hello data
    hmac_input.insert(hmac_input.end(),
                     client_info.client_hello_data.begin(),
                     client_info.client_hello_data.end());
    
    // Calculate HMAC-SHA256
    unsigned int hmac_len = 0;
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    
    if (!HMAC(EVP_sha256(), 
              secret_key_.data(), static_cast<int>(secret_key_.size()),
              hmac_input.data(), hmac_input.size(),
              hmac_result, &hmac_len)) {
        return Result<memory::Buffer>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    if (hmac_len != HMAC_SIZE) {
        return Result<memory::Buffer>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    // Write HMAC
    std::memcpy(data + offset, hmac_result, HMAC_SIZE);
    
    return Result<memory::Buffer>(std::move(cookie));
}

bool CookieManager::verify_hmac_cookie(const memory::Buffer& cookie, 
                                      const ClientInfo& client_info,
                                      uint64_t& timestamp) const {
    if (cookie.size() < 4 + 1 + 8 + HMAC_SIZE) {
        return false;
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(cookie.data());
    size_t offset = 0;
    
    // Verify magic number
    uint32_t magic;
    std::memcpy(&magic, data + offset, 4);
    if (ntohl(magic) != COOKIE_MAGIC) {
        return false;
    }
    offset += 4;
    
    // Verify version
    if (data[offset] != COOKIE_VERSION) {
        return false;
    }
    offset += 1;
    
    // Extract timestamp
    uint64_t timestamp_be;
    std::memcpy(&timestamp_be, data + offset, 8);
    timestamp = be64toh(timestamp_be);
    offset += 8;
    
    // Prepare HMAC input (everything except HMAC)
    size_t hmac_input_size = offset + client_info.client_address.size() + 2 + client_info.client_hello_data.size();
    std::vector<uint8_t> hmac_input;
    hmac_input.reserve(hmac_input_size);
    
    // Add cookie prefix
    hmac_input.insert(hmac_input.end(), data, data + offset);
    
    // Add client info
    hmac_input.insert(hmac_input.end(), 
                     client_info.client_address.begin(), 
                     client_info.client_address.end());
    
    uint16_t port_be = htons(client_info.client_port);
    hmac_input.insert(hmac_input.end(), 
                     reinterpret_cast<const uint8_t*>(&port_be),
                     reinterpret_cast<const uint8_t*>(&port_be) + 2);
    
    hmac_input.insert(hmac_input.end(),
                     client_info.client_hello_data.begin(),
                     client_info.client_hello_data.end());
    
    // Calculate expected HMAC
    unsigned int hmac_len = 0;
    unsigned char expected_hmac[EVP_MAX_MD_SIZE];
    
    if (!HMAC(EVP_sha256(), 
              secret_key_.data(), static_cast<int>(secret_key_.size()),
              hmac_input.data(), hmac_input.size(),
              expected_hmac, &hmac_len)) {
        return false;
    }
    
    if (hmac_len != HMAC_SIZE) {
        return false;
    }
    
    // Compare HMACs using constant-time comparison
    return CRYPTO_memcmp(data + offset, expected_hmac, HMAC_SIZE) == 0;
}

std::string CookieManager::generate_cookie_key(const memory::Buffer& cookie) const {
    // Use SHA-256 hash of cookie as key
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(cookie.data()), 
           cookie.size(), hash);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return oss.str();
}

bool CookieManager::client_has_too_many_cookies(const ClientInfo& client_info) const {
    std::string client_id = client_info.get_client_id();
    auto it = client_cookie_mapping_.find(client_id);
    
    if (it == client_cookie_mapping_.end()) {
        return false;
    }
    
    // Count valid (non-expired, non-consumed) cookies
    uint32_t valid_cookies = 0;
    for (const auto& cookie_key : it->second) {
        auto cookie_it = active_cookies_.find(cookie_key);
        if (cookie_it != active_cookies_.end() &&
            !cookie_it->second.consumed &&
            !cookie_it->second.is_expired(config_.cookie_lifetime)) {
            ++valid_cookies;
        }
    }
    
    return valid_cookies >= config_.max_cookies_per_client;
}

void CookieManager::remove_client_cookies(const ClientInfo& client_info) {
    std::string client_id = client_info.get_client_id();
    auto client_it = client_cookie_mapping_.find(client_id);
    
    if (client_it == client_cookie_mapping_.end()) {
        return;
    }
    
    // Remove oldest cookies first
    auto& cookie_list = client_it->second;
    std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> cookie_times;
    
    for (const auto& cookie_key : cookie_list) {
        auto cookie_it = active_cookies_.find(cookie_key);
        if (cookie_it != active_cookies_.end()) {
            cookie_times.emplace_back(cookie_key, cookie_it->second.creation_time);
        }
    }
    
    // Sort by creation time (oldest first)
    std::sort(cookie_times.begin(), cookie_times.end(),
              [](const auto& a, const auto& b) {
                  return a.second < b.second;
              });
    
    // Remove oldest cookies until we're under the limit
    size_t cookies_to_remove = cookie_times.size() - (config_.max_cookies_per_client - 1);
    for (size_t i = 0; i < cookies_to_remove && i < cookie_times.size(); ++i) {
        const auto& cookie_key = cookie_times[i].first;
        active_cookies_.erase(cookie_key);
        cookie_list.erase(
            std::remove(cookie_list.begin(), cookie_list.end(), cookie_key),
            cookie_list.end());
    }
    
    if (cookie_list.empty()) {
        client_cookie_mapping_.erase(client_it);
    }
}

// Utility functions
Result<CookieManager::ClientInfo> 
extract_client_info(const std::string& address, 
                    const std::vector<uint8_t>& client_hello_data) {
    
    // Parse address string (format: "IP:PORT")
    size_t colon_pos = address.find_last_of(':');
    if (colon_pos == std::string::npos) {
        return Result<CookieManager::ClientInfo>(DTLSError::INVALID_PARAMETER);
    }
    
    std::string ip = address.substr(0, colon_pos);
    std::string port_str = address.substr(colon_pos + 1);
    
    uint16_t port;
    try {
        port = static_cast<uint16_t>(std::stoul(port_str));
    } catch (const std::exception&) {
        return Result<CookieManager::ClientInfo>(DTLSError::INVALID_PARAMETER);
    }
    
    CookieManager::ClientInfo client_info(ip, port, client_hello_data);
    return Result<CookieManager::ClientInfo>(std::move(client_info));
}

// Cookie extension functions are implemented in handshake.cpp to avoid duplicate definitions

bool is_valid_cookie_format(const memory::Buffer& cookie) {
    if (cookie.size() < MIN_COOKIE_SIZE || cookie.size() > MAX_COOKIE_SIZE) {
        return false;
    }
    
    if (cookie.size() < 4 + 1 + 8 + HMAC_SIZE) {
        return false; // Too small for our cookie format
    }
    
    // Check magic number
    const uint8_t* data = reinterpret_cast<const uint8_t*>(cookie.data());
    uint32_t magic;
    std::memcpy(&magic, data, 4);
    
    if (ntohl(magic) != COOKIE_MAGIC) {
        return false;
    }
    
    // Check version
    if (data[4] != COOKIE_VERSION) {
        return false;
    }
    
    return true;
}

memory::Buffer generate_test_cookie(uint8_t size) {
    if (size < MIN_COOKIE_SIZE) size = MIN_COOKIE_SIZE;
    if (size > MAX_COOKIE_SIZE) size = MAX_COOKIE_SIZE;
    
    memory::Buffer cookie(size);
    cookie.resize(size);
    
    // Fill with pseudo-random data for testing
    if (RAND_bytes(reinterpret_cast<unsigned char*>(cookie.mutable_data()), static_cast<int>(size)) != 1) {
        // Fallback to deterministic pattern if OpenSSL fails
        uint8_t* data = reinterpret_cast<uint8_t*>(cookie.mutable_data());
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i & 0xFF);
        }
    }
    
    return cookie;
}

} // namespace dtls::v13::protocol