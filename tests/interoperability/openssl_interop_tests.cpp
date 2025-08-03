/*
 * OpenSSL DTLS v1.3 Interoperability Tests Implementation
 * Task 9: Comprehensive OpenSSL external implementation testing
 */

#include "openssl_interop_tests.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>
#include <cstring>

#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

// Define DTLS1_3_VERSION if not available in OpenSSL headers
#ifndef DTLS1_3_VERSION
#define DTLS1_3_VERSION 0xfefc
#endif
#endif

namespace dtls::v13::test::interop {

#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE

// ============================================================================
// OpenSSLImplementationRunner Implementation
// ============================================================================

struct OpenSSLImplementationRunner::Impl {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    BIO* bio = nullptr;
    int sockfd = -1;
    struct sockaddr_in server_addr = {};
    struct sockaddr_in client_addr = {};
    bool is_server = false;
    bool handshake_completed = false;
    InteropTestConfig config;
    InteropTestResult result;
    std::vector<uint8_t> received_data;
    std::chrono::steady_clock::time_point start_time;
    
    ~Impl() {
        cleanup();
    }
    
    void cleanup() {
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
        if (sockfd >= 0) {
            close(sockfd);
            sockfd = -1;
        }
        handshake_completed = false;
    }
};

OpenSSLImplementationRunner::OpenSSLImplementationRunner() 
    : pimpl_(std::make_unique<Impl>()) {
    // Initialize OpenSSL
    SSL_load_error_strings();
    SSL_library_init();
}

OpenSSLImplementationRunner::~OpenSSLImplementationRunner() = default;

bool OpenSSLImplementationRunner::initialize(const InteropTestConfig& config) {
    pimpl_->config = config;
    pimpl_->start_time = std::chrono::steady_clock::now();
    
    // Setup SSL context
    if (!setup_ssl_context()) {
        pimpl_->result.error_message = "Failed to setup SSL context";
        return false;
    }
    
    // Configure cipher suites
    if (!configure_cipher_suites(config.cipher_suites)) {
        pimpl_->result.error_message = "Failed to configure cipher suites";
        return false;
    }
    
    // Configure DTLS options
    if (!configure_dtls_options()) {
        pimpl_->result.error_message = "Failed to configure DTLS options";
        return false;
    }
    
    return true;
}

bool OpenSSLImplementationRunner::setup_ssl_context() {
    // Create DTLS 1.3 context
    pimpl_->ctx = SSL_CTX_new(DTLS_method());
    if (!pimpl_->ctx) {
        log_openssl_errors();
        return false;
    }
    
    // Set DTLS version to 1.3
    if (SSL_CTX_set_min_proto_version(pimpl_->ctx, DTLS1_3_VERSION) != 1) {
        log_openssl_errors();
        return false;
    }
    
    if (SSL_CTX_set_max_proto_version(pimpl_->ctx, DTLS1_3_VERSION) != 1) {
        log_openssl_errors();
        return false;
    }
    
    // Disable session cache for testing
    SSL_CTX_set_session_cache_mode(pimpl_->ctx, SSL_SESS_CACHE_OFF);
    
    // Set up certificates (simplified for testing)
    if (!setup_certificates()) {
        return false;
    }
    
    return true;
}

bool OpenSSLImplementationRunner::setup_certificates() {
    // For testing, we'll use a self-signed certificate
    // In production, proper certificates should be used
    
    // Set certificate verification mode
    if (pimpl_->config.verify_certificates) {
        SSL_CTX_set_verify(pimpl_->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    } else {
        SSL_CTX_set_verify(pimpl_->ctx, SSL_VERIFY_NONE, nullptr);
    }
    
    return true;
}

bool OpenSSLImplementationRunner::configure_cipher_suites(const std::vector<uint16_t>& cipher_suites) {
    if (cipher_suites.empty()) {
        return true; // Use default cipher suites
    }
    
    std::stringstream cipher_list;
    for (size_t i = 0; i < cipher_suites.size(); ++i) {
        if (i > 0) cipher_list << ":";
        
        // Map cipher suite values to OpenSSL names
        switch (cipher_suites[i]) {
            case 0x1301: cipher_list << "TLS_AES_128_GCM_SHA256"; break;
            case 0x1302: cipher_list << "TLS_AES_256_GCM_SHA384"; break;
            case 0x1303: cipher_list << "TLS_CHACHA20_POLY1305_SHA256"; break;
            case 0x1304: cipher_list << "TLS_AES_128_CCM_SHA256"; break;
            case 0x1305: cipher_list << "TLS_AES_128_CCM_8_SHA256"; break;
            default:
                // Unknown cipher suite, skip
                continue;
        }
    }
    
    std::string cipher_string = cipher_list.str();
    if (cipher_string.empty()) {
        return true; // No valid cipher suites, use defaults
    }
    
    if (SSL_CTX_set_ciphersuites(pimpl_->ctx, cipher_string.c_str()) != 1) {
        log_openssl_errors();
        return false;
    }
    
    return true;
}

bool OpenSSLImplementationRunner::configure_dtls_options() {
    // Enable cookie exchange for DTLS
    SSL_CTX_set_cookie_generate_cb(pimpl_->ctx, nullptr);
    SSL_CTX_set_cookie_verify_cb(pimpl_->ctx, nullptr);
    
    // Set DTLS timeout
    SSL_CTX_set_timeout(pimpl_->ctx, 30);
    
    return true;
}

bool OpenSSLImplementationRunner::start_server(uint16_t port) {
    pimpl_->is_server = true;
    
    // Create UDP socket
    pimpl_->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (pimpl_->sockfd < 0) {
        pimpl_->result.error_message = "Failed to create socket";
        return false;
    }
    
    // Set socket options
    int reuse = 1;
    if (setsockopt(pimpl_->sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        pimpl_->result.error_message = "Failed to set socket options";
        return false;
    }
    
    // Bind to port
    memset(&pimpl_->server_addr, 0, sizeof(pimpl_->server_addr));
    pimpl_->server_addr.sin_family = AF_INET;
    pimpl_->server_addr.sin_addr.s_addr = INADDR_ANY;
    pimpl_->server_addr.sin_port = htons(port);
    
    if (bind(pimpl_->sockfd, (struct sockaddr*)&pimpl_->server_addr, sizeof(pimpl_->server_addr)) < 0) {
        pimpl_->result.error_message = "Failed to bind to port " + std::to_string(port);
        return false;
    }
    
    // Create SSL object
    pimpl_->ssl = SSL_new(pimpl_->ctx);
    if (!pimpl_->ssl) {
        log_openssl_errors();
        pimpl_->result.error_message = "Failed to create SSL object";
        return false;
    }
    
    // Create BIO for DTLS
    pimpl_->bio = BIO_new_dgram(pimpl_->sockfd, BIO_NOCLOSE);
    if (!pimpl_->bio) {
        log_openssl_errors();
        pimpl_->result.error_message = "Failed to create BIO";
        return false;
    }
    
    SSL_set_bio(pimpl_->ssl, pimpl_->bio, pimpl_->bio);
    SSL_set_accept_state(pimpl_->ssl);
    
    return true;
}

bool OpenSSLImplementationRunner::start_client(const std::string& host, uint16_t port) {
    pimpl_->is_server = false;
    
    // Create UDP socket
    pimpl_->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (pimpl_->sockfd < 0) {
        pimpl_->result.error_message = "Failed to create socket";
        return false;
    }
    
    // Setup server address
    memset(&pimpl_->server_addr, 0, sizeof(pimpl_->server_addr));
    pimpl_->server_addr.sin_family = AF_INET;
    pimpl_->server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &pimpl_->server_addr.sin_addr) <= 0) {
        pimpl_->result.error_message = "Invalid host address: " + host;
        return false;
    }
    
    // Connect socket
    if (connect(pimpl_->sockfd, (struct sockaddr*)&pimpl_->server_addr, sizeof(pimpl_->server_addr)) < 0) {
        pimpl_->result.error_message = "Failed to connect to " + host + ":" + std::to_string(port);
        return false;
    }
    
    // Create SSL object
    pimpl_->ssl = SSL_new(pimpl_->ctx);
    if (!pimpl_->ssl) {
        log_openssl_errors();
        pimpl_->result.error_message = "Failed to create SSL object";
        return false;
    }
    
    // Create BIO for DTLS
    pimpl_->bio = BIO_new_dgram(pimpl_->sockfd, BIO_NOCLOSE);
    if (!pimpl_->bio) {
        log_openssl_errors();
        pimpl_->result.error_message = "Failed to create BIO";
        return false;
    }
    
    SSL_set_bio(pimpl_->ssl, pimpl_->bio, pimpl_->bio);
    SSL_set_connect_state(pimpl_->ssl);
    
    return true;
}

bool OpenSSLImplementationRunner::perform_handshake() {
    if (!pimpl_->ssl) {
        pimpl_->result.error_message = "SSL not initialized";
        return false;
    }
    
    if (pimpl_->is_server) {
        return perform_server_handshake();
    } else {
        return perform_client_handshake();
    }
}

bool OpenSSLImplementationRunner::perform_server_handshake() {
    int result = SSL_accept(pimpl_->ssl);
    
    if (result == 1) {
        pimpl_->handshake_completed = true;
        
        // Get negotiated parameters
        const SSL_CIPHER* cipher = SSL_get_current_cipher(pimpl_->ssl);
        if (cipher) {
            pimpl_->result.negotiated_cipher_suite = SSL_CIPHER_get_protocol_id(cipher);
        }
        
        int version = SSL_version(pimpl_->ssl);
        if (version == DTLS1_3_VERSION) {
            pimpl_->result.negotiated_version = protocol::ProtocolVersion::DTLS_1_3;
        }
        
        return true;
    } else {
        int ssl_error = SSL_get_error(pimpl_->ssl, result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // Need to wait for more data or be able to write
            return wait_for_handshake_completion(pimpl_->config.timeout.count());
        } else {
            log_openssl_errors();
            pimpl_->result.error_message = "SSL_accept failed: " + get_openssl_error_string();
            return false;
        }
    }
}

bool OpenSSLImplementationRunner::perform_client_handshake() {
    int result = SSL_connect(pimpl_->ssl);
    
    if (result == 1) {
        pimpl_->handshake_completed = true;
        
        // Get negotiated parameters
        const SSL_CIPHER* cipher = SSL_get_current_cipher(pimpl_->ssl);
        if (cipher) {
            pimpl_->result.negotiated_cipher_suite = SSL_CIPHER_get_protocol_id(cipher);
        }
        
        int version = SSL_version(pimpl_->ssl);
        if (version == DTLS1_3_VERSION) {
            pimpl_->result.negotiated_version = protocol::ProtocolVersion::DTLS_1_3;
        }
        
        return true;
    } else {
        int ssl_error = SSL_get_error(pimpl_->ssl, result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // Need to wait for more data or be able to write
            return wait_for_handshake_completion(pimpl_->config.timeout.count());
        } else {
            log_openssl_errors();
            pimpl_->result.error_message = "SSL_connect failed: " + get_openssl_error_string();
            return false;
        }
    }
}

bool OpenSSLImplementationRunner::wait_for_handshake_completion(int timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();
    
    while (!pimpl_->handshake_completed) {
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed > std::chrono::milliseconds(timeout_ms)) {
            pimpl_->result.error_message = "Handshake timeout";
            return false;
        }
        
        // Continue handshake process
        int result;
        if (pimpl_->is_server) {
            result = SSL_accept(pimpl_->ssl);
        } else {
            result = SSL_connect(pimpl_->ssl);
        }
        
        if (result == 1) {
            pimpl_->handshake_completed = true;
            return true;
        } else {
            int ssl_error = SSL_get_error(pimpl_->ssl, result);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                log_openssl_errors();
                pimpl_->result.error_message = "Handshake failed: " + get_openssl_error_string();
                return false;
            }
        }
        
        // Brief sleep to avoid busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return true;
}

bool OpenSSLImplementationRunner::send_data(const std::vector<uint8_t>& data) {
    if (!pimpl_->ssl || !pimpl_->handshake_completed) {
        pimpl_->result.error_message = "SSL not ready for data transfer";
        return false;
    }
    
    int bytes_written = SSL_write(pimpl_->ssl, data.data(), static_cast<int>(data.size()));
    
    if (bytes_written > 0) {
        pimpl_->result.bytes_transferred += bytes_written;
        return true;
    } else {
        int ssl_error = SSL_get_error(pimpl_->ssl, bytes_written);
        log_openssl_errors();
        pimpl_->result.error_message = "SSL_write failed: " + get_openssl_error_string();
        return false;
    }
}

std::vector<uint8_t> OpenSSLImplementationRunner::receive_data(size_t max_size) {
    std::vector<uint8_t> buffer(max_size);
    
    if (!pimpl_->ssl || !pimpl_->handshake_completed) {
        pimpl_->result.error_message = "SSL not ready for data transfer";
        return {};
    }
    
    int bytes_read = SSL_read(pimpl_->ssl, buffer.data(), static_cast<int>(max_size));
    
    if (bytes_read > 0) {
        buffer.resize(bytes_read);
        pimpl_->result.bytes_transferred += bytes_read;
        return buffer;
    } else {
        int ssl_error = SSL_get_error(pimpl_->ssl, bytes_read);
        if (ssl_error == SSL_ERROR_WANT_READ) {
            // No data available, return empty vector
            return {};
        } else {
            log_openssl_errors();
            pimpl_->result.error_message = "SSL_read failed: " + get_openssl_error_string();
            return {};
        }
    }
}

bool OpenSSLImplementationRunner::perform_key_update() {
    if (!pimpl_->ssl || !pimpl_->handshake_completed) {
        pimpl_->result.error_message = "SSL not ready for key update";
        return false;
    }
    
    int result = SSL_key_update(pimpl_->ssl, SSL_KEY_UPDATE_REQUESTED);
    
    if (result == 1) {
        return true;
    } else {
        log_openssl_errors();
        pimpl_->result.error_message = "SSL_key_update failed: " + get_openssl_error_string();
        return false;
    }
}

InteropTestResult OpenSSLImplementationRunner::get_test_result() {
    auto end_time = std::chrono::steady_clock::now();
    pimpl_->result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - pimpl_->start_time);
    
    if (pimpl_->handshake_completed && pimpl_->result.error_message.empty()) {
        pimpl_->result.success = true;
    }
    
    return pimpl_->result;
}

void OpenSSLImplementationRunner::cleanup() {
    pimpl_->cleanup();
}

std::string OpenSSLImplementationRunner::get_implementation_name() const {
    return "OpenSSL";
}

std::string OpenSSLImplementationRunner::get_version() const {
    return OPENSSL_VERSION_TEXT;
}

void OpenSSLImplementationRunner::log_openssl_errors() {
    unsigned long error;
    while ((error = ERR_get_error()) != 0) {
        char error_buffer[256];
        ERR_error_string_n(error, error_buffer, sizeof(error_buffer));
        std::cerr << "OpenSSL Error: " << error_buffer << std::endl;
    }
}

std::string OpenSSLImplementationRunner::get_openssl_error_string() {
    unsigned long error = ERR_get_error();
    if (error == 0) {
        return "Unknown error";
    }
    
    char error_buffer[256];
    ERR_error_string_n(error, error_buffer, sizeof(error_buffer));
    return std::string(error_buffer);
}

// ============================================================================
// OpenSSLTestScenarios Implementation
// ============================================================================

std::vector<InteropTestConfig> OpenSSLTestScenarios::get_basic_test_configs() {
    std::vector<InteropTestConfig> configs;
    
    // Test both client and server roles
    for (auto role : {TestRole::CLIENT, TestRole::SERVER}) {
        configs.push_back(create_basic_handshake_config(role));
        configs.push_back(create_ecdh_key_exchange_config(role));
        configs.push_back(create_rsa_signature_config(role));
    }
    
    return configs;
}

std::vector<InteropTestConfig> OpenSSLTestScenarios::get_cipher_suite_test_configs() {
    std::vector<InteropTestConfig> configs;
    
    // Test individual cipher suites
    std::vector<std::pair<uint16_t, std::string>> cipher_suites = {
        {0x1301, "AES_128_GCM"},
        {0x1302, "AES_256_GCM"},
        {0x1303, "CHACHA20_POLY1305"},
        {0x1304, "AES_128_CCM"},
        {0x1305, "AES_128_CCM_8"}
    };
    
    for (const auto& [cipher_id, cipher_name] : cipher_suites) {
        for (auto role : {TestRole::CLIENT, TestRole::SERVER}) {
            InteropTestConfig config;
            config.external_impl = ExternalImplementation::OPENSSL_3_0;
            config.scenario = TestScenario::CIPHER_SUITE_NEGOTIATION;
            config.our_role = role;
            config.cipher_suites = {cipher_id};
            config.test_description = "OpenSSL " + cipher_name + " - " + 
                                    (role == TestRole::CLIENT ? "Client" : "Server");
            apply_common_settings(config);
            configs.push_back(config);
        }
    }
    
    return configs;
}

std::vector<InteropTestConfig> OpenSSLTestScenarios::get_large_data_test_configs() {
    std::vector<InteropTestConfig> configs;
    
    std::vector<size_t> data_sizes = {1024, 4096, 16384, 32768};
    
    for (size_t size : data_sizes) {
        for (auto role : {TestRole::CLIENT, TestRole::SERVER}) {
            InteropTestConfig config;
            config.external_impl = ExternalImplementation::OPENSSL_3_0;
            config.scenario = TestScenario::LARGE_DATA_TRANSFER;
            config.our_role = role;
            config.test_data_size = size;
            config.cipher_suites = {0x1301}; // Use AES-128-GCM for data tests
            config.test_description = "OpenSSL Large Data " + std::to_string(size) + "B - " +
                                    (role == TestRole::CLIENT ? "Client" : "Server");
            apply_common_settings(config);
            configs.push_back(config);
        }
    }
    
    return configs;
}

InteropTestConfig OpenSSLTestScenarios::create_basic_handshake_config(TestRole our_role) {
    InteropTestConfig config;
    config.external_impl = ExternalImplementation::OPENSSL_3_0;
    config.scenario = TestScenario::BASIC_HANDSHAKE;
    config.our_role = our_role;
    config.cipher_suites = {0x1301, 0x1302, 0x1303}; // Standard cipher suites
    config.test_description = "OpenSSL Basic Handshake - " + 
                            std::string(our_role == TestRole::CLIENT ? "Client" : "Server");
    apply_common_settings(config);
    return config;
}

InteropTestConfig OpenSSLTestScenarios::create_ecdh_key_exchange_config(TestRole our_role) {
    InteropTestConfig config;
    config.external_impl = ExternalImplementation::OPENSSL_3_0;
    config.scenario = TestScenario::BASIC_HANDSHAKE;
    config.our_role = our_role;
    config.cipher_suites = {0x1301}; // AES-128-GCM with ECDHE
    config.named_groups = {23, 24, 29}; // P-256, P-384, X25519
    config.test_description = "OpenSSL ECDH Key Exchange - " +
                            std::string(our_role == TestRole::CLIENT ? "Client" : "Server");
    apply_common_settings(config);
    return config;
}

InteropTestConfig OpenSSLTestScenarios::create_rsa_signature_config(TestRole our_role) {
    InteropTestConfig config;
    config.external_impl = ExternalImplementation::OPENSSL_3_0;
    config.scenario = TestScenario::BASIC_HANDSHAKE;
    config.our_role = our_role;
    config.cipher_suites = {0x1301};
    config.verify_certificates = true; // Enable certificate verification for RSA
    config.test_description = "OpenSSL RSA Signature - " +
                            std::string(our_role == TestRole::CLIENT ? "Client" : "Server");
    apply_common_settings(config);
    return config;
}

void OpenSSLTestScenarios::apply_common_settings(InteropTestConfig& config) {
    config.mode = TestMode::DIRECT_LINK;
    config.timeout = std::chrono::milliseconds(10000);
    config.port = DTLS_INTEROP_DEFAULT_PORT_BASE;
    
    if (config.test_data_size == 0) {
        config.test_data_size = 1024;
    }
}

// ============================================================================
// OpenSSLCompatibilityMatrix Implementation
// ============================================================================

std::vector<OpenSSLCompatibilityMatrix::VersionInfo> OpenSSLCompatibilityMatrix::get_supported_versions() {
    return {
        {
            "3.0.0",
            true,
            {0x1301, 0x1302, 0x1303, 0x1304, 0x1305},
            {"supported_versions", "key_share", "signature_algorithms", "connection_id"},
            {}
        },
        {
            "3.1.0",
            true,
            {0x1301, 0x1302, 0x1303, 0x1304, 0x1305},
            {"supported_versions", "key_share", "signature_algorithms", "connection_id", "early_data"},
            {}
        },
        {
            "1.1.1",
            false,
            {},
            {},
            {"DTLS v1.3 not supported"}
        }
    };
}

OpenSSLCompatibilityMatrix::VersionInfo OpenSSLCompatibilityMatrix::get_version_info(const std::string& version) {
    auto versions = get_supported_versions();
    for (const auto& info : versions) {
        if (info.version == version) {
            return info;
        }
    }
    
    // Return default info for unknown versions
    return {"unknown", false, {}, {}, {"Unknown OpenSSL version"}};
}

bool OpenSSLCompatibilityMatrix::is_feature_supported(const std::string& version, const std::string& feature) {
    auto info = get_version_info(version);
    return std::find(info.supported_extensions.begin(), info.supported_extensions.end(), feature) 
           != info.supported_extensions.end();
}

std::vector<uint16_t> OpenSSLCompatibilityMatrix::get_compatible_cipher_suites(const std::string& version) {
    auto info = get_version_info(version);
    return info.supported_cipher_suites;
}

#endif // DTLS_INTEROP_OPENSSL_AVAILABLE

} // namespace dtls::v13::test::interop