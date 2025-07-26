/*
 * OpenSSL DTLS v1.3 Interoperability Tests
 * Task 9: OpenSSL external implementation testing
 */

#pragma once

#include "interop_test_framework.h"
#include "interop_config.h"

#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#endif

#include <memory>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

namespace dtls::v13::test::interop {

#ifdef DTLS_INTEROP_OPENSSL_AVAILABLE

/**
 * OpenSSL DTLS v1.3 implementation runner
 * Provides interface to external OpenSSL DTLS implementation
 */
class OpenSSLImplementationRunner : public ExternalImplementationRunner {
public:
    OpenSSLImplementationRunner();
    ~OpenSSLImplementationRunner() override;
    
    // ExternalImplementationRunner interface
    bool initialize(const InteropTestConfig& config) override;
    bool start_server(uint16_t port) override;
    bool start_client(const std::string& host, uint16_t port) override;
    bool send_data(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> receive_data(size_t max_size) override;
    bool perform_handshake() override;
    bool perform_key_update() override;
    InteropTestResult get_test_result() override;
    void cleanup() override;
    
    std::string get_implementation_name() const override;
    std::string get_version() const override;
    
private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
    
    // OpenSSL-specific helper methods
    bool setup_ssl_context();
    bool setup_certificates();
    bool configure_cipher_suites(const std::vector<uint16_t>& cipher_suites);
    bool configure_dtls_options();
    bool setup_bio_dgram();
    
    // Handshake and data transfer helpers
    bool perform_server_handshake();
    bool perform_client_handshake();
    bool wait_for_handshake_completion(int timeout_ms);
    
    // Error handling
    void log_openssl_errors();
    std::string get_openssl_error_string();
};

/**
 * Docker-based OpenSSL implementation runner
 * Runs OpenSSL DTLS server/client in isolated Docker container
 */
class DockerOpenSSLRunner : public ExternalImplementationRunner {
public:
    DockerOpenSSLRunner();
    ~DockerOpenSSLRunner() override;
    
    bool initialize(const InteropTestConfig& config) override;
    bool start_server(uint16_t port) override;
    bool start_client(const std::string& host, uint16_t port) override;
    bool send_data(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> receive_data(size_t max_size) override;
    bool perform_handshake() override;
    bool perform_key_update() override;
    InteropTestResult get_test_result() override;
    void cleanup() override;
    
    std::string get_implementation_name() const override;
    std::string get_version() const override;
    
private:
    struct DockerImpl;
    std::unique_ptr<DockerImpl> pimpl_;
    
    // Docker management
    bool start_container(const std::string& command, uint16_t port);
    bool stop_container();
    bool send_command_to_container(const std::string& command);
    std::string read_output_from_container();
    
    // Container communication
    bool write_data_to_container(const std::vector<uint8_t>& data);
    std::vector<uint8_t> read_data_from_container(size_t max_size);
};

/**
 * OpenSSL test scenarios
 */
class OpenSSLTestScenarios {
public:
    static std::vector<InteropTestConfig> get_basic_test_configs();
    static std::vector<InteropTestConfig> get_cipher_suite_test_configs();
    static std::vector<InteropTestConfig> get_key_update_test_configs();
    static std::vector<InteropTestConfig> get_connection_id_test_configs();
    static std::vector<InteropTestConfig> get_large_data_test_configs();
    static std::vector<InteropTestConfig> get_error_handling_test_configs();
    
    // Specific test scenarios
    static InteropTestConfig create_basic_handshake_config(TestRole our_role);
    static InteropTestConfig create_ecdh_key_exchange_config(TestRole our_role);
    static InteropTestConfig create_rsa_signature_config(TestRole our_role);
    static InteropTestConfig create_psk_config(TestRole our_role);
    static InteropTestConfig create_client_cert_config(TestRole our_role);
    
private:
    static void apply_common_settings(InteropTestConfig& config);
};

/**
 * OpenSSL version compatibility matrix
 */
class OpenSSLCompatibilityMatrix {
public:
    struct VersionInfo {
        std::string version;
        bool dtls13_support;
        std::vector<uint16_t> supported_cipher_suites;
        std::vector<std::string> supported_extensions;
        std::vector<std::string> known_issues;
    };
    
    static std::vector<VersionInfo> get_supported_versions();
    static VersionInfo get_version_info(const std::string& version);
    static bool is_feature_supported(const std::string& version, const std::string& feature);
    static std::vector<uint16_t> get_compatible_cipher_suites(const std::string& version);
};

#endif // DTLS_INTEROP_OPENSSL_AVAILABLE

} // namespace dtls::v13::test::interop