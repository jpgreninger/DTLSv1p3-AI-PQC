#pragma once

/**
 * @file dtls12_compat.h
 * @brief DTLS 1.2 Backward Compatibility Layer
 * 
 * Provides backward compatibility with DTLS 1.2 clients and servers
 * while maintaining full DTLS 1.3 security guarantees where possible.
 */

#include "dtls/types.h"
#include "dtls/error.h" 
#include "dtls/result.h"
#include "dtls/protocol/handshake.h"
#include "dtls/protocol/record.h"
#include "dtls/crypto/provider.h"

namespace dtls {
namespace v13 {
namespace compatibility {

/**
 * @brief DTLS 1.2 specific cipher suites
 */
enum class DTLS12CipherSuite : uint16_t {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   = 0xC02F,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   = 0xC030,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xCCA8,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     = 0x009E,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     = 0x009F,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   = 0xC027,
};

/**
 * @brief DTLS 1.2 record format handler
 */
class DTLS_API DTLS12RecordLayer {
public:
    /**
     * @brief Create DTLS 1.2 compatible record layer
     */
    static std::unique_ptr<DTLS12RecordLayer> create(
        const std::shared_ptr<crypto::CryptoProvider>& crypto_provider
    );

    virtual ~DTLS12RecordLayer() = default;

    /**
     * @brief Process incoming DTLS 1.2 record
     */
    virtual Result<protocol::PlaintextRecord> process_dtls12_record(
        const std::vector<uint8_t>& data,
        const crypto::KeySchedule& keys
    ) = 0;

    /**
     * @brief Create DTLS 1.2 compatible record
     */
    virtual Result<std::vector<uint8_t>> create_dtls12_record(
        ContentType content_type,
        const std::vector<uint8_t>& payload,
        const crypto::KeySchedule& keys
    ) = 0;

    /**
     * @brief Check if record uses DTLS 1.2 format
     */
    virtual bool is_dtls12_record(const std::vector<uint8_t>& data) = 0;
};

/**
 * @brief DTLS 1.2 handshake message converter
 */
class DTLS_API DTLS12HandshakeConverter {
public:
    /**
     * @brief Convert DTLS 1.2 ClientHello to DTLS 1.3 format
     */
    static Result<protocol::ClientHello> convert_client_hello_from_dtls12(
        const std::vector<uint8_t>& dtls12_client_hello
    );

    /**
     * @brief Convert DTLS 1.3 ServerHello to DTLS 1.2 format
     */
    static Result<std::vector<uint8_t>> convert_server_hello_to_dtls12(
        const protocol::ServerHello& dtls13_server_hello
    );

    /**
     * @brief Map DTLS 1.2 cipher suite to DTLS 1.3 equivalent
     */
    static Result<CipherSuite> map_dtls12_cipher_suite(DTLS12CipherSuite dtls12_suite);

    /**
     * @brief Map DTLS 1.3 cipher suite to DTLS 1.2 equivalent
     */
    static Result<DTLS12CipherSuite> map_dtls13_cipher_suite(CipherSuite dtls13_suite);

    /**
     * @brief Convert DTLS 1.2 extension to DTLS 1.3 format
     */
    static Result<protocol::Extension> convert_extension_from_dtls12(
        uint16_t extension_type,
        const std::vector<uint8_t>& extension_data
    );
};

/**
 * @brief DTLS 1.2 compatibility context
 */
struct DTLS12CompatibilityContext {
    bool enable_dtls12_fallback = true;
    bool strict_dtls13_security = false;
    std::vector<DTLS12CipherSuite> allowed_dtls12_ciphers;
    bool allow_dtls12_renegotiation = false;
    std::chrono::seconds dtls12_session_timeout{3600};
    size_t max_dtls12_connections = 1000;
    
    DTLS12CompatibilityContext() {
        // Default to secure DTLS 1.2 cipher suites
        allowed_dtls12_ciphers = {
            DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        };
    }
};

/**
 * @brief DTLS 1.2/1.3 version negotiation handler
 */
class DTLS_API VersionNegotiator {
public:
    /**
     * @brief Negotiate protocol version from ClientHello
     */
    static Result<ProtocolVersion> negotiate_version(
        const std::vector<uint8_t>& client_hello_data,
        const DTLS12CompatibilityContext& compat_context
    );

    /**
     * @brief Check if DTLS 1.2 fallback is required
     */
    static bool requires_dtls12_fallback(
        const std::vector<uint8_t>& client_hello_data
    );

    /**
     * @brief Create version-appropriate ServerHello
     */
    static Result<std::vector<uint8_t>> create_version_appropriate_server_hello(
        ProtocolVersion negotiated_version,
        const protocol::ServerHello& base_server_hello
    );
};

/**
 * @brief DTLS 1.2 connection adapter
 */
class DTLS_API DTLS12ConnectionAdapter {
public:
    /**
     * @brief Create adapter for DTLS 1.2 connection
     */
    static std::unique_ptr<DTLS12ConnectionAdapter> create(
        const DTLS12CompatibilityContext& context,
        const std::shared_ptr<crypto::CryptoProvider>& crypto_provider
    );

    virtual ~DTLS12ConnectionAdapter() = default;

    /**
     * @brief Process DTLS 1.2 handshake message
     */
    virtual Result<std::vector<uint8_t>> process_dtls12_handshake(
        const std::vector<uint8_t>& message
    ) = 0;

    /**
     * @brief Send data using DTLS 1.2 format
     */
    virtual Result<std::vector<uint8_t>> send_dtls12_data(
        const std::vector<uint8_t>& application_data
    ) = 0;

    /**
     * @brief Receive and decrypt DTLS 1.2 data
     */
    virtual Result<std::vector<uint8_t>> receive_dtls12_data(
        const std::vector<uint8_t>& encrypted_data
    ) = 0;

    /**
     * @brief Check if connection is using DTLS 1.2
     */
    virtual bool is_dtls12_connection() const = 0;

    /**
     * @brief Get security level of DTLS 1.2 connection
     */
    virtual SecurityLevel get_security_level() const = 0;
};

/**
 * @brief Compatibility statistics
 */
struct CompatibilityStats {
    size_t dtls13_connections = 0;
    size_t dtls12_connections = 0;
    size_t dtls12_fallbacks = 0;
    size_t version_negotiation_failures = 0;
    size_t security_downgrades = 0;
    std::chrono::steady_clock::time_point start_time;
    
    CompatibilityStats() : start_time(std::chrono::steady_clock::now()) {}
    
    double dtls12_usage_percentage() const {
        size_t total = dtls13_connections + dtls12_connections;
        return total > 0 ? (static_cast<double>(dtls12_connections) / total) * 100.0 : 0.0;
    }
};

/**
 * @brief Main compatibility manager
 */
class DTLS_API CompatibilityManager {
public:
    /**
     * @brief Create compatibility manager
     */
    static std::unique_ptr<CompatibilityManager> create(
        const DTLS12CompatibilityContext& context
    );

    virtual ~CompatibilityManager() = default;

    /**
     * @brief Register crypto provider for DTLS 1.2 operations
     */
    virtual Result<void> register_crypto_provider(
        const std::shared_ptr<crypto::CryptoProvider>& provider
    ) = 0;

    /**
     * @brief Handle incoming connection with version detection
     */
    virtual Result<std::unique_ptr<DTLS12ConnectionAdapter>> handle_incoming_connection(
        const std::vector<uint8_t>& initial_message
    ) = 0;

    /**
     * @brief Create outgoing connection with version preference
     */
    virtual Result<std::unique_ptr<DTLS12ConnectionAdapter>> create_outgoing_connection(
        ProtocolVersion preferred_version
    ) = 0;

    /**
     * @brief Get compatibility statistics
     */
    virtual CompatibilityStats get_statistics() const = 0;

    /**
     * @brief Update compatibility context
     */
    virtual Result<void> update_context(const DTLS12CompatibilityContext& new_context) = 0;
};

/**
 * @brief Utility functions for DTLS 1.2 compatibility
 */
namespace utils {

/**
 * @brief Check if cipher suite is DTLS 1.2 compatible
 */
bool is_dtls12_compatible_cipher_suite(CipherSuite suite);

/**
 * @brief Get security level for DTLS 1.2 cipher suite
 */
SecurityLevel get_dtls12_cipher_security_level(DTLS12CipherSuite suite);

/**
 * @brief Check if DTLS 1.2 cipher suite provides perfect forward secrecy
 */
bool dtls12_cipher_provides_pfs(DTLS12CipherSuite suite);

/**
 * @brief Convert DTLS version to string
 */
std::string version_to_string(ProtocolVersion version);

/**
 * @brief Validate DTLS 1.2 compatibility context
 */
Result<void> validate_dtls12_context(const DTLS12CompatibilityContext& context);

} // namespace utils

} // namespace compatibility
} // namespace v13
} // namespace dtls