/**
 * @file dtls12_compat.cpp
 * @brief Implementation of DTLS 1.2 Backward Compatibility Layer
 */

#include "dtls/compatibility/dtls12_compat.h"
#include "dtls/result.h"
#include "dtls/crypto/crypto_utils.h"
#include "dtls/memory/buffer.h"
#include "dtls/protocol/record.h"
#include <algorithm>
#include <unordered_map>
#include <memory>

namespace dtls {
namespace v13 {
namespace compatibility {

namespace {

/**
 * @brief DTLS 1.2 cipher suite mapping table
 */
const std::unordered_map<DTLS12CipherSuite, CipherSuite> g_dtls12_to_dtls13_cipher_map = {
    {DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite::TLS_AES_128_GCM_SHA256},
    {DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite::TLS_AES_128_GCM_SHA256},
    {DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite::TLS_AES_256_GCM_SHA384},
    {DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite::TLS_AES_256_GCM_SHA384},
    {DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite::TLS_CHACHA20_POLY1305_SHA256},
    {DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite::TLS_CHACHA20_POLY1305_SHA256},
};

/**
 * @brief Reverse mapping for DTLS 1.3 to DTLS 1.2
 */
const std::unordered_map<CipherSuite, DTLS12CipherSuite> g_dtls13_to_dtls12_cipher_map = {
    {CipherSuite::TLS_AES_128_GCM_SHA256, DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
    {CipherSuite::TLS_AES_256_GCM_SHA384, DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
    {CipherSuite::TLS_CHACHA20_POLY1305_SHA256, DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
};

/**
 * @brief DTLS 1.2 extension type mapping
 */
constexpr uint16_t DTLS12_EXTENSION_SUPPORTED_VERSIONS = 43;
constexpr uint16_t DTLS12_EXTENSION_SIGNATURE_ALGORITHMS = 13;
constexpr uint16_t DTLS12_EXTENSION_SUPPORTED_GROUPS = 10;

} // anonymous namespace

/**
 * @brief Implementation of DTLS 1.2 record layer
 */
class DTLS12RecordLayerImpl : public DTLS12RecordLayer {
private:
    std::shared_ptr<crypto::CryptoProvider> crypto_provider_;
    uint16_t current_epoch_ = 0;
    uint64_t sequence_number_ = 0;

public:
    explicit DTLS12RecordLayerImpl(const std::shared_ptr<crypto::CryptoProvider>& crypto_provider)
        : crypto_provider_(crypto_provider) {}

    Result<protocol::PlaintextRecord> process_dtls12_record(
        const std::vector<uint8_t>& data,
        const crypto::KeySchedule& keys) override {
        
        if (data.size() < protocol::RecordHeader::SERIALIZED_SIZE) {
            return make_error<protocol::PlaintextRecord>(DTLSError::INVALID_RECORD_HEADER);
        }

        // Parse DTLS 1.2 record header
        protocol::RecordHeader header;
        auto header_result = header.deserialize(data);
        if (!header_result) {
            return make_error<protocol::PlaintextRecord>(DTLSError::INVALID_RECORD_HEADER);
        }

        // Validate DTLS 1.2 version
        if (header.version != protocol::ProtocolVersion::DTLS_1_2) {
            return make_error<protocol::PlaintextRecord>(DTLSError::UNSUPPORTED_RECORD_VERSION);
        }

        // Extract payload
        size_t header_size = protocol::RecordHeader::SERIALIZED_SIZE;
        if (data.size() < header_size + header.length) {
            return make_error<protocol::PlaintextRecord>(DTLSError::RECORD_LENGTH_MISMATCH);
        }

        std::vector<uint8_t> payload(data.begin() + header_size, 
                                   data.begin() + header_size + header.length);

        // For application data, decrypt using DTLS 1.2 method
        if (header.content_type == ContentType::APPLICATION_DATA) {
            auto decrypt_result = decrypt_dtls12_payload(payload, keys, header);
            if (!decrypt_result) {
                return make_error<protocol::PlaintextRecord>(decrypt_result.error());
            }
            payload = std::move(decrypt_result.value());
        }

        // Create plaintext record
        protocol::PlaintextRecord record;
        record.header() = header;
        record.payload() = std::move(payload);

        return make_result(std::move(record));
    }

    Result<std::vector<uint8_t>> create_dtls12_record(
        ContentType content_type,
        const std::vector<uint8_t>& payload,
        const crypto::KeySchedule& keys) override {
        
        protocol::RecordHeader header;
        header.content_type = content_type;
        header.version = protocol::ProtocolVersion::DTLS_1_2;
        header.epoch = current_epoch_;
        header.sequence_number = sequence_number_++;
        header.length = static_cast<uint16_t>(payload.size());

        // Encrypt application data using DTLS 1.2 method
        std::vector<uint8_t> final_payload = payload;
        if (content_type == ContentType::APPLICATION_DATA) {
            auto encrypt_result = encrypt_dtls12_payload(payload, keys, header);
            if (!encrypt_result) {
                return make_error<std::vector<uint8_t>>(encrypt_result.error());
            }
            final_payload = std::move(encrypt_result.value());
            header.length = static_cast<uint16_t>(final_payload.size());
        }

        // Serialize record
        std::vector<uint8_t> record_data;
        record_data.resize(protocol::RecordHeader::SERIALIZED_SIZE + final_payload.size());
        
        auto serialize_result = header.serialize(record_data);
        if (!serialize_result) {
            return make_error<std::vector<uint8_t>>(DTLSError::SERIALIZATION_FAILED);
        }

        std::copy(final_payload.begin(), final_payload.end(), 
                 record_data.begin() + protocol::RecordHeader::SERIALIZED_SIZE);

        return make_result(std::move(record_data));
    }

    bool is_dtls12_record(const std::vector<uint8_t>& data) override {
        if (data.size() < 3) return false;
        
        // Check for DTLS 1.2 version (0xFEFD)
        return data[1] == 0xFE && data[2] == 0xFD;
    }

private:
    Result<std::vector<uint8_t>> encrypt_dtls12_payload(
        const std::vector<uint8_t>& payload,
        const crypto::KeySchedule& keys,
        const protocol::RecordHeader& header) {
        
        // DTLS 1.2 uses explicit nonce for AEAD
        std::vector<uint8_t> nonce(8); // 8-byte explicit nonce
        crypto_provider_->generate_random({nonce.size(), true, {}}, nonce);
        
        // Construct full nonce (implicit IV + explicit nonce)
        std::vector<uint8_t> full_nonce(keys.server_write_iv);
        full_nonce.insert(full_nonce.end(), nonce.begin(), nonce.end());
        
        // Construct additional data for AEAD
        std::vector<uint8_t> aad;
        aad.resize(13);
        // Sequence number (8 bytes)
        for (int i = 7; i >= 0; --i) {
            aad[i] = static_cast<uint8_t>((header.sequence_number >> (8 * (7 - i))) & 0xFF);
        }
        aad[8] = static_cast<uint8_t>(header.content_type);
        aad[9] = static_cast<uint8_t>(header.version >> 8);
        aad[10] = static_cast<uint8_t>(header.version & 0xFF);
        aad[11] = static_cast<uint8_t>(payload.size() >> 8);
        aad[12] = static_cast<uint8_t>(payload.size() & 0xFF);
        
        // Encrypt using AEAD
        crypto::AEADParams params;
        params.key = keys.server_write_key;
        params.nonce = full_nonce;
        params.additional_data = aad;
        params.cipher = AEADCipher::AES_128_GCM; // Default, should be based on cipher suite
        
        auto encrypt_result = crypto_provider_->aead_encrypt(params, payload);
        if (!encrypt_result) {
            return make_error<std::vector<uint8_t>>(encrypt_result.error());
        }
        
        // Prepend explicit nonce to ciphertext
        std::vector<uint8_t> final_payload(nonce);
        final_payload.insert(final_payload.end(), 
                           encrypt_result.value().begin(), 
                           encrypt_result.value().end());
        
        return make_result(std::move(final_payload));
    }
    
    Result<std::vector<uint8_t>> decrypt_dtls12_payload(
        const std::vector<uint8_t>& encrypted_payload,
        const crypto::KeySchedule& keys,
        const protocol::RecordHeader& header) {
        
        if (encrypted_payload.size() < 8) {
            return make_error<std::vector<uint8_t>>(DTLSError::DECRYPT_ERROR);
        }
        
        // Extract explicit nonce (first 8 bytes)
        std::vector<uint8_t> explicit_nonce(encrypted_payload.begin(), 
                                          encrypted_payload.begin() + 8);
        
        // Construct full nonce
        std::vector<uint8_t> full_nonce(keys.client_write_iv);
        full_nonce.insert(full_nonce.end(), explicit_nonce.begin(), explicit_nonce.end());
        
        // Extract ciphertext (remaining bytes)
        std::vector<uint8_t> ciphertext(encrypted_payload.begin() + 8, 
                                      encrypted_payload.end());
        
        // Construct additional data
        size_t plaintext_length = ciphertext.size() - 16; // Subtract tag length
        std::vector<uint8_t> aad;
        aad.resize(13);
        for (int i = 7; i >= 0; --i) {
            aad[i] = static_cast<uint8_t>((header.sequence_number >> (8 * (7 - i))) & 0xFF);
        }
        aad[8] = static_cast<uint8_t>(header.content_type);
        aad[9] = static_cast<uint8_t>(header.version >> 8);
        aad[10] = static_cast<uint8_t>(header.version & 0xFF);
        aad[11] = static_cast<uint8_t>(plaintext_length >> 8);
        aad[12] = static_cast<uint8_t>(plaintext_length & 0xFF);
        
        // Decrypt using AEAD
        crypto::AEADParams params;
        params.key = keys.client_write_key;
        params.nonce = full_nonce;
        params.additional_data = aad;
        params.cipher = AEADCipher::AES_128_GCM;
        
        return crypto_provider_->aead_decrypt(params, ciphertext);
    }
};

// DTLS12RecordLayer factory method
std::unique_ptr<DTLS12RecordLayer> DTLS12RecordLayer::create(
    const std::shared_ptr<crypto::CryptoProvider>& crypto_provider) {
    return std::make_unique<DTLS12RecordLayerImpl>(crypto_provider);
}

// DTLS12HandshakeConverter implementation
Result<protocol::ClientHello> DTLS12HandshakeConverter::convert_client_hello_from_dtls12(
    const std::vector<uint8_t>& dtls12_client_hello) {
    
    protocol::ClientHello client_hello;
    
    // Parse DTLS 1.2 ClientHello
    auto deserialize_result = client_hello.deserialize(dtls12_client_hello);
    if (!deserialize_result) {
        return make_error<protocol::ClientHello>(DTLSError::DECODE_ERROR);
    }
    
    // Convert cipher suites to DTLS 1.3 equivalents
    std::vector<CipherSuite> dtls13_cipher_suites;
    for (auto dtls12_suite_value : client_hello.cipher_suites()) {
        auto dtls12_suite = static_cast<DTLS12CipherSuite>(dtls12_suite_value);
        auto it = g_dtls12_to_dtls13_cipher_map.find(dtls12_suite);
        if (it != g_dtls12_to_dtls13_cipher_map.end()) {
            dtls13_cipher_suites.push_back(it->second);
        }
    }
    
    // Update cipher suites in ClientHello
    std::vector<uint16_t> cipher_suite_values;
    for (auto suite : dtls13_cipher_suites) {
        cipher_suite_values.push_back(static_cast<uint16_t>(suite));
    }
    client_hello.set_cipher_suites(cipher_suite_values);
    
    // Add supported_versions extension for DTLS 1.3
    protocol::Extension supported_versions_ext;
    supported_versions_ext.type = static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS);
    
    // Add DTLS 1.3 and 1.2 as supported versions
    std::vector<uint8_t> versions_data;
    versions_data.push_back(4); // Length of version list
    versions_data.push_back(0xFE); versions_data.push_back(0xFC); // DTLS 1.3
    versions_data.push_back(0xFE); versions_data.push_back(0xFD); // DTLS 1.2
    
    supported_versions_ext.data = std::move(versions_data);
    client_hello.add_extension(supported_versions_ext);
    
    return make_result(std::move(client_hello));
}

Result<std::vector<uint8_t>> DTLS12HandshakeConverter::convert_server_hello_to_dtls12(
    const protocol::ServerHello& dtls13_server_hello) {
    
    protocol::ServerHello dtls12_server_hello = dtls13_server_hello;
    
    // Set legacy version to DTLS 1.2
    dtls12_server_hello.set_legacy_version(protocol::ProtocolVersion::DTLS_1_2);
    
    // Convert cipher suite to DTLS 1.2 equivalent
    auto dtls13_suite = static_cast<CipherSuite>(dtls13_server_hello.cipher_suite());
    auto it = g_dtls13_to_dtls12_cipher_map.find(dtls13_suite);
    if (it != g_dtls13_to_dtls12_cipher_map.end()) {
        dtls12_server_hello.set_cipher_suite(static_cast<uint16_t>(it->second));
    }
    
    // Remove DTLS 1.3 specific extensions
    // Note: This is a simplified implementation
    
    return dtls12_server_hello.serialize();
}

Result<CipherSuite> DTLS12HandshakeConverter::map_dtls12_cipher_suite(DTLS12CipherSuite dtls12_suite) {
    auto it = g_dtls12_to_dtls13_cipher_map.find(dtls12_suite);
    if (it != g_dtls12_to_dtls13_cipher_map.end()) {
        return make_result(it->second);
    }
    return make_error<CipherSuite>(DTLSError::CIPHER_SUITE_NOT_SUPPORTED);
}

Result<DTLS12CipherSuite> DTLS12HandshakeConverter::map_dtls13_cipher_suite(CipherSuite dtls13_suite) {
    auto it = g_dtls13_to_dtls12_cipher_map.find(dtls13_suite);
    if (it != g_dtls13_to_dtls12_cipher_map.end()) {
        return make_result(it->second);
    }
    return make_error<DTLS12CipherSuite>(DTLSError::CIPHER_SUITE_NOT_SUPPORTED);
}

Result<protocol::Extension> DTLS12HandshakeConverter::convert_extension_from_dtls12(
    uint16_t extension_type,
    const std::vector<uint8_t>& extension_data) {
    
    protocol::Extension extension;
    extension.type = extension_type;
    extension.data = extension_data;
    
    // Handle specific DTLS 1.2 extensions that need conversion
    switch (extension_type) {
        case DTLS12_EXTENSION_SUPPORTED_VERSIONS:
            // Convert to DTLS 1.3 supported versions format
            break;
        case DTLS12_EXTENSION_SIGNATURE_ALGORITHMS:
            // Signature algorithms are compatible
            break;
        case DTLS12_EXTENSION_SUPPORTED_GROUPS:
            // Supported groups are compatible
            break;
        default:
            // Most extensions are compatible between versions
            break;
    }
    
    return make_result(std::move(extension));
}

// VersionNegotiator implementation
Result<ProtocolVersion> VersionNegotiator::negotiate_version(
    const std::vector<uint8_t>& client_hello_data,
    const DTLS12CompatibilityContext& compat_context) {
    
    // Parse client hello to check supported versions
    protocol::ClientHello client_hello;
    auto parse_result = client_hello.deserialize(client_hello_data);
    if (!parse_result) {
        return make_error<ProtocolVersion>(DTLSError::DECODE_ERROR);
    }
    
    // Check for supported_versions extension
    if (client_hello.has_extension(static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS))) {
        auto extension = client_hello.get_extension(static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS));
        if (extension) {
            auto& data = extension->data;
            if (!data.empty()) {
                // Check if DTLS 1.3 is supported
                for (size_t i = 1; i < data.size(); i += 2) {
                    if (i + 1 < data.size()) {
                        uint16_t version = (data[i] << 8) | data[i + 1];
                        if (version == static_cast<uint16_t>(protocol::ProtocolVersion::DTLS_1_3)) {
                            return make_result(protocol::ProtocolVersion::DTLS_1_3);
                        }
                    }
                }
            }
        }
    }
    
    // Check legacy version field
    if (client_hello.legacy_version() == protocol::ProtocolVersion::DTLS_1_3) {
        return make_result(protocol::ProtocolVersion::DTLS_1_3);
    } else if (client_hello.legacy_version() == protocol::ProtocolVersion::DTLS_1_2 && 
               compat_context.enable_dtls12_fallback) {
        return make_result(protocol::ProtocolVersion::DTLS_1_2);
    }
    
    return make_error<ProtocolVersion>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
}

bool VersionNegotiator::requires_dtls12_fallback(
    const std::vector<uint8_t>& client_hello_data) {
    
    // Simple heuristic: check if client only supports DTLS 1.2
    if (client_hello_data.size() >= 3) {
        // Check legacy version field in ClientHello
        return client_hello_data[0] == 0xFE && client_hello_data[1] == 0xFD;
    }
    return false;
}

Result<std::vector<uint8_t>> VersionNegotiator::create_version_appropriate_server_hello(
    ProtocolVersion negotiated_version,
    const protocol::ServerHello& base_server_hello) {
    
    if (negotiated_version == protocol::ProtocolVersion::DTLS_1_3) {
        return base_server_hello.serialize();
    } else if (negotiated_version == protocol::ProtocolVersion::DTLS_1_2) {
        return DTLS12HandshakeConverter::convert_server_hello_to_dtls12(base_server_hello);
    }
    
    return make_error<std::vector<uint8_t>>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
}

// Utility functions
namespace utils {

bool is_dtls12_compatible_cipher_suite(CipherSuite suite) {
    return g_dtls13_to_dtls12_cipher_map.find(suite) != g_dtls13_to_dtls12_cipher_map.end();
}

SecurityLevel get_dtls12_cipher_security_level(DTLS12CipherSuite suite) {
    switch (suite) {
        case DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return SecurityLevel::HIGH;
        case DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            return SecurityLevel::MEDIUM;
        default:
            return SecurityLevel::LOW;
    }
}

bool dtls12_cipher_provides_pfs(DTLS12CipherSuite suite) {
    // All ECDHE cipher suites provide perfect forward secrecy
    switch (suite) {
        case DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case DTLS12CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case DTLS12CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return true;
        default:
            return false;
    }
}

std::string version_to_string(ProtocolVersion version) {
    switch (version) {
        case ProtocolVersion::DTLS_1_0: return "DTLS 1.0";
        case ProtocolVersion::DTLS_1_2: return "DTLS 1.2";
        case ProtocolVersion::DTLS_1_3: return "DTLS 1.3";
        default: return "Unknown";
    }
}

Result<void> validate_dtls12_context(const DTLS12CompatibilityContext& context) {
    if (context.allowed_dtls12_ciphers.empty()) {
        return make_error<void>(DTLSError::INVALID_CONFIGURATION);
    }
    
    if (context.max_dtls12_connections == 0) {
        return make_error<void>(DTLSError::INVALID_CONFIGURATION);
    }
    
    if (context.dtls12_session_timeout.count() <= 0) {
        return make_error<void>(DTLSError::INVALID_CONFIGURATION);
    }
    
    return make_result();
}

} // namespace utils

} // namespace compatibility
} // namespace v13
} // namespace dtls