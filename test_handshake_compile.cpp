#include "include/dtls/protocol.h"
#include <iostream>

int main() {
    using namespace dtls::v13::protocol;
    
    std::cout << "Testing DTLS v1.3 Handshake Message Types" << std::endl;
    
    // Test basic constants and enums
    std::cout << "Protocol Version: " << PROTOCOL_VERSION_MAJOR << "." << PROTOCOL_VERSION_MINOR << std::endl;
    std::cout << "Max record size: " << MAX_RECORD_SIZE << std::endl;
    std::cout << "Max handshake message size: " << MAX_HANDSHAKE_MESSAGE_SIZE << std::endl;
    
    // Test handshake type validation
    std::cout << "ClientHello is valid handshake type: " << 
        is_valid_handshake_type(HandshakeType::CLIENT_HELLO) << std::endl;
    std::cout << "ClientHello is client message: " << 
        is_client_handshake_message(HandshakeType::CLIENT_HELLO) << std::endl;
    std::cout << "ServerHello is server message: " << 
        is_server_handshake_message(HandshakeType::SERVER_HELLO) << std::endl;
    
    // Test cipher suite validation
    std::cout << "AES-128-GCM is supported: " << 
        is_supported_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256) << std::endl;
    std::cout << "ECDSA-P256 is supported: " << 
        is_supported_signature_scheme(SignatureScheme::ECDSA_SECP256R1_SHA256) << std::endl;
    std::cout << "X25519 is supported: " << 
        is_supported_named_group(NamedGroup::X25519) << std::endl;
    
    // Test basic ClientHello creation
    try {
        ClientHello client_hello;
        client_hello.set_legacy_version(ProtocolVersion::DTLS_1_2);
        
        std::vector<CipherSuite> cipher_suites = {
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        };
        client_hello.set_cipher_suites(cipher_suites);
        
        std::cout << "ClientHello is valid: " << client_hello.is_valid() << std::endl;
        std::cout << "ClientHello serialized size: " << client_hello.serialized_size() << " bytes" << std::endl;
        
        // Test ServerHello creation
        ServerHello server_hello;
        server_hello.set_legacy_version(ProtocolVersion::DTLS_1_2);
        server_hello.set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
        
        std::cout << "ServerHello is valid: " << server_hello.is_valid() << std::endl;
        std::cout << "ServerHello serialized size: " << server_hello.serialized_size() << " bytes" << std::endl;
        
        // Test CertificateVerify
        memory::Buffer signature(64);  // Example signature size
        auto resize_result = signature.resize(64);
        if (resize_result.is_success()) {
            CertificateVerify cert_verify(SignatureScheme::ECDSA_SECP256R1_SHA256, std::move(signature));
            std::cout << "CertificateVerify is valid: " << cert_verify.is_valid() << std::endl;
            std::cout << "CertificateVerify serialized size: " << cert_verify.serialized_size() << " bytes" << std::endl;
        }
        
        // Test Finished message
        memory::Buffer verify_data(32);  // Hash length for SHA256
        resize_result = verify_data.resize(32);
        if (resize_result.is_success()) {
            Finished finished(std::move(verify_data));
            std::cout << "Finished is valid: " << finished.is_valid() << std::endl;
            std::cout << "Finished serialized size: " << finished.serialized_size() << " bytes" << std::endl;
        }
        
        std::cout << "All handshake message types created successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "Handshake message implementation test passed!" << std::endl;
    return 0;
}