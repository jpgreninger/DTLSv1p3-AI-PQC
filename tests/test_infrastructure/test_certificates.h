#ifndef DTLS_TEST_CERTIFICATES_H
#define DTLS_TEST_CERTIFICATES_H

#include <string>
#include <vector>

namespace dtls {
namespace test {

/**
 * Test Certificate Infrastructure
 * 
 * Provides test certificates and keys for DTLS integration testing.
 * These are self-signed certificates for testing purposes only.
 */
class TestCertificates {
public:
    /**
     * Get test server certificate in PEM format
     */
    static std::string get_server_certificate();
    
    /**
     * Get test server private key in PEM format
     */
    static std::string get_server_private_key();
    
    /**
     * Get test client certificate in PEM format
     */
    static std::string get_client_certificate();
    
    /**
     * Get test client private key in PEM format
     */
    static std::string get_client_private_key();
    
    /**
     * Get test Certificate Authority certificate in PEM format
     */
    static std::string get_ca_certificate();
    
    /**
     * Get test Certificate Authority private key in PEM format
     */
    static std::string get_ca_private_key();
    
    /**
     * Create temporary certificate files for testing
     * Returns paths to created files
     */
    struct CertificateFiles {
        std::string server_cert_file;
        std::string server_key_file;
        std::string client_cert_file;
        std::string client_key_file;
        std::string ca_cert_file;
    };
    
    static CertificateFiles create_temporary_files();
    
    /**
     * Cleanup temporary certificate files
     */
    static void cleanup_temporary_files(const CertificateFiles& files);
    
    /**
     * Validate certificate chain
     */
    static bool validate_certificate_chain(const std::string& cert_pem, 
                                          const std::string& ca_cert_pem);
};

} // namespace test
} // namespace dtls

#endif // DTLS_TEST_CERTIFICATES_H