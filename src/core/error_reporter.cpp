#include <dtls/error_reporter.h>
#include <dtls/error_context.h>
#include <iostream>

namespace dtls {
namespace v13 {

ErrorReporter::ErrorReporter() : config_{} {
}

ErrorReporter::ErrorReporter(const ReportingConfig& config) : config_(config) {
}

ErrorReporter::~ErrorReporter() = default;

Result<void> ErrorReporter::report_error(LogLevel level,
                                        DTLSError error,
                                        const std::string& category,
                                        const std::string& message,
                                        std::shared_ptr<ErrorContext> context) {
    // Stub implementation - just log to stderr
    std::cerr << "[" << category << "] Error " << static_cast<int>(error) 
              << ": " << message << std::endl;
    return make_result();
}

Result<void> ErrorReporter::report_security_incident(DTLSError error,
                                                    const std::string& incident_type,
                                                    double confidence,
                                                    std::shared_ptr<ErrorContext> context) {
    // Stub implementation - just log to stderr
    std::cerr << "[SECURITY] " << incident_type << " (confidence: " << confidence 
              << ") - Error " << static_cast<int>(error) << std::endl;
    return make_result();
}

Result<void> ErrorReporter::update_configuration(const ReportingConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    return make_result();
}

std::string ErrorReporter::error_to_safe_description(DTLSError error) {
    // Return safe, non-sensitive descriptions
    switch (error) {
        case DTLSError::SUCCESS: return "Operation completed successfully";
        case DTLSError::DECRYPT_ERROR: return "Decryption operation failed";
        case DTLSError::HANDSHAKE_FAILURE: return "Handshake process failed";
        case DTLSError::CERTIFICATE_VERIFY_FAILED: return "Certificate verification failed";
        case DTLSError::TIMEOUT: return "Operation timed out";
        case DTLSError::CONNECTION_CLOSED: return "Connection was closed";
        case DTLSError::AUTHENTICATION_FAILED: return "Authentication failed";
        case DTLSError::INVALID_PARAMETER: return "Invalid parameter provided";
        default: return "DTLS operation error occurred";
    }
}


} // namespace v13
} // namespace dtls