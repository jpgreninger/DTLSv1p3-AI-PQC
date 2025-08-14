/**
 * @file compatibility_utils.cpp
 * @brief Minimal compatibility utilities implementation
 */

#include "dtls/compatibility/dtls12_compat.h"
#include "dtls/result.h"

namespace dtls {
namespace v13 {
namespace compatibility {
namespace utils {

/**
 * @brief Validate DTLS 1.2 compatibility context - minimal implementation
 */
Result<void> validate_dtls12_context(const DTLS12CompatibilityContext& context) {
    // Basic validation - check if context is minimally valid
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