#include "dtls/protocol.h"

namespace dtls::v13::protocol {

bool is_supported_version(ProtocolVersion version) {
    return version == ProtocolVersion::DTLS_1_3 ||
           version == ProtocolVersion::DTLS_1_2 ||
           version == ProtocolVersion::DTLS_1_0;
}

bool is_valid_content_type(ContentType content_type) {
    switch (content_type) {
        case ContentType::CHANGE_CIPHER_SPEC:
        case ContentType::ALERT:
        case ContentType::HANDSHAKE:
        case ContentType::APPLICATION_DATA:
        case ContentType::HEARTBEAT:
        case ContentType::TLS12_CID:
            return true;
        case ContentType::INVALID:
        default:
            return false;
    }
}

bool is_handshake_content_type(ContentType content_type) {
    return content_type == ContentType::HANDSHAKE;
}

bool is_application_data_content_type(ContentType content_type) {
    return content_type == ContentType::APPLICATION_DATA;
}

}  // namespace dtls::v13::protocol