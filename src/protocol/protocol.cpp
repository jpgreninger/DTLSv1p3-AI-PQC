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

bool is_valid_handshake_type(HandshakeType type) {
    switch (type) {
        case HandshakeType::CLIENT_HELLO:
        case HandshakeType::SERVER_HELLO:
        case HandshakeType::HELLO_VERIFY_REQUEST_RESERVED:
        case HandshakeType::NEW_SESSION_TICKET:
        case HandshakeType::END_OF_EARLY_DATA:
        case HandshakeType::HELLO_RETRY_REQUEST:
        case HandshakeType::ENCRYPTED_EXTENSIONS:
        case HandshakeType::CERTIFICATE:
        case HandshakeType::SERVER_KEY_EXCHANGE_RESERVED:
        case HandshakeType::CERTIFICATE_REQUEST:
        case HandshakeType::SERVER_HELLO_DONE_RESERVED:
        case HandshakeType::CERTIFICATE_VERIFY:
        case HandshakeType::CLIENT_KEY_EXCHANGE_RESERVED:
        case HandshakeType::FINISHED:
        case HandshakeType::CERTIFICATE_URL_RESERVED:
        case HandshakeType::CERTIFICATE_STATUS_RESERVED:
        case HandshakeType::SUPPLEMENTAL_DATA_RESERVED:
        case HandshakeType::KEY_UPDATE:
        case HandshakeType::MESSAGE_HASH:
            return true;
        default:
            return false;
    }
}

bool is_client_handshake_message(HandshakeType type) {
    switch (type) {
        case HandshakeType::CLIENT_HELLO:
        case HandshakeType::END_OF_EARLY_DATA:
        case HandshakeType::CERTIFICATE:
        case HandshakeType::CERTIFICATE_VERIFY:
        case HandshakeType::CLIENT_KEY_EXCHANGE_RESERVED:
        case HandshakeType::FINISHED:
            return true;
        default:
            return false;
    }
}

bool is_server_handshake_message(HandshakeType type) {
    switch (type) {
        case HandshakeType::SERVER_HELLO:
        case HandshakeType::HELLO_VERIFY_REQUEST_RESERVED:
        case HandshakeType::NEW_SESSION_TICKET:
        case HandshakeType::HELLO_RETRY_REQUEST:
        case HandshakeType::ENCRYPTED_EXTENSIONS:
        case HandshakeType::CERTIFICATE:
        case HandshakeType::SERVER_KEY_EXCHANGE_RESERVED:
        case HandshakeType::CERTIFICATE_REQUEST:
        case HandshakeType::SERVER_HELLO_DONE_RESERVED:
        case HandshakeType::CERTIFICATE_VERIFY:
        case HandshakeType::FINISHED:
        case HandshakeType::CERTIFICATE_STATUS_RESERVED:
        case HandshakeType::KEY_UPDATE:
            return true;
        default:
            return false;
    }
}

}  // namespace dtls::v13::protocol