#pragma once

#include "dtls/protocol/record.h"

// Main protocol module header for DTLS v1.3
// This header provides access to all protocol-level components

namespace dtls::v13::protocol {

// Version information
constexpr uint16_t PROTOCOL_VERSION_MAJOR = 1;
constexpr uint16_t PROTOCOL_VERSION_MINOR = 3;
constexpr ProtocolVersion DEFAULT_PROTOCOL_VERSION = ProtocolVersion::DTLS_1_3;

// Protocol constants
constexpr size_t MAX_RECORD_SIZE = 16384;  // 2^14 bytes (RFC 9147)
constexpr size_t MAX_HANDSHAKE_MESSAGE_SIZE = 262144;  // 2^18 bytes
constexpr size_t CONNECTION_ID_MAX_LENGTH = 255;
constexpr uint16_t DEFAULT_EPOCH = 0;

// Helper functions for common protocol operations
bool is_supported_version(ProtocolVersion version);
bool is_valid_content_type(ContentType content_type);
bool is_handshake_content_type(ContentType content_type);
bool is_application_data_content_type(ContentType content_type);

}  // namespace dtls::v13::protocol