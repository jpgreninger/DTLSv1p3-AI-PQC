#ifndef DTLS_TLM_EXTENSIONS_H
#define DTLS_TLM_EXTENSIONS_H

#include "dtls_systemc_types.h"
#include <systemc>
#include <tlm.h>
#include <tlm_utils/tlm_quantumkeeper.h>
#include <memory>
#include <vector>
#include <sstream>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

using namespace ::sc_core;
using namespace ::tlm;

/**
 * DTLS Extension for TLM Generic Payload
 * 
 * Extends TLM generic payload with DTLS-specific transaction information
 * including connection context, security parameters, and performance metrics.
 */
class dtls_extension : public tlm::tlm_extension<dtls_extension> {
public:
    // Connection context
    uint32_t connection_id{0};
    uint16_t epoch{0};
    uint64_t sequence_number{0};
    std::vector<uint8_t> connection_id_data;
    
    // Security parameters
    uint16_t cipher_suite{0};
    uint16_t signature_scheme{0};
    uint16_t named_group{0};
    std::vector<uint8_t> master_secret;
    std::vector<uint8_t> client_random;
    std::vector<uint8_t> server_random;
    
    // Message context
    enum class MessageType {
        HANDSHAKE,
        APPLICATION_DATA,
        ALERT,
        CHANGE_CIPHER_SPEC,
        ACK
    } message_type{MessageType::APPLICATION_DATA};
    
    enum class HandshakeType {
        CLIENT_HELLO = 1,
        SERVER_HELLO = 2,
        NEW_SESSION_TICKET = 4,
        END_OF_EARLY_DATA = 5,
        ENCRYPTED_EXTENSIONS = 8,
        CERTIFICATE = 11,
        CERTIFICATE_REQUEST = 13,
        CERTIFICATE_VERIFY = 15,
        FINISHED = 20,
        KEY_UPDATE = 24,
        MESSAGE_HASH = 254
    } handshake_type{HandshakeType::CLIENT_HELLO};
    
    // Fragmentation information
    bool is_fragmented{false};
    uint16_t fragment_offset{0};
    uint16_t fragment_length{0};
    uint16_t message_length{0};
    uint16_t message_sequence{0};
    
    // Performance tracking
    sc_time processing_start_time{SC_ZERO_TIME};
    sc_time crypto_processing_time{SC_ZERO_TIME};
    sc_time network_processing_time{SC_ZERO_TIME};
    sc_time memory_processing_time{SC_ZERO_TIME};
    
    // Quality of Service
    enum class Priority {
        LOW = 0,
        NORMAL = 1,
        HIGH = 2,
        CRITICAL = 3
    } priority{Priority::NORMAL};
    
    sc_time deadline{SC_ZERO_TIME};
    bool real_time_constraint{false};
    
    // Error information
    bool has_error{false};
    uint8_t alert_level{0};     // 1=warning, 2=fatal
    uint8_t alert_description{0};
    std::string error_message;

public:
    dtls_extension() = default;
    virtual ~dtls_extension() = default;
    
    // TLM extension interface
    virtual tlm_extension_base* clone() const override {
        return new dtls_extension(*this);
    }
    
    virtual void copy_from(const tlm_extension_base& ext) override {
        const dtls_extension& other = static_cast<const dtls_extension&>(ext);
        *this = other;
    }
    
    // Utility methods
    void set_connection_context(uint32_t conn_id, uint16_t ep, uint64_t seq_num) {
        connection_id = conn_id;
        epoch = ep;
        sequence_number = seq_num;
    }
    
    void set_security_parameters(uint16_t cipher, uint16_t sig_scheme, uint16_t group) {
        cipher_suite = cipher;
        signature_scheme = sig_scheme;
        named_group = group;
    }
    
    void set_fragmentation_info(uint16_t offset, uint16_t frag_len, uint16_t msg_len, uint16_t msg_seq) {
        is_fragmented = (frag_len < msg_len);
        fragment_offset = offset;
        fragment_length = frag_len;
        message_length = msg_len;
        message_sequence = msg_seq;
    }
    
    void start_timing() {
        processing_start_time = sc_time_stamp();
    }
    
    void add_crypto_time(sc_time time) {
        crypto_processing_time += time;
    }
    
    void add_network_time(sc_time time) {
        network_processing_time += time;
    }
    
    void add_memory_time(sc_time time) {
        memory_processing_time += time;
    }
    
    sc_time get_total_processing_time() const {
        return crypto_processing_time + network_processing_time + memory_processing_time;
    }
    
    void set_error(uint8_t level, uint8_t description, const std::string& message = "") {
        has_error = true;
        alert_level = level;
        alert_description = description;
        error_message = message;
    }
    
    bool is_handshake_message() const {
        return message_type == MessageType::HANDSHAKE;
    }
    
    bool is_application_data() const {
        return message_type == MessageType::APPLICATION_DATA;
    }
    
    bool needs_fragmentation(uint16_t mtu) const {
        return message_length > mtu;
    }
    
    std::string to_string() const {
        std::ostringstream oss;
        oss << "DTLS Extension [ConnID:" << connection_id 
            << ", Epoch:" << epoch 
            << ", SeqNum:" << sequence_number
            << ", MsgType:" << static_cast<int>(message_type)
            << ", Priority:" << static_cast<int>(priority);
        
        if (is_fragmented) {
            oss << ", Fragmented:" << fragment_offset << "/" << message_length;
        }
        
        if (has_error) {
            oss << ", Error:L" << static_cast<int>(alert_level) << "D" << static_cast<int>(alert_description);
        }
        
        oss << "]";
        return oss.str();
    }
};

/**
 * DTLS Transaction Wrapper
 * 
 * High-level wrapper for TLM transactions with DTLS-specific functionality.
 * Provides convenience methods for creating and managing DTLS transactions.
 */
class dtls_transaction {
private:
    std::unique_ptr<tlm::tlm_generic_payload> payload;
    std::unique_ptr<dtls_extension> extension;
    sc_time delay;

public:
    dtls_transaction() 
        : payload(std::make_unique<tlm::tlm_generic_payload>())
        , extension(std::make_unique<dtls_extension>()) 
        , delay(SC_ZERO_TIME) {
        payload->set_extension(extension.get());
    }
    
    explicit dtls_transaction(size_t data_size)
        : dtls_transaction() {
        allocate_data(data_size);
    }
    
    ~dtls_transaction() {
        if (payload && payload->get_data_ptr()) {
            delete[] payload->get_data_ptr();
        }
    }
    
    // Move constructor and assignment
    dtls_transaction(dtls_transaction&& other) noexcept
        : payload(std::move(other.payload))
        , extension(std::move(other.extension))
        , delay(other.delay) {
        if (payload) {
            payload->set_extension(extension.get());
        }
    }
    
    dtls_transaction& operator=(dtls_transaction&& other) noexcept {
        if (this != &other) {
            payload = std::move(other.payload);
            extension = std::move(other.extension);
            delay = other.delay;
            if (payload) {
                payload->set_extension(extension.get());
            }
        }
        return *this;
    }
    
    // Disable copy constructor and assignment
    dtls_transaction(const dtls_transaction&) = delete;
    dtls_transaction& operator=(const dtls_transaction&) = delete;
    
    // Data management
    void allocate_data(size_t size) {
        unsigned char* data = new unsigned char[size];
        std::memset(data, 0, size);
        payload->set_data_ptr(data);
        payload->set_data_length(size);
        payload->set_streaming_width(size);
    }
    
    void set_data(const unsigned char* data, size_t size) {
        allocate_data(size);
        std::memcpy(payload->get_data_ptr(), data, size);
    }
    
    unsigned char* get_data() const {
        return payload->get_data_ptr();
    }
    
    size_t get_data_size() const {
        return payload->get_data_length();
    }
    
    // TLM payload access
    tlm::tlm_generic_payload& get_payload() {
        return *payload;
    }
    
    const tlm::tlm_generic_payload& get_payload() const {
        return *payload;
    }
    
    // DTLS extension access
    dtls_extension& get_extension() {
        return *extension;
    }
    
    const dtls_extension& get_extension() const {
        return *extension;
    }
    
    // Timing management
    void set_delay(sc_time t) {
        delay = t;
    }
    
    sc_time get_delay() const {
        return delay;
    }
    
    void add_delay(sc_time t) {
        delay += t;
    }
    
    // Transaction configuration
    void configure_as_handshake(dtls_extension::HandshakeType type, uint32_t conn_id) {
        extension->message_type = dtls_extension::MessageType::HANDSHAKE;
        extension->handshake_type = type;
        extension->connection_id = conn_id;
        extension->priority = dtls_extension::Priority::HIGH;
        payload->set_command(tlm::TLM_WRITE_COMMAND);
    }
    
    void configure_as_application_data(uint32_t conn_id, const unsigned char* data, size_t size) {
        extension->message_type = dtls_extension::MessageType::APPLICATION_DATA;
        extension->connection_id = conn_id;
        extension->priority = dtls_extension::Priority::NORMAL;
        set_data(data, size);
        payload->set_command(tlm::TLM_WRITE_COMMAND);
    }
    
    void configure_as_alert(uint8_t level, uint8_t description, uint32_t conn_id) {
        extension->message_type = dtls_extension::MessageType::ALERT;
        extension->connection_id = conn_id;
        extension->priority = (level == 2) ? dtls_extension::Priority::CRITICAL : dtls_extension::Priority::HIGH;
        extension->set_error(level, description);
        payload->set_command(tlm::TLM_WRITE_COMMAND);
    }
    
    // Fragmentation support
    std::vector<dtls_transaction> fragment(uint16_t mtu) {
        std::vector<dtls_transaction> fragments;
        
        size_t data_size = get_data_size();
        if (data_size <= mtu) {
            // No fragmentation needed
            return fragments;
        }
        
        unsigned char* data = get_data();
        uint16_t fragment_count = (data_size + mtu - 1) / mtu;
        
        for (uint16_t i = 0; i < fragment_count; ++i) {
            dtls_transaction fragment;
            
            uint16_t offset = i * mtu;
            uint16_t length = std::min(static_cast<size_t>(mtu), data_size - offset);
            
            fragment.set_data(data + offset, length);
            
            // Copy extension information
            fragment.get_extension() = *extension;
            fragment.get_extension().set_fragmentation_info(
                offset, length, data_size, extension->message_sequence);
            
            // Copy payload settings
            fragment.get_payload().set_command(payload->get_command());
            fragment.get_payload().set_address(payload->get_address() + offset);
            
            fragments.push_back(std::move(fragment));
        }
        
        return fragments;
    }
    
    // Status and validation
    bool is_response_ok() const {
        return payload->get_response_status() == tlm::TLM_OK_RESPONSE;
    }
    
    bool has_error() const {
        return extension->has_error || 
               payload->get_response_status() != tlm::TLM_OK_RESPONSE;
    }
    
    std::string get_error_message() const {
        if (extension->has_error) {
            return extension->error_message;
        }
        
        switch (payload->get_response_status()) {
            case tlm::TLM_GENERIC_ERROR_RESPONSE:
                return "Generic TLM error";
            case tlm::TLM_ADDRESS_ERROR_RESPONSE:
                return "Address error";
            case tlm::TLM_COMMAND_ERROR_RESPONSE:
                return "Command error";
            case tlm::TLM_BURST_ERROR_RESPONSE:
                return "Burst error";
            case tlm::TLM_BYTE_ENABLE_ERROR_RESPONSE:
                return "Byte enable error";
            default:
                return "Unknown error";
        }
    }
    
    // Debug and logging
    std::string to_string() const {
        std::ostringstream oss;
        oss << "DTLS Transaction ["
            << "Size:" << get_data_size()
            << ", Command:" << (payload->get_command() == tlm::TLM_READ_COMMAND ? "READ" : "WRITE")
            << ", Status:" << payload->get_response_status()
            << ", Delay:" << delay
            << ", " << extension->to_string()
            << "]";
        return oss.str();
    }
};

// Output stream operator for dtls_transaction
inline std::ostream& operator<<(std::ostream& os, const dtls_transaction& trans) {
    return os << trans.to_string();
}

/**
 * DTLS Protocol Interface
 * 
 * High-level interface for DTLS protocol operations using TLM transactions.
 * Provides methods for common DTLS operations with proper transaction handling.
 */
class dtls_protocol_interface {
public:
    // Socket types for different protocol layers
    using crypto_socket_type = tlm_utils::simple_initiator_socket<dtls_protocol_interface>;
    using record_socket_type = tlm_utils::simple_initiator_socket<dtls_protocol_interface>;
    using message_socket_type = tlm_utils::simple_initiator_socket<dtls_protocol_interface>;
    using transport_socket_type = tlm_utils::simple_initiator_socket<dtls_protocol_interface>;

private:
    crypto_socket_type* crypto_socket;
    record_socket_type* record_socket;
    message_socket_type* message_socket;
    transport_socket_type* transport_socket;
    
    tlm_utils::tlm_quantumkeeper quantum_keeper;

public:
    dtls_protocol_interface(crypto_socket_type* crypto_sock,
                           record_socket_type* record_sock,
                           message_socket_type* message_sock,
                           transport_socket_type* transport_sock)
        : crypto_socket(crypto_sock)
        , record_socket(record_sock)
        , message_socket(message_sock)
        , transport_socket(transport_sock) {
        quantum_keeper.reset();
    }
    
    // High-level protocol operations
    bool send_client_hello(uint32_t connection_id, const std::vector<uint16_t>& cipher_suites) {
        dtls_transaction trans(1024); // Typical ClientHello size
        trans.configure_as_handshake(dtls_extension::HandshakeType::CLIENT_HELLO, connection_id);
        
        // TODO: Populate ClientHello data
        
        return send_handshake_message(trans);
    }
    
    bool send_server_hello(uint32_t connection_id, uint16_t selected_cipher_suite) {
        dtls_transaction trans(512);
        trans.configure_as_handshake(dtls_extension::HandshakeType::SERVER_HELLO, connection_id);
        
        // TODO: Populate ServerHello data
        
        return send_handshake_message(trans);
    }
    
    bool send_application_data(uint32_t connection_id, const unsigned char* data, size_t size) {
        dtls_transaction trans;
        trans.configure_as_application_data(connection_id, data, size);
        
        return send_protected_data(trans);
    }
    
    bool send_alert(uint32_t connection_id, uint8_t level, uint8_t description) {
        dtls_transaction trans(2); // Alert is 2 bytes
        trans.configure_as_alert(level, description, connection_id);
        
        return send_protocol_message(trans);
    }
    
    // Protocol layer operations
    bool encrypt_data(dtls_transaction& trans) {
        if (!crypto_socket) return false;
        
        sc_time delay = quantum_keeper.get_local_time();
        trans.get_extension().start_timing();
        
        (*crypto_socket)->b_transport(trans.get_payload(), delay);
        
        trans.get_extension().add_crypto_time(delay - quantum_keeper.get_local_time());
        quantum_keeper.set(delay);
        
        return trans.is_response_ok();
    }
    
    bool protect_record(dtls_transaction& trans) {
        if (!record_socket) return false;
        
        sc_time delay = quantum_keeper.get_local_time();
        (*record_socket)->b_transport(trans.get_payload(), delay);
        
        trans.get_extension().add_network_time(delay - quantum_keeper.get_local_time());
        quantum_keeper.set(delay);
        
        return trans.is_response_ok();
    }
    
    bool process_message(dtls_transaction& trans) {
        if (!message_socket) return false;
        
        sc_time delay = quantum_keeper.get_local_time();
        (*message_socket)->b_transport(trans.get_payload(), delay);
        
        trans.add_delay(delay - quantum_keeper.get_local_time());
        quantum_keeper.set(delay);
        
        return trans.is_response_ok();
    }
    
    bool transmit_packet(dtls_transaction& trans) {
        if (!transport_socket) return false;
        
        sc_time delay = quantum_keeper.get_local_time();
        (*transport_socket)->b_transport(trans.get_payload(), delay);
        
        trans.get_extension().add_network_time(delay - quantum_keeper.get_local_time());
        quantum_keeper.set(delay);
        
        return trans.is_response_ok();
    }

private:
    bool send_handshake_message(dtls_transaction& trans) {
        // Process through message layer
        if (!process_message(trans)) {
            return false;
        }
        
        // Protect at record layer
        if (!protect_record(trans)) {
            return false;
        }
        
        // Encrypt if needed
        if (!encrypt_data(trans)) {
            return false;
        }
        
        // Transmit over network
        return transmit_packet(trans);
    }
    
    bool send_protected_data(dtls_transaction& trans) {
        // Encrypt application data
        if (!encrypt_data(trans)) {
            return false;
        }
        
        // Protect at record layer
        if (!protect_record(trans)) {
            return false;
        }
        
        // Transmit over network
        return transmit_packet(trans);
    }
    
    bool send_protocol_message(dtls_transaction& trans) {
        // Process through message layer
        if (!process_message(trans)) {
            return false;
        }
        
        // Protect at record layer
        if (!protect_record(trans)) {
            return false;
        }
        
        // Transmit over network
        return transmit_packet(trans);
    }
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_TLM_EXTENSIONS_H