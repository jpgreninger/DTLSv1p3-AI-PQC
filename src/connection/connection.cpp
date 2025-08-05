#include <dtls/connection.h>
#include <dtls/protocol/message_layer.h>
#include <dtls/protocol/handshake_manager.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/memory/pool.h>
#include <dtls/transport/udp_transport.h>

#include <algorithm>
#include <random>

namespace dtls {
namespace v13 {

// Connection implementation

Connection::Connection(const ConnectionConfig& config,
                      std::unique_ptr<crypto::CryptoProvider> crypto_provider,
                      const NetworkAddress& peer_address,
                      bool is_client,
                      ConnectionEventCallback event_callback)
    : config_(config)
    , crypto_provider_(std::move(crypto_provider))
    , peer_address_(peer_address)
    , is_client_(is_client)
    , state_(ConnectionState::INITIAL)
    , event_callback_(std::move(event_callback)) {
}

Connection::~Connection() {
    // Ensure connection is properly closed during destruction
    if (!force_closed_.load()) {
        force_close();
    }
}

Result<std::unique_ptr<Connection>> Connection::create_client(
    const ConnectionConfig& config,
    std::unique_ptr<crypto::CryptoProvider> crypto_provider,
    const NetworkAddress& server_address,
    ConnectionEventCallback event_callback) {
    
    if (!crypto_provider) {
        return make_error<std::unique_ptr<Connection>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Use private constructor
    auto connection = std::unique_ptr<Connection>(new Connection(
        config, std::move(crypto_provider), server_address, true, std::move(event_callback)
    ));
    
    return make_result(std::move(connection));
}

Result<std::unique_ptr<Connection>> Connection::create_server(
    const ConnectionConfig& config,
    std::unique_ptr<crypto::CryptoProvider> crypto_provider,
    const NetworkAddress& client_address,
    ConnectionEventCallback event_callback) {
    
    if (!crypto_provider) {
        return make_error<std::unique_ptr<Connection>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Use private constructor
    auto connection = std::unique_ptr<Connection>(new Connection(
        config, std::move(crypto_provider), client_address, false, std::move(event_callback)
    ));
    
    return make_result(std::move(connection));
}

Result<void> Connection::initialize() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ != ConnectionState::INITIAL) {
        return make_error<void>(DTLSError::ALREADY_INITIALIZED);
    }
    
    // TODO: Initialize record layer properly when provider cloning is implemented
    // For now, skip record layer initialization to fix compilation
    // record_layer_ = std::make_unique<protocol::RecordLayer>(crypto_provider);
    // auto record_result = record_layer_->initialize();
    // if (!record_result) {
    //     return record_result;
    // }
    
    // Initialize transport layer
    transport::TransportConfig transport_config;
    transport_config.receive_buffer_size = config_.receive_buffer_size;
    transport_config.send_buffer_size = config_.send_buffer_size;
    
    transport_ = std::make_unique<transport::UDPTransport>(transport_config);
    auto transport_result = transport_->initialize();
    if (!transport_result) {
        return transport_result;
    }
    
    // Set transport event callback
    transport_->set_event_callback([this](transport::TransportEvent event,
                                          const transport::NetworkEndpoint& endpoint,
                                          const std::vector<uint8_t>& data) {
        handle_transport_event(event, endpoint, data);
    });
    
    // Initialize message layer (will be implemented when message layer utilities exist)
    // message_layer_ = std::make_unique<protocol::MessageLayer>();
    // auto message_result = message_layer_->initialize();
    // if (!message_result) {
    //     return message_result;
    // }
    
    // Initialize handshake manager with ACK support
    protocol::HandshakeManager::Config handshake_config;
    handshake_config.initial_timeout = config_.retransmission_timeout;
    handshake_config.max_timeout = config_.handshake_timeout;
    handshake_config.max_retransmissions = config_.max_retransmissions;
    handshake_config.enable_ack_processing = true; // Enable ACK processing
    
    handshake_manager_ = std::make_unique<protocol::HandshakeManager>(handshake_config);
    
    // Initialize record layer with its own crypto provider instance
    auto record_crypto_result = crypto::ProviderFactory::instance().create_default_provider();
    if (!record_crypto_result) {
        return make_error<void>(DTLSError::CRYPTO_PROVIDER_ERROR, "Failed to create crypto provider for record layer");
    }
    record_layer_ = std::make_unique<protocol::RecordLayer>(std::move(record_crypto_result.value()));
    
    // Setup handshake manager callbacks
    auto send_callback = [this](const protocol::HandshakeMessage& message) -> Result<void> {
        return send_handshake_message(message);
    };
    
    auto event_callback = [this](protocol::HandshakeEvent event, const std::vector<uint8_t>& data) {
        // Map handshake events to connection events
        switch (event) {
            case protocol::HandshakeEvent::HANDSHAKE_COMPLETE:
                fire_event(ConnectionEvent::HANDSHAKE_COMPLETED, data);
                break;
            case protocol::HandshakeEvent::HANDSHAKE_FAILED:
                fire_event(ConnectionEvent::HANDSHAKE_FAILED, data);
                break;
            case protocol::HandshakeEvent::RETRANSMISSION_NEEDED:
                stats_.handshake_retransmissions++;
                break;
            default:
                // Other events are handled internally
                break;
        }
    };
    
    auto init_result = handshake_manager_->initialize(send_callback, event_callback);
    if (!init_result) {
        return init_result;
    }
    
    // Initialize record layer
    auto record_init_result = record_layer_->initialize();
    if (!record_init_result) {
        return record_init_result;
    }
    
    // Update statistics
    stats_.connection_start = std::chrono::steady_clock::now();
    stats_.last_activity = stats_.connection_start;
    
    return make_result();
}

Result<void> Connection::start_handshake() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ != ConnectionState::INITIAL) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Transition to waiting state based on client/server role
    if (is_client_) {
        auto result = transition_state(ConnectionState::WAIT_SERVER_HELLO);
        if (!result) {
            return result;
        }
        
        // TODO: Send ClientHello message
        fire_event(ConnectionEvent::HANDSHAKE_STARTED);
        
    } else {
        auto result = transition_state(ConnectionState::WAIT_CLIENT_CERTIFICATE);
        if (!result) {
            return result;
        }
        
        fire_event(ConnectionEvent::HANDSHAKE_STARTED);
    }
    
    update_last_activity();
    return make_result();
}

Result<void> Connection::process_incoming_data(const memory::ZeroCopyBuffer& data) {
    if (force_closed_ || is_closing_) {
        return make_error<void>(DTLSError::CONNECTION_CLOSED);
    }
    
    update_last_activity();
    
    // Parse DTLS records from incoming data
    size_t offset = 0;
    const std::byte* buffer = data.data();
    size_t remaining = data.size();
    
    while (remaining >= protocol::RecordHeader::SERIALIZED_SIZE) {
        // Extract record header
        protocol::RecordHeader header;
        auto buffer_slice = data.slice(offset, protocol::RecordHeader::SERIALIZED_SIZE);
        if (!buffer_slice) {
            return make_error<void>(DTLSError::INVALID_RECORD_HEADER);
        }
        auto header_result = protocol::RecordHeader::deserialize(buffer_slice.value(), 0);
        if (!header_result) {
            return make_error<void>(DTLSError::INVALID_RECORD_HEADER);
        }
        
        // Check if we have complete record
        size_t record_size = protocol::RecordHeader::SERIALIZED_SIZE + header_result.value().length;
        if (remaining < record_size) {
            // Incomplete record, wait for more data
            break;
        }
        
        // Create record buffer
        auto record_buffer_result = data.slice(offset, record_size);
        if (!record_buffer_result) {
            return make_error<void>(DTLSError::INSUFFICIENT_BUFFER);
        }
        auto record_buffer = std::move(record_buffer_result.value());
        
        // Process the record
        auto process_result = process_record_data(record_buffer);
        if (!process_result) {
            return process_result;
        }
        
        offset += record_size;
        remaining -= record_size;
        stats_.records_received++;
    }
    
    stats_.bytes_received += offset;
    return make_result();
}

Result<void> Connection::process_record_data(const memory::ZeroCopyBuffer& record_data) {
    // Try deserializing as DTLSCiphertext first (new format)
    auto dtls_ciphertext_result = protocol::DTLSCiphertext::deserialize(record_data, 0);
    if (dtls_ciphertext_result) {
        // Process through record layer
        auto plaintext_result = record_layer_->process_incoming_record(dtls_ciphertext_result.value());
        if (!plaintext_result) {
            stats_.decrypt_errors++;
            return make_error<void>(plaintext_result.error());
        }
        
        return process_dtls_plaintext_record(plaintext_result.value());
    }
    
    // Fallback to legacy CiphertextRecord format
    auto ciphertext_result = protocol::CiphertextRecord::deserialize(record_data, 0);
    if (!ciphertext_result) {
        return make_error<void>(DTLSError::INVALID_CIPHERTEXT_RECORD);
    }
    
    auto ciphertext = std::move(ciphertext_result.value());
    
    // Convert legacy format to DTLSCiphertext and process
    auto converted_result = convert_legacy_to_dtls_ciphertext(ciphertext);
    if (!converted_result) {
        return converted_result.error();
    }
    
    auto plaintext_result = record_layer_->process_incoming_record(converted_result.value());
    if (!plaintext_result) {
        stats_.decrypt_errors++;
        return make_error<void>(plaintext_result.error());
    }
    
    return process_dtls_plaintext_record(plaintext_result.value());
}

Result<void> Connection::process_record(const protocol::PlaintextRecord& record) {
    const auto& header = record.header();
    
    switch (header.content_type) {
        case protocol::ContentType::HANDSHAKE:
            return handle_handshake_data(record.payload());
            
        case protocol::ContentType::APPLICATION_DATA:
            return handle_application_data(record.payload());
            
        case protocol::ContentType::ALERT:
            return handle_alert_data(record.payload());
            
        case protocol::ContentType::CHANGE_CIPHER_SPEC:
            // Deprecated in DTLS v1.3, ignore
            return make_result();
            
        default:
            return make_error<void>(DTLSError::INVALID_CONTENT_TYPE);
    }
}

Result<void> Connection::process_dtls_plaintext_record(const protocol::DTLSPlaintext& record) {
    switch (record.get_type()) {
        case protocol::ContentType::HANDSHAKE:
            return handle_handshake_data(record.get_fragment());
            
        case protocol::ContentType::APPLICATION_DATA:
            return handle_application_data(record.get_fragment());
            
        case protocol::ContentType::ALERT:
            return handle_alert_data(record.get_fragment());
            
        case protocol::ContentType::CHANGE_CIPHER_SPEC:
            // Deprecated in DTLS v1.3, ignore
            return make_result();
            
        default:
            return make_error<void>(DTLSError::INVALID_CONTENT_TYPE);
    }
}

Result<protocol::DTLSCiphertext> Connection::convert_legacy_to_dtls_ciphertext(const protocol::CiphertextRecord& legacy_record) {
    const auto& header = legacy_record.header();
    
    // Convert sequence number to SequenceNumber48
    protocol::SequenceNumber48 encrypted_seq_num(header.sequence_number);
    
    // Create ZeroCopyBuffer from encrypted payload
    memory::ZeroCopyBuffer encrypted_payload(
        legacy_record.encrypted_payload().data(), 
        legacy_record.encrypted_payload().size()
    );
    
    // Create DTLSCiphertext from legacy record
    protocol::DTLSCiphertext dtls_ciphertext(
        header.content_type,
        header.version,
        header.epoch,
        encrypted_seq_num,
        std::move(encrypted_payload)
    );
    
    return make_result(std::move(dtls_ciphertext));
}

Result<protocol::PlaintextRecord> Connection::convert_dtls_to_legacy_plaintext(const protocol::DTLSPlaintext& dtls_record) {
    // Create a copy of the fragment buffer
    memory::Buffer fragment_copy(dtls_record.get_fragment().data(), dtls_record.get_fragment().size());
    
    // Create legacy plaintext record using constructor parameters
    protocol::PlaintextRecord legacy_record(
        dtls_record.get_type(),
        dtls_record.get_version(),
        dtls_record.get_epoch(),
        dtls_record.get_sequence_number(),
        std::move(fragment_copy)
    );
    
    return make_result(std::move(legacy_record));
}

Result<void> Connection::handle_handshake_data(const memory::ZeroCopyBuffer& data) {
    // Process handshake messages through message layer for fragmentation handling
    // TODO: Implement when message layer utilities exist
    // auto messages_result = message_layer_->process_handshake_data(data);
    // if (!messages_result) {
    //     return messages_result.error();
    // }
    
    // For now, create a dummy handshake message for processing
    protocol::HandshakeMessage dummy_message;
    auto handle_result = handle_handshake_message(dummy_message);
    if (!handle_result) {
        fire_event(ConnectionEvent::HANDSHAKE_FAILED);
        return handle_result;
    }
    
    return make_result();
}

Result<void> Connection::handle_handshake_message(const protocol::HandshakeMessage& message) {
    // Process message through HandshakeManager for ACK support and reliability
    if (handshake_manager_) {
        auto process_result = handshake_manager_->process_message(message);
        if (!process_result) {
            fire_event(ConnectionEvent::HANDSHAKE_FAILED);
            return process_result;
        }
    }
    
    // Handle ACK messages specifically
    if (message.message_type() == HandshakeType::ACK) {
        if (message.holds<protocol::ACK>()) {
            return handle_ack_message(message.get<protocol::ACK>());
        }
        return make_result(); // ACK processed by HandshakeManager
    }
    
    // State machine processing for non-ACK messages
    switch (message.message_type()) {
        case HandshakeType::CLIENT_HELLO:
            return handle_client_hello_message(message);
            
        case HandshakeType::SERVER_HELLO:
            return handle_server_hello_message(message);
            
        case HandshakeType::HELLO_RETRY_REQUEST:
            return handle_hello_retry_request_message(message);
            
        case HandshakeType::ENCRYPTED_EXTENSIONS:
            return handle_encrypted_extensions_message(message);
            
        case HandshakeType::CERTIFICATE_REQUEST:
            return handle_certificate_request_message(message);
            
        case HandshakeType::CERTIFICATE:
            return handle_certificate_message(message);
            
        case HandshakeType::CERTIFICATE_VERIFY:
            return handle_certificate_verify_message(message);
            
        case HandshakeType::FINISHED:
            return handle_finished_message(message);
            
        case HandshakeType::NEW_SESSION_TICKET:
            return handle_new_session_ticket_message(message);
            
        case HandshakeType::KEY_UPDATE:
            return handle_key_update_message(message);
            
        case HandshakeType::END_OF_EARLY_DATA:
            return handle_end_of_early_data_message(message);
            
        default:
            // Unknown handshake message type
            return make_error<void>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    return make_result();
}

Result<void> Connection::handle_application_data(const memory::ZeroCopyBuffer& data) {
    if (state_ != ConnectionState::CONNECTED) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Add to receive queue (move to avoid copy)
    {
        std::lock_guard<std::mutex> lock(receive_queue_mutex_);
        receive_queue_.push_back(std::move(const_cast<memory::ZeroCopyBuffer&>(data)));
    }
    
    fire_event(ConnectionEvent::DATA_RECEIVED, std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(data.data()), 
        reinterpret_cast<const uint8_t*>(data.data()) + data.size()));
    return make_result();
}

Result<void> Connection::handle_alert_data(const memory::ZeroCopyBuffer& data) {
    if (data.size() < 2) {
        return make_error<void>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    AlertLevel level = static_cast<AlertLevel>(reinterpret_cast<const uint8_t*>(data.data())[0]);
    AlertDescription description = static_cast<AlertDescription>(reinterpret_cast<const uint8_t*>(data.data())[1]);
    
    return handle_alert(level, description);
}

Result<void> Connection::handle_alert(AlertLevel level, AlertDescription description) {
    fire_event(ConnectionEvent::ALERT_RECEIVED, {static_cast<uint8_t>(level), static_cast<uint8_t>(description)});
    
    if (level == AlertLevel::FATAL) {
        // Fatal alert, close connection
        transition_state(ConnectionState::CLOSED);
        fire_event(ConnectionEvent::CONNECTION_CLOSED);
        return make_error<void>(DTLSError::CONNECTION_CLOSED);
    }
    
    // Handle warning alerts
    switch (description) {
        case AlertDescription::CLOSE_NOTIFY:
            transition_state(ConnectionState::CLOSED);
            fire_event(ConnectionEvent::CONNECTION_CLOSED);
            break;
            
        default:
            // Log warning but continue
            break;
    }
    
    return make_result();
}

Result<void> Connection::send_application_data(const memory::ZeroCopyBuffer& data) {
    if (!is_connection_valid_for_operations()) {
        // Record error and potentially attempt recovery
        if (config_.error_recovery.enable_automatic_recovery) {
            recover_from_error(DTLSError::CONNECTION_CLOSED, "send_application_data: connection not valid");
        }
        return make_error<void>(DTLSError::CONNECTION_CLOSED);
    }
    
    if (state_ != ConnectionState::CONNECTED) {
        // Record error and potentially attempt recovery
        if (config_.error_recovery.enable_automatic_recovery) {
            recover_from_error(DTLSError::STATE_MACHINE_ERROR, "send_application_data: invalid state");
        }
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Create DTLSPlaintext record for application data
    memory::Buffer fragment_buffer(data.data(), data.size());
    protocol::DTLSPlaintext plaintext_record(
        protocol::ContentType::APPLICATION_DATA,
        protocol::ProtocolVersion::DTLS_1_3,
        1, // Current epoch - should come from record layer
        protocol::SequenceNumber48(0), // Will be set by record layer
        std::move(fragment_buffer)
    );
    
    // Protect the record through the record layer
    auto protected_result = record_layer_->prepare_outgoing_record(plaintext_record);
    if (!protected_result) {
        return make_error<void>(protected_result.error());
    }
    
    // Serialize the protected record
    memory::Buffer send_buffer(protected_result.value().total_size());
    auto serialize_result = protected_result.value().serialize(send_buffer);
    if (!serialize_result) {
        return make_error<void>(serialize_result.error());
    }
    
    // Convert to ZeroCopyBuffer for transport
    memory::ZeroCopyBuffer transport_buffer(send_buffer.data(), serialize_result.value());
    
    // TODO: Convert peer address to transport endpoint properly
    // For now, use a placeholder endpoint 
    transport::NetworkEndpoint peer_endpoint("127.0.0.1", 12345);
    
    // Send through transport layer
    auto send_result = transport_->send_packet(peer_endpoint, transport_buffer);
    if (!send_result) {
        return send_result;
    }
    
    // Update statistics
    stats_.bytes_sent += data.size();
    stats_.records_sent++;
    
    update_last_activity();
    return make_result();
}

Result<memory::ZeroCopyBuffer> Connection::receive_application_data() {
    std::lock_guard<std::mutex> lock(receive_queue_mutex_);
    
    if (receive_queue_.empty()) {
        return make_error<memory::ZeroCopyBuffer>(DTLSError::RESOURCE_UNAVAILABLE);
    }
    
    auto data = std::move(receive_queue_.front());
    receive_queue_.erase(receive_queue_.begin());
    
    return make_result(std::move(data));
}

Result<void> Connection::close() {
    if (force_closed_.load()) {
        return make_result();
    }
    
    // Check if already closed under mutex protection
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (state_ == ConnectionState::CLOSED) {
            return make_result();
        }
    }
    
    // Set closing flag to prevent new operations
    is_closing_.store(true);
    
    // Send close_notify alert if connection is established
    if (state_ == ConnectionState::CONNECTED) {
        auto alert_result = send_close_notify_alert();
        if (!alert_result.is_success()) {
            // Log error but continue with closure
            // Note: In production, this might be logged via a logging system
        }
    }
    
    // Transition to closed state
    auto transition_result = transition_state(ConnectionState::CLOSED);
    if (transition_result.is_success()) {
        fire_event(ConnectionEvent::CONNECTION_CLOSED);
    }
    
    // Always attempt cleanup even if state transition fails
    auto cleanup_result = cleanup_resources();
    
    // Return the first error encountered, if any
    if (!transition_result.is_success()) {
        return transition_result;
    }
    return cleanup_result;
}

void Connection::force_close() {
    force_closed_.store(true);
    is_closing_.store(true);
    
    // Force state to closed without normal transition validation
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        state_ = ConnectionState::CLOSED;
    }
    
    // Cleanup all resources
    auto cleanup_result = cleanup_resources();
    
    // Fire connection closed event
    fire_event(ConnectionEvent::CONNECTION_CLOSED);
    
    // Note: Ignoring cleanup errors in force close since this is emergency cleanup
}

bool Connection::is_connected() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_ == ConnectionState::CONNECTED;
}

bool Connection::is_handshake_complete() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_ == ConnectionState::CONNECTED;
}

ConnectionState Connection::get_state() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_;
}

const ConnectionStats& Connection::get_stats() const {
    return stats_;
}

const ConnectionConfig& Connection::get_config() const {
    return config_;
}

Result<ConnectionID> Connection::get_local_connection_id() const {
    if (!config_.enable_connection_id) {
        return make_error<ConnectionID>(DTLSError::FEATURE_NOT_ENABLED);
    }
    
    // TODO: Get from record layer connection ID manager
    return make_error<ConnectionID>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<ConnectionID> Connection::get_peer_connection_id() const {
    if (!config_.enable_connection_id) {
        return make_error<ConnectionID>(DTLSError::FEATURE_NOT_ENABLED);
    }
    
    // TODO: Get from record layer connection ID manager
    return make_error<ConnectionID>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<void> Connection::update_keys() {
    if (!is_connection_valid_for_operations()) {
        return make_error<void>(DTLSError::CONNECTION_CLOSED);
    }
    
    if (state_ != ConnectionState::CONNECTED) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Create KeyUpdate message (request peer to also update keys)
    protocol::KeyUpdate key_update_msg(protocol::KeyUpdateRequest::UPDATE_REQUESTED);
    
    // Create handshake message
    auto handshake_message = protocol::HandshakeMessage(key_update_msg, get_next_handshake_sequence());
    
    // Serialize the handshake message
    memory::Buffer message_buffer(handshake_message.serialized_size());
    auto serialize_result = handshake_message.serialize(message_buffer);
    if (!serialize_result.is_success()) {
        return make_error<void>(serialize_result.error());
    }
    
    // Create DTLS plaintext record for the handshake message
    protocol::DTLSPlaintext plaintext(
        protocol::ContentType::HANDSHAKE,
        protocol::ProtocolVersion::DTLS_1_3,
        1, // Default epoch since record_layer_ is not initialized
        protocol::SequenceNumber48(0), // Will be set by record layer
        std::move(message_buffer)
    );
    
    // Send the KeyUpdate message through record layer
    auto protected_result = record_layer_->prepare_outgoing_record(plaintext);
    if (!protected_result) {
        return make_error<void>(protected_result.error());
    }
    
    // Serialize and send the protected record
    memory::Buffer send_buffer(protected_result.value().total_size());
    auto protected_serialize_result = protected_result.value().serialize(send_buffer);
    if (!protected_serialize_result) {
        return make_error<void>(protected_serialize_result.error());
    }
    
    // TODO: Send through transport layer (similar to send_application_data)
    
    // Update our traffic keys using record layer
    auto key_update_result = record_layer_->update_traffic_keys();
    if (!key_update_result) {
        return key_update_result;
    }
    
    // Update connection statistics
    stats_.key_updates_performed++;
    stats_.last_activity = std::chrono::steady_clock::now();
    
    // Fire key update completed event
    fire_event(ConnectionEvent::KEY_UPDATE_COMPLETED);
    
    return make_result();
}

Result<std::vector<uint8_t>> Connection::export_key_material(
    const std::string& label,
    const std::vector<uint8_t>& context,
    size_t length) {
    
    if (state_ != ConnectionState::CONNECTED) {
        return make_error<std::vector<uint8_t>>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // TODO: Implement key export using crypto provider
    return make_error<std::vector<uint8_t>>(DTLSError::OPERATION_NOT_SUPPORTED);
}

void Connection::set_event_callback(ConnectionEventCallback callback) {
    event_callback_ = std::move(callback);
}

const NetworkAddress& Connection::get_peer_address() const {
    return peer_address_;
}

bool Connection::is_client() const {
    return is_client_;
}

bool Connection::is_server() const {
    return !is_client_;
}

Result<void> Connection::process_handshake_timeouts() {
    if (!handshake_manager_) {
        return make_result();
    }
    
    // Only process timeouts during active handshake states
    if (!should_process_ack_for_state(state_)) {
        return make_result();
    }
    
    auto timeout_result = handshake_manager_->process_timeouts();
    if (!timeout_result) {
        // Timeout processing failed, might indicate handshake failure
        fire_event(ConnectionEvent::HANDSHAKE_FAILED);
        return timeout_result;
    }
    
    update_last_activity();
    return make_result();
}

// Private helper methods

Result<void> Connection::transition_state(ConnectionState new_state) {
    // Validate state transition according to RFC 9147
    if (!is_valid_state_transition(state_, new_state)) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    ConnectionState old_state = state_;
    
    // Perform state-specific transition logic
    auto transition_result = perform_state_transition(old_state, new_state);
    if (!transition_result) {
        return transition_result;
    }
    
    // Update state
    state_ = new_state;
    
    // Log state transition for debugging
    // In production, this might be configurable logging
    
    // Fire state-specific events
    fire_state_transition_events(old_state, new_state);
    
    return make_result();
}

void Connection::fire_event(ConnectionEvent event, const std::vector<uint8_t>& data) {
    if (event_callback_) {
        event_callback_(event, data);
    }
}

bool Connection::is_valid_state_transition(ConnectionState from, ConnectionState to) const {
    // Define valid state transitions according to RFC 9147
    switch (from) {
        case ConnectionState::INITIAL:
            return (to == ConnectionState::WAIT_SERVER_HELLO && is_client_) ||
                   (to == ConnectionState::WAIT_CLIENT_CERTIFICATE && !is_client_) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_SERVER_HELLO:
            return (to == ConnectionState::WAIT_ENCRYPTED_EXTENSIONS) ||
                   (to == ConnectionState::EARLY_DATA && is_client_) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_ENCRYPTED_EXTENSIONS:
            return (to == ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST) ||
                   (to == ConnectionState::WAIT_SERVER_FINISHED) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST:
            return (to == ConnectionState::WAIT_CERTIFICATE_VERIFY) ||
                   (to == ConnectionState::WAIT_CLIENT_CERTIFICATE) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_CERTIFICATE_VERIFY:
            return (to == ConnectionState::WAIT_SERVER_FINISHED && is_client_) ||
                   (to == ConnectionState::WAIT_CLIENT_FINISHED && !is_client_) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_SERVER_FINISHED:
            return (to == ConnectionState::CONNECTED) ||
                   (to == ConnectionState::WAIT_CLIENT_CERTIFICATE) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_CLIENT_CERTIFICATE:
            return (to == ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY) ||
                   (to == ConnectionState::WAIT_CLIENT_FINISHED) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY:
            return (to == ConnectionState::WAIT_CLIENT_FINISHED) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_CLIENT_FINISHED:
            return (to == ConnectionState::CONNECTED) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::EARLY_DATA:
            return (to == ConnectionState::WAIT_END_OF_EARLY_DATA) ||
                   (to == ConnectionState::EARLY_DATA_REJECTED) ||
                   (to == ConnectionState::WAIT_ENCRYPTED_EXTENSIONS) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::WAIT_END_OF_EARLY_DATA:
            return (to == ConnectionState::WAIT_ENCRYPTED_EXTENSIONS) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::EARLY_DATA_REJECTED:
            return (to == ConnectionState::WAIT_ENCRYPTED_EXTENSIONS) ||
                   (to == ConnectionState::CLOSED);
            
        case ConnectionState::CONNECTED:
            return (to == ConnectionState::CLOSED);
            
        case ConnectionState::CLOSED:
            return false; // No transitions from closed state
            
        default:
            return false; // Unknown state
    }
}

Result<void> Connection::perform_state_transition(ConnectionState from, ConnectionState to) {
    // Perform state-specific setup and validation
    switch (to) {
        case ConnectionState::WAIT_SERVER_HELLO:
            if (is_client_) {
                // Client transitioning to wait for ServerHello
                // Update handshake timeout
                update_last_activity();
                return make_result();
            }
            break;
            
        case ConnectionState::WAIT_ENCRYPTED_EXTENSIONS:
            // Prepare to receive EncryptedExtensions
            if (is_client_) {
                update_last_activity();
            }
            return make_result();
            
        case ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST:
            // Prepare for certificate or certificate request
            update_last_activity();
            return make_result();
            
        case ConnectionState::WAIT_CERTIFICATE_VERIFY:
            // Prepare for certificate verification
            update_last_activity();
            return make_result();
            
        case ConnectionState::WAIT_SERVER_FINISHED:
            if (is_client_) {
                // Client waiting for server's Finished message
                update_last_activity();
            }
            return make_result();
            
        case ConnectionState::WAIT_CLIENT_CERTIFICATE:
            if (!is_client_) {
                // Server waiting for client certificate
                update_last_activity();
            }
            return make_result();
            
        case ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY:
            if (!is_client_) {
                // Server waiting for client certificate verification
                update_last_activity();
            }
            return make_result();
            
        case ConnectionState::WAIT_CLIENT_FINISHED:
            if (!is_client_) {
                // Server waiting for client's Finished message
                update_last_activity();
            }
            return make_result();
            
        case ConnectionState::EARLY_DATA:
            if (is_client_ && config_.enable_early_data) {
                // Client entering early data state
                std::lock_guard<std::mutex> lock(early_data_mutex_);
                early_data_context_.state = protocol::EarlyDataState::SENDING;
                early_data_context_.start_time = std::chrono::steady_clock::now();
                update_last_activity();
                return make_result();
            }
            return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
            
        case ConnectionState::WAIT_END_OF_EARLY_DATA:
            if (!is_client_) {
                // Server waiting for EndOfEarlyData message
                update_last_activity();
                return make_result();
            }
            return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
            
        case ConnectionState::EARLY_DATA_REJECTED:
            if (config_.enable_early_data) {
                // Early data was rejected
                std::lock_guard<std::mutex> lock(early_data_mutex_);
                early_data_context_.state = protocol::EarlyDataState::REJECTED;
                update_last_activity();
                return make_result();
            }
            return make_result();
            
        case ConnectionState::CONNECTED:
            // Handshake completed successfully
            {
                std::lock_guard<std::mutex> lock(early_data_mutex_);
                if (early_data_context_.state == protocol::EarlyDataState::SENDING) {
                    early_data_context_.state = protocol::EarlyDataState::ACCEPTED;
                }
            }
            
            // Calculate handshake duration
            stats_.handshake_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - stats_.connection_start
            );
            
            update_last_activity();
            return make_result();
            
        case ConnectionState::CLOSED:
            // Connection closed
            // Cleanup will be handled by the calling code
            return make_result();
            
        default:
            return make_result();
    }
    
    return make_result();
}

void Connection::fire_state_transition_events(ConnectionState from, ConnectionState to) {
    // Fire events based on state transitions
    switch (to) {
        case ConnectionState::EARLY_DATA:
            // No specific event - early data events are fired when data is sent/received
            break;
            
        case ConnectionState::EARLY_DATA_REJECTED:
            fire_event(ConnectionEvent::EARLY_DATA_REJECTED);
            break;
            
        case ConnectionState::CONNECTED:
            if (from != ConnectionState::CONNECTED) {
                fire_event(ConnectionEvent::HANDSHAKE_COMPLETED);
                
                // Check if early data was accepted
                {
                    std::lock_guard<std::mutex> lock(early_data_mutex_);
                    if (early_data_context_.state == protocol::EarlyDataState::ACCEPTED) {
                        fire_event(ConnectionEvent::EARLY_DATA_ACCEPTED);
                    }
                }
            }
            break;
            
        case ConnectionState::CLOSED:
            if (from != ConnectionState::CLOSED) {
                fire_event(ConnectionEvent::CONNECTION_CLOSED);
            }
            break;
            
        default:
            // No specific events for other state transitions
            break;
    }
}

Result<void> Connection::cleanup_resources() {
    // Ensure cleanup is idempotent - can be called multiple times safely
    if (state_ == ConnectionState::CLOSED && !crypto_provider_ && !transport_) {
        return make_result(); // Already cleaned up
    }
    
    // Clear application data buffers
    {
        std::lock_guard<std::mutex> lock(receive_queue_mutex_);
        receive_queue_.clear();
        receive_queue_.shrink_to_fit(); // Release memory
    }
    
    // Clear early data context and buffers
    {
        std::lock_guard<std::mutex> lock(early_data_mutex_);
        early_data_context_ = protocol::EarlyDataContext{}; // Reset to default state
    }
    
    // Stop and cleanup transport layer
    if (transport_) {
        try {
            transport_->stop();
        } catch (...) {
            // Ignore transport stop errors during cleanup
        }
        transport_.reset();
    }
    
    // Reset protocol layer managers (they will clean up automatically via destructors)
    handshake_manager_.reset();
    
    // Reset early data management
    session_ticket_manager_.reset();
    replay_protection_.reset();
    
    // Reset record and message layers
    record_layer_.reset();
    // message_layer_.reset();      // Still commented out due to incomplete type
    
    // Cleanup crypto provider resources
    if (crypto_provider_) {
        try {
            crypto_provider_->cleanup();
        } catch (...) {
            // Ignore crypto cleanup errors during connection cleanup
        }
        crypto_provider_.reset();
    }
    
    // Clear event callback to prevent callback during cleanup
    event_callback_ = nullptr;
    
    // Reset connection statistics
    stats_ = ConnectionStats{}; // Reset to default state
    
    // Reset atomic flags
    next_handshake_sequence_.store(0);
    is_closing_.store(true);
    
    return make_result();
}

// Handshake message handlers

Result<void> Connection::handle_client_hello_message(const protocol::HandshakeMessage& message) {
    if (is_client_) {
        // Client should not receive ClientHello
        return make_error<void>(DTLSError::UNEXPECTED_MESSAGE);
    }
    
    if (state_ != ConnectionState::INITIAL) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Server processing ClientHello
    auto result = transition_state(ConnectionState::WAIT_SERVER_HELLO);
    if (result && should_process_ack_for_state(state_)) {
        // ACK will be generated automatically by HandshakeManager
    }
    return result;
}

Result<void> Connection::handle_server_hello_message(const protocol::HandshakeMessage& message) {
    if (!is_client_) {
        // Server should not receive ServerHello
        return make_error<void>(DTLSError::UNEXPECTED_MESSAGE);
    }
    
    if (state_ != ConnectionState::WAIT_SERVER_HELLO) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Client processing ServerHello
    auto result = transition_state(ConnectionState::WAIT_ENCRYPTED_EXTENSIONS);
    if (result && should_process_ack_for_state(state_)) {
        // ACK will be generated automatically by HandshakeManager
    }
    return result;
}

Result<void> Connection::handle_hello_retry_request_message(const protocol::HandshakeMessage& message) {
    if (!is_client_) {
        // Server should not receive HelloRetryRequest
        return make_error<void>(DTLSError::UNEXPECTED_MESSAGE);
    }
    
    if (state_ != ConnectionState::WAIT_SERVER_HELLO) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Client processing HelloRetryRequest - stay in same state but prepare for retry
    update_last_activity();
    return make_result();
}

Result<void> Connection::handle_encrypted_extensions_message(const protocol::HandshakeMessage& message) {
    if (!is_client_) {
        // Server should not receive EncryptedExtensions
        return make_error<void>(DTLSError::UNEXPECTED_MESSAGE);
    }
    
    if (state_ != ConnectionState::WAIT_ENCRYPTED_EXTENSIONS) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Client processing EncryptedExtensions
    // Determine next state based on server authentication requirements
    return transition_state(ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST);
}

Result<void> Connection::handle_certificate_request_message(const protocol::HandshakeMessage& message) {
    if (!is_client_) {
        // Server should not receive CertificateRequest
        return make_error<void>(DTLSError::UNEXPECTED_MESSAGE);
    }
    
    if (state_ != ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Client processing CertificateRequest - prepare to send client certificate
    return transition_state(ConnectionState::WAIT_CLIENT_CERTIFICATE);
}

Result<void> Connection::handle_certificate_message(const protocol::HandshakeMessage& message) {
    switch (state_) {
        case ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST:
            // Client receiving server certificate
            if (is_client_) {
                return transition_state(ConnectionState::WAIT_CERTIFICATE_VERIFY);
            }
            break;
            
        case ConnectionState::WAIT_CLIENT_CERTIFICATE:
            // Server receiving client certificate
            if (!is_client_) {
                return transition_state(ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY);
            }
            break;
            
        default:
            return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
}

Result<void> Connection::handle_certificate_verify_message(const protocol::HandshakeMessage& message) {
    switch (state_) {
        case ConnectionState::WAIT_CERTIFICATE_VERIFY:
            // Client receiving server certificate verification
            if (is_client_) {
                return transition_state(ConnectionState::WAIT_SERVER_FINISHED);
            }
            break;
            
        case ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY:
            // Server receiving client certificate verification
            if (!is_client_) {
                return transition_state(ConnectionState::WAIT_CLIENT_FINISHED);
            }
            break;
            
        default:
            return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
}

Result<void> Connection::handle_finished_message(const protocol::HandshakeMessage& message) {
    switch (state_) {
        case ConnectionState::WAIT_CLIENT_FINISHED:
            // Server receiving client Finished
            if (!is_client_) {
                return transition_state(ConnectionState::CONNECTED);
            }
            break;
            
        case ConnectionState::WAIT_SERVER_FINISHED:
            // Client receiving server Finished
            if (is_client_) {
                return transition_state(ConnectionState::CONNECTED);
            }
            break;
            
        default:
            return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
}

Result<void> Connection::handle_new_session_ticket_message(const protocol::HandshakeMessage& message) {
    if (!is_client_) {
        // Server should not receive NewSessionTicket
        return make_error<void>(DTLSError::UNEXPECTED_MESSAGE);
    }
    
    if (state_ != ConnectionState::CONNECTED) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Client processing NewSessionTicket for future session resumption
    if (message.holds<protocol::NewSessionTicket>()) {
        auto ticket = message.get<protocol::NewSessionTicket>();
        auto store_result = store_session_ticket(ticket);
        if (store_result) {
            fire_event(ConnectionEvent::NEW_SESSION_TICKET_RECEIVED);
        }
        return store_result;
    }
    
    return make_error<void>(DTLSError::INVALID_MESSAGE_FORMAT);
}

Result<void> Connection::handle_key_update_message(const protocol::HandshakeMessage& message) {
    if (state_ != ConnectionState::CONNECTED) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Extract KeyUpdate message
    if (!message.holds<protocol::KeyUpdate>()) {
        return make_error<void>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    auto key_update = message.get<protocol::KeyUpdate>();
    
    // TODO: Update our traffic keys using record layer when available
    // For now, simulate key update success
    
    // If peer requested us to also update keys, send our own KeyUpdate message
    if (key_update.requests_peer_update()) {
        // Create KeyUpdate message (not requesting further updates to avoid loops)
        protocol::KeyUpdate our_key_update(protocol::KeyUpdateRequest::UPDATE_NOT_REQUESTED);
        
        // Create handshake message
        auto our_handshake_message = protocol::HandshakeMessage(our_key_update, get_next_handshake_sequence());
        
        // Serialize the handshake message
        memory::Buffer our_message_buffer(our_handshake_message.serialized_size());
        auto serialize_result = our_handshake_message.serialize(our_message_buffer);
        if (!serialize_result.is_success()) {
            return make_error<void>(serialize_result.error());
        }
        
        // TODO: Create DTLS plaintext record and send when record layer is available
        // For now, simulate sending the response KeyUpdate message
    }
    
    // Update connection statistics
    stats_.key_updates_performed++;
    update_last_activity();
    
    // Fire key update completed event
    fire_event(ConnectionEvent::KEY_UPDATE_COMPLETED);
    
    return make_result();
}

Result<void> Connection::handle_end_of_early_data_message(const protocol::HandshakeMessage& message) {
    if (!is_client_) {
        // Server should not receive EndOfEarlyData
        return make_error<void>(DTLSError::UNEXPECTED_MESSAGE);
    }
    
    if (state_ != ConnectionState::WAIT_END_OF_EARLY_DATA) {
        return make_error<void>(DTLSError::STATE_MACHINE_ERROR);
    }
    
    // Client sending EndOfEarlyData - transition to normal handshake flow
    {
        std::lock_guard<std::mutex> lock(early_data_mutex_);
        early_data_context_.state = protocol::EarlyDataState::COMPLETED;
    }
    
    return transition_state(ConnectionState::WAIT_ENCRYPTED_EXTENSIONS);
}

void Connection::update_last_activity() {
    stats_.last_activity = std::chrono::steady_clock::now();
}

uint32_t Connection::get_next_handshake_sequence() {
    return next_handshake_sequence_.fetch_add(1);
}

Result<void> Connection::send_close_notify_alert() {
    // Create close_notify alert structure
    struct Alert {
        AlertLevel level;
        AlertDescription description;
    };
    
    Alert close_alert;
    close_alert.level = AlertLevel::WARNING;
    close_alert.description = AlertDescription::CLOSE_NOTIFY;
    
    // TODO: When record layer is available, implement proper alert sending
    // For now, simulate the alert sending process
    
    // Serialize the alert (2 bytes: level + description)
    memory::Buffer alert_buffer(2);
    alert_buffer.mutable_data()[0] = static_cast<std::byte>(close_alert.level);
    alert_buffer.mutable_data()[1] = static_cast<std::byte>(close_alert.description);
    
    // Create DTLS plaintext record for the alert
    protocol::DTLSPlaintext alert_plaintext(
        protocol::ContentType::ALERT,
        protocol::ProtocolVersion::DTLS_1_3,
        1, // Default epoch since record_layer_ is not initialized
        protocol::SequenceNumber48(0), // Will be set by record layer
        std::move(alert_buffer)
    );
    
    // TODO: Send the alert through record layer when available
    // For now, simulate alert sending success
    
    // Update statistics
    update_last_activity();
    
    return make_result();
}

bool Connection::is_connection_valid_for_operations() const {
    return !is_closing_.load() && !force_closed_.load() && state_ != ConnectionState::CLOSED;
}

// Error Recovery Implementation

ConnectionHealth Connection::get_health_status() const {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    return recovery_state_.health_status;
}

const ErrorRecoveryState& Connection::get_recovery_state() const {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    return recovery_state_;
}

Result<void> Connection::recover_from_error(DTLSError error, const std::string& context) {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    
    // Record the error first
    record_error(error, context);
    
    // Check if we should attempt recovery
    if (!should_attempt_recovery()) {
        return make_error<void>(DTLSError::RESOURCE_EXHAUSTED);
    }
    
    // Determine recovery strategy
    RecoveryStrategy strategy = determine_recovery_strategy(error);
    
    // Fire recovery started event
    fire_event(ConnectionEvent::RECOVERY_STARTED);
    
    recovery_state_.recovery_in_progress = true;
    recovery_state_.current_strategy = strategy;
    recovery_state_.recovery_start_time = std::chrono::steady_clock::now();
    recovery_state_.total_recovery_attempts++;
    
    // Execute the recovery strategy
    auto result = execute_recovery_strategy(strategy, error);
    
    if (result.is_success()) {
        recovery_state_.successful_recoveries++;
        recovery_state_.consecutive_errors = 0;
        recovery_state_.recovery_in_progress = false;
        update_health_status();
        fire_event(ConnectionEvent::RECOVERY_SUCCEEDED);
    } else {
        recovery_state_.failed_recoveries++;
        recovery_state_.recovery_in_progress = false;
        update_health_status();
        fire_event(ConnectionEvent::RECOVERY_FAILED);
    }
    
    return result;
}

void Connection::reset_recovery_state() {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    recovery_state_ = ErrorRecoveryState{};
}

bool Connection::is_in_degraded_mode() const {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    return recovery_state_.health_status == ConnectionHealth::DEGRADED;
}

double Connection::get_error_rate(std::chrono::seconds window) const {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto cutoff_time = now - window;
    
    // Count errors within the time window
    uint32_t error_count = 0;
    for (const auto& timestamp : recovery_state_.error_timestamps) {
        if (timestamp >= cutoff_time) {
            error_count++;
        }
    }
    
    // Calculate error rate (errors per second)
    return static_cast<double>(error_count) / window.count();
}

Result<void> Connection::perform_health_check() {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    
    // Clean up old error timestamps
    cleanup_old_error_timestamps();
    
    // Update health status based on current conditions
    update_health_status();
    
    // If in failed state, attempt recovery
    if (recovery_state_.health_status == ConnectionHealth::FAILED && 
        config_.error_recovery.enable_automatic_recovery) {
        return recover_from_error(recovery_state_.last_error_code, "Automatic health check recovery");
    }
    
    return make_result();
}

void Connection::record_error(DTLSError error, const std::string& context) {
    // This method is called with recovery_mutex_ already locked
    
    auto now = std::chrono::steady_clock::now();
    
    // Record error timestamp
    recovery_state_.error_timestamps.push_back(now);
    recovery_state_.consecutive_errors++;
    recovery_state_.last_error_code = error;
    recovery_state_.last_error_message = context;
    
    // Update statistics
    if (error >= DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED && error <= DTLSError::STATE_MACHINE_ERROR) {
        stats_.protocol_errors++;
    }
    
    // Clean up old timestamps to maintain memory efficiency
    cleanup_old_error_timestamps();
    
    // Update health status
    update_health_status();
}

void Connection::update_health_status() {
    // This method is called with recovery_mutex_ already locked
    
    double error_rate = get_error_rate(std::chrono::seconds{60});
    uint32_t consecutive_errors = recovery_state_.consecutive_errors;
    
    ConnectionHealth old_health = recovery_state_.health_status;
    ConnectionHealth new_health = ConnectionHealth::HEALTHY;
    
    // Determine health status based on error patterns
    if (consecutive_errors >= config_.error_recovery.max_consecutive_errors) {
        new_health = ConnectionHealth::FAILED;
    } else if (error_rate >= config_.error_recovery.degraded_mode_threshold) {
        new_health = ConnectionHealth::DEGRADED;
    } else if (consecutive_errors >= 2 || error_rate > 0.1) {
        new_health = ConnectionHealth::UNSTABLE;
    } else if (consecutive_errors >= 1 || error_rate > 0.05) {
        new_health = ConnectionHealth::HEALTHY;
    }
    
    recovery_state_.health_status = new_health;
    
    // Fire events for health status changes
    if (old_health != new_health) {
        if (new_health == ConnectionHealth::DEGRADED) {
            fire_event(ConnectionEvent::CONNECTION_DEGRADED);
        } else if (old_health == ConnectionHealth::DEGRADED && new_health == ConnectionHealth::HEALTHY) {
            fire_event(ConnectionEvent::CONNECTION_RESTORED);
        }
    }
}

RecoveryStrategy Connection::determine_recovery_strategy(DTLSError error) const {
    // This method is called with recovery_mutex_ already locked
    
    // Map error types to recovery strategies based on configuration
    if (error >= DTLSError::HANDSHAKE_FAILURE && error <= DTLSError::HANDSHAKE_TIMEOUT) {
        return config_.error_recovery.handshake_error_strategy;
    } else if (error >= DTLSError::DECRYPT_ERROR && error <= DTLSError::CRYPTO_HARDWARE_ERROR) {
        return config_.error_recovery.crypto_error_strategy;
    } else if (error >= DTLSError::NETWORK_ERROR && error <= DTLSError::TRANSPORT_ERROR) {
        return config_.error_recovery.network_error_strategy;
    } else if (error >= DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED && error <= DTLSError::STATE_MACHINE_ERROR) {
        return config_.error_recovery.protocol_error_strategy;
    }
    
    // Default strategy based on error severity
    if (is_retryable_error(error)) {
        return RecoveryStrategy::RETRY_WITH_BACKOFF;
    } else {
        return RecoveryStrategy::GRACEFUL_DEGRADATION;
    }
}

Result<void> Connection::execute_recovery_strategy(RecoveryStrategy strategy, DTLSError original_error) {
    // This method is called with recovery_mutex_ already locked
    
    switch (strategy) {
        case RecoveryStrategy::RETRY_IMMEDIATE:
            // Immediate retry without delay
            recovery_state_.retry_attempt = 0;
            return make_result();
            
        case RecoveryStrategy::RETRY_WITH_BACKOFF:
            return retry_with_backoff();
            
        case RecoveryStrategy::GRACEFUL_DEGRADATION:
            return enter_degraded_mode();
            
        case RecoveryStrategy::RESET_CONNECTION:
            return reset_connection_state();
            
        case RecoveryStrategy::FAILOVER:
            // TODO: Implement provider failover when multiple providers are available
            return make_error<void>(DTLSError::OPERATION_NOT_SUPPORTED);
            
        case RecoveryStrategy::ABORT_CONNECTION:
            force_close();
            return make_error<void>(DTLSError::CONNECTION_CLOSED);
            
        case RecoveryStrategy::NONE:
        default:
            return make_error<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
}

Result<void> Connection::retry_with_backoff() {
    // This method is called with recovery_mutex_ already locked
    
    if (recovery_state_.retry_attempt >= config_.error_recovery.max_retries) {
        return make_error<void>(DTLSError::RESOURCE_EXHAUSTED);
    }
    
    auto delay = calculate_retry_delay();
    recovery_state_.retry_attempt++;
    recovery_state_.last_retry_time = std::chrono::steady_clock::now() + delay;
    
    // In a real implementation, we would schedule the retry after the delay
    // For now, we just record the intention to retry
    
    return make_result();
}

Result<void> Connection::reset_connection_state() {
    // This method is called with recovery_mutex_ already locked
    
    // Reset connection to initial state while preserving essential configuration
    {
        std::lock_guard<std::mutex> state_lock(state_mutex_);
        if (state_ != ConnectionState::CLOSED) {
            state_ = ConnectionState::INITIAL;
        }
    }
    
    // Reset sequence numbers
    next_handshake_sequence_.store(0);
    
    // Clear buffers
    {
        std::lock_guard<std::mutex> queue_lock(receive_queue_mutex_);
        receive_queue_.clear();
    }
    
    // Reset transport if available
    if (transport_) {
        auto stop_result = transport_->stop();
        if (stop_result.is_success()) {
            auto init_result = transport_->initialize();
            if (!init_result.is_success()) {
                return init_result;
            }
        }
    }
    
    return make_result();
}

Result<void> Connection::enter_degraded_mode() {
    // This method is called with recovery_mutex_ already locked
    
    recovery_state_.health_status = ConnectionHealth::DEGRADED;
    
    // In degraded mode, we might:
    // - Disable non-essential features
    // - Reduce encryption strength (if policy allows)
    // - Use simplified protocol flows
    // - Increase timeout values
    
    // For now, just record the state change
    return make_result();
}

Result<void> Connection::exit_degraded_mode() {
    std::lock_guard<std::mutex> lock(recovery_mutex_);
    
    if (recovery_state_.health_status == ConnectionHealth::DEGRADED) {
        recovery_state_.health_status = ConnectionHealth::HEALTHY;
        fire_event(ConnectionEvent::CONNECTION_RESTORED);
    }
    
    return make_result();
}

bool Connection::should_attempt_recovery() const {
    // This method is called with recovery_mutex_ already locked
    
    if (!config_.error_recovery.enable_automatic_recovery) {
        return false;
    }
    
    if (recovery_state_.recovery_in_progress) {
        return false;
    }
    
    if (recovery_state_.total_recovery_attempts >= config_.error_recovery.max_retries * 2) {
        return false;
    }
    
    if (recovery_state_.consecutive_errors >= config_.error_recovery.max_consecutive_errors) {
        return false;
    }
    
    return true;
}

std::chrono::milliseconds Connection::calculate_retry_delay() const {
    // This method is called with recovery_mutex_ already locked
    
    auto base_delay = config_.error_recovery.initial_retry_delay;
    auto max_delay = config_.error_recovery.max_retry_delay;
    auto multiplier = config_.error_recovery.backoff_multiplier;
    
    // Calculate exponential backoff delay
    auto delay = base_delay;
    for (uint32_t i = 0; i < recovery_state_.retry_attempt; ++i) {
        delay = std::chrono::milliseconds(static_cast<long long>(delay.count() * multiplier));
        if (delay > max_delay) {
            delay = max_delay;
            break;
        }
    }
    
    return delay;
}

void Connection::cleanup_old_error_timestamps() {
    // This method is called with recovery_mutex_ already locked
    
    auto now = std::chrono::steady_clock::now();
    auto cutoff_time = now - config_.error_recovery.error_rate_window;
    
    // Remove timestamps older than the error rate window
    recovery_state_.error_timestamps.erase(
        std::remove_if(recovery_state_.error_timestamps.begin(),
                      recovery_state_.error_timestamps.end(),
                      [&cutoff_time](const auto& timestamp) {
                          return timestamp < cutoff_time;
                      }),
        recovery_state_.error_timestamps.end()
    );
}

bool Connection::is_retryable_error(DTLSError error) const {
    // Determine if an error is transient and worth retrying
    switch (error) {
        // Network errors are usually transient
        case DTLSError::NETWORK_ERROR:
        case DTLSError::TIMEOUT:
        case DTLSError::SEND_ERROR:
        case DTLSError::RECEIVE_ERROR:
        case DTLSError::NETWORK_UNREACHABLE:
        case DTLSError::HOST_UNREACHABLE:
        case DTLSError::CONNECTION_TIMEOUT:
            return true;
            
        // Some handshake errors can be retried
        case DTLSError::HANDSHAKE_TIMEOUT:
        case DTLSError::FRAGMENTATION_ERROR:
            return true;
            
        // Resource errors might be temporary
        case DTLSError::RESOURCE_UNAVAILABLE:
        case DTLSError::INSUFFICIENT_BUFFER:
        case DTLSError::OUT_OF_MEMORY:
            return true;
            
        // These errors are typically permanent
        case DTLSError::INVALID_PARAMETER:
        case DTLSError::CERTIFICATE_VERIFY_FAILED:
        case DTLSError::CERTIFICATE_EXPIRED:
        case DTLSError::CERTIFICATE_REVOKED:
        case DTLSError::ACCESS_DENIED:
        case DTLSError::AUTHENTICATION_FAILED:
        case DTLSError::AUTHORIZATION_FAILED:
            return false;
            
        default:
            // Conservative approach: don't retry unknown errors
            return false;
    }
}

void Connection::handle_transport_event(transport::TransportEvent event,
                                       const transport::NetworkEndpoint& endpoint,
                                       const std::vector<uint8_t>& data) {
    switch (event) {
        case transport::TransportEvent::PACKET_RECEIVED:
            // Process received packet data
            if (!data.empty()) {
                memory::ZeroCopyBuffer buffer(
                    reinterpret_cast<const std::byte*>(data.data()), 
                    data.size());
                auto process_result = process_incoming_data(buffer);
                if (!process_result) {
                    fire_event(ConnectionEvent::ERROR_OCCURRED);
                }
            }
            break;
            
        case transport::TransportEvent::PACKET_SENT:
            // Packet successfully sent, nothing special to do
            break;
            
        case transport::TransportEvent::SEND_ERROR:
            stats_.protocol_errors++;
            fire_event(ConnectionEvent::ERROR_OCCURRED);
            break;
            
        case transport::TransportEvent::RECEIVE_ERROR:
            stats_.protocol_errors++;
            fire_event(ConnectionEvent::ERROR_OCCURRED);
            break;
            
        case transport::TransportEvent::SOCKET_ERROR:
            stats_.protocol_errors++;
            fire_event(ConnectionEvent::ERROR_OCCURRED);
            // Consider closing connection on socket errors
            if (config_.error_recovery.enable_automatic_recovery) {
                recover_from_error(DTLSError::SOCKET_ERROR, "transport event: socket error");
            }
            break;
            
        case transport::TransportEvent::CONNECTION_TIMEOUT:
            // Handle connection timeout
            if (config_.error_recovery.enable_automatic_recovery) {
                recover_from_error(DTLSError::CONNECTION_TIMEOUT, "transport event: connection timeout");
            }
            if (state_ != ConnectionState::CONNECTED) {
                fire_event(ConnectionEvent::HANDSHAKE_FAILED);
            }
            break;
            
        case transport::TransportEvent::INTERFACE_CHANGE:
            // Network interface changed, might need to handle reconnection
            break;
    }
    
    update_last_activity();
}

// ACK processing methods

Result<void> Connection::handle_ack_message(const protocol::ACK& ack_message) {
    // ACK messages are primarily handled by the HandshakeManager
    // but we can perform additional state-specific validation here
    
    if (!should_process_ack_for_state(state_)) {
        // Ignore ACKs in states where they're not expected
        return make_result();
    }
    
    // The actual ACK processing (sequence number tracking, retransmission management)
    // is handled by HandshakeManager, but we can add state-specific logic here
    
    // Update activity timestamp
    update_last_activity();
    
    // Log ACK reception for debugging/monitoring
    // (In production, this might be configurable logging)
    
    return make_result();
}

Result<void> Connection::send_handshake_message(const protocol::HandshakeMessage& message) {
    // This method is called by HandshakeManager to send messages
    // We need to wrap the handshake message in a record and send it
    
    if (force_closed_ || is_closing_) {
        return make_error<void>(DTLSError::CONNECTION_CLOSED);
    }
    
    // TODO: When record layer is properly implemented, use it to create records
    // For now, we'll simulate sending by updating statistics
    
    // Create a mock transport packet (in real implementation, this would go through record layer)
    // For demonstration, we'll just update statistics and fire events
    
    stats_.records_sent++;
    update_last_activity();
    
    // Message sent successfully
    return make_result();
}

bool Connection::should_process_ack_for_state(ConnectionState state) const {
    // Define which states should process ACK messages
    switch (state) {
        case ConnectionState::INITIAL:
            return false; // No handshake in progress yet
            
        case ConnectionState::WAIT_SERVER_HELLO:
        case ConnectionState::WAIT_ENCRYPTED_EXTENSIONS:
        case ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST:
        case ConnectionState::WAIT_CERTIFICATE_VERIFY:
        case ConnectionState::WAIT_SERVER_FINISHED:
        case ConnectionState::WAIT_CLIENT_CERTIFICATE:
        case ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY:
        case ConnectionState::WAIT_CLIENT_FINISHED:
            return true; // Active handshake states
            
        case ConnectionState::CONNECTED:
            return false; // Handshake complete, no more ACKs needed
            
        case ConnectionState::CLOSED:
            return false; // Connection closed
            
        default:
            return false; // Unknown state, don't process ACKs
    }
}

// ConnectionManager implementation

Result<void> ConnectionManager::add_connection(std::unique_ptr<Connection> connection) {
    if (!connection) {
        return make_error<void>(DTLSError::INVALID_PARAMETER);
    }
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    connections_.push_back(std::move(connection));
    
    return make_result();
}

Result<void> ConnectionManager::remove_connection(const ConnectionID& connection_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&connection_id](const std::unique_ptr<Connection>& conn) {
            auto cid_result = conn->get_local_connection_id();
            return cid_result && cid_result.value() == connection_id;
        });
    
    if (it != connections_.end()) {
        connections_.erase(it);
        return make_result();
    }
    
    return make_error<void>(DTLSError::CONNECTION_NOT_FOUND);
}

Result<Connection*> ConnectionManager::find_connection(const ConnectionID& connection_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&connection_id](const std::unique_ptr<Connection>& conn) {
            auto cid_result = conn->get_local_connection_id();
            return cid_result && cid_result.value() == connection_id;
        });
    
    if (it != connections_.end()) {
        return make_result(it->get());
    }
    
    return make_error<Connection*>(DTLSError::CONNECTION_NOT_FOUND);
}

Result<Connection*> ConnectionManager::find_connection(const NetworkAddress& address) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&address](const std::unique_ptr<Connection>& conn) {
            return conn->get_peer_address().address == address.address &&
                   conn->get_peer_address().port == address.port;
        });
    
    if (it != connections_.end()) {
        return make_result(it->get());
    }
    
    return make_error<Connection*>(DTLSError::CONNECTION_NOT_FOUND);
}

std::vector<Connection*> ConnectionManager::get_all_connections() {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    std::vector<Connection*> result;
    result.reserve(connections_.size());
    
    for (const auto& conn : connections_) {
        result.push_back(conn.get());
    }
    
    return result;
}

void ConnectionManager::close_all_connections() {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    for (auto& conn : connections_) {
        conn->close();
    }
}

size_t ConnectionManager::get_connection_count() const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    return connections_.size();
}

void ConnectionManager::cleanup_closed_connections() {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
            [](const std::unique_ptr<Connection>& conn) {
                return conn->get_state() == ConnectionState::CLOSED;
            }),
        connections_.end());
}

// Early Data Support Implementation (RFC 9147)

Result<void> Connection::send_early_data(const memory::ZeroCopyBuffer& data) {
    std::lock_guard<std::mutex> lock(early_data_mutex_);
    
    if (force_closed_ || is_closing_) {
        return make_error<void>(DTLSError::CONNECTION_CLOSED);
    }
    
    if (!is_client_) {
        return make_error<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!config_.enable_early_data) {
        return make_error<void>(DTLSError::FEATURE_NOT_ENABLED);
    }
    
    // Check if we can send early data
    if (!can_send_early_data()) {
        return make_error<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Validate data size against configured limits
    if (data.size() > config_.max_early_data_size) {
        return make_error<void>(DTLSError::MESSAGE_TOO_LARGE);
    }
    
    // Check if we exceed the per-session early data limit
    if (early_data_context_.bytes_sent + data.size() > early_data_context_.max_allowed) {
        return make_error<void>(DTLSError::QUOTA_EXCEEDED);
    }
    
    // Update early data context
    early_data_context_.state = protocol::EarlyDataState::SENDING;
    early_data_context_.bytes_sent += data.size();
    
    // Buffer the early data
    early_data_context_.early_data_buffer.insert(
        early_data_context_.early_data_buffer.end(),
        reinterpret_cast<const uint8_t*>(data.data()),
        reinterpret_cast<const uint8_t*>(data.data()) + data.size()
    );
    
    // TODO: When record layer is properly implemented, protect early data with early traffic keys
    // For now, simulate sending early data through transport layer
    
    // Update statistics
    stats_.bytes_sent += data.size();
    update_last_activity();
    
    // Fire event for early data sent
    fire_event(ConnectionEvent::EARLY_DATA_RECEIVED, std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(data.data()),
        reinterpret_cast<const uint8_t*>(data.data()) + data.size()
    ));
    
    return make_result();
}

bool Connection::can_send_early_data() const {
    std::lock_guard<std::mutex> lock(early_data_mutex_);
    
    if (!is_client_ || !config_.enable_early_data) {
        return false;
    }
    
    // Check if we have a valid session ticket for early data
    if (!early_data_context_.ticket.has_value()) {
        return false;
    }
    
    // Verify the ticket is still valid
    if (!early_data_context_.ticket->is_valid()) {
        return false;
    }
    
    // Check if early data is within allowed limits
    return early_data_context_.can_send_early_data();
}

bool Connection::is_early_data_accepted() const {
    std::lock_guard<std::mutex> lock(early_data_mutex_);
    return early_data_context_.is_early_data_accepted();
}

bool Connection::is_early_data_rejected() const {
    std::lock_guard<std::mutex> lock(early_data_mutex_);
    return early_data_context_.is_early_data_rejected();
}

Connection::EarlyDataStats Connection::get_early_data_stats() const {
    std::lock_guard<std::mutex> lock(early_data_mutex_);
    
    EarlyDataStats stats;
    stats.bytes_sent = early_data_context_.bytes_sent;
    stats.was_attempted = (early_data_context_.state != protocol::EarlyDataState::NOT_ATTEMPTED);
    
    if (early_data_context_.state == protocol::EarlyDataState::ACCEPTED) {
        stats.bytes_accepted = early_data_context_.bytes_sent;
        stats.bytes_rejected = 0;
    } else if (early_data_context_.state == protocol::EarlyDataState::REJECTED) {
        stats.bytes_accepted = 0;
        stats.bytes_rejected = early_data_context_.bytes_sent;
    }
    
    // Calculate response time if early data phase has started
    if (stats.was_attempted && early_data_context_.start_time != std::chrono::steady_clock::time_point{}) {
        auto now = std::chrono::steady_clock::now();
        stats.response_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - early_data_context_.start_time
        );
    }
    
    return stats;
}

Result<void> Connection::store_session_ticket(const protocol::NewSessionTicket& ticket) {
    if (!session_ticket_manager_) {
        return make_error<void>(DTLSError::FEATURE_NOT_ENABLED);
    }
    
    // Extract early data information from ticket
    auto max_early_data_result = protocol::extract_max_early_data_from_ticket(ticket);
    if (!max_early_data_result) {
        return make_error<void>(DTLSError::ILLEGAL_PARAMETER);
    }
    
    std::lock_guard<std::mutex> lock(early_data_mutex_);
    
    // Store the ticket for future early data use
    protocol::SessionTicket session_ticket;
    session_ticket.ticket_data = ticket.ticket();
    session_ticket.ticket_nonce = ticket.ticket_nonce();
    session_ticket.ticket_lifetime = ticket.ticket_lifetime();
    session_ticket.ticket_age_add = ticket.ticket_age_add();
    session_ticket.max_early_data_size = max_early_data_result.value();
    session_ticket.issued_time = std::chrono::steady_clock::now();
    session_ticket.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256; // TODO: Get from current session
    
    // Store the session ticket
    std::string ticket_identity = "ticket_" + std::to_string(std::hash<std::string>{}(
        std::string(reinterpret_cast<const char*>(ticket.ticket().data()), ticket.ticket().size())
    ));
    
    if (!session_ticket_manager_->store_ticket(ticket_identity, session_ticket)) {
        return make_error<void>(DTLSError::INTERNAL_ERROR);
    }
    
    // Set up early data context if early data is enabled
    if (config_.enable_early_data && max_early_data_result.value() > 0) {
        early_data_context_.ticket = session_ticket;
        early_data_context_.max_allowed = max_early_data_result.value();
        early_data_context_.state = protocol::EarlyDataState::NOT_ATTEMPTED;
    }
    
    return make_result();
}

std::vector<std::string> Connection::get_available_session_tickets() const {
    if (!session_ticket_manager_) {
        return {};
    }
    
    // TODO: Implement when SessionTicketManager provides enumeration API
    return {};
}

void Connection::clear_session_tickets() {
    if (session_ticket_manager_) {
        session_ticket_manager_->clear_all_tickets();
    }
    
    std::lock_guard<std::mutex> lock(early_data_mutex_);
    early_data_context_.reset();
}

// Context class implementations

Result<std::unique_ptr<Context>> Context::create_client() {
    // Create default client configuration
    ConnectionConfig config;
    config.supported_cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    config.supported_groups = {
        NamedGroup::X25519,
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1
    };
    config.supported_signatures = {
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ED25519
    };
    
    // Create default crypto provider
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    if (!crypto_provider) {
        return make_error<std::unique_ptr<Context>>(DTLSError::OUT_OF_MEMORY);
    }
    
    auto init_result = crypto_provider->initialize();
    if (!init_result.is_ok()) {
        return make_error<std::unique_ptr<Context>>(DTLSError::INITIALIZATION_FAILED);
    }
    
    // Create connection with dummy address (will be set when actually connecting)
    NetworkAddress dummy_address;
    dummy_address.family = NetworkAddress::Family::IPv4;
    // Set IPv4 address 127.0.0.1
    dummy_address.address[0] = 127;
    dummy_address.address[1] = 0;
    dummy_address.address[2] = 0;
    dummy_address.address[3] = 1;
    dummy_address.port = 4433;
    
    auto connection_result = Connection::create_client(config, std::move(crypto_provider), dummy_address);
    if (!connection_result.is_ok()) {
        return make_error<std::unique_ptr<Context>>(connection_result.error());
    }
    
    return make_result(std::unique_ptr<Context>(new Context(std::move(connection_result.value()))));
}

Result<std::unique_ptr<Context>> Context::create_server() {
    // Create default server configuration
    ConnectionConfig config;
    config.supported_cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    config.supported_groups = {
        NamedGroup::X25519,
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1
    };
    config.supported_signatures = {
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ED25519
    };
    
    // Create default crypto provider
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    if (!crypto_provider) {
        return make_error<std::unique_ptr<Context>>(DTLSError::OUT_OF_MEMORY);
    }
    
    auto init_result = crypto_provider->initialize();
    if (!init_result.is_ok()) {
        return make_error<std::unique_ptr<Context>>(DTLSError::INITIALIZATION_FAILED);
    }
    
    // Create connection with dummy address (will be set when actually accepting)
    NetworkAddress dummy_address;
    dummy_address.family = NetworkAddress::Family::IPv4;
    // Set IPv4 address 0.0.0.0
    dummy_address.address[0] = 0;
    dummy_address.address[1] = 0;
    dummy_address.address[2] = 0;
    dummy_address.address[3] = 0;
    dummy_address.port = 4433;
    
    auto connection_result = Connection::create_server(config, std::move(crypto_provider), dummy_address);
    if (!connection_result.is_ok()) {
        return make_error<std::unique_ptr<Context>>(connection_result.error());
    }
    
    return make_result(std::unique_ptr<Context>(new Context(std::move(connection_result.value()))));
}

Result<void> Context::initialize() {
    if (!connection_) {
        return make_error<void>(DTLSError::NOT_INITIALIZED);
    }
    
    return connection_->initialize();
}

}  // namespace v13
}  // namespace dtls