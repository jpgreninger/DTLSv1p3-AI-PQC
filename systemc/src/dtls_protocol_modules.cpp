#include "dtls_protocol_modules.h"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <sstream>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

// Record Layer Module Implementation
// SC_MODULE_EXPORT not needed - handled by CMake

record_layer_module::record_layer_module(sc_module_name name)
    : sc_module(name)
    , target_socket("target_socket")
    , crypto_socket("crypto_socket")
    , network_socket("network_socket")
    , enable_protection("enable_protection")
    , cipher_suite("cipher_suite")
    , max_record_size("max_record_size")
    , hardware_acceleration("hardware_acceleration")
    , records_protected("records_protected")
    , records_unprotected("records_unprotected")
    , average_protection_time("average_protection_time")
    , throughput_mbps("throughput_mbps")
    , encryption_queue_depth("encryption_queue_depth")
    , security_overhead_percent("security_overhead_percent")
    , replay_attacks_detected("replay_attacks_detected")
    , authentication_failures("authentication_failures")
    , active_epochs("active_epochs")
    , security_alert("security_alert")
{
    // Bind TLM transport interface
    target_socket.register_b_transport(this, &record_layer_module::b_transport);
    
    // Initialize components and configure
    initialize_components();
    connect_internal_interfaces();
    
    // Register SystemC processes
    SC_THREAD(record_processing_thread);
    SC_THREAD(performance_monitoring_thread);
    SC_THREAD(security_monitoring_thread);
    SC_THREAD(queue_management_thread);
    
    // Initialize output ports
    records_protected.initialize(0);
    records_unprotected.initialize(0);
    average_protection_time.initialize(SC_ZERO_TIME);
    throughput_mbps.initialize(0.0);
    encryption_queue_depth.initialize(0);
    security_overhead_percent.initialize(0.0);
    replay_attacks_detected.initialize(0);
    authentication_failures.initialize(0);
    active_epochs.initialize(0);
    security_alert.initialize(false);
}

void record_layer_module::initialize_components() {
    // Create internal TLM components
    record_processor = std::make_unique<RecordLayerTLM>("record_processor");
    anti_replay = std::make_unique<AntiReplayWindowTLM>("anti_replay");
    seq_manager = std::make_unique<SequenceNumberManagerTLM>("seq_manager");
    epoch_manager = std::make_unique<EpochManagerTLM>("epoch_manager");
    
    // Create timing models
    crypto_timing = std::make_unique<crypto_timing_model>("crypto_timing");
    memory_timing = std::make_unique<memory_timing_model>("memory_timing");
}

void record_layer_module::connect_internal_interfaces() {
    // Connect internal components through TLM sockets
    // This would involve binding sockets in a real implementation
    
    // Configure timing models with realistic parameters
    crypto_timing->configure_cipher_timing("aes-gcm", {
        sc_time(40, SC_NS),   // base_time
        sc_time(2, SC_NS),    // per_byte_time
        sc_time(10, SC_NS),   // setup_time
        sc_time(5, SC_NS),    // teardown_time
        3.5,                  // hardware_speedup_factor
        4                     // parallel_operations_limit
    });
}

void record_layer_module::record_processing_thread() {
    while (true) {
        wait(record_processed);
        
        // Process protection and unprotection queues
        process_protection_queue();
        process_unprotection_queue();
        
        // Update queue depth monitoring
        encryption_queue_depth.write(protection_queue.size() + unprotection_queue.size());
        
        // Check for performance thresholds
        if (protection_queue.size() > 100 || unprotection_queue.size() > 100) {
            performance_threshold_exceeded.notify();
        }
    }
}

void record_layer_module::performance_monitoring_thread() {
    while (true) {
        wait(sc_time(100, SC_MS)); // Performance monitoring interval
        
        update_performance_metrics();
        
        // Update output ports
        std::lock_guard<std::mutex> lock(stats_mutex);
        records_protected.write(stats.records_protected);
        records_unprotected.write(stats.records_unprotected);
        average_protection_time.write(stats.average_processing_time);
        throughput_mbps.write(stats.current_throughput_mbps);
        
        // Calculate security overhead
        if (stats.bytes_processed > 0) {
            double overhead = ((double)stats.total_records_processed * 16) / stats.bytes_processed * 100.0;
            security_overhead_percent.write(overhead);
        }
    }
}

void record_layer_module::security_monitoring_thread() {
    while (true) {
        wait(security_event);
        
        update_security_metrics();
        
        // Update security monitoring ports
        std::lock_guard<std::mutex> lock(stats_mutex);
        replay_attacks_detected.write(stats.replay_attacks_blocked);
        authentication_failures.write(stats.authentication_failures);
        active_epochs.write(connection_epochs.size());
        
        // Check for security alerts
        bool alert_condition = (stats.replay_attacks_blocked > 10) ||
                              (stats.authentication_failures > 5) ||
                              (stats.sequence_number_violations > 20);
        
        security_alert.write(alert_condition);
        
        if (alert_condition) {
            std::cout << "[" << sc_time_stamp() << "] SECURITY ALERT: Record layer security violations detected" << std::endl;
        }
    }
}

void record_layer_module::queue_management_thread() {
    while (true) {
        wait(sc_time(50, SC_MS)); // Queue management interval
        
        // Monitor queue sizes and trigger processing
        if (!protection_queue.empty() || !unprotection_queue.empty()) {
            record_processed.notify();
        }
        
        // Update performance statistics
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.current_queue_depth = protection_queue.size() + unprotection_queue.size();
        
        if (stats.current_queue_depth > stats.peak_queue_depth) {
            stats.peak_queue_depth = stats.current_queue_depth;
        }
    }
}

void record_layer_module::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    sc_time processing_start = sc_time_stamp();
    
    // Extract DTLS extension from transaction
    dtls_extension* ext = nullptr;
    trans.get_extension(ext);
    
    if (!ext) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Create DTLS transaction wrapper
    auto dtls_trans = std::make_unique<dtls_transaction>();
    
    // Copy TLM payload fields (assignment operator is private)
    auto& payload = dtls_trans->get_payload();
    payload.set_command(trans.get_command());
    payload.set_address(trans.get_address());
    payload.set_data_ptr(trans.get_data_ptr());
    payload.set_data_length(trans.get_data_length());
    payload.set_streaming_width(trans.get_streaming_width());
    payload.set_response_status(trans.get_response_status());
    
    // Copy extension
    dtls_trans->get_extension() = *ext;
    dtls_trans->set_delay(delay);
    
    // Determine operation type
    bool is_protection = (trans.get_command() == tlm::TLM_WRITE_COMMAND);
    
    if (is_protection) {
        // Queue for protection (encrypt outgoing data)
        protection_queue.push(std::move(dtls_trans));
    } else {
        // Queue for unprotection (decrypt incoming data)
        unprotection_queue.push(std::move(dtls_trans));
    }
    
    // Calculate processing delay
    sc_time processing_delay = crypto_timing->calculate_cipher_time("aes-gcm", trans.get_data_length());
    delay += processing_delay;
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_records_processed++;
    stats.bytes_processed += trans.get_data_length();
    
    sc_time total_processing_time = sc_time_stamp() - processing_start + delay;
    stats.total_processing_time += total_processing_time;
    
    if (stats.total_records_processed > 0) {
        stats.average_processing_time = stats.total_processing_time / stats.total_records_processed;
    }
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
    
    // Trigger processing
    record_processed.notify();
}

bool record_layer_module::protect_record(dtls_transaction& trans) {
    if (!protection_enabled) {
        return false;
    }
    
    // Validate record before protection
    if (!validate_record_security(trans)) {
        return false;
    }
    
    // Calculate crypto processing time
    sc_time crypto_time = crypto_timing->calculate_cipher_time("aes-gcm", trans.get_data_size());
    sc_time memory_time = memory_timing->calculate_access_time(trans.get_data(), trans.get_data_size());
    
    trans.add_delay(crypto_time + memory_time);
    trans.get_extension().add_crypto_time(crypto_time);
    trans.get_extension().add_memory_time(memory_time);
    
    // Simulate protection processing
    wait(crypto_time + memory_time);
    
    // Forward to crypto provider
    if (crypto_socket.size() > 0) {
        sc_time crypto_delay = trans.get_delay();
        crypto_socket->b_transport(trans.get_payload(), crypto_delay);
        trans.set_delay(crypto_delay);
    }
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.records_protected++;
    
    return trans.is_response_ok();
}

bool record_layer_module::unprotect_record(dtls_transaction& trans) {
    if (!protection_enabled) {
        return false;
    }
    
    // Check for replay attacks
    if (detect_replay_attack(trans)) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.replay_attacks_blocked++;
        security_event.notify();
        return false;
    }
    
    // Validate epoch and sequence number
    if (!validate_epoch_sequence(trans)) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.sequence_number_violations++;
        security_event.notify();
        return false;
    }
    
    // Calculate processing time
    sc_time crypto_time = crypto_timing->calculate_cipher_time("aes-gcm", trans.get_data_size());
    sc_time memory_time = memory_timing->calculate_access_time(trans.get_data(), trans.get_data_size());
    
    trans.add_delay(crypto_time + memory_time);
    trans.get_extension().add_crypto_time(crypto_time);
    trans.get_extension().add_memory_time(memory_time);
    
    // Simulate unprotection processing
    wait(crypto_time + memory_time);
    
    // Forward to crypto provider for decryption
    if (crypto_socket.size() > 0) {
        sc_time crypto_delay = trans.get_delay();
        crypto_socket->b_transport(trans.get_payload(), crypto_delay);
        trans.set_delay(crypto_delay);
        
        // Check for authentication failures
        if (!trans.is_response_ok()) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.authentication_failures++;
            security_event.notify();
            return false;
        }
    }
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.records_unprotected++;
    
    return true;
}

bool record_layer_module::validate_record_security(const dtls_transaction& trans) {
    const dtls_extension& ext = trans.get_extension();
    
    // Check connection ID validity
    if (ext.connection_id == 0) {
        return false;
    }
    
    // Check epoch validity
    auto epoch_it = connection_epochs.find(ext.connection_id);
    if (epoch_it != connection_epochs.end() && ext.epoch < epoch_it->second) {
        return false; // Old epoch
    }
    
    // Check record size limits
    if (trans.get_data_size() > max_record_size_bytes) {
        return false;
    }
    
    return true;
}

void record_layer_module::process_protection_queue() {
    while (!protection_queue.empty()) {
        auto trans = std::move(protection_queue.front());
        protection_queue.pop();
        
        if (!protect_record(*trans)) {
            handle_security_event("Protection Failed", trans->get_extension().connection_id);
        }
        
        // Forward to network layer
        if (network_socket.size() > 0) {
            sc_time network_delay = trans->get_delay();
            network_socket->b_transport(trans->get_payload(), network_delay);
            trans->set_delay(network_delay);
        }
    }
}

void record_layer_module::process_unprotection_queue() {
    while (!unprotection_queue.empty()) {
        auto trans = std::move(unprotection_queue.front());
        unprotection_queue.pop();
        
        if (!unprotect_record(*trans)) {
            handle_security_event("Unprotection Failed", trans->get_extension().connection_id);
        }
    }
}

bool record_layer_module::detect_replay_attack(const dtls_transaction& trans) {
    const dtls_extension& ext = trans.get_extension();
    
    // Simple replay detection based on sequence number
    // In a real implementation, this would use the anti-replay window
    static std::map<uint32_t, uint64_t> last_sequence_numbers;
    
    auto it = last_sequence_numbers.find(ext.connection_id);
    if (it != last_sequence_numbers.end()) {
        if (ext.sequence_number <= it->second) {
            return true; // Potential replay
        }
    }
    
    last_sequence_numbers[ext.connection_id] = ext.sequence_number;
    return false;
}

bool record_layer_module::validate_epoch_sequence(const dtls_transaction& trans) {
    const dtls_extension& ext = trans.get_extension();
    
    // Update connection epoch tracking
    auto it = connection_epochs.find(ext.connection_id);
    if (it == connection_epochs.end()) {
        connection_epochs[ext.connection_id] = ext.epoch;
        return true;
    }
    
    // Check epoch progression
    if (ext.epoch > it->second) {
        it->second = ext.epoch;
        epoch_changed.notify();
    } else if (ext.epoch < it->second) {
        return false; // Invalid old epoch
    }
    
    return true;
}

void record_layer_module::update_performance_metrics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    // Calculate throughput
    static sc_time last_update = SC_ZERO_TIME;
    static uint64_t last_bytes = 0;
    
    sc_time current_time = sc_time_stamp();
    sc_time time_delta = current_time - last_update;
    
    if (time_delta > SC_ZERO_TIME && stats.bytes_processed > last_bytes) {
        uint64_t bytes_delta = stats.bytes_processed - last_bytes;
        double time_seconds = time_delta.to_seconds();
        
        if (time_seconds > 0.0) {
            double bytes_per_second = bytes_delta / time_seconds;
            stats.current_throughput_mbps = (bytes_per_second * 8.0) / (1024.0 * 1024.0);
            
            if (stats.current_throughput_mbps > stats.peak_throughput_mbps) {
                stats.peak_throughput_mbps = stats.current_throughput_mbps;
            }
        }
    }
    
    last_update = current_time;
    last_bytes = stats.bytes_processed;
}

void record_layer_module::update_security_metrics() {
    // Update security-related statistics and monitoring
    // This would involve more sophisticated security analysis in a real implementation
}

void record_layer_module::handle_security_event(const std::string& event_type, uint32_t connection_id) {
    std::cout << "[" << sc_time_stamp() << "] RECORD_LAYER: Security event '" 
              << event_type << "' for connection " << connection_id << std::endl;
    security_event.notify();
}

record_layer_module::RecordLayerStats record_layer_module::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void record_layer_module::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.reset();
}

// Handshake Engine Module Implementation
// SC_MODULE_EXPORT not needed - handled by CMake

handshake_engine_module::handshake_engine_module(sc_module_name name)
    : sc_module(name)
    , target_socket("target_socket")
    , message_socket("message_socket")
    , crypto_socket("crypto_socket")
    , record_socket("record_socket")
    , enable_handshake_processing("enable_handshake_processing")
    , handshake_timeout_ms("handshake_timeout_ms")
    , enable_early_data("enable_early_data")
    , max_fragment_size("max_fragment_size")
    , active_handshakes("active_handshakes")
    , completed_handshakes("completed_handshakes")
    , failed_handshakes("failed_handshakes")
    , average_handshake_time("average_handshake_time")
    , handshake_success_rate("handshake_success_rate")
    , message_processing_queue_depth("message_processing_queue_depth")
    , certificate_verification_time("certificate_verification_time")
    , key_exchange_time("key_exchange_time")
    , cpu_utilization_percent("cpu_utilization_percent")
    , invalid_signatures_detected("invalid_signatures_detected")
    , certificate_validation_failures("certificate_validation_failures")
    , protocol_violations("protocol_violations")
    , handshake_security_alert("handshake_security_alert")
{
    // Bind TLM transport interface
    target_socket.register_b_transport(this, &handshake_engine_module::b_transport);
    
    // Initialize message processing components
    initialize_message_components();
    
    // Register SystemC processes
    SC_THREAD(handshake_processing_thread);
    SC_THREAD(timeout_monitoring_thread);
    SC_THREAD(performance_analysis_thread);
    SC_THREAD(security_validation_thread);
    
    // Initialize output ports
    active_handshakes.initialize(0);
    completed_handshakes.initialize(0);
    failed_handshakes.initialize(0);
    average_handshake_time.initialize(SC_ZERO_TIME);
    handshake_success_rate.initialize(0.0);
    message_processing_queue_depth.initialize(0);
    certificate_verification_time.initialize(SC_ZERO_TIME);
    key_exchange_time.initialize(SC_ZERO_TIME);
    cpu_utilization_percent.initialize(0.0);
    invalid_signatures_detected.initialize(0);
    certificate_validation_failures.initialize(0);
    protocol_violations.initialize(0);
    handshake_security_alert.initialize(false);
}

void handshake_engine_module::initialize_message_components() {
    // Create message processing components
    message_processor = std::make_unique<MessageLayerTLM>("message_processor");
    reassembler = std::make_unique<MessageReassemblerTLM>("reassembler");
    fragmenter = std::make_unique<MessageFragmenterTLM>("fragmenter");
    flight_manager = std::make_unique<FlightManagerTLM>("flight_manager");
}

void handshake_engine_module::handshake_processing_thread() {
    while (true) {
        wait(handshake_completed | handshake_failed);
        
        if (handshake_completed.triggered()) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.successful_handshakes++;
            
            // Update timing statistics
            // This would be calculated from actual handshake contexts
            stats.average_handshake_time = stats.total_handshake_time / stats.successful_handshakes;
        }
        
        if (handshake_failed.triggered()) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.failed_handshakes++;
        }
        
        cleanup_completed_handshakes();
    }
}

void handshake_engine_module::timeout_monitoring_thread() {
    while (true) {
        wait(sc_time(1, SC_SEC)); // Check timeouts every second
        
        sc_time current_time = sc_time_stamp();
        sc_time timeout_threshold = sc_time(timeout_ms, SC_MS);
        
        std::lock_guard<std::mutex> lock(handshake_mutex);
        
        auto it = active_handshake_contexts.begin();
        while (it != active_handshake_contexts.end()) {
            HandshakeContext& context = *it->second;
            
            if (current_time - context.last_activity > timeout_threshold) {
                handle_handshake_timeout(it->first);
                it = active_handshake_contexts.erase(it);
                
                std::lock_guard<std::mutex> stats_lock(stats_mutex);
                stats.timeout_handshakes++;
            } else {
                ++it;
            }
        }
    }
}

void handshake_engine_module::performance_analysis_thread() {
    while (true) {
        wait(sc_time(200, SC_MS)); // Performance analysis interval
        
        update_performance_metrics();
        
        // Update output ports
        std::lock_guard<std::mutex> lock(handshake_mutex);
        active_handshakes.write(active_handshake_contexts.size());
        
        std::lock_guard<std::mutex> stats_lock(stats_mutex);
        completed_handshakes.write(stats.successful_handshakes);
        failed_handshakes.write(stats.failed_handshakes);
        average_handshake_time.write(stats.average_handshake_time);
        handshake_success_rate.write(calculate_success_rate());
        
        // Update performance metrics
        message_processing_queue_depth.write(0); // Would be actual queue depth
        certificate_verification_time.write(sc_time(2, SC_MS)); // Example timing
        key_exchange_time.write(sc_time(5, SC_MS)); // Example timing
        cpu_utilization_percent.write(calculate_cpu_utilization());
    }
}

void handshake_engine_module::security_validation_thread() {
    while (true) {
        wait(sc_time(500, SC_MS)); // Security validation interval
        
        std::lock_guard<std::mutex> lock(stats_mutex);
        
        // Update security monitoring ports
        invalid_signatures_detected.write(stats.signature_verification_failures);
        certificate_validation_failures.write(stats.certificate_validation_failures);
        protocol_violations.write(stats.protocol_violations);
        
        // Check for security alerts
        bool alert_condition = (stats.signature_verification_failures > 5) ||
                              (stats.certificate_validation_failures > 3) ||
                              (stats.protocol_violations > 10);
        
        handshake_security_alert.write(alert_condition);
        
        if (alert_condition) {
            std::cout << "[" << sc_time_stamp() << "] HANDSHAKE SECURITY ALERT: Multiple security violations detected" << std::endl;
        }
    }
}

void handshake_engine_module::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    // Extract DTLS extension
    dtls_extension* ext = nullptr;
    trans.get_extension(ext);
    
    if (!ext || !ext->is_handshake_message()) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Create DTLS transaction wrapper
    dtls_transaction dtls_trans;
    
    // Copy TLM payload fields (assignment operator is private)
    auto& payload = dtls_trans.get_payload();
    payload.set_command(trans.get_command());
    payload.set_address(trans.get_address());
    payload.set_data_ptr(trans.get_data_ptr());
    payload.set_data_length(trans.get_data_length());
    payload.set_streaming_width(trans.get_streaming_width());
    payload.set_response_status(trans.get_response_status());
    
    dtls_trans.get_extension() = *ext;
    dtls_trans.set_delay(delay);
    
    // Process handshake message
    bool success = process_handshake_message(dtls_trans);
    
    delay = dtls_trans.get_delay();
    trans.set_response_status(success ? tlm::TLM_OK_RESPONSE : tlm::TLM_GENERIC_ERROR_RESPONSE);
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.messages_processed++;
}

bool handshake_engine_module::process_handshake_message(dtls_transaction& trans) {
    if (!processing_enabled) {
        return false;
    }
    
    const dtls_extension& ext = trans.get_extension();
    uint32_t connection_id = ext.connection_id;
    
    // Validate message format
    if (!validate_message_format(trans)) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.invalid_message_formats++;
        return false;
    }
    
    // Get or create handshake context
    std::lock_guard<std::mutex> lock(handshake_mutex);
    
    auto it = active_handshake_contexts.find(connection_id);
    if (it == active_handshake_contexts.end()) {
        // Create new handshake context
        auto context = std::make_unique<HandshakeContext>();
        context->connection_id = connection_id;
        context->start_time = sc_time_stamp();
        context->last_activity = sc_time_stamp();
        context->state = HandshakeState::IDLE;
        
        active_handshake_contexts[connection_id] = std::move(context);
        it = active_handshake_contexts.find(connection_id);
        
        std::lock_guard<std::mutex> stats_lock(stats_mutex);
        stats.total_handshakes_initiated++;
    }
    
    HandshakeContext& context = *it->second;
    context.last_activity = sc_time_stamp();
    
    // Process message based on type
    bool success = false;
    
    switch (ext.handshake_type) {
        case dtls_extension::HandshakeType::CLIENT_HELLO:
            success = process_client_hello(context, trans);
            break;
        case dtls_extension::HandshakeType::SERVER_HELLO:
            success = process_server_hello(context, trans);
            break;
        case dtls_extension::HandshakeType::NEW_CONNECTION_ID:
            success = process_new_connection_id(context, trans);
            break;
        case dtls_extension::HandshakeType::REQUEST_CONNECTION_ID:
            success = process_retire_connection_id(context, trans);
            break;
        case dtls_extension::HandshakeType::CERTIFICATE:
            success = process_certificate(context, trans);
            break;
        case dtls_extension::HandshakeType::CERTIFICATE_VERIFY:
            success = process_certificate_verify(context, trans);
            break;
        case dtls_extension::HandshakeType::FINISHED:
            success = process_finished(context, trans);
            break;
        default:
            success = false;
            break;
    }
    
    if (success) {
        // Advance handshake state
        success = advance_handshake_state(connection_id, trans);
    }
    
    if (!success) {
        handle_handshake_failure(connection_id, "Message processing failed");
    }
    
    return success;
}

bool handshake_engine_module::validate_message_format(const dtls_transaction& trans) {
    // Basic message format validation
    if (trans.get_data_size() < 4) { // Minimum handshake message size
        return false;
    }
    
    const dtls_extension& ext = trans.get_extension();
    
    // Validate handshake type
    if (static_cast<uint8_t>(ext.handshake_type) == 0 || 
        static_cast<uint8_t>(ext.handshake_type) > 255) {
        return false;
    }
    
    // Validate fragmentation parameters
    if (ext.is_fragmented) {
        if (ext.fragment_offset + ext.fragment_length > ext.message_length) {
            return false;
        }
    }
    
    return true;
}

bool handshake_engine_module::process_client_hello(HandshakeContext& context, const dtls_transaction& trans) {
    // Simulate ClientHello processing
    sc_time processing_time = sc_time(100, SC_US);
    wait(processing_time);
    
    context.crypto_processing_time += processing_time;
    
    // Extract client random (simulated)
    context.client_random.resize(32);
    // In real implementation, would extract from message
    
    return true;
}

bool handshake_engine_module::process_server_hello(HandshakeContext& context, const dtls_transaction& trans) {
    // Simulate ServerHello processing
    sc_time processing_time = sc_time(80, SC_US);
    wait(processing_time);
    
    context.crypto_processing_time += processing_time;
    
    // Extract server random and selected cipher suite (simulated)
    context.server_random.resize(32);
    context.selected_cipher_suite = trans.get_extension().cipher_suite;
    
    return true;
}

bool handshake_engine_module::process_certificate(HandshakeContext& context, const dtls_transaction& trans) {
    // Simulate certificate processing and validation
    sc_time processing_time = sc_time(2, SC_MS); // Certificate validation is expensive
    wait(processing_time);
    
    context.certificate_processing_time += processing_time;
    
    // Simulate certificate validation failure occasionally
    static int cert_counter = 0;
    if (++cert_counter % 100 == 0) { // 1% failure rate
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.certificate_validation_failures++;
        return false;
    }
    
    certificate_validated.notify();
    return true;
}

bool handshake_engine_module::process_certificate_verify(HandshakeContext& context, const dtls_transaction& trans) {
    // Simulate signature verification
    sc_time processing_time = sc_time(3, SC_MS); // Signature verification is expensive
    wait(processing_time);
    
    context.crypto_processing_time += processing_time;
    
    // Simulate signature verification failure occasionally
    static int sig_counter = 0;
    if (++sig_counter % 200 == 0) { // 0.5% failure rate
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.signature_verification_failures++;
        return false;
    }
    
    return true;
}

bool handshake_engine_module::process_finished(HandshakeContext& context, const dtls_transaction& trans) {
    // Simulate Finished message processing
    sc_time processing_time = sc_time(50, SC_US);
    wait(processing_time);
    
    context.crypto_processing_time += processing_time;
    
    // Mark handshake as complete
    context.state = HandshakeState::HANDSHAKE_COMPLETE;
    
    handshake_completed.notify();
    return true;
}

bool handshake_engine_module::advance_handshake_state(uint32_t connection_id, const dtls_transaction& trans) {
    auto it = active_handshake_contexts.find(connection_id);
    if (it == active_handshake_contexts.end()) {
        return false;
    }
    
    HandshakeContext& context = *it->second;
    HandshakeState next_state = get_next_state(context.state, static_cast<uint8_t>(trans.get_extension().handshake_type));
    
    if (validate_state_transition(context.state, next_state)) {
        context.state = next_state;
        return true;
    }
    
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.protocol_violations++;
    return false;
}

handshake_engine_module::HandshakeState handshake_engine_module::get_next_state(HandshakeState current, uint8_t message_type) {
    // RFC 9147 compliant state machine with CID support
    switch (current) {
        case HandshakeState::IDLE:
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::CLIENT_HELLO)) {
                return HandshakeState::CLIENT_HELLO_RECEIVED;
            }
            break;
        case HandshakeState::CLIENT_HELLO_RECEIVED:
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::SERVER_HELLO)) {
                return HandshakeState::SERVER_HELLO_SENT;
            }
            break;
        case HandshakeState::SERVER_HELLO_SENT:
            // Check for CID negotiation first
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::NEW_CONNECTION_ID) ||
                message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::REQUEST_CONNECTION_ID)) {
                return HandshakeState::CID_NEGOTIATION;
            }
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::CERTIFICATE)) {
                return HandshakeState::CERTIFICATE_EXCHANGE;
            }
            break;
        case HandshakeState::CID_NEGOTIATION:
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::NEW_CONNECTION_ID) ||
                message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::REQUEST_CONNECTION_ID)) {
                return HandshakeState::CID_NEGOTIATION; // Stay in CID negotiation
            }
            // CID negotiation complete, proceed to certificate exchange
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::CERTIFICATE)) {
                return HandshakeState::CID_EXCHANGE_COMPLETE;
            }
            break;
        case HandshakeState::CID_EXCHANGE_COMPLETE:
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::CERTIFICATE)) {
                return HandshakeState::CERTIFICATE_EXCHANGE;
            }
            break;
        case HandshakeState::CERTIFICATE_EXCHANGE:
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::CERTIFICATE_VERIFY)) {
                return HandshakeState::CERTIFICATE_VERIFY;
            }
            break;
        case HandshakeState::CERTIFICATE_VERIFY:
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::FINISHED)) {
                return HandshakeState::HANDSHAKE_COMPLETE;
            }
            break;
        case HandshakeState::HANDSHAKE_COMPLETE:
            // Post-handshake CID updates
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::NEW_CONNECTION_ID) ||
                message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::REQUEST_CONNECTION_ID)) {
                return HandshakeState::CID_UPDATE_PENDING;
            }
            break;
        case HandshakeState::CID_UPDATE_PENDING:
            if (message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::NEW_CONNECTION_ID) ||
                message_type == static_cast<uint8_t>(dtls_extension::HandshakeType::REQUEST_CONNECTION_ID)) {
                return HandshakeState::CID_UPDATE_PENDING; // Continue CID updates
            }
            return HandshakeState::HANDSHAKE_COMPLETE; // Return to normal operation
        default:
            break;
    }
    return current; // No state change
}

bool handshake_engine_module::validate_state_transition(HandshakeState from, HandshakeState to) {
    // Basic state transition validation
    return (static_cast<int>(to) >= static_cast<int>(from)) || (to == HandshakeState::HANDSHAKE_FAILED);
}

void handshake_engine_module::handle_handshake_timeout(uint32_t connection_id) {
    log_handshake_event(connection_id, "Handshake timeout");
    handshake_failed.notify();
}

void handshake_engine_module::handle_handshake_failure(uint32_t connection_id, const std::string& reason) {
    log_handshake_event(connection_id, "Handshake failed: " + reason);
    
    auto it = active_handshake_contexts.find(connection_id);
    if (it != active_handshake_contexts.end()) {
        it->second->state = HandshakeState::HANDSHAKE_FAILED;
    }
    
    handshake_failed.notify();
}

void handshake_engine_module::cleanup_completed_handshakes() {
    std::lock_guard<std::mutex> lock(handshake_mutex);
    
    auto it = active_handshake_contexts.begin();
    while (it != active_handshake_contexts.end()) {
        const HandshakeContext& context = *it->second;
        
        if (context.is_complete() || context.has_failed()) {
            // Update timing statistics
            if (context.is_complete()) {
                std::lock_guard<std::mutex> stats_lock(stats_mutex);
                sc_time handshake_time = context.get_total_time();
                stats.total_handshake_time += handshake_time;
                
                if (stats.min_handshake_time == SC_ZERO_TIME || handshake_time < stats.min_handshake_time) {
                    stats.min_handshake_time = handshake_time;
                }
                
                if (handshake_time > stats.max_handshake_time) {
                    stats.max_handshake_time = handshake_time;
                }
            }
            
            it = active_handshake_contexts.erase(it);
        } else {
            ++it;
        }
    }
}

void handshake_engine_module::update_performance_metrics() {
    std::lock_guard<std::mutex> stats_lock(stats_mutex);
    
    // Update peak statistics
    std::lock_guard<std::mutex> handshake_lock(handshake_mutex);
    if (active_handshake_contexts.size() > stats.peak_active_handshakes) {
        stats.peak_active_handshakes = active_handshake_contexts.size();
    }
    
    // Calculate average handshake time
    if (stats.successful_handshakes > 0) {
        stats.average_handshake_time = stats.total_handshake_time / stats.successful_handshakes;
    }
}

double handshake_engine_module::calculate_success_rate() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    uint32_t total_attempts = stats.successful_handshakes + stats.failed_handshakes + stats.timeout_handshakes;
    if (total_attempts > 0) {
        return (static_cast<double>(stats.successful_handshakes) / total_attempts) * 100.0;
    }
    return 0.0;
}

double handshake_engine_module::calculate_cpu_utilization() {
    // Simplified CPU utilization calculation
    std::lock_guard<std::mutex> handshake_lock(handshake_mutex);
    std::lock_guard<std::mutex> stats_lock(stats_mutex);
    
    double utilization = (active_handshake_contexts.size() * 10.0); // 10% per active handshake
    return std::min(100.0, utilization);
}

void handshake_engine_module::log_handshake_event(uint32_t connection_id, const std::string& event) {
    std::cout << "[" << sc_time_stamp() << "] HANDSHAKE: Connection " << connection_id 
              << " - " << event << std::endl;
}

// RFC 9147 Connection ID Processing Implementation

bool handshake_engine_module::process_new_connection_id(HandshakeContext& context, const dtls_transaction& trans) {
    if (!validate_cid_message(trans)) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.protocol_violations++;
        return false;
    }
    
    // Simulate NEW_CONNECTION_ID processing
    sc_time processing_time = sc_time(50, SC_US);
    wait(processing_time);
    
    const dtls_extension& ext = trans.get_extension();
    const unsigned char* data = trans.get_data();
    size_t data_size = trans.get_data_size();
    
    if (data_size < 9) { // Minimum: 1 byte length + 8 bytes sequence number
        return false;
    }
    
    // Parse NEW_CONNECTION_ID message
    uint8_t cid_length = data[0];
    if (cid_length > 20 || data_size < 1 + cid_length + 8) { // length + CID + sequence
        return false;
    }
    
    std::vector<uint8_t> new_cid(data + 1, data + 1 + cid_length);
    uint64_t sequence_number = 0;
    
    // Extract sequence number (big-endian)
    for (int i = 0; i < 8; ++i) {
        sequence_number = (sequence_number << 8) | data[1 + cid_length + i];
    }
    
    // Update connection context
    bool success = update_active_cid(context, sequence_number, new_cid);
    if (success) {
        context.cid_negotiation_accepted = true;
        log_handshake_event(context.connection_id, 
                           "NEW_CONNECTION_ID processed, CID length: " + std::to_string(cid_length));
    }
    
    return success;
}

bool handshake_engine_module::process_retire_connection_id(HandshakeContext& context, const dtls_transaction& trans) {
    if (!validate_cid_message(trans)) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.protocol_violations++;
        return false;
    }
    
    // Simulate RETIRE_CONNECTION_ID processing
    sc_time processing_time = sc_time(30, SC_US);
    wait(processing_time);
    
    const unsigned char* data = trans.get_data();
    size_t data_size = trans.get_data_size();
    
    if (data_size < 8) { // Need 8 bytes for sequence number
        return false;
    }
    
    // Extract sequence number to retire (big-endian)
    uint64_t sequence_to_retire = 0;
    for (int i = 0; i < 8; ++i) {
        sequence_to_retire = (sequence_to_retire << 8) | data[i];
    }
    
    // Retire the specified CID
    bool success = retire_cid(context, sequence_to_retire);
    if (success) {
        log_handshake_event(context.connection_id, 
                           "RETIRE_CONNECTION_ID processed, sequence: " + std::to_string(sequence_to_retire));
    }
    
    return success;
}

bool handshake_engine_module::validate_cid_message(const dtls_transaction& trans) {
    // Basic CID message validation
    if (trans.get_data_size() == 0) {
        return false;
    }
    
    const dtls_extension& ext = trans.get_extension();
    
    // CID messages should have valid connection context
    if (ext.connection_id == 0) {
        return false;
    }
    
    // Validate handshake type
    bool valid_handshake_type = (ext.handshake_type == dtls_extension::HandshakeType::NEW_CONNECTION_ID ||
                                ext.handshake_type == dtls_extension::HandshakeType::REQUEST_CONNECTION_ID);
    
    if (!valid_handshake_type) {
        return false;
    }
    
    // RFC 9147 specific CID validation
    return validate_cid_rfc9147_compliance(ext);
}

bool handshake_engine_module::validate_cid_rfc9147_compliance(const dtls_extension& ext) {
    // RFC 9147 Section 9: Connection ID validation
    
    // Validate CID length constraints (0-20 bytes per RFC 9147)
    if (ext.cid_length > 20) {
        log_handshake_event(ext.connection_id, "CID validation failed: length exceeds RFC 9147 limit");
        return false;
    }
    
    // Validate CID sequence number for NEW_CONNECTION_ID messages
    if (ext.handshake_type == dtls_extension::HandshakeType::NEW_CONNECTION_ID) {
        // Sequence number must be valid and not duplicate
        if (!validate_cid_sequence_number(ext.connection_id, ext.sequence_number)) {
            log_handshake_event(ext.connection_id, "CID validation failed: invalid sequence number");
            return false;
        }
    }
    
    // Validate CID is not all zeros (reserved value per RFC 9147)
    if (ext.local_cid.size() > 0) {
        bool all_zeros = std::all_of(ext.local_cid.begin(), ext.local_cid.end(), 
                                    [](uint8_t byte) { return byte == 0; });
        if (all_zeros) {
            log_handshake_event(ext.connection_id, "CID validation failed: all-zero CID not allowed");
            return false;
        }
    }
    
    // Validate CID negotiation state consistency
    if (ext.cid_negotiation_enabled && ext.local_cid.empty() && ext.peer_cid.empty()) {
        log_handshake_event(ext.connection_id, "CID validation failed: negotiation enabled but no CIDs present");
        return false;
    }
    
    return true;
}

bool handshake_engine_module::validate_cid_sequence_number(uint32_t connection_id, uint64_t sequence) {
    auto it = active_handshake_contexts.find(connection_id);
    if (it == active_handshake_contexts.end()) {
        return false; // No context for this connection
    }
    
    HandshakeContext& context = *it->second;
    
    // Sequence number must be greater than current (no replay)
    if (sequence <= context.cid_sequence_number) {
        return false;
    }
    
    // Check for sequence number gap (RFC 9147 allows gaps but we validate reasonableness)
    uint64_t gap = sequence - context.cid_sequence_number;
    if (gap > 1000) { // Configurable limit for reasonable gaps
        log_handshake_event(connection_id, "CID sequence gap too large: " + std::to_string(gap));
        return false;
    }
    
    return true;
}

bool handshake_engine_module::validate_cid_migration_request(const HandshakeContext& context, const std::vector<uint8_t>& new_cid) {
    // RFC 9147 Section 8: CID migration validation
    
    // Check if migration is supported for this connection
    if (!context.cid_migration_supported) {
        return false;
    }
    
    // Validate new CID is different from current CIDs
    if (!context.local_cid.empty() && context.local_cid == new_cid) {
        return false; // Cannot migrate to same CID
    }
    
    if (!context.peer_cid.empty() && context.peer_cid == new_cid) {
        return false; // Cannot use peer's CID as our own
    }
    
    // Check active CID pool doesn't already contain this CID
    for (const auto& [seq, cid] : context.active_cids) {
        if (cid == new_cid) {
            return false; // CID already in use
        }
    }
    
    return true;
}

bool handshake_engine_module::negotiate_connection_id(HandshakeContext& context, const std::vector<uint8_t>& proposed_cid) {
    // RFC 9147 CID negotiation logic
    if (proposed_cid.size() > 20) {
        return false; // CID too long
    }
    
    // Accept the proposed CID
    context.local_cid = proposed_cid;
    context.cid_negotiation_requested = true;
    context.cid_migration_supported = true;
    
    // Store in active CIDs with sequence 0
    context.active_cids[0] = proposed_cid;
    
    log_handshake_event(context.connection_id, 
                       "CID negotiation completed, CID length: " + std::to_string(proposed_cid.size()));
    
    return true;
}

bool handshake_engine_module::update_active_cid(HandshakeContext& context, uint64_t sequence, const std::vector<uint8_t>& new_cid) {
    // RFC 9147 CID update logic
    if (new_cid.size() > 20) {
        return false; // CID too long
    }
    
    // Check if sequence number is valid (must be greater than current)
    if (sequence <= context.cid_sequence_number) {
        return false; // Invalid sequence number
    }
    
    // Add to active CIDs
    context.active_cids[sequence] = new_cid;
    context.cid_sequence_number = sequence;
    
    // Update peer CID if this is from peer
    context.peer_cid = new_cid;
    
    return true;
}

bool handshake_engine_module::retire_cid(HandshakeContext& context, uint64_t sequence_to_retire) {
    // RFC 9147 CID retirement logic
    auto it = context.active_cids.find(sequence_to_retire);
    if (it == context.active_cids.end()) {
        return false; // CID not found
    }
    
    // Cannot retire the current CID if it's the only one
    if (context.active_cids.size() <= 1) {
        return false; // Must have at least one active CID
    }
    
    // Remove the CID
    context.active_cids.erase(it);
    
    return true;
}

handshake_engine_module::HandshakeEngineStats handshake_engine_module::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void handshake_engine_module::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.reset();
}

// Key Manager Module Implementation  
// SC_MODULE_EXPORT not needed - handled by CMake

key_manager_module::key_manager_module(sc_module_name name) 
    : sc_module(name)
    , target_socket("target_socket")
    , crypto_socket("crypto_socket")
    , enable_key_updates("enable_key_updates")
    , key_update_threshold("key_update_threshold")
    , hardware_key_storage("hardware_key_storage")
    , cipher_suite("cipher_suite")
    , active_key_contexts("active_key_contexts")
    , keys_derived("keys_derived")
    , key_updates_performed("key_updates_performed")
    , average_key_derivation_time("average_key_derivation_time")
    , key_storage_secure("key_storage_secure")
    , hkdf_processing_time("hkdf_processing_time")
    , traffic_key_generation_time("traffic_key_generation_time")
    , key_derivation_queue_depth("key_derivation_queue_depth")
    , key_generation_throughput("key_generation_throughput")
    , key_compromise_events("key_compromise_events")
    , key_validation_failures("key_validation_failures")
    , key_security_alert("key_security_alert")
{
    // Bind TLM transport interface
    target_socket.register_b_transport(this, &key_manager_module::b_transport);
    
    // Initialize crypto components
    initialize_crypto_components();
    
    // Register SystemC processes
    SC_THREAD(key_management_thread);
    SC_THREAD(key_rotation_thread);
    SC_THREAD(security_monitoring_thread);
    SC_THREAD(performance_monitoring_thread);
    
    // Initialize output ports
    active_key_contexts.initialize(0);
    keys_derived.initialize(0);
    key_updates_performed.initialize(0);
    average_key_derivation_time.initialize(SC_ZERO_TIME);
    key_storage_secure.initialize(true);
    hkdf_processing_time.initialize(SC_ZERO_TIME);
    traffic_key_generation_time.initialize(SC_ZERO_TIME);
    key_derivation_queue_depth.initialize(0);
    key_generation_throughput.initialize(0.0);
    key_compromise_events.initialize(0);
    key_validation_failures.initialize(0);
    key_security_alert.initialize(false);
}

void key_manager_module::initialize_crypto_components() {
    // Create crypto manager and timing model
    crypto_manager = std::make_unique<CryptoManagerTLM>("crypto_manager");
    crypto_timing = std::make_unique<crypto_timing_model>("crypto_timing");
}

void key_manager_module::key_management_thread() {
    while (true) {
        wait(key_derived | key_updated);
        
        if (key_derived.triggered()) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.successful_derivations++;
            keys_derived.write(stats.successful_derivations);
        }
        
        if (key_updated.triggered()) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.key_updates++;
            key_updates_performed.write(stats.key_updates);
        }
        
        // Update active contexts count
        std::lock_guard<std::mutex> key_lock(key_mutex);
        active_key_contexts.write(key_contexts.size());
    }
}

void key_manager_module::key_rotation_thread() {
    while (true) {
        wait(sc_time(10, SC_SEC)); // Key rotation check interval
        
        if (key_updates_enabled) {
            perform_key_rotation();
        }
    }
}

void key_manager_module::security_monitoring_thread() {
    while (true) {
        wait(key_compromise_detected);
        
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.key_compromise_events++;
        key_compromise_events.write(stats.key_compromise_events);
        
        key_security_alert.write(stats.key_compromise_events > 0);
        
        std::cout << "[" << sc_time_stamp() << "] KEY_MANAGER: Security alert - key compromise detected" << std::endl;
    }
}

void key_manager_module::performance_monitoring_thread() {
    while (true) {
        wait(sc_time(500, SC_MS)); // Performance monitoring interval
        
        update_performance_metrics();
        
        // Update performance ports
        std::lock_guard<std::mutex> lock(stats_mutex);
        average_key_derivation_time.write(stats.average_derivation_time);
        hkdf_processing_time.write(sc_time(100, SC_NS)); // Example timing
        traffic_key_generation_time.write(sc_time(200, SC_NS)); // Example timing
        key_derivation_queue_depth.write(0); // Would be actual queue depth
        key_generation_throughput.write(calculate_key_generation_throughput());
        
        key_storage_secure.write(hw_key_storage);
    }
}

void key_manager_module::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    // Extract DTLS extension
    dtls_extension* ext = nullptr;
    trans.get_extension(ext);
    
    if (!ext) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    uint32_t connection_id = ext->connection_id;
    
    // Simulate key derivation processing
    sc_time processing_time = crypto_timing->calculate_key_derivation_time("hkdf-sha256", 32);
    delay += processing_time;
    wait(processing_time);
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_key_derivations++;
    stats.total_derivation_time += processing_time;
    
    if (stats.total_key_derivations > 0) {
        stats.average_derivation_time = stats.total_derivation_time / stats.total_key_derivations;
    }
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
    key_derived.notify();
}

bool key_manager_module::create_key_context(uint32_t connection_id, uint16_t cipher_suite) {
    std::lock_guard<std::mutex> lock(key_mutex);
    
    if (key_contexts.find(connection_id) != key_contexts.end()) {
        return false; // Already exists
    }
    
    auto context = std::make_unique<KeyContext>();
    context->connection_id = connection_id;
    context->cipher_suite = cipher_suite;
    context->creation_time = sc_time_stamp();
    context->last_update = sc_time_stamp();
    context->hardware_stored = hw_key_storage;
    
    // Initialize key lengths based on cipher suite
    switch (cipher_suite) {
        case 0x1301: // TLS_AES_128_GCM_SHA256
            context->key_length = 16;
            context->iv_length = 12;
            break;
        case 0x1302: // TLS_AES_256_GCM_SHA384
            context->key_length = 32;
            context->iv_length = 12;
            break;
        default:
            context->key_length = 16;
            context->iv_length = 12;
            break;
    }
    
    key_contexts[connection_id] = std::move(context);
    
    log_key_event(connection_id, "Key context created");
    return true;
}

bool key_manager_module::derive_handshake_keys(uint32_t connection_id, const std::vector<uint8_t>& shared_secret) {
    KeyContext* context = get_key_context(connection_id);
    if (!context) {
        return false;
    }
    
    // Simulate HKDF processing time
    sc_time processing_time = crypto_timing->calculate_key_derivation_time("hkdf-sha256", shared_secret.size());
    wait(processing_time);
    
    // Derive handshake secret (simplified)
    context->handshake_secret = derive_key_material(shared_secret, "handshake_secret", 32);
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_derivation_time += processing_time;
    stats.successful_derivations++;
    
    log_key_event(connection_id, "Handshake keys derived");
    key_derived.notify();
    
    return true;
}

bool key_manager_module::derive_traffic_keys(uint32_t connection_id, const std::vector<uint8_t>& master_secret) {
    KeyContext* context = get_key_context(connection_id);
    if (!context) {
        return false;
    }
    
    // Simulate key derivation processing
    sc_time processing_time = crypto_timing->calculate_key_derivation_time("hkdf-sha256", master_secret.size());
    wait(processing_time);
    
    // Derive traffic keys (simplified)
    context->master_secret = master_secret;
    context->client_write_key = derive_key_material(master_secret, "client_write_key", context->key_length);
    context->server_write_key = derive_key_material(master_secret, "server_write_key", context->key_length);
    context->client_write_iv = derive_key_material(master_secret, "client_write_iv", context->iv_length);
    context->server_write_iv = derive_key_material(master_secret, "server_write_iv", context->iv_length);
    
    context->last_update = sc_time_stamp();
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_derivation_time += processing_time;
    stats.successful_derivations++;
    
    log_key_event(connection_id, "Traffic keys derived");
    key_derived.notify();
    
    return true;
}

std::vector<uint8_t> key_manager_module::derive_key_material(const std::vector<uint8_t>& secret,
                                                           const std::string& label,
                                                           uint32_t length) {
    // Simplified key derivation - real implementation would use proper HKDF
    std::vector<uint8_t> result(length);
    
    // Simple hash-based derivation for simulation
    for (uint32_t i = 0; i < length; ++i) {
        result[i] = static_cast<uint8_t>((secret[i % secret.size()] + label[i % label.size()] + i) & 0xFF);
    }
    
    return result;
}

void key_manager_module::perform_key_rotation() {
    std::lock_guard<std::mutex> lock(key_mutex);
    
    for (auto& pair : key_contexts) {
        KeyContext& context = *pair.second;
        
        if (context.needs_update(update_threshold)) {
            // Perform key update
            std::vector<uint8_t> new_master_secret = derive_key_material(context.master_secret, "key_update", 32);
            
            // Update traffic keys
            context.client_write_key = derive_key_material(new_master_secret, "updated_client_key", context.key_length);
            context.server_write_key = derive_key_material(new_master_secret, "updated_server_key", context.key_length);
            
            context.last_update = sc_time_stamp();
            context.usage_count = 0;
            context.bytes_protected = 0;
            
            std::lock_guard<std::mutex> stats_lock(stats_mutex);
            stats.key_updates++;
            
            log_key_event(context.connection_id, "Key rotation performed");
            key_updated.notify();
        }
    }
}

void key_manager_module::update_performance_metrics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    // Update peak statistics
    std::lock_guard<std::mutex> key_lock(key_mutex);
    if (key_contexts.size() > stats.peak_active_contexts) {
        stats.peak_active_contexts = key_contexts.size();
    }
    
    // Calculate average derivation time
    if (stats.total_key_derivations > 0) {
        stats.average_derivation_time = stats.total_derivation_time / stats.total_key_derivations;
    }
}

double key_manager_module::calculate_key_generation_throughput() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    static sc_time last_update = SC_ZERO_TIME;
    static uint64_t last_keys = 0;
    
    sc_time current_time = sc_time_stamp();
    sc_time time_delta = current_time - last_update;
    
    if (time_delta > SC_ZERO_TIME && stats.successful_derivations > last_keys) {
        uint64_t keys_delta = stats.successful_derivations - last_keys;
        double time_seconds = time_delta.to_seconds();
        
        if (time_seconds > 0.0) {
            double throughput = keys_delta / time_seconds;
            last_update = current_time;
            last_keys = stats.successful_derivations;
            return throughput;
        }
    }
    
    return 0.0;
}

void key_manager_module::log_key_event(uint32_t connection_id, const std::string& event) {
    std::cout << "[" << sc_time_stamp() << "] KEY_MANAGER: Connection " << connection_id 
              << " - " << event << std::endl;
}

key_manager_module::KeyContext* key_manager_module::get_key_context(uint32_t connection_id) {
    std::lock_guard<std::mutex> lock(key_mutex);
    
    auto it = key_contexts.find(connection_id);
    if (it != key_contexts.end()) {
        return it->second.get();
    }
    return nullptr;
}

key_manager_module::KeyManagerStats key_manager_module::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void key_manager_module::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.reset();
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls