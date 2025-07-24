#include "dtls_protocol_stack.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cmath>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

// Global timing configuration for protocol stack
dtls_timing_config g_protocol_stack_timing;

// Constructor
SC_MODULE_EXPORT(dtls_protocol_stack);

dtls_protocol_stack::dtls_protocol_stack(sc_module_name name)
    : sc_module(name)
    , application_target_socket("application_target_socket")
    , network_initiator_socket("network_initiator_socket")
    , enable_stack("enable_stack")
    , reset_stack("reset_stack")
    , max_connections("max_connections")
    , hardware_acceleration_enabled("hardware_acceleration_enabled")
    , mtu_size("mtu_size")
    , active_connections("active_connections")
    , total_bytes_processed("total_bytes_processed")
    , average_throughput_mbps("average_throughput_mbps")
    , average_handshake_time("average_handshake_time")
    , stack_operational("stack_operational")
    , crypto_queue_depth("crypto_queue_depth")
    , record_queue_depth("record_queue_depth")
    , message_queue_depth("message_queue_depth")
    , cpu_utilization_percent("cpu_utilization_percent")
    , memory_usage_bytes("memory_usage_bytes")
    , last_performance_update(SC_ZERO_TIME)
{
    // Bind TLM transport methods
    application_target_socket.register_b_transport(this, &dtls_protocol_stack::b_transport_application);
    
    // Initialize components
    initialize_components();
    connect_internal_channels();
    configure_timing_models();
    
    // Register SystemC processes
    SC_THREAD(application_interface_process);
    SC_THREAD(network_interface_process);
    SC_THREAD(performance_monitoring_process);
    SC_THREAD(connection_management_process);
    SC_THREAD(error_handling_process);
    
    // Initialize output ports
    active_connections.initialize(0);
    total_bytes_processed.initialize(0);
    average_throughput_mbps.initialize(0.0);
    average_handshake_time.initialize(SC_ZERO_TIME);
    stack_operational.initialize(false);
    crypto_queue_depth.initialize(0);
    record_queue_depth.initialize(0);
    message_queue_depth.initialize(0);
    cpu_utilization_percent.initialize(0.0);
    memory_usage_bytes.initialize(0);
    
    log_event("DTLS Protocol Stack Initialized", "Ready for operation");
}

void dtls_protocol_stack::initialize_components() {
    // Create protocol layer components
    record_layer = std::make_unique<RecordLayerTLM>("record_layer");
    message_layer = std::make_unique<MessageLayerTLM>("message_layer");
    crypto_provider = std::make_unique<CryptoProviderTLM>("crypto_provider");
    hw_crypto_provider = std::make_unique<HardwareAcceleratedCryptoTLM>("hw_crypto_provider");
    crypto_manager = std::make_unique<CryptoManagerTLM>("crypto_manager");
    
    // Create internal communication channels
    crypto_channel = std::make_unique<CryptoOperationChannel>("crypto_channel");
    record_channel = std::make_unique<RecordOperationChannel>("record_channel");
    message_channel = std::make_unique<MessageOperationChannel>("message_channel");
    transport_channel = std::make_unique<TransportChannel>("transport_channel");
    interconnect_bus = std::make_unique<DTLSInterconnectBus>("interconnect_bus");
}

void dtls_protocol_stack::connect_internal_channels() {
    // Connect components through channels and interconnect bus
    
    // Crypto connections
    crypto_manager->crypto_provider_socket.bind(crypto_provider->target_socket);
    crypto_manager->hw_crypto_provider_socket.bind(hw_crypto_provider->target_socket);
    
    // Record layer connections  
    record_layer->crypto_initiator_socket.bind(crypto_manager->target_socket);
    
    // Message layer connections
    message_layer->record_initiator_socket.bind(record_layer->target_socket);
    
    // Interconnect bus connections
    interconnect_bus->bind_crypto_channel(*crypto_channel);
    interconnect_bus->bind_record_channel(*record_channel);
    interconnect_bus->bind_message_channel(*message_channel);
    interconnect_bus->bind_transport_channel(*transport_channel);
}

void dtls_protocol_stack::configure_timing_models() {
    // Configure timing parameters for realistic simulation
    g_protocol_stack_timing.aes_encryption_time = sc_time(50, SC_NS);
    g_protocol_stack_timing.aes_decryption_time = sc_time(45, SC_NS);
    g_protocol_stack_timing.ecdsa_sign_time = sc_time(2000, SC_NS);
    g_protocol_stack_timing.ecdsa_verify_time = sc_time(3000, SC_NS);
    g_protocol_stack_timing.hkdf_derive_time = sc_time(100, SC_NS);
    g_protocol_stack_timing.random_generation_time = sc_time(25, SC_NS);
    g_protocol_stack_timing.hash_computation_time = sc_time(30, SC_NS);
    
    g_protocol_stack_timing.record_protection_time = sc_time(75, SC_NS);
    g_protocol_stack_timing.record_unprotection_time = sc_time(80, SC_NS);
    g_protocol_stack_timing.anti_replay_check_time = sc_time(10, SC_NS);
    g_protocol_stack_timing.sequence_number_gen_time = sc_time(5, SC_NS);
    g_protocol_stack_timing.epoch_advance_time = sc_time(15, SC_NS);
    
    g_protocol_stack_timing.message_fragmentation_time = sc_time(40, SC_NS);
    g_protocol_stack_timing.fragment_reassembly_time = sc_time(60, SC_NS);
    g_protocol_stack_timing.flight_creation_time = sc_time(35, SC_NS);
    g_protocol_stack_timing.retransmission_check_time = sc_time(20, SC_NS);
    
    g_protocol_stack_timing.packet_transmission_time = sc_time(1000, SC_NS);
    g_protocol_stack_timing.network_latency = sc_time(50000, SC_NS);
    g_protocol_stack_timing.mtu_discovery_time = sc_time(5000, SC_NS);
    
    g_protocol_stack_timing.buffer_allocation_time = sc_time(25, SC_NS);
    g_protocol_stack_timing.memory_copy_time = sc_time(2, SC_NS);
    g_protocol_stack_timing.secure_zero_time = sc_time(5, SC_NS);
}

void dtls_protocol_stack::application_interface_process() {
    while (true) {
        wait(handshake_completed | connection_established | error_detected);
        
        if (handshake_completed.triggered()) {
            log_event("Handshake Completed", "Connection ready for data transfer");
            stats.successful_handshakes++;
        }
        
        if (connection_established.triggered()) {
            log_event("Connection Established", "New connection active");
            stats.active_connections++;
            active_connections.write(stats.active_connections);
        }
        
        if (error_detected.triggered()) {
            log_event("Error Detected", "Protocol error occurred");
            // Handle error recovery
        }
    }
}

void dtls_protocol_stack::network_interface_process() {
    while (true) {
        wait(sc_time(1, SC_MS)); // Network processing cycle
        
        // Process network events and timeouts
        cleanup_inactive_connections();
        
        // Update network-related statistics
        if (stats.active_connections > 0) {
            stack_operational.write(true);
        } else {
            stack_operational.write(false);
        }
    }
}

void dtls_protocol_stack::performance_monitoring_process() {
    while (true) {
        wait(sc_time(100, SC_MS)); // Performance monitoring interval
        
        update_performance_metrics();
        
        // Write performance metrics to output ports
        total_bytes_processed.write(stats.total_application_bytes + stats.total_network_bytes);
        average_throughput_mbps.write(calculate_throughput());
        average_handshake_time.write(stats.average_handshake_time);
        cpu_utilization_percent.write(calculate_cpu_utilization());
        memory_usage_bytes.write(calculate_memory_usage());
        
        // Check performance thresholds
        if (calculate_cpu_utilization() > 90.0 || 
            calculate_memory_usage() > 1024 * 1024 * 1024) { // 1GB
            performance_threshold_exceeded.notify();
        }
    }
}

void dtls_protocol_stack::connection_management_process() {
    while (true) {
        wait(connection_terminated | performance_threshold_exceeded);
        
        if (connection_terminated.triggered()) {
            stats.active_connections = static_cast<uint32_t>(active_connections_map.size());
            active_connections.write(stats.active_connections);
        }
        
        if (performance_threshold_exceeded.triggered()) {
            log_event("Performance Threshold Exceeded", "System under stress");
            // Implement load shedding or connection limiting
        }
    }
}

void dtls_protocol_stack::error_handling_process() {
    while (true) {
        wait(error_detected);
        
        stats.protocol_violations++;
        log_event("Protocol Error", "Error handling activated");
        
        // Implement error recovery mechanisms
        // - Connection recovery
        // - State reset
        // - Resource cleanup
    }
}

void dtls_protocol_stack::b_transport_application(tlm::tlm_generic_payload& trans, sc_time& delay) {
    process_application_data(trans, delay);
}

void dtls_protocol_stack::b_transport_network(tlm::tlm_generic_payload& trans, sc_time& delay) {
    process_network_data(trans, delay);
}

void dtls_protocol_stack::process_application_data(tlm::tlm_generic_payload& trans, sc_time& delay) {
    sc_time processing_start = sc_time_stamp();
    
    // Extract transaction data
    unsigned char* data = trans.get_data_ptr();
    unsigned int length = trans.get_data_length();
    
    if (!data || length == 0) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Route through protocol layers
    sc_time layer_delay = SC_ZERO_TIME;
    
    // Message layer processing
    route_message_operation(trans, layer_delay);
    delay += layer_delay;
    
    // Record layer processing
    route_record_operation(trans, layer_delay);
    delay += layer_delay;
    
    // Crypto processing
    route_crypto_operation(trans, layer_delay);
    delay += layer_delay;
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_application_bytes += length;
    
    sc_time processing_time = sc_time_stamp() - processing_start + delay;
    stats.total_data_processing_time += processing_time;
    
    if (stats.total_connections_created > 0) {
        stats.average_data_processing_time = 
            stats.total_data_processing_time / stats.total_connections_created;
    }
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
}

void dtls_protocol_stack::process_network_data(tlm::tlm_generic_payload& trans, sc_time& delay) {
    sc_time processing_start = sc_time_stamp();
    
    // Extract network packet data
    unsigned char* data = trans.get_data_ptr();
    unsigned int length = trans.get_data_length();
    
    if (!data || length == 0) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Reverse processing through protocol layers
    sc_time layer_delay = SC_ZERO_TIME;
    
    // Record layer unprotection
    route_record_operation(trans, layer_delay);
    delay += layer_delay;
    
    // Message layer reassembly
    route_message_operation(trans, layer_delay);
    delay += layer_delay;
    
    // Update statistics
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_network_bytes += length;
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
}

void dtls_protocol_stack::route_crypto_operation(tlm::tlm_generic_payload& trans, sc_time& delay) {
    if (use_hardware_acceleration && hw_crypto_provider) {
        hw_crypto_provider->target_socket->b_transport(trans, delay);
    } else {
        crypto_provider->target_socket->b_transport(trans, delay);
    }
    
    delay += g_protocol_stack_timing.aes_encryption_time;
}

void dtls_protocol_stack::route_record_operation(tlm::tlm_generic_payload& trans, sc_time& delay) {
    record_layer->target_socket->b_transport(trans, delay);
    delay += g_protocol_stack_timing.record_protection_time;
}

void dtls_protocol_stack::route_message_operation(tlm::tlm_generic_payload& trans, sc_time& delay) {
    message_layer->target_socket->b_transport(trans, delay);
    delay += g_protocol_stack_timing.message_fragmentation_time;
}

uint32_t dtls_protocol_stack::create_connection() {
    uint32_t connection_id = utils::generate_connection_id();
    
    auto context = std::make_unique<ConnectionContext>();
    context->connection_id = connection_id;
    context->creation_time = sc_time_stamp();
    context->last_activity = sc_time_stamp();
    context->bytes_sent = 0;
    context->bytes_received = 0;
    context->handshake_complete = false;
    context->state = ConnectionContext::State::INITIALIZING;
    
    active_connections_map[connection_id] = std::move(context);
    
    stats.total_connections_created++;
    stats.active_connections = static_cast<uint32_t>(active_connections_map.size());
    
    connection_established.notify();
    
    return connection_id;
}

bool dtls_protocol_stack::destroy_connection(uint32_t connection_id) {
    auto it = active_connections_map.find(connection_id);
    if (it != active_connections_map.end()) {
        active_connections_map.erase(it);
        stats.active_connections = static_cast<uint32_t>(active_connections_map.size());
        connection_terminated.notify();
        return true;
    }
    return false;
}

void dtls_protocol_stack::update_performance_metrics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    
    sc_time current_time = sc_time_stamp();
    sc_time time_delta = current_time - last_performance_update;
    
    if (time_delta > SC_ZERO_TIME) {
        // Calculate throughput
        stats.overhead_percentage = calculate_overhead_percentage();
        
        // Update timing statistics
        if (stats.successful_handshakes > 0) {
            stats.average_handshake_time = 
                stats.total_handshake_time / stats.successful_handshakes;
        }
        
        // Update resource utilization
        stats.current_memory_usage = calculate_memory_usage();
        stats.current_cpu_utilization = calculate_cpu_utilization();
        
        if (stats.current_memory_usage > stats.peak_memory_usage) {
            stats.peak_memory_usage = stats.current_memory_usage;
        }
        
        if (stats.current_cpu_utilization > stats.peak_cpu_utilization) {
            stats.peak_cpu_utilization = stats.current_cpu_utilization;
        }
    }
    
    last_performance_update = current_time;
}

double dtls_protocol_stack::calculate_throughput() {
    sc_time current_time = sc_time_stamp();
    sc_time time_delta = current_time - last_performance_update;
    
    if (time_delta <= SC_ZERO_TIME) {
        return 0.0;
    }
    
    uint64_t bytes_delta = bytes_processed_since_last_update;
    double time_seconds = time_delta.to_seconds();
    
    if (time_seconds > 0.0) {
        double bytes_per_second = bytes_delta / time_seconds;
        return (bytes_per_second * 8.0) / (1024.0 * 1024.0); // Convert to Mbps
    }
    
    return 0.0;
}

double dtls_protocol_stack::calculate_cpu_utilization() {
    sc_time current_time = sc_time_stamp();
    sc_time time_delta = current_time - last_performance_update;
    
    if (time_delta <= SC_ZERO_TIME) {
        return 0.0;
    }
    
    double processing_ratio = processing_time_since_last_update.to_seconds() / time_delta.to_seconds();
    return std::min(100.0, processing_ratio * 100.0);
}

uint64_t dtls_protocol_stack::calculate_memory_usage() {
    // Estimate memory usage based on active connections and buffers
    uint64_t base_usage = 1024 * 1024; // 1MB base
    uint64_t connection_usage = active_connections_map.size() * 64 * 1024; // 64KB per connection
    uint64_t buffer_usage = stats.total_application_bytes / 100; // Estimate buffer overhead
    
    return base_usage + connection_usage + buffer_usage;
}

double dtls_protocol_stack::calculate_overhead_percentage() {
    if (stats.total_application_bytes == 0) {
        return 0.0;
    }
    
    stats.protocol_overhead_bytes = stats.total_network_bytes - stats.total_application_bytes;
    return (static_cast<double>(stats.protocol_overhead_bytes) / stats.total_application_bytes) * 100.0;
}

void dtls_protocol_stack::cleanup_inactive_connections() {
    sc_time current_time = sc_time_stamp();
    sc_time timeout_threshold = sc_time(30, SC_SEC); // 30 second timeout
    
    auto it = active_connections_map.begin();
    while (it != active_connections_map.end()) {
        if (current_time - it->second->last_activity > timeout_threshold) {
            log_event("Connection Timeout", "Cleaning up inactive connection");
            it = active_connections_map.erase(it);
            stats.timeout_events++;
        } else {
            ++it;
        }
    }
}

void dtls_protocol_stack::log_event(const std::string& event, const std::string& details) {
    std::cout << "[" << sc_time_stamp() << "] DTLS_STACK: " << event;
    if (!details.empty()) {
        std::cout << " - " << details;
    }
    std::cout << std::endl;
}

dtls_protocol_stack::ProtocolStackStats dtls_protocol_stack::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex);
    return stats;
}

void dtls_protocol_stack::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.reset();
    last_performance_update = sc_time_stamp();
    bytes_processed_since_last_update = 0;
    processing_time_since_last_update = SC_ZERO_TIME;
}

// Utility function implementations
namespace utils {

sc_time calculate_protocol_processing_time(const std::string& operation, size_t data_size) {
    sc_time base_time = g_protocol_stack_timing.buffer_allocation_time;
    sc_time data_time = sc_time(data_size * 2, SC_NS); // 2ns per byte
    
    if (operation == "encrypt") {
        return base_time + g_protocol_stack_timing.aes_encryption_time + data_time;
    } else if (operation == "decrypt") {
        return base_time + g_protocol_stack_timing.aes_decryption_time + data_time;
    } else if (operation == "sign") {
        return base_time + g_protocol_stack_timing.ecdsa_sign_time + data_time;
    } else if (operation == "verify") {
        return base_time + g_protocol_stack_timing.ecdsa_verify_time + data_time;
    }
    
    return base_time + data_time;
}

uint32_t generate_connection_id() {
    static uint32_t counter = 1;
    return counter++;
}

void convert_result_to_transaction(const dtls_protocol_stack::ProtocolStackStats& stats,
                                 tlm::tlm_generic_payload& trans) {
    // Convert statistics to transaction payload
    size_t stats_size = sizeof(dtls_protocol_stack::ProtocolStackStats);
    unsigned char* data = new unsigned char[stats_size];
    std::memcpy(data, &stats, stats_size);
    
    trans.set_data_ptr(data);
    trans.set_data_length(stats_size);
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
}

const dtls_timing_config& get_protocol_stack_timing() {
    return g_protocol_stack_timing;
}

} // namespace utils

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls