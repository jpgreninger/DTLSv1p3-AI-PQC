#ifndef DTLS_PROTOCOL_STACK_H
#define DTLS_PROTOCOL_STACK_H

#include "dtls_systemc_types.h"
#include "record_layer_tlm.h"
#include "message_layer_tlm.h"
#include "crypto_provider_tlm.h"
#include "dtls_channels.h"
#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_target_socket.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <memory>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * Main DTLS v1.3 Protocol Stack SystemC Module
 * 
 * This is the top-level SystemC module that integrates all DTLS v1.3
 * protocol layers including record layer, message layer, crypto provider,
 * and transport interfaces. It provides TLM-2.0 compliant interfaces
 * for integration with larger system models.
 * 
 * Features:
 * - Complete DTLS v1.3 protocol stack simulation
 * - TLM-2.0 socket interfaces for system integration
 * - Comprehensive timing and performance modeling
 * - Hardware acceleration simulation
 * - Connection lifecycle management
 * - Performance monitoring and analysis
 */
SC_MODULE(dtls_protocol_stack) {
public:
    // TLM-2.0 Interface Sockets
    tlm_utils::simple_target_socket<dtls_protocol_stack> 
        application_target_socket;
    tlm_utils::simple_initiator_socket<dtls_protocol_stack> 
        network_initiator_socket;
    
    // Configuration ports
    sc_in<bool> enable_stack;
    sc_in<bool> reset_stack;
    sc_in<uint32_t> max_connections;
    sc_in<bool> hardware_acceleration_enabled;
    sc_in<uint16_t> mtu_size;
    
    // Status and monitoring ports
    sc_out<uint32_t> active_connections;
    sc_out<uint64_t> total_bytes_processed;
    sc_out<double> average_throughput_mbps;
    sc_out<sc_time> average_handshake_time;
    sc_out<bool> stack_operational;
    
    // Performance monitoring ports
    sc_out<uint32_t> crypto_queue_depth;
    sc_out<uint32_t> record_queue_depth;
    sc_out<uint32_t> message_queue_depth;
    sc_out<double> cpu_utilization_percent;
    sc_out<uint64_t> memory_usage_bytes;
    
    // SystemC events for coordination
    sc_event handshake_completed;
    sc_event connection_established;
    sc_event connection_terminated;
    sc_event error_detected;
    sc_event performance_threshold_exceeded;

    /**
     * Protocol stack statistics
     */
    struct ProtocolStackStats {
        // Connection statistics
        uint32_t total_connections_created{0};
        uint32_t active_connections{0};
        uint32_t successful_handshakes{0};
        uint32_t failed_handshakes{0};
        uint32_t connection_migrations{0};
        
        // Performance statistics  
        uint64_t total_application_bytes{0};
        uint64_t total_network_bytes{0};
        uint64_t protocol_overhead_bytes{0};
        double overhead_percentage{0.0};
        
        // Timing statistics
        sc_time total_handshake_time{0, SC_NS};
        sc_time average_handshake_time{0, SC_NS};
        sc_time min_handshake_time{0, SC_NS};
        sc_time max_handshake_time{0, SC_NS};
        
        sc_time total_data_processing_time{0, SC_NS};
        sc_time average_data_processing_time{0, SC_NS};
        
        // Resource utilization
        uint64_t peak_memory_usage{0};
        uint64_t current_memory_usage{0};
        double peak_cpu_utilization{0.0};
        double current_cpu_utilization{0.0};
        
        // Error statistics
        uint32_t protocol_violations{0};
        uint32_t crypto_failures{0};
        uint32_t network_errors{0};
        uint32_t timeout_events{0};
        
        void reset() {
            total_connections_created = 0;
            active_connections = 0;
            successful_handshakes = 0;
            failed_handshakes = 0;
            connection_migrations = 0;
            total_application_bytes = 0;
            total_network_bytes = 0;
            protocol_overhead_bytes = 0;
            overhead_percentage = 0.0;
            total_handshake_time = sc_time(0, SC_NS);
            average_handshake_time = sc_time(0, SC_NS);
            min_handshake_time = sc_time(0, SC_NS);
            max_handshake_time = sc_time(0, SC_NS);
            total_data_processing_time = sc_time(0, SC_NS);
            average_data_processing_time = sc_time(0, SC_NS);
            peak_memory_usage = 0;
            current_memory_usage = 0;
            peak_cpu_utilization = 0.0;
            current_cpu_utilization = 0.0;
            protocol_violations = 0;
            crypto_failures = 0;
            network_errors = 0;
            timeout_events = 0;
        }
    };

private:
    // Protocol layer components
    std::unique_ptr<RecordLayerTLM> record_layer;
    std::unique_ptr<MessageLayerTLM> message_layer;
    std::unique_ptr<CryptoProviderTLM> crypto_provider;
    std::unique_ptr<HardwareAcceleratedCryptoTLM> hw_crypto_provider;
    std::unique_ptr<CryptoManagerTLM> crypto_manager;
    
    // Internal communication channels
    std::unique_ptr<CryptoOperationChannel> crypto_channel;
    std::unique_ptr<RecordOperationChannel> record_channel;
    std::unique_ptr<MessageOperationChannel> message_channel;
    std::unique_ptr<TransportChannel> transport_channel;
    std::unique_ptr<DTLSInterconnectBus> interconnect_bus;
    
    // Connection management
    struct ConnectionContext {
        uint32_t connection_id;
        sc_time creation_time;
        sc_time last_activity;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        bool handshake_complete;
        enum class State {
            INITIALIZING,
            HANDSHAKING,
            ESTABLISHED,
            CLOSING,
            CLOSED,
            ERROR
        } state;
    };
    
    std::map<uint32_t, std::unique_ptr<ConnectionContext>> active_connections_map;
    
    // Statistics and monitoring
    ProtocolStackStats stats;
    mutable std::mutex stats_mutex;
    
    // Performance monitoring
    sc_time last_performance_update;
    uint64_t bytes_processed_since_last_update{0};
    sc_time processing_time_since_last_update{0, SC_NS};
    
    // Configuration
    bool stack_enabled{true};
    uint32_t max_connections_limit{1000};
    bool use_hardware_acceleration{false};
    uint16_t current_mtu{1500};

public:
    // Constructor
    SC_CTOR(dtls_protocol_stack);
    
    // SystemC processes
    void application_interface_process();
    void network_interface_process();
    void performance_monitoring_process();
    void connection_management_process();
    void error_handling_process();
    
    // TLM transport methods
    void b_transport_application(tlm::tlm_generic_payload& trans, sc_time& delay);
    void b_transport_network(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Configuration methods
    void configure_stack(uint32_t max_conn, bool hw_accel, uint16_t mtu);
    void enable_stack(bool enable);
    void reset_stack();
    
    // Connection management methods
    uint32_t create_connection();
    bool destroy_connection(uint32_t connection_id);
    ConnectionContext* get_connection(uint32_t connection_id);
    
    // Performance monitoring methods
    void update_performance_metrics();
    ProtocolStackStats get_statistics() const;
    void reset_statistics();
    
    // Utility methods
    void log_event(const std::string& event, const std::string& details = "");
    void handle_protocol_error(uint32_t connection_id, const std::string& error);
    
private:
    // Internal initialization methods
    void initialize_components();
    void connect_internal_channels();
    void configure_timing_models();
    
    // Internal processing methods
    void process_application_data(tlm::tlm_generic_payload& trans, sc_time& delay);
    void process_network_data(tlm::tlm_generic_payload& trans, sc_time& delay);
    void route_crypto_operation(tlm::tlm_generic_payload& trans, sc_time& delay);
    void route_record_operation(tlm::tlm_generic_payload& trans, sc_time& delay);
    void route_message_operation(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Performance calculation methods
    double calculate_throughput();
    double calculate_cpu_utilization();
    uint64_t calculate_memory_usage();
    double calculate_overhead_percentage();
    
    // Connection state management
    void update_connection_state(uint32_t connection_id, ConnectionContext::State new_state);
    void cleanup_inactive_connections();
    bool validate_connection_limits();
};

// Global timing configuration for the protocol stack
extern dtls_timing_config g_protocol_stack_timing;

// Utility functions for protocol stack management
namespace utils {
    /**
     * Calculate processing time based on operation type and data size
     */
    sc_time calculate_protocol_processing_time(const std::string& operation, size_t data_size);
    
    /**
     * Generate unique connection ID
     */
    uint32_t generate_connection_id();
    
    /**
     * Convert protocol stack result to TLM transaction
     */
    void convert_result_to_transaction(const ProtocolStackStats& stats,
                                     tlm::tlm_generic_payload& trans);
    
    /**
     * Get protocol stack timing configuration
     */
    const dtls_timing_config& get_protocol_stack_timing();
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_STACK_H