#ifndef MESSAGE_LAYER_TLM_H
#define MESSAGE_LAYER_TLM_H

#include "dtls_systemc_types.h"
#include "record_layer_tlm.h"
#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_target_socket.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <mutex>
#include <queue>
#include <map>

// Forward declarations for DTLS protocol types
namespace dtls::v13::protocol {
    struct MessageFragment;
    class HandshakeMessage;
    enum class FlightType : uint32_t;
}

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * SystemC TLM Model for Message Fragment Reassembler
 * 
 * Handles collection and reassembly of fragmented DTLS handshake messages
 * with support for out-of-order delivery and gap detection.
 */
SC_MODULE(MessageReassemblerTLM) {
public:
    // TLM target socket for fragment processing
    tlm_utils::simple_target_socket<MessageReassemblerTLM> target_socket;
    
    // Control ports
    sc_in<bool> enable_reassembly;
    sc_in<uint32_t> reassembly_timeout_ms;
    
    // Status ports
    sc_out<uint16_t> active_reassemblies;
    sc_out<uint32_t> completed_messages;
    sc_out<uint32_t> timeout_count;
    
    /**
     * Reassembly statistics
     */
    struct ReassemblyStats {
        uint64_t total_fragments_received{0};
        uint64_t duplicate_fragments{0};
        uint64_t out_of_order_fragments{0};
        uint64_t messages_completed{0};
        uint64_t messages_timed_out{0};
        uint32_t active_reassemblies{0};
        uint32_t max_concurrent_reassemblies{0};
        
        sc_time total_reassembly_time{0, SC_NS};
        sc_time average_reassembly_time{0, SC_NS};
        sc_time max_reassembly_time{0, SC_NS};
        
        size_t total_bytes_reassembled{0};
        double reassembly_efficiency{0.0}; // successful/total ratio
    };
    
    // Constructor
    MessageReassemblerTLM(sc_module_name name);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                      tlm::tlm_phase& phase, 
                                      sc_time& delay);
    
    // Reassembly operations (simplified for SystemC modeling)
    bool add_fragment(uint16_t message_seq, uint32_t fragment_offset, uint32_t fragment_length);
    bool is_message_complete(uint16_t message_seq) const;
    bool get_completed_message(uint16_t message_seq);
    
    // Configuration and monitoring
    void set_reassembly_timeout(sc_time timeout);
    ReassemblyStats get_statistics() const;
    void reset_statistics();

private:
    // Fragment storage for active reassemblies (simplified for SystemC modeling)
    struct FragmentInfo {
        sc_time arrival_time;
        bool processed;
        
        // Simplified SystemC modeling - store only essential data
        uint32_t fragment_offset;
        uint32_t fragment_length;
        
        FragmentInfo(uint32_t offset, uint32_t length) 
            : arrival_time(sc_time_stamp()), processed(false), fragment_offset(offset), fragment_length(length) {}
    };
    
    struct MessageReassemblyState {
        uint32_t total_length{0};
        std::vector<FragmentInfo> fragments;
        sc_time start_time;
        sc_time last_fragment_time;
        bool complete{false};
        
        MessageReassemblyState() : start_time(sc_time_stamp()) {}
    };
    
    // Active reassemblies indexed by message sequence number
    std::map<uint16_t, MessageReassemblyState> active_reassemblies_;
    mutable std::mutex reassembly_mutex_;
    
    // Configuration
    sc_time reassembly_timeout_{30, SC_SEC};
    bool reassembly_enabled_{true};
    
    // Statistics
    mutable std::mutex stats_mutex_;
    ReassemblyStats stats_;
    
    // SystemC processes
    void reassembly_timeout_process();
    void statistics_update_process();
    void configuration_monitor_process();
    
    // Internal methods (simplified for SystemC modeling)
    bool process_fragment(uint16_t message_seq, uint32_t offset, uint32_t length);
    bool check_reassembly_complete(uint16_t message_seq) const;
    bool assemble_message(uint16_t message_seq); // Simplified for SystemC - returns success/failure
    void cleanup_timed_out_reassemblies();
    void update_statistics(const MessageReassemblyState& state, bool completed);
    
    SC_HAS_PROCESS(MessageReassemblerTLM);
};

/**
 * SystemC TLM Model for Message Fragmenter
 * 
 * Handles fragmentation of large handshake messages for transmission
 * over networks with MTU limitations.
 */
SC_MODULE(MessageFragmenterTLM) {
public:
    // TLM target socket for fragmentation requests
    tlm_utils::simple_target_socket<MessageFragmenterTLM> target_socket;
    
    // Configuration ports
    sc_in<uint32_t> max_fragment_size;
    sc_in<bool> enable_fragmentation;
    
    // Status ports
    sc_out<uint32_t> messages_fragmented;
    sc_out<uint32_t> total_fragments_created;
    sc_out<double> average_fragments_per_message;
    
    /**
     * Fragmentation statistics
     */
    struct FragmentationStats {
        uint64_t messages_processed{0};
        uint64_t messages_fragmented{0};
        uint64_t total_fragments_created{0};
        uint64_t bytes_fragmented{0};
        
        double average_fragments_per_message{0.0};
        double fragmentation_overhead_ratio{0.0};
        
        sc_time total_fragmentation_time{0, SC_NS};
        sc_time average_fragmentation_time{0, SC_NS};
        
        uint32_t max_fragments_per_message{0};
        size_t largest_message_size{0};
    };
    
    // Constructor
    MessageFragmenterTLM(sc_module_name name, uint32_t default_max_fragment_size = 1200);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Fragmentation operations (simplified for SystemC modeling)
    uint32_t fragment_message(uint32_t message_length, uint16_t message_seq);
    
    // Configuration and monitoring
    void set_max_fragment_size(uint32_t size);
    FragmentationStats get_statistics() const;
    void reset_statistics();

private:
    // Configuration
    uint32_t max_fragment_size_;
    bool fragmentation_enabled_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    FragmentationStats stats_;
    
    // SystemC processes
    void performance_monitor_process();
    void configuration_monitor_process();
    
    // Internal methods (simplified for SystemC modeling)
    uint32_t perform_fragmentation(uint32_t message_length, uint16_t message_seq);
    void update_statistics(size_t message_size, size_t fragment_count, sc_time processing_time);
    
    SC_HAS_PROCESS(MessageFragmenterTLM);
};

/**
 * SystemC TLM Model for Handshake Flight Manager
 * 
 * Manages grouping of related handshake messages into flights
 * for reliable delivery with retransmission support.
 */
SC_MODULE(FlightManagerTLM) {
public:
    // TLM target socket for flight operations
    tlm_utils::simple_target_socket<FlightManagerTLM> target_socket;
    
    // Control ports
    sc_in<bool> enable_retransmission;
    sc_in<uint32_t> retransmission_timeout_ms;
    sc_in<uint8_t> max_retransmissions;
    
    // Status ports
    sc_out<uint8_t> active_flights_count;
    sc_out<uint32_t> flights_completed;
    sc_out<uint32_t> total_retransmissions;
    
    /**
     * Flight management statistics
     */
    struct FlightStats {
        uint32_t flights_created{0};
        uint32_t flights_transmitted{0};
        uint32_t flights_acknowledged{0};
        uint32_t flights_failed{0};
        uint32_t total_retransmissions{0};
        
        uint8_t active_flights{0};
        uint8_t max_concurrent_flights{0};
        
        sc_time total_flight_time{0, SC_NS};
        sc_time average_flight_time{0, SC_NS};
        sc_time average_rtt{0, SC_NS};
        
        double flight_success_ratio{0.0};
        double average_retransmissions_per_flight{0.0};
    };
    
    // Constructor
    FlightManagerTLM(sc_module_name name);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                      tlm::tlm_phase& phase, 
                                      sc_time& delay);
    
    // Flight operations (simplified for SystemC modeling)
    bool create_flight(uint32_t flight_type);
    bool add_message_to_flight(uint32_t flight_type, uint32_t message_length);
    bool transmit_flight(uint32_t flight_type);
    bool acknowledge_flight(uint32_t flight_type);
    
    // Configuration and monitoring
    void set_retransmission_params(sc_time timeout, uint8_t max_retries);
    FlightStats get_statistics() const;
    void reset_statistics();

private:
    // Flight state management (simplified for SystemC modeling)
    struct FlightState {
        uint32_t type;
        uint32_t message_count{0};
        sc_time creation_time;
        sc_time last_transmission_time;
        uint8_t retransmission_count{0};
        bool acknowledged{false};
        bool failed{false};
        
        FlightState(uint32_t t) 
            : type(t), creation_time(sc_time_stamp()) {}
    };
    
    std::map<uint32_t, FlightState> active_flights_;
    mutable std::mutex flights_mutex_;
    
    // Configuration
    sc_time retransmission_timeout_{1, SC_SEC};
    uint8_t max_retransmissions_{3};
    bool retransmission_enabled_{true};
    
    // Statistics
    mutable std::mutex stats_mutex_;
    FlightStats stats_;
    
    // SystemC processes
    void retransmission_timer_process();
    void flight_monitoring_process();
    void configuration_monitor_process();
    
    // Internal methods
    bool should_retransmit_flight(const FlightState& flight) const;
    void perform_flight_retransmission(uint32_t type);
    void cleanup_completed_flights();
    void update_flight_statistics(const FlightState& flight, bool completed);
    
    SC_HAS_PROCESS(FlightManagerTLM);
};

/**
 * SystemC TLM Model for Message Layer
 * 
 * Top-level message layer that orchestrates fragmentation, reassembly,
 * and flight management for reliable DTLS handshake message delivery.
 */
SC_MODULE(MessageLayerTLM) {
public:
    // External TLM interfaces
    tlm_utils::simple_target_socket<MessageLayerTLM> target_socket;
    tlm_utils::simple_initiator_socket<MessageLayerTLM> record_layer_socket;
    
    // Internal component interfaces
    tlm_utils::simple_initiator_socket<MessageLayerTLM> fragmenter_socket;
    tlm_utils::simple_initiator_socket<MessageLayerTLM> reassembler_socket;
    tlm_utils::simple_initiator_socket<MessageLayerTLM> flight_mgr_socket;
    
    // Configuration ports
    sc_in<uint32_t> max_fragment_size;
    sc_in<uint32_t> reassembly_timeout_ms;
    sc_in<bool> enable_reliable_delivery;
    
    // Status ports
    sc_out<uint64_t> messages_sent;
    sc_out<uint64_t> messages_received;
    sc_out<uint32_t> active_operations;
    sc_out<double> message_throughput_mps; // messages per second
    
    /**
     * Message layer performance statistics
     */
    struct MessageLayerStats {
        uint64_t handshake_messages_sent{0};
        uint64_t handshake_messages_received{0};
        uint64_t fragments_sent{0};
        uint64_t fragments_received{0};
        uint64_t messages_reassembled{0};
        uint64_t flights_transmitted{0};
        uint64_t retransmissions_performed{0};
        uint64_t reassembly_timeouts{0};
        
        uint32_t active_send_operations{0};
        uint32_t active_receive_operations{0};
        
        sc_time total_send_time{0, SC_NS};
        sc_time total_receive_time{0, SC_NS};
        sc_time average_send_time{0, SC_NS};
        sc_time average_receive_time{0, SC_NS};
        
        double message_throughput_mps{0.0};
        double fragment_overhead_ratio{0.0};
        double reliability_effectiveness{0.0};
    };
    
    // Constructor
    MessageLayerTLM(sc_module_name name);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                      tlm::tlm_phase& phase, 
                                      sc_time& delay);
    
    // Message operations (simplified for SystemC modeling)
    bool send_handshake_message(uint32_t message_length);
    bool send_handshake_flight(uint32_t message_count, uint32_t flight_type);
    uint32_t process_incoming_fragments(uint32_t fragment_count);
    
    // Configuration and monitoring
    void set_max_fragment_size(uint32_t size);
    void set_reassembly_timeout(sc_time timeout);
    void enable_reliable_delivery_mode(bool enable);
    
    MessageLayerStats get_statistics() const;
    void reset_statistics();

private:
    // Configuration
    uint32_t max_fragment_size_{1200};
    sc_time reassembly_timeout_{30, SC_SEC};
    bool reliable_delivery_enabled_{true};
    
    // Statistics
    mutable std::mutex stats_mutex_;
    MessageLayerStats stats_;
    
    // Internal state
    std::atomic<uint32_t> active_send_operations_{0};
    std::atomic<uint32_t> active_receive_operations_{0};
    std::atomic<uint16_t> next_message_sequence_{0};
    
    // SystemC processes
    void message_processing_thread();
    void performance_monitoring_process();
    void throughput_calculation_process();
    void configuration_monitor_process();
    
    // Internal message handling
    bool handle_send_message(tlm::tlm_generic_payload& trans);
    bool handle_receive_fragments(tlm::tlm_generic_payload& trans);
    bool handle_flight_operation(tlm::tlm_generic_payload& trans);
    
    // Component coordination (simplified for SystemC modeling)
    bool fragment_and_send_message(uint32_t message_length, uint16_t seq);
    bool reassemble_incoming_message(uint32_t fragment_count);
    bool manage_flight_transmission(uint32_t message_count, uint32_t flight_type);
    
    // Statistics updates
    void update_send_statistics(size_t message_size, sc_time processing_time, bool success);
    void update_receive_statistics(size_t fragments_count, sc_time processing_time, bool success);
    void calculate_performance_metrics();
    
    SC_HAS_PROCESS(MessageLayerTLM);
};

/**
 * SystemC TLM Model for integrated Message Layer System
 * 
 * Complete message layer system integrating all components with
 * system-level coordination and monitoring.
 */
SC_MODULE(MessageLayerSystemTLM) {
public:
    // External interface
    tlm_utils::simple_target_socket<MessageLayerSystemTLM> external_socket;
    
    // Component instances
    MessageLayerTLM message_layer;
    MessageFragmenterTLM message_fragmenter;
    MessageReassemblerTLM message_reassembler;
    FlightManagerTLM flight_manager;
    
    // System-level control
    sc_in<bool> system_enable;
    sc_in<bool> system_reset;
    
    // System-level status
    sc_out<bool> system_ready;
    sc_out<uint32_t> system_load_percentage;
    sc_out<double> overall_efficiency;
    
    /**
     * System-level statistics
     */
    struct SystemStats {
        uint64_t total_system_operations{0};
        uint64_t successful_operations{0};
        uint64_t failed_operations{0};
        
        sc_time system_uptime{0, SC_NS};
        sc_time total_processing_time{0, SC_NS};
        
        double system_efficiency{0.0};
        double component_utilization{0.0};
        uint32_t system_load_percentage{0};
    };
    
    // Constructor
    MessageLayerSystemTLM(sc_module_name name);
    
    // TLM interface
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // System operations
    void initialize_system();
    void reset_system();
    void shutdown_system();
    
    // System monitoring
    SystemStats get_system_statistics() const;
    bool is_system_ready() const;
    uint32_t get_system_load() const;

private:
    // System state
    bool system_ready_;
    bool system_enabled_;
    sc_time system_start_time_;
    
    // Statistics
    mutable std::mutex system_stats_mutex_;
    SystemStats system_stats_;
    
    // SystemC processes
    void system_control_process();
    void system_monitoring_process();
    void load_balancing_process();
    
    // Internal methods
    void update_system_statistics();
    void calculate_system_efficiency();
    uint32_t calculate_system_load();
    
    SC_HAS_PROCESS(MessageLayerSystemTLM);
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // MESSAGE_LAYER_TLM_H