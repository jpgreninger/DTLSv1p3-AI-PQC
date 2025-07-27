#ifndef DTLS_CHANNELS_H
#define DTLS_CHANNELS_H

#include "dtls_systemc_types.h"
#include <systemc>
#include <queue>
#include <mutex>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * SystemC Channel for DTLS Crypto Operations
 * 
 * Provides a channel for secure communication of cryptographic
 * operations between components with priority queuing and flow control.
 */
SC_MODULE(CryptoOperationChannel) {
public:
    // Channel interface ports  
    sc_export<sc_fifo_in_if<crypto_extension>> crypto_in;
    sc_export<sc_fifo_out_if<crypto_extension>> crypto_out;
    
    // Control signals
    sc_in<bool> enable_crypto_operations;
    sc_in<uint32_t> max_queue_size;
    
    // Status signals
    sc_out<uint32_t> pending_operations;
    sc_out<bool> queue_full;
    sc_out<bool> queue_empty;
    
    // Performance monitoring
    sc_out<double> average_latency_ns;
    sc_out<uint64_t> total_operations_processed;
    
    /**
     * Channel statistics
     */
    struct ChannelStats {
        uint64_t operations_queued{0};
        uint64_t operations_completed{0};
        uint64_t operations_dropped{0};
        uint32_t max_queue_depth{0};
        sc_time total_latency{0, SC_NS};
        sc_time average_latency{0, SC_NS};
        sc_time max_latency{0, SC_NS};
    };
    
    // Constructor
    CryptoOperationChannel(sc_module_name name, uint32_t default_queue_size = 64);
    
    // Channel operations
    bool write(const crypto_transaction& trans);
    bool read(crypto_transaction& trans);
    bool nb_write(const crypto_transaction& trans);
    bool nb_read(crypto_transaction& trans);
    
    // Channel management
    void set_max_queue_size(uint32_t size);
    uint32_t get_queue_size() const;
    bool is_full() const;
    bool is_empty() const;
    
    // Statistics
    ChannelStats get_statistics() const;
    void reset_statistics();

private:
    // Internal FIFO storage
    sc_fifo<crypto_transaction> operation_queue_;
    
    // Channel configuration
    uint32_t max_queue_size_;
    bool operations_enabled_;
    
    // Statistics tracking
    mutable std::mutex stats_mutex_;
    ChannelStats stats_;
    std::map<uint64_t, sc_time> operation_timestamps_;
    
    // SystemC processes
    void channel_monitor_process();
    void statistics_update_process();
    void flow_control_process();
    
    // Internal methods
    void update_latency_statistics(uint64_t transaction_id);
    void check_queue_status();
    
    SC_HAS_PROCESS(CryptoOperationChannel);
};

/**
 * SystemC Channel for DTLS Record Operations
 * 
 * Handles record layer communications with support for
 * different record types and priority handling.
 */
SC_MODULE(RecordOperationChannel) {
public:
    // Channel interface ports
    sc_export<sc_fifo_in_if<record_transaction>> record_in;
    sc_export<sc_fifo_out_if<record_transaction>> record_out;
    
    // Control signals
    sc_in<bool> enable_record_operations;
    sc_in<uint16_t> current_epoch;
    sc_in<bool> connection_id_enabled;
    
    // Status signals
    sc_out<uint32_t> pending_records;
    sc_out<uint64_t> records_processed;
    sc_out<uint32_t> replay_attacks_blocked;
    
    /**
     * Priority levels for record operations
     */
    enum class RecordPriority {
        LOW = 0,
        NORMAL = 1,
        HIGH = 2,
        CRITICAL = 3
    };
    
    /**
     * Channel statistics
     */
    struct RecordChannelStats {
        uint64_t records_queued{0};
        uint64_t records_processed{0};
        uint64_t protection_operations{0};
        uint64_t unprotection_operations{0};
        uint64_t replay_detections{0};
        
        sc_time total_processing_time{0, SC_NS};
        sc_time protection_time{0, SC_NS};
        sc_time unprotection_time{0, SC_NS};
        
        uint32_t max_queue_depth{0};
        double processing_efficiency{0.0};
    };
    
    // Constructor
    RecordOperationChannel(sc_module_name name, uint32_t queue_size = 128);
    
    // Channel operations with priority
    bool write(const record_transaction& trans, RecordPriority priority = RecordPriority::NORMAL);
    bool read(record_transaction& trans);
    bool nb_write(const record_transaction& trans, RecordPriority priority = RecordPriority::NORMAL);
    bool nb_read(record_transaction& trans);
    
    // Priority queue management
    void set_priority_weights(const std::map<RecordPriority, double>& weights);
    RecordPriority get_next_priority() const;
    
    // Channel management
    uint32_t get_queue_size() const;
    uint32_t get_priority_queue_size(RecordPriority priority) const;
    
    // Statistics
    RecordChannelStats get_statistics() const;
    void reset_statistics();

private:
    // Priority queue storage
    std::map<RecordPriority, sc_fifo<record_transaction>*> priority_queues_;
    std::map<RecordPriority, double> priority_weights_;
    
    // Channel configuration
    uint32_t total_queue_size_;
    bool operations_enabled_;
    uint16_t current_epoch_;
    bool connection_id_enabled_;
    
    // Statistics tracking
    mutable std::mutex stats_mutex_;
    RecordChannelStats stats_;
    
    // SystemC processes
    void priority_scheduler_process();
    void epoch_monitor_process();
    void performance_monitor_process();
    
    // Internal methods
    RecordPriority determine_operation_priority(const record_transaction& trans) const;
    void update_processing_statistics(const record_transaction& trans);
    void balance_queue_loads();
    
    SC_HAS_PROCESS(RecordOperationChannel);
};

/**
 * SystemC Channel for DTLS Message Operations
 * 
 * Handles message layer communications including fragmentation,
 * reassembly, and flight management operations.
 */
SC_MODULE(MessageOperationChannel) {
public:
    // Channel interface ports
    sc_export<sc_fifo_in_if<message_transaction>> message_in;
    sc_export<sc_fifo_out_if<message_transaction>> message_out;
    
    // Control signals
    sc_in<bool> enable_message_operations;
    sc_in<uint32_t> max_fragment_size;
    sc_in<bool> reliable_delivery_enabled;
    
    // Status signals
    sc_out<uint32_t> pending_messages;
    sc_out<uint32_t> active_reassemblies;
    sc_out<uint32_t> active_flights;
    
    /**
     * Message operation types with different handling requirements
     */
    enum class MessageOperationType {
        FRAGMENTATION,
        REASSEMBLY,
        FLIGHT_MANAGEMENT,
        RETRANSMISSION
    };
    
    /**
     * Channel statistics
     */
    struct MessageChannelStats {
        uint64_t messages_queued{0};
        uint64_t messages_processed{0};
        uint64_t fragmentation_operations{0};
        uint64_t reassembly_operations{0};
        uint64_t flight_operations{0};
        uint64_t retransmission_operations{0};
        
        uint32_t active_reassemblies{0};
        uint32_t active_flights{0};
        uint32_t max_concurrent_operations{0};
        
        sc_time total_processing_time{0, SC_NS};
        double message_throughput_mps{0.0};
        double reliability_ratio{0.0};
    };
    
    // Constructor
    MessageOperationChannel(sc_module_name name, uint32_t queue_size = 256);
    
    // Channel operations
    bool write(const message_transaction& trans);
    bool read(message_transaction& trans);
    bool nb_write(const message_transaction& trans);
    bool nb_read(message_transaction& trans);
    
    // Specialized message operations
    bool queue_for_fragmentation(const message_transaction& trans);
    bool queue_for_reassembly(const message_transaction& trans);
    bool queue_for_flight_management(const message_transaction& trans);
    
    // Channel management
    void set_operation_priorities(const std::map<MessageOperationType, int>& priorities);
    uint32_t get_operation_queue_size(MessageOperationType type) const;
    
    // Statistics
    MessageChannelStats get_statistics() const;
    void reset_statistics();

private:
    // Operation-specific queues
    std::map<MessageOperationType, sc_fifo<message_transaction>*> operation_queues_;
    std::map<MessageOperationType, int> operation_priorities_;
    
    // Channel configuration
    uint32_t total_queue_size_;
    bool operations_enabled_;
    uint32_t max_fragment_size_;
    bool reliable_delivery_enabled_;
    
    // Statistics tracking
    mutable std::mutex stats_mutex_;
    MessageChannelStats stats_;
    
    // Active operation tracking
    std::atomic<uint32_t> active_reassembly_count_{0};
    std::atomic<uint32_t> active_flight_count_{0};
    
    // SystemC processes
    void message_scheduler_process();
    void operation_monitor_process();
    void throughput_calculation_process();
    
    // Internal methods
    MessageOperationType determine_operation_type(const message_transaction& trans) const;
    void update_operation_statistics(const message_transaction& trans);
    MessageOperationType get_next_operation_type() const;
    
    SC_HAS_PROCESS(MessageOperationChannel);
};

/**
 * SystemC Channel for Transport Layer Operations
 * 
 * Handles network transport communications with network condition
 * simulation and packet loss/delay modeling.
 */
SC_MODULE(TransportChannel) {
public:
    // Channel interface ports
    sc_export<sc_fifo_in_if<transport_transaction>> transport_in;
    sc_export<sc_fifo_out_if<transport_transaction>> transport_out;
    
    // Network condition simulation
    sc_in<double> packet_loss_probability;
    sc_in<sc_time> network_latency;
    sc_in<double> bandwidth_mbps;
    
    // Status signals
    sc_out<uint32_t> packets_in_transit;
    sc_out<uint64_t> packets_transmitted;
    sc_out<uint64_t> packets_dropped;
    sc_out<double> effective_bandwidth_mbps;
    
    /**
     * Network condition parameters
     */
    struct NetworkConditions {
        double packet_loss_probability{0.0};
        sc_time base_latency{50, SC_MS};
        sc_time jitter{10, SC_MS};
        double bandwidth_mbps{100.0};
        uint32_t mtu_size{1500};
        bool congestion_control_enabled{true};
    };
    
    /**
     * Channel statistics
     */
    struct TransportChannelStats {
        uint64_t packets_sent{0};
        uint64_t packets_received{0};
        uint64_t packets_dropped{0};
        uint64_t bytes_transmitted{0};
        
        sc_time total_transmission_time{0, SC_NS};
        sc_time average_latency{0, SC_NS};
        sc_time max_latency{0, SC_NS};
        
        double effective_bandwidth_mbps{0.0};
        double packet_loss_rate{0.0};
        uint32_t max_packets_in_transit{0};
    };
    
    // Constructor
    TransportChannel(sc_module_name name, const NetworkConditions& conditions = NetworkConditions{});
    
    // Channel operations
    bool write(const transport_transaction& trans);
    bool read(transport_transaction& trans);
    bool nb_write(const transport_transaction& trans);
    bool nb_read(transport_transaction& trans);
    
    // Network simulation
    void set_network_conditions(const NetworkConditions& conditions);
    NetworkConditions get_network_conditions() const;
    void simulate_packet_loss(bool enable);
    void simulate_network_congestion(bool enable);
    
    // Statistics
    TransportChannelStats get_statistics() const;
    void reset_statistics();

private:
    // Network simulation state
    NetworkConditions network_conditions_;
    bool packet_loss_simulation_enabled_;
    bool congestion_simulation_enabled_;
    
    // Transport queue with timing
    struct TimedPacket {
        transport_transaction transaction;
        sc_time arrival_time;
        sc_time delivery_time;
        bool dropped;
        
        TimedPacket(const transport_transaction& trans) 
            : transaction(trans), arrival_time(sc_time_stamp()), dropped(false) {}
    };
    
    std::queue<TimedPacket> in_transit_packets_;
    mutable std::mutex transport_mutex_;
    
    // Statistics tracking
    mutable std::mutex stats_mutex_;
    TransportChannelStats stats_;
    
    // SystemC processes
    void packet_delivery_process();
    void network_simulation_process();
    void bandwidth_monitor_process();
    void congestion_control_process();
    
    // Internal methods
    bool should_drop_packet() const;
    sc_time calculate_transmission_delay(size_t packet_size) const;
    sc_time add_network_jitter(sc_time base_delay) const;
    void update_transmission_statistics(const TimedPacket& packet);
    
    SC_HAS_PROCESS(TransportChannel);
};

/**
 * SystemC Interconnect Bus for DTLS Components
 * 
 * Provides a shared communication bus connecting all DTLS TLM components
 * with routing, arbitration, and performance monitoring.
 */
SC_MODULE(DTLSInterconnectBus) {
public:
    // Component connection ports
    sc_export<sc_fifo_in_if<crypto_transaction>> crypto_bus_in;
    sc_export<sc_fifo_out_if<crypto_transaction>> crypto_bus_out;
    sc_export<sc_fifo_in_if<record_transaction>> record_bus_in;
    sc_export<sc_fifo_out_if<record_transaction>> record_bus_out;
    sc_export<sc_fifo_in_if<message_transaction>> message_bus_in;
    sc_export<sc_fifo_out_if<message_transaction>> message_bus_out;
    sc_export<sc_fifo_in_if<transport_transaction>> transport_bus_in;
    sc_export<sc_fifo_out_if<transport_transaction>> transport_bus_out;
    
    // Bus control
    sc_in<bool> bus_enable;
    sc_in<uint32_t> bus_clock_mhz;
    
    // Bus status
    sc_out<uint32_t> total_bus_utilization_percent;
    sc_out<uint64_t> total_transactions;
    sc_out<bool> bus_congestion_detected;
    
    /**
     * Bus configuration parameters
     */
    struct BusConfig {
        uint32_t max_concurrent_transactions{16};
        sc_time arbitration_delay{1, SC_NS};
        sc_time bus_cycle_time{10, SC_NS};
        bool priority_arbitration_enabled{true};
        uint32_t congestion_threshold_percent{80};
    };
    
    /**
     * Bus statistics
     */
    struct BusStats {
        uint64_t total_transactions{0};
        uint64_t crypto_transactions{0};
        uint64_t record_transactions{0};
        uint64_t message_transactions{0};
        uint64_t transport_transactions{0};
        
        sc_time total_bus_time{0, SC_NS};
        sc_time arbitration_time{0, SC_NS};
        
        uint32_t max_concurrent_transactions{0};
        double average_utilization_percent{0.0};
        uint32_t congestion_events{0};
    };
    
    // Constructor
    DTLSInterconnectBus(sc_module_name name, const BusConfig& config = BusConfig{});
    
    // Bus operations
    bool route_transaction(const crypto_transaction& trans);
    bool route_transaction(const record_transaction& trans);
    bool route_transaction(const message_transaction& trans);
    bool route_transaction(const transport_transaction& trans);
    
    // Bus management
    void set_bus_configuration(const BusConfig& config);
    BusConfig get_bus_configuration() const;
    void enable_priority_arbitration(bool enable);
    
    // Statistics and monitoring
    BusStats get_statistics() const;
    void reset_statistics();
    bool is_congested() const;

private:
    // Bus configuration
    BusConfig bus_config_;
    bool bus_enabled_;
    uint32_t bus_clock_mhz_;
    
    // Internal channels
    CryptoOperationChannel crypto_channel_;
    RecordOperationChannel record_channel_;
    MessageOperationChannel message_channel_;
    TransportChannel transport_channel_;
    
    // Bus arbitration state
    std::atomic<uint32_t> active_transactions_{0};
    std::queue<std::function<void()>> pending_transactions_;
    mutable std::mutex arbitration_mutex_;
    
    // Statistics tracking
    mutable std::mutex stats_mutex_;
    BusStats stats_;
    
    // SystemC processes
    void bus_arbitration_process();
    void utilization_monitor_process();
    void congestion_detection_process();
    void performance_optimization_process();
    
    // Internal methods
    void process_pending_transactions();
    void update_bus_statistics();
    bool check_congestion_condition() const;
    void optimize_bus_performance();
    
    SC_HAS_PROCESS(DTLSInterconnectBus);
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_CHANNELS_H