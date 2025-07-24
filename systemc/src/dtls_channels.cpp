#include "dtls_channels.h"
#include <random>
#include <algorithm>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * Crypto Operation Channel Implementation
 */
CryptoOperationChannel::CryptoOperationChannel(sc_module_name name, uint32_t default_queue_size)
    : sc_module(name)
    , crypto_in("crypto_in")
    , crypto_out("crypto_out")
    , enable_crypto_operations("enable_crypto_operations")
    , max_queue_size("max_queue_size")
    , pending_operations("pending_operations")
    , queue_full("queue_full")
    , queue_empty("queue_empty")
    , average_latency_ns("average_latency_ns")
    , total_operations_processed("total_operations_processed")
    , operation_queue_("operation_queue", default_queue_size)
    , max_queue_size_(default_queue_size)
    , operations_enabled_(true)
{
    // Bind exports to internal FIFO
    crypto_in.bind(operation_queue_);
    crypto_out.bind(operation_queue_);
    
    SC_THREAD(channel_monitor_process);
    SC_THREAD(statistics_update_process);
    SC_THREAD(flow_control_process);
    
    reset_statistics();
}

bool CryptoOperationChannel::write(const crypto_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Record timestamp for latency calculation
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        operation_timestamps_[trans.transaction_id] = sc_time_stamp();
        stats_.operations_queued++;
    }
    
    bool success = operation_queue_.write(trans);
    
    if (!success) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.operations_dropped++;
    }
    
    return success;
}

bool CryptoOperationChannel::read(crypto_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    trans = operation_queue_.read();
    
    // Update latency statistics
    update_latency_statistics(trans.transaction_id);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.operations_completed++;
    
    return true;
}

bool CryptoOperationChannel::nb_write(const crypto_transaction& trans) {
    if (!operations_enabled_ || operation_queue_.num_free() == 0) {
        return false;
    }
    
    return write(trans);
}

bool CryptoOperationChannel::nb_read(crypto_transaction& trans) {
    if (!operations_enabled_ || operation_queue_.num_available() == 0) {
        return false;
    }
    
    return read(trans);
}

void CryptoOperationChannel::update_latency_statistics(uint64_t transaction_id) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto it = operation_timestamps_.find(transaction_id);
    if (it != operation_timestamps_.end()) {
        sc_time latency = sc_time_stamp() - it->second;
        stats_.total_latency += latency;
        
        if (latency > stats_.max_latency) {
            stats_.max_latency = latency;
        }
        
        if (stats_.operations_completed > 0) {
            stats_.average_latency = sc_time(
                stats_.total_latency.to_double() / stats_.operations_completed,
                stats_.total_latency.get_time_unit()
            );
        }
        
        operation_timestamps_.erase(it);
    }
}

void CryptoOperationChannel::channel_monitor_process() {
    while (true) {
        wait(1, SC_MS);
        check_queue_status();
    }
}

void CryptoOperationChannel::check_queue_status() {
    uint32_t current_size = operation_queue_.num_available();
    uint32_t free_space = operation_queue_.num_free();
    
    // Update queue depth statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (current_size > stats_.max_queue_depth) {
            stats_.max_queue_depth = current_size;
        }
    }
    
    // Update status outputs
    pending_operations.write(current_size);
    queue_full.write(free_space == 0);
    queue_empty.write(current_size == 0);
}

void CryptoOperationChannel::statistics_update_process() {
    while (true) {
        wait(1, SC_SEC);
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Update output ports
        average_latency_ns.write(stats_.average_latency.to_double() * 1e9 / SC_NS);
        total_operations_processed.write(stats_.operations_completed);
    }
}

void CryptoOperationChannel::flow_control_process() {
    while (true) {
        wait(enable_crypto_operations.value_changed_event() | max_queue_size.value_changed_event());
        
        operations_enabled_ = enable_crypto_operations.read();
        
        uint32_t new_size = max_queue_size.read();
        if (new_size > 0 && new_size != max_queue_size_) {
            set_max_queue_size(new_size);
        }
    }
}

void CryptoOperationChannel::set_max_queue_size(uint32_t size) {
    max_queue_size_ = size;
    // Note: sc_fifo size cannot be changed after construction
    // In a real implementation, would need to recreate the FIFO
}

CryptoOperationChannel::ChannelStats CryptoOperationChannel::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void CryptoOperationChannel::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = ChannelStats{};
    operation_timestamps_.clear();
}

/**
 * Record Operation Channel Implementation
 */
RecordOperationChannel::RecordOperationChannel(sc_module_name name, uint32_t queue_size)
    : sc_module(name)
    , record_in("record_in")
    , record_out("record_out")
    , enable_record_operations("enable_record_operations")
    , current_epoch("current_epoch")
    , connection_id_enabled("connection_id_enabled")
    , pending_records("pending_records")
    , records_processed("records_processed")
    , replay_attacks_blocked("replay_attacks_blocked")
    , total_queue_size_(queue_size)
    , operations_enabled_(true)
    , current_epoch_(0)
    , connection_id_enabled_(false)
{
    // Create priority queues
    uint32_t queue_per_priority = queue_size / 4;
    priority_queues_[RecordPriority::CRITICAL] = new sc_fifo<record_transaction>(queue_per_priority);
    priority_queues_[RecordPriority::HIGH] = new sc_fifo<record_transaction>(queue_per_priority);
    priority_queues_[RecordPriority::NORMAL] = new sc_fifo<record_transaction>(queue_per_priority);
    priority_queues_[RecordPriority::LOW] = new sc_fifo<record_transaction>(queue_per_priority);
    
    // Set default priority weights
    priority_weights_[RecordPriority::CRITICAL] = 1.0;
    priority_weights_[RecordPriority::HIGH] = 0.7;
    priority_weights_[RecordPriority::NORMAL] = 0.4;
    priority_weights_[RecordPriority::LOW] = 0.1;
    
    SC_THREAD(priority_scheduler_process);
    SC_THREAD(epoch_monitor_process);
    SC_THREAD(performance_monitor_process);
    
    reset_statistics();
}

bool RecordOperationChannel::write(const record_transaction& trans, RecordPriority priority) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Determine priority if not specified
    if (priority == RecordPriority::NORMAL) {
        priority = determine_operation_priority(trans);
    }
    
    auto queue_it = priority_queues_.find(priority);
    if (queue_it == priority_queues_.end()) {
        return false;
    }
    
    bool success = queue_it->second->nb_write(trans);
    
    if (success) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.records_queued++;
    }
    
    return success;
}

bool RecordOperationChannel::read(record_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Find next priority level with available data
    RecordPriority next_priority = get_next_priority();
    
    auto queue_it = priority_queues_.find(next_priority);
    if (queue_it == priority_queues_.end()) {
        return false;
    }
    
    if (queue_it->second->num_available() == 0) {
        return false;
    }
    
    trans = queue_it->second->read();
    
    // Update statistics
    update_processing_statistics(trans);
    
    return true;
}

RecordOperationChannel::RecordPriority RecordOperationChannel::determine_operation_priority(
    const record_transaction& trans) const {
    
    switch (trans.operation) {
        case record_transaction::ANTI_REPLAY_CHECK:
            return RecordPriority::HIGH; // Anti-replay is security critical
        case record_transaction::PROTECT_RECORD:
            return RecordPriority::NORMAL;
        case record_transaction::UNPROTECT_RECORD:
            return RecordPriority::NORMAL;
        case record_transaction::EPOCH_ADVANCE:
            return RecordPriority::CRITICAL; // Epoch changes are critical
        case record_transaction::SEQUENCE_NUMBER_GEN:
            return RecordPriority::HIGH; // Sequence numbers are important for ordering
        default:
            return RecordPriority::LOW;
    }
}

RecordOperationChannel::RecordPriority RecordOperationChannel::get_next_priority() const {
    // Weighted priority selection
    static std::random_device rd;
    static std::mt19937 gen(rd());
    
    // Check critical first
    if (priority_queues_.at(RecordPriority::CRITICAL)->num_available() > 0) {
        return RecordPriority::CRITICAL;
    }
    
    // Weighted selection for other priorities
    std::vector<std::pair<RecordPriority, double>> weighted_priorities;
    for (const auto& [priority, weight] : priority_weights_) {
        if (priority != RecordPriority::CRITICAL && 
            priority_queues_.at(priority)->num_available() > 0) {
            weighted_priorities.push_back({priority, weight});
        }
    }
    
    if (weighted_priorities.empty()) {
        return RecordPriority::LOW; // Fallback
    }
    
    // Simple weighted selection
    std::uniform_real_distribution<> dis(0.0, 1.0);
    double random_value = dis(gen);
    
    for (const auto& [priority, weight] : weighted_priorities) {
        if (random_value <= weight) {
            return priority;
        }
    }
    
    return weighted_priorities.front().first;
}

void RecordOperationChannel::update_processing_statistics(const record_transaction& trans) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.records_processed++;
    stats_.total_processing_time += trans.processing_time;
    
    switch (trans.operation) {
        case record_transaction::PROTECT_RECORD:
            stats_.protection_operations++;
            stats_.protection_time += trans.processing_time;
            break;
        case record_transaction::UNPROTECT_RECORD:
            stats_.unprotection_operations++;
            stats_.unprotection_time += trans.processing_time;
            break;
        case record_transaction::ANTI_REPLAY_CHECK:
            if (trans.replay_detected) {
                stats_.replay_detections++;
            }
            break;
    }
    
    // Calculate processing efficiency
    uint64_t total_operations = stats_.protection_operations + stats_.unprotection_operations;
    if (total_operations > 0) {
        stats_.processing_efficiency = static_cast<double>(stats_.records_processed) / total_operations;
    }
}

void RecordOperationChannel::priority_scheduler_process() {
    while (true) {
        wait(1, SC_MS);
        balance_queue_loads();
    }
}

void RecordOperationChannel::balance_queue_loads() {
    // Monitor queue levels and adjust priorities if needed
    uint32_t total_pending = 0;
    uint32_t max_depth = 0;
    
    for (const auto& [priority, queue] : priority_queues_) {
        uint32_t depth = queue->num_available();
        total_pending += depth;
        if (depth > max_depth) {
            max_depth = depth;
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (max_depth > stats_.max_queue_depth) {
            stats_.max_queue_depth = max_depth;
        }
    }
    
    // Update status outputs
    pending_records.write(total_pending);
    records_processed.write(stats_.records_processed);
    replay_attacks_blocked.write(static_cast<uint32_t>(stats_.replay_detections));
}

void RecordOperationChannel::epoch_monitor_process() {
    while (true) {
        wait(current_epoch.value_changed_event() | 
             connection_id_enabled.value_changed_event() |
             enable_record_operations.value_changed_event());
        
        operations_enabled_ = enable_record_operations.read();
        current_epoch_ = current_epoch.read();
        connection_id_enabled_ = connection_id_enabled.read();
    }
}

void RecordOperationChannel::performance_monitor_process() {
    while (true) {
        wait(1, SC_SEC);
        // Additional performance monitoring can be added here
    }
}

RecordOperationChannel::RecordChannelStats RecordOperationChannel::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void RecordOperationChannel::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = RecordChannelStats{};
}

/**
 * Transport Channel Implementation
 */
TransportChannel::TransportChannel(sc_module_name name, const NetworkConditions& conditions)
    : sc_module(name)
    , transport_in("transport_in")
    , transport_out("transport_out")
    , packet_loss_probability("packet_loss_probability")
    , network_latency("network_latency")
    , bandwidth_mbps("bandwidth_mbps")
    , packets_in_transit("packets_in_transit")
    , packets_transmitted("packets_transmitted")
    , packets_dropped("packets_dropped")
    , effective_bandwidth_mbps("effective_bandwidth_mbps")
    , network_conditions_(conditions)
    , packet_loss_simulation_enabled_(true)
    , congestion_simulation_enabled_(true)
{
    SC_THREAD(packet_delivery_process);
    SC_THREAD(network_simulation_process);
    SC_THREAD(bandwidth_monitor_process);
    SC_THREAD(congestion_control_process);
    
    reset_statistics();
}

bool TransportChannel::write(const transport_transaction& trans) {
    std::lock_guard<std::mutex> lock(transport_mutex_);
    
    TimedPacket packet(trans);
    
    // Check if packet should be dropped
    if (packet_loss_simulation_enabled_ && should_drop_packet()) {
        packet.dropped = true;
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.packets_dropped++;
        return false;
    }
    
    // Calculate delivery time
    sc_time transmission_delay = calculate_transmission_delay(trans.packet_data.size());
    sc_time total_delay = network_conditions_.base_latency + transmission_delay;
    total_delay = add_network_jitter(total_delay);
    
    packet.delivery_time = packet.arrival_time + total_delay;
    
    in_transit_packets_.push(packet);
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.packets_sent++;
        stats_.bytes_transmitted += trans.packet_data.size();
    }
    
    return true;
}

bool TransportChannel::read(transport_transaction& trans) {
    std::lock_guard<std::mutex> lock(transport_mutex_);
    
    sc_time current_time = sc_time_stamp();
    
    // Check if any packets are ready for delivery
    while (!in_transit_packets_.empty()) {
        TimedPacket& packet = in_transit_packets_.front();
        
        if (packet.delivery_time <= current_time && !packet.dropped) {
            trans = packet.transaction;
            update_transmission_statistics(packet);
            in_transit_packets_.pop();
            
            {
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.packets_received++;
            }
            
            return true;
        } else if (packet.dropped) {
            in_transit_packets_.pop();
        } else {
            break; // Not ready yet
        }
    }
    
    return false;
}

bool TransportChannel::should_drop_packet() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    
    return dis(gen) < network_conditions_.packet_loss_probability;
}

sc_time TransportChannel::calculate_transmission_delay(size_t packet_size) const {
    if (network_conditions_.bandwidth_mbps <= 0) {
        return SC_ZERO_TIME;
    }
    
    // Calculate transmission time based on bandwidth
    double bits = packet_size * 8.0;
    double megabits = bits / 1000000.0;
    double seconds = megabits / network_conditions_.bandwidth_mbps;
    
    return sc_time(seconds, SC_SEC);
}

sc_time TransportChannel::add_network_jitter(sc_time base_delay) const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    
    sc_time jitter_amount = sc_time(
        network_conditions_.jitter.to_double() * dis(gen),
        network_conditions_.jitter.get_time_unit()
    );
    
    return base_delay + jitter_amount;
}

void TransportChannel::update_transmission_statistics(const TimedPacket& packet) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    sc_time latency = packet.delivery_time - packet.arrival_time;
    stats_.total_transmission_time += latency;
    
    if (latency > stats_.max_latency) {
        stats_.max_latency = latency;
    }
    
    if (stats_.packets_received > 0) {
        stats_.average_latency = sc_time(
            stats_.total_transmission_time.to_double() / stats_.packets_received,
            stats_.total_transmission_time.get_time_unit()
        );
    }
}

void TransportChannel::packet_delivery_process() {
    while (true) {
        wait(1, SC_MS);
        
        std::lock_guard<std::mutex> lock(transport_mutex_);
        
        // Update status outputs
        packets_in_transit.write(static_cast<uint32_t>(in_transit_packets_.size()));
        
        // Update max packets in transit statistic
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            uint32_t current_in_transit = static_cast<uint32_t>(in_transit_packets_.size());
            if (current_in_transit > stats_.max_packets_in_transit) {
                stats_.max_packets_in_transit = current_in_transit;
            }
        }
    }
}

void TransportChannel::network_simulation_process() {
    while (true) {
        wait(packet_loss_probability.value_changed_event() | 
             network_latency.value_changed_event() |
             bandwidth_mbps.value_changed_event());
        
        network_conditions_.packet_loss_probability = packet_loss_probability.read();
        network_conditions_.base_latency = network_latency.read();
        network_conditions_.bandwidth_mbps = bandwidth_mbps.read();
    }
}

void TransportChannel::bandwidth_monitor_process() {
    while (true) {
        wait(1, SC_SEC);
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Calculate effective bandwidth
        if (stats_.total_transmission_time > SC_ZERO_TIME) {
            double seconds = stats_.total_transmission_time.to_seconds();
            double megabits = static_cast<double>(stats_.bytes_transmitted * 8) / 1000000.0;
            stats_.effective_bandwidth_mbps = megabits / seconds;
        }
        
        // Calculate packet loss rate
        uint64_t total_attempts = stats_.packets_sent + stats_.packets_dropped;
        if (total_attempts > 0) {
            stats_.packet_loss_rate = static_cast<double>(stats_.packets_dropped) / total_attempts;
        }
        
        // Update output ports
        packets_transmitted.write(stats_.packets_sent);
        packets_dropped.write(stats_.packets_dropped);
        effective_bandwidth_mbps.write(stats_.effective_bandwidth_mbps);
    }
}

void TransportChannel::congestion_control_process() {
    while (true) {
        wait(10, SC_MS); // Check congestion every 10ms
        
        if (!congestion_simulation_enabled_) {
            continue;
        }
        
        // Simple congestion control based on queue size
        std::lock_guard<std::mutex> lock(transport_mutex_);
        size_t queue_size = in_transit_packets_.size();
        
        if (queue_size > 100) { // Threshold for congestion
            // Simulate congestion by increasing latency
            network_conditions_.base_latency = sc_time(100, SC_MS);
            network_conditions_.packet_loss_probability = std::min(0.1, 
                network_conditions_.packet_loss_probability * 1.1);
        } else {
            // Normal conditions
            network_conditions_.base_latency = sc_time(50, SC_MS);
        }
    }
}

TransportChannel::TransportChannelStats TransportChannel::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void TransportChannel::set_network_conditions(const NetworkConditions& conditions) {
    network_conditions_ = conditions;
}

void TransportChannel::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = TransportChannelStats{};
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls