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
    , max_queue_size_(default_queue_size)
    , operations_enabled_(true)
    , interface_wrapper_(this)
{
    // Bind exports to the interface wrapper
    crypto_in.bind(interface_wrapper_);
    crypto_out.bind(interface_wrapper_);
    
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
        operation_timestamps_[reinterpret_cast<uint64_t>(&trans)] = sc_time_stamp();
        stats_.operations_queued++;
    }
    
    // Use custom queue with move semantics
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (operation_queue_.size() >= max_queue_size_) {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.operations_dropped++;
            return false;
        }
        operation_queue_.push(std::move(const_cast<crypto_transaction&>(trans)));
    }
    
    return true;
}

bool CryptoOperationChannel::read(crypto_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (operation_queue_.empty()) {
            return false;
        }
        trans = std::move(operation_queue_.front());
        operation_queue_.pop();
    }
    
    // Update latency statistics
    update_latency_statistics(reinterpret_cast<uint64_t>(&trans));
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.operations_completed++;
    
    return true;
}

bool CryptoOperationChannel::nb_write(const crypto_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (operation_queue_.size() >= max_queue_size_) {
        return false;
    }
    
    operation_queue_.push(std::move(const_cast<crypto_transaction&>(trans)));
    return true;
}

bool CryptoOperationChannel::nb_read(crypto_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (operation_queue_.empty()) {
        return false;
    }
    
    trans = std::move(operation_queue_.front());
    operation_queue_.pop();
    return true;
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
                SC_NS
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
    uint32_t current_size;
    uint32_t free_space;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        current_size = operation_queue_.size();
        free_space = max_queue_size_ - current_size;
    }
    
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

uint32_t CryptoOperationChannel::size() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return static_cast<uint32_t>(operation_queue_.size());
}

bool CryptoOperationChannel::is_empty() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return operation_queue_.empty();
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
    , interface_wrapper_(this)
{
    // Bind exports to the interface wrapper
    record_in.bind(interface_wrapper_);
    record_out.bind(interface_wrapper_);
    
    // Initialize priority queues with std::queue (no need for dynamic allocation)
    // Note: queue size is managed through application logic since std::queue is unlimited
    priority_queues_[RecordPriority::CRITICAL] = std::queue<record_transaction>();
    priority_queues_[RecordPriority::HIGH] = std::queue<record_transaction>();
    priority_queues_[RecordPriority::NORMAL] = std::queue<record_transaction>();
    priority_queues_[RecordPriority::LOW] = std::queue<record_transaction>();
    
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
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(priority_mutex_);
        // Check queue size limit (simple implementation)
        if (queue_it->second.size() >= total_queue_size_ / 4) {
            return false; // Queue full
        }
        queue_it->second.push(std::move(const_cast<record_transaction&>(trans)));
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.records_queued++;
    }
    
    return true;
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
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(priority_mutex_);
        if (queue_it->second.empty()) {
            return false;
        }
        trans = std::move(queue_it->second.front());
        queue_it->second.pop();
    }
    
    // Update statistics
    update_processing_statistics(trans);
    
    return true;
}

bool RecordOperationChannel::nb_write(const record_transaction& trans, RecordPriority priority) {
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
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(priority_mutex_);
        // Check queue size limit (simple implementation)
        if (queue_it->second.size() >= total_queue_size_ / 4) {
            return false; // Queue full
        }
        queue_it->second.push(std::move(const_cast<record_transaction&>(trans)));
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.records_queued++;
    }
    
    return true;
}

bool RecordOperationChannel::nb_read(record_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Find next priority level with available data
    RecordPriority next_priority = get_next_priority();
    
    auto queue_it = priority_queues_.find(next_priority);
    if (queue_it == priority_queues_.end()) {
        return false;
    }
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(priority_mutex_);
        if (queue_it->second.empty()) {
            return false;
        }
        trans = std::move(queue_it->second.front());
        queue_it->second.pop();
    }
    
    // Update statistics
    update_processing_statistics(trans);
    
    return true;
}

RecordOperationChannel::RecordPriority RecordOperationChannel::determine_operation_priority(
    const record_transaction& trans) const {
    
    record_extension* ext = trans.get_payload().get_extension<record_extension>();
    if (!ext) {
        return RecordPriority::LOW;
    }
    
    switch (ext->operation) {
        case record_extension::ANTI_REPLAY_CHECK:
            return RecordPriority::HIGH; // Anti-replay is security critical
        case record_extension::PROTECT_RECORD:
            return RecordPriority::NORMAL;
        case record_extension::UNPROTECT_RECORD:
            return RecordPriority::NORMAL;
        case record_extension::EPOCH_ADVANCE:
            return RecordPriority::CRITICAL; // Epoch changes are critical
        case record_extension::SEQUENCE_NUMBER_GEN:
            return RecordPriority::HIGH; // Sequence numbers are important for ordering
        default:
            return RecordPriority::LOW;
    }
}

RecordOperationChannel::RecordPriority RecordOperationChannel::get_next_priority() const {
    // Weighted priority selection
    static std::random_device rd;
    static std::mt19937 gen(rd());
    
    // Use mutex to protect queue access during priority checking
    std::lock_guard<std::mutex> lock(priority_mutex_);
    
    // Check critical first
    if (!priority_queues_.at(RecordPriority::CRITICAL).empty()) {
        return RecordPriority::CRITICAL;
    }
    
    // Weighted selection for other priorities
    std::vector<std::pair<RecordPriority, double>> weighted_priorities;
    for (const auto& [priority, weight] : priority_weights_) {
        if (priority != RecordPriority::CRITICAL && 
            !priority_queues_.at(priority).empty()) {
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
    
    record_extension* ext = trans.get_payload().get_extension<record_extension>();
    if (!ext) {
        return; // Cannot process statistics without extension
    }
    
    stats_.records_processed++;
    stats_.total_processing_time += ext->processing_time;

    switch (ext->operation) {
        case record_extension::PROTECT_RECORD:
            stats_.protection_operations++;
            stats_.protection_time += ext->processing_time;
            break;
        case record_extension::UNPROTECT_RECORD:
            stats_.unprotection_operations++;
            stats_.unprotection_time += ext->processing_time;
            break;
        case record_extension::ANTI_REPLAY_CHECK:
            if (ext->replay_detected) {
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
    
    // Use mutex to protect queue access during monitoring
    {
        std::lock_guard<std::mutex> lock(priority_mutex_);
        for (const auto& [priority, queue] : priority_queues_) {
            uint32_t depth = static_cast<uint32_t>(queue.size());
            total_pending += depth;
            if (depth > max_depth) {
                max_depth = depth;
            }
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

uint32_t RecordOperationChannel::get_queue_size() const {
    std::lock_guard<std::mutex> lock(priority_mutex_);
    uint32_t total_size = 0;
    for (const auto& [priority, queue] : priority_queues_) {
        total_size += static_cast<uint32_t>(queue.size());
    }
    return total_size;
}

uint32_t RecordOperationChannel::get_priority_queue_size(RecordPriority priority) const {
    std::lock_guard<std::mutex> lock(priority_mutex_);
    auto it = priority_queues_.find(priority);
    if (it != priority_queues_.end()) {
        return static_cast<uint32_t>(it->second.size());
    }
    return 0;
}

void RecordOperationChannel::set_priority_weights(const std::map<RecordPriority, double>& weights) {
    priority_weights_ = weights;
}

bool RecordOperationChannel::is_empty() const {
    std::lock_guard<std::mutex> lock(priority_mutex_);
    for (const auto& [priority, queue] : priority_queues_) {
        if (!queue.empty()) {
            return false;
        }
    }
    return true;
}

uint32_t RecordOperationChannel::size() const {
    return get_queue_size(); // Reuse existing implementation
}

/**
 * Message Operation Channel Implementation
 */
MessageOperationChannel::MessageOperationChannel(sc_module_name name, uint32_t queue_size)
    : sc_module(name)
    , message_in("message_in")
    , message_out("message_out")
    , enable_message_operations("enable_message_operations")
    , max_fragment_size("max_fragment_size")
    , reliable_delivery_enabled("reliable_delivery_enabled")
    , pending_messages("pending_messages")
    , active_reassemblies("active_reassemblies")
    , active_flights("active_flights")
    , total_queue_size_(queue_size)
    , operations_enabled_(true)
    , max_fragment_size_(1024)
    , reliable_delivery_enabled_(true)
    , interface_wrapper_(this)
{
    // Bind exports to the interface wrapper
    message_in.bind(interface_wrapper_);
    message_out.bind(interface_wrapper_);
    
    // Initialize operation queues with std::queue
    operation_queues_[MessageOperationType::FRAGMENTATION] = std::queue<message_transaction>();
    operation_queues_[MessageOperationType::REASSEMBLY] = std::queue<message_transaction>();
    operation_queues_[MessageOperationType::FLIGHT_MANAGEMENT] = std::queue<message_transaction>();
    operation_queues_[MessageOperationType::RETRANSMISSION] = std::queue<message_transaction>();
    
    // Set default operation priorities
    operation_priorities_[MessageOperationType::FRAGMENTATION] = 1;
    operation_priorities_[MessageOperationType::REASSEMBLY] = 2;
    operation_priorities_[MessageOperationType::FLIGHT_MANAGEMENT] = 3;
    operation_priorities_[MessageOperationType::RETRANSMISSION] = 4;
    
    SC_THREAD(message_scheduler_process);
    SC_THREAD(operation_monitor_process);
    SC_THREAD(throughput_calculation_process);
    
    reset_statistics();
}

bool MessageOperationChannel::write(const message_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Determine operation type
    MessageOperationType op_type = determine_operation_type(trans);
    
    auto queue_it = operation_queues_.find(op_type);
    if (queue_it == operation_queues_.end()) {
        return false;
    }
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        // Check queue size limit (simple implementation)
        if (queue_it->second.size() >= total_queue_size_ / 4) {
            return false; // Queue full
        }
        queue_it->second.push(std::move(const_cast<message_transaction&>(trans)));
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_queued++;
    }
    
    return true;
}

bool MessageOperationChannel::read(message_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Find next operation type with available data (priority-based)
    MessageOperationType next_type = get_next_operation_type();
    
    auto queue_it = operation_queues_.find(next_type);
    if (queue_it == operation_queues_.end()) {
        return false;
    }
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (queue_it->second.empty()) {
            return false;
        }
        trans = std::move(queue_it->second.front());
        queue_it->second.pop();
    }
    
    // Update statistics
    update_operation_statistics(trans);
    
    return true;
}

bool MessageOperationChannel::nb_write(const message_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Determine operation type
    MessageOperationType op_type = determine_operation_type(trans);
    
    auto queue_it = operation_queues_.find(op_type);
    if (queue_it == operation_queues_.end()) {
        return false;
    }
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        // Check queue size limit (simple implementation)
        if (queue_it->second.size() >= total_queue_size_ / 4) {
            return false; // Queue full
        }
        queue_it->second.push(std::move(const_cast<message_transaction&>(trans)));
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_queued++;
    }
    
    return true;
}

bool MessageOperationChannel::nb_read(message_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    // Find next operation type with available data (priority-based)
    MessageOperationType next_type = get_next_operation_type();
    
    auto queue_it = operation_queues_.find(next_type);
    if (queue_it == operation_queues_.end()) {
        return false;
    }
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (queue_it->second.empty()) {
            return false;
        }
        trans = std::move(queue_it->second.front());
        queue_it->second.pop();
    }
    
    // Update statistics
    update_operation_statistics(trans);
    
    return true;
}

bool MessageOperationChannel::queue_for_fragmentation(const message_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    auto& frag_queue = operation_queues_[MessageOperationType::FRAGMENTATION];
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (frag_queue.size() >= total_queue_size_ / 4) {
            return false; // Queue full
        }
        frag_queue.push(std::move(const_cast<message_transaction&>(trans)));
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_queued++;
        stats_.fragmentation_operations++;
    }
    
    return true;
}

bool MessageOperationChannel::queue_for_reassembly(const message_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    auto& reassembly_queue = operation_queues_[MessageOperationType::REASSEMBLY];
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (reassembly_queue.size() >= total_queue_size_ / 4) {
            return false; // Queue full
        }
        reassembly_queue.push(std::move(const_cast<message_transaction&>(trans)));
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_queued++;
        stats_.reassembly_operations++;
    }
    
    active_reassembly_count_++;
    
    return true;
}

bool MessageOperationChannel::queue_for_flight_management(const message_transaction& trans) {
    if (!operations_enabled_) {
        return false;
    }
    
    auto& flight_queue = operation_queues_[MessageOperationType::FLIGHT_MANAGEMENT];
    
    // Use mutex to protect queue access
    {
        std::lock_guard<std::mutex> lock(operation_mutex_);
        if (flight_queue.size() >= total_queue_size_ / 4) {
            return false; // Queue full
        }
        flight_queue.push(std::move(const_cast<message_transaction&>(trans)));
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_queued++;
        stats_.flight_operations++;
    }
    
    active_flight_count_++;
    
    return true;
}

void MessageOperationChannel::set_operation_priorities(const std::map<MessageOperationType, int>& priorities) {
    operation_priorities_ = priorities;
}

uint32_t MessageOperationChannel::get_operation_queue_size(MessageOperationType type) const {
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto it = operation_queues_.find(type);
    if (it != operation_queues_.end()) {
        return static_cast<uint32_t>(it->second.size());
    }
    return 0;
}

MessageOperationChannel::MessageChannelStats MessageOperationChannel::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void MessageOperationChannel::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = MessageChannelStats{};
    active_reassembly_count_ = 0;
    active_flight_count_ = 0;
}

MessageOperationChannel::MessageOperationType MessageOperationChannel::determine_operation_type(
    const message_transaction& trans) const {
    
    message_extension* ext = trans.get_payload().get_extension<message_extension>();
    if (!ext) {
        return MessageOperationType::FRAGMENTATION; // Default
    }
    
    switch (ext->operation) {
        case message_extension::FRAGMENT_MESSAGE:
            return MessageOperationType::FRAGMENTATION;
        case message_extension::REASSEMBLE_MESSAGE:
            return MessageOperationType::REASSEMBLY;
        case message_extension::MANAGE_FLIGHT:
            return MessageOperationType::FLIGHT_MANAGEMENT;
        case message_extension::RETRANSMIT_MESSAGE:
            return MessageOperationType::RETRANSMISSION;
        default:
            return MessageOperationType::FRAGMENTATION;
    }
}

void MessageOperationChannel::update_operation_statistics(const message_transaction& trans) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    message_extension* ext = trans.get_payload().get_extension<message_extension>();
    if (!ext) {
        return; // Cannot process statistics without extension
    }
    
    stats_.messages_processed++;
    stats_.total_processing_time += ext->processing_time;
    
    switch (ext->operation) {
        case message_extension::FRAGMENT_MESSAGE:
            stats_.fragmentation_operations++;
            break;
        case message_extension::REASSEMBLE_MESSAGE:
            stats_.reassembly_operations++;
            stats_.active_reassemblies = active_reassembly_count_.load();
            break;
        case message_extension::MANAGE_FLIGHT:
            stats_.flight_operations++;
            stats_.active_flights = active_flight_count_.load();
            break;
        case message_extension::RETRANSMIT_MESSAGE:
            stats_.retransmission_operations++;
            break;
    }
    
    // Update max concurrent operations
    uint32_t current_concurrent = active_reassembly_count_.load() + active_flight_count_.load();
    if (current_concurrent > stats_.max_concurrent_operations) {
        stats_.max_concurrent_operations = current_concurrent;
    }
    
    // Calculate message throughput (messages per second)
    if (stats_.total_processing_time > SC_ZERO_TIME) {
        double seconds = stats_.total_processing_time.to_seconds();
        stats_.message_throughput_mps = static_cast<double>(stats_.messages_processed) / seconds;
    }
    
    // Calculate reliability ratio (successful operations / total operations)
    uint64_t total_operations = stats_.fragmentation_operations + stats_.reassembly_operations + 
                               stats_.flight_operations + stats_.retransmission_operations;
    if (total_operations > 0) {
        stats_.reliability_ratio = static_cast<double>(stats_.messages_processed) / total_operations;
    }
}

MessageOperationChannel::MessageOperationType MessageOperationChannel::get_next_operation_type() const {
    std::lock_guard<std::mutex> lock(operation_mutex_);
    
    // Priority-based selection (lower number = higher priority)
    std::vector<std::pair<MessageOperationType, int>> available_operations;
    
    for (const auto& [op_type, priority] : operation_priorities_) {
        auto queue_it = operation_queues_.find(op_type);
        if (queue_it != operation_queues_.end() && !queue_it->second.empty()) {
            available_operations.push_back({op_type, priority});
        }
    }
    
    if (available_operations.empty()) {
        return MessageOperationType::FRAGMENTATION; // Fallback
    }
    
    // Sort by priority (ascending - lower number = higher priority)
    std::sort(available_operations.begin(), available_operations.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    return available_operations.front().first;
}

void MessageOperationChannel::message_scheduler_process() {
    while (true) {
        wait(1, SC_MS);
        
        // Monitor queue levels and update status
        uint32_t total_pending = 0;
        {
            std::lock_guard<std::mutex> lock(operation_mutex_);
            for (const auto& [op_type, queue] : operation_queues_) {
                total_pending += static_cast<uint32_t>(queue.size());
            }
        }
        
        // Update status outputs
        pending_messages.write(total_pending);
        active_reassemblies.write(active_reassembly_count_.load());
        active_flights.write(active_flight_count_.load());
    }
}

void MessageOperationChannel::operation_monitor_process() {
    while (true) {
        wait(enable_message_operations.value_changed_event() | 
             max_fragment_size.value_changed_event() |
             reliable_delivery_enabled.value_changed_event());
        
        operations_enabled_ = enable_message_operations.read();
        max_fragment_size_ = max_fragment_size.read();
        reliable_delivery_enabled_ = reliable_delivery_enabled.read();
    }
}

void MessageOperationChannel::throughput_calculation_process() {
    while (true) {
        wait(1, SC_SEC);
        
        // Additional throughput monitoring can be added here
        // The actual calculation is done in update_operation_statistics
    }
}

bool MessageOperationChannel::is_empty() const {
    std::lock_guard<std::mutex> lock(operation_mutex_);
    for (const auto& [op_type, queue] : operation_queues_) {
        if (!queue.empty()) {
            return false;
        }
    }
    return true;
}

uint32_t MessageOperationChannel::size() const {
    std::lock_guard<std::mutex> lock(operation_mutex_);
    uint32_t total_size = 0;
    for (const auto& [op_type, queue] : operation_queues_) {
        total_size += static_cast<uint32_t>(queue.size());
    }
    return total_size;
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
    , interface_wrapper_(this)
{
    // Bind exports to the interface wrapper
    transport_in.bind(interface_wrapper_);
    transport_out.bind(interface_wrapper_);
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
    sc_time transmission_delay = calculate_transmission_delay(trans.get_data_size());
    sc_time total_delay = network_conditions_.base_latency + transmission_delay;
    total_delay = add_network_jitter(total_delay);
    
    packet.delivery_time = packet.arrival_time + total_delay;
    
    in_transit_packets_.push(std::move(packet));
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.packets_sent++;
        stats_.bytes_transmitted += trans.get_data_size();
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
            trans = std::move(*packet.transaction);
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
        SC_NS
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
            SC_NS
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

bool TransportChannel::is_empty() const {
    std::lock_guard<std::mutex> lock(transport_mutex_);
    return in_transit_packets_.empty();
}

uint32_t TransportChannel::size() const {
    std::lock_guard<std::mutex> lock(transport_mutex_);
    return static_cast<uint32_t>(in_transit_packets_.size());
}

/**
 * DTLSInterconnectBus Implementation
 */
DTLSInterconnectBus::DTLSInterconnectBus(sc_module_name name, const BusConfig& config)
    : sc_module(name)
    , crypto_bus_in("crypto_bus_in")
    , crypto_bus_out("crypto_bus_out")
    , record_bus_in("record_bus_in")
    , record_bus_out("record_bus_out")
    , message_bus_in("message_bus_in")
    , message_bus_out("message_bus_out")
    , transport_bus_in("transport_bus_in")
    , transport_bus_out("transport_bus_out")
    , bus_enable("bus_enable")
    , bus_clock_mhz("bus_clock_mhz")
    , total_bus_utilization_percent("total_bus_utilization_percent")
    , total_transactions("total_transactions")
    , bus_congestion_detected("bus_congestion_detected")
    , bus_config_(config)
    , bus_enabled_(true)
    , bus_clock_mhz_(100)
    , crypto_channel_("crypto_channel", 64)
    , record_channel_("record_channel", 64)
    , message_channel_("message_channel", 64)
    , transport_channel_("transport_channel")
{
    // Bind bus exports to internal channel interface wrappers
    crypto_bus_in.bind(crypto_channel_.interface_wrapper_);
    crypto_bus_out.bind(crypto_channel_.interface_wrapper_);
    record_bus_in.bind(record_channel_.interface_wrapper_);
    record_bus_out.bind(record_channel_.interface_wrapper_);
    message_bus_in.bind(message_channel_.interface_wrapper_);
    message_bus_out.bind(message_channel_.interface_wrapper_);
    transport_bus_in.bind(transport_channel_.interface_wrapper_);
    transport_bus_out.bind(transport_channel_.interface_wrapper_);
    
    SC_THREAD(bus_arbitration_process);
    SC_THREAD(utilization_monitor_process);
    SC_THREAD(congestion_detection_process);
    SC_THREAD(performance_optimization_process);
    
    // Initialize statistics
    reset_statistics();
}

bool DTLSInterconnectBus::route_transaction(const dtls_transaction& trans) {
    if (!bus_enabled_) {
        return false;
    }
    
    // Update statistics based on transaction type
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_transactions++;
        
        // For now, just increment total transactions
        // In a full implementation, you would inspect the transaction extension
        // to determine the specific type and route accordingly
    }
    
    // Simulate bus arbitration delay
    wait(bus_config_.arbitration_delay);
    
    return true;
}

void DTLSInterconnectBus::set_bus_configuration(const BusConfig& config) {
    bus_config_ = config;
}

DTLSInterconnectBus::BusConfig DTLSInterconnectBus::get_bus_configuration() const {
    return bus_config_;
}

void DTLSInterconnectBus::enable_priority_arbitration(bool enable) {
    bus_config_.priority_arbitration_enabled = enable;
}

DTLSInterconnectBus::BusStats DTLSInterconnectBus::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void DTLSInterconnectBus::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = BusStats{};
}

bool DTLSInterconnectBus::is_congested() const {
    // Simple congestion detection based on pending transactions
    // In a full implementation, this would be more sophisticated
    return false;
}

void DTLSInterconnectBus::bus_arbitration_process() {
    while (true) {
        wait(bus_config_.arbitration_delay);
        process_pending_transactions();
    }
}

void DTLSInterconnectBus::utilization_monitor_process() {
    while (true) {
        wait(1, SC_MS);
        update_bus_statistics();
    }
}

void DTLSInterconnectBus::congestion_detection_process() {
    while (true) {
        wait(10, SC_MS);
        
        bool congested = check_congestion_condition();
        bus_congestion_detected.write(congested);
    }
}

void DTLSInterconnectBus::performance_optimization_process() {
    while (true) {
        wait(100, SC_MS);
        optimize_bus_performance();
    }
}

void DTLSInterconnectBus::process_pending_transactions() {
    std::lock_guard<std::mutex> lock(arbitration_mutex_);
    
    while (!pending_transactions_.empty() && 
           active_transactions_.load() < bus_config_.max_concurrent_transactions) {
        auto transaction = pending_transactions_.front();
        pending_transactions_.pop();
        
        // Execute the transaction
        transaction();
        active_transactions_++;
    }
}

void DTLSInterconnectBus::update_bus_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Update utilization based on active transactions
    uint32_t utilization = (active_transactions_.load() * 100) / bus_config_.max_concurrent_transactions;
    total_bus_utilization_percent.write(utilization);
    total_transactions.write(stats_.total_transactions);
    
    stats_.average_utilization_percent = static_cast<double>(utilization);
}

bool DTLSInterconnectBus::check_congestion_condition() const {
    uint32_t current_utilization = (active_transactions_.load() * 100) / bus_config_.max_concurrent_transactions;
    return current_utilization >= bus_config_.congestion_threshold_percent;
}

void DTLSInterconnectBus::optimize_bus_performance() {
    // Simple performance optimization based on congestion
    if (is_congested()) {
        // Could implement dynamic priority adjustment, queue reordering, etc.
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.congestion_events++;
    }
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls