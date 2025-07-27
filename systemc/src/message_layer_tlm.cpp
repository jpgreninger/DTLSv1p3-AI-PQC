#include "message_layer_tlm.h"
#include <dtls/types.h>
#include <algorithm>
#include <numeric>

// Forward declarations to avoid full header includes
namespace dtls::v13::protocol {
    class HandshakeMessage;
    enum class FlightType : uint32_t;
}

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * Message Reassembler TLM Implementation
 */
MessageReassemblerTLM::MessageReassemblerTLM(sc_module_name name)
    : sc_module(name)
    , target_socket("target_socket")
    , enable_reassembly("enable_reassembly")
    , reassembly_timeout_ms("reassembly_timeout_ms")
    , active_reassemblies("active_reassemblies")
    , completed_messages("completed_messages")
    , timeout_count("timeout_count")
{
    target_socket.register_b_transport(this, &MessageReassemblerTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &MessageReassemblerTLM::nb_transport_fw);
    
    SC_THREAD(reassembly_timeout_process);
    SC_THREAD(statistics_update_process);
    SC_THREAD(configuration_monitor_process);
    
    reset_statistics();
}

void MessageReassemblerTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    message_extension* ext = trans.get_extension<message_extension>();
    
    if (!ext || ext->operation != message_extension::REASSEMBLE_MESSAGE) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    if (!reassembly_enabled_) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    sc_time processing_start = sc_time_stamp();
    
    // Process fragment (simplified for SystemC modeling)
    bool all_successful = process_fragment(ext->message_sequence, 0, trans.get_data_length());
    
    // Check if any messages are now complete
    std::vector<uint16_t> completed_sequences;
    {
        std::lock_guard<std::mutex> lock(reassembly_mutex_);
        for (auto& [seq, state] : active_reassemblies_) {
            if (!state.complete && check_reassembly_complete(seq)) {
                state.complete = true;
                completed_sequences.push_back(seq);
            }
        }
    }
    
    // Update extension with completed messages (simplified for SystemC modeling)
    for (uint16_t seq : completed_sequences) {
        get_completed_message(seq);
        ext->message_complete = true;
    }
    
    // Calculate processing time
    sc_time processing_time = g_dtls_timing.fragment_reassembly_time;
    processing_time += utils::calculate_processing_time(
        ext->fragment_count * 100, // Approximate fragment overhead
        sc_time(0, SC_NS),
        sc_time(1, SC_NS) // 1ns per fragment
    );
    
    delay += processing_time;
    ext->processing_time = processing_time;
    
    trans.set_response_status(all_successful ? tlm::TLM_OK_RESPONSE : tlm::TLM_GENERIC_ERROR_RESPONSE);
}

tlm::tlm_sync_enum MessageReassemblerTLM::nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                                         tlm::tlm_phase& phase, 
                                                         sc_time& delay) {
    if (phase == tlm::BEGIN_REQ) {
        b_transport(trans, delay);
        phase = tlm::END_REQ;
        return tlm::TLM_COMPLETED;
    }
    
    return tlm::TLM_ACCEPTED;
}

bool MessageReassemblerTLM::process_fragment(uint16_t message_seq, uint32_t offset, uint32_t length) {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.total_fragments_received++;
    }
    
    // Find or create reassembly state
    auto it = active_reassemblies_.find(message_seq);
    if (it == active_reassemblies_.end()) {
        auto [new_it, inserted] = active_reassemblies_.emplace(message_seq, MessageReassemblyState{});
        it = new_it;
        it->second.total_length = length; // Simplified - use fragment length as total
    }
    
    MessageReassemblyState& state = it->second;
    state.last_fragment_time = sc_time_stamp();
    
    // Check for duplicate fragment (simplified)
    for (const auto& existing : state.fragments) {
        if (existing.fragment_offset == offset && existing.fragment_length == length) {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.duplicate_fragments++;
            return true; // Not an error, just ignore duplicate
        }
    }
    
    // Add fragment to reassembly state (simplified for SystemC modeling)
    state.fragments.emplace_back(offset, length);
    
    // Check if fragments are out of order
    if (state.fragments.size() > 1) {
        auto last_it = state.fragments.end() - 1;
        auto second_last_it = state.fragments.end() - 2;
        if (last_it->fragment_offset < second_last_it->fragment_offset) {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.out_of_order_fragments++;
        }
    }
    
    return true;
}

bool MessageReassemblerTLM::check_reassembly_complete(uint16_t message_seq) const {
    auto it = active_reassemblies_.find(message_seq);
    if (it == active_reassemblies_.end()) {
        return false;
    }
    
    const MessageReassemblyState& state = it->second;
    
    // Sort fragments by offset
    std::vector<const FragmentInfo*> sorted_fragments;
    for (const auto& frag_info : state.fragments) {
        sorted_fragments.push_back(&frag_info);
    }
    
    std::sort(sorted_fragments.begin(), sorted_fragments.end(),
              [](const FragmentInfo* a, const FragmentInfo* b) {
                  return a->fragment_offset < b->fragment_offset;
              });
    
    // Check for complete coverage
    uint32_t expected_offset = 0;
    for (const auto* frag_info : sorted_fragments) {
        if (frag_info->fragment_offset != expected_offset) {
            return false; // Gap detected
        }
        expected_offset += frag_info->fragment_length;
    }
    
    return expected_offset == state.total_length;
}

bool MessageReassemblerTLM::assemble_message(uint16_t message_seq) {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    auto it = active_reassemblies_.find(message_seq);
    if (it == active_reassemblies_.end() || !it->second.complete) {
        return false; // Reassembly not complete or not found
    }
    
    MessageReassemblyState& state = it->second;
    
    // Sort fragments by offset (simplified for SystemC modeling)
    std::sort(state.fragments.begin(), state.fragments.end(),
              [](const FragmentInfo& a, const FragmentInfo& b) {
                  return a.fragment_offset < b.fragment_offset;
              });
    
    // Assemble complete message data (simplified for SystemC modeling)
    size_t total_size = 0;
    for (const auto& frag_info : state.fragments) {
        total_size += frag_info.fragment_length;
    }
    
    // Update statistics
    update_statistics(state, true);
    
    // Clean up completed reassembly
    active_reassemblies_.erase(it);
    
    return true; // Successfully assembled
}

void MessageReassemblerTLM::update_statistics(const MessageReassemblyState& state, bool completed) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    if (completed) {
        stats_.messages_completed++;
        stats_.total_bytes_reassembled += state.total_length;
        
        sc_time reassembly_time = state.last_fragment_time - state.start_time;
        stats_.total_reassembly_time += reassembly_time;
        
        if (reassembly_time > stats_.max_reassembly_time) {
            stats_.max_reassembly_time = reassembly_time;
        }
        
        if (stats_.messages_completed > 0) {
            stats_.average_reassembly_time = sc_time(
                stats_.total_reassembly_time.to_double() / stats_.messages_completed,
                SC_NS
            );
        }
    } else {
        stats_.messages_timed_out++;
    }
    
    stats_.active_reassemblies = static_cast<uint32_t>(active_reassemblies_.size());
    if (stats_.active_reassemblies > stats_.max_concurrent_reassemblies) {
        stats_.max_concurrent_reassemblies = stats_.active_reassemblies;
    }
    
    // Calculate efficiency ratio
    uint64_t total_attempts = stats_.messages_completed + stats_.messages_timed_out;
    if (total_attempts > 0) {
        stats_.reassembly_efficiency = static_cast<double>(stats_.messages_completed) / total_attempts;
    }
}

void MessageReassemblerTLM::reassembly_timeout_process() {
    while (true) {
        wait(1, SC_SEC); // Check every second
        cleanup_timed_out_reassemblies();
    }
}

void MessageReassemblerTLM::cleanup_timed_out_reassemblies() {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    sc_time current_time = sc_time_stamp();
    auto it = active_reassemblies_.begin();
    
    while (it != active_reassemblies_.end()) {
        sc_time elapsed = current_time - it->second.start_time;
        
        if (elapsed > reassembly_timeout_) {
            update_statistics(it->second, false);
            it = active_reassemblies_.erase(it);
        } else {
            ++it;
        }
    }
}

void MessageReassemblerTLM::statistics_update_process() {
    while (true) {
        wait(1, SC_SEC);
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Update output ports
        active_reassemblies.write(static_cast<uint16_t>(stats_.active_reassemblies));
        completed_messages.write(static_cast<uint32_t>(stats_.messages_completed));
        timeout_count.write(static_cast<uint32_t>(stats_.messages_timed_out));
    }
}

void MessageReassemblerTLM::configuration_monitor_process() {
    while (true) {
        wait(reassembly_timeout_ms.value_changed_event() | enable_reassembly.value_changed_event());
        
        reassembly_enabled_ = enable_reassembly.read();
        
        uint32_t timeout_ms = reassembly_timeout_ms.read();
        if (timeout_ms > 0) {
            reassembly_timeout_ = sc_time(timeout_ms, SC_MS);
        }
    }
}

MessageReassemblerTLM::ReassemblyStats MessageReassemblerTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void MessageReassemblerTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = ReassemblyStats{};
}

// Additional simplified methods for SystemC modeling
bool MessageReassemblerTLM::add_fragment(uint16_t message_seq, uint32_t fragment_offset, uint32_t fragment_length) {
    return process_fragment(message_seq, fragment_offset, fragment_length);
}

bool MessageReassemblerTLM::is_message_complete(uint16_t message_seq) const {
    return check_reassembly_complete(message_seq);
}

bool MessageReassemblerTLM::get_completed_message(uint16_t message_seq) {
    return assemble_message(message_seq); // Returns true if successfully assembled
}

void MessageReassemblerTLM::set_reassembly_timeout(sc_time timeout) {
    reassembly_timeout_ = timeout;
}

/**
 * Message Fragmenter TLM Implementation
 */
MessageFragmenterTLM::MessageFragmenterTLM(sc_module_name name, uint32_t default_max_fragment_size)
    : sc_module(name)
    , target_socket("target_socket")
    , max_fragment_size("max_fragment_size")
    , enable_fragmentation("enable_fragmentation")
    , messages_fragmented("messages_fragmented")
    , total_fragments_created("total_fragments_created")
    , average_fragments_per_message("average_fragments_per_message")
    , max_fragment_size_(default_max_fragment_size)
    , fragmentation_enabled_(true)
{
    target_socket.register_b_transport(this, &MessageFragmenterTLM::b_transport);
    
    SC_THREAD(performance_monitor_process);
    SC_THREAD(configuration_monitor_process);
    
    reset_statistics();
}

void MessageFragmenterTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    message_extension* ext = trans.get_extension<message_extension>();
    
    if (!ext || ext->operation != message_extension::FRAGMENT_MESSAGE) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    if (!fragmentation_enabled_) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    sc_time processing_start = sc_time_stamp();
    
    // Perform message fragmentation (simplified for SystemC modeling)
    uint32_t fragment_count = perform_fragmentation(trans.get_data_length(), ext->message_sequence);
    
    ext->fragment_count = fragment_count;
    
    // Calculate processing time
    sc_time processing_time = g_dtls_timing.message_fragmentation_time;
    size_t message_size = trans.get_data_length();
    processing_time += utils::calculate_processing_time(
        message_size, sc_time(0, SC_NS), sc_time(1, SC_NS) // 1ns per byte
    );
    
    delay += processing_time;
    ext->processing_time = processing_time;
    
    // Update statistics
    update_statistics(message_size, ext->fragment_count, processing_time);
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
}

uint32_t MessageFragmenterTLM::perform_fragmentation(uint32_t message_length, uint16_t message_seq) {
    
    // Calculate fragment parameters (simplified for SystemC modeling)
    size_t fragment_header_size = 12; // DTLS handshake message header size
    size_t payload_per_fragment = max_fragment_size_ - fragment_header_size;
    uint32_t total_fragments = static_cast<uint32_t>((message_length + payload_per_fragment - 1) / payload_per_fragment);
    
    // For SystemC modeling, we just return the fragment count
    // In full implementation, this would create actual MessageFragment objects
    
    return total_fragments;
}

void MessageFragmenterTLM::update_statistics(size_t message_size, size_t fragment_count, sc_time processing_time) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.messages_processed++;
    stats_.total_fragmentation_time += processing_time;
    
    if (fragment_count > 1) {
        stats_.messages_fragmented++;
        stats_.total_fragments_created += fragment_count;
        stats_.bytes_fragmented += message_size;
        
        if (fragment_count > stats_.max_fragments_per_message) {
            stats_.max_fragments_per_message = static_cast<uint32_t>(fragment_count);
        }
    }
    
    if (message_size > stats_.largest_message_size) {
        stats_.largest_message_size = message_size;
    }
    
    // Calculate averages
    if (stats_.messages_fragmented > 0) {
        stats_.average_fragments_per_message = 
            static_cast<double>(stats_.total_fragments_created) / stats_.messages_fragmented;
    }
    
    if (stats_.messages_processed > 0) {
        stats_.average_fragmentation_time = sc_time(
            stats_.total_fragmentation_time.to_double() / stats_.messages_processed,
            SC_NS
        );
    }
    
    // Calculate overhead ratio
    if (stats_.bytes_fragmented > 0) {
        size_t total_fragment_overhead = stats_.total_fragments_created * 12; // Header size per fragment
        stats_.fragmentation_overhead_ratio = 
            static_cast<double>(total_fragment_overhead) / stats_.bytes_fragmented;
    }
}

void MessageFragmenterTLM::performance_monitor_process() {
    while (true) {
        wait(1, SC_SEC);
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Update output ports
        messages_fragmented.write(static_cast<uint32_t>(stats_.messages_fragmented));
        total_fragments_created.write(static_cast<uint32_t>(stats_.total_fragments_created));
        average_fragments_per_message.write(stats_.average_fragments_per_message);
    }
}

void MessageFragmenterTLM::configuration_monitor_process() {
    while (true) {
        wait(max_fragment_size.value_changed_event() | enable_fragmentation.value_changed_event());
        
        fragmentation_enabled_ = enable_fragmentation.read();
        
        uint32_t new_size = max_fragment_size.read();
        if (new_size > 0 && new_size <= 65535) {
            max_fragment_size_ = new_size;
        }
    }
}

MessageFragmenterTLM::FragmentationStats MessageFragmenterTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void MessageFragmenterTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = FragmentationStats{};
}

// Additional simplified methods for SystemC modeling
uint32_t MessageFragmenterTLM::fragment_message(uint32_t message_length, uint16_t message_seq) {
    return perform_fragmentation(message_length, message_seq);
}

void MessageFragmenterTLM::set_max_fragment_size(uint32_t size) {
    if (size > 0 && size <= 65535) {
        max_fragment_size_ = size;
    }
}

/**
 * Message Layer TLM Implementation
 */
MessageLayerTLM::MessageLayerTLM(sc_module_name name)
    : sc_module(name)
    , target_socket("target_socket")
    , record_layer_socket("record_layer_socket")
    , fragmenter_socket("fragmenter_socket")
    , reassembler_socket("reassembler_socket")
    , flight_mgr_socket("flight_mgr_socket")
    , max_fragment_size("max_fragment_size")
    , reassembly_timeout_ms("reassembly_timeout_ms")
    , enable_reliable_delivery("enable_reliable_delivery")
    , messages_sent("messages_sent")
    , messages_received("messages_received")
    , active_operations("active_operations")
    , message_throughput_mps("message_throughput_mps")
{
    target_socket.register_b_transport(this, &MessageLayerTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &MessageLayerTLM::nb_transport_fw);
    
    SC_THREAD(message_processing_thread);
    SC_THREAD(performance_monitoring_process);
    SC_THREAD(throughput_calculation_process);
    SC_THREAD(configuration_monitor_process);
    
    reset_statistics();
}

void MessageLayerTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    message_extension* ext = trans.get_extension<message_extension>();
    
    if (!ext) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    bool success = false;
    sc_time processing_start = sc_time_stamp();
    
    switch (ext->operation) {
        case message_extension::SEND_FLIGHT:
            success = handle_flight_operation(trans);
            active_send_operations_++;
            break;
            
        case message_extension::RECEIVE_FRAGMENT:
            success = handle_receive_fragments(trans);
            active_receive_operations_++;
            break;
            
        case message_extension::FRAGMENT_MESSAGE:
        case message_extension::REASSEMBLE_MESSAGE:
            success = handle_send_message(trans);
            break;
            
        default:
            trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
            return;
    }
    
    sc_time processing_time = sc_time_stamp() - processing_start;
    ext->processing_time = processing_time;
    delay += processing_time;
    
    // Update operation counters
    if (ext->operation == message_extension::SEND_FLIGHT) {
        active_send_operations_--;
    } else if (ext->operation == message_extension::RECEIVE_FRAGMENT) {
        active_receive_operations_--;
    }
    
    trans.set_response_status(success ? tlm::TLM_OK_RESPONSE : tlm::TLM_GENERIC_ERROR_RESPONSE);
}

tlm::tlm_sync_enum MessageLayerTLM::nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                                   tlm::tlm_phase& phase, 
                                                   sc_time& delay) {
    if (phase == tlm::BEGIN_REQ) {
        b_transport(trans, delay);
        phase = tlm::END_REQ;
        return tlm::TLM_COMPLETED;
    }
    
    return tlm::TLM_ACCEPTED;
}

bool MessageLayerTLM::handle_send_message(tlm::tlm_generic_payload& trans) {
    message_extension* ext = trans.get_extension<message_extension>();
    if (!ext) return false;
    
    uint16_t message_seq = next_message_sequence_.fetch_add(1);
    
    // Fragment the message (simplified for SystemC modeling)
    bool fragment_success = fragment_and_send_message(trans.get_data_length(), message_seq);
    
    if (fragment_success) {
        size_t message_size = trans.get_data_length();
        update_send_statistics(message_size, ext->processing_time, true);
    } else {
        update_send_statistics(0, ext->processing_time, false);
    }
    
    return fragment_success;
}

bool MessageLayerTLM::handle_receive_fragments(tlm::tlm_generic_payload& trans) {
    message_extension* ext = trans.get_extension<message_extension>();
    if (!ext) return false;
    
    bool success = reassemble_incoming_message(ext->fragment_count);
    
    if (success) {
        ext->message_complete = true;
        update_receive_statistics(ext->fragment_count, ext->processing_time, true);
    } else {
        update_receive_statistics(ext->fragment_count, ext->processing_time, false);
    }
    
    return success;
}

bool MessageLayerTLM::handle_flight_operation(tlm::tlm_generic_payload& trans) {
    message_extension* ext = trans.get_extension<message_extension>();
    if (!ext || ext->operation != message_extension::SEND_FLIGHT) {
        return false;
    }
    
    // Create flight with single message (simplified for SystemC modeling)
    bool success = manage_flight_transmission(1, ext->flight_type_value);
    
    if (success) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.flights_transmitted++;
    }
    
    return success;
}

bool MessageLayerTLM::fragment_and_send_message(uint32_t message_length, uint16_t seq) {
    // Create fragmentation transaction
    tlm::tlm_generic_payload payload;
    message_extension* ext = new message_extension(message_extension::FRAGMENT_MESSAGE);
    ext->message_sequence = seq;
    ext->max_fragment_size = max_fragment_size_;
    payload.set_extension(ext);
    payload.set_data_length(message_length);
    
    // Make TLM call to fragmenter
    sc_time delay = SC_ZERO_TIME;
    
    fragmenter_socket->b_transport(payload, delay);
    
    if (payload.get_response_status() != tlm::TLM_OK_RESPONSE) {
        return false;
    }
    
    // Send fragments through record layer (simplified for SystemC modeling)
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.fragments_sent += ext->fragment_count;
    
    return true;
}

bool MessageLayerTLM::reassemble_incoming_message(uint32_t fragment_count) {
    // Create reassembly transaction
    tlm::tlm_generic_payload payload;
    message_extension* ext = new message_extension(message_extension::REASSEMBLE_MESSAGE);
    ext->fragment_count = fragment_count;
    payload.set_extension(ext);
    
    // Make TLM call to reassembler
    sc_time delay = SC_ZERO_TIME;
    
    reassembler_socket->b_transport(payload, delay);
    
    bool success = (payload.get_response_status() == tlm::TLM_OK_RESPONSE);
    
    if (success && ext->message_complete) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_reassembled++;
        stats_.fragments_received += fragment_count;
    }
    
    return success;
}

void MessageLayerTLM::update_send_statistics(size_t message_size, sc_time processing_time, bool success) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    if (success) {
        stats_.handshake_messages_sent++;
    }
    
    stats_.total_send_time += processing_time;
    
    if (stats_.handshake_messages_sent > 0) {
        stats_.average_send_time = sc_time(
            stats_.total_send_time.to_double() / stats_.handshake_messages_sent,
            SC_NS
        );
    }
}

void MessageLayerTLM::update_receive_statistics(size_t fragments_count, sc_time processing_time, bool success) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    if (success) {
        stats_.handshake_messages_received++;
    }
    
    stats_.total_receive_time += processing_time;
    
    if (stats_.handshake_messages_received > 0) {
        stats_.average_receive_time = sc_time(
            stats_.total_receive_time.to_double() / stats_.handshake_messages_received,
            SC_NS
        );
    }
}

void MessageLayerTLM::calculate_performance_metrics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Calculate message throughput (messages per second)
    if (stats_.total_send_time > SC_ZERO_TIME && stats_.handshake_messages_sent > 0) {
        double seconds = stats_.total_send_time.to_seconds();
        stats_.message_throughput_mps = static_cast<double>(stats_.handshake_messages_sent) / seconds;
    }
    
    // Calculate fragment overhead ratio
    if (stats_.handshake_messages_sent > 0) {
        stats_.fragment_overhead_ratio = 
            static_cast<double>(stats_.fragments_sent) / stats_.handshake_messages_sent;
    }
    
    // Calculate reliability effectiveness
    uint64_t total_attempts = stats_.handshake_messages_sent + stats_.retransmissions_performed;
    if (total_attempts > 0) {
        stats_.reliability_effectiveness = 
            static_cast<double>(stats_.handshake_messages_sent) / total_attempts;
    }
}

void MessageLayerTLM::message_processing_thread() {
    while (true) {
        wait(100, SC_MS);
        calculate_performance_metrics();
    }
}

void MessageLayerTLM::performance_monitoring_process() {
    while (true) {
        wait(1, SC_SEC);
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Update output ports
        messages_sent.write(stats_.handshake_messages_sent);
        messages_received.write(stats_.handshake_messages_received);
        active_operations.write(active_send_operations_.load() + active_receive_operations_.load());
        message_throughput_mps.write(stats_.message_throughput_mps);
    }
}

void MessageLayerTLM::throughput_calculation_process() {
    while (true) {
        wait(1, SC_SEC);
        calculate_performance_metrics();
    }
}

void MessageLayerTLM::configuration_monitor_process() {
    while (true) {
        wait(max_fragment_size.value_changed_event() | 
             reassembly_timeout_ms.value_changed_event() |
             enable_reliable_delivery.value_changed_event());
        
        uint32_t new_frag_size = max_fragment_size.read();
        if (new_frag_size > 0) {
            max_fragment_size_ = new_frag_size;
        }
        
        uint32_t new_timeout = reassembly_timeout_ms.read();
        if (new_timeout > 0) {
            reassembly_timeout_ = sc_time(new_timeout, SC_MS);
        }
        
        reliable_delivery_enabled_ = enable_reliable_delivery.read();
    }
}

MessageLayerTLM::MessageLayerStats MessageLayerTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void MessageLayerTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = MessageLayerStats{};
    active_send_operations_.store(0);
    active_receive_operations_.store(0);
}

// Additional simplified methods for SystemC modeling
bool MessageLayerTLM::send_handshake_message(uint32_t message_length) {
    // Create a simplified transaction for sending
    tlm::tlm_generic_payload trans;
    message_extension* ext = new message_extension(message_extension::FRAGMENT_MESSAGE);
    trans.set_extension(ext);
    trans.set_data_length(message_length);
    
    return handle_send_message(trans);
}

bool MessageLayerTLM::send_handshake_flight(uint32_t message_count, uint32_t flight_type) {
    return manage_flight_transmission(message_count, flight_type);
}

uint32_t MessageLayerTLM::process_incoming_fragments(uint32_t fragment_count) {
    if (reassemble_incoming_message(fragment_count)) {
        return 1; // Successfully reassembled 1 message
    }
    return 0;
}

void MessageLayerTLM::set_max_fragment_size(uint32_t size) {
    if (size > 0) {
        max_fragment_size_ = size;
    }
}

void MessageLayerTLM::set_reassembly_timeout(sc_time timeout) {
    reassembly_timeout_ = timeout;
}

void MessageLayerTLM::enable_reliable_delivery_mode(bool enable) {
    reliable_delivery_enabled_ = enable;
}

/**
 * Flight Manager TLM Implementation
 */
FlightManagerTLM::FlightManagerTLM(sc_module_name name)
    : sc_module(name)
    , target_socket("target_socket")
    , enable_retransmission("enable_retransmission")
    , retransmission_timeout_ms("retransmission_timeout_ms")
    , max_retransmissions("max_retransmissions")
    , active_flights_count("active_flights_count")
    , flights_completed("flights_completed")
    , total_retransmissions("total_retransmissions")
{
    target_socket.register_b_transport(this, &FlightManagerTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &FlightManagerTLM::nb_transport_fw);
    
    SC_THREAD(retransmission_timer_process);
    SC_THREAD(flight_monitoring_process);
    SC_THREAD(configuration_monitor_process);
    
    reset_statistics();
}

void FlightManagerTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    message_extension* ext = trans.get_extension<message_extension>();
    
    if (!ext) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    bool success = false;
    sc_time processing_start = sc_time_stamp();
    
    switch (ext->operation) {
        case message_extension::SEND_FLIGHT:
            success = create_flight(ext->flight_type_value);
            break;
            
        case message_extension::RETRANSMIT_FLIGHT:
            success = transmit_flight(ext->flight_type_value);
            break;
            
        default:
            trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
            return;
    }
    
    sc_time processing_time = g_dtls_timing.flight_creation_time;
    delay += processing_time;
    ext->processing_time = processing_time;
    
    trans.set_response_status(success ? tlm::TLM_OK_RESPONSE : tlm::TLM_GENERIC_ERROR_RESPONSE);
}

tlm::tlm_sync_enum FlightManagerTLM::nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                                    tlm::tlm_phase& phase, 
                                                    sc_time& delay) {
    if (phase == tlm::BEGIN_REQ) {
        b_transport(trans, delay);
        phase = tlm::END_REQ;
        return tlm::TLM_COMPLETED;
    }
    
    return tlm::TLM_ACCEPTED;
}

bool FlightManagerTLM::create_flight(uint32_t flight_type) {
    std::lock_guard<std::mutex> lock(flights_mutex_);
    
    auto [it, inserted] = active_flights_.emplace(flight_type, FlightState(flight_type));
    if (!inserted) {
        return false; // Flight already exists
    }
    
    update_flight_statistics(it->second, false);
    
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.flights_created++;
    stats_.active_flights = static_cast<uint8_t>(active_flights_.size());
    
    return true;
}

bool FlightManagerTLM::add_message_to_flight(uint32_t flight_type, uint32_t message_length) {
    std::lock_guard<std::mutex> lock(flights_mutex_);
    
    auto it = active_flights_.find(flight_type);
    if (it == active_flights_.end()) {
        return false;
    }
    
    it->second.message_count++;
    return true;
}

bool FlightManagerTLM::transmit_flight(uint32_t flight_type) {
    std::lock_guard<std::mutex> lock(flights_mutex_);
    
    auto it = active_flights_.find(flight_type);
    if (it == active_flights_.end()) {
        return false;
    }
    
    FlightState& flight = it->second;
    flight.last_transmission_time = sc_time_stamp();
    
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.flights_transmitted++;
    
    return true;
}

bool FlightManagerTLM::acknowledge_flight(uint32_t flight_type) {
    std::lock_guard<std::mutex> lock(flights_mutex_);
    
    auto it = active_flights_.find(flight_type);
    if (it == active_flights_.end()) {
        return false;
    }
    
    FlightState& flight = it->second;
    flight.acknowledged = true;
    
    update_flight_statistics(flight, true);
    active_flights_.erase(it);
    
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.flights_acknowledged++;
    stats_.active_flights = static_cast<uint8_t>(active_flights_.size());
    
    return true;
}

void FlightManagerTLM::set_retransmission_params(sc_time timeout, uint8_t max_retries) {
    retransmission_timeout_ = timeout;
    max_retransmissions_ = max_retries;
}

bool FlightManagerTLM::should_retransmit_flight(const FlightState& flight) const {
    if (!retransmission_enabled_ || flight.acknowledged || flight.failed) {
        return false;
    }
    
    if (flight.retransmission_count >= max_retransmissions_) {
        return false;
    }
    
    sc_time elapsed = sc_time_stamp() - flight.last_transmission_time;
    return elapsed >= retransmission_timeout_;
}

void FlightManagerTLM::perform_flight_retransmission(uint32_t type) {
    // Simplified for SystemC modeling
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_retransmissions++;
}

void FlightManagerTLM::cleanup_completed_flights() {
    std::lock_guard<std::mutex> lock(flights_mutex_);
    
    auto it = active_flights_.begin();
    while (it != active_flights_.end()) {
        if (it->second.acknowledged || it->second.failed) {
            it = active_flights_.erase(it);
        } else {
            ++it;
        }
    }
}

void FlightManagerTLM::update_flight_statistics(const FlightState& flight, bool completed) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    if (completed) {
        stats_.flights_acknowledged++;
        
        sc_time flight_time = sc_time_stamp() - flight.creation_time;
        stats_.total_flight_time += flight_time;
        
        if (stats_.flights_acknowledged > 0) {
            stats_.average_flight_time = sc_time(
                stats_.total_flight_time.to_double() / stats_.flights_acknowledged,
                SC_NS
            );
        }
    }
    
    // Calculate success ratio
    uint32_t total_attempts = stats_.flights_acknowledged + stats_.flights_failed;
    if (total_attempts > 0) {
        stats_.flight_success_ratio = static_cast<double>(stats_.flights_acknowledged) / total_attempts;
    }
    
    // Calculate average retransmissions
    if (stats_.flights_transmitted > 0) {
        stats_.average_retransmissions_per_flight = 
            static_cast<double>(stats_.total_retransmissions) / stats_.flights_transmitted;
    }
}

void FlightManagerTLM::retransmission_timer_process() {
    while (true) {
        wait(retransmission_timeout_ / 4); // Check more frequently than timeout
        
        std::lock_guard<std::mutex> lock(flights_mutex_);
        
        for (auto& [type, flight] : active_flights_) {
            if (should_retransmit_flight(flight)) {
                if (flight.retransmission_count < max_retransmissions_) {
                    flight.retransmission_count++;
                    flight.last_transmission_time = sc_time_stamp();
                    perform_flight_retransmission(type);
                } else {
                    flight.failed = true;
                    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                    stats_.flights_failed++;
                }
            }
        }
    }
}

void FlightManagerTLM::flight_monitoring_process() {
    while (true) {
        wait(1, SC_SEC);
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Update output ports
        active_flights_count.write(stats_.active_flights);
        flights_completed.write(stats_.flights_acknowledged);
        total_retransmissions.write(stats_.total_retransmissions);
        
        // Update max concurrent flights
        if (stats_.active_flights > stats_.max_concurrent_flights) {
            stats_.max_concurrent_flights = stats_.active_flights;
        }
    }
}

void FlightManagerTLM::configuration_monitor_process() {
    while (true) {
        wait(enable_retransmission.value_changed_event() | 
             retransmission_timeout_ms.value_changed_event() |
             max_retransmissions.value_changed_event());
        
        retransmission_enabled_ = enable_retransmission.read();
        
        uint32_t timeout_ms = retransmission_timeout_ms.read();
        if (timeout_ms > 0) {
            retransmission_timeout_ = sc_time(timeout_ms, SC_MS);
        }
        
        uint8_t max_retries = max_retransmissions.read();
        if (max_retries > 0) {
            max_retransmissions_ = max_retries;
        }
    }
}

FlightManagerTLM::FlightStats FlightManagerTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void FlightManagerTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = FlightStats{};
}

/**
 * Message Layer System TLM Implementation
 */
MessageLayerSystemTLM::MessageLayerSystemTLM(sc_module_name name)
    : sc_module(name)
    , external_socket("external_socket")
    , message_layer("message_layer")
    , message_fragmenter("message_fragmenter")
    , message_reassembler("message_reassembler")
    , flight_manager("flight_manager")
    , system_enable("system_enable")
    , system_reset("system_reset")
    , system_ready("system_ready")
    , system_load_percentage("system_load_percentage")
    , overall_efficiency("overall_efficiency")
    , system_ready_(false)
    , system_enabled_(false)
{
    external_socket.register_b_transport(this, &MessageLayerSystemTLM::b_transport);
    
    // Connect internal components
    message_layer.fragmenter_socket.bind(message_fragmenter.target_socket);
    message_layer.reassembler_socket.bind(message_reassembler.target_socket);
    message_layer.flight_mgr_socket.bind(flight_manager.target_socket);
    
    SC_THREAD(system_control_process);
    SC_THREAD(system_monitoring_process);
    SC_THREAD(load_balancing_process);
    
    initialize_system();
}

void MessageLayerSystemTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    if (!system_ready_) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    sc_time processing_start = sc_time_stamp();
    
    // Forward to message layer
    message_layer.b_transport(trans, delay);
    
    sc_time total_time = sc_time_stamp() - processing_start + delay;
    update_system_statistics();
    
    std::lock_guard<std::mutex> lock(system_stats_mutex_);
    system_stats_.total_system_operations++;
    system_stats_.total_processing_time += total_time;
    
    if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
        system_stats_.successful_operations++;
    } else {
        system_stats_.failed_operations++;
    }
}

void MessageLayerSystemTLM::initialize_system() {
    system_start_time_ = sc_time_stamp();
    system_ready_ = true;
    system_enabled_ = true;
    
    std::lock_guard<std::mutex> lock(system_stats_mutex_);
    system_stats_ = SystemStats{};
}

void MessageLayerSystemTLM::reset_system() {
    system_ready_ = false;
    
    message_layer.reset_statistics();
    message_fragmenter.reset_statistics();
    message_reassembler.reset_statistics();
    flight_manager.reset_statistics();
    
    std::lock_guard<std::mutex> lock(system_stats_mutex_);
    system_stats_ = SystemStats{};
    
    initialize_system();
}

void MessageLayerSystemTLM::shutdown_system() {
    system_ready_ = false;
    system_enabled_ = false;
}

void MessageLayerSystemTLM::update_system_statistics() {
    std::lock_guard<std::mutex> lock(system_stats_mutex_);
    
    // Calculate system efficiency
    calculate_system_efficiency();
    
    // Calculate system load
    system_stats_.system_load_percentage = calculate_system_load();
    
    // Calculate uptime
    system_stats_.system_uptime = sc_time_stamp() - system_start_time_;
}

void MessageLayerSystemTLM::calculate_system_efficiency() {
    if (system_stats_.total_system_operations > 0) {
        system_stats_.system_efficiency = 
            static_cast<double>(system_stats_.successful_operations) / system_stats_.total_system_operations;
    }
}

uint32_t MessageLayerSystemTLM::calculate_system_load() {
    // Simplified load calculation based on active operations
    auto msg_stats = message_layer.get_statistics();
    uint32_t active_ops = msg_stats.active_send_operations + msg_stats.active_receive_operations;
    
    // Normalize to percentage (assuming max 100 concurrent operations)
    return std::min(100u, active_ops);
}

void MessageLayerSystemTLM::system_control_process() {
    while (true) {
        wait(system_enable.value_changed_event() | system_reset.value_changed_event());
        
        if (system_reset.read()) {
            reset_system();
        } else {
            system_enabled_ = system_enable.read();
            if (!system_enabled_) {
                shutdown_system();
            } else {
                initialize_system();
            }
        }
    }
}

void MessageLayerSystemTLM::system_monitoring_process() {
    while (true) {
        wait(1, SC_SEC);
        
        update_system_statistics();
        
        std::lock_guard<std::mutex> lock(system_stats_mutex_);
        
        // Update output ports
        system_ready.write(system_ready_);
        system_load_percentage.write(system_stats_.system_load_percentage);
        overall_efficiency.write(system_stats_.system_efficiency);
    }
}

void MessageLayerSystemTLM::load_balancing_process() {
    while (true) {
        wait(5, SC_SEC); // Check load every 5 seconds
        
        uint32_t load = get_system_load();
        if (load > 80) {
            // System overloaded - could implement load balancing here
            // For now, just monitor
        }
    }
}

MessageLayerSystemTLM::SystemStats MessageLayerSystemTLM::get_system_statistics() const {
    std::lock_guard<std::mutex> lock(system_stats_mutex_);
    return system_stats_;
}

bool MessageLayerSystemTLM::is_system_ready() const {
    return system_ready_;
}

uint32_t MessageLayerSystemTLM::get_system_load() const {
    std::lock_guard<std::mutex> lock(system_stats_mutex_);
    return system_stats_.system_load_percentage;
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls