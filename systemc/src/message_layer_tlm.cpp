#include "message_layer_tlm.h"
#include <algorithm>
#include <numeric>

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
    message_transaction* msg_trans = reinterpret_cast<message_transaction*>(trans.get_data_ptr());
    
    if (!msg_trans || msg_trans->operation != message_transaction::REASSEMBLE_MESSAGE) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    if (!reassembly_enabled_) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    sc_time processing_start = sc_time_stamp();
    
    // Process all fragments in the transaction
    bool all_successful = true;
    for (const auto& fragment : msg_trans->fragments) {
        if (!process_fragment(fragment)) {
            all_successful = false;
        }
    }
    
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
    
    // Update transaction with completed messages
    for (uint16_t seq : completed_sequences) {
        msg_trans->handshake_message = get_completed_message(seq);
        msg_trans->message_complete = true;
    }
    
    // Calculate processing time
    sc_time processing_time = g_dtls_timing.fragment_reassembly_time;
    processing_time += utils::calculate_processing_time(
        msg_trans->fragments.size() * 100, // Approximate fragment overhead
        sc_time(0, SC_NS),
        sc_time(1, SC_NS) // 1ns per fragment
    );
    
    delay += processing_time;
    msg_trans->processing_time = processing_time;
    
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

bool MessageReassemblerTLM::process_fragment(const protocol::MessageFragment& fragment) {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    uint16_t message_seq = fragment.message_seq;
    
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
        it->second.total_length = fragment.total_length;
    }
    
    MessageReassemblyState& state = it->second;
    state.last_fragment_time = sc_time_stamp();
    
    // Check for duplicate fragment
    for (const auto& existing : state.fragments) {
        if (existing.fragment.fragment_offset == fragment.fragment_offset &&
            existing.fragment.fragment_length == fragment.fragment_length) {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.duplicate_fragments++;
            return true; // Not an error, just ignore duplicate
        }
    }
    
    // Add fragment to reassembly state
    state.fragments.emplace_back(fragment);
    
    // Check if fragments are out of order
    if (state.fragments.size() > 1) {
        auto last_it = state.fragments.end() - 1;
        auto second_last_it = state.fragments.end() - 2;
        if (last_it->fragment.fragment_offset < second_last_it->fragment.fragment_offset) {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.out_of_order_fragments++;
        }
    }
    
    return true;
}

bool MessageReassemblerTLM::check_reassembly_complete(uint16_t message_seq) {
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
                  return a->fragment.fragment_offset < b->fragment.fragment_offset;
              });
    
    // Check for complete coverage
    uint32_t expected_offset = 0;
    for (const auto* frag_info : sorted_fragments) {
        if (frag_info->fragment.fragment_offset != expected_offset) {
            return false; // Gap detected
        }
        expected_offset += frag_info->fragment.fragment_length;
    }
    
    return expected_offset == state.total_length;
}

protocol::HandshakeMessage MessageReassemblerTLM::assemble_message(uint16_t message_seq) {
    std::lock_guard<std::mutex> lock(reassembly_mutex_);
    
    auto it = active_reassemblies_.find(message_seq);
    if (it == active_reassemblies_.end() || !it->second.complete) {
        return protocol::HandshakeMessage{}; // Return empty message
    }
    
    MessageReassemblyState& state = it->second;
    
    // Sort fragments by offset
    std::sort(state.fragments.begin(), state.fragments.end(),
              [](const FragmentInfo& a, const FragmentInfo& b) {
                  return a.fragment.fragment_offset < b.fragment.fragment_offset;
              });
    
    // Assemble complete message data
    memory::Buffer complete_data(state.total_length);
    uint32_t current_offset = 0;
    
    for (const auto& frag_info : state.fragments) {
        const auto& fragment = frag_info.fragment;
        std::memcpy(complete_data.mutable_data() + current_offset,
                   fragment.fragment_data.data(),
                   fragment.fragment_length);
        current_offset += fragment.fragment_length;
    }
    
    // Create handshake message (simplified)
    protocol::HandshakeMessage message;
    // In a real implementation, would deserialize from complete_data
    
    // Update statistics
    update_statistics(state, true);
    
    // Clean up completed reassembly
    active_reassemblies_.erase(it);
    
    return message;
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
                stats_.total_reassembly_time.get_time_unit()
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
    message_transaction* msg_trans = reinterpret_cast<message_transaction*>(trans.get_data_ptr());
    
    if (!msg_trans || msg_trans->operation != message_transaction::FRAGMENT_MESSAGE) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    if (!fragmentation_enabled_) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    sc_time processing_start = sc_time_stamp();
    
    // Perform message fragmentation
    std::vector<protocol::MessageFragment> fragments = perform_fragmentation(
        msg_trans->handshake_message, msg_trans->message_sequence);
    
    msg_trans->fragments = std::move(fragments);
    msg_trans->fragment_count = msg_trans->fragments.size();
    
    // Calculate processing time
    sc_time processing_time = g_dtls_timing.message_fragmentation_time;
    size_t message_size = msg_trans->handshake_message.serialized_size();
    processing_time += utils::calculate_processing_time(
        message_size, sc_time(0, SC_NS), sc_time(1, SC_NS) // 1ns per byte
    );
    
    delay += processing_time;
    msg_trans->processing_time = processing_time;
    
    // Update statistics
    update_statistics(message_size, msg_trans->fragment_count, processing_time);
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
}

std::vector<protocol::MessageFragment> MessageFragmenterTLM::perform_fragmentation(
    const protocol::HandshakeMessage& message, uint16_t message_seq) {
    
    std::vector<protocol::MessageFragment> fragments;
    
    // Serialize the message to get raw data
    size_t message_size = message.serialized_size();
    memory::Buffer message_data(message_size);
    // In real implementation: message.serialize(message_data);
    
    // Calculate fragment parameters
    size_t fragment_header_size = 12; // DTLS handshake message header size
    size_t payload_per_fragment = max_fragment_size_ - fragment_header_size;
    size_t total_fragments = (message_size + payload_per_fragment - 1) / payload_per_fragment;
    
    // Create fragments
    for (size_t i = 0; i < total_fragments; ++i) {
        uint32_t offset = static_cast<uint32_t>(i * payload_per_fragment);
        uint32_t remaining = static_cast<uint32_t>(message_size - offset);
        uint32_t fragment_length = std::min(remaining, static_cast<uint32_t>(payload_per_fragment));
        
        // Create fragment data
        memory::Buffer fragment_data(fragment_length);
        std::memcpy(fragment_data.mutable_data(), 
                   message_data.data() + offset, 
                   fragment_length);
        
        // Create fragment
        protocol::MessageFragment fragment(
            message_seq,
            offset,
            fragment_length,
            static_cast<uint32_t>(message_size),
            std::move(fragment_data)
        );
        
        fragments.push_back(std::move(fragment));
    }
    
    return fragments;
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
            stats_.total_fragmentation_time.get_time_unit()
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
    message_transaction* msg_trans = reinterpret_cast<message_transaction*>(trans.get_data_ptr());
    
    if (!msg_trans) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    bool success = false;
    sc_time processing_start = sc_time_stamp();
    
    switch (msg_trans->operation) {
        case message_transaction::SEND_FLIGHT:
            success = handle_flight_operation(*msg_trans);
            active_send_operations_++;
            break;
            
        case message_transaction::RECEIVE_FRAGMENT:
            success = handle_receive_fragments(*msg_trans);
            active_receive_operations_++;
            break;
            
        case message_transaction::FRAGMENT_MESSAGE:
        case message_transaction::REASSEMBLE_MESSAGE:
            success = handle_send_message(*msg_trans);
            break;
            
        default:
            trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
            return;
    }
    
    sc_time processing_time = sc_time_stamp() - processing_start;
    msg_trans->processing_time = processing_time;
    delay += processing_time;
    
    // Update operation counters
    if (msg_trans->operation == message_transaction::SEND_FLIGHT) {
        active_send_operations_--;
    } else if (msg_trans->operation == message_transaction::RECEIVE_FRAGMENT) {
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

bool MessageLayerTLM::handle_send_message(message_transaction& trans) {
    uint16_t message_seq = next_message_sequence_.fetch_add(1);
    
    // Fragment the message
    bool fragment_success = fragment_and_send_message(trans.handshake_message, message_seq);
    
    if (fragment_success) {
        size_t message_size = trans.handshake_message.serialized_size();
        update_send_statistics(message_size, trans.processing_time, true);
    } else {
        update_send_statistics(0, trans.processing_time, false);
    }
    
    return fragment_success;
}

bool MessageLayerTLM::handle_receive_fragments(message_transaction& trans) {
    bool success = reassemble_incoming_message(trans.fragments);
    
    if (success) {
        trans.message_complete = true;
        update_receive_statistics(trans.fragments.size(), trans.processing_time, true);
    } else {
        update_receive_statistics(trans.fragments.size(), trans.processing_time, false);
    }
    
    return success;
}

bool MessageLayerTLM::handle_flight_operation(message_transaction& trans) {
    if (trans.operation != message_transaction::SEND_FLIGHT) {
        return false;
    }
    
    // Create flight with single message (simplified)
    std::vector<protocol::HandshakeMessage> messages = {trans.handshake_message};
    
    bool success = manage_flight_transmission(messages, trans.flight_type);
    
    if (success) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.flights_transmitted++;
    }
    
    return success;
}

bool MessageLayerTLM::fragment_and_send_message(const protocol::HandshakeMessage& message, uint16_t seq) {
    // Create fragmentation transaction
    message_transaction frag_trans(message_transaction::FRAGMENT_MESSAGE);
    frag_trans.handshake_message = message;
    frag_trans.message_sequence = seq;
    frag_trans.max_fragment_size = max_fragment_size_;
    
    // Make TLM call to fragmenter
    tlm::tlm_generic_payload payload;
    payload.set_data_ptr(reinterpret_cast<unsigned char*>(&frag_trans));
    sc_time delay = SC_ZERO_TIME;
    
    fragmenter_socket->b_transport(payload, delay);
    
    if (payload.get_response_status() != tlm::TLM_OK_RESPONSE) {
        return false;
    }
    
    // Send fragments through record layer
    for (const auto& fragment : frag_trans.fragments) {
        // In real implementation, would send each fragment via record layer
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.fragments_sent++;
    }
    
    return true;
}

bool MessageLayerTLM::reassemble_incoming_message(const std::vector<protocol::MessageFragment>& fragments) {
    // Create reassembly transaction
    message_transaction reassembly_trans(message_transaction::REASSEMBLE_MESSAGE);
    reassembly_trans.fragments = fragments;
    
    // Make TLM call to reassembler
    tlm::tlm_generic_payload payload;
    payload.set_data_ptr(reinterpret_cast<unsigned char*>(&reassembly_trans));
    sc_time delay = SC_ZERO_TIME;
    
    reassembler_socket->b_transport(payload, delay);
    
    bool success = (payload.get_response_status() == tlm::TLM_OK_RESPONSE);
    
    if (success && reassembly_trans.message_complete) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_reassembled++;
        stats_.fragments_received += fragments.size();
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
            stats_.total_send_time.get_time_unit()
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
            stats_.total_receive_time.get_time_unit()
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

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls