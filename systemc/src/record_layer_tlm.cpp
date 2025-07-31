#include "record_layer_tlm.h"
#include <dtls/protocol/record_layer.h>
#include <dtls/types.h>
#include <algorithm>
#include <numeric>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * Anti-Replay Window TLM Implementation
 */
AntiReplayWindowTLM::AntiReplayWindowTLM(sc_module_name name, uint32_t window_size)
    : sc_module(name)
    , target_socket("target_socket")
    , window_size_config("window_size_config")
    , reset_window("reset_window")
    , highest_sequence_number("highest_sequence_number")
    , replay_count("replay_count")
    , window_utilization("window_utilization")
    , window_size_(window_size)
    , highest_sequence_number_(0)
    , window_(window_size, false)
{
    target_socket.register_b_transport(this, &AntiReplayWindowTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &AntiReplayWindowTLM::nb_transport_fw);
    
    SC_THREAD(window_monitor_process);
    SC_THREAD(configuration_process);
    
    reset_statistics();
}

void AntiReplayWindowTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    record_extension* ext = trans.get_extension<record_extension>();
    
    if (!ext || ext->operation != record_extension::ANTI_REPLAY_CHECK) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    sc_time check_start = sc_time_stamp();
    
    // Perform anti-replay check
    bool is_replay = !check_and_update_window(ext->sequence_number);
    ext->replay_detected = is_replay;
    ext->window_position = highest_sequence_number_;
    
    // Calculate processing time
    sc_time check_time = g_dtls_timing.anti_replay_check_time;
    delay += check_time;
    
    // Update statistics
    update_statistics(is_replay, check_time);
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
}

tlm::tlm_sync_enum AntiReplayWindowTLM::nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                                       tlm::tlm_phase& phase, 
                                                       sc_time& delay) {
    if (phase == tlm::BEGIN_REQ) {
        // Non-blocking version - immediate response for anti-replay checks
        b_transport(trans, delay);
        phase = tlm::END_REQ;
        return tlm::TLM_COMPLETED;
    }
    
    return tlm::TLM_ACCEPTED;
}

bool AntiReplayWindowTLM::check_and_update_window(uint64_t sequence_number) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Check if sequence number is too old
    if (sequence_number + window_size_ <= highest_sequence_number_) {
        return false; // Too old, definitely a replay
    }
    
    // Check if sequence number is new highest
    if (sequence_number > highest_sequence_number_) {
        slide_window(sequence_number);
        highest_sequence_number_ = sequence_number;
        window_[0] = true; // Mark as received
        return true;
    }
    
    // Sequence number is within window
    uint64_t position = highest_sequence_number_ - sequence_number;
    if (position < window_.size()) {
        if (window_[position]) {
            return false; // Already received, replay detected
        }
        window_[position] = true;
        return true;
    }
    
    return false;
}

void AntiReplayWindowTLM::slide_window(uint64_t new_highest) {
    uint64_t slide_amount = new_highest - highest_sequence_number_;
    
    if (slide_amount >= window_.size()) {
        // Complete window shift
        std::fill(window_.begin(), window_.end(), false);
    } else {
        // Partial window shift
        std::rotate(window_.begin(), window_.begin() + slide_amount, window_.end());
        std::fill(window_.end() - slide_amount, window_.end(), false);
    }
}

void AntiReplayWindowTLM::update_statistics(bool replay_detected, sc_time check_time) {
    stats_.total_checks++;
    stats_.total_check_time += check_time;
    
    if (replay_detected) {
        stats_.replay_detections++;
    } else {
        stats_.valid_packets++;
    }
    
    stats_.current_highest_seq = highest_sequence_number_;
    
    // Calculate window utilization
    size_t used_slots = std::count(window_.begin(), window_.end(), true);
    stats_.utilization_ratio = static_cast<double>(used_slots) / window_.size();
    
    // Calculate average check time
    if (stats_.total_checks > 0) {
        stats_.average_check_time = sc_time(
            stats_.total_check_time.to_double() / stats_.total_checks,
            SC_NS
        );
    }
}

void AntiReplayWindowTLM::window_monitor_process() {
    while (true) {
        wait(1, SC_MS); // Monitor every millisecond
        
        // Update output ports
        highest_sequence_number.write(highest_sequence_number_);
        replay_count.write(static_cast<uint32_t>(stats_.replay_detections));
        window_utilization.write(stats_.utilization_ratio);
    }
}

void AntiReplayWindowTLM::configuration_process() {
    while (true) {
        wait(window_size_config.value_changed_event() | reset_window.value_changed_event());
        
        if (reset_window.read()) {
            reset();
        }
        
        uint32_t new_size = window_size_config.read();
        if (new_size != window_size_ && new_size > 0) {
            set_window_size(new_size);
        }
    }
}

void AntiReplayWindowTLM::set_window_size(uint32_t size) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    window_size_ = size;
    window_.resize(size, false);
    stats_.current_window_size = size;
}

void AntiReplayWindowTLM::reset() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    highest_sequence_number_ = 0;
    std::fill(window_.begin(), window_.end(), false);
}

AntiReplayWindowTLM::AntiReplayStats AntiReplayWindowTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void AntiReplayWindowTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = AntiReplayStats{};
    stats_.current_window_size = window_size_;
}

/**
 * Sequence Number Manager TLM Implementation  
 */
SequenceNumberManagerTLM::SequenceNumberManagerTLM(sc_module_name name)
    : sc_module(name)
    , target_socket("target_socket")
    , reset_sequence("reset_sequence")
    , current_epoch("current_epoch")
    , current_sequence_number("current_sequence_number")
    , overflow_warning("overflow_warning")
    , remaining_sequence_numbers("remaining_sequence_numbers")
    , current_sequence_number_(0)
    , current_epoch_(0)
{
    target_socket.register_b_transport(this, &SequenceNumberManagerTLM::b_transport);
    
    SC_THREAD(overflow_monitor_process);
    SC_THREAD(epoch_sync_process);
    
    reset_statistics();
}

void SequenceNumberManagerTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    record_extension* ext = trans.get_extension<record_extension>();
    
    if (!ext || ext->operation != record_extension::SEQUENCE_NUMBER_GEN) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    sc_time gen_start = sc_time_stamp();
    
    // Generate next sequence number
    uint64_t next_seq = get_next_sequence_number();
    ext->sequence_number = next_seq;
    
    // Calculate processing time
    sc_time gen_time = g_dtls_timing.sequence_number_gen_time;
    delay += gen_time;
    
    // Update statistics
    update_statistics(gen_time);
    
    trans.set_response_status(tlm::TLM_OK_RESPONSE);
}

uint64_t SequenceNumberManagerTLM::get_next_sequence_number() {
    uint64_t next = current_sequence_number_.fetch_add(1);
    
    if (next >= MAX_SEQUENCE_NUMBER) {
        // Sequence number overflow - should trigger epoch advance
        current_sequence_number_.store(MAX_SEQUENCE_NUMBER);
        return MAX_SEQUENCE_NUMBER;
    }
    
    return next;
}

uint64_t SequenceNumberManagerTLM::get_current_sequence_number() const {
    return current_sequence_number_.load();
}

bool SequenceNumberManagerTLM::would_overflow() const {
    return current_sequence_number_.load() >= OVERFLOW_WARNING_THRESHOLD;
}

void SequenceNumberManagerTLM::reset() {
    current_sequence_number_.store(0);
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.current_sequence = 0;
    stats_.remaining_numbers = MAX_SEQUENCE_NUMBER;
    stats_.overflow_imminent = false;
}

void SequenceNumberManagerTLM::update_statistics(sc_time generation_time) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.numbers_generated++;
    stats_.current_sequence = current_sequence_number_.load();
    stats_.remaining_numbers = MAX_SEQUENCE_NUMBER - stats_.current_sequence;
    stats_.total_generation_time += generation_time;
    
    if (stats_.numbers_generated > 0) {
        stats_.average_generation_time = sc_time(
            stats_.total_generation_time.to_double() / stats_.numbers_generated,
            SC_NS
        );
    }
    
    check_overflow_warning();
}

void SequenceNumberManagerTLM::check_overflow_warning() {
    stats_.overflow_imminent = (stats_.current_sequence >= OVERFLOW_WARNING_THRESHOLD);
}

void SequenceNumberManagerTLM::overflow_monitor_process() {
    while (true) {
        wait(100, SC_MS); // Check every 100ms
        
        uint64_t current = current_sequence_number_.load();
        bool warning = (current >= OVERFLOW_WARNING_THRESHOLD);
        
        // Update output ports
        current_sequence_number.write(current);
        overflow_warning.write(warning);
        remaining_sequence_numbers.write(MAX_SEQUENCE_NUMBER - current);
    }
}

void SequenceNumberManagerTLM::epoch_sync_process() {
    while (true) {
        wait(current_epoch.value_changed_event() | reset_sequence.value_changed_event());
        
        if (reset_sequence.read()) {
            reset();
        }
        
        uint16_t new_epoch = current_epoch.read();
        if (new_epoch != current_epoch_) {
            current_epoch_ = new_epoch;
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.current_epoch = new_epoch;
        }
    }
}

SequenceNumberManagerTLM::SequenceStats SequenceNumberManagerTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void SequenceNumberManagerTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = SequenceStats{};
    stats_.remaining_numbers = MAX_SEQUENCE_NUMBER;
}

/**
 * Record Layer TLM Implementation
 */
RecordLayerTLM::RecordLayerTLM(sc_module_name name)
    : sc_module(name)
    , target_socket("target_socket")
    , crypto_initiator_socket("crypto_initiator_socket")
    , antireplay_socket("antireplay_socket")
    , sequence_socket("sequence_socket")
    , epoch_socket("epoch_socket")
    , connection_id_enabled("connection_id_enabled")
    , current_cipher_suite("current_cipher_suite")
    , records_protected("records_protected")
    , records_unprotected("records_unprotected")
    , replay_attacks_blocked("replay_attacks_blocked")
    , protection_throughput_mbps("protection_throughput_mbps")
    , current_cipher_suite_(CipherSuite::TLS_AES_128_GCM_SHA256)
    , connection_id_enabled_(false)
{
    target_socket.register_b_transport(this, &RecordLayerTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &RecordLayerTLM::nb_transport_fw);
    
    SC_THREAD(record_processing_thread);
    SC_THREAD(performance_monitor_process);
    SC_THREAD(throughput_calculation_process);
    
    reset_statistics();
}

void RecordLayerTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    record_extension* ext = trans.get_extension<record_extension>();
    
    if (!ext) {
        trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    bool success = false;
    sc_time processing_time;
    
    switch (ext->operation) {
        case record_extension::PROTECT_RECORD:
            success = perform_record_protection(trans);
            processing_time = g_dtls_timing.record_protection_time;
            break;
            
        case record_extension::UNPROTECT_RECORD:
            success = perform_record_unprotection(trans);
            processing_time = g_dtls_timing.record_unprotection_time;
            break;
            
        default:
            trans.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
            return;
    }
    
    ext->processing_time = processing_time;
    delay += processing_time;
    
    trans.set_response_status(success ? tlm::TLM_OK_RESPONSE : tlm::TLM_GENERIC_ERROR_RESPONSE);
}

tlm::tlm_sync_enum RecordLayerTLM::nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                                  tlm::tlm_phase& phase, 
                                                  sc_time& delay) {
    if (phase == tlm::BEGIN_REQ) {
        b_transport(trans, delay);
        phase = tlm::END_REQ;
        return tlm::TLM_COMPLETED;
    }
    
    return tlm::TLM_ACCEPTED;
}

bool RecordLayerTLM::perform_record_protection(tlm::tlm_generic_payload& trans) {
    record_extension* ext = trans.get_extension<record_extension>();
    if (!ext) return false;
    
    // Step 1: Get next sequence number
    uint64_t seq_num = get_next_sequence_number();
    ext->sequence_number = seq_num;
    
    // Step 2: Construct AEAD parameters (simplified for SystemC modeling)
    std::vector<uint8_t> nonce = construct_aead_nonce(ext->epoch, seq_num, {});
    
    // Step 3: Perform AEAD encryption (simulated for SystemC modeling)
    size_t payload_size = trans.get_data_length();
    ext->bytes_processed = payload_size;
    
    // For SystemC modeling, we just simulate the processing
    // The actual data transformation is not performed
    
    // Update statistics 
    update_protection_statistics(payload_size, ext->processing_time, true);
    
    return true;
}

bool RecordLayerTLM::perform_record_unprotection(tlm::tlm_generic_payload& trans) {
    record_extension* ext = trans.get_extension<record_extension>();
    if (!ext) return false;
    
    // Step 1: Check anti-replay
    if (!check_anti_replay(ext->sequence_number, ext->epoch)) {
        ext->replay_detected = true;
        return false;
    }
    
    // Step 2: Construct AEAD parameters (simplified for SystemC modeling)
    std::vector<uint8_t> nonce = construct_aead_nonce(ext->epoch, ext->sequence_number, {});
    
    // Step 3: Perform AEAD decryption (simulated for SystemC modeling)
    size_t payload_size = trans.get_data_length();
    ext->bytes_processed = payload_size;
    
    // For SystemC modeling, we just simulate the processing
    // The actual data transformation is not performed
    
    // Update statistics
    update_unprotection_statistics(payload_size, ext->processing_time, true);
    
    return true;
}

bool RecordLayerTLM::check_anti_replay(uint64_t sequence_number, uint16_t epoch) {
    // Create TLM payload with record extension
    tlm::tlm_generic_payload payload;
    record_extension* ext = new record_extension(record_extension::ANTI_REPLAY_CHECK);
    ext->sequence_number = sequence_number;
    ext->epoch = epoch;
    payload.set_extension(ext);
    
    sc_time delay = SC_ZERO_TIME;
    
    // Make TLM call to anti-replay window
    antireplay_socket->b_transport(payload, delay);
    
    return !ext->replay_detected;
}

uint64_t RecordLayerTLM::get_next_sequence_number() {
    // Create TLM payload with record extension
    tlm::tlm_generic_payload payload;
    record_extension* ext = new record_extension(record_extension::SEQUENCE_NUMBER_GEN);
    payload.set_extension(ext);
    
    sc_time delay = SC_ZERO_TIME;
    
    // Make TLM call to sequence number manager
    sequence_socket->b_transport(payload, delay);
    
    return ext->sequence_number;
}

std::vector<uint8_t> RecordLayerTLM::construct_aead_nonce(uint16_t epoch, 
                                                         uint64_t sequence_number,
                                                         const std::vector<uint8_t>& base_iv) {
    // Construct 12-byte nonce for AES-GCM
    std::vector<uint8_t> nonce(12, 0);
    
    // Base IV (first 4 bytes)
    if (base_iv.size() >= 4) {
        std::copy(base_iv.begin(), base_iv.begin() + 4, nonce.begin());
    }
    
    // Epoch (bytes 4-5)
    nonce[4] = static_cast<uint8_t>(epoch >> 8);
    nonce[5] = static_cast<uint8_t>(epoch & 0xFF);
    
    // Sequence number (bytes 6-11)
    for (int i = 0; i < 6; ++i) {
        nonce[6 + i] = static_cast<uint8_t>((sequence_number >> (8 * (5 - i))) & 0xFF);
    }
    
    return nonce;
}

std::vector<uint8_t> RecordLayerTLM::construct_additional_data(const protocol::RecordHeader& header,
                                                              const ConnectionID& cid) {
    std::vector<uint8_t> additional_data;
    
    // Add connection ID if present
    if (connection_id_enabled_ && !cid.empty()) {
        additional_data.insert(additional_data.end(), cid.begin(), cid.end());
    }
    
    // Add record header fields
    additional_data.push_back(static_cast<uint8_t>(header.content_type));
    uint16_t version_val = static_cast<uint16_t>(header.version);
    additional_data.push_back(static_cast<uint8_t>(version_val >> 8));
    additional_data.push_back(static_cast<uint8_t>(version_val & 0xFF));
    additional_data.push_back(static_cast<uint8_t>(header.epoch >> 8));
    additional_data.push_back(static_cast<uint8_t>(header.epoch & 0xFF));
    
    // Add sequence number
    for (int i = 0; i < 6; ++i) {
        additional_data.push_back(static_cast<uint8_t>((header.sequence_number >> (8 * (5 - i))) & 0xFF));
    }
    
    // Add length
    additional_data.push_back(static_cast<uint8_t>(header.length >> 8));
    additional_data.push_back(static_cast<uint8_t>(header.length & 0xFF));
    
    return additional_data;
}

void RecordLayerTLM::record_processing_thread() {
    while (true) {
        wait(1, SC_MS);
        // Background processing tasks
        calculate_throughput();
    }
}

void RecordLayerTLM::performance_monitor_process() {
    while (true) {
        wait(1, SC_SEC); // Update every second
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Update output ports
        records_protected.write(stats_.successful_protections);
        records_unprotected.write(stats_.successful_unprotections);
        replay_attacks_blocked.write(static_cast<uint32_t>(stats_.replay_attacks_detected));
        protection_throughput_mbps.write(stats_.protection_throughput_mbps);
    }
}

void RecordLayerTLM::throughput_calculation_process() {
    while (true) {
        wait(1, SC_SEC);
        calculate_throughput();
    }
}

void RecordLayerTLM::calculate_throughput() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    if (stats_.total_protection_time > SC_ZERO_TIME && stats_.total_bytes_protected > 0) {
        double seconds = stats_.total_protection_time.to_seconds();
        double megabytes = static_cast<double>(stats_.total_bytes_protected) / (1024.0 * 1024.0);
        stats_.protection_throughput_mbps = megabytes / seconds;
    }
    
    if (stats_.total_unprotection_time > SC_ZERO_TIME && stats_.total_bytes_unprotected > 0) {
        double seconds = stats_.total_unprotection_time.to_seconds();
        double megabytes = static_cast<double>(stats_.total_bytes_unprotected) / (1024.0 * 1024.0);
        stats_.unprotection_throughput_mbps = megabytes / seconds;
    }
}

void RecordLayerTLM::update_protection_statistics(size_t bytes_processed, sc_time processing_time, bool success) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_protect_operations++;
    stats_.total_bytes_protected += bytes_processed;
    stats_.total_protection_time += processing_time;
    
    if (success) {
        stats_.successful_protections++;
    } else {
        stats_.failed_protections++;
    }
    
    if (stats_.total_protect_operations > 0) {
        stats_.average_protection_time = sc_time(
            stats_.total_protection_time.to_double() / stats_.total_protect_operations,
            SC_NS
        );
    }
}

void RecordLayerTLM::update_unprotection_statistics(size_t bytes_processed, sc_time processing_time, bool success) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_unprotect_operations++;
    stats_.total_bytes_unprotected += bytes_processed;
    stats_.total_unprotection_time += processing_time;
    
    if (success) {
        stats_.successful_unprotections++;
    } else {
        stats_.failed_unprotections++;
    }
    
    if (stats_.total_unprotect_operations > 0) {
        stats_.average_unprotection_time = sc_time(
            stats_.total_unprotection_time.to_double() / stats_.total_unprotect_operations,
            SC_NS
        );
    }
}

RecordLayerTLM::RecordLayerStats RecordLayerTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void RecordLayerTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = RecordLayerStats{};
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls