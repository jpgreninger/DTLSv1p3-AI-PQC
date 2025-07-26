#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory.h"
#include "dtls/protocol/handshake.h"
#include <chrono>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <optional>

namespace dtls::v13::protocol {

// Early data state tracking
enum class EarlyDataState : uint8_t {
    NOT_ATTEMPTED = 0,     // No early data attempted
    SENDING = 1,           // Client sending early data
    ACCEPTED = 2,          // Server accepted early data
    REJECTED = 3,          // Server rejected early data
    COMPLETED = 4          // Early data phase completed
};

// Session ticket for resumption and early data
struct SessionTicket {
    std::vector<uint8_t> ticket_data;           // Encrypted ticket content
    std::vector<uint8_t> ticket_nonce;         // Unique nonce for this ticket
    uint32_t ticket_lifetime;                  // Lifetime in seconds
    uint32_t ticket_age_add;                   // Age obfuscation value
    uint32_t max_early_data_size;              // Max early data for this ticket
    std::chrono::steady_clock::time_point issued_time; // When ticket was issued
    
    // Cryptographic state
    std::vector<uint8_t> resumption_master_secret; // For key derivation
    CipherSuite cipher_suite;                       // Cipher suite for this session
    
    SessionTicket() : ticket_lifetime(0), ticket_age_add(0), max_early_data_size(0) {}
    
    bool is_valid() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - issued_time);
        return elapsed.count() < ticket_lifetime && !ticket_data.empty();
    }
    
    uint32_t get_obfuscated_age() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - issued_time);
        return static_cast<uint32_t>(elapsed.count()) + ticket_age_add;
    }
};

// Session ticket storage and management
class DTLS_API SessionTicketManager {
private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, SessionTicket> tickets_; // Key: ticket identity
    std::vector<uint8_t> encryption_key_;                    // Key for encrypting tickets
    size_t max_tickets_per_connection_{10};
    std::chrono::seconds default_ticket_lifetime_{86400};    // 24 hours
    
public:
    SessionTicketManager();
    ~SessionTicketManager() = default;
    
    // Ticket creation and management
    Result<NewSessionTicket> create_ticket(const std::vector<uint8_t>& resumption_master_secret,
                                          CipherSuite cipher_suite,
                                          uint32_t max_early_data_size = 0);
    
    Result<SessionTicket> decrypt_ticket(const std::vector<uint8_t>& encrypted_ticket);
    
    bool store_ticket(const std::string& identity, const SessionTicket& ticket);
    std::optional<SessionTicket> get_ticket(const std::string& identity) const;
    bool remove_ticket(const std::string& identity);
    
    // Cleanup and maintenance
    size_t cleanup_expired_tickets();
    void clear_all_tickets();
    size_t get_ticket_count() const;
    
    // Configuration
    void set_max_tickets_per_connection(size_t max_tickets) { max_tickets_per_connection_ = max_tickets; }
    void set_default_ticket_lifetime(std::chrono::seconds lifetime) { default_ticket_lifetime_ = lifetime; }
    
private:
    Result<std::vector<uint8_t>> encrypt_ticket_data(const SessionTicket& ticket);
    std::string generate_ticket_identity();
};

// Early data replay protection
class DTLS_API EarlyDataReplayProtection {
private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> seen_tickets_;
    std::chrono::seconds replay_window_{60}; // 60 second replay window
    
public:
    EarlyDataReplayProtection() = default;
    ~EarlyDataReplayProtection() = default;
    
    // Replay detection
    bool is_replay(const std::string& ticket_identity, 
                   const std::vector<uint8_t>& early_data_hash);
    
    void record_early_data(const std::string& ticket_identity,
                          const std::vector<uint8_t>& early_data_hash);
    
    // Maintenance
    size_t cleanup_old_entries();
    void set_replay_window(std::chrono::seconds window) { replay_window_ = window; }
    
private:
    std::string create_replay_key(const std::string& ticket_identity,
                                 const std::vector<uint8_t>& early_data_hash);
};

// Early data context and state management
struct EarlyDataContext {
    EarlyDataState state = EarlyDataState::NOT_ATTEMPTED;
    std::optional<SessionTicket> ticket;                // Ticket used for early data
    std::vector<uint8_t> early_data_buffer;            // Buffered early data
    size_t bytes_sent = 0;                              // Bytes of early data sent
    size_t max_allowed = 0;                             // Max early data allowed
    std::chrono::steady_clock::time_point start_time;  // When early data started
    
    // State queries
    bool can_send_early_data() const {
        return state == EarlyDataState::SENDING && bytes_sent < max_allowed;
    }
    
    bool is_early_data_accepted() const {
        return state == EarlyDataState::ACCEPTED;
    }
    
    bool is_early_data_rejected() const {
        return state == EarlyDataState::REJECTED;
    }
    
    bool is_early_data_complete() const {
        return state == EarlyDataState::COMPLETED;
    }
    
    void reset() {
        state = EarlyDataState::NOT_ATTEMPTED;
        ticket.reset();
        early_data_buffer.clear();
        bytes_sent = 0;
        max_allowed = 0;
    }
};

// Early data utility functions
Result<std::vector<uint8_t>> derive_early_traffic_secret(
    const std::vector<uint8_t>& resumption_master_secret,
    const std::vector<uint8_t>& client_hello_hash);

Result<std::vector<uint8_t>> calculate_early_data_hash(
    const std::vector<uint8_t>& early_data);

bool validate_early_data_extensions(const std::vector<Extension>& extensions);

Result<uint32_t> extract_max_early_data_from_ticket(const NewSessionTicket& ticket);

}  // namespace dtls::v13::protocol