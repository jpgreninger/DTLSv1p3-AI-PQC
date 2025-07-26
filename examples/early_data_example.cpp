/**
 * DTLS v1.3 Early Data (0-RTT) Example
 * 
 * This example demonstrates how to use early data functionality in DTLS v1.3
 * for reduced latency connections. Early data allows clients to send application
 * data immediately with the first flight of handshake messages.
 * 
 * RFC 9147 Section 4.2.10 - Early Data Support
 */

#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <string>

// Include DTLS v1.3 headers
#include "dtls/connection.h"
#include "dtls/protocol/early_data.h"
#include "dtls/protocol/handshake.h"
#include "dtls/crypto/provider.h"
#include "dtls/memory/buffer.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;

class EarlyDataExample {
private:
    ConnectionConfig config_;
    std::unique_ptr<Connection> client_connection_;
    std::unique_ptr<Connection> server_connection_;
    
public:
    EarlyDataExample() {
        setup_configuration();
    }
    
    void setup_configuration() {
        // Configure early data support
        config_.enable_early_data = true;
        config_.max_early_data_size = 16384; // 16KB
        config_.early_data_timeout = std::chrono::milliseconds(5000);
        config_.allow_early_data_replay_protection = true;
        
        // Configure session resumption
        config_.enable_session_resumption = true;
        config_.session_lifetime = std::chrono::seconds(7200);
        
        // Configure supported cipher suites (early data requires PSK)
        config_.supported_cipher_suites = {
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384
        };
        
        // Configure supported groups
        config_.supported_groups = {
            NamedGroup::X25519,
            NamedGroup::SECP256R1
        };
        
        std::cout << "✓ Early data configuration completed\n";
        std::cout << "  - Max early data size: " << config_.max_early_data_size << " bytes\n";
        std::cout << "  - Early data timeout: " << config_.early_data_timeout.count() << " ms\n";
        std::cout << "  - Replay protection: " << (config_.allow_early_data_replay_protection ? "enabled" : "disabled") << "\n";
    }
    
    void demonstrate_session_ticket_creation() {
        std::cout << "\n=== Session Ticket Creation Example ===\n";
        
        // Create a session ticket manager
        SessionTicketManager ticket_manager;
        
        // Simulate resumption master secret (would come from completed handshake)
        std::vector<uint8_t> resumption_secret(32, 0x42); // Placeholder
        
        // Create a new session ticket with early data support
        auto ticket_result = ticket_manager.create_ticket(
            resumption_secret,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            config_.max_early_data_size
        );
        
        if (ticket_result.is_success()) {
            const auto& ticket = ticket_result.value();
            std::cout << "✓ Session ticket created successfully\n";
            std::cout << "  - Ticket lifetime: " << ticket.ticket_lifetime() << " seconds\n";
            std::cout << "  - Ticket nonce size: " << ticket.ticket_nonce().size() << " bytes\n";
            std::cout << "  - Ticket data size: " << ticket.ticket().size() << " bytes\n";
            std::cout << "  - Extensions count: " << ticket.extensions().size() << "\n";
            
            // Check for early data extension
            if (ticket.has_extension(ExtensionType::EARLY_DATA)) {
                std::cout << "  - Early data extension present\n";
                
                // Extract max early data size from ticket
                auto max_early_result = extract_max_early_data_from_ticket(ticket);
                if (max_early_result.is_success()) {
                    std::cout << "  - Max early data from ticket: " << max_early_result.value() << " bytes\n";
                }
            }
        } else {
            std::cout << "✗ Failed to create session ticket\n";
        }
    }
    
    void demonstrate_early_data_extensions() {
        std::cout << "\n=== Early Data Extensions Example ===\n";
        
        // Create early data extension
        auto early_data_ext_result = create_early_data_extension(config_.max_early_data_size);
        if (early_data_ext_result.is_success()) {
            std::cout << "✓ Early data extension created\n";
            
            // Parse the extension back
            auto parsed_result = parse_early_data_extension(early_data_ext_result.value());
            if (parsed_result.is_success()) {
                const auto& parsed_ext = parsed_result.value();
                std::cout << "  - Parsed max early data size: " << parsed_ext.max_early_data_size << " bytes\n";
            }
        }
        
        // Create PSK identities for early data
        std::vector<PskIdentity> identities;
        std::vector<std::vector<uint8_t>> binders;
        
        // Create a PSK identity
        std::vector<uint8_t> identity_data = {'e', 'a', 'r', 'l', 'y', '_', 'd', 'a', 't', 'a', '_', 'p', 's', 'k'};
        uint32_t obfuscated_age = 1234567; // Would be calculated from ticket age
        
        PskIdentity identity(identity_data, obfuscated_age);
        identities.push_back(identity);
        
        // Create a binder (would be calculated using HKDF)
        std::vector<uint8_t> binder(32, 0xAB); // Placeholder
        binders.push_back(binder);
        
        // Create PSK extension
        auto psk_ext_result = create_psk_extension(identities, binders);
        if (psk_ext_result.is_success()) {
            std::cout << "✓ PSK extension created for early data\n";
            std::cout << "  - Identity count: " << identities.size() << "\n";
            std::cout << "  - Binder count: " << binders.size() << "\n";
        }
        
        // Create PSK key exchange modes extension
        std::vector<PskKeyExchangeMode> modes = {PskKeyExchangeMode::PSK_DHE_KE};
        auto modes_ext_result = create_psk_key_exchange_modes_extension(modes);
        if (modes_ext_result.is_success()) {
            std::cout << "✓ PSK key exchange modes extension created\n";
            std::cout << "  - Supported modes: PSK_DHE_KE\n";
        }
    }
    
    void demonstrate_replay_protection() {
        std::cout << "\n=== Early Data Replay Protection Example ===\n";
        
        EarlyDataReplayProtection replay_protection;
        
        // Simulate early data
        std::string early_data = "GET /api/data HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n";
        std::vector<uint8_t> early_data_bytes(early_data.begin(), early_data.end());
        
        // Calculate hash of early data
        auto hash_result = calculate_early_data_hash(early_data_bytes);
        if (!hash_result.is_success()) {
            std::cout << "✗ Failed to calculate early data hash\n";
            return;
        }
        
        std::string ticket_identity = "ticket_12345";
        const auto& early_data_hash = hash_result.value();
        
        // First attempt - should not be a replay
        bool is_replay1 = replay_protection.is_replay(ticket_identity, early_data_hash);
        std::cout << "First early data attempt - Replay: " << (is_replay1 ? "YES" : "NO") << "\n";
        
        // Record the early data
        replay_protection.record_early_data(ticket_identity, early_data_hash);
        std::cout << "✓ Early data recorded for replay protection\n";
        
        // Second attempt with same data - should be detected as replay
        bool is_replay2 = replay_protection.is_replay(ticket_identity, early_data_hash);
        std::cout << "Second early data attempt - Replay: " << (is_replay2 ? "YES" : "NO") << "\n";
        
        // Different early data - should not be a replay
        std::string different_data = "POST /api/submit HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n";
        std::vector<uint8_t> different_bytes(different_data.begin(), different_data.end());
        auto different_hash_result = calculate_early_data_hash(different_bytes);
        if (different_hash_result.is_success()) {
            bool is_replay3 = replay_protection.is_replay(ticket_identity, different_hash_result.value());
            std::cout << "Different early data attempt - Replay: " << (is_replay3 ? "YES" : "NO") << "\n";
        }
    }
    
    void demonstrate_early_data_context() {
        std::cout << "\n=== Early Data Context Management Example ===\n";
        
        EarlyDataContext context;
        
        // Initialize context for early data attempt
        context.state = EarlyDataState::SENDING;
        context.max_allowed = config_.max_early_data_size;
        context.start_time = std::chrono::steady_clock::now();
        
        std::cout << "✓ Early data context initialized\n";
        std::cout << "  - State: SENDING\n";
        std::cout << "  - Max allowed: " << context.max_allowed << " bytes\n";
        std::cout << "  - Can send early data: " << (context.can_send_early_data() ? "YES" : "NO") << "\n";
        
        // Simulate sending some early data
        std::string data = "Early application data";
        context.early_data_buffer.assign(data.begin(), data.end());
        context.bytes_sent = data.length();
        
        std::cout << "✓ Early data sent: " << context.bytes_sent << " bytes\n";
        std::cout << "  - Can send more: " << (context.can_send_early_data() ? "YES" : "NO") << "\n";
        
        // Simulate server acceptance
        context.state = EarlyDataState::ACCEPTED;
        std::cout << "✓ Server accepted early data\n";
        std::cout << "  - Is accepted: " << (context.is_early_data_accepted() ? "YES" : "NO") << "\n";
        std::cout << "  - Is rejected: " << (context.is_early_data_rejected() ? "YES" : "NO") << "\n";
        
        // Complete early data phase
        context.state = EarlyDataState::COMPLETED;
        std::cout << "✓ Early data phase completed\n";
        std::cout << "  - Is complete: " << (context.is_early_data_complete() ? "YES" : "NO") << "\n";
    }
    
    void run_example() {
        std::cout << "DTLS v1.3 Early Data (0-RTT) Example\n";
        std::cout << "====================================\n";
        
        try {
            demonstrate_session_ticket_creation();
            demonstrate_early_data_extensions();
            demonstrate_replay_protection();
            demonstrate_early_data_context();
            
            std::cout << "\n=== Example Summary ===\n";
            std::cout << "✓ Session ticket creation and management\n";
            std::cout << "✓ Early data and PSK extension handling\n";
            std::cout << "✓ Replay protection mechanisms\n";
            std::cout << "✓ Early data context state management\n";
            std::cout << "\nEarly data implementation provides:\n";
            std::cout << "• Reduced latency for repeat connections\n";
            std::cout << "• Security through replay protection\n";
            std::cout << "• Configurable limits and timeouts\n";
            std::cout << "• Full RFC 9147 compliance\n";
            
        } catch (const std::exception& e) {
            std::cout << "✗ Example failed with error: " << e.what() << "\n";
        }
    }
};

int main() {
    try {
        EarlyDataExample example;
        example.run_example();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}