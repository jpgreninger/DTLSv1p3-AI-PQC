#include "dtls/protocol/early_data.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/crypto_utils.h"
#include "dtls/error.h"
#include <algorithm>
#include <random>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

namespace dtls::v13::protocol {

// Helper functions for byte order conversion
inline void copy_to_byte_buffer(std::byte* dest, const void* src, size_t size) {
    std::memcpy(dest, src, size);
}

inline void copy_from_byte_buffer(void* dest, const std::byte* src, size_t size) {
    std::memcpy(dest, src, size);
}

// SessionTicketManager implementation
SessionTicketManager::SessionTicketManager() {
    // Generate a random encryption key for tickets
    encryption_key_.resize(32); // 256-bit key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    for (auto& byte : encryption_key_) {
        byte = dis(gen);
    }
}

Result<NewSessionTicket> SessionTicketManager::create_ticket(
    const std::vector<uint8_t>& resumption_master_secret,
    CipherSuite cipher_suite,
    uint32_t max_early_data_size) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Create the session ticket structure
    SessionTicket ticket;
    ticket.resumption_master_secret = resumption_master_secret;
    ticket.cipher_suite = cipher_suite;
    ticket.max_early_data_size = max_early_data_size;
    ticket.ticket_lifetime = static_cast<uint32_t>(default_ticket_lifetime_.count());
    ticket.issued_time = std::chrono::steady_clock::now();
    
    // Generate random values
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> age_dis;
    ticket.ticket_age_add = age_dis(gen);
    
    // Generate unique nonce
    ticket.ticket_nonce.resize(16);
    std::uniform_int_distribution<uint8_t> byte_dis(0, 255);
    for (auto& byte : ticket.ticket_nonce) {
        byte = byte_dis(gen);
    }
    
    // Encrypt the ticket data
    auto encrypted_result = encrypt_ticket_data(ticket);
    if (!encrypted_result.is_success()) {
        return Result<NewSessionTicket>(encrypted_result.error());
    }
    ticket.ticket_data = encrypted_result.value();
    
    // Store the ticket
    std::string identity = generate_ticket_identity();
    tickets_[identity] = ticket;
    
    // Create the NewSessionTicket message
    NewSessionTicket new_ticket;
    new_ticket.set_ticket_lifetime(ticket.ticket_lifetime);
    new_ticket.set_ticket_age_add(ticket.ticket_age_add);
    new_ticket.set_ticket_nonce(ticket.ticket_nonce);
    new_ticket.set_ticket(ticket.ticket_data);
    
    // Add early data extension if max_early_data_size > 0
    if (max_early_data_size > 0) {
        auto early_data_ext_result = create_early_data_extension(max_early_data_size);
        if (early_data_ext_result.is_success()) {
            new_ticket.add_extension(early_data_ext_result.value());
        }
    }
    
    return Result<NewSessionTicket>(std::move(new_ticket));
}

Result<SessionTicket> SessionTicketManager::decrypt_ticket(const std::vector<uint8_t>& encrypted_ticket) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (encrypted_ticket.size() < 12) { // Need at least nonce (12 bytes)
        return Result<SessionTicket>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    // Get crypto provider for AEAD decryption
    auto provider = dtls::v13::crypto::ProviderFactory::instance().create_default_provider();
    if (!provider.is_success()) {
        return Result<SessionTicket>(provider.error());
    }
    
    // Extract nonce (first 12 bytes), ciphertext, and tag (last 16 bytes for AES-GCM)
    constexpr size_t TAG_SIZE = 16;
    if (encrypted_ticket.size() < 12 + TAG_SIZE) {
        return Result<SessionTicket>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    std::vector<uint8_t> nonce(encrypted_ticket.begin(), encrypted_ticket.begin() + 12);
    std::vector<uint8_t> ciphertext(encrypted_ticket.begin() + 12, encrypted_ticket.end() - TAG_SIZE);
    std::vector<uint8_t> tag(encrypted_ticket.end() - TAG_SIZE, encrypted_ticket.end());
    
    // Setup AEAD parameters for decryption
    dtls::v13::crypto::AEADDecryptionParams aead_params;
    aead_params.key = encryption_key_;
    aead_params.nonce = nonce;
    aead_params.ciphertext = ciphertext;
    aead_params.tag = tag;
    aead_params.cipher = AEADCipher::AES_128_GCM;
    
    // Decrypt the ticket
    auto decrypt_result = provider.value()->decrypt_aead(aead_params);
    if (!decrypt_result.is_success()) {
        return Result<SessionTicket>(DTLSError::DECRYPT_ERROR);
    }
    
    std::vector<uint8_t> plaintext = decrypt_result.value();
    if (plaintext.size() < 6) { // Need at least cipher suite (2) + max_early_data (4)
        return Result<SessionTicket>(DTLSError::INVALID_MESSAGE_FORMAT);
    }
    
    // Parse the decrypted ticket data
    SessionTicket ticket;
    size_t offset = 0;
    
    // Extract resumption master secret (everything except last 6 bytes)
    size_t secret_len = plaintext.size() - 6;
    ticket.resumption_master_secret.assign(plaintext.begin(), plaintext.begin() + secret_len);
    offset += secret_len;
    
    // Extract cipher suite (2 bytes)
    uint16_t cipher_be;
    std::memcpy(&cipher_be, plaintext.data() + offset, 2);
    ticket.cipher_suite = static_cast<CipherSuite>(ntohs(cipher_be));
    offset += 2;
    
    // Extract max early data size (4 bytes)
    uint32_t max_early_be;
    std::memcpy(&max_early_be, plaintext.data() + offset, 4);
    ticket.max_early_data_size = ntohl(max_early_be);
    
    ticket.issued_time = std::chrono::steady_clock::now(); // Reset timestamp for security
    ticket.ticket_lifetime = static_cast<uint32_t>(default_ticket_lifetime_.count());
    ticket.ticket_data = encrypted_ticket;
    
    return Result<SessionTicket>(std::move(ticket));
}

bool SessionTicketManager::store_ticket(const std::string& identity, const SessionTicket& ticket) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (tickets_.size() >= max_tickets_per_connection_) {
        // Remove oldest ticket
        auto oldest = std::min_element(tickets_.begin(), tickets_.end(),
            [](const auto& a, const auto& b) {
                return a.second.issued_time < b.second.issued_time;
            });
        if (oldest != tickets_.end()) {
            tickets_.erase(oldest);
        }
    }
    
    tickets_[identity] = ticket;
    return true;
}

std::optional<SessionTicket> SessionTicketManager::get_ticket(const std::string& identity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = tickets_.find(identity);
    if (it != tickets_.end() && it->second.is_valid()) {
        return it->second;
    }
    
    return std::nullopt;
}

bool SessionTicketManager::remove_ticket(const std::string& identity) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tickets_.erase(identity) > 0;
}

size_t SessionTicketManager::cleanup_expired_tickets() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t removed = 0;
    auto it = tickets_.begin();
    while (it != tickets_.end()) {
        if (!it->second.is_valid()) {
            it = tickets_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    
    return removed;
}

void SessionTicketManager::clear_all_tickets() {
    std::lock_guard<std::mutex> lock(mutex_);
    tickets_.clear();
}

size_t SessionTicketManager::get_ticket_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tickets_.size();
}

Result<std::vector<uint8_t>> SessionTicketManager::encrypt_ticket_data(const SessionTicket& ticket) {
    // Get crypto provider for proper AEAD encryption
    auto provider = dtls::v13::crypto::ProviderFactory::instance().create_default_provider();
    if (!provider.is_success()) {
        return Result<std::vector<uint8_t>>(provider.error());
    }
    
    std::vector<uint8_t> plaintext;
    
    // Serialize ticket data
    plaintext.insert(plaintext.end(), ticket.resumption_master_secret.begin(), ticket.resumption_master_secret.end());
    
    // Add cipher suite (2 bytes)
    uint16_t cipher_be = htons(static_cast<uint16_t>(ticket.cipher_suite));
    plaintext.insert(plaintext.end(), reinterpret_cast<uint8_t*>(&cipher_be), 
                     reinterpret_cast<uint8_t*>(&cipher_be) + 2);
    
    // Add max early data size (4 bytes)
    uint32_t max_early_be = htonl(ticket.max_early_data_size);
    plaintext.insert(plaintext.end(), reinterpret_cast<uint8_t*>(&max_early_be),
                     reinterpret_cast<uint8_t*>(&max_early_be) + 4);
    
    // Generate random nonce for AEAD
    std::vector<uint8_t> nonce(12); // 96-bit nonce for AES-GCM
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    for (auto& byte : nonce) {
        byte = dis(gen);
    }
    
    // Use AES-128-GCM encryption
    dtls::v13::crypto::AEADEncryptionParams aead_params;
    aead_params.key = encryption_key_;
    aead_params.nonce = nonce;
    aead_params.plaintext = plaintext;
    aead_params.cipher = AEADCipher::AES_128_GCM;
    
    auto encrypt_result = provider.value()->encrypt_aead(aead_params);
    if (!encrypt_result.is_success()) {
        return Result<std::vector<uint8_t>>(encrypt_result.error());
    }
    
    // Prepend nonce to encrypted data for decryption
    auto encryption_output = encrypt_result.value();
    std::vector<uint8_t> final_encrypted = nonce;
    final_encrypted.insert(final_encrypted.end(), encryption_output.ciphertext.begin(), encryption_output.ciphertext.end());
    final_encrypted.insert(final_encrypted.end(), encryption_output.tag.begin(), encryption_output.tag.end());
    
    return Result<std::vector<uint8_t>>(std::move(final_encrypted));
}

std::string SessionTicketManager::generate_ticket_identity() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    std::vector<uint8_t> identity(16); // 128-bit identity
    for (auto& byte : identity) {
        byte = dis(gen);
    }
    
    // Convert to hex string
    std::string identity_str;
    identity_str.reserve(32);
    for (uint8_t byte : identity) {
        char hex[3];
        std::sprintf(hex, "%02x", byte);
        identity_str += hex;
    }
    
    return identity_str;
}

// EarlyDataReplayProtection implementation
bool EarlyDataReplayProtection::is_replay(const std::string& ticket_identity,
                                         const std::vector<uint8_t>& early_data_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string replay_key = create_replay_key(ticket_identity, early_data_hash);
    auto it = seen_tickets_.find(replay_key);
    
    if (it != seen_tickets_.end()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        
        // If within replay window, it's a replay
        return elapsed < replay_window_;
    }
    
    return false;
}

void EarlyDataReplayProtection::record_early_data(const std::string& ticket_identity,
                                                 const std::vector<uint8_t>& early_data_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string replay_key = create_replay_key(ticket_identity, early_data_hash);
    seen_tickets_[replay_key] = std::chrono::steady_clock::now();
}

size_t EarlyDataReplayProtection::cleanup_old_entries() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    size_t removed = 0;
    
    auto it = seen_tickets_.begin();
    while (it != seen_tickets_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (elapsed >= replay_window_) {
            it = seen_tickets_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    
    return removed;
}

std::string EarlyDataReplayProtection::create_replay_key(const std::string& ticket_identity,
                                                       const std::vector<uint8_t>& early_data_hash) {
    std::string key = ticket_identity + ":";
    for (uint8_t byte : early_data_hash) {
        char hex[3];
        std::sprintf(hex, "%02x", byte);
        key += hex;
    }
    return key;
}

// Utility function implementations
Result<std::vector<uint8_t>> derive_early_traffic_secret(
    const std::vector<uint8_t>& resumption_master_secret,
    const std::vector<uint8_t>& client_hello_hash) {
    
    // RFC 9147 Section 4.4.1: Early Data Support
    // early_secret = HKDF-Expand-Label(resumption_master_secret, "c e traffic", ClientHello..HelloRetryRequest, Hash.length)
    
    if (resumption_master_secret.empty() || client_hello_hash.empty()) {
        return Result<std::vector<uint8_t>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Get crypto provider for HKDF-Expand-Label
    auto provider = dtls::v13::crypto::ProviderFactory::instance().create_default_provider();
    if (!provider.is_success()) {
        return Result<std::vector<uint8_t>>(provider.error());
    }
    
    // Use proper HKDF-Expand-Label with "c e traffic" label for early data
    return dtls::v13::crypto::utils::hkdf_expand_label(
        *provider.value(),
        HashAlgorithm::SHA256,
        resumption_master_secret,
        "c e traffic",
        client_hello_hash,
        32  // 256-bit output for SHA256
    );
}

Result<std::vector<uint8_t>> calculate_early_data_hash(const std::vector<uint8_t>& early_data) {
    // Use proper cryptographic hash function (SHA-256) via crypto provider
    
    // Get crypto provider for hash computation
    auto provider = dtls::v13::crypto::ProviderFactory::instance().create_default_provider();
    if (!provider.is_success()) {
        return Result<std::vector<uint8_t>>(provider.error());
    }
    
    // Compute SHA-256 hash of early data
    dtls::v13::crypto::HashParams hash_params;
    hash_params.data = early_data;
    hash_params.algorithm = HashAlgorithm::SHA256;
    
    return provider.value()->compute_hash(hash_params);
}

bool validate_early_data_extensions(const std::vector<Extension>& extensions) {
    // Check for required extensions and validate their content
    bool has_early_data = false;
    bool has_psk = false;
    
    for (const auto& ext : extensions) {
        switch (ext.type) {
            case ExtensionType::EARLY_DATA:
                has_early_data = true;
                break;
            case ExtensionType::PRE_SHARED_KEY: {
                has_psk = true;
                // Validate PSK extension format
                auto psk_result = parse_psk_extension(ext);
                if (!psk_result.is_success() || !psk_result.value().is_valid()) {
                    return false;
                }
                break;
            }
            default:
                // Allow other extensions
                break;
        }
    }
    
    // Early data requires PSK
    return has_early_data && has_psk;
}

Result<uint32_t> extract_max_early_data_from_ticket(const NewSessionTicket& ticket) {
    for (const auto& ext : ticket.extensions()) {
        if (ext.type == ExtensionType::EARLY_DATA) {
            auto early_data_result = parse_early_data_extension(ext);
            if (early_data_result.is_success()) {
                return Result<uint32_t>(early_data_result.value().max_early_data_size);
            }
        }
    }
    
    return Result<uint32_t>(0); // No early data extension found
}

}  // namespace dtls::v13::protocol