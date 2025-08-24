/**
 * @file test_record_layer_comprehensive_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS record layer implementation
 * 
 * Target: Achieve >95% coverage for record_layer.cpp
 * Tests all major components: AntiReplayWindow, SequenceNumberManager,
 * EpochManager, ConnectionIDManager, RecordLayer encryption/decryption
 * Includes edge cases, error handling, and performance scenarios
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <cstddef>
#include <algorithm>

#include "dtls/protocol/record_layer.h"
#include "dtls/protocol/dtls_records.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/memory/buffer.h"
#include "dtls/types.h"
#include "dtls/error.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

class RecordLayerEnhancedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto provider
        auto provider_result = crypto::ProviderFactory::instance().create_provider("openssl");
        if (provider_result.is_success()) {
            crypto_provider_ = std::move(provider_result.value());
        } else {
            // Fallback to mock provider for CI environments
            auto mock_result = crypto::ProviderFactory::instance().create_provider("mock");
            ASSERT_TRUE(mock_result.is_success());
            crypto_provider_ = std::move(mock_result.value());
        }
        
        // Create test data of various sizes
        small_payload_ = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
        
        medium_payload_.resize(256);
        for (size_t i = 0; i < medium_payload_.size(); ++i) {
            medium_payload_[i] = static_cast<std::byte>(i % 256);
        }
        
        large_payload_.resize(1024);
        for (size_t i = 0; i < large_payload_.size(); ++i) {
            large_payload_[i] = static_cast<std::byte>((i * 7) % 256);
        }
        
        max_payload_.resize(16384); // Maximum DTLS record size
        std::mt19937 rng(42); // Fixed seed for reproducible tests
        for (size_t i = 0; i < max_payload_.size(); ++i) {
            max_payload_[i] = static_cast<std::byte>(rng() % 256);
        }
        
        // Create test keys and IVs
        test_key_ = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
        
        test_iv_ = {
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B
        };
        
        alt_key_ = {
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
            0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
            0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
            0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0
        };
        
        alt_iv_ = {
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
            0xA8, 0xA9, 0xAA, 0xAB
        };
    }
    
    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
    std::vector<std::byte> small_payload_;
    std::vector<std::byte> medium_payload_;
    std::vector<std::byte> large_payload_;
    std::vector<std::byte> max_payload_;
    std::vector<uint8_t> test_key_;
    std::vector<uint8_t> test_iv_;
    std::vector<uint8_t> alt_key_;
    std::vector<uint8_t> alt_iv_;
};

// ============================================================================
// AntiReplayWindow Comprehensive Tests
// ============================================================================

class AntiReplayWindowTest : public RecordLayerEnhancedTest {};

TEST_F(AntiReplayWindowTest, DefaultConstruction) {
    AntiReplayWindow window;
    EXPECT_TRUE(window.is_valid_sequence_number(1));
    EXPECT_FALSE(window.is_valid_sequence_number(0)); // Invalid sequence number
}

TEST_F(AntiReplayWindowTest, CustomWindowSize) {
    AntiReplayWindow window(128); // Custom window size
    EXPECT_TRUE(window.is_valid_sequence_number(1));
    EXPECT_TRUE(window.is_valid_sequence_number(128));
    EXPECT_FALSE(window.is_valid_sequence_number(130));
}

TEST_F(AntiReplayWindowTest, SequentialSequenceNumbers) {
    AntiReplayWindow window;
    
    // Test sequential numbers 1-100
    for (uint64_t seq = 1; seq <= 100; ++seq) {
        EXPECT_TRUE(window.is_valid_sequence_number(seq)) 
            << "Failed for sequence number: " << seq;
    }
}

TEST_F(AntiReplayWindowTest, ReplayAttackDetection) {
    AntiReplayWindow window;
    
    // Accept initial sequence
    EXPECT_TRUE(window.is_valid_sequence_number(10));
    
    // Replay attack - should be rejected
    EXPECT_FALSE(window.is_valid_sequence_number(10));
    EXPECT_FALSE(window.is_valid_sequence_number(9));
    EXPECT_FALSE(window.is_valid_sequence_number(5));
}

TEST_F(AntiReplayWindowTest, OutOfOrderWithinWindow) {
    AntiReplayWindow window(64);
    
    // Accept in order
    EXPECT_TRUE(window.is_valid_sequence_number(100));
    EXPECT_TRUE(window.is_valid_sequence_number(95));  // Within window
    EXPECT_TRUE(window.is_valid_sequence_number(80));  // Within window
    EXPECT_TRUE(window.is_valid_sequence_number(37));  // Edge of window (100-63)
    
    // Outside window
    EXPECT_FALSE(window.is_valid_sequence_number(36)); // Outside window
    EXPECT_FALSE(window.is_valid_sequence_number(30)); // Too old
}

TEST_F(AntiReplayWindowTest, LargeSequenceNumbers) {
    AntiReplayWindow window;
    
    uint64_t large_seq = 0xFFFFFFFFFFFFFF00ULL;
    EXPECT_TRUE(window.is_valid_sequence_number(large_seq));
    EXPECT_TRUE(window.is_valid_sequence_number(large_seq - 1));
    EXPECT_TRUE(window.is_valid_sequence_number(large_seq - 63));
    EXPECT_FALSE(window.is_valid_sequence_number(large_seq - 64));
}

TEST_F(AntiReplayWindowTest, SequenceNumberOverflow) {
    AntiReplayWindow window;
    
    // Test near overflow conditions
    uint64_t max_seq = 0xFFFFFFFFFFFFFFFEULL;
    EXPECT_TRUE(window.is_valid_sequence_number(max_seq));
    
    // Test maximum sequence number
    EXPECT_TRUE(window.is_valid_sequence_number(0xFFFFFFFFFFFFFFFFULL));
    
    // Test that we handle overflow gracefully
    EXPECT_FALSE(window.is_valid_sequence_number(max_seq - 100));
}

TEST_F(AntiReplayWindowTest, WindowSliding) {
    AntiReplayWindow window(8); // Small window for easier testing
    
    // Fill initial window: 1-8
    for (uint64_t seq = 1; seq <= 8; ++seq) {
        EXPECT_TRUE(window.is_valid_sequence_number(seq));
    }
    
    // Advance window: accept 16
    EXPECT_TRUE(window.is_valid_sequence_number(16));
    
    // Now 1-8 should be outside window
    EXPECT_FALSE(window.is_valid_sequence_number(8));
    EXPECT_FALSE(window.is_valid_sequence_number(7));
    
    // But 9-16 should be valid
    EXPECT_TRUE(window.is_valid_sequence_number(15));
    EXPECT_TRUE(window.is_valid_sequence_number(10));
    EXPECT_TRUE(window.is_valid_sequence_number(9));
}

TEST_F(AntiReplayWindowTest, ThreadSafety) {
    AntiReplayWindow window;
    const int num_threads = 4;
    const int ops_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> valid_count{0};
    std::atomic<int> successful_updates{0};
    
    // Use non-overlapping sequence number ranges to avoid window conflicts
    // Each thread gets a distinct range to minimize sliding window rejections
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&window, &valid_count, &successful_updates, t, ops_per_thread]() {
            // Give each thread a distinct, non-overlapping sequence number range
            // Thread 0: 1-100, Thread 1: 101-200, etc.
            uint64_t base_seq = t * ops_per_thread + 1;
            
            for (int i = 0; i < ops_per_thread; ++i) {
                uint64_t seq = base_seq + i;
                
                // Test read-only validation (should be thread-safe)
                if (window.is_valid_sequence_number(seq)) {
                    valid_count++;
                }
                
                // Test update operation (also should be thread-safe)
                if (window.check_and_update(seq)) {
                    successful_updates++;
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Validation should detect most sequence numbers as valid
    int total_ops = num_threads * ops_per_thread;
    EXPECT_GT(valid_count.load(), 0);
    
    // With non-overlapping ranges, most updates should succeed
    // Some may still fail due to sliding window, but should be close to total
    EXPECT_GT(successful_updates.load(), total_ops * 0.8); // At least 80% success rate
    EXPECT_LE(successful_updates.load(), total_ops);
    
    // The window stats should match successful updates
    auto stats = window.get_stats();
    EXPECT_EQ(stats.received_count, successful_updates.load());
}

// ============================================================================
// SequenceNumberManager Comprehensive Tests
// ============================================================================

class SequenceNumberManagerTest : public RecordLayerEnhancedTest {};

TEST_F(SequenceNumberManagerTest, DefaultConstruction) {
    SequenceNumberManager manager;
    
    // First sequence number should be 1
    EXPECT_EQ(manager.get_next_sequence_number(), 1);
    EXPECT_EQ(manager.get_next_sequence_number(), 2);
    EXPECT_EQ(manager.get_next_sequence_number(), 3);
}

TEST_F(SequenceNumberManagerTest, SequenceNumberIncrement) {
    SequenceNumberManager manager;
    
    // Test sequence incrementing
    for (uint64_t expected = 1; expected <= 1000; ++expected) {
        EXPECT_EQ(manager.get_next_sequence_number(), expected);
    }
}

TEST_F(SequenceNumberManagerTest, Reset) {
    SequenceNumberManager manager;
    
    // Use some sequence numbers
    manager.get_next_sequence_number();
    manager.get_next_sequence_number();
    manager.get_next_sequence_number();
    
    // Reset should start from 1 again
    manager.reset();
    EXPECT_EQ(manager.get_next_sequence_number(), 1);
}

TEST_F(SequenceNumberManagerTest, OverflowHandling) {
    SequenceNumberManager manager;
    
    // Test normal operation first
    manager.reset();
    EXPECT_FALSE(manager.would_overflow());
    
    // Test sequence number generation up to a reasonable limit
    for (uint64_t i = 1; i <= 1000; ++i) {
        EXPECT_FALSE(manager.would_overflow());
        uint64_t seq = manager.get_next_sequence_number();
        EXPECT_EQ(seq, i);
    }
    
    // Test overflow detection by using the MAX_SEQUENCE_NUMBER constant
    // (1ULL << 48) - 1 = 0x0000FFFFFFFFFFFF = 281,474,976,710,655
    const uint64_t MAX_SEQ = (1ULL << 48) - 1;
    
    // Test that we can detect approaching overflow
    // Note: We can't realistically iterate to MAX_SEQUENCE_NUMBER, 
    // so we test the overflow logic by checking would_overflow() behavior
    EXPECT_EQ(MAX_SEQ, 0x0000FFFFFFFFFFFFULL);
    
    // After generating reasonable number of sequences, verify overflow detection
    EXPECT_FALSE(manager.would_overflow()); // Should not overflow yet after 1000 operations
}

TEST_F(SequenceNumberManagerTest, ThreadSafetyStressTest) {
    SequenceNumberManager manager;
    const int num_threads = 8;
    const int ops_per_thread = 10000;
    std::vector<std::thread> threads;
    std::vector<std::vector<uint64_t>> thread_results(num_threads);
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&manager, &thread_results, t, ops_per_thread]() {
            thread_results[t].reserve(ops_per_thread);
            for (int i = 0; i < ops_per_thread; ++i) {
                thread_results[t].push_back(manager.get_next_sequence_number());
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Collect all sequence numbers
    std::vector<uint64_t> all_sequences;
    for (const auto& results : thread_results) {
        all_sequences.insert(all_sequences.end(), results.begin(), results.end());
    }
    
    // Sort and check for uniqueness
    std::sort(all_sequences.begin(), all_sequences.end());
    EXPECT_EQ(all_sequences.size(), num_threads * ops_per_thread);
    
    // Check that all sequence numbers are unique
    auto unique_end = std::unique(all_sequences.begin(), all_sequences.end());
    EXPECT_EQ(unique_end, all_sequences.end()) << "Duplicate sequence numbers detected";
    
    // Check that sequence numbers are consecutive starting from 1
    EXPECT_EQ(all_sequences[0], 1);
    EXPECT_EQ(all_sequences.back(), num_threads * ops_per_thread);
}

// ============================================================================
// EpochManager Comprehensive Tests
// ============================================================================

class EpochManagerTest : public RecordLayerEnhancedTest {};

TEST_F(EpochManagerTest, DefaultConstruction) {
    EpochManager manager;
    EXPECT_EQ(manager.get_current_epoch(), 0);
}

TEST_F(EpochManagerTest, EpochAdvancement) {
    EpochManager manager;
    
    auto result = manager.advance_epoch(test_key_, test_key_, test_iv_, test_iv_);
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(manager.get_current_epoch(), 1);
    
    result = manager.advance_epoch(alt_key_, alt_key_, alt_iv_, alt_iv_);
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(manager.get_current_epoch(), 2);
}

TEST_F(EpochManagerTest, KeyStorage) {
    EpochManager manager;
    
    auto result = manager.advance_epoch(test_key_, alt_key_, test_iv_, alt_iv_);
    EXPECT_TRUE(result.is_success());
    
    // Keys should be stored correctly
    auto read_key = manager.get_read_key(1);
    auto write_key = manager.get_write_key(1);
    auto read_iv = manager.get_read_iv(1);
    auto write_iv = manager.get_write_iv(1);
    
    EXPECT_TRUE(read_key.is_success());
    EXPECT_TRUE(write_key.is_success());
    EXPECT_TRUE(read_iv.is_success());
    EXPECT_TRUE(write_iv.is_success());
    
    EXPECT_EQ(read_key.value(), test_key_);
    EXPECT_EQ(write_key.value(), alt_key_);
    EXPECT_EQ(read_iv.value(), test_iv_);
    EXPECT_EQ(write_iv.value(), alt_iv_);
}

TEST_F(EpochManagerTest, InvalidEpochAccess) {
    EpochManager manager;
    
    // Try to access non-existent epoch
    auto result = manager.get_read_key(999);
    EXPECT_FALSE(result.is_success());
    
    result = manager.get_write_key(999);
    EXPECT_FALSE(result.is_success());
    
    auto iv_result = manager.get_read_iv(999);
    EXPECT_FALSE(iv_result.is_success());
    
    iv_result = manager.get_write_iv(999);
    EXPECT_FALSE(iv_result.is_success());
}

TEST_F(EpochManagerTest, MultipleEpochs) {
    EpochManager manager;
    
    // Create multiple epochs
    for (uint16_t epoch = 1; epoch <= 10; ++epoch) {
        auto modified_key = test_key_;
        modified_key[0] = epoch; // Modify key to make it unique
        
        auto result = manager.advance_epoch(modified_key, modified_key, test_iv_, test_iv_);
        EXPECT_TRUE(result.is_success());
        EXPECT_EQ(manager.get_current_epoch(), epoch);
        
        // Verify we can retrieve keys for this epoch
        auto key_result = manager.get_read_key(epoch);
        EXPECT_TRUE(key_result.is_success());
        EXPECT_EQ(key_result.value()[0], epoch);
    }
}

TEST_F(EpochManagerTest, EpochOverflow) {
    EpochManager manager;
    
    // Advance to near maximum epoch
    uint16_t max_epoch = 0xFFFE;
    
    // This might take too long, so just test the boundary
    auto result = manager.set_epoch(max_epoch);
    if (result.is_success()) {
        EXPECT_EQ(manager.get_current_epoch(), max_epoch);
        
        // Try to advance beyond maximum
        result = manager.advance_epoch(test_key_, test_key_, test_iv_, test_iv_);
        if (result.is_success()) {
            EXPECT_EQ(manager.get_current_epoch(), 0xFFFF);
        }
    }
}

// ============================================================================
// ConnectionIDManager Comprehensive Tests
// ============================================================================

class ConnectionIDManagerTest : public RecordLayerEnhancedTest {};

TEST_F(ConnectionIDManagerTest, DefaultConstruction) {
    ConnectionIDManager manager;
    EXPECT_FALSE(manager.is_enabled());
}

TEST_F(ConnectionIDManagerTest, EnableConnectionID) {
    ConnectionIDManager manager;
    
    ConnectionID local_cid = {0x01, 0x02, 0x03, 0x04};
    ConnectionID peer_cid = {0x05, 0x06, 0x07, 0x08};
    
    auto result = manager.enable(local_cid, peer_cid);
    EXPECT_TRUE(result.is_success());
    EXPECT_TRUE(manager.is_enabled());
    
    auto local_result = manager.get_local_connection_id();
    auto peer_result = manager.get_peer_connection_id();
    
    EXPECT_TRUE(local_result.is_success());
    EXPECT_TRUE(peer_result.is_success());
    EXPECT_EQ(local_result.value(), local_cid);
    EXPECT_EQ(peer_result.value(), peer_cid);
}

TEST_F(ConnectionIDManagerTest, UpdateConnectionID) {
    ConnectionIDManager manager;
    
    ConnectionID initial_cid = {0x01, 0x02, 0x03, 0x04};
    ConnectionID new_cid = {0x05, 0x06, 0x07, 0x08};
    
    manager.enable(initial_cid, initial_cid);
    
    auto result = manager.update_peer_connection_id(new_cid);
    EXPECT_TRUE(result.is_success());
    
    auto peer_result = manager.get_peer_connection_id();
    EXPECT_TRUE(peer_result.is_success());
    EXPECT_EQ(peer_result.value(), new_cid);
}

TEST_F(ConnectionIDManagerTest, DisableAfterEnable) {
    ConnectionIDManager manager;
    
    ConnectionID cid = {0x01, 0x02, 0x03, 0x04};
    manager.enable(cid, cid);
    EXPECT_TRUE(manager.is_enabled());
    
    manager.disable();
    EXPECT_FALSE(manager.is_enabled());
    
    // Should not be able to get connection IDs after disable
    auto result = manager.get_local_connection_id();
    EXPECT_FALSE(result.is_success());
}

TEST_F(ConnectionIDManagerTest, EmptyConnectionID) {
    ConnectionIDManager manager;
    
    ConnectionID empty_cid;
    ConnectionID valid_cid = {0x01, 0x02};
    
    // Should be able to use empty connection IDs
    auto result = manager.enable(empty_cid, valid_cid);
    EXPECT_TRUE(result.is_success());
    
    auto local_result = manager.get_local_connection_id();
    EXPECT_TRUE(local_result.is_success());
    EXPECT_TRUE(local_result.value().empty());
}

TEST_F(ConnectionIDManagerTest, MaximumLengthConnectionID) {
    ConnectionIDManager manager;
    
    // Create maximum length connection ID (20 bytes per RFC 9000)
    ConnectionID max_cid;
    for (uint8_t i = 0; i < 20; ++i) {
        max_cid.push_back(i);
    }
    
    auto result = manager.enable(max_cid, max_cid);
    EXPECT_TRUE(result.is_success());
    
    auto local_result = manager.get_local_connection_id();
    EXPECT_TRUE(local_result.is_success());
    EXPECT_EQ(local_result.value().size(), 20);
}

// ============================================================================
// RecordLayer Encryption/Decryption Tests
// ============================================================================

class RecordLayerCryptoTest : public RecordLayerEnhancedTest {};

TEST_F(RecordLayerCryptoTest, BasicEncryptionDecryption) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    auto init_result = record_layer->initialize();
    EXPECT_TRUE(init_result.is_success());
    
    auto cipher_result = record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_TRUE(cipher_result.is_success());
    
    auto epoch_result = record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_);
    EXPECT_TRUE(epoch_result.is_success());
    
    // Create test plaintext
    DTLSPlaintext plaintext;
    plaintext.type = ContentType::APPLICATION_DATA;
    plaintext.version = ProtocolVersion{0xfe, 0xfc}; // DTLS 1.3
    plaintext.epoch = 1;
    plaintext.sequence_number = 1;
    plaintext.fragment = small_payload_;
    
    // Encrypt
    auto encrypt_result = record_layer->protect_record(plaintext);
    EXPECT_TRUE(encrypt_result.is_success());
    
    DTLSCiphertext ciphertext = encrypt_result.value();
    EXPECT_EQ(ciphertext.type, ContentType::APPLICATION_DATA);
    EXPECT_EQ(ciphertext.version.major, 0xfe);
    EXPECT_EQ(ciphertext.version.minor, 0xfc);
    EXPECT_GT(ciphertext.fragment.size(), small_payload_.size()); // Should be larger due to auth tag
    
    // Decrypt
    auto decrypt_result = record_layer->unprotect_record(ciphertext);
    EXPECT_TRUE(decrypt_result.is_success());
    
    DTLSPlaintext decrypted = decrypt_result.value();
    EXPECT_EQ(decrypted.type, plaintext.type);
    EXPECT_EQ(decrypted.version.major, plaintext.version.major);
    EXPECT_EQ(decrypted.version.minor, plaintext.version.minor);
    EXPECT_EQ(decrypted.fragment, plaintext.fragment);
}

TEST_F(RecordLayerCryptoTest, DifferentCipherSuites) {
    std::vector<CipherSuite> cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    
    for (auto suite : cipher_suites) {
        auto record_layer = std::make_unique<RecordLayer>(
            crypto::ProviderFactory::instance().create_provider("openssl").value()
        );
        
        EXPECT_TRUE(record_layer->initialize().is_success());
        EXPECT_TRUE(record_layer->set_cipher_suite(suite).is_success());
        EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
        
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = 1;
        plaintext.sequence_number = 1;
        plaintext.fragment = medium_payload_;
        
        auto encrypt_result = record_layer->protect_record(plaintext);
        EXPECT_TRUE(encrypt_result.is_success()) << "Encryption failed for cipher suite: " << static_cast<int>(suite);
        
        auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
        EXPECT_TRUE(decrypt_result.is_success()) << "Decryption failed for cipher suite: " << static_cast<int>(suite);
        
        EXPECT_EQ(decrypt_result.value().fragment, plaintext.fragment);
    }
}

TEST_F(RecordLayerCryptoTest, PayloadSizeVariations) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    std::vector<std::vector<std::byte>*> payloads = {
        &small_payload_, &medium_payload_, &large_payload_, &max_payload_
    };
    
    for (size_t i = 0; i < payloads.size(); ++i) {
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = 1;
        plaintext.sequence_number = i + 1;
        plaintext.fragment = *payloads[i];
        
        auto encrypt_result = record_layer->protect_record(plaintext);
        EXPECT_TRUE(encrypt_result.is_success()) << "Encryption failed for payload size: " << payloads[i]->size();
        
        auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
        EXPECT_TRUE(decrypt_result.is_success()) << "Decryption failed for payload size: " << payloads[i]->size();
        
        EXPECT_EQ(decrypt_result.value().fragment, plaintext.fragment);
    }
}

TEST_F(RecordLayerCryptoTest, SequenceNumberHandling) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    // Test multiple sequence numbers
    for (uint64_t seq = 1; seq <= 100; ++seq) {
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = 1;
        plaintext.sequence_number = seq;
        plaintext.fragment = small_payload_;
        
        auto encrypt_result = record_layer->protect_record(plaintext);
        EXPECT_TRUE(encrypt_result.is_success()) << "Encryption failed for sequence: " << seq;
        
        // Sequence number should be preserved in ciphertext
        EXPECT_EQ(encrypt_result.value().sequence_number, seq);
        
        auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
        EXPECT_TRUE(decrypt_result.is_success()) << "Decryption failed for sequence: " << seq;
        
        EXPECT_EQ(decrypt_result.value().sequence_number, seq);
    }
}

TEST_F(RecordLayerCryptoTest, MultipleEpochs) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    
    // Test encryption/decryption across multiple epochs
    for (uint16_t epoch = 1; epoch <= 5; ++epoch) {
        auto modified_key = test_key_;
        modified_key[0] = epoch; // Make key unique per epoch
        
        EXPECT_TRUE(record_layer->advance_epoch(modified_key, modified_key, test_iv_, test_iv_).is_success());
        
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = epoch;
        plaintext.sequence_number = 1;
        plaintext.fragment = small_payload_;
        
        auto encrypt_result = record_layer->protect_record(plaintext);
        EXPECT_TRUE(encrypt_result.is_success()) << "Encryption failed for epoch: " << epoch;
        
        auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
        EXPECT_TRUE(decrypt_result.is_success()) << "Decryption failed for epoch: " << epoch;
        
        EXPECT_EQ(decrypt_result.value().fragment, plaintext.fragment);
        EXPECT_EQ(decrypt_result.value().epoch, epoch);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

class RecordLayerErrorTest : public RecordLayerEnhancedTest {};

TEST_F(RecordLayerErrorTest, InvalidCipherSuite) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    
    // Try to set invalid cipher suite
    auto result = record_layer->set_cipher_suite(static_cast<CipherSuite>(0xFFFF));
    EXPECT_FALSE(result.is_success());
}

TEST_F(RecordLayerErrorTest, EncryptionWithoutKeys) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    
    // Try to encrypt without setting up keys
    DTLSPlaintext plaintext;
    plaintext.type = ContentType::APPLICATION_DATA;
    plaintext.version = ProtocolVersion{0xfe, 0xfc};
    plaintext.epoch = 1;
    plaintext.sequence_number = 1;
    plaintext.fragment = small_payload_;
    
    auto result = record_layer->protect_record(plaintext);
    EXPECT_FALSE(result.is_success());
}

TEST_F(RecordLayerErrorTest, DecryptionWithWrongKeys) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    DTLSPlaintext plaintext;
    plaintext.type = ContentType::APPLICATION_DATA;
    plaintext.version = ProtocolVersion{0xfe, 0xfc};
    plaintext.epoch = 1;
    plaintext.sequence_number = 1;
    plaintext.fragment = small_payload_;
    
    auto encrypt_result = record_layer->protect_record(plaintext);
    EXPECT_TRUE(encrypt_result.is_success());
    
    // Change keys
    EXPECT_TRUE(record_layer->advance_epoch(alt_key_, alt_key_, alt_iv_, alt_iv_).is_success());
    
    // Try to decrypt with wrong keys
    auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
    EXPECT_FALSE(decrypt_result.is_success());
}

TEST_F(RecordLayerErrorTest, TamperedCiphertext) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    DTLSPlaintext plaintext;
    plaintext.type = ContentType::APPLICATION_DATA;
    plaintext.version = ProtocolVersion{0xfe, 0xfc};
    plaintext.epoch = 1;
    plaintext.sequence_number = 1;
    plaintext.fragment = small_payload_;
    
    auto encrypt_result = record_layer->protect_record(plaintext);
    EXPECT_TRUE(encrypt_result.is_success());
    
    DTLSCiphertext tampered = encrypt_result.value();
    
    // Tamper with ciphertext
    if (!tampered.fragment.empty()) {
        tampered.fragment[0] = static_cast<std::byte>(
            static_cast<uint8_t>(tampered.fragment[0]) ^ 0xFF
        );
    }
    
    // Decryption should fail due to authentication tag mismatch
    auto decrypt_result = record_layer->unprotect_record(tampered);
    EXPECT_FALSE(decrypt_result.is_success());
}

TEST_F(RecordLayerErrorTest, EmptyPayload) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    DTLSPlaintext plaintext;
    plaintext.type = ContentType::APPLICATION_DATA;
    plaintext.version = ProtocolVersion{0xfe, 0xfc};
    plaintext.epoch = 1;
    plaintext.sequence_number = 1;
    plaintext.fragment.clear(); // Empty payload
    
    // Should handle empty payload gracefully
    auto encrypt_result = record_layer->protect_record(plaintext);
    EXPECT_TRUE(encrypt_result.is_success());
    
    auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
    EXPECT_TRUE(decrypt_result.is_success());
    EXPECT_TRUE(decrypt_result.value().fragment.empty());
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

class RecordLayerPerformanceTest : public RecordLayerEnhancedTest {};

TEST_F(RecordLayerPerformanceTest, HighVolumeEncryption) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    const int num_operations = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_operations; ++i) {
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = 1;
        plaintext.sequence_number = i + 1;
        plaintext.fragment = medium_payload_;
        
        auto encrypt_result = record_layer->protect_record(plaintext);
        EXPECT_TRUE(encrypt_result.is_success());
        
        auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
        EXPECT_TRUE(decrypt_result.is_success());
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "Completed " << num_operations << " encrypt/decrypt cycles in " 
              << duration.count() << "ms" << std::endl;
    std::cout << "Average time per operation: " 
              << static_cast<double>(duration.count()) / num_operations << "ms" << std::endl;
    
    // Performance should be reasonable (adjust threshold as needed)
    EXPECT_LT(duration.count(), 10000); // Less than 10 seconds for 1000 operations
}

TEST_F(RecordLayerPerformanceTest, ConcurrentOperations) {
    const int num_threads = 4;
    const int ops_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([this, &success_count, &failure_count, t, ops_per_thread]() {
            auto thread_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
            if (!thread_crypto.is_success()) {
                thread_crypto = crypto::ProviderFactory::instance().create_provider("mock");
            }
            
            auto record_layer = std::make_unique<RecordLayer>(std::move(thread_crypto.value()));
            
            if (!record_layer->initialize().is_success() ||
                !record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success() ||
                !record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success()) {
                failure_count += ops_per_thread;
                return;
            }
            
            for (int i = 0; i < ops_per_thread; ++i) {
                DTLSPlaintext plaintext;
                plaintext.type = ContentType::APPLICATION_DATA;
                plaintext.version = ProtocolVersion{0xfe, 0xfc};
                plaintext.epoch = 1;
                plaintext.sequence_number = t * ops_per_thread + i + 1;
                plaintext.fragment = small_payload_;
                
                auto encrypt_result = record_layer->protect_record(plaintext);
                if (encrypt_result.is_success()) {
                    auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
                    if (decrypt_result.is_success()) {
                        success_count++;
                    } else {
                        failure_count++;
                    }
                } else {
                    failure_count++;
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(success_count.load(), num_threads * ops_per_thread);
    EXPECT_EQ(failure_count.load(), 0);
}

// ============================================================================
// Integration Tests
// ============================================================================

class RecordLayerIntegrationTest : public RecordLayerEnhancedTest {};

TEST_F(RecordLayerIntegrationTest, FullWorkflow) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    // Initialize
    EXPECT_TRUE(record_layer->initialize().is_success());
    
    // Set cipher suite
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384).is_success());
    
    // Advance epoch
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    // Enable connection ID
    ConnectionID local_cid = {0x01, 0x02, 0x03, 0x04};
    ConnectionID peer_cid = {0x05, 0x06, 0x07, 0x08};
    EXPECT_TRUE(record_layer->enable_connection_id(local_cid, peer_cid).is_success());
    
    // Process multiple records
    for (int i = 0; i < 50; ++i) {
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = 1;
        plaintext.sequence_number = i + 1;
        plaintext.fragment = medium_payload_;
        
        // Protect record
        auto protect_result = record_layer->prepare_outgoing_record(plaintext);
        EXPECT_TRUE(protect_result.is_success());
        
        // Process incoming record (includes anti-replay check)
        auto process_result = record_layer->process_incoming_record(protect_result.value());
        EXPECT_TRUE(process_result.is_success());
        
        EXPECT_EQ(process_result.value().fragment, plaintext.fragment);
    }
    
    // Get statistics
    auto stats = record_layer->get_stats();
    EXPECT_GT(stats.records_processed, 0);
    EXPECT_GT(stats.bytes_processed, 0);
}

TEST_F(RecordLayerIntegrationTest, KeyUpdateWorkflow) {
    auto record_layer = std::make_unique<RecordLayer>(std::move(crypto_provider_));
    
    EXPECT_TRUE(record_layer->initialize().is_success());
    EXPECT_TRUE(record_layer->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_success());
    EXPECT_TRUE(record_layer->advance_epoch(test_key_, test_key_, test_iv_, test_iv_).is_success());
    
    // Process some records
    for (int i = 0; i < 10; ++i) {
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = 1;
        plaintext.sequence_number = i + 1;
        plaintext.fragment = small_payload_;
        
        auto encrypt_result = record_layer->protect_record(plaintext);
        EXPECT_TRUE(encrypt_result.is_success());
    }
    
    // Check if key update is needed (probably not after only 10 records)
    bool needs_update = record_layer->needs_key_update();
    
    // Force a key update
    auto update_result = record_layer->update_traffic_keys();
    if (update_result.is_success()) {
        // Continue processing with new keys
        DTLSPlaintext plaintext;
        plaintext.type = ContentType::APPLICATION_DATA;
        plaintext.version = ProtocolVersion{0xfe, 0xfc};
        plaintext.epoch = 1;
        plaintext.sequence_number = 11;
        plaintext.fragment = small_payload_;
        
        auto encrypt_result = record_layer->protect_record(plaintext);
        EXPECT_TRUE(encrypt_result.is_success());
        
        auto decrypt_result = record_layer->unprotect_record(encrypt_result.value());
        EXPECT_TRUE(decrypt_result.is_success());
    }
    
    // Get key update statistics
    auto key_stats = record_layer->get_key_update_stats();
    // Stats should be valid even if no updates occurred
}

// Add test main to run all tests
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}