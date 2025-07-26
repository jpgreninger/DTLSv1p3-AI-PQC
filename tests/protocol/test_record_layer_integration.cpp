#include <gtest/gtest.h>
#include <dtls/protocol/record_layer.h>
#include <dtls/protocol/dtls_records.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/crypto/botan_provider.h>
#include <dtls/crypto/crypto_utils.h>
#include <chrono>
#include <thread>

using namespace dtls::v13::protocol;
using namespace dtls::v13::crypto;

class RecordLayerIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto providers
        openssl_provider_ = std::make_unique<OpenSSLProvider>();
        if (openssl_provider_->is_available()) {
            openssl_provider_->initialize();
        }
        
        if (botan_utils::is_botan_available()) {
            botan_provider_ = std::make_unique<BotanProvider>();
            botan_provider_->initialize();
        }
        
        // Create record layer for testing
        record_layer_ = std::make_unique<RecordLayer>(
            std::make_unique<OpenSSLProvider>(*openssl_provider_));
        record_layer_->initialize();
        record_layer_->set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
        
        // Setup initial epoch with test keys
        std::vector<uint8_t> test_key(16, 0x42);
        std::vector<uint8_t> test_iv(12, 0x24);
        
        auto advance_result = record_layer_->advance_epoch(test_key, test_key, test_iv, test_iv);
        ASSERT_TRUE(advance_result.is_success());
    }
    
    void TearDown() override {
        if (openssl_provider_) {
            openssl_provider_->cleanup();
        }
        if (botan_provider_) {
            botan_provider_->cleanup();
        }
    }
    
    std::unique_ptr<OpenSSLProvider> openssl_provider_;
    std::unique_ptr<BotanProvider> botan_provider_;
    std::unique_ptr<RecordLayer> record_layer_;
};

// ============================================================================
// DTLSPlaintext/DTLSCiphertext Integration Tests
// ============================================================================

TEST_F(RecordLayerIntegrationTest, DTLSRecordProtectUnprotectRoundtrip) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Create test DTLSPlaintext
    std::string test_data = "Hello, DTLS v1.3 with RFC 9147 compliance!";
    memory::Buffer payload(test_data.size());
    std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
    
    DTLSPlaintext original_plaintext(
        ContentType::APPLICATION_DATA,
        ProtocolVersion::DTLS_1_3,
        1,  // epoch
        SequenceNumber48(12345),
        std::move(payload)
    );
    
    // Protect the record
    auto ciphertext_result = record_layer_->protect_record(original_plaintext);
    ASSERT_TRUE(ciphertext_result.is_success());
    auto ciphertext = ciphertext_result.value();
    
    // Verify encryption occurred
    EXPECT_NE(ciphertext.get_encrypted_sequence_number(), original_plaintext.get_sequence_number());
    EXPECT_GT(ciphertext.get_encrypted_record().size(), test_data.size()); // includes auth tag
    
    // Unprotect the record
    auto plaintext_result = record_layer_->unprotect_record(ciphertext);
    ASSERT_TRUE(plaintext_result.is_success());
    auto recovered_plaintext = plaintext_result.value();
    
    // Verify round-trip integrity
    EXPECT_EQ(recovered_plaintext.get_type(), original_plaintext.get_type());
    EXPECT_EQ(recovered_plaintext.get_version(), original_plaintext.get_version());
    EXPECT_EQ(recovered_plaintext.get_epoch(), original_plaintext.get_epoch());
    EXPECT_EQ(recovered_plaintext.get_sequence_number(), original_plaintext.get_sequence_number());
    
    // Verify payload integrity
    const auto& recovered_fragment = recovered_plaintext.get_fragment();
    std::string recovered_data(
        reinterpret_cast<const char*>(recovered_fragment.data()),
        recovered_fragment.size()
    );
    EXPECT_EQ(recovered_data, test_data);
}

TEST_F(RecordLayerIntegrationTest, SequenceNumberEncryptionValidation) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    std::string test_data = "Sequence encryption test";
    memory::Buffer payload(test_data.size());
    std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
    
    // Test with different sequence numbers
    std::vector<uint64_t> test_sequences = {0, 1, 100, 0x123456789ABCULL, 0xFFFFFFFFFFFFULL};
    
    for (uint64_t seq_num : test_sequences) {
        DTLSPlaintext plaintext(
            ContentType::APPLICATION_DATA,
            ProtocolVersion::DTLS_1_3,
            1,  // epoch
            SequenceNumber48(seq_num),
            memory::Buffer(payload) // copy payload
        );
        
        // Protect and verify sequence number encryption
        auto ciphertext_result = record_layer_->protect_record(plaintext);
        ASSERT_TRUE(ciphertext_result.is_success());
        auto ciphertext = ciphertext_result.value();
        
        // Sequence number should be encrypted (different from original)
        EXPECT_NE(static_cast<uint64_t>(ciphertext.get_encrypted_sequence_number()), seq_num)
            << "Sequence number " << seq_num << " was not encrypted";
        
        // Unprotect and verify sequence number recovery
        auto plaintext_result = record_layer_->unprotect_record(ciphertext);
        ASSERT_TRUE(plaintext_result.is_success());
        auto recovered_plaintext = plaintext_result.value();
        
        EXPECT_EQ(static_cast<uint64_t>(recovered_plaintext.get_sequence_number()), seq_num)
            << "Sequence number " << seq_num << " was not correctly recovered";
    }
}

TEST_F(RecordLayerIntegrationTest, AntiReplayWithEncryptedSequences) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    std::string test_data = "Anti-replay test with encrypted sequences";
    memory::Buffer payload(test_data.size());
    std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
    
    // Create and process records with different sequence numbers
    std::vector<uint64_t> sequence_numbers = {1, 3, 2, 5, 4, 7, 6}; // Out of order
    std::vector<DTLSCiphertext> ciphertexts;
    
    // Protect all records first
    for (uint64_t seq_num : sequence_numbers) {
        DTLSPlaintext plaintext(
            ContentType::APPLICATION_DATA,
            ProtocolVersion::DTLS_1_3,
            1,  // epoch
            SequenceNumber48(seq_num),
            memory::Buffer(payload) // copy payload
        );
        
        auto ciphertext_result = record_layer_->protect_record(plaintext);
        ASSERT_TRUE(ciphertext_result.is_success());
        ciphertexts.push_back(ciphertext_result.value());
    }
    
    // Process records and verify anti-replay works with encrypted sequences
    std::set<uint64_t> processed_sequences;
    for (const auto& ciphertext : ciphertexts) {
        auto plaintext_result = record_layer_->process_incoming_record(ciphertext);
        ASSERT_TRUE(plaintext_result.is_success());
        
        uint64_t recovered_seq = plaintext_result.value().get_sequence_number();
        processed_sequences.insert(recovered_seq);
    }
    
    // Verify all sequences were processed correctly
    std::set<uint64_t> expected_sequences(sequence_numbers.begin(), sequence_numbers.end());
    EXPECT_EQ(processed_sequences, expected_sequences);
    
    // Test replay attack detection - try to process the same record again
    auto replay_result = record_layer_->process_incoming_record(ciphertexts[0]);
    EXPECT_FALSE(replay_result.is_success());
    EXPECT_EQ(replay_result.error(), DTLSError::REPLAY_ATTACK_DETECTED);
}

TEST_F(RecordLayerIntegrationTest, ConnectionIDIntegration) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Enable connection ID
    ConnectionID local_cid = {0x01, 0x02, 0x03, 0x04};
    ConnectionID peer_cid = {0x05, 0x06, 0x07, 0x08};
    
    auto enable_result = record_layer_->enable_connection_id(local_cid, peer_cid);
    ASSERT_TRUE(enable_result.is_success());
    
    // Create test record
    std::string test_data = "Connection ID test";
    memory::Buffer payload(test_data.size());
    std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
    
    DTLSPlaintext plaintext(
        ContentType::APPLICATION_DATA,
        ProtocolVersion::DTLS_1_3,
        1,  // epoch
        SequenceNumber48(999),
        std::move(payload)
    );
    
    // Protect record (should include connection ID)
    auto ciphertext_result = record_layer_->protect_record(plaintext);
    ASSERT_TRUE(ciphertext_result.is_success());
    auto ciphertext = ciphertext_result.value();
    
    // Verify connection ID is present
    EXPECT_TRUE(ciphertext.has_cid());
    auto cid_vector = ciphertext.get_connection_id_vector();
    EXPECT_EQ(cid_vector, peer_cid);
    
    // Unprotect record
    auto plaintext_result = record_layer_->unprotect_record(ciphertext);
    ASSERT_TRUE(plaintext_result.is_success());
    
    // Verify data integrity despite connection ID
    const auto& recovered_fragment = plaintext_result.value().get_fragment();
    std::string recovered_data(
        reinterpret_cast<const char*>(recovered_fragment.data()),
        recovered_fragment.size()
    );
    EXPECT_EQ(recovered_data, test_data);
}

TEST_F(RecordLayerIntegrationTest, LegacyCompatibilityLayer) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Create legacy PlaintextRecord
    std::string test_data = "Legacy compatibility test";
    memory::Buffer payload(test_data.size());
    std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
    
    PlaintextRecord legacy_plaintext(
        ContentType::APPLICATION_DATA,
        ProtocolVersion::DTLS_1_3,
        1,  // epoch
        888, // sequence number
        std::move(payload)
    );
    
    // Protect using legacy method
    auto ciphertext_result = record_layer_->protect_record_legacy(legacy_plaintext);
    ASSERT_TRUE(ciphertext_result.is_success());
    auto legacy_ciphertext = ciphertext_result.value();
    
    // Verify legacy structure
    EXPECT_EQ(legacy_ciphertext.header().content_type, ContentType::APPLICATION_DATA);
    EXPECT_EQ(legacy_ciphertext.header().epoch, 1);
    EXPECT_NE(legacy_ciphertext.header().sequence_number, 888); // Should be encrypted
    
    // Unprotect using legacy method
    auto plaintext_result = record_layer_->unprotect_record_legacy(legacy_ciphertext);
    ASSERT_TRUE(plaintext_result.is_success());
    auto recovered_plaintext = plaintext_result.value();
    
    // Verify round-trip integrity
    EXPECT_EQ(recovered_plaintext.header().sequence_number, 888); // Should be decrypted
    
    const auto& recovered_payload = recovered_plaintext.payload();
    std::string recovered_data(
        reinterpret_cast<const char*>(recovered_payload.data()),
        recovered_payload.size()
    );
    EXPECT_EQ(recovered_data, test_data);
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

TEST_F(RecordLayerIntegrationTest, PerformanceWithEncryptedSequences) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    const int iterations = 100;
    std::string test_data = "Performance test data for encrypted sequences";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        memory::Buffer payload(test_data.size());
        std::memcpy(payload.mutable_data(), test_data.data(), test_data.size());
        
        DTLSPlaintext plaintext(
            ContentType::APPLICATION_DATA,
            ProtocolVersion::DTLS_1_3,
            1,
            SequenceNumber48(i),
            std::move(payload)
        );
        
        // Protect record
        auto ciphertext_result = record_layer_->protect_record(plaintext);
        ASSERT_TRUE(ciphertext_result.is_success());
        
        // Unprotect record
        auto plaintext_result = record_layer_->unprotect_record(ciphertext_result.value());
        ASSERT_TRUE(plaintext_result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete 100 round-trips in reasonable time (< 500ms)
    EXPECT_LT(duration.count(), 500000);
    
    std::cout << "Record layer performance: " 
              << iterations << " round-trips in " 
              << duration.count() << " microseconds ("
              << (duration.count() / iterations) << " μs per round-trip)"
              << std::endl;
}

TEST_F(RecordLayerIntegrationTest, SequenceNumberOverflowHandling) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test near-overflow sequence numbers
    std::vector<uint64_t> overflow_sequences = {
        0xFFFFFFFFFFFEULL,  // Max - 1
        0xFFFFFFFFFFFFULL   // Max (48-bit)
    };
    
    for (uint64_t seq_num : overflow_sequences) {
        memory::Buffer payload(16);
        std::fill(payload.mutable_data(), payload.mutable_data() + 16, std::byte{0xAB});
        
        DTLSPlaintext plaintext(
            ContentType::APPLICATION_DATA,
            ProtocolVersion::DTLS_1_3,
            1,
            SequenceNumber48(seq_num),
            std::move(payload)
        );
        
        // Should handle max sequence numbers gracefully
        auto ciphertext_result = record_layer_->protect_record(plaintext);
        ASSERT_TRUE(ciphertext_result.is_success());
        
        auto plaintext_result = record_layer_->unprotect_record(ciphertext_result.value());
        ASSERT_TRUE(plaintext_result.is_success());
        
        EXPECT_EQ(static_cast<uint64_t>(plaintext_result.value().get_sequence_number()), seq_num);
    }
}

// ============================================================================
// Error Handling Tests  
// ============================================================================

TEST_F(RecordLayerIntegrationTest, InvalidRecordHandling) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test with invalid DTLSCiphertext (too small for auth tag)
    memory::Buffer small_record(8); // Too small for any meaningful encrypted record
    std::fill(small_record.mutable_data(), small_record.mutable_data() + 8, std::byte{0xFF});
    
    DTLSCiphertext invalid_ciphertext(
        ContentType::APPLICATION_DATA,
        ProtocolVersion::DTLS_1_3,
        1,
        SequenceNumber48(1),
        std::move(small_record)
    );
    
    auto result = record_layer_->unprotect_record(invalid_ciphertext);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INVALID_CIPHERTEXT_RECORD);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}