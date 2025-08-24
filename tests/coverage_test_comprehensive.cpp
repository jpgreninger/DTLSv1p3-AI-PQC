/**
 * @file coverage_test_comprehensive.cpp
 * @brief Comprehensive test suite designed to achieve >95% code coverage
 * 
 * This test file specifically targets uncovered code paths to reach the
 * coverage requirements. It exercises core functionality across all modules
 * with correct API usage.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <random>

// Include all major components with correct headers
#include "dtls/types.h"
#include "dtls/error.h"
#include "dtls/result.h"
#include "dtls/memory/buffer.h"
#include "dtls/core_protocol/anti_replay_core.h"
#include "dtls/protocol/dtls_records.h"
#include "dtls/crypto/provider_factory.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;
using namespace dtls::v13::protocol;
using namespace dtls::v13::core_protocol;

class ComprehensiveCoverageTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
        test_data_.resize(1024);
        std::iota(test_data_.begin(), test_data_.end(), 0);
        
        small_payload_ = {0xDE, 0xAD, 0xBE, 0xEF};
        large_payload_.resize(8192);
        std::fill(large_payload_.begin(), large_payload_.end(), std::byte{0xAB});
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> small_payload_;
    std::vector<std::byte> large_payload_;
};

// Test core types and error handling
TEST_F(ComprehensiveCoverageTest, CoreTypesAndErrorHandling) {
    // Test NetworkAddress with correct API
    auto addr_result = NetworkAddress::from_string("192.168.1.100:5000");
    ASSERT_TRUE(addr_result.is_ok());
    
    auto addr = addr_result.value();
    EXPECT_EQ(addr.get_port(), 5000);
    EXPECT_FALSE(addr.get_ip_string().empty());
    
    // Test different address formats
    auto ipv4_result = NetworkAddress::from_string("10.0.0.1:8080");
    ASSERT_TRUE(ipv4_result.is_ok());
    
    // Test invalid address format
    auto invalid_result = NetworkAddress::from_string("invalid-address");
    EXPECT_TRUE(invalid_result.is_error());
    
    // Test NetworkAddress comparison operators
    EXPECT_NE(addr, ipv4_result.value());
    EXPECT_EQ(addr, addr); // Self comparison
    EXPECT_FALSE(addr < addr); // Self comparison
    
    // Test error code creation and properties
    auto error_code = make_error_code(DTLSError::DECODE_ERROR);
    EXPECT_EQ(error_code.value(), static_cast<int>(DTLSError::DECODE_ERROR));
    EXPECT_FALSE(error_code.message().empty());
    
    // Test different error types
    std::vector<DTLSError> test_errors = {
        DTLSError::NONE,
        DTLSError::WOULD_BLOCK,
        DTLSError::TIMEOUT,
        DTLSError::CONNECTION_REFUSED,
        DTLSError::HANDSHAKE_FAILURE,
        DTLSError::BAD_CERTIFICATE,
        DTLSError::DECRYPT_ERROR,
        DTLSError::RECORD_OVERFLOW,
        DTLSError::DECOMPRESSION_FAILURE,
        DTLSError::HANDSHAKE_FAILURE,
        DTLSError::NO_CERTIFICATE,
        DTLSError::BAD_CERTIFICATE,
        DTLSError::UNSUPPORTED_CERTIFICATE,
        DTLSError::CERTIFICATE_REVOKED,
        DTLSError::CERTIFICATE_EXPIRED,
        DTLSError::CERTIFICATE_UNKNOWN,
        DTLSError::ILLEGAL_PARAMETER,
        DTLSError::UNKNOWN_CA,
        DTLSError::ACCESS_DENIED,
        DTLSError::DECODE_ERROR,
        DTLSError::DECRYPT_ERROR,
        DTLSError::EXPORT_RESTRICTION,
        DTLSError::PROTOCOL_VERSION,
        DTLSError::INSUFFICIENT_SECURITY,
        DTLSError::INTERNAL_ERROR,
        DTLSError::USER_CANCELED,
        DTLSError::NO_RENEGOTIATION
    };
    
    for (auto error : test_errors) {
        auto code = make_error_code(error);
        EXPECT_FALSE(code.message().empty());
        
        // Test is_fatal_error function
        bool is_fatal = is_fatal_error(error);
        if (error == DTLSError::NONE || 
            error == DTLSError::WOULD_BLOCK || 
            error == DTLSError::TIMEOUT ||
            error == DTLSError::USER_CANCELED ||
            error == DTLSError::NO_RENEGOTIATION) {
            EXPECT_FALSE(is_fatal);
        } else {
            // Most errors should be considered fatal
            EXPECT_TRUE(is_fatal || error == DTLSError::CONNECTION_REFUSED);
        }
    }
}

// Test memory management comprehensive coverage
TEST_F(ComprehensiveCoverageTest, MemoryManagementCoverage) {
    // Test ZeroCopyBuffer construction variants
    ZeroCopyBuffer buffer1; // Default
    EXPECT_EQ(buffer1.size(), 0);
    EXPECT_TRUE(buffer1.empty());
    
    ZeroCopyBuffer buffer2(1024); // With capacity
    EXPECT_GE(buffer2.capacity(), 1024);
    
    ZeroCopyBuffer buffer3(small_payload_.data(), small_payload_.size()); // From data
    EXPECT_EQ(buffer3.size(), small_payload_.size());
    EXPECT_EQ(std::memcmp(buffer3.data(), small_payload_.data(), small_payload_.size()), 0);
    
    // Test buffer operations comprehensive coverage
    auto append_result = buffer2.append(test_data_.data(), test_data_.size());
    ASSERT_TRUE(append_result.is_ok());
    EXPECT_EQ(buffer2.size(), test_data_.size());
    
    // Test prepend
    auto prepend_result = buffer2.prepend(small_payload_.data(), small_payload_.size());
    ASSERT_TRUE(prepend_result.is_ok());
    EXPECT_EQ(buffer2.size(), test_data_.size() + small_payload_.size());
    
    // Test slicing
    auto slice_result = buffer2.slice(small_payload_.size(), test_data_.size());
    ASSERT_TRUE(slice_result.is_ok());
    auto slice = slice_result.value();
    EXPECT_EQ(slice.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(slice.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test zero-copy slice
    auto zero_copy_slice = buffer2.create_slice(0, small_payload_.size());
    EXPECT_EQ(zero_copy_slice.size(), small_payload_.size());
    
    // Test buffer sharing
    auto share_result = buffer2.share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    auto shared = share_result.value();
    EXPECT_TRUE(shared.is_shared());
    EXPECT_GT(shared.reference_count(), 1);
    
    // Test copy-on-write
    auto make_unique_result = shared.make_unique();
    EXPECT_TRUE(make_unique_result.is_ok());
    EXPECT_FALSE(shared.is_shared());
    EXPECT_TRUE(shared.can_modify());
    
    // Test memory operations
    auto reserve_result = buffer2.reserve(2048);
    EXPECT_TRUE(reserve_result.is_ok());
    EXPECT_GE(buffer2.capacity(), 2048);
    
    auto resize_result = buffer2.resize(512);
    EXPECT_TRUE(resize_result.is_ok());
    EXPECT_EQ(buffer2.size(), 512);
    
    buffer2.clear();
    EXPECT_EQ(buffer2.size(), 0);
    EXPECT_TRUE(buffer2.empty());
    
    // Test security features
    ZeroCopyBuffer secure_buffer(test_data_.data(), test_data_.size());
    secure_buffer.zero_memory();
    for (size_t i = 0; i < secure_buffer.size(); ++i) {
        EXPECT_EQ(secure_buffer.data()[i], std::byte{0});
    }
    
    // Test iterator support
    ZeroCopyBuffer iter_buffer(small_payload_.data(), small_payload_.size());
    auto* begin = iter_buffer.begin();
    auto* end = iter_buffer.end();
    EXPECT_EQ(end - begin, static_cast<ptrdiff_t>(iter_buffer.size()));
    
    const auto& const_buffer = iter_buffer;
    auto* const_begin = const_buffer.cbegin();
    auto* const_end = const_buffer.cend();
    EXPECT_EQ(const_end - const_begin, static_cast<ptrdiff_t>(iter_buffer.size()));
}

// Test DTLS record structures comprehensive coverage
TEST_F(ComprehensiveCoverageTest, DTLSRecordStructuresCoverage) {
    // Test SequenceNumber48 comprehensive coverage
    SequenceNumber48 seq1;
    EXPECT_EQ(seq1.value, 0);
    
    SequenceNumber48 seq2(0x123456789ABC);
    EXPECT_EQ(seq2.value, 0x123456789ABC);
    
    // Test 48-bit overflow handling
    SequenceNumber48 seq3(0xFFFFFFFFFFFFFFFF); // Full 64-bit
    EXPECT_EQ(seq3.value, 0xFFFFFFFFFFFF);     // Should be masked to 48-bit
    
    // Test increment operators
    ++seq1;
    EXPECT_EQ(seq1.value, 1);
    
    auto post_inc = seq1++;
    EXPECT_EQ(seq1.value, 2);
    EXPECT_EQ(post_inc.value, 1);
    
    // Test overflow detection
    SequenceNumber48 max_seq(0xFFFFFFFFFFFF);
    EXPECT_TRUE(max_seq.would_overflow());
    
    SequenceNumber48 not_max(0xFFFFFFFFFFFE);
    EXPECT_FALSE(not_max.would_overflow());
    
    // Test serialization/deserialization
    uint8_t buffer[SequenceNumber48::SERIALIZED_SIZE];
    auto serialize_result = seq2.serialize_to_buffer(buffer);
    ASSERT_TRUE(serialize_result.is_ok());
    
    auto deserialize_result = SequenceNumber48::deserialize_from_buffer(buffer);
    ASSERT_TRUE(deserialize_result.is_ok());
    EXPECT_EQ(deserialize_result.value().value, seq2.value);
    
    // Test DTLSPlaintext comprehensive coverage
    ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
    DTLSPlaintext record(
        ContentType::HANDSHAKE,
        DTLS_V13,
        1,
        SequenceNumber48(42),
        std::move(payload)
    );
    
    EXPECT_EQ(record.type, ContentType::HANDSHAKE);
    EXPECT_EQ(record.version, DTLS_V13);
    EXPECT_EQ(record.epoch, 1);
    EXPECT_EQ(static_cast<uint64_t>(record.sequence_number), 42);
    EXPECT_TRUE(record.is_valid());
    
    // Test serialization with buffer parameter
    ZeroCopyBuffer serialize_buffer(1024);
    auto record_serialize_result = record.serialize(serialize_buffer);
    ASSERT_TRUE(record_serialize_result.is_ok());
    EXPECT_GT(serialize_buffer.size(), DTLSPlaintext::HEADER_SIZE);
    
    // Test deserialization
    auto deserialize_record_result = DTLSPlaintext::deserialize(serialize_buffer);
    ASSERT_TRUE(deserialize_record_result.is_ok());
    
    auto deserialized_record = deserialize_record_result.value();
    EXPECT_EQ(deserialized_record.type, record.type);
    EXPECT_EQ(deserialized_record.version, record.version);
    EXPECT_EQ(deserialized_record.epoch, record.epoch);
    EXPECT_EQ(static_cast<uint64_t>(deserialized_record.sequence_number), static_cast<uint64_t>(record.sequence_number));
    
    // Test validation edge cases
    DTLSPlaintext invalid_record = record;
    invalid_record.type = ContentType::INVALID;
    EXPECT_FALSE(invalid_record.is_valid());
    
    invalid_record = record;
    invalid_record.version = 0x0000;
    EXPECT_FALSE(invalid_record.is_valid());
    
    // Test total size calculation
    EXPECT_EQ(record.total_size(), DTLSPlaintext::HEADER_SIZE + small_payload_.size());
    
    // Test different content types
    std::vector<ContentType> content_types = {
        ContentType::CHANGE_CIPHER_SPEC,
        ContentType::ALERT,
        ContentType::HANDSHAKE,
        ContentType::APPLICATION_DATA,
        ContentType::HEARTBEAT,
        ContentType::ACK
    };
    
    for (auto content_type : content_types) {
        ZeroCopyBuffer type_payload(small_payload_.data(), small_payload_.size());
        DTLSPlaintext type_record(
            content_type,
            DTLS_V13,
            1,
            SequenceNumber48(1),
            std::move(type_payload)
        );
        EXPECT_TRUE(type_record.is_valid());
        EXPECT_EQ(type_record.type, content_type);
    }
}

// Test Anti-Replay Core comprehensive coverage
TEST_F(ComprehensiveCoverageTest, AntiReplayCoreComprehensiveCoverage) {
    // Test WindowState construction
    AntiReplayCore::WindowState window_state;
    EXPECT_EQ(window_state.highest_sequence_number, 0);
    EXPECT_EQ(window_state.received_count, 0);
    EXPECT_EQ(window_state.replay_count, 0);
    EXPECT_EQ(window_state.window.size(), AntiReplayCore::DEFAULT_WINDOW_SIZE);
    
    AntiReplayCore::WindowState custom_window(128);
    EXPECT_EQ(custom_window.window.size(), 128);
    
    // Test sequence number validation
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(1, window_state));
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(2, window_state));
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(100, window_state));
    
    // Test window updates
    EXPECT_TRUE(AntiReplayCore::update_window(1, window_state));
    EXPECT_EQ(window_state.highest_sequence_number, 1);
    EXPECT_EQ(window_state.received_count, 1);
    
    EXPECT_TRUE(AntiReplayCore::update_window(5, window_state));
    EXPECT_EQ(window_state.highest_sequence_number, 5);
    EXPECT_EQ(window_state.received_count, 2);
    
    // Test replay detection
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(1, window_state)); // Replay
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(5, window_state)); // Replay
    
    // Test check_and_update combined operation
    EXPECT_TRUE(AntiReplayCore::check_and_update(10, window_state));
    EXPECT_EQ(window_state.highest_sequence_number, 10);
    EXPECT_EQ(window_state.received_count, 3);
    
    EXPECT_FALSE(AntiReplayCore::check_and_update(10, window_state)); // Replay
    EXPECT_EQ(window_state.replay_count, 1);
    
    // Test window sliding behavior
    uint64_t large_seq = window_state.highest_sequence_number + AntiReplayCore::DEFAULT_WINDOW_SIZE + 10;
    EXPECT_TRUE(AntiReplayCore::check_and_update(large_seq, window_state));
    EXPECT_EQ(window_state.highest_sequence_number, large_seq);
    
    // Test out-of-window packets
    uint64_t old_seq = large_seq - AntiReplayCore::DEFAULT_WINDOW_SIZE - 1;
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(old_seq, window_state));
    
    // Test window utilization
    double utilization = AntiReplayCore::get_window_utilization(window_state);
    EXPECT_GE(utilization, 0.0);
    EXPECT_LE(utilization, 1.0);
    
    // Test statistics
    auto stats = AntiReplayCore::get_stats(window_state);
    EXPECT_EQ(stats.highest_sequence_number, window_state.highest_sequence_number);
    EXPECT_EQ(stats.received_count, window_state.received_count);
    EXPECT_EQ(stats.replay_count, window_state.replay_count);
    EXPECT_EQ(stats.window_size, window_state.window.size());
    EXPECT_GE(stats.utilization_ratio, 0.0);
    EXPECT_LE(stats.utilization_ratio, 1.0);
    
    // Test window reset
    AntiReplayCore::reset_window(window_state);
    EXPECT_EQ(window_state.highest_sequence_number, 0);
    EXPECT_EQ(window_state.received_count, 0);
    EXPECT_EQ(window_state.replay_count, 0);
    
    // Test edge case: sequence number 0
    EXPECT_TRUE(AntiReplayCore::check_and_update(0, window_state));
    EXPECT_EQ(window_state.highest_sequence_number, 0);
    
    // Test rapid sequence updates
    for (uint64_t i = 1; i <= 1000; ++i) {
        bool result = AntiReplayCore::check_and_update(i, window_state);
        EXPECT_TRUE(result);
    }
    EXPECT_EQ(window_state.received_count, 1001); // Including the initial 0
    EXPECT_EQ(window_state.replay_count, 0);
}

// Test crypto provider factory coverage
TEST_F(ComprehensiveCoverageTest, CryptoProviderFactoryCoverage) {
    auto& factory = crypto::ProviderFactory::instance();
    
    // Test getting available providers
    auto providers = factory.get_available_providers();
    // Should have at least OpenSSL provider
    EXPECT_GE(providers.size(), 1);
    
    // Test provider creation
    if (!providers.empty()) {
        const auto& provider_name = providers[0];
        auto provider_result = factory.create_provider(provider_name);
        
        if (provider_result.is_ok()) {
            auto provider = provider_result.value();
            EXPECT_TRUE(provider != nullptr);
            
            // Test provider capabilities
            auto capabilities = provider->get_capabilities();
            // Should support some basic operations
            EXPECT_TRUE(capabilities.supports_aes || 
                       capabilities.supports_rsa || 
                       capabilities.supports_ecdsa);
        }
    }
    
    // Test provider selection with criteria
    crypto::ProviderSelectionCriteria criteria;
    criteria.required_algorithms.push_back("AES-256-GCM");
    criteria.required_algorithms.push_back("SHA-256");
    criteria.minimum_security_level = 128;
    
    auto selected_result = factory.select_best_provider(criteria);
    // May succeed or fail depending on available providers
    
    // Test getting provider information
    if (!providers.empty()) {
        auto info_result = factory.get_provider_info(providers[0]);
        if (info_result.is_ok()) {
            auto info = info_result.value();
            EXPECT_FALSE(info.name.empty());
            EXPECT_FALSE(info.description.empty());
        }
    }
}

// Test comprehensive error scenarios and edge cases
TEST_F(ComprehensiveCoverageTest, ErrorScenariosAndEdgeCases) {
    // Test Result type with various error conditions
    Result<int> success_result = Result<int>::ok(42);
    EXPECT_TRUE(success_result.is_ok());
    EXPECT_FALSE(success_result.is_error());
    EXPECT_EQ(success_result.value(), 42);
    
    Result<int> error_result = Result<int>::error(DTLSError::DECODE_ERROR);
    EXPECT_FALSE(error_result.is_ok());
    EXPECT_TRUE(error_result.is_error());
    EXPECT_EQ(error_result.error(), DTLSError::DECODE_ERROR);
    
    // Test buffer operations with edge cases
    ZeroCopyBuffer small_buffer(10);
    
    // Test overflow conditions
    auto overflow_result = small_buffer.append(large_payload_.data(), large_payload_.size());
    EXPECT_TRUE(overflow_result.is_error());
    
    // Test null pointer handling
    auto null_result = small_buffer.append(nullptr, 10);
    EXPECT_TRUE(null_result.is_error());
    
    // Test invalid slice parameters
    ZeroCopyBuffer test_buffer(test_data_.data(), test_data_.size());
    auto invalid_slice = test_buffer.slice(test_data_.size() + 1, 10);
    EXPECT_TRUE(invalid_slice.is_error());
    
    auto invalid_slice2 = test_buffer.slice(10, test_data_.size());
    EXPECT_TRUE(invalid_slice2.is_error());
    
    // Test DTLSPlaintext deserialization errors
    ZeroCopyBuffer corrupt_data(5); // Too small
    corrupt_data.append(reinterpret_cast<const std::byte*>("HELLO"), 5);
    
    auto corrupt_deserialize = DTLSPlaintext::deserialize(corrupt_data);
    EXPECT_TRUE(corrupt_deserialize.is_error());
    
    // Test invalid sequence number serialization edge cases
    SequenceNumber48 seq(0xFFFFFFFFFFFF);
    uint8_t buffer[SequenceNumber48::SERIALIZED_SIZE];
    auto serialize_result = seq.serialize_to_buffer(buffer);
    EXPECT_TRUE(serialize_result.is_ok());
    
    // Verify all bytes are 0xFF for maximum value
    for (int i = 0; i < SequenceNumber48::SERIALIZED_SIZE; ++i) {
        EXPECT_EQ(buffer[i], 0xFF);
    }
}

// Test performance and stress scenarios
TEST_F(ComprehensiveCoverageTest, PerformanceAndStressScenarios) {
    constexpr int iterations = 1000;
    
    // Stress test memory operations
    std::vector<ZeroCopyBuffer> buffers;
    buffers.reserve(iterations);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        ZeroCopyBuffer buffer(1024);
        auto result = buffer.append(test_data_.data(), test_data_.size());
        ASSERT_TRUE(result.is_ok());
        buffers.push_back(std::move(buffer));
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should complete reasonably quickly
    EXPECT_LT(duration.count(), 100000); // Less than 100ms
    
    // Stress test record operations
    start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        ZeroCopyBuffer payload(small_payload_.data(), small_payload_.size());
        DTLSPlaintext record(
            ContentType::APPLICATION_DATA,
            DTLS_V13,
            static_cast<uint16_t>(i % 65536),
            SequenceNumber48(i),
            std::move(payload)
        );
        
        ZeroCopyBuffer serialize_buffer(1024);
        auto serialize_result = record.serialize(serialize_buffer);
        ASSERT_TRUE(serialize_result.is_ok());
        
        auto deserialize_result = DTLSPlaintext::deserialize(serialize_buffer);
        ASSERT_TRUE(deserialize_result.is_ok());
    }
    
    end_time = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should complete reasonably quickly
    EXPECT_LT(duration.count(), 200000); // Less than 200ms
    
    // Stress test anti-replay
    AntiReplayCore::WindowState window;
    
    start_time = std::chrono::high_resolution_clock::now();
    
    for (uint64_t i = 1; i <= iterations; ++i) {
        bool result = AntiReplayCore::check_and_update(i, window);
        EXPECT_TRUE(result);
    }
    
    end_time = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    EXPECT_LT(duration.count(), 50000); // Less than 50ms
    EXPECT_EQ(window.received_count, iterations);
}

// Test concurrency and thread safety aspects
TEST_F(ComprehensiveCoverageTest, ConcurrencyAndThreadSafety) {
    // Test concurrent buffer operations
    constexpr int num_threads = 4;
    constexpr int operations_per_thread = 100;
    
    std::vector<std::thread> threads;
    std::atomic<int> successful_operations{0};
    std::atomic<int> failed_operations{0};
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < operations_per_thread; ++i) {
                try {
                    ZeroCopyBuffer buffer(512);
                    auto result = buffer.append(small_payload_.data(), small_payload_.size());
                    
                    if (result.is_ok()) {
                        successful_operations.fetch_add(1);
                        
                        // Test sharing
                        auto share_result = buffer.share_buffer();
                        if (share_result.is_ok()) {
                            auto shared = share_result.value();
                            // Use the shared buffer briefly
                            EXPECT_EQ(shared.size(), small_payload_.size());
                        }
                    } else {
                        failed_operations.fetch_add(1);
                    }
                } catch (...) {
                    failed_operations.fetch_add(1);
                }
                
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    int total_expected = num_threads * operations_per_thread;
    EXPECT_EQ(successful_operations.load() + failed_operations.load(), total_expected);
    EXPECT_GT(successful_operations.load(), total_expected * 0.95); // At least 95% success
    
    // Test concurrent anti-replay operations
    AntiReplayCore::WindowState shared_window;
    std::mutex window_mutex; // Protection needed since AntiReplayCore is not thread-safe
    
    threads.clear();
    std::atomic<uint64_t> sequence_counter{1};
    std::atomic<int> replay_detections{0};
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < operations_per_thread; ++i) {
                uint64_t seq = sequence_counter.fetch_add(1);
                
                {
                    std::lock_guard<std::mutex> lock(window_mutex);
                    bool result = AntiReplayCore::check_and_update(seq, shared_window);
                    if (!result) {
                        replay_detections.fetch_add(1);
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::microseconds(5));
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should have no replays since we're using unique sequence numbers
    EXPECT_EQ(replay_detections.load(), 0);
    EXPECT_EQ(shared_window.received_count, total_expected);
}