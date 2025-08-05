#include <gtest/gtest.h>
#include <dtls/protocol/fragment_reassembler.h>
#include <dtls/memory/buffer.h>
#include <dtls/error.h>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>

using namespace dtls::v13;
using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

class FragmentReassemblerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up test configuration
        config_.reassembly_timeout = std::chrono::milliseconds(5000);
        config_.max_concurrent_reassemblies = 100;
        config_.max_reassembly_memory = 1048576; // 1MB
        config_.max_message_size = 65536; // 64KB
        config_.max_fragments_per_message = 64;
        config_.strict_validation = true;
        config_.detect_duplicates = true;
        config_.handle_out_of_order = true;
        
        reassembler_ = std::make_unique<FragmentReassembler>(config_);
        
        // Create test message data
        test_message_data_ = create_test_message(1000); // 1KB test message
    }
    
    ZeroCopyBuffer create_test_message(size_t size) {
        ZeroCopyBuffer buffer(size);
        buffer.resize(size);
        
        uint8_t* data = reinterpret_cast<uint8_t*>(buffer.mutable_data());
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        
        return buffer;
    }
    
    ZeroCopyBuffer create_fragment(const ZeroCopyBuffer& message, 
                                  uint32_t offset, uint32_t length) {
        ZeroCopyBuffer fragment(length);
        fragment.resize(length);
        
        std::memcpy(fragment.mutable_data(), 
                   reinterpret_cast<const uint8_t*>(message.data()) + offset, 
                   length);
                   
        return fragment;
    }
    
    FragmentReassemblyConfig config_;
    std::unique_ptr<FragmentReassembler> reassembler_;
    ZeroCopyBuffer test_message_data_;
};

// Basic Fragment Reassembly Tests
TEST_F(FragmentReassemblerTest, SingleFragmentMessage) {
    uint16_t message_seq = 1;
    uint32_t total_length = test_message_data_.size();
    
    // Add complete message as single fragment
    auto result = reassembler_->add_fragment(
        message_seq, 0, total_length, total_length, test_message_data_);
    
    ASSERT_TRUE(result.is_success());
    EXPECT_TRUE(result.value()); // Should be complete
    EXPECT_TRUE(reassembler_->is_message_complete(message_seq));
    
    // Retrieve complete message
    auto message_result = reassembler_->get_complete_message(message_seq);
    ASSERT_TRUE(message_result.is_success());
    
    const auto& complete_message = message_result.value();
    EXPECT_EQ(complete_message.size(), test_message_data_.size());
    EXPECT_EQ(std::memcmp(complete_message.data(), test_message_data_.data(), 
                         test_message_data_.size()), 0);
}

TEST_F(FragmentReassemblerTest, MultipleFragmentMessage) {
    uint16_t message_seq = 2;
    uint32_t total_length = test_message_data_.size();
    uint32_t fragment_size = 250; // Split into 4 fragments
    
    // Add fragments in order
    for (uint32_t offset = 0; offset < total_length; offset += fragment_size) {
        uint32_t current_fragment_size = std::min(fragment_size, total_length - offset);
        auto fragment_data = create_fragment(test_message_data_, offset, current_fragment_size);
        
        auto result = reassembler_->add_fragment(
            message_seq, offset, current_fragment_size, total_length, fragment_data);
        
        ASSERT_TRUE(result.is_success());
        
        // Last fragment should complete the message
        if (offset + current_fragment_size >= total_length) {
            EXPECT_TRUE(result.value());
            EXPECT_TRUE(reassembler_->is_message_complete(message_seq));
        } else {
            EXPECT_FALSE(result.value());
            EXPECT_FALSE(reassembler_->is_message_complete(message_seq));
        }
    }
    
    // Retrieve and verify complete message
    auto message_result = reassembler_->get_complete_message(message_seq);
    ASSERT_TRUE(message_result.is_success());
    
    const auto& complete_message = message_result.value();
    EXPECT_EQ(complete_message.size(), test_message_data_.size());
    EXPECT_EQ(std::memcmp(complete_message.data(), test_message_data_.data(), 
                         test_message_data_.size()), 0);
}

TEST_F(FragmentReassemblerTest, OutOfOrderFragments) {
    uint16_t message_seq = 3;
    uint32_t total_length = test_message_data_.size();
    uint32_t fragment_size = 200;
    
    std::vector<std::pair<uint32_t, uint32_t>> fragments; // (offset, size) pairs
    
    // Calculate fragment offsets
    for (uint32_t offset = 0; offset < total_length; offset += fragment_size) {
        uint32_t current_fragment_size = std::min(fragment_size, total_length - offset);
        fragments.emplace_back(offset, current_fragment_size);
    }
    
    // Add fragments in reverse order
    for (auto it = fragments.rbegin(); it != fragments.rend(); ++it) {
        uint32_t offset = it->first;
        uint32_t current_fragment_size = it->second;
        auto fragment_data = create_fragment(test_message_data_, offset, current_fragment_size);
        
        auto result = reassembler_->add_fragment(
            message_seq, offset, current_fragment_size, total_length, fragment_data);
        
        ASSERT_TRUE(result.is_success());
        
        // Only the last fragment added (which completes the message) should return true
        if (it == fragments.rend() - 1) {
            EXPECT_TRUE(result.value());
        } else {
            EXPECT_FALSE(result.value());
        }
    }
    
    EXPECT_TRUE(reassembler_->is_message_complete(message_seq));
    
    // Verify complete message
    auto message_result = reassembler_->get_complete_message(message_seq);
    ASSERT_TRUE(message_result.is_success());
    
    const auto& complete_message = message_result.value();
    EXPECT_EQ(complete_message.size(), test_message_data_.size());
    EXPECT_EQ(std::memcmp(complete_message.data(), test_message_data_.data(), 
                         test_message_data_.size()), 0);
}

TEST_F(FragmentReassemblerTest, DuplicateFragmentDetection) {
    uint16_t message_seq = 4;
    uint32_t total_length = 500;
    uint32_t fragment_size = 250;
    
    auto fragment1 = create_fragment(test_message_data_, 0, fragment_size);
    auto fragment2 = create_fragment(test_message_data_, fragment_size, fragment_size);
    
    // Add first fragment
    auto result1 = reassembler_->add_fragment(
        message_seq, 0, fragment_size, total_length, fragment1);
    ASSERT_TRUE(result1.is_success());
    EXPECT_FALSE(result1.value()); // Not complete yet
    
    // Add second fragment
    auto result2 = reassembler_->add_fragment(
        message_seq, fragment_size, fragment_size, total_length, fragment2);
    ASSERT_TRUE(result2.is_success());
    EXPECT_TRUE(result2.value()); // Should be complete
    
    // Try to add duplicate first fragment
    auto result_dup = reassembler_->add_fragment(
        message_seq, 0, fragment_size, total_length, fragment1);
    ASSERT_TRUE(result_dup.is_success());
    EXPECT_TRUE(result_dup.value()); // Still complete
    
    // Verify statistics show duplicate detection
    const auto& stats = reassembler_->get_stats();
    EXPECT_GT(stats.fragments_duplicate.load(), 0);
}

// Error Handling Tests
TEST_F(FragmentReassemblerTest, InvalidFragmentParameters) {
    uint16_t message_seq = 5;
    uint32_t total_length = 1000;
    
    auto fragment_data = create_fragment(test_message_data_, 0, 100);
    
    // Fragment offset beyond total length
    auto result1 = reassembler_->add_fragment(
        message_seq, total_length + 1, 100, total_length, fragment_data);
    EXPECT_FALSE(result1.is_success());
    
    // Fragment extends beyond total length
    auto result2 = reassembler_->add_fragment(
        message_seq, total_length - 50, 100, total_length, fragment_data);
    EXPECT_FALSE(result2.is_success());
    
    // Fragment data size mismatch
    auto result3 = reassembler_->add_fragment(
        message_seq, 0, 200, total_length, fragment_data); // fragment_data is only 100 bytes
    EXPECT_FALSE(result3.is_success());
}

TEST_F(FragmentReassemblerTest, TotalLengthMismatch) {
    uint16_t message_seq = 6;
    uint32_t fragment_size = 100;
    
    auto fragment1 = create_fragment(test_message_data_, 0, fragment_size);
    auto fragment2 = create_fragment(test_message_data_, fragment_size, fragment_size);
    
    // Add first fragment with total length 1000
    auto result1 = reassembler_->add_fragment(
        message_seq, 0, fragment_size, 1000, fragment1);
    ASSERT_TRUE(result1.is_success());
    
    // Try to add second fragment with different total length
    auto result2 = reassembler_->add_fragment(
        message_seq, fragment_size, fragment_size, 2000, fragment2);
    EXPECT_FALSE(result2.is_success());
}

// Memory Management Tests
TEST_F(FragmentReassemblerTest, MemoryLimitEnforcement) {
    // Create reassembler with very small memory limit
    FragmentReassemblyConfig small_config = config_;
    small_config.max_reassembly_memory = 200; // Very small limit
    
    FragmentReassembler small_reassembler(small_config);
    
    uint16_t message_seq = 7;
    uint32_t fragment_size = 150;
    auto fragment_data = create_fragment(test_message_data_, 0, fragment_size);
    
    // First fragment should succeed
    auto result1 = small_reassembler.add_fragment(
        message_seq, 0, fragment_size, 1000, fragment_data);
    ASSERT_TRUE(result1.is_success());
    
    // Second fragment should fail due to memory limit
    auto result2 = small_reassembler.add_fragment(
        message_seq + 1, 0, fragment_size, 1000, fragment_data);
    EXPECT_FALSE(result2.is_success());
    EXPECT_EQ(result2.error(), DTLSError::RESOURCE_EXHAUSTED);
}

TEST_F(FragmentReassemblerTest, ConcurrencyLimitEnforcement) {
    // Create reassembler with small concurrency limit
    FragmentReassemblyConfig small_config = config_;
    small_config.max_concurrent_reassemblies = 2;
    
    FragmentReassembler small_reassembler(small_config);
    
    uint32_t fragment_size = 100;
    auto fragment_data = create_fragment(test_message_data_, 0, fragment_size);
    
    // First two messages should succeed
    auto result1 = small_reassembler.add_fragment(1, 0, fragment_size, 1000, fragment_data);
    ASSERT_TRUE(result1.is_success());
    
    auto result2 = small_reassembler.add_fragment(2, 0, fragment_size, 1000, fragment_data);
    ASSERT_TRUE(result2.is_success());
    
    // Third message should fail due to concurrency limit
    auto result3 = small_reassembler.add_fragment(3, 0, fragment_size, 1000, fragment_data);
    EXPECT_FALSE(result3.is_success());
    EXPECT_EQ(result3.error(), DTLSError::RESOURCE_EXHAUSTED);
}

// Timeout Tests
TEST_F(FragmentReassemblerTest, TimeoutCleanup) {
    // Create reassembler with very short timeout
    FragmentReassemblyConfig timeout_config = config_;
    timeout_config.reassembly_timeout = std::chrono::milliseconds(100);
    
    FragmentReassembler timeout_reassembler(timeout_config);
    
    uint16_t message_seq = 8;
    uint32_t fragment_size = 100;
    auto fragment_data = create_fragment(test_message_data_, 0, fragment_size);
    
    // Add incomplete fragment
    auto result = timeout_reassembler.add_fragment(
        message_seq, 0, fragment_size, 1000, fragment_data);
    ASSERT_TRUE(result.is_success());
    EXPECT_FALSE(result.value()); // Not complete
    
    // Wait for timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    
    // Cleanup should remove timed-out reassembly
    timeout_reassembler.cleanup_timed_out_reassemblies();
    
    // Message should no longer be found
    EXPECT_FALSE(timeout_reassembler.is_message_complete(message_seq));
    
    // Verify timeout statistics
    const auto& stats = timeout_reassembler.get_stats();
    EXPECT_GT(stats.messages_timed_out.load(), 0);
}

// Statistics Tests
TEST_F(FragmentReassemblerTest, StatisticsTracking) {
    uint16_t message_seq = 9;
    uint32_t total_length = test_message_data_.size();
    uint32_t fragment_size = 200;
    
    const auto& stats = reassembler_->get_stats();
    uint64_t initial_messages_started = stats.messages_started.load();
    uint64_t initial_messages_completed = stats.messages_completed.load();
    uint64_t initial_fragments_received = stats.fragments_received.load();
    
    // Add fragments to complete a message
    for (uint32_t offset = 0; offset < total_length; offset += fragment_size) {
        uint32_t current_fragment_size = std::min(fragment_size, total_length - offset);
        auto fragment_data = create_fragment(test_message_data_, offset, current_fragment_size);
        
        auto result = reassembler_->add_fragment(
            message_seq, offset, current_fragment_size, total_length, fragment_data);
        ASSERT_TRUE(result.is_success());
    }
    
    // Retrieve complete message
    auto message_result = reassembler_->get_complete_message(message_seq);
    ASSERT_TRUE(message_result.is_success());
    
    // Verify statistics updated
    EXPECT_GT(stats.messages_started.load(), initial_messages_started);
    EXPECT_GT(stats.messages_completed.load(), initial_messages_completed);
    EXPECT_GT(stats.fragments_received.load(), initial_fragments_received);
    EXPECT_GT(stats.get_success_rate(), 0.0);
}

// Connection Fragment Manager Tests
class ConnectionFragmentManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager_ = std::make_unique<ConnectionFragmentManager>();
    }
    
    HandshakeHeader create_test_header(HandshakeType type, uint16_t message_seq,
                                     uint32_t length, uint32_t fragment_offset,
                                     uint32_t fragment_length) {
        HandshakeHeader header;
        header.msg_type = type;
        header.message_seq = message_seq;
        header.length = length;
        header.fragment_offset = fragment_offset;
        header.fragment_length = fragment_length;
        return header;
    }
    
    ZeroCopyBuffer create_client_hello_fragment(size_t size = 100) {
        // Create test data of the requested size
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        
        ZeroCopyBuffer buffer(data.size());
        buffer.resize(data.size());
        std::memcpy(buffer.mutable_data(), data.data(), data.size());
        return buffer;
    }
    
    std::unique_ptr<ConnectionFragmentManager> manager_;
};

TEST_F(ConnectionFragmentManagerTest, CompleteHandshakeMessage) {
    auto header = create_test_header(HandshakeType::CLIENT_HELLO, 1, 100, 0, 100);
    auto fragment_data = create_client_hello_fragment(100);
    
    // Process complete fragment - this will fail during deserialization
    // since we're using test data that's not a valid ClientHello
    auto result = manager_->process_handshake_fragment(header, fragment_data);
    EXPECT_FALSE(result.is_success()); // Expected to fail due to invalid ClientHello data
    
    // Test that the underlying reassembly worked by checking fragment manager stats
    const auto& stats = manager_->get_stats();
    EXPECT_GT(stats.fragments_received.load(), 0);
}

TEST_F(ConnectionFragmentManagerTest, MaintenanceCleanup) {
    // Add some incomplete fragments and verify maintenance works
    auto header = create_test_header(HandshakeType::CLIENT_HELLO, 2, 200, 0, 100);
    auto fragment_data = create_client_hello_fragment();
    fragment_data.resize(100);
    
    auto result = manager_->process_handshake_fragment(header, fragment_data);
    ASSERT_TRUE(result.is_success());
    EXPECT_FALSE(result.value()); // Not complete
    
    // Perform maintenance (should not crash)
    manager_->perform_maintenance();
    
    // Get statistics
    const auto& stats = manager_->get_stats();
    EXPECT_GT(stats.fragments_received.load(), 0);
}

// Performance Tests
TEST_F(FragmentReassemblerTest, LargeMessagePerformance) {
    auto large_message = create_test_message(32768); // 32KB message
    uint16_t message_seq = 100;
    uint32_t total_length = large_message.size();
    uint32_t fragment_size = 1024; // 1KB fragments
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Fragment and reassemble large message
    for (uint32_t offset = 0; offset < total_length; offset += fragment_size) {
        uint32_t current_fragment_size = std::min(fragment_size, total_length - offset);
        auto fragment_data = create_fragment(large_message, offset, current_fragment_size);
        
        auto result = reassembler_->add_fragment(
            message_seq, offset, current_fragment_size, total_length, fragment_data);
        ASSERT_TRUE(result.is_success());
    }
    
    auto message_result = reassembler_->get_complete_message(message_seq);
    ASSERT_TRUE(message_result.is_success());
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Performance should be reasonable (less than 10ms for 32KB message)
    EXPECT_LT(duration.count(), 10000); // 10ms limit
    
    // Verify message integrity
    const auto& complete_message = message_result.value();
    EXPECT_EQ(complete_message.size(), large_message.size());
    EXPECT_EQ(std::memcmp(complete_message.data(), large_message.data(), 
                         large_message.size()), 0);
}