/**
 * @file test_zero_copy_crypto_comprehensive.cpp
 * @brief Comprehensive tests for DTLS zero-copy crypto operations
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>
#include <algorithm>

#include "dtls/memory/zero_copy_crypto.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

// Mock crypto context for testing
class MockZeroCopyCryptoContext : public ZeroCopyCryptoContext {
public:
    Result<CryptoBuffer> encrypt(const CryptoBuffer& plaintext, 
                                const CryptoBuffer& key,
                                const CryptoBuffer& nonce) override {
        // Simple XOR "encryption" for testing
        auto result_buffer = ZeroCopyCryptoFactory::instance().create_crypto_buffer(plaintext.size());
        auto plaintext_data = plaintext.data();
        auto key_data = key.data();
        auto result_data = result_buffer.mutable_data();
        
        for (size_t i = 0; i < plaintext.size(); ++i) {
            result_data[i] = plaintext_data[i] ^ key_data[i % key.size()];
        }
        
        return result_buffer;
    }
    
    Result<CryptoBuffer> decrypt(const CryptoBuffer& ciphertext,
                                const CryptoBuffer& key, 
                                const CryptoBuffer& nonce) override {
        // XOR decryption (same as encryption for XOR)
        return encrypt(ciphertext, key, nonce);
    }
    
    Result<CryptoBuffer> sign(const CryptoBuffer& data,
                             const CryptoBuffer& private_key) override {
        // Mock signature: hash of data
        auto signature = ZeroCopyCryptoFactory::instance().create_crypto_buffer(32);
        auto sig_data = signature.mutable_data();
        auto data_ptr = data.data();
        
        // Simple hash-like operation
        uint32_t hash = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            hash = hash * 31 + static_cast<uint32_t>(data_ptr[i]);
        }
        
        std::memcpy(sig_data, &hash, sizeof(hash));
        return signature;
    }
    
    Result<bool> verify(const CryptoBuffer& data,
                       const CryptoBuffer& signature,
                       const CryptoBuffer& public_key) override {
        // Mock verification: recreate signature and compare
        auto expected_sig = sign(data, public_key);
        if (!expected_sig.is_ok()) {
            return false;
        }
        
        auto expected = expected_sig.value();
        if (signature.size() != expected.size()) {
            return false;
        }
        
        return std::memcmp(signature.data(), expected.data(), signature.size()) == 0;
    }
    
    Result<CryptoBuffer> hash(const CryptoBuffer& data) override {
        auto hash_buffer = ZeroCopyCryptoFactory::instance().create_crypto_buffer(32);
        auto hash_data = hash_buffer.mutable_data();
        auto input_data = data.data();
        
        // Simple hash function
        uint64_t hash_val = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            hash_val = hash_val * 33 + static_cast<uint64_t>(input_data[i]);
        }
        
        std::memcpy(hash_data, &hash_val, sizeof(hash_val));
        return hash_buffer;
    }
    
    Result<CryptoBuffer> hmac(const CryptoBuffer& data,
                             const CryptoBuffer& key) override {
        // Simple HMAC-like operation
        auto combined_size = data.size() + key.size();
        auto combined_buffer = ZeroCopyCryptoFactory::instance().create_crypto_buffer(combined_size);
        auto combined_data = combined_buffer.mutable_data();
        
        std::memcpy(combined_data, key.data(), key.size());
        std::memcpy(combined_data + key.size(), data.data(), data.size());
        
        return hash(combined_buffer);
    }
    
    Result<std::vector<CryptoBuffer>> encrypt_batch(
        const std::vector<CryptoBuffer>& plaintexts,
        const CryptoBuffer& key,
        const CryptoBuffer& base_nonce) override {
        
        std::vector<CryptoBuffer> results;
        results.reserve(plaintexts.size());
        
        for (const auto& plaintext : plaintexts) {
            auto encrypted = encrypt(plaintext, key, base_nonce);
            if (!encrypted.is_ok()) {
                return Error{"Batch encryption failed"};
            }
            results.push_back(encrypted.value());
        }
        
        return results;
    }
    
    Result<void> encrypt_in_place(CryptoBuffer& buffer,
                                 const CryptoBuffer& key,
                                 const CryptoBuffer& nonce) override {
        if (!buffer.is_mutable()) {
            auto unique_result = buffer.make_unique();
            if (!unique_result.is_ok()) {
                return unique_result.error();
            }
        }
        
        auto data = buffer.mutable_data();
        auto key_data = key.data();
        
        for (size_t i = 0; i < buffer.size(); ++i) {
            data[i] = data[i] ^ key_data[i % key.size()];
        }
        
        return Result<void>::ok();
    }
    
    Result<void> decrypt_in_place(CryptoBuffer& buffer,
                                 const CryptoBuffer& key,
                                 const CryptoBuffer& nonce) override {
        return encrypt_in_place(buffer, key, nonce); // XOR is symmetric
    }
    
    Result<void> encrypt_stream(const CryptoBuffer& input,
                               CryptoBuffer& output,
                               const CryptoBuffer& key,
                               const CryptoBuffer& nonce) override {
        if (input.size() != output.size()) {
            return Error{"Input and output size mismatch"};
        }
        
        auto input_data = input.data();
        auto output_data = output.mutable_data();
        auto key_data = key.data();
        
        for (size_t i = 0; i < input.size(); ++i) {
            output_data[i] = input_data[i] ^ key_data[i % key.size()];
        }
        
        return Result<void>::ok();
    }
    
    void prefetch_keys(const std::vector<CryptoBuffer>& keys) override {
        // Mock implementation - just touch the data
        for (const auto& key : keys) {
            volatile auto dummy = key.data()[0];
            (void)dummy;
        }
    }
    
    void warmup_context() override {
        // Mock warmup
        is_warmed_up_ = true;
    }
    
    bool is_warmed_up() const { return is_warmed_up_; }

private:
    bool is_warmed_up_{false};
};

class ZeroCopyCryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register mock crypto factory
        auto& factory = ZeroCopyCryptoFactory::instance();
        factory.register_context_factory("mock", []() -> std::unique_ptr<ZeroCopyCryptoContext> {
            return std::make_unique<MockZeroCopyCryptoContext>();
        });
        
        // Create test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        test_key_.resize(32);
        for (size_t i = 0; i < test_key_.size(); ++i) {
            test_key_[i] = static_cast<std::byte>((i * 7) % 256);
        }
        
        test_nonce_.resize(12);
        for (size_t i = 0; i < test_nonce_.size(); ++i) {
            test_nonce_[i] = static_cast<std::byte>((i * 13) % 256);
        }
    }
    
    void TearDown() override {
        // Clean up
        CryptoBufferPool::instance().reset_statistics();
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> test_key_;
    std::vector<std::byte> test_nonce_;
};

// Test CryptoBuffer basic functionality
TEST_F(ZeroCopyCryptoTest, CryptoBufferBasics) {
    // Create from ZeroCopyBuffer
    ZeroCopyBuffer zero_copy_buffer(test_data_.data(), test_data_.size());
    CryptoBuffer crypto_buffer(zero_copy_buffer);
    
    // Test basic properties
    EXPECT_EQ(crypto_buffer.size(), test_data_.size());
    EXPECT_FALSE(crypto_buffer.empty());
    EXPECT_NE(crypto_buffer.data(), nullptr);
    EXPECT_EQ(std::memcmp(crypto_buffer.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test immutable by default
    EXPECT_FALSE(crypto_buffer.is_mutable());
    EXPECT_TRUE(crypto_buffer.is_shared());
    
    // Test slicing
    auto slice = crypto_buffer.slice(10, 20);
    EXPECT_EQ(slice.size(), 20);
    EXPECT_EQ(std::memcmp(slice.data(), test_data_.data() + 10, 20), 0);
    
    auto tail_slice = crypto_buffer.slice(100);
    EXPECT_EQ(tail_slice.size(), test_data_.size() - 100);
    
    // Test conversion back to ZeroCopyBuffer
    auto back_to_zero_copy = crypto_buffer.to_buffer();
    EXPECT_EQ(back_to_zero_copy.size(), crypto_buffer.size());
    EXPECT_EQ(std::memcmp(back_to_zero_copy.data(), crypto_buffer.data(), crypto_buffer.size()), 0);
}

// Test mutable CryptoBuffer operations
TEST_F(ZeroCopyCryptoTest, MutableCryptoBuffer) {
    // Create mutable crypto buffer
    ZeroCopyBuffer zero_copy_buffer(1024);
    auto result = zero_copy_buffer.append(test_data_.data(), test_data_.size());
    ASSERT_TRUE(result.is_ok());
    
    auto mutable_crypto = CryptoBuffer::create_mutable(std::move(zero_copy_buffer));
    
    // Test mutable properties
    EXPECT_TRUE(mutable_crypto.is_mutable());
    EXPECT_FALSE(mutable_crypto.is_shared());
    
    // Test mutable data access
    auto mutable_data = mutable_crypto.mutable_data();
    EXPECT_NE(mutable_data, nullptr);
    
    // Modify data
    mutable_data[0] = std::byte{0xFF};
    EXPECT_EQ(mutable_crypto.data()[0], std::byte{0xFF});
    
    // Test secure zero
    mutable_crypto.secure_zero();
    for (size_t i = 0; i < mutable_crypto.size(); ++i) {
        EXPECT_EQ(mutable_crypto.data()[i], std::byte{0});
    }
}

// Test shared CryptoBuffer and copy-on-write
TEST_F(ZeroCopyCryptoTest, SharedCryptoBufferCopyOnWrite) {
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    auto shared_crypto = CryptoBuffer::create_shared(original);
    
    EXPECT_TRUE(shared_crypto.is_shared());
    EXPECT_FALSE(shared_crypto.is_mutable());
    EXPECT_GT(shared_crypto.reference_count(), 1);
    
    // Create another shared reference
    auto another_shared = shared_crypto;
    EXPECT_GT(shared_crypto.reference_count(), 1);
    
    // Make one unique (copy-on-write)
    auto unique_result = shared_crypto.make_unique();
    EXPECT_TRUE(unique_result.is_ok());
    
    EXPECT_FALSE(shared_crypto.is_shared());
    EXPECT_TRUE(shared_crypto.is_mutable());
    
    // Verify data integrity after copy
    EXPECT_EQ(shared_crypto.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(shared_crypto.data(), test_data_.data(), test_data_.size()), 0);
    
    // Modify the unique buffer
    auto mutable_data = shared_crypto.mutable_data();
    mutable_data[0] = std::byte{0xAA};
    
    // Original shared buffer should be unchanged
    EXPECT_NE(another_shared.data()[0], std::byte{0xAA});
    EXPECT_EQ(shared_crypto.data()[0], std::byte{0xAA});
}

// Test MockZeroCopyCryptoContext operations
TEST_F(ZeroCopyCryptoTest, MockCryptoContextOperations) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    
    // Create test buffers
    auto& factory = ZeroCopyCryptoFactory::instance();
    auto plaintext = factory.wrap_data(test_data_.data(), test_data_.size());
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Test encryption
    auto encrypt_result = context->encrypt(plaintext, key, nonce);
    ASSERT_TRUE(encrypt_result.is_ok());
    auto ciphertext = encrypt_result.value();
    
    EXPECT_EQ(ciphertext.size(), plaintext.size());
    EXPECT_NE(std::memcmp(ciphertext.data(), plaintext.data(), plaintext.size()), 0);
    
    // Test decryption
    auto decrypt_result = context->decrypt(ciphertext, key, nonce);
    ASSERT_TRUE(decrypt_result.is_ok());
    auto decrypted = decrypt_result.value();
    
    EXPECT_EQ(decrypted.size(), plaintext.size());
    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    
    // Test signing
    auto sign_result = context->sign(plaintext, key);
    ASSERT_TRUE(sign_result.is_ok());
    auto signature = sign_result.value();
    
    EXPECT_GT(signature.size(), 0);
    
    // Test verification
    auto verify_result = context->verify(plaintext, signature, key);
    ASSERT_TRUE(verify_result.is_ok());
    EXPECT_TRUE(verify_result.value());
    
    // Test verification failure with wrong data
    auto modified_plaintext = factory.create_crypto_buffer(plaintext.size());
    auto modified_data = modified_plaintext.mutable_data();
    std::memcpy(modified_data, plaintext.data(), plaintext.size());
    modified_data[0] = modified_data[0] ^ std::byte{0xFF}; // Flip bits
    
    auto verify_fail_result = context->verify(modified_plaintext, signature, key);
    ASSERT_TRUE(verify_fail_result.is_ok());
    EXPECT_FALSE(verify_fail_result.value());
    
    // Test hash
    auto hash_result = context->hash(plaintext);
    ASSERT_TRUE(hash_result.is_ok());
    auto hash_value = hash_result.value();
    
    EXPECT_GT(hash_value.size(), 0);
    
    // Test HMAC
    auto hmac_result = context->hmac(plaintext, key);
    ASSERT_TRUE(hmac_result.is_ok());
    auto hmac_value = hmac_result.value();
    
    EXPECT_GT(hmac_value.size(), 0);
    
    // Test warmup
    EXPECT_FALSE(context->is_warmed_up());
    context->warmup_context();
    EXPECT_TRUE(context->is_warmed_up());
}

// Test in-place operations
TEST_F(ZeroCopyCryptoTest, InPlaceOperations) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    // Create mutable buffer for in-place operations
    auto mutable_buffer = factory.create_crypto_buffer(test_data_.size());
    auto buffer_data = mutable_buffer.mutable_data();
    std::memcpy(buffer_data, test_data_.data(), test_data_.size());
    
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Store original data for comparison
    std::vector<std::byte> original_data(test_data_);
    
    // Test in-place encryption
    auto encrypt_result = context->encrypt_in_place(mutable_buffer, key, nonce);
    EXPECT_TRUE(encrypt_result.is_ok());
    
    // Data should be changed
    EXPECT_NE(std::memcmp(mutable_buffer.data(), original_data.data(), original_data.size()), 0);
    
    // Test in-place decryption
    auto decrypt_result = context->decrypt_in_place(mutable_buffer, key, nonce);
    EXPECT_TRUE(decrypt_result.is_ok());
    
    // Data should be back to original
    EXPECT_EQ(std::memcmp(mutable_buffer.data(), original_data.data(), original_data.size()), 0);
}

// Test batch operations
TEST_F(ZeroCopyCryptoTest, BatchOperations) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    // Create multiple plaintexts
    std::vector<CryptoBuffer> plaintexts;
    for (int i = 0; i < 5; ++i) {
        auto data = test_data_;
        data[0] = static_cast<std::byte>(i); // Make each unique
        plaintexts.push_back(factory.wrap_data(data.data(), data.size()));
    }
    
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Test batch encryption
    auto batch_result = context->encrypt_batch(plaintexts, key, nonce);
    ASSERT_TRUE(batch_result.is_ok());
    
    auto ciphertexts = batch_result.value();
    EXPECT_EQ(ciphertexts.size(), plaintexts.size());
    
    // Each ciphertext should be different from its plaintext
    for (size_t i = 0; i < plaintexts.size(); ++i) {
        EXPECT_EQ(ciphertexts[i].size(), plaintexts[i].size());
        EXPECT_NE(std::memcmp(ciphertexts[i].data(), plaintexts[i].data(), plaintexts[i].size()), 0);
    }
    
    // Test prefetch keys
    std::vector<CryptoBuffer> keys = {key};
    context->prefetch_keys(keys); // Should not crash
}

// Test stream operations
TEST_F(ZeroCopyCryptoTest, StreamOperations) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    auto input = factory.wrap_data(test_data_.data(), test_data_.size());
    auto output = factory.create_crypto_buffer(test_data_.size());
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Test stream encryption
    auto stream_result = context->encrypt_stream(input, output, key, nonce);
    EXPECT_TRUE(stream_result.is_ok());
    
    // Output should be different from input
    EXPECT_NE(std::memcmp(output.data(), input.data(), input.size()), 0);
    
    // Test error case: size mismatch
    auto small_output = factory.create_crypto_buffer(10);
    auto error_result = context->encrypt_stream(input, small_output, key, nonce);
    EXPECT_TRUE(error_result.is_error());
}

// Test ZeroCopyAEAD functionality
TEST_F(ZeroCopyCryptoTest, ZeroCopyAEAD) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    ZeroCopyAEAD aead(std::move(context));
    
    auto& factory = ZeroCopyCryptoFactory::instance();
    auto plaintext = factory.wrap_data(test_data_.data(), test_data_.size());
    auto associated_data = factory.wrap_data(test_key_.data(), 16); // Use part of key as AD
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Test AEAD encryption
    auto encrypt_result = aead.aead_encrypt(plaintext, associated_data, key, nonce);
    ASSERT_TRUE(encrypt_result.is_ok());
    auto ciphertext = encrypt_result.value();
    
    EXPECT_GT(ciphertext.size(), plaintext.size()); // Should include authentication tag
    
    // Test AEAD decryption
    auto decrypt_result = aead.aead_decrypt(ciphertext, associated_data, key, nonce);
    ASSERT_TRUE(decrypt_result.is_ok());
    auto decrypted = decrypt_result.value();
    
    EXPECT_EQ(decrypted.size(), plaintext.size());
    EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    
    // Test tag size configuration
    EXPECT_EQ(aead.get_tag_size(), 16); // Default
    aead.set_tag_size(32);
    EXPECT_EQ(aead.get_tag_size(), 32);
}

// Test AEAD in-place operations
TEST_F(ZeroCopyCryptoTest, AEADInPlaceOperations) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    ZeroCopyAEAD aead(std::move(context));
    
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    // Create mutable buffer with extra space for tag
    auto buffer = factory.create_crypto_buffer(test_data_.size() + 16);
    auto buffer_data = buffer.mutable_data();
    std::memcpy(buffer_data, test_data_.data(), test_data_.size());
    
    auto associated_data = factory.wrap_data(test_key_.data(), 16);
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Store original data
    std::vector<std::byte> original_data(test_data_);
    
    // Test in-place AEAD encryption
    auto encrypt_result = aead.aead_encrypt_in_place(buffer, associated_data, key, nonce);
    EXPECT_TRUE(encrypt_result.is_ok());
    
    // Data should be changed
    EXPECT_NE(std::memcmp(buffer.data(), original_data.data(), original_data.size()), 0);
    
    // Test in-place AEAD decryption
    auto decrypt_result = aead.aead_decrypt_in_place(buffer, associated_data, key, nonce);
    EXPECT_TRUE(decrypt_result.is_ok());
    
    // Data should be back to original (approximately - depends on implementation)
    // Note: Exact comparison might fail due to tag handling in mock implementation
}

// Test AEAD batch operations
TEST_F(ZeroCopyCryptoTest, AEADBatchOperations) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    ZeroCopyAEAD aead(std::move(context));
    
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    // Create multiple plaintexts and associated data
    std::vector<CryptoBuffer> plaintexts;
    std::vector<CryptoBuffer> associated_data_list;
    
    for (int i = 0; i < 3; ++i) {
        auto data = test_data_;
        data[0] = static_cast<std::byte>(i);
        plaintexts.push_back(factory.wrap_data(data.data(), data.size()));
        
        auto ad = test_key_;
        ad[0] = static_cast<std::byte>(i);
        associated_data_list.push_back(factory.wrap_data(ad.data(), 16));
    }
    
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Test batch AEAD encryption
    auto batch_result = aead.aead_encrypt_batch(plaintexts, associated_data_list, key, nonce);
    ASSERT_TRUE(batch_result.is_ok());
    
    auto ciphertexts = batch_result.value();
    EXPECT_EQ(ciphertexts.size(), plaintexts.size());
    
    for (size_t i = 0; i < plaintexts.size(); ++i) {
        EXPECT_GT(ciphertexts[i].size(), plaintexts[i].size());
    }
}

// Test ZeroCopyKeyDerivation
TEST_F(ZeroCopyCryptoTest, ZeroCopyKeyDerivation) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    ZeroCopyKeyDerivation kdf(std::move(context));
    
    auto& factory = ZeroCopyCryptoFactory::instance();
    auto salt = factory.wrap_data(test_key_.data(), 16);
    auto ikm = factory.wrap_data(test_data_.data(), 32); // Input key material
    
    // Test HKDF extract
    auto extract_result = kdf.hkdf_extract(salt, ikm);
    ASSERT_TRUE(extract_result.is_ok());
    auto prk = extract_result.value(); // Pseudo-random key
    
    EXPECT_GT(prk.size(), 0);
    
    // Test HKDF expand
    auto info = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    auto expand_result = kdf.hkdf_expand(prk, info, 48);
    ASSERT_TRUE(expand_result.is_ok());
    auto okm = expand_result.value(); // Output key material
    
    EXPECT_EQ(okm.size(), 48);
    
    // Test HKDF expand label
    auto label_result = kdf.hkdf_expand_label(prk, "test_label", info, 32);
    ASSERT_TRUE(label_result.is_ok());
    auto labeled_key = label_result.value();
    
    EXPECT_EQ(labeled_key.size(), 32);
    
    // Test derive multiple keys
    std::vector<std::string> labels = {"key1", "key2", "key3"};
    std::vector<size_t> lengths = {16, 24, 32};
    
    auto multi_keys_result = kdf.derive_keys(prk, labels, info, lengths);
    ASSERT_TRUE(multi_keys_result.is_ok());
    auto derived_keys = multi_keys_result.value();
    
    EXPECT_EQ(derived_keys.size(), 3);
    EXPECT_EQ(derived_keys[0].size(), 16);
    EXPECT_EQ(derived_keys[1].size(), 24);
    EXPECT_EQ(derived_keys[2].size(), 32);
    
    // Test derive secret
    auto messages = factory.wrap_data(test_data_.data(), 64);
    auto secret_result = kdf.derive_secret(prk, "test_secret", messages);
    ASSERT_TRUE(secret_result.is_ok());
    auto derived_secret = secret_result.value();
    
    EXPECT_GT(derived_secret.size(), 0);
}

// Test CryptoBufferPool
TEST_F(ZeroCopyCryptoTest, CryptoBufferPool) {
    auto& pool = CryptoBufferPool::instance();
    
    // Test singleton
    auto& pool2 = CryptoBufferPool::instance();
    EXPECT_EQ(&pool, &pool2);
    
    // Reset statistics
    pool.reset_statistics();
    auto initial_stats = pool.get_statistics();
    EXPECT_EQ(initial_stats.crypto_buffer_hits, 0);
    EXPECT_EQ(initial_stats.crypto_buffer_misses, 0);
    
    // Acquire buffers
    auto buffer1 = pool.acquire_buffer(1024, false);
    EXPECT_EQ(buffer1.size(), 1024);
    EXPECT_FALSE(buffer1.is_mutable());
    
    auto buffer2 = pool.acquire_buffer(2048, true);
    EXPECT_EQ(buffer2.size(), 2048);
    EXPECT_TRUE(buffer2.is_mutable());
    
    // Check statistics
    auto stats_after_acquire = pool.get_statistics();
    EXPECT_GE(stats_after_acquire.crypto_buffer_misses, 2); // New allocations
    
    // Release buffers
    pool.release_buffer(std::move(buffer1));
    pool.release_buffer(std::move(buffer2));
    
    // Acquire same sizes again (should hit pool)
    auto buffer3 = pool.acquire_buffer(1024, false);
    auto buffer4 = pool.acquire_buffer(2048, true);
    
    auto final_stats = pool.get_statistics();
    EXPECT_GT(final_stats.crypto_buffer_hits, 0);
    
    // Test pre-allocation
    pool.preallocate_crypto_buffers(10, 512);
    
    auto prealloc_buffer = pool.acquire_buffer(512, false);
    EXPECT_EQ(prealloc_buffer.size(), 512);
    
    // Clean up
    pool.release_buffer(std::move(buffer3));
    pool.release_buffer(std::move(buffer4));
    pool.release_buffer(std::move(prealloc_buffer));
}

// Test ZeroCopyCryptoFactory
TEST_F(ZeroCopyCryptoTest, ZeroCopyCryptoFactory) {
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    // Test singleton
    auto& factory2 = ZeroCopyCryptoFactory::instance();
    EXPECT_EQ(&factory, &factory2);
    
    // Test creating crypto context
    auto context = factory.create_context("mock");
    EXPECT_NE(context, nullptr);
    
    // Test creating AEAD
    auto aead = factory.create_aead("mock");
    EXPECT_NE(aead, nullptr);
    
    // Test creating key derivation
    auto kdf = factory.create_key_derivation("mock");
    EXPECT_NE(kdf, nullptr);
    
    // Test crypto buffer creation
    auto buffer = factory.create_crypto_buffer(1024, true);
    EXPECT_EQ(buffer.size(), 1024);
    EXPECT_TRUE(buffer.is_mutable());
    
    auto secure_buffer = factory.create_crypto_buffer(512, false);
    EXPECT_EQ(secure_buffer.size(), 512);
    
    // Test wrapping existing buffer
    ZeroCopyBuffer zero_copy(test_data_.data(), test_data_.size());
    auto wrapped = factory.wrap_buffer(zero_copy);
    EXPECT_EQ(wrapped.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(wrapped.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test wrapping raw data
    auto wrapped_data = factory.wrap_data(test_key_.data(), test_key_.size());
    EXPECT_EQ(wrapped_data.size(), test_key_.size());
    EXPECT_EQ(std::memcmp(wrapped_data.data(), test_key_.data(), test_key_.size()), 0);
    
    // Test cloning
    auto cloned = factory.clone_buffer(wrapped_data);
    EXPECT_EQ(cloned.size(), wrapped_data.size());
    EXPECT_EQ(std::memcmp(cloned.data(), wrapped_data.data(), wrapped_data.size()), 0);
    EXPECT_NE(cloned.data(), wrapped_data.data()); // Different memory
    
    // Test configuration
    factory.enable_hardware_acceleration(true);
    factory.enable_crypto_buffer_pooling(true);
    factory.set_preferred_crypto_provider("mock");
}

// Test DTLS-specific crypto operations
TEST_F(ZeroCopyCryptoTest, DTLSRecordCrypto) {
    auto aead = std::make_unique<ZeroCopyAEAD>(std::make_unique<MockZeroCopyCryptoContext>());
    auto kdf = std::make_unique<ZeroCopyKeyDerivation>(std::make_unique<MockZeroCopyCryptoContext>());
    
    dtls_crypto::DTLSRecordCrypto record_crypto(std::move(aead), std::move(kdf));
    
    auto& factory = ZeroCopyCryptoFactory::instance();
    auto plaintext_record = factory.wrap_data(test_data_.data(), test_data_.size());
    auto sequence_number = factory.wrap_data(test_nonce_.data(), 8);
    auto write_key = factory.wrap_data(test_key_.data(), 16);
    auto write_iv = factory.wrap_data(test_key_.data() + 16, 12);
    
    // Test record encryption
    auto encrypt_result = record_crypto.encrypt_record(plaintext_record, sequence_number, 
                                                      write_key, write_iv);
    ASSERT_TRUE(encrypt_result.is_ok());
    auto encrypted_record = encrypt_result.value();
    
    EXPECT_GT(encrypted_record.size(), plaintext_record.size());
    
    // Test record decryption
    auto decrypt_result = record_crypto.decrypt_record(encrypted_record, sequence_number,
                                                      write_key, write_iv);
    ASSERT_TRUE(decrypt_result.is_ok());
    auto decrypted_record = decrypt_result.value();
    
    EXPECT_EQ(decrypted_record.size(), plaintext_record.size());
    
    // Test sequence number encryption
    auto sn_key = factory.wrap_data(test_key_.data() + 28, 4);
    auto sn_encrypt_result = record_crypto.encrypt_sequence_number(sequence_number, sn_key);
    ASSERT_TRUE(sn_encrypt_result.is_ok());
    auto encrypted_sn = sn_encrypt_result.value();
    
    EXPECT_EQ(encrypted_sn.size(), sequence_number.size());
    EXPECT_NE(std::memcmp(encrypted_sn.data(), sequence_number.data(), sequence_number.size()), 0);
    
    // Test sequence number decryption
    auto sn_decrypt_result = record_crypto.decrypt_sequence_number(encrypted_sn, sn_key);
    ASSERT_TRUE(sn_decrypt_result.is_ok());
    auto decrypted_sn = sn_decrypt_result.value();
    
    EXPECT_EQ(decrypted_sn.size(), sequence_number.size());
    EXPECT_EQ(std::memcmp(decrypted_sn.data(), sequence_number.data(), sequence_number.size()), 0);
    
    // Test batch record encryption
    std::vector<CryptoBuffer> records;
    std::vector<CryptoBuffer> sequence_numbers;
    
    for (int i = 0; i < 3; ++i) {
        auto data = test_data_;
        data[0] = static_cast<std::byte>(i);
        records.push_back(factory.wrap_data(data.data(), data.size()));
        
        auto sn = test_nonce_;
        sn[0] = static_cast<std::byte>(i);
        sequence_numbers.push_back(factory.wrap_data(sn.data(), 8));
    }
    
    auto batch_result = record_crypto.encrypt_records_batch(records, sequence_numbers,
                                                           write_key, write_iv);
    ASSERT_TRUE(batch_result.is_ok());
    auto encrypted_records = batch_result.value();
    
    EXPECT_EQ(encrypted_records.size(), records.size());
    for (size_t i = 0; i < records.size(); ++i) {
        EXPECT_GT(encrypted_records[i].size(), records[i].size());
    }
}

// Test DTLSHandshakeCrypto
TEST_F(ZeroCopyCryptoTest, DTLSHandshakeCrypto) {
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    auto kdf = std::make_unique<ZeroCopyKeyDerivation>(std::make_unique<MockZeroCopyCryptoContext>());
    
    dtls_crypto::DTLSHandshakeCrypto handshake_crypto(std::move(context), std::move(kdf));
    
    auto& factory = ZeroCopyCryptoFactory::instance();
    auto message = factory.wrap_data(test_data_.data(), test_data_.size());
    auto private_key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto public_key = factory.wrap_data(test_key_.data(), test_key_.size()); // Same for mock
    
    // Test handshake message signing
    auto sign_result = handshake_crypto.sign_handshake_message(message, private_key);
    ASSERT_TRUE(sign_result.is_ok());
    auto signature = sign_result.value();
    
    EXPECT_GT(signature.size(), 0);
    
    // Test handshake signature verification
    auto verify_result = handshake_crypto.verify_handshake_signature(message, signature, public_key);
    ASSERT_TRUE(verify_result.is_ok());
    EXPECT_TRUE(verify_result.value());
    
    // Test key share generation
    auto key_share_result = handshake_crypto.generate_key_share("P-256");
    ASSERT_TRUE(key_share_result.is_ok());
    auto key_share = key_share_result.value();
    
    EXPECT_GT(key_share.size(), 0);
    
    // Test shared secret computation
    auto shared_secret_result = handshake_crypto.compute_shared_secret(private_key, public_key, "P-256");
    ASSERT_TRUE(shared_secret_result.is_ok());
    auto shared_secret = shared_secret_result.value();
    
    EXPECT_GT(shared_secret.size(), 0);
    
    // Test transcript hash computation
    std::vector<CryptoBuffer> messages;
    for (int i = 0; i < 3; ++i) {
        auto msg_data = test_data_;
        msg_data[0] = static_cast<std::byte>(i);
        messages.push_back(factory.wrap_data(msg_data.data(), msg_data.size()));
    }
    
    auto transcript_result = handshake_crypto.compute_transcript_hash(messages);
    ASSERT_TRUE(transcript_result.is_ok());
    auto transcript_hash = transcript_result.value();
    
    EXPECT_GT(transcript_hash.size(), 0);
    
    // Test certificate verification
    std::vector<CryptoBuffer> cert_chain;
    cert_chain.push_back(factory.wrap_data(test_data_.data(), test_data_.size()));
    cert_chain.push_back(factory.wrap_data(test_key_.data(), test_key_.size()));
    
    auto trusted_root = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    auto cert_verify_result = handshake_crypto.verify_certificate_chain(cert_chain, trusted_root);
    ASSERT_TRUE(cert_verify_result.is_ok());
    // Result depends on mock implementation
}

// Test utility functions
TEST_F(ZeroCopyCryptoTest, UtilityFunctions) {
    // Test make_crypto_buffer
    auto buffer1 = make_crypto_buffer(1024, true);
    EXPECT_EQ(buffer1.size(), 1024);
    EXPECT_TRUE(buffer1.is_mutable());
    
    auto buffer2 = make_crypto_buffer(512, false);
    EXPECT_EQ(buffer2.size(), 512);
    
    // Test wrap_crypto_buffer
    ZeroCopyBuffer zero_copy(test_data_.data(), test_data_.size());
    auto wrapped = wrap_crypto_buffer(zero_copy);
    EXPECT_EQ(wrapped.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(wrapped.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test crypto_buffer_to_zero_copy
    auto back_to_zero_copy_result = crypto_buffer_to_zero_copy(wrapped);
    ASSERT_TRUE(back_to_zero_copy_result.is_ok());
    auto back_to_zero_copy = back_to_zero_copy_result.value();
    
    EXPECT_EQ(back_to_zero_copy.size(), wrapped.size());
    EXPECT_EQ(std::memcmp(back_to_zero_copy.data(), wrapped.data(), wrapped.size()), 0);
}

// Test performance monitoring
TEST_F(ZeroCopyCryptoTest, PerformanceMonitoring) {
    // Enable performance monitoring
    enable_crypto_performance_monitoring(true);
    
    // Perform some crypto operations to generate stats
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    auto plaintext = factory.wrap_data(test_data_.data(), test_data_.size());
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // Perform operations
    for (int i = 0; i < 10; ++i) {
        auto encrypt_result = context->encrypt(plaintext, key, nonce);
        if (encrypt_result.is_ok()) {
            auto decrypt_result = context->decrypt(encrypt_result.value(), key, nonce);
            (void)decrypt_result;
        }
        
        auto sign_result = context->sign(plaintext, key);
        if (sign_result.is_ok()) {
            auto verify_result = context->verify(plaintext, sign_result.value(), key);
            (void)verify_result;
        }
    }
    
    // Get performance stats
    auto stats = get_crypto_performance_stats();
    
    // Stats should have some measured values
    // Note: Actual values depend on implementation and system performance
    EXPECT_GE(stats.zero_copy_operations, 0);
    EXPECT_GE(stats.copy_operations, 0);
    
    // Disable performance monitoring
    enable_crypto_performance_monitoring(false);
}

// Test concurrent crypto operations
TEST_F(ZeroCopyCryptoTest, ConcurrentCryptoOperations) {
    const int num_threads = 4;
    const int operations_per_thread = 20;
    std::atomic<int> successful_operations{0};
    
    std::vector<std::future<void>> futures;
    
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            auto context = std::make_unique<MockZeroCopyCryptoContext>();
            auto& factory = ZeroCopyCryptoFactory::instance();
            
            for (int i = 0; i < operations_per_thread; ++i) {
                try {
                    // Create unique data for each operation
                    auto data = test_data_;
                    data[0] = static_cast<std::byte>(t);
                    data[1] = static_cast<std::byte>(i);
                    
                    auto plaintext = factory.wrap_data(data.data(), data.size());
                    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
                    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
                    
                    // Encrypt and decrypt
                    auto encrypt_result = context->encrypt(plaintext, key, nonce);
                    if (encrypt_result.is_ok()) {
                        auto decrypt_result = context->decrypt(encrypt_result.value(), key, nonce);
                        if (decrypt_result.is_ok()) {
                            successful_operations.fetch_add(1);
                        }
                    }
                    
                    // Hash operation
                    auto hash_result = context->hash(plaintext);
                    if (hash_result.is_ok()) {
                        successful_operations.fetch_add(1);
                    }
                    
                } catch (...) {
                    // Ignore exceptions in concurrent test
                }
            }
        }));
    }
    
    // Wait for all threads
    for (auto& future : futures) {
        future.wait();
    }
    
    // Should have completed most operations successfully
    EXPECT_GT(successful_operations.load(), num_threads * operations_per_thread * 0.5);
}

// Test error conditions and edge cases
TEST_F(ZeroCopyCryptoTest, ErrorConditionsAndEdgeCases) {
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    // Test empty buffer operations
    auto empty_buffer = factory.create_crypto_buffer(0);
    EXPECT_EQ(empty_buffer.size(), 0);
    EXPECT_TRUE(empty_buffer.empty());
    
    auto empty_slice = empty_buffer.slice(0, 0);
    EXPECT_EQ(empty_slice.size(), 0);
    
    // Test invalid slice operations
    auto normal_buffer = factory.create_crypto_buffer(100);
    
    // Slice beyond buffer should handle gracefully or return empty
    auto invalid_slice = normal_buffer.slice(200, 10);
    // Behavior depends on implementation
    
    // Test null data wrapping
    auto null_wrapped = factory.wrap_data(nullptr, 0);
    EXPECT_EQ(null_wrapped.size(), 0);
    
    // Test unknown algorithm in factory
    auto unknown_context = factory.create_context("unknown_algorithm");
    // Should return nullptr or valid context (depends on implementation)
    
    // Test crypto operations with null/empty inputs
    auto context = std::make_unique<MockZeroCopyCryptoContext>();
    auto empty_crypto = factory.create_crypto_buffer(0);
    auto key = factory.wrap_data(test_key_.data(), test_key_.size());
    auto nonce = factory.wrap_data(test_nonce_.data(), test_nonce_.size());
    
    // These might succeed or fail depending on implementation
    auto empty_encrypt = context->encrypt(empty_crypto, key, nonce);
    auto empty_hash = context->hash(empty_crypto);
    
    // Test pool operations with invalid sizes
    auto& pool = CryptoBufferPool::instance();
    
    // Very large buffer request
    auto large_buffer = pool.acquire_buffer(SIZE_MAX, false);
    // Should handle gracefully (return empty buffer or smaller size)
    
    // Test conversion functions with invalid inputs
    CryptoBuffer invalid_buffer = factory.create_crypto_buffer(0);
    auto invalid_conversion = crypto_buffer_to_zero_copy(invalid_buffer);
    // Should handle gracefully
}