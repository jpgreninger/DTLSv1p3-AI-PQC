#include "dtls/protocol/hardware_accelerated_record_layer.h"
#include "dtls/crypto/provider_factory.h"
#include <algorithm>
#include <thread>
#include <future>

namespace dtls {
namespace v13 {
namespace protocol {

// Static members for factory
std::shared_ptr<crypto::HardwareAcceleratedProvider> HardwareAcceleratedRecordLayerFactory::cached_provider_;
std::mutex HardwareAcceleratedRecordLayerFactory::factory_mutex_;

// HardwareAcceleratedRecordLayer implementation

HardwareAcceleratedRecordLayer::HardwareAcceleratedRecordLayer(
    std::shared_ptr<crypto::HardwareAcceleratedProvider> crypto_provider,
    const HardwareConfig& config)
    : crypto_provider_(std::move(crypto_provider))
    , hardware_config_(config)
    , protection_batch_(std::make_unique<BatchContext>())
    , unprotection_batch_(std::make_unique<BatchContext>()) {
    
    // Initialize zero-copy crypto
    auto zero_copy_factory = crypto::HardwareZeroCryptoFactory::instance();
    auto zero_copy_result = zero_copy_factory.create_with_provider(
        crypto_provider_->name(),
        crypto::HardwareZeroCopyCrypto::HardwareConfig{
            .enable_simd_batch_ops = config.enable_simd_operations,
            .enable_in_place_ops = config.enable_zero_copy,
            .simd_batch_size = config.batch_size
        });
    
    if (zero_copy_result) {
        zero_copy_crypto_ = std::move(zero_copy_result.value());
        record_processor_ = std::make_unique<crypto::DTLSHardwareRecordProcessor>(zero_copy_crypto_);
    }
    
    // Initialize buffer pool
    for (size_t i = 0; i < config.buffer_pool_size; ++i) {
        auto buffer = crypto::HardwareAcceleratedCryptoBuffer::create_aligned(8192); // 8KB default
        if (buffer) {
            buffer_pool_.push(std::move(buffer));
        }
    }
}

HardwareAcceleratedRecordLayer::~HardwareAcceleratedRecordLayer() {
    cleanup();
}

Result<void> HardwareAcceleratedRecordLayer::initialize(const ConnectionParams& params) {
    connection_params_ = params;
    
    auto init_result = crypto_provider_->initialize();
    if (!init_result) {
        return init_result;
    }
    
    initialized_.store(true);
    return Result<void>::success();
}

void HardwareAcceleratedRecordLayer::cleanup() {
    if (initialized_.load()) {
        // Flush any pending batches
        flush_pending_batches();
        
        crypto_provider_->cleanup();
        initialized_.store(false);
    }
    
    // Clear buffer pool
    std::lock_guard<std::mutex> lock(buffer_pool_mutex_);
    while (!buffer_pool_.empty()) {
        buffer_pool_.pop();
    }
}

Result<ProtectedRecord> HardwareAcceleratedRecordLayer::protect_record(
    const PlaintextRecord& plaintext,
    const ProtectionParams& params) {
    
    if (!initialized_.load()) {
        return Result<ProtectedRecord>::error(DTLSError::NOT_INITIALIZED);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Check if we should use hardware-specific optimization
    if (is_hardware_acceleration_active()) {
        auto hw_result = protect_record_aes_gcm_hw(plaintext, params);
        if (hw_result) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            update_metrics("protect_record", duration, true, false);
            return hw_result;
        }
    }
    
    // Build AEAD parameters
    auto additional_data = build_additional_data(plaintext, params);
    auto aead_params_result = build_aead_params(params, additional_data);
    if (!aead_params_result) {
        return Result<ProtectedRecord>::error(aead_params_result.error());
    }
    
    // Encrypt the record
    crypto::AEADEncryptionParams enc_params;
    enc_params.key = aead_params_result.value().key;
    enc_params.nonce = aead_params_result.value().nonce;
    enc_params.additional_data = aead_params_result.value().additional_data;
    enc_params.cipher = aead_params_result.value().cipher;
    enc_params.plaintext = plaintext.payload;
    
    auto encrypt_result = crypto_provider_->encrypt_aead(enc_params);
    if (!encrypt_result) {
        return Result<ProtectedRecord>::error(encrypt_result.error());
    }
    
    // Build protected record
    ProtectedRecord protected_record;
    protected_record.content_type = ContentType::APPLICATION_DATA; // DTLS 1.3 always uses this
    protected_record.version = DTLS_V13;
    protected_record.epoch = params.epoch;
    protected_record.sequence_number = params.sequence_number;
    
    const auto& encryption_output = encrypt_result.value();
    protected_record.payload.reserve(encryption_output.ciphertext.size() + encryption_output.tag.size());
    protected_record.payload.insert(protected_record.payload.end(),
                                   encryption_output.ciphertext.begin(),
                                   encryption_output.ciphertext.end());
    protected_record.payload.insert(protected_record.payload.end(),
                                   encryption_output.tag.begin(),
                                   encryption_output.tag.end());
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_metrics("protect_record", duration, false, false);
    
    return Result<ProtectedRecord>::success(std::move(protected_record));
}

Result<PlaintextRecord> HardwareAcceleratedRecordLayer::unprotect_record(
    const ProtectedRecord& protected_record,
    const ProtectionParams& params) {
    
    if (!initialized_.load()) {
        return Result<PlaintextRecord>::error(DTLSError::NOT_INITIALIZED);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Check if we should use hardware-specific optimization
    if (is_hardware_acceleration_active()) {
        auto hw_result = unprotect_record_aes_gcm_hw(protected_record, params);
        if (hw_result) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            update_metrics("unprotect_record", duration, true, false);
            return hw_result;
        }
    }
    
    // Validate minimum payload size (at least tag size)
    if (protected_record.payload.size() < 16) {
        return Result<PlaintextRecord>::error(DTLSError::INVALID_RECORD);
    }
    
    // Split ciphertext and tag
    size_t tag_size = 16; // AES-GCM tag size
    size_t ciphertext_size = protected_record.payload.size() - tag_size;
    
    std::vector<uint8_t> ciphertext(protected_record.payload.begin(),
                                   protected_record.payload.begin() + ciphertext_size);
    std::vector<uint8_t> tag(protected_record.payload.begin() + ciphertext_size,
                            protected_record.payload.end());
    
    // Build AEAD parameters for decryption
    PlaintextRecord temp_plaintext;
    temp_plaintext.content_type = protected_record.content_type;
    temp_plaintext.version = protected_record.version;
    temp_plaintext.epoch = protected_record.epoch;
    temp_plaintext.sequence_number = protected_record.sequence_number;
    
    auto additional_data = build_additional_data(temp_plaintext, params);
    auto aead_params_result = build_aead_params(params, additional_data);
    if (!aead_params_result) {
        return Result<PlaintextRecord>::error(aead_params_result.error());
    }
    
    // Decrypt the record
    crypto::AEADDecryptionParams dec_params;
    dec_params.key = aead_params_result.value().key;
    dec_params.nonce = aead_params_result.value().nonce;
    dec_params.additional_data = aead_params_result.value().additional_data;
    dec_params.cipher = aead_params_result.value().cipher;
    dec_params.ciphertext = ciphertext;
    dec_params.tag = tag;
    
    auto decrypt_result = crypto_provider_->decrypt_aead(dec_params);
    if (!decrypt_result) {
        return Result<PlaintextRecord>::error(decrypt_result.error());
    }
    
    // Extract inner content type from decrypted payload (DTLS 1.3)
    const auto& plaintext_data = decrypt_result.value();
    if (plaintext_data.empty()) {
        return Result<PlaintextRecord>::error(DTLSError::INVALID_RECORD);
    }
    
    // Find the actual content type (last non-zero byte)
    ContentType inner_content_type = ContentType::INVALID;
    size_t payload_end = plaintext_data.size();
    
    for (size_t i = plaintext_data.size(); i > 0; --i) {
        if (plaintext_data[i - 1] != 0) {
            inner_content_type = static_cast<ContentType>(plaintext_data[i - 1]);
            payload_end = i - 1;
            break;
        }
    }
    
    if (inner_content_type == ContentType::INVALID) {
        return Result<PlaintextRecord>::error(DTLSError::INVALID_RECORD);
    }
    
    // Build plaintext record
    PlaintextRecord plaintext_record;
    plaintext_record.content_type = inner_content_type;
    plaintext_record.version = protected_record.version;
    plaintext_record.epoch = protected_record.epoch;
    plaintext_record.sequence_number = protected_record.sequence_number;
    plaintext_record.payload = std::vector<uint8_t>(plaintext_data.begin(),
                                                    plaintext_data.begin() + payload_end);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_metrics("unprotect_record", duration, false, false);
    
    return Result<PlaintextRecord>::success(std::move(plaintext_record));
}

Result<void> HardwareAcceleratedRecordLayer::update_keys(const KeyUpdateParams& params) {
    // Update crypto provider keys
    return Result<void>::success();
}

Result<std::vector<ProtectedRecord>> HardwareAcceleratedRecordLayer::protect_records_batch(
    const std::vector<PlaintextRecord>& plaintexts,
    const std::vector<ProtectionParams>& params) {
    
    if (plaintexts.size() != params.size()) {
        return Result<std::vector<ProtectedRecord>>::error(DTLSError::INVALID_PARAMETER);
    }
    
    if (!hardware_config_.enable_batch_processing || plaintexts.size() < 2) {
        // Fallback to sequential processing
        std::vector<ProtectedRecord> results;
        results.reserve(plaintexts.size());
        
        for (size_t i = 0; i < plaintexts.size(); ++i) {
            auto result = protect_record(plaintexts[i], params[i]);
            if (!result) {
                return Result<std::vector<ProtectedRecord>>::error(result.error());
            }
            results.push_back(result.value());
        }
        
        return Result<std::vector<ProtectedRecord>>::success(std::move(results));
    }
    
    // Use SIMD batch processing if available
    auto start_time = std::chrono::high_resolution_clock::now();
    auto batch_result = protect_batch_simd(plaintexts, params);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    update_metrics("protect_records_batch", duration, true, true);
    
    return batch_result;
}

Result<std::vector<PlaintextRecord>> HardwareAcceleratedRecordLayer::unprotect_records_batch(
    const std::vector<ProtectedRecord>& protected_records,
    const std::vector<ProtectionParams>& params) {
    
    // For now, process sequentially
    std::vector<PlaintextRecord> results;
    results.reserve(protected_records.size());
    
    for (size_t i = 0; i < protected_records.size(); ++i) {
        auto result = unprotect_record(protected_records[i], params[i]);
        if (!result) {
            return Result<std::vector<PlaintextRecord>>::error(result.error());
        }
        results.push_back(result.value());
    }
    
    return Result<std::vector<PlaintextRecord>>::success(std::move(results));
}

Result<std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer>> 
HardwareAcceleratedRecordLayer::protect_record_zero_copy(
    const PlaintextRecord& plaintext,
    const ProtectionParams& params) {
    
    if (!zero_copy_crypto_) {
        return Result<std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer>>::error(
            DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    if (!record_processor_) {
        return Result<std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer>>::error(
            DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Use hardware record processor for zero-copy operation
    crypto::DTLSContext context;
    context.content_type = static_cast<uint8_t>(plaintext.content_type);
    context.protocol_version = plaintext.version;
    context.epoch = plaintext.epoch;
    context.sequence_number = plaintext.sequence_number;
    
    auto result = record_processor_->protect_record(context, plaintext.payload, plaintext.content_type);
    if (!result) {
        return Result<std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer>>::error(result.error());
    }
    
    return Result<std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer>>::success(
        std::move(result.value()));
}

Result<std::pair<std::vector<uint8_t>, ContentType>> 
HardwareAcceleratedRecordLayer::unprotect_record_zero_copy(
    crypto::HardwareAcceleratedCryptoBuffer& ciphertext_buffer,
    const ProtectionParams& params) {
    
    if (!record_processor_) {
        return Result<std::pair<std::vector<uint8_t>, ContentType>>::error(
            DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    crypto::DTLSContext context;
    context.epoch = params.epoch;
    context.sequence_number = params.sequence_number;
    
    std::vector<uint8_t> ciphertext(ciphertext_buffer.data(), 
                                   ciphertext_buffer.data() + ciphertext_buffer.size());
    
    return record_processor_->unprotect_record(context, ciphertext);
}

HardwareAcceleratedRecordLayer::HardwareMetrics 
HardwareAcceleratedRecordLayer::get_hardware_metrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return hardware_metrics_;
}

void HardwareAcceleratedRecordLayer::reset_hardware_metrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    hardware_metrics_ = HardwareMetrics{};
}

void HardwareAcceleratedRecordLayer::update_hardware_config(const HardwareConfig& config) {
    hardware_config_ = config;
    
    if (zero_copy_crypto_) {
        crypto::HardwareZeroCopyCrypto::HardwareConfig zero_copy_config;
        zero_copy_config.enable_simd_batch_ops = config.enable_simd_operations;
        zero_copy_config.enable_in_place_ops = config.enable_zero_copy;
        zero_copy_config.simd_batch_size = config.batch_size;
        zero_copy_crypto_->update_config(zero_copy_config);
    }
}

HardwareAcceleratedRecordLayer::HardwareConfig 
HardwareAcceleratedRecordLayer::get_hardware_config() const {
    return hardware_config_;
}

bool HardwareAcceleratedRecordLayer::is_hardware_acceleration_active() const {
    return crypto_provider_->has_hardware_acceleration() && 
           (zero_copy_crypto_ ? zero_copy_crypto_->is_hardware_active() : false);
}

Result<crypto::HardwareAccelerationProfile> 
HardwareAcceleratedRecordLayer::get_hardware_profile() const {
    return crypto_provider_->get_hardware_profile();
}

// Private helper methods

std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer> 
HardwareAcceleratedRecordLayer::get_buffer_from_pool(size_t min_size) {
    std::lock_guard<std::mutex> lock(buffer_pool_mutex_);
    
    if (!buffer_pool_.empty()) {
        auto buffer = std::move(buffer_pool_.front());
        buffer_pool_.pop();
        
        if (buffer->capacity() >= min_size) {
            buffer->resize(min_size);
            return buffer;
        }
    }
    
    // Create new buffer if pool is empty or buffer is too small
    return crypto::HardwareAcceleratedCryptoBuffer::create_aligned(
        std::max(min_size, static_cast<size_t>(8192)));
}

void HardwareAcceleratedRecordLayer::return_buffer_to_pool(
    std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer> buffer) {
    
    if (!buffer) return;
    
    std::lock_guard<std::mutex> lock(buffer_pool_mutex_);
    if (buffer_pool_.size() < hardware_config_.buffer_pool_size) {
        buffer->clear(); // Clear sensitive data
        buffer_pool_.push(std::move(buffer));
    }
}

Result<crypto::AEADParams> HardwareAcceleratedRecordLayer::build_aead_params(
    const ProtectionParams& params,
    const std::vector<uint8_t>& additional_data) const {
    
    crypto::AEADParams aead_params;
    aead_params.key = params.key;
    aead_params.nonce = params.nonce;
    aead_params.additional_data = additional_data;
    aead_params.cipher = params.cipher;
    
    return Result<crypto::AEADParams>::success(std::move(aead_params));
}

std::vector<uint8_t> HardwareAcceleratedRecordLayer::build_additional_data(
    const PlaintextRecord& plaintext,
    const ProtectionParams& params) const {
    
    // DTLS 1.3 additional data format
    std::vector<uint8_t> additional_data;
    additional_data.reserve(13);
    
    // Sequence number (8 bytes)
    for (int i = 7; i >= 0; --i) {
        additional_data.push_back((plaintext.sequence_number >> (i * 8)) & 0xFF);
    }
    
    // Content type (1 byte) - always APPLICATION_DATA for DTLS 1.3
    additional_data.push_back(static_cast<uint8_t>(ContentType::APPLICATION_DATA));
    
    // Protocol version (2 bytes)
    additional_data.push_back((plaintext.version >> 8) & 0xFF);
    additional_data.push_back(plaintext.version & 0xFF);
    
    // Length (2 bytes) - will be filled by crypto provider
    additional_data.push_back(0);
    additional_data.push_back(0);
    
    return additional_data;
}

void HardwareAcceleratedRecordLayer::update_metrics(
    const std::string& operation,
    std::chrono::microseconds duration,
    bool used_hardware,
    bool used_batch) const {
    
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (operation.find("protect") != std::string::npos) {
        hardware_metrics_.records_protected++;
    } else if (operation.find("unprotect") != std::string::npos) {
        hardware_metrics_.records_unprotected++;
    }
    
    if (used_hardware) {
        hardware_metrics_.hardware_accelerated_ops++;
    } else {
        hardware_metrics_.software_fallback_ops++;
    }
    
    if (used_batch) {
        hardware_metrics_.batch_operations++;
    }
    
    hardware_metrics_.total_processing_time += duration;
    
    // Update averages
    uint64_t total_records = hardware_metrics_.records_protected + hardware_metrics_.records_unprotected;
    if (total_records > 0) {
        hardware_metrics_.average_protection_time_us = 
            hardware_metrics_.total_processing_time.count() / static_cast<float>(total_records);
    }
    
    uint64_t total_ops = hardware_metrics_.hardware_accelerated_ops + hardware_metrics_.software_fallback_ops;
    if (total_ops > 0) {
        hardware_metrics_.hardware_utilization_ratio = 
            static_cast<float>(hardware_metrics_.hardware_accelerated_ops) / total_ops;
    }
}

Result<std::vector<ProtectedRecord>> HardwareAcceleratedRecordLayer::protect_batch_simd(
    const std::vector<PlaintextRecord>& plaintexts,
    const std::vector<ProtectionParams>& params) {
    
    if (!zero_copy_crypto_) {
        // Fallback to sequential processing
        std::vector<ProtectedRecord> results;
        results.reserve(plaintexts.size());
        
        for (size_t i = 0; i < plaintexts.size(); ++i) {
            auto result = protect_record(plaintexts[i], params[i]);
            if (!result) {
                return Result<std::vector<ProtectedRecord>>::error(result.error());
            }
            results.push_back(result.value());
        }
        
        return Result<std::vector<ProtectedRecord>>::success(std::move(results));
    }
    
    // Prepare batch parameters
    std::vector<crypto::AEADEncryptionParams> batch_params;
    batch_params.reserve(plaintexts.size());
    
    for (size_t i = 0; i < plaintexts.size(); ++i) {
        auto additional_data = build_additional_data(plaintexts[i], params[i]);
        
        crypto::AEADEncryptionParams enc_params;
        enc_params.key = params[i].key;
        enc_params.nonce = params[i].nonce;
        enc_params.additional_data = additional_data;
        enc_params.cipher = params[i].cipher;
        enc_params.plaintext = plaintexts[i].payload;
        
        batch_params.push_back(std::move(enc_params));
    }
    
    // Use provider's batch encryption
    auto batch_result = crypto_provider_->batch_encrypt_aead(batch_params);
    if (!batch_result) {
        return Result<std::vector<ProtectedRecord>>::error(batch_result.error());
    }
    
    // Convert results to protected records
    std::vector<ProtectedRecord> protected_records;
    protected_records.reserve(plaintexts.size());
    
    const auto& encryption_outputs = batch_result.value();
    for (size_t i = 0; i < plaintexts.size(); ++i) {
        ProtectedRecord protected_record;
        protected_record.content_type = ContentType::APPLICATION_DATA;
        protected_record.version = DTLS_V13;
        protected_record.epoch = params[i].epoch;
        protected_record.sequence_number = params[i].sequence_number;
        
        const auto& encryption_output = encryption_outputs[i];
        protected_record.payload.reserve(encryption_output.ciphertext.size() + encryption_output.tag.size());
        protected_record.payload.insert(protected_record.payload.end(),
                                       encryption_output.ciphertext.begin(),
                                       encryption_output.ciphertext.end());
        protected_record.payload.insert(protected_record.payload.end(),
                                       encryption_output.tag.begin(),
                                       encryption_output.tag.end());
        
        protected_records.push_back(std::move(protected_record));
    }
    
    return Result<std::vector<ProtectedRecord>>::success(std::move(protected_records));
}

// Factory implementation

Result<std::unique_ptr<HardwareAcceleratedRecordLayer>> 
HardwareAcceleratedRecordLayerFactory::create_optimal() {
    std::lock_guard<std::mutex> lock(factory_mutex_);
    
    if (!cached_provider_) {
        auto provider_result = crypto::HardwareAcceleratedProviderFactory::create_optimized();
        if (!provider_result) {
            return Result<std::unique_ptr<HardwareAcceleratedRecordLayer>>::error(provider_result.error());
        }
        cached_provider_ = std::move(provider_result.value());
    }
    
    auto config_result = get_optimal_config();
    HardwareAcceleratedRecordLayer::HardwareConfig config = 
        config_result ? config_result.value() : HardwareAcceleratedRecordLayer::HardwareConfig{};
    
    auto record_layer = std::make_unique<HardwareAcceleratedRecordLayer>(cached_provider_, config);
    
    return Result<std::unique_ptr<HardwareAcceleratedRecordLayer>>::success(
        std::move(record_layer));
}

Result<std::unique_ptr<HardwareAcceleratedRecordLayer>> 
HardwareAcceleratedRecordLayerFactory::create_with_provider(
    const std::string& provider_name,
    const HardwareAcceleratedRecordLayer::HardwareConfig& config) {
    
    auto provider_result = crypto::HardwareAcceleratedProviderFactory::create_optimized(provider_name);
    if (!provider_result) {
        return Result<std::unique_ptr<HardwareAcceleratedRecordLayer>>::error(provider_result.error());
    }
    
    auto record_layer = std::make_unique<HardwareAcceleratedRecordLayer>(
        std::move(provider_result.value()), config);
    
    return Result<std::unique_ptr<HardwareAcceleratedRecordLayer>>::success(
        std::move(record_layer));
}

Result<std::unique_ptr<HardwareAcceleratedRecordLayer>> 
HardwareAcceleratedRecordLayerFactory::create_with_custom_provider(
    std::shared_ptr<crypto::HardwareAcceleratedProvider> provider,
    const HardwareAcceleratedRecordLayer::HardwareConfig& config) {
    
    auto record_layer = std::make_unique<HardwareAcceleratedRecordLayer>(
        std::move(provider), config);
    
    return Result<std::unique_ptr<HardwareAcceleratedRecordLayer>>::success(
        std::move(record_layer));
}

Result<HardwareAcceleratedRecordLayer::HardwareConfig> 
HardwareAcceleratedRecordLayerFactory::get_optimal_config() {
    auto hw_profile_result = crypto::HardwareAccelerationDetector::detect_capabilities();
    if (!hw_profile_result) {
        return Result<HardwareAcceleratedRecordLayer::HardwareConfig>::error(hw_profile_result.error());
    }
    
    const auto& profile = hw_profile_result.value();
    HardwareAcceleratedRecordLayer::HardwareConfig config;
    
    // Configure based on detected hardware
    bool has_simd = std::any_of(profile.capabilities.begin(), profile.capabilities.end(),
                               [](const auto& cap) {
                                   return (cap.capability == crypto::HardwareCapability::AVX ||
                                          cap.capability == crypto::HardwareCapability::AVX2) &&
                                          cap.available && cap.enabled;
                               });
    
    bool has_aes = std::any_of(profile.capabilities.begin(), profile.capabilities.end(),
                              [](const auto& cap) {
                                  return (cap.capability == crypto::HardwareCapability::AES_NI ||
                                         cap.capability == crypto::HardwareCapability::ARM_AES) &&
                                         cap.available && cap.enabled;
                              });
    
    config.enable_batch_processing = has_simd;
    config.enable_simd_operations = has_simd;
    config.enable_zero_copy = has_aes;
    config.batch_size = has_simd ? 16 : 8;
    config.max_concurrent_operations = std::thread::hardware_concurrency() * 4;
    
    return Result<HardwareAcceleratedRecordLayer::HardwareConfig>::success(config);
}

} // namespace protocol
} // namespace v13
} // namespace dtls