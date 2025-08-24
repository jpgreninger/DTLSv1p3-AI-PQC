/**
 * @file test_pqc_signatures_comprehensive.cpp
 * @brief Comprehensive test suite for Post-Quantum Cryptographic signatures (FIPS 204 & FIPS 205)
 * 
 * This test suite validates both pure PQC signatures (ML-DSA and SLH-DSA) and hybrid
 * PQC+Classical signatures across all crypto providers.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/crypto/botan_provider.h>
#include <dtls/crypto/hardware_accelerated_provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <test_infrastructure/test_certificates.h>
#include <test_infrastructure/test_utilities.h>
#include <chrono>
#include <random>
#include <array>

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace dtls::test;

class PQCSignatureTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize OpenSSL provider (primary provider for PQC)
        openssl_provider_ = std::make_unique<OpenSSLProvider>();
        if (openssl_provider_->is_available()) {
            auto init_result = openssl_provider_->initialize();
            ASSERT_TRUE(init_result.is_success()) << "Failed to initialize OpenSSL provider";
        }
        
        // Initialize Botan provider (experimental PQC support)
        botan_provider_ = std::make_unique<BotanProvider>();
        if (botan_provider_->is_available()) {
            auto init_result = botan_provider_->initialize();
            if (!init_result.is_success()) {
                std::cout << "Note: Botan provider initialization failed - this is expected for PQC operations" << std::endl;
            }
        }
        
        // Initialize hardware accelerated provider
        if (openssl_provider_->is_available()) {
            hardware_provider_ = std::make_unique<HardwareAcceleratedProvider>(
                std::make_unique<OpenSSLProvider>(),
                HardwareAccelerationProfile{}
            );
            hardware_provider_->initialize();
        }
        
        // Create test data
        createTestData();
    }
    
    void TearDown() override {
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
        if (hardware_provider_) hardware_provider_->cleanup();
    }
    
    void createTestData() {
        // Create test messages of various sizes
        test_message_small_ = std::vector<uint8_t>(32, 0x42);
        test_message_medium_ = std::vector<uint8_t>(1024, 0x43);
        test_message_large_ = std::vector<uint8_t>(8192, 0x44);
        
        // Create random test data
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        test_message_random_.resize(2048);
        for (auto& byte : test_message_random_) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        
        // Context strings for ML-DSA
        test_context_empty_ = std::vector<uint8_t>{};
        test_context_short_ = std::vector<uint8_t>{'t', 'e', 's', 't'};
        test_context_max_.resize(255, 0x55);  // Maximum context length
    }
    
    // Test helper functions
    void testMLDSAKeyGeneration(CryptoProvider* provider, MLDSAParameterSet param_set) {
        if (!provider || !provider->is_available()) return;
        
        MLDSAKeyGenParams params;
        params.parameter_set = param_set;
        
        auto result = provider->ml_dsa_generate_keypair(params);
        
        if (result.is_success()) {
            auto [private_key, public_key] = result.value();
            
            EXPECT_FALSE(private_key.empty());
            EXPECT_FALSE(public_key.empty());
            
            // Verify key sizes are reasonable for the parameter set
            switch (param_set) {
                case MLDSAParameterSet::ML_DSA_44:
                    EXPECT_GT(private_key.size(), 2000);  // Approximately 2560 bytes
                    EXPECT_GT(public_key.size(), 1200);   // Approximately 1312 bytes
                    break;
                case MLDSAParameterSet::ML_DSA_65:
                    EXPECT_GT(private_key.size(), 3500);  // Approximately 4032 bytes
                    EXPECT_GT(public_key.size(), 1800);   // Approximately 1952 bytes
                    break;
                case MLDSAParameterSet::ML_DSA_87:
                    EXPECT_GT(private_key.size(), 4500);  // Approximately 4896 bytes
                    EXPECT_GT(public_key.size(), 2400);   // Approximately 2592 bytes
                    break;
            }
        } else {
            // For providers without PQC support, expect specific error
            EXPECT_EQ(result.error(), DTLSError::OPERATION_NOT_SUPPORTED);
        }
    }
    
    void testSLHDSAKeyGeneration(CryptoProvider* provider, SLHDSAParameterSet param_set) {
        if (!provider || !provider->is_available()) return;
        
        SLHDSAKeyGenParams params;
        params.parameter_set = param_set;
        
        auto result = provider->slh_dsa_generate_keypair(params);
        
        if (result.is_success()) {
            auto [private_key, public_key] = result.value();
            
            EXPECT_FALSE(private_key.empty());
            EXPECT_FALSE(public_key.empty());
            
            // SLH-DSA has consistent key sizes: 64-byte private key, 32-byte public key
            EXPECT_EQ(private_key.size(), 64);
            EXPECT_EQ(public_key.size(), 32);
        } else {
            EXPECT_EQ(result.error(), DTLSError::OPERATION_NOT_SUPPORTED);
        }
    }
    
    void testMLDSASignAndVerify(CryptoProvider* provider, MLDSAParameterSet param_set,
                                const std::vector<uint8_t>& message,
                                const std::vector<uint8_t>& context,
                                bool deterministic = false) {
        if (!provider || !provider->is_available()) return;
        
        // Generate key pair
        MLDSAKeyGenParams keygen_params;
        keygen_params.parameter_set = param_set;
        
        auto keygen_result = provider->ml_dsa_generate_keypair(keygen_params);
        if (!keygen_result.is_success()) {
            EXPECT_EQ(keygen_result.error(), DTLSError::OPERATION_NOT_SUPPORTED);
            return;
        }
        
        auto [private_key, public_key] = keygen_result.value();
        
        // Sign the message
        MLDSASignatureParams sign_params;
        sign_params.parameter_set = param_set;
        sign_params.message = message;
        sign_params.private_key = private_key;
        sign_params.context = context;
        sign_params.deterministic = deterministic;
        
        auto sign_result = provider->ml_dsa_sign(sign_params);
        ASSERT_TRUE(sign_result.is_success()) << "ML-DSA signing failed";
        
        auto signature = sign_result.value();
        EXPECT_FALSE(signature.empty());
        
        // Verify expected signature sizes
        switch (param_set) {
            case MLDSAParameterSet::ML_DSA_44:
                EXPECT_GT(signature.size(), 2200);   // ~2420 bytes
                EXPECT_LT(signature.size(), 2700);
                break;
            case MLDSAParameterSet::ML_DSA_65:
                EXPECT_GT(signature.size(), 3000);   // ~3309 bytes
                EXPECT_LT(signature.size(), 3600);
                break;
            case MLDSAParameterSet::ML_DSA_87:
                EXPECT_GT(signature.size(), 4500);   // ~4627 bytes
                EXPECT_LT(signature.size(), 5000);
                break;
        }
        
        // Verify the signature
        MLDSAVerificationParams verify_params;
        verify_params.parameter_set = param_set;
        verify_params.message = message;
        verify_params.signature = signature;
        verify_params.public_key = public_key;
        verify_params.context = context;
        
        auto verify_result = provider->ml_dsa_verify(verify_params);
        ASSERT_TRUE(verify_result.is_success()) << "ML-DSA verification failed";
        EXPECT_TRUE(verify_result.value()) << "ML-DSA signature verification returned false";
        
        // Test with corrupted signature
        auto corrupted_signature = signature;
        corrupted_signature[signature.size() / 2] ^= 0xFF;
        
        verify_params.signature = corrupted_signature;
        auto verify_corrupted = provider->ml_dsa_verify(verify_params);
        EXPECT_TRUE(verify_corrupted.is_success());
        EXPECT_FALSE(verify_corrupted.value()) << "Corrupted signature should not verify";
    }
    
    void testSLHDSASignAndVerify(CryptoProvider* provider, SLHDSAParameterSet param_set,
                                 const std::vector<uint8_t>& message,
                                 const std::vector<uint8_t>& context,
                                 bool use_prehash = false) {
        if (!provider || !provider->is_available()) return;
        
        // Generate key pair
        SLHDSAKeyGenParams keygen_params;
        keygen_params.parameter_set = param_set;
        
        auto keygen_result = provider->slh_dsa_generate_keypair(keygen_params);
        if (!keygen_result.is_success()) {
            EXPECT_EQ(keygen_result.error(), DTLSError::OPERATION_NOT_SUPPORTED);
            return;
        }
        
        auto [private_key, public_key] = keygen_result.value();
        
        // Sign the message
        SLHDSASignatureParams sign_params;
        sign_params.parameter_set = param_set;
        sign_params.message = message;
        sign_params.private_key = private_key;
        sign_params.context = context;
        sign_params.use_prehash = use_prehash;
        
        auto sign_result = provider->slh_dsa_sign(sign_params);
        ASSERT_TRUE(sign_result.is_success()) << "SLH-DSA signing failed";
        
        auto signature = sign_result.value();
        EXPECT_FALSE(signature.empty());
        
        // SLH-DSA signatures have variable sizes based on parameter set
        // Typical sizes: 128s/128f=7856, 192s/192f=16224, 256s/256f=29792
        EXPECT_GT(signature.size(), 7000);   // Minimum reasonable size
        EXPECT_LT(signature.size(), 35000);  // Maximum reasonable size
        
        // Verify the signature
        SLHDSAVerificationParams verify_params;
        verify_params.parameter_set = param_set;
        verify_params.message = message;
        verify_params.signature = signature;
        verify_params.public_key = public_key;
        verify_params.context = context;
        verify_params.use_prehash = use_prehash;
        
        auto verify_result = provider->slh_dsa_verify(verify_params);
        ASSERT_TRUE(verify_result.is_success()) << "SLH-DSA verification failed";
        EXPECT_TRUE(verify_result.value()) << "SLH-DSA signature verification returned false";
        
        // Test with corrupted signature
        auto corrupted_signature = signature;
        corrupted_signature[signature.size() / 2] ^= 0xFF;
        
        verify_params.signature = corrupted_signature;
        auto verify_corrupted = provider->slh_dsa_verify(verify_params);
        EXPECT_TRUE(verify_corrupted.is_success());
        EXPECT_FALSE(verify_corrupted.value()) << "Corrupted signature should not verify";
    }

protected:
    std::unique_ptr<OpenSSLProvider> openssl_provider_;
    std::unique_ptr<BotanProvider> botan_provider_;
    std::unique_ptr<HardwareAcceleratedProvider> hardware_provider_;
    
    // Test data
    std::vector<uint8_t> test_message_small_;
    std::vector<uint8_t> test_message_medium_;
    std::vector<uint8_t> test_message_large_;
    std::vector<uint8_t> test_message_random_;
    
    std::vector<uint8_t> test_context_empty_;
    std::vector<uint8_t> test_context_short_;
    std::vector<uint8_t> test_context_max_;
};

// ML-DSA (FIPS 204) Key Generation Tests
TEST_F(PQCSignatureTest, MLDSA44KeyGeneration) {
    testMLDSAKeyGeneration(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_44);
    testMLDSAKeyGeneration(botan_provider_.get(), MLDSAParameterSet::ML_DSA_44);
    testMLDSAKeyGeneration(hardware_provider_.get(), MLDSAParameterSet::ML_DSA_44);
}

TEST_F(PQCSignatureTest, MLDSA65KeyGeneration) {
    testMLDSAKeyGeneration(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_65);
    testMLDSAKeyGeneration(botan_provider_.get(), MLDSAParameterSet::ML_DSA_65);
    testMLDSAKeyGeneration(hardware_provider_.get(), MLDSAParameterSet::ML_DSA_65);
}

TEST_F(PQCSignatureTest, MLDSA87KeyGeneration) {
    testMLDSAKeyGeneration(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_87);
    testMLDSAKeyGeneration(botan_provider_.get(), MLDSAParameterSet::ML_DSA_87);
    testMLDSAKeyGeneration(hardware_provider_.get(), MLDSAParameterSet::ML_DSA_87);
}

// SLH-DSA (FIPS 205) Key Generation Tests
TEST_F(PQCSignatureTest, SLHDSA_SHA2_128S_KeyGeneration) {
    testSLHDSAKeyGeneration(openssl_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHA2_128S);
    testSLHDSAKeyGeneration(botan_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHA2_128S);
    testSLHDSAKeyGeneration(hardware_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHA2_128S);
}

TEST_F(PQCSignatureTest, SLHDSA_SHAKE_256F_KeyGeneration) {
    testSLHDSAKeyGeneration(openssl_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHAKE_256F);
    testSLHDSAKeyGeneration(botan_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHAKE_256F);
    testSLHDSAKeyGeneration(hardware_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHAKE_256F);
}

// ML-DSA Signature and Verification Tests
TEST_F(PQCSignatureTest, MLDSA44SignAndVerify) {
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_44, 
                           test_message_small_, test_context_empty_);
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_44, 
                           test_message_medium_, test_context_short_);
}

TEST_F(PQCSignatureTest, MLDSA65SignAndVerify) {
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_65, 
                           test_message_large_, test_context_max_);
}

TEST_F(PQCSignatureTest, MLDSA87SignAndVerify) {
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_87, 
                           test_message_random_, test_context_empty_);
}

TEST_F(PQCSignatureTest, MLDSADeterministicSigning) {
    // Test deterministic vs non-deterministic signing
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_44, 
                           test_message_small_, test_context_empty_, true);
}

// SLH-DSA Signature and Verification Tests  
TEST_F(PQCSignatureTest, SLHDSA_SHA2_128S_SignAndVerify) {
    testSLHDSASignAndVerify(openssl_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHA2_128S,
                            test_message_small_, test_context_empty_);
}

TEST_F(PQCSignatureTest, SLHDSA_SHAKE_256F_SignAndVerify) {
    testSLHDSASignAndVerify(openssl_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHAKE_256F,
                            test_message_medium_, test_context_short_);
}

TEST_F(PQCSignatureTest, SLHDSAPrehashedSigning) {
    testSLHDSASignAndVerify(openssl_provider_.get(), SLHDSAParameterSet::SLH_DSA_SHA2_128F,
                            test_message_large_, test_context_empty_, true);
}

// Pure PQC Unified Interface Tests
TEST_F(PQCSignatureTest, PurePQCUnifiedInterface) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) return;
    
    // Test ML-DSA via unified interface
    PurePQCSignatureParams sign_params;
    sign_params.scheme = SignatureScheme::ML_DSA_44;
    sign_params.message = test_message_small_;
    sign_params.context = test_context_empty_;
    sign_params.deterministic = false;
    
    // Generate keypair first via ML-DSA interface
    MLDSAKeyGenParams keygen_params;
    keygen_params.parameter_set = MLDSAParameterSet::ML_DSA_44;
    
    auto keygen_result = openssl_provider_->ml_dsa_generate_keypair(keygen_params);
    if (!keygen_result.is_success()) return;
    
    auto [private_key, public_key] = keygen_result.value();
    sign_params.private_key = private_key;
    
    auto sign_result = openssl_provider_->pure_pqc_sign(sign_params);
    if (!sign_result.is_success()) {
        EXPECT_EQ(sign_result.error(), DTLSError::OPERATION_NOT_SUPPORTED);
        return;
    }
    
    auto signature = sign_result.value();
    EXPECT_FALSE(signature.empty());
    
    // Verify via unified interface
    PurePQCVerificationParams verify_params;
    verify_params.scheme = SignatureScheme::ML_DSA_44;
    verify_params.message = test_message_small_;
    verify_params.signature = signature;
    verify_params.public_key = public_key;
    verify_params.context = test_context_empty_;
    
    auto verify_result = openssl_provider_->pure_pqc_verify(verify_params);
    ASSERT_TRUE(verify_result.is_success());
    EXPECT_TRUE(verify_result.value());
}

// Hybrid PQC Signature Tests
TEST_F(PQCSignatureTest, HybridPQCSignatures) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) return;
    
    HybridPQCSignatureParams params;
    params.hybrid_scheme = SignatureScheme::RSA3072_ML_DSA_44;
    params.message = test_message_medium_;
    
    auto result = openssl_provider_->hybrid_pqc_sign(params);
    if (!result.is_success()) {
        // Hybrid PQC might not be implemented yet
        EXPECT_EQ(result.error(), DTLSError::OPERATION_NOT_SUPPORTED);
        return;
    }
    
    auto hybrid_result = result.value();
    EXPECT_FALSE(hybrid_result.classical_signature.empty());
    EXPECT_FALSE(hybrid_result.pqc_signature.empty());
    EXPECT_FALSE(hybrid_result.combined_signature.empty());
}

// Performance and Stress Tests
TEST_F(PQCSignatureTest, PQCSignaturePerformance) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) return;
    
    const int iterations = 10;
    std::vector<double> ml_dsa_times;
    std::vector<double> slh_dsa_times;
    
    // ML-DSA Performance Test
    for (int i = 0; i < iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        
        MLDSAKeyGenParams keygen_params;
        keygen_params.parameter_set = MLDSAParameterSet::ML_DSA_44;
        
        auto keygen_result = openssl_provider_->ml_dsa_generate_keypair(keygen_params);
        if (!keygen_result.is_success()) break;
        
        auto [private_key, public_key] = keygen_result.value();
        
        MLDSASignatureParams sign_params;
        sign_params.parameter_set = MLDSAParameterSet::ML_DSA_44;
        sign_params.message = test_message_small_;
        sign_params.private_key = private_key;
        
        auto sign_result = openssl_provider_->ml_dsa_sign(sign_params);
        if (!sign_result.is_success()) break;
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        ml_dsa_times.push_back(duration.count());
    }
    
    if (!ml_dsa_times.empty()) {
        double avg_time = std::accumulate(ml_dsa_times.begin(), ml_dsa_times.end(), 0.0) / ml_dsa_times.size();
        std::cout << "ML-DSA-44 average keygen+sign time: " << avg_time << " µs" << std::endl;
        
        // ML-DSA should complete within reasonable time (< 10ms for keygen+sign)
        EXPECT_LT(avg_time, 10000.0);
    }
}

TEST_F(PQCSignatureTest, PQCSignatureSizes) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) return;
    
    // Test that signature sizes are within expected bounds
    struct SizeTest {
        MLDSAParameterSet param_set;
        size_t min_sig_size;
        size_t max_sig_size;
        const char* name;
    };
    
    std::vector<SizeTest> size_tests = {
        {MLDSAParameterSet::ML_DSA_44, 2200, 2700, "ML-DSA-44"},
        {MLDSAParameterSet::ML_DSA_65, 3000, 3600, "ML-DSA-65"},
        {MLDSAParameterSet::ML_DSA_87, 4500, 5000, "ML-DSA-87"}
    };
    
    for (const auto& test : size_tests) {
        MLDSAKeyGenParams keygen_params;
        keygen_params.parameter_set = test.param_set;
        
        auto keygen_result = openssl_provider_->ml_dsa_generate_keypair(keygen_params);
        if (!keygen_result.is_success()) continue;
        
        auto [private_key, public_key] = keygen_result.value();
        
        MLDSASignatureParams sign_params;
        sign_params.parameter_set = test.param_set;
        sign_params.message = test_message_medium_;
        sign_params.private_key = private_key;
        
        auto sign_result = openssl_provider_->ml_dsa_sign(sign_params);
        if (!sign_result.is_success()) continue;
        
        auto signature = sign_result.value();
        
        EXPECT_GE(signature.size(), test.min_sig_size) 
            << test.name << " signature too small: " << signature.size();
        EXPECT_LE(signature.size(), test.max_sig_size) 
            << test.name << " signature too large: " << signature.size();
    }
}

// Edge Case Tests
TEST_F(PQCSignatureTest, PQCSignatureEdgeCases) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) return;
    
    // Test empty message signing (should be allowed)
    std::vector<uint8_t> empty_message;
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_44,
                           empty_message, test_context_empty_);
    
    // Test maximum context length
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_44,
                           test_message_small_, test_context_max_);
    
    // Test very large messages
    std::vector<uint8_t> huge_message(1024 * 1024, 0x55);  // 1MB message
    testMLDSASignAndVerify(openssl_provider_.get(), MLDSAParameterSet::ML_DSA_44,
                           huge_message, test_context_empty_);
}

// Security Tests
TEST_F(PQCSignatureTest, PQCSignatureSecurityProperties) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) return;
    
    // Generate key pair
    MLDSAKeyGenParams keygen_params;
    keygen_params.parameter_set = MLDSAParameterSet::ML_DSA_44;
    
    auto keygen_result = openssl_provider_->ml_dsa_generate_keypair(keygen_params);
    if (!keygen_result.is_success()) return;
    
    auto [private_key, public_key] = keygen_result.value();
    
    // Test that different messages produce different signatures (probabilistic)
    MLDSASignatureParams sign_params1;
    sign_params1.parameter_set = MLDSAParameterSet::ML_DSA_44;
    sign_params1.message = test_message_small_;
    sign_params1.private_key = private_key;
    sign_params1.deterministic = false;  // Non-deterministic
    
    MLDSASignatureParams sign_params2 = sign_params1;
    sign_params2.message = test_message_medium_;
    
    auto sig1 = openssl_provider_->ml_dsa_sign(sign_params1);
    auto sig2 = openssl_provider_->ml_dsa_sign(sign_params2);
    
    if (sig1.is_success() && sig2.is_success()) {
        EXPECT_NE(sig1.value(), sig2.value()) << "Different messages should produce different signatures";
    }
    
    // Test that wrong public key fails verification
    auto another_keygen = openssl_provider_->ml_dsa_generate_keypair(keygen_params);
    if (another_keygen.is_success()) {
        auto [_, wrong_public_key] = another_keygen.value();
        
        if (sig1.is_success()) {
            MLDSAVerificationParams verify_params;
            verify_params.parameter_set = MLDSAParameterSet::ML_DSA_44;
            verify_params.message = test_message_small_;
            verify_params.signature = sig1.value();
            verify_params.public_key = wrong_public_key;  // Wrong key
            
            auto verify_result = openssl_provider_->ml_dsa_verify(verify_params);
            EXPECT_TRUE(verify_result.is_success());
            EXPECT_FALSE(verify_result.value()) << "Wrong public key should fail verification";
        }
    }
}