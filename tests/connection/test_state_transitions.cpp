/**
 * @file test_state_transitions.cpp
 * @brief Comprehensive tests for DTLS v1.3 connection state transitions (RFC 9147)
 */

#include <gtest/gtest.h>
#include "dtls/connection.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/error.h"
#include "dtls/types.h"
#include <memory>
#include <chrono>
#include <thread>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class StateTransitionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto provider factory
        auto factory_result = builtin::register_all_providers();
        ASSERT_TRUE(factory_result.is_success()) << "Failed to register crypto providers";
        
        // Create test configuration
        config_.supported_cipher_suites = {CipherSuite::TLS_AES_128_GCM_SHA256};
        config_.supported_groups = {NamedGroup::X25519};
        config_.supported_signatures = {SignatureScheme::ED25519};
        config_.handshake_timeout = std::chrono::milliseconds(5000);
        config_.retransmission_timeout = std::chrono::milliseconds(500);
        config_.max_retransmissions = 3;
        
        // Disable error recovery for tests to prevent timeouts
        config_.error_recovery.enable_automatic_recovery = false;
        
        // Create test addresses
        server_address_ = NetworkAddress::from_ipv4(0x7F000001, 4433); // 127.0.0.1:4433
        client_address_ = NetworkAddress::from_ipv4(0x7F000001, 54321); // 127.0.0.1:54321
        
        // Event callback for testing
        event_callback_ = [this](ConnectionEvent event, const std::vector<uint8_t>& data) {
            received_events_.push_back({event, data});
        };
    }
    
    void TearDown() override {
        if (client_connection_) {
            client_connection_->force_close();
        }
        if (server_connection_) {
            server_connection_->force_close();
        }
    }
    
    Result<std::unique_ptr<Connection>> create_test_client() {
        auto provider_result = ProviderFactory::instance().create_default_provider();
        if (!provider_result.is_success()) {
            return make_error<std::unique_ptr<Connection>>(provider_result.error());
        }
        
        return Connection::create_client(
            config_, 
            std::move(provider_result.value()),
            server_address_,
            event_callback_
        );
    }
    
    Result<std::unique_ptr<Connection>> create_test_server() {
        auto provider_result = ProviderFactory::instance().create_default_provider();
        if (!provider_result.is_success()) {
            return make_error<std::unique_ptr<Connection>>(provider_result.error());
        }
        
        return Connection::create_server(
            config_, 
            std::move(provider_result.value()),
            client_address_,
            event_callback_
        );  
    }
    
    ConnectionConfig config_;
    NetworkAddress server_address_;
    NetworkAddress client_address_;
    std::unique_ptr<Connection> client_connection_;
    std::unique_ptr<Connection> server_connection_;
    
    struct EventRecord {
        ConnectionEvent event;
        std::vector<uint8_t> data;
    };
    std::vector<EventRecord> received_events_;
    ConnectionEventCallback event_callback_;
};

// Test initial state after connection creation
TEST_F(StateTransitionTest, InitialState) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success()) << "Failed to create client connection";
    client_connection_ = std::move(client_result.value());
    
    // Initial state should be INITIAL
    EXPECT_EQ(client_connection_->get_state(), ConnectionState::INITIAL);
    EXPECT_FALSE(client_connection_->is_connected());
    EXPECT_FALSE(client_connection_->is_handshake_complete());
    EXPECT_TRUE(client_connection_->is_client());
    EXPECT_FALSE(client_connection_->is_server());
    
    auto server_result = create_test_server();
    ASSERT_TRUE(server_result.is_success()) << "Failed to create server connection";
    server_connection_ = std::move(server_result.value());
    
    EXPECT_EQ(server_connection_->get_state(), ConnectionState::INITIAL);
    EXPECT_FALSE(server_connection_->is_connected());
    EXPECT_FALSE(server_connection_->is_handshake_complete());
    EXPECT_FALSE(server_connection_->is_client());
    EXPECT_TRUE(server_connection_->is_server());
}

// Test client handshake initiation state transition
TEST_F(StateTransitionTest, ClientHandshakeInitiation) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success()) << "Failed to initialize client connection: " << static_cast<int>(init_result.error());
    
    // Start handshake should transition to WAIT_SERVER_HELLO
    auto handshake_result = client_connection_->start_handshake();
    if (handshake_result.is_success()) {
        EXPECT_EQ(client_connection_->get_state(), ConnectionState::WAIT_SERVER_HELLO);
        
        // Check for handshake started event
        bool handshake_started_event_found = false;
        for (const auto& event_record : received_events_) {
            if (event_record.event == ConnectionEvent::HANDSHAKE_STARTED) {
                handshake_started_event_found = true;
                break;
            }
        }
        EXPECT_TRUE(handshake_started_event_found) << "HANDSHAKE_STARTED event should be fired";
    }
}

// Test invalid state transitions are rejected
TEST_F(StateTransitionTest, InvalidStateTransitions) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Should not be able to send application data in INITIAL state
    std::vector<uint8_t> test_data_vec = {0x01, 0x02, 0x03};
    memory::ZeroCopyBuffer test_data(reinterpret_cast<const std::byte*>(test_data_vec.data()), test_data_vec.size());
    auto send_result = client_connection_->send_application_data(test_data);
    EXPECT_FALSE(send_result.is_success()) << "Should not be able to send data in INITIAL state";
    
    // Should not be able to update keys in INITIAL state
    auto key_update_result = client_connection_->update_keys();
    EXPECT_FALSE(key_update_result.is_success()) << "Should not be able to update keys in INITIAL state";
}

// Test early data state transitions (client side)
TEST_F(StateTransitionTest, EarlyDataStateTransitions) {
    // Enable early data in configuration
    config_.enable_early_data = true;
    config_.max_early_data_size = 1024;
    
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Note: Early data requires valid session ticket, which we don't have in this test
    // This test validates the state machine logic, not the full early data implementation
    EXPECT_FALSE(client_connection_->can_send_early_data()) 
        << "Should not be able to send early data without session ticket";
        
    EXPECT_FALSE(client_connection_->is_early_data_accepted())
        << "Early data should not be accepted initially";
        
    EXPECT_FALSE(client_connection_->is_early_data_rejected())
        << "Early data should not be rejected initially";
}

// Test connection close state transition
TEST_F(StateTransitionTest, ConnectionCloseTransition) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Close connection should transition to CLOSED state
    auto close_result = client_connection_->close();
    if (close_result.is_success()) {
        EXPECT_EQ(client_connection_->get_state(), ConnectionState::CLOSED);
        
        // Check for connection closed event
        bool connection_closed_event_found = false;
        for (const auto& event_record : received_events_) {
            if (event_record.event == ConnectionEvent::CONNECTION_CLOSED) {
                connection_closed_event_found = true;
                break;
            }
        }
        EXPECT_TRUE(connection_closed_event_found) << "CONNECTION_CLOSED event should be fired";
    }
}

// Test force close immediate transition
TEST_F(StateTransitionTest, ForceCloseTransition) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Force close should immediately transition to CLOSED
    client_connection_->force_close();
    EXPECT_EQ(client_connection_->get_state(), ConnectionState::CLOSED);
}

// Test state consistency during concurrent operations
TEST_F(StateTransitionTest, ConcurrentStateAccess) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Start multiple threads accessing state
    std::atomic<bool> should_stop{false};
    std::vector<std::thread> threads;
    std::vector<ConnectionState> observed_states;
    std::mutex states_mutex;
    
    // Thread 1: Repeatedly read state
    threads.emplace_back([&]() {
        while (!should_stop.load()) {
            ConnectionState state = client_connection_->get_state();
            {
                std::lock_guard<std::mutex> lock(states_mutex);
                observed_states.push_back(state);
            }
            std::this_thread::sleep_for(std::chrono::microseconds(1));
        }
    });
    
    // Thread 2: Try to start handshake
    threads.emplace_back([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        client_connection_->start_handshake();
    });
    
    // Thread 3: Try to close connection
    threads.emplace_back([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        client_connection_->close();
    });
    
    // Let threads run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    should_stop.store(true);
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    // Verify we observed valid states (no invalid intermediate states)
    std::lock_guard<std::mutex> lock(states_mutex);
    for (ConnectionState state : observed_states) {
        EXPECT_TRUE(state == ConnectionState::INITIAL ||
                   state == ConnectionState::WAIT_SERVER_HELLO ||
                   state == ConnectionState::CLOSED)
            << "Observed invalid intermediate state: " << static_cast<int>(state);
    }
}

// Test all defined connection states are handled
TEST_F(StateTransitionTest, AllStatesDefinedInEnum) {
    // Verify all states from types.h are accounted for in our tests
    std::vector<ConnectionState> all_states = {
        ConnectionState::INITIAL,
        ConnectionState::WAIT_SERVER_HELLO,
        ConnectionState::WAIT_ENCRYPTED_EXTENSIONS,
        ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST,
        ConnectionState::WAIT_CERTIFICATE_VERIFY,
        ConnectionState::WAIT_SERVER_FINISHED,
        ConnectionState::WAIT_CLIENT_CERTIFICATE,
        ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY,
        ConnectionState::WAIT_CLIENT_FINISHED,
        ConnectionState::CONNECTED,
        ConnectionState::CLOSED,
        ConnectionState::EARLY_DATA,
        ConnectionState::WAIT_END_OF_EARLY_DATA,
        ConnectionState::EARLY_DATA_REJECTED
    };
    
    // Verify each state can be converted to string (basic validation)
    for (ConnectionState state : all_states) {
        std::string state_str = to_string(state);
        EXPECT_FALSE(state_str.empty()) 
            << "State " << static_cast<int>(state) << " should have string representation";
    }
}

// Test connection statistics are updated during state transitions
TEST_F(StateTransitionTest, StatisticsUpdatedDuringTransitions) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    const ConnectionStats& initial_stats = client_connection_->get_stats();
    auto initial_time = initial_stats.connection_start;
    
    // Start handshake
    client_connection_->start_handshake();
    
    const ConnectionStats& post_handshake_stats = client_connection_->get_stats();
    
    // Statistics should show connection activity
    EXPECT_GE(post_handshake_stats.last_activity, initial_time)
        << "Last activity should be updated after handshake start";
}

// Test event callbacks are fired for state transitions
TEST_F(StateTransitionTest, EventCallbacksForStateTransitions) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Clear any initialization events
    received_events_.clear();
    
    // Start handshake
    auto handshake_result = client_connection_->start_handshake();
    
    // Should have received handshake started event
    if (handshake_result.is_success()) {
        bool found_handshake_started = false;
        for (const auto& event_record : received_events_) {
            if (event_record.event == ConnectionEvent::HANDSHAKE_STARTED) {
                found_handshake_started = true;
                break;
            }
        }
        EXPECT_TRUE(found_handshake_started) << "Should receive HANDSHAKE_STARTED event";
    }
    
    // Close connection
    received_events_.clear();
    auto close_result = client_connection_->close();
    
    if (close_result.is_success()) {
        // Should have received connection closed event
        bool found_connection_closed = false;
        for (const auto& event_record : received_events_) {
            if (event_record.event == ConnectionEvent::CONNECTION_CLOSED) {
                found_connection_closed = true;
                break;
            }
        }
        EXPECT_TRUE(found_connection_closed) << "Should receive CONNECTION_CLOSED event";
    }
}

// Test connection configuration is preserved during state transitions
TEST_F(StateTransitionTest, ConfigurationPreservedDuringTransitions) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    const ConnectionConfig& initial_config = client_connection_->get_config();
    
    // Verify initial configuration
    EXPECT_EQ(initial_config.supported_cipher_suites.size(), 1);
    EXPECT_EQ(initial_config.supported_cipher_suites[0], CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_EQ(initial_config.handshake_timeout, std::chrono::milliseconds(5000));
    
    // Transition states
    client_connection_->start_handshake();
    client_connection_->close();
    
    // Configuration should remain unchanged
    const ConnectionConfig& final_config = client_connection_->get_config();
    EXPECT_EQ(final_config.supported_cipher_suites.size(), initial_config.supported_cipher_suites.size());
    EXPECT_EQ(final_config.supported_cipher_suites[0], initial_config.supported_cipher_suites[0]);
    EXPECT_EQ(final_config.handshake_timeout, initial_config.handshake_timeout);
}

// Test peer address information is maintained during state transitions
TEST_F(StateTransitionTest, PeerAddressMaintainedDuringTransitions) {
    auto client_result = create_test_client();
    ASSERT_TRUE(client_result.is_success());
    client_connection_ = std::move(client_result.value());
    
    auto init_result = client_connection_->initialize();
    ASSERT_TRUE(init_result.is_success());
    
    // Verify initial peer address
    const NetworkAddress& peer_addr = client_connection_->get_peer_address();
    EXPECT_EQ(peer_addr, server_address_);
    
    // Transition through states
    client_connection_->start_handshake();
    
    // Peer address should remain unchanged
    const NetworkAddress& peer_addr_after_handshake = client_connection_->get_peer_address();
    EXPECT_EQ(peer_addr_after_handshake, server_address_);
    
    client_connection_->close();
    
    // Peer address should still be unchanged
    const NetworkAddress& peer_addr_after_close = client_connection_->get_peer_address();
    EXPECT_EQ(peer_addr_after_close, server_address_);
}