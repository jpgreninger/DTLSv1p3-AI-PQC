# DTLS v1.3 SystemC TLM API Documentation

Complete reference for the SystemC Transaction Level Modeling (TLM) implementation of DTLS v1.3. This provides hardware/software co-design capabilities for verification and performance analysis.

## Table of Contents

- [Overview](#overview)
- [SystemC Components](#systemc-components)
- [TLM Interfaces](#tlm-interfaces)
- [Protocol Stack Model](#protocol-stack-model)
- [Timing Models](#timing-models)
- [Communication Channels](#communication-channels)
- [Testbenches](#testbenches)
- [Performance Analysis](#performance-analysis)
- [Examples](#examples)

## Overview

The SystemC implementation provides:

- **Transaction Level Modeling**: High-level protocol modeling with timing accuracy
- **TLM-2.0 Compliance**: Standard SystemC TLM interfaces and protocols
- **Configurable Timing**: Adjustable timing models for different hardware targets
- **Protocol Verification**: Comprehensive test infrastructure
- **Performance Analysis**: Detailed timing and throughput analysis

### Key Features

- Full DTLS v1.3 protocol stack in SystemC
- TLM-2.0 generic payload extensions for DTLS
- Configurable timing models (approximate, loosely-timed, cycle-accurate)
- Hardware acceleration modeling
- Power consumption estimation
- SystemC verification components

## SystemC Components

### Base Includes

```cpp
#include <systemc>
#include <tlm>
#include <dtls_systemc/protocol_stack.h>
#include <dtls_systemc/tlm_extensions.h>
#include <dtls_systemc/timing_models.h>
#include <dtls_systemc/channels.h>

using namespace sc_core;
using namespace tlm;
using namespace dtls::systemc;
```

### Core Component Hierarchy

```cpp
namespace dtls::systemc {

// Base component for all DTLS modules
class dtls_module_base : public sc_module {
public:
    // Constructor with configurable timing
    dtls_module_base(sc_module_name name, 
                     const timing_config& timing = timing_config::default_config());
    
    // Common interfaces
    virtual void set_timing_model(std::shared_ptr<timing_model_base> model) = 0;
    virtual timing_stats get_timing_statistics() const = 0;
    virtual void reset() = 0;
    
protected:
    timing_config timing_cfg;
    std::shared_ptr<timing_model_base> timing_model;
    
    // Timing annotation helpers
    void annotate_delay(sc_time delay);
    void annotate_timing_point(const std::string& label);
};

}
```

## TLM Interfaces

### DTLS TLM Extensions

Custom TLM generic payload extensions for DTLS-specific data:

```cpp
namespace dtls::systemc {

// DTLS message extension for TLM generic payload
class dtls_extension : public tlm_extension<dtls_extension> {
public:
    dtls_extension();
    virtual ~dtls_extension();
    
    // TLM extension interface
    virtual tlm_extension_base* clone() const override;
    virtual void copy_from(const tlm_extension_base& ext) override;
    
    // DTLS-specific data
    struct dtls_message {
        ContentType content_type;
        HandshakeType handshake_type;
        Epoch epoch;
        SequenceNumber sequence_number;
        std::vector<uint8_t> payload;
        std::optional<ConnectionID> connection_id;
        
        // Security context
        bool encrypted;
        AEADCipher cipher;
        std::vector<uint8_t> auth_tag;
        
        // Timing information
        sc_time arrival_time;
        sc_time processing_deadline;
        
        // Quality of service
        enum class priority { LOW, NORMAL, HIGH, CRITICAL } qos_priority;
        
        dtls_message() : encrypted(false), qos_priority(priority::NORMAL) {}
    };
    
    // Accessors
    void set_message(const dtls_message& msg);
    const dtls_message& get_message() const;
    
    // Convenience methods
    bool is_handshake_message() const;
    bool is_application_data() const;
    bool requires_acknowledgment() const;
    
private:
    dtls_message message_;
};

// Connection state extension
class dtls_connection_extension : public tlm_extension<dtls_connection_extension> {
public:
    ConnectionState state;
    std::optional<ConnectionID> connection_id;
    std::optional<ConnectionID> peer_connection_id;
    CipherSuite negotiated_cipher_suite;
    
    // Performance metrics
    struct perf_metrics {
        sc_time handshake_latency;
        uint64_t bytes_transmitted;
        uint64_t packets_transmitted;
        uint32_t retransmission_count;
        double throughput_mbps;
    } metrics;
    
    // Constructor and TLM interface methods
    dtls_connection_extension();
    virtual ~dtls_connection_extension();
    virtual tlm_extension_base* clone() const override;
    virtual void copy_from(const tlm_extension_base& ext) override;
};

// Security context extension
class dtls_security_extension : public tlm_extension<dtls_security_extension> {
public:
    struct security_context {
        // Cryptographic state
        Epoch current_epoch;
        std::map<Epoch, KeyMaterial> read_keys;
        std::map<Epoch, KeyMaterial> write_keys;
        
        // Anti-replay window
        struct replay_window {
            uint64_t window_mask;
            SequenceNumber highest_sequence;
            size_t window_size;
        } anti_replay;
        
        // Security level
        SecurityLevel level;
        bool perfect_forward_secrecy;
        
        security_context() : current_epoch(0), level(SecurityLevel::HIGH), 
                           perfect_forward_secrecy(true) {}
    } context;
    
    dtls_security_extension();
    virtual ~dtls_security_extension();
    virtual tlm_extension_base* clone() const override;
    virtual void copy_from(const tlm_extension_base& ext) override;
};

}
```

### TLM Sockets and Interfaces

```cpp
namespace dtls::systemc {

// Forward declarations
class dtls_initiator_socket;
class dtls_target_socket;

// DTLS-specific TLM interface
class dtls_transport_if : public virtual tlm_transport_if<> {
public:
    // Additional DTLS-specific transport methods
    virtual void set_connection_id(const ConnectionID& cid) = 0;
    virtual std::optional<ConnectionID> get_connection_id() const = 0;
    
    virtual void enable_early_data(bool enable) = 0;
    virtual bool is_early_data_enabled() const = 0;
    
    virtual void update_security_context(const dtls_security_extension::security_context& ctx) = 0;
    virtual void trigger_key_update() = 0;
};

// DTLS initiator socket (client side)
class dtls_initiator_socket : public tlm_initiator_socket<> {
public:
    dtls_initiator_socket(const char* name = "dtls_initiator_socket");
    
    // DTLS-specific operations
    sync_enum_type dtls_send(dtls_extension::dtls_message& message, 
                            sc_time& delay);
    
    void dtls_send_nb(dtls_extension::dtls_message& message,
                     sc_event& completion_event);
    
    // Connection management
    void initiate_handshake();
    void send_application_data(const std::vector<uint8_t>& data);
    void close_connection(AlertDescription alert = AlertDescription::CLOSE_NOTIFY);
    
private:
    std::unique_ptr<dtls_transport_if> transport_impl;
};

// DTLS target socket (server side)
class dtls_target_socket : public tlm_target_socket<> {
public:
    dtls_target_socket(const char* name = "dtls_target_socket");
    
    // TLM-2.0 interface implementation
    virtual sync_enum_type nb_transport_fw(tlm_generic_payload& payload,
                                          tlm_phase& phase,
                                          sc_time& delay) override;
    
    virtual void b_transport(tlm_generic_payload& payload,
                           sc_time& delay) override;
    
    virtual bool get_direct_mem_ptr(tlm_generic_payload& payload,
                                  tlm_dmi& dmi_data) override;
    
    virtual unsigned int transport_dbg(tlm_generic_payload& payload) override;
    
    // DTLS-specific callbacks
    void register_handshake_callback(
        std::function<void(const dtls_extension::dtls_message&)> callback);
    
    void register_data_callback(
        std::function<void(const std::vector<uint8_t>&)> callback);
    
    void register_error_callback(
        std::function<void(const std::string&)> callback);
    
private:
    std::function<void(const dtls_extension::dtls_message&)> handshake_cb;
    std::function<void(const std::vector<uint8_t>&)> data_cb;
    std::function<void(const std::string&)> error_cb;
};

}
```

## Protocol Stack Model

### Main Protocol Stack Component

```cpp
namespace dtls::systemc {

class dtls_protocol_stack : public dtls_module_base {
public:
    // Constructor
    dtls_protocol_stack(sc_module_name name,
                       const protocol_config& config = protocol_config::default_config(),
                       const timing_config& timing = timing_config::default_config());
    
    // TLM sockets
    dtls_initiator_socket initiator_socket;
    dtls_target_socket target_socket;
    
    // Configuration ports
    sc_port<tlm_fifo_get_if<ConnectionConfig>> config_port;
    sc_port<tlm_fifo_put_if<ConnectionStats>> stats_port;
    
    // Interrupt/event ports
    sc_out<bool> handshake_complete_signal;
    sc_out<bool> error_signal;
    sc_out<bool> data_ready_signal;
    
    // Clock and reset
    sc_in<bool> clk;
    sc_in<bool> reset_n;
    
    // SystemC process methods
    void protocol_thread();
    void handshake_thread();
    void record_processing_thread();
    void security_monitoring_thread();
    
    // Configuration and control
    void configure(const protocol_config& config);
    protocol_config get_configuration() const;
    
    void set_role(bool is_server);
    bool is_server_role() const;
    
    void set_certificates(const std::vector<std::vector<uint8_t>>& cert_chain);
    void set_private_key(const std::vector<uint8_t>& private_key);
    
    // Statistics and monitoring
    protocol_stack_stats get_statistics() const;
    void reset_statistics();
    
    // Timing model interface
    virtual void set_timing_model(std::shared_ptr<timing_model_base> model) override;
    virtual timing_stats get_timing_statistics() const override;
    virtual void reset() override;
    
protected:
    SC_HAS_PROCESS(dtls_protocol_stack);
    
    // Internal state
    protocol_config config_;
    ConnectionState current_state_;
    bool is_server_;
    
    // Subcomponents
    std::unique_ptr<record_layer_model> record_layer_;
    std::unique_ptr<handshake_manager_model> handshake_mgr_;
    std::unique_ptr<crypto_engine_model> crypto_engine_;
    std::unique_ptr<security_monitor_model> security_monitor_;
    
    // Internal FIFOs and channels
    sc_fifo<dtls_extension::dtls_message> incoming_messages;
    sc_fifo<dtls_extension::dtls_message> outgoing_messages;
    sc_fifo<handshake_state_event> handshake_events;
    
    // Timing and performance
    mutable timing_stats timing_statistics_;
    
    // Helper methods
    void process_incoming_message(const dtls_extension::dtls_message& msg);
    void send_outgoing_message(const dtls_extension::dtls_message& msg);
    void update_connection_state(ConnectionState new_state);
    void handle_security_event(const security_event& event);
};

// Configuration structures
struct protocol_config {
    // Basic configuration
    std::vector<CipherSuite> supported_cipher_suites;
    std::vector<NamedGroup> supported_groups;
    std::vector<SignatureScheme> supported_signatures;
    
    // Timing parameters
    sc_time handshake_timeout;
    sc_time retransmission_timeout;
    uint32_t max_retransmissions;
    
    // Feature flags
    bool enable_connection_id;
    uint8_t connection_id_length;
    bool enable_early_data;
    uint32_t max_early_data_size;
    bool enable_session_resumption;
    
    // Security settings
    SecurityLevel security_level;
    bool enforce_perfect_forward_secrecy;
    
    // SystemC-specific settings
    bool enable_timing_annotation;
    bool enable_power_estimation;
    bool enable_debug_trace;
    
    static protocol_config default_config();
    static protocol_config server_config();
    static protocol_config client_config();
};

// Statistics structure
struct protocol_stack_stats {
    // Protocol statistics
    uint64_t handshakes_completed;
    uint64_t handshakes_failed;
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
    // Timing statistics
    sc_time total_handshake_time;
    sc_time average_handshake_time;
    sc_time total_processing_time;
    sc_time average_message_processing_time;
    
    // Security statistics
    uint32_t replay_attacks_blocked;
    uint32_t invalid_signatures_detected;
    uint32_t key_updates_performed;
    
    // Performance metrics
    double throughput_mbps;
    double packet_rate_pps;
    double cpu_utilization_percent;
    double power_consumption_mw;
    
    protocol_stack_stats();
    void reset();
    std::string to_string() const;
};

}
```

### Subcomponent Models

#### Record Layer Model

```cpp
class record_layer_model : public dtls_module_base {
public:
    record_layer_model(sc_module_name name, const timing_config& timing);
    
    // TLM interfaces
    tlm_target_socket<> plaintext_in;
    tlm_initiator_socket<> ciphertext_out;
    tlm_target_socket<> ciphertext_in;
    tlm_initiator_socket<> plaintext_out;
    
    // Control interface
    sc_export<record_layer_control_if> control_export;
    
    // Configuration
    void set_encryption_keys(Epoch epoch, 
                           const KeyMaterial& key, 
                           const KeyMaterial& iv,
                           AEADCipher cipher);
    
    void enable_sequence_number_encryption(bool enable);
    void set_connection_id(const ConnectionID& cid);
    
    // Statistics
    struct record_layer_stats {
        uint64_t records_encrypted;
        uint64_t records_decrypted;
        uint64_t encryption_failures;
        uint64_t decryption_failures;
        sc_time total_encryption_time;
        sc_time total_decryption_time;
    } statistics;
    
protected:
    void encrypt_thread();
    void decrypt_thread();
    
private:
    std::map<Epoch, crypto_context> encryption_contexts_;
    std::optional<ConnectionID> connection_id_;
    bool sequence_encryption_enabled_;
};

// Record layer control interface
class record_layer_control_if : public virtual sc_interface {
public:
    virtual void set_write_keys(Epoch epoch, const KeyMaterial& key, 
                               const KeyMaterial& iv, AEADCipher cipher) = 0;
    virtual void set_read_keys(Epoch epoch, const KeyMaterial& key, 
                              const KeyMaterial& iv, AEADCipher cipher) = 0;
    virtual void update_keys(const KeyMaterial& update_secret) = 0;
    virtual SequenceNumber get_next_sequence_number(Epoch epoch) = 0;
    virtual bool validate_sequence_number(Epoch epoch, SequenceNumber seq) = 0;
};
```

#### Crypto Engine Model

```cpp
class crypto_engine_model : public dtls_module_base {
public:
    crypto_engine_model(sc_module_name name, 
                       const crypto_config& config,
                       const timing_config& timing);
    
    // TLM interfaces for crypto operations
    tlm_target_socket<> hash_request_socket;
    tlm_initiator_socket<> hash_response_socket;
    tlm_target_socket<> encrypt_request_socket;
    tlm_initiator_socket<> encrypt_response_socket;
    tlm_target_socket<> sign_request_socket;
    tlm_initiator_socket<> sign_response_socket;
    
    // Hardware acceleration interface
    sc_port<tlm_fifo_get_if<crypto_request>> hw_accel_request_port;
    sc_port<tlm_fifo_put_if<crypto_response>> hw_accel_response_port;
    
    // Configuration
    struct crypto_config {
        // Provider selection
        std::string provider_name;
        bool enable_hardware_acceleration;
        bool enable_constant_time_operations;
        
        // Performance settings
        uint32_t max_concurrent_operations;
        sc_time operation_timeout;
        
        // Security settings
        bool enable_side_channel_protection;
        bool enable_fault_injection_protection;
        
        static crypto_config default_config();
        static crypto_config hardware_accelerated_config();
    };
    
    // Operation interfaces
    void hash_async(const std::vector<uint8_t>& data, 
                   HashAlgorithm algorithm,
                   std::function<void(const std::vector<uint8_t>&)> callback);
    
    void encrypt_async(const std::vector<uint8_t>& plaintext,
                      const KeyMaterial& key,
                      AEADCipher cipher,
                      std::function<void(const std::vector<uint8_t>&)> callback);
    
    void sign_async(const std::vector<uint8_t>& message,
                   const KeyMaterial& private_key,
                   SignatureScheme scheme,
                   std::function<void(const std::vector<uint8_t>&)> callback);
    
    // Statistics
    struct crypto_stats {
        uint64_t hash_operations;
        uint64_t encrypt_operations;
        uint64_t decrypt_operations;
        uint64_t sign_operations;
        uint64_t verify_operations;
        
        sc_time total_hash_time;
        sc_time total_encrypt_time;
        sc_time total_decrypt_time;
        sc_time total_sign_time;
        sc_time total_verify_time;
        
        uint32_t hardware_acceleration_hits;
        double power_consumption_mw;
    } statistics;
    
protected:
    void crypto_operation_thread();
    void hardware_acceleration_thread();
    
private:
    crypto_config config_;
    std::queue<crypto_request> operation_queue_;
    std::shared_ptr<crypto_provider_model> software_provider_;
    std::shared_ptr<hardware_crypto_model> hardware_provider_;
};
```

## Timing Models

### Configurable Timing Framework

```cpp
namespace dtls::systemc {

// Base timing model interface
class timing_model_base {
public:
    virtual ~timing_model_base() = default;
    
    // Core timing methods
    virtual sc_time get_handshake_latency(HandshakeType type) const = 0;
    virtual sc_time get_crypto_operation_latency(const std::string& operation,
                                                size_t data_size) const = 0;
    virtual sc_time get_record_processing_latency(size_t record_size) const = 0;
    virtual sc_time get_network_transmission_latency(size_t data_size) const = 0;
    
    // Advanced timing
    virtual sc_time get_power_on_latency() const = 0;
    virtual sc_time get_context_switch_latency() const = 0;
    virtual double get_power_consumption(const std::string& operation) const = 0;
    
    // Configuration
    virtual void set_clock_frequency(double freq_mhz) = 0;
    virtual void set_memory_latency(sc_time latency) = 0;
    virtual void enable_power_modeling(bool enable) = 0;
};

// Approximate timing model (fast simulation)
class approximate_timing_model : public timing_model_base {
public:
    approximate_timing_model(const approximate_timing_config& config);
    
    // Implementation of timing interface
    virtual sc_time get_handshake_latency(HandshakeType type) const override;
    virtual sc_time get_crypto_operation_latency(const std::string& operation,
                                                size_t data_size) const override;
    // ... other methods
    
    // Configuration structure
    struct approximate_timing_config {
        sc_time base_handshake_latency = sc_time(10, SC_MS);
        sc_time base_crypto_latency = sc_time(100, SC_US);
        sc_time base_record_latency = sc_time(10, SC_US);
        sc_time base_network_latency = sc_time(1, SC_MS);
        
        double crypto_scaling_factor = 1.0;  // per byte
        double network_scaling_factor = 0.001;  // per byte
        
        static approximate_timing_config default_config();
        static approximate_timing_config fast_simulation_config();
    };
    
private:
    approximate_timing_config config_;
};

// Cycle-accurate timing model (detailed simulation)
class cycle_accurate_timing_model : public timing_model_base {
public:
    cycle_accurate_timing_model(const cycle_accurate_config& config);
    
    // Detailed timing implementation
    virtual sc_time get_handshake_latency(HandshakeType type) const override;
    virtual sc_time get_crypto_operation_latency(const std::string& operation,
                                                size_t data_size) const override;
    
    // Hardware-specific timing
    sc_time get_cache_access_latency(cache_level level, cache_access_type type) const;
    sc_time get_instruction_execution_latency(instruction_type instr) const;
    sc_time get_memory_access_latency(memory_type mem_type, size_t size) const;
    
    // Configuration for specific hardware
    struct cycle_accurate_config {
        double cpu_frequency_mhz = 1000.0;
        
        // Cache configuration
        struct cache_config {
            sc_time l1_hit_latency = sc_time(1, SC_NS);
            sc_time l2_hit_latency = sc_time(10, SC_NS);
            sc_time l3_hit_latency = sc_time(30, SC_NS);
            sc_time main_memory_latency = sc_time(100, SC_NS);
        } cache;
        
        // Crypto unit configuration
        struct crypto_unit_config {
            sc_time aes_setup_latency = sc_time(50, SC_NS);
            sc_time aes_per_block_latency = sc_time(5, SC_NS);
            sc_time hash_per_block_latency = sc_time(3, SC_NS);
            sc_time rng_latency = sc_time(100, SC_NS);
        } crypto_unit;
        
        // Network interface configuration
        struct network_config {
            double bandwidth_mbps = 1000.0;  // 1 Gbps
            sc_time packet_processing_latency = sc_time(1, SC_US);
            sc_time interrupt_latency = sc_time(500, SC_NS);
        } network;
        
        static cycle_accurate_config arm_cortex_a75_config();
        static cycle_accurate_config intel_xeon_config();
        static cycle_accurate_config embedded_config();
    };
    
private:
    cycle_accurate_config config_;
    mutable std::map<std::string, sc_time> operation_cache_;
};

// Power modeling extension
class power_model {
public:
    power_model(const power_config& config);
    
    // Power consumption estimation
    double get_static_power_mw() const;
    double get_dynamic_power_mw(const std::string& operation, 
                               double activity_factor) const;
    double get_leakage_power_mw() const;
    
    // Energy consumption
    double get_operation_energy_uj(const std::string& operation, 
                                  sc_time duration) const;
    
    struct power_config {
        double voltage_v = 1.2;
        double temperature_c = 25.0;
        
        // Component power characteristics
        struct component_power {
            double static_power_mw = 100.0;
            double dynamic_power_per_mhz_mw = 0.1;
            double leakage_coefficient = 0.01;
        };
        
        component_power cpu_core;
        component_power crypto_unit;
        component_power memory_controller;
        component_power network_interface;
        
        static power_config mobile_config();
        static power_config server_config();
        static power_config iot_config();
    };
    
private:
    power_config config_;
};

}
```

## Communication Channels

### DTLS-Specific Channels

```cpp
namespace dtls::systemc {

// DTLS message channel with flow control
template<typename T = dtls_extension::dtls_message>
class dtls_message_channel : public sc_channel, 
                            public tlm_fifo_get_if<T>,
                            public tlm_fifo_put_if<T> {
public:
    explicit dtls_message_channel(size_t size = 16);
    
    // tlm_fifo_get_if implementation
    virtual T get(tlm_tag<T>* = nullptr) override;
    virtual bool nb_get(T& val) override;
    virtual bool nb_can_get(tlm_tag<T>* = nullptr) const override;
    virtual const sc_event& ok_to_get(tlm_tag<T>* = nullptr) const override;
    
    // tlm_fifo_put_if implementation
    virtual void put(const T& val) override;
    virtual bool nb_put(const T& val) override;
    virtual bool nb_can_put(tlm_tag<T>* = nullptr) const override;
    virtual const sc_event& ok_to_put(tlm_tag<T>* = nullptr) const override;
    
    // DTLS-specific methods
    void set_priority_filter(std::function<bool(const T&)> filter);
    void enable_flow_control(bool enable);
    void set_backpressure_threshold(size_t threshold);
    
    // Statistics
    struct channel_stats {
        uint64_t messages_sent;
        uint64_t messages_received;
        uint64_t messages_dropped;
        uint64_t backpressure_events;
        sc_time total_latency;
        size_t peak_usage;
    } statistics;
    
    const channel_stats& get_statistics() const { return statistics_; }
    void reset_statistics() { statistics_ = channel_stats{}; }
    
private:
    std::queue<T> queue_;
    size_t max_size_;
    mutable sc_event ok_to_get_event_;
    mutable sc_event ok_to_put_event_;
    std::function<bool(const T&)> priority_filter_;
    bool flow_control_enabled_;
    size_t backpressure_threshold_;
    channel_stats statistics_;
};

// Network simulation channel
class network_channel : public sc_channel {
public:
    network_channel(sc_module_name name, const network_config& config);
    
    // Network interface
    void send_packet(const std::vector<uint8_t>& packet, 
                    const NetworkAddress& dest,
                    packet_priority priority = packet_priority::NORMAL);
    
    void register_receiver(const NetworkAddress& addr,
                          std::function<void(const std::vector<uint8_t>&)> callback);
    
    // Network characteristics
    struct network_config {
        double bandwidth_mbps = 100.0;
        sc_time propagation_delay = sc_time(1, SC_MS);
        double packet_loss_rate = 0.001;  // 0.1%
        sc_time jitter_max = sc_time(100, SC_US);
        
        // Quality of Service
        bool enable_qos = true;
        size_t max_queue_size = 1000;
        
        // Error simulation
        bool enable_error_injection = false;
        double bit_error_rate = 1e-9;
        
        static network_config lan_config();
        static network_config wan_config();
        static network_config wireless_config();
    };
    
    void set_network_config(const network_config& config);
    network_config get_network_config() const { return config_; }
    
    // Statistics and monitoring
    struct network_stats {
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t packets_dropped;
        uint64_t packets_corrupted;
        uint64_t bytes_transmitted;
        sc_time total_latency;
        double current_utilization;
    } statistics;
    
    const network_stats& get_statistics() const { return statistics_; }
    
protected:
    void network_thread();
    void packet_corruption_thread();
    
private:
    network_config config_;
    std::map<NetworkAddress, std::function<void(const std::vector<uint8_t>&)>> receivers_;
    std::queue<network_packet> packet_queue_;
    network_stats statistics_;
    
    struct network_packet {
        std::vector<uint8_t> data;
        NetworkAddress source;
        NetworkAddress destination;
        packet_priority priority;
        sc_time timestamp;
    };
};

}
```

## Testbenches

### Protocol Verification Testbench

```cpp
namespace dtls::systemc::test {

class dtls_protocol_testbench : public sc_module {
public:
    dtls_protocol_testbench(sc_module_name name, const testbench_config& config);
    
    // Test components
    std::unique_ptr<dtls_protocol_stack> client_stack;
    std::unique_ptr<dtls_protocol_stack> server_stack;
    std::unique_ptr<network_channel> network;
    std::unique_ptr<test_traffic_generator> traffic_gen;
    std::unique_ptr<test_monitor> monitor;
    
    // Test control
    void run_test_suite();
    void run_single_test(const std::string& test_name);
    
    // Test cases
    void test_basic_handshake();
    void test_session_resumption();
    void test_early_data();
    void test_connection_id_migration();
    void test_key_update();
    void test_error_recovery();
    void test_dos_protection();
    void test_interoperability();
    void test_performance_regression();
    
    // Configuration
    struct testbench_config {
        // Test selection
        std::set<std::string> enabled_tests;
        bool run_all_tests = true;
        
        // Simulation parameters
        sc_time simulation_timeout = sc_time(10, SC_SEC);
        bool enable_logging = true;
        bool enable_waveform_dump = false;
        
        // Test data generation
        struct traffic_config {
            size_t min_message_size = 64;
            size_t max_message_size = 1500;
            double message_rate_hz = 100.0;
            size_t total_messages = 1000;
        } traffic;
        
        // Network simulation
        network_channel::network_config network;
        
        // Coverage collection
        bool enable_coverage = true;
        std::string coverage_db_path = "coverage.db";
        
        static testbench_config regression_config();
        static testbench_config performance_config();
        static testbench_config debug_config();
    };
    
    // Test results
    struct test_results {
        struct test_case_result {
            std::string name;
            bool passed;
            std::string failure_reason;
            sc_time execution_time;
            std::map<std::string, double> metrics;
        };
        
        std::vector<test_case_result> test_cases;
        size_t total_tests = 0;
        size_t passed_tests = 0;
        size_t failed_tests = 0;
        sc_time total_execution_time;
        
        void print_summary() const;
        void save_to_file(const std::string& filename) const;
    };
    
    test_results get_test_results() const { return results_; }
    
protected:
    SC_HAS_PROCESS(dtls_protocol_testbench);
    void test_runner_thread();
    void timeout_monitor_thread();
    
private:
    testbench_config config_;
    test_results results_;
    sc_event test_complete_event_;
};

// Traffic generator for testing
class test_traffic_generator : public sc_module {
public:
    test_traffic_generator(sc_module_name name, const traffic_config& config);
    
    // TLM interface to connect to protocol stack
    tlm_initiator_socket<> socket;
    
    // Control interface
    sc_in<bool> start_signal;
    sc_out<bool> complete_signal;
    sc_in<bool> clk;
    sc_in<bool> reset_n;
    
    // Configuration
    struct traffic_config {
        enum class pattern { CONSTANT_RATE, BURSTY, RANDOM, TRACE_FILE } pattern;
        
        // Rate configuration
        double base_rate_hz = 100.0;
        double burst_rate_hz = 1000.0;
        sc_time burst_duration = sc_time(100, SC_MS);
        sc_time inter_burst_interval = sc_time(1, SC_SEC);
        
        // Message characteristics
        size_t min_size = 64;
        size_t max_size = 1500;
        ContentType content_type = ContentType::APPLICATION_DATA;
        
        // Test duration
        sc_time test_duration = sc_time(10, SC_SEC);
        size_t max_messages = 10000;
        
        // Trace file (if pattern == TRACE_FILE)
        std::string trace_file_path;
        
        static traffic_config constant_rate_config(double rate_hz);
        static traffic_config bursty_config();
        static traffic_config random_config();
    };
    
    void configure(const traffic_config& config);
    void start_generation();
    void stop_generation();
    
    // Statistics
    struct generator_stats {
        uint64_t messages_generated;
        uint64_t bytes_generated;
        double actual_rate_hz;
        sc_time generation_time;
    } statistics;
    
protected:
    void generation_thread();
    
private:
    traffic_config config_;
    bool generating_;
    generator_stats statistics_;
};

}
```

## Performance Analysis

### Performance Monitoring and Analysis

```cpp
namespace dtls::systemc::analysis {

class performance_analyzer : public sc_module {
public:
    performance_analyzer(sc_module_name name);
    
    // Monitoring interfaces
    void register_protocol_stack(dtls_protocol_stack* stack, const std::string& name);
    void register_network_channel(network_channel* channel, const std::string& name);
    
    // Analysis methods
    void start_analysis();
    void stop_analysis();
    void generate_report();
    
    // Performance metrics
    struct performance_metrics {
        // Throughput metrics
        double peak_throughput_mbps;
        double average_throughput_mbps;
        double min_throughput_mbps;
        
        // Latency metrics
        sc_time peak_latency;
        sc_time average_latency;
        sc_time min_latency;
        sc_time p99_latency;  // 99th percentile
        
        // Handshake performance
        sc_time average_handshake_time;
        double handshake_success_rate;
        
        // Resource utilization
        double cpu_utilization;
        double memory_utilization;
        double network_utilization;
        
        // Power consumption
        double average_power_mw;
        double peak_power_mw;
        double total_energy_mj;
        
        // Error rates
        double packet_loss_rate;
        double retransmission_rate;
        double crypto_error_rate;
    };
    
    performance_metrics get_current_metrics() const;
    std::vector<performance_metrics> get_historical_metrics() const;
    
    // Bottleneck analysis
    struct bottleneck_analysis {
        enum class bottleneck_type {
            CPU_BOUND, MEMORY_BOUND, NETWORK_BOUND, 
            CRYPTO_BOUND, PROTOCOL_BOUND
        } primary_bottleneck;
        
        std::map<std::string, double> component_utilization;
        std::vector<std::string> optimization_suggestions;
    };
    
    bottleneck_analysis analyze_bottlenecks() const;
    
    // Comparison and regression analysis
    struct comparison_result {
        double throughput_improvement_percent;
        sc_time latency_improvement;
        double power_efficiency_improvement;
        bool performance_regression_detected;
        std::vector<std::string> regression_details;
    };
    
    comparison_result compare_with_baseline(const performance_metrics& baseline) const;
    
    // Report generation
    void save_metrics_csv(const std::string& filename) const;
    void save_performance_report(const std::string& filename) const;
    void generate_plots(const std::string& output_dir) const;
    
protected:
    void monitoring_thread();
    void analysis_thread();
    
private:
    struct monitored_stack {
        dtls_protocol_stack* stack;
        std::string name;
        std::vector<performance_metrics> history;
    };
    
    struct monitored_channel {
        network_channel* channel;
        std::string name;
        std::vector<network_channel::network_stats> history;
    };
    
    std::vector<monitored_stack> protocol_stacks_;
    std::vector<monitored_channel> network_channels_;
    
    bool analyzing_;
    sc_time analysis_interval_;
    performance_metrics current_metrics_;
    std::vector<performance_metrics> historical_metrics_;
};

}
```

## Examples

### Basic SystemC DTLS Client-Server

```cpp
#include <systemc>
#include <dtls_systemc/protocol_stack.h>
#include <dtls_systemc/channels.h>

using namespace sc_core;
using namespace dtls::systemc;

int sc_main(int argc, char* argv[]) {
    // Create clock and reset
    sc_clock clk("clk", 10, SC_NS);
    sc_signal<bool> reset_n("reset_n");
    
    // Network simulation
    network_channel::network_config net_config = network_channel::network_config::lan_config();
    network_channel network("network", net_config);
    
    // Client configuration
    protocol_config client_config = protocol_config::client_config();
    client_config.enable_early_data = true;
    
    // Server configuration
    protocol_config server_config = protocol_config::server_config();
    server_config.enable_connection_id = true;
    
    // Create protocol stacks
    dtls_protocol_stack client("client", client_config);
    dtls_protocol_stack server("server", server_config);
    
    // Connect clocks and resets
    client.clk(clk);
    client.reset_n(reset_n);
    server.clk(clk);
    server.reset_n(reset_n);
    
    // Connect to network
    // Note: In real implementation, this would involve more complex networking
    
    // Configure addresses
    NetworkAddress server_addr = NetworkAddress::from_string("192.168.1.100:4433").value();
    NetworkAddress client_addr = NetworkAddress::from_string("192.168.1.101:12345").value();
    
    // Register network receivers
    network.register_receiver(server_addr, [&server](const std::vector<uint8_t>& packet) {
        // Process incoming packet in server
        dtls_extension::dtls_message msg;
        // ... deserialize packet to message ...
        // server.process_message(msg);
    });
    
    network.register_receiver(client_addr, [&client](const std::vector<uint8_t>& packet) {
        // Process incoming packet in client
        dtls_extension::dtls_message msg;
        // ... deserialize packet to message ...
        // client.process_message(msg);
    });
    
    // Set up event handlers
    client.handshake_complete_signal.bind(sc_signal<bool>("client_handshake_complete"));
    server.handshake_complete_signal.bind(sc_signal<bool>("server_handshake_complete"));
    
    // Initialize simulation
    reset_n = false;
    sc_start(100, SC_NS);  // Reset period
    reset_n = true;
    
    // Run simulation
    sc_start(10, SC_SEC);
    
    // Print statistics
    auto client_stats = client.get_statistics();
    auto server_stats = server.get_statistics();
    auto network_stats = network.get_statistics();
    
    std::cout << "Client Statistics:\n" << client_stats.to_string() << std::endl;
    std::cout << "Server Statistics:\n" << server_stats.to_string() << std::endl;
    std::cout << "Network Statistics:\n";
    std::cout << "  Packets sent: " << network_stats.packets_sent << std::endl;
    std::cout << "  Packets received: " << network_stats.packets_received << std::endl;
    std::cout << "  Utilization: " << network_stats.current_utilization * 100 << "%" << std::endl;
    
    return 0;
}
```

### Performance Benchmarking Example

```cpp
#include <systemc>
#include <dtls_systemc/protocol_stack.h>
#include <dtls_systemc/test/testbench.h>
#include <dtls_systemc/analysis/performance_analyzer.h>

using namespace sc_core;
using namespace dtls::systemc;
using namespace dtls::systemc::test;
using namespace dtls::systemc::analysis;

class performance_benchmark : public sc_module {
public:
    performance_benchmark(sc_module_name name) : sc_module(name) {
        // Create testbench configuration for performance testing
        testbench_config config = testbench_config::performance_config();
        config.traffic.message_rate_hz = 10000.0;  // High rate for stress testing
        config.traffic.total_messages = 100000;
        config.simulation_timeout = sc_time(30, SC_SEC);
        
        // Create testbench
        testbench = std::make_unique<dtls_protocol_testbench>("testbench", config);
        
        // Create performance analyzer
        analyzer = std::make_unique<performance_analyzer>("analyzer");
        
        // Register components for monitoring
        analyzer->register_protocol_stack(testbench->client_stack.get(), "client");
        analyzer->register_protocol_stack(testbench->server_stack.get(), "server");
        analyzer->register_network_channel(testbench->network.get(), "network");
        
        // Start analysis thread
        SC_THREAD(benchmark_thread);
    }
    
    void benchmark_thread() {
        // Wait for reset deassertion
        wait(100, SC_NS);
        
        std::cout << "Starting performance benchmark..." << std::endl;
        
        // Start performance analysis
        analyzer->start_analysis();
        
        // Run different test scenarios
        run_throughput_test();
        run_latency_test();
        run_scalability_test();
        run_power_efficiency_test();
        
        // Stop analysis
        analyzer->stop_analysis();
        
        // Generate comprehensive report
        generate_benchmark_report();
        
        std::cout << "Performance benchmark completed." << std::endl;
    }
    
private:
    std::unique_ptr<dtls_protocol_testbench> testbench;
    std::unique_ptr<performance_analyzer> analyzer;
    
    void run_throughput_test() {
        std::cout << "Running throughput test..." << std::endl;
        
        // Configure high-rate traffic
        test_traffic_generator::traffic_config traffic_config;
        traffic_config.pattern = test_traffic_generator::traffic_config::pattern::CONSTANT_RATE;
        traffic_config.base_rate_hz = 50000.0;  // 50k messages/sec
        traffic_config.min_size = 1400;  // Large messages for throughput
        traffic_config.max_size = 1400;
        traffic_config.test_duration = sc_time(5, SC_SEC);
        
        testbench->traffic_gen->configure(traffic_config);
        testbench->traffic_gen->start_generation();
        
        // Wait for test completion
        wait(traffic_config.test_duration + sc_time(1, SC_SEC));
        
        testbench->traffic_gen->stop_generation();
        
        // Collect metrics
        auto metrics = analyzer->get_current_metrics();
        std::cout << "Peak throughput: " << metrics.peak_throughput_mbps << " Mbps" << std::endl;
        std::cout << "Average throughput: " << metrics.average_throughput_mbps << " Mbps" << std::endl;
    }
    
    void run_latency_test() {
        std::cout << "Running latency test..." << std::endl;
        
        // Configure low-rate, small messages for latency measurement
        test_traffic_generator::traffic_config traffic_config;
        traffic_config.pattern = test_traffic_generator::traffic_config::pattern::CONSTANT_RATE;
        traffic_config.base_rate_hz = 1000.0;  // 1k messages/sec
        traffic_config.min_size = 64;   // Small messages for latency
        traffic_config.max_size = 64;
        traffic_config.test_duration = sc_time(5, SC_SEC);
        
        testbench->traffic_gen->configure(traffic_config);
        testbench->traffic_gen->start_generation();
        
        wait(traffic_config.test_duration + sc_time(1, SC_SEC));
        
        testbench->traffic_gen->stop_generation();
        
        // Collect metrics
        auto metrics = analyzer->get_current_metrics();
        std::cout << "Average latency: " << metrics.average_latency << std::endl;
        std::cout << "P99 latency: " << metrics.p99_latency << std::endl;
    }
    
    void run_scalability_test() {
        std::cout << "Running scalability test..." << std::endl;
        
        // Test with increasing connection counts
        // This would require multiple client stacks in a real implementation
        std::cout << "Scalability test placeholder - would test multiple connections" << std::endl;
    }
    
    void run_power_efficiency_test() {
        std::cout << "Running power efficiency test..." << std::endl;
        
        // Test different power optimization settings
        auto metrics = analyzer->get_current_metrics();
        std::cout << "Average power consumption: " << metrics.average_power_mw << " mW" << std::endl;
        std::cout << "Energy per message: " << 
                     (metrics.total_energy_mj * 1000.0) / 
                     testbench->traffic_gen->statistics.messages_generated << " µJ" << std::endl;
    }
    
    void generate_benchmark_report() {
        // Generate comprehensive performance report
        analyzer->save_performance_report("performance_benchmark_report.html");
        analyzer->save_metrics_csv("performance_metrics.csv");
        analyzer->generate_plots("benchmark_plots/");
        
        // Bottleneck analysis
        auto bottleneck = analyzer->analyze_bottlenecks();
        std::cout << "Primary bottleneck: ";
        switch (bottleneck.primary_bottleneck) {
            case performance_analyzer::bottleneck_analysis::bottleneck_type::CPU_BOUND:
                std::cout << "CPU"; break;
            case performance_analyzer::bottleneck_analysis::bottleneck_type::MEMORY_BOUND:
                std::cout << "Memory"; break;
            case performance_analyzer::bottleneck_analysis::bottleneck_type::NETWORK_BOUND:
                std::cout << "Network"; break;
            case performance_analyzer::bottleneck_analysis::bottleneck_type::CRYPTO_BOUND:
                std::cout << "Cryptography"; break;
            case performance_analyzer::bottleneck_analysis::bottleneck_type::PROTOCOL_BOUND:
                std::cout << "Protocol"; break;
        }
        std::cout << std::endl;
        
        std::cout << "Optimization suggestions:" << std::endl;
        for (const auto& suggestion : bottleneck.optimization_suggestions) {
            std::cout << "  - " << suggestion << std::endl;
        }
    }
};

int sc_main(int argc, char* argv[]) {
    performance_benchmark bench("benchmark");
    
    sc_start();
    
    return 0;
}
```

---

## Building and Running SystemC Models

### CMake Integration

```cmake
# Find SystemC
find_package(SystemCLanguage CONFIG REQUIRED)

# DTLS SystemC library
add_library(dtls_systemc
    systemc/src/protocol_stack.cpp
    systemc/src/tlm_extensions.cpp
    systemc/src/timing_models.cpp
    systemc/src/channels.cpp
    # ... other SystemC sources
)

target_link_libraries(dtls_systemc 
    SystemC::systemc
    dtlsv13  # Main C++ library
)

target_include_directories(dtls_systemc PUBLIC
    systemc/include
)

# Test executables
add_executable(systemc_test
    systemc/tests/basic_test.cpp
)

target_link_libraries(systemc_test dtls_systemc)
```

### Compilation and Execution

```bash
# Build SystemC model
cd systemc && mkdir -p build && cd build
cmake .. -DSYSTEMC_ROOT=/path/to/systemc
make -j$(nproc)

# Run basic test
./systemc_test

# Run performance benchmark
./performance_benchmark

# Generate waveforms (if VCD enabled)
gtkwave simulation.vcd
```

This SystemC API provides comprehensive transaction-level modeling capabilities for DTLS v1.3, enabling detailed performance analysis, verification, and hardware/software co-design workflows.