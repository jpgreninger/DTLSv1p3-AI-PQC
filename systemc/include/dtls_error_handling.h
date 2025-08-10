#ifndef DTLS_SYSTEMC_ERROR_HANDLING_H
#define DTLS_SYSTEMC_ERROR_HANDLING_H

#include <systemc>
#include <tlm>
#include <dtls/error_handler.h>
#include <dtls/error_context.h>
#include <dtls/alert_manager.h>
#include <dtls/error_reporter.h>
#include <memory>
#include <queue>
#include <mutex>

namespace dtls {
namespace v13 {
namespace systemc {

/**
 * SystemC TLM Extension for DTLS Error Handling
 * 
 * Provides error handling context and statistics for SystemC TLM transactions
 * while maintaining RFC 9147 compliance in the hardware/software co-design model
 */
class dtls_error_extension : public tlm::tlm_extension<dtls_error_extension> {
public:
    // Error transaction types for SystemC modeling
    enum class TransactionType {
        HANDSHAKE_ERROR,          // Handshake protocol errors
        RECORD_ERROR,             // Record layer errors  
        CRYPTO_ERROR,             // Cryptographic operation errors
        TRANSPORT_ERROR,          // Network/transport errors
        SECURITY_INCIDENT,        // Security-related errors
        PERFORMANCE_DEGRADATION   // Performance/timing errors
    };
    
    struct ErrorTransaction {
        TransactionType type;
        DTLSError error_code;
        sc_core::sc_time timestamp;
        sc_core::sc_time processing_delay;
        std::string component_name;
        std::string description;
        bool is_fatal;
        bool requires_alert;
        double threat_confidence;
        
        ErrorTransaction(TransactionType t, DTLSError err, const std::string& comp)
            : type(t), error_code(err), timestamp(sc_core::sc_time_stamp())
            , processing_delay(sc_core::SC_ZERO_TIME), component_name(comp)
            , is_fatal(false), requires_alert(false), threat_confidence(0.0) {}
    };
    
    dtls_error_extension() = default;
    virtual ~dtls_error_extension() = default;
    
    // TLM extension interface
    virtual tlm_extension_base* clone() const override {
        return new dtls_error_extension(*this);
    }
    
    virtual void copy_from(const tlm_extension_base& ext) override {
        const auto& other = static_cast<const dtls_error_extension&>(ext);
        error_transactions_ = other.error_transactions_;
        total_error_count_ = other.total_error_count_;
        security_error_count_ = other.security_error_count_;
        performance_impact_ = other.performance_impact_;
    }
    
    // Error transaction management
    void add_error_transaction(const ErrorTransaction& transaction) {
        error_transactions_.push_back(transaction);
        total_error_count_++;
        
        if (transaction.type == TransactionType::SECURITY_INCIDENT) {
            security_error_count_++;
        }
        
        // Accumulate performance impact
        performance_impact_ += transaction.processing_delay;
    }
    
    const std::vector<ErrorTransaction>& get_error_transactions() const {
        return error_transactions_;
    }
    
    uint32_t get_total_error_count() const { return total_error_count_; }
    uint32_t get_security_error_count() const { return security_error_count_; }
    sc_core::sc_time get_performance_impact() const { return performance_impact_; }
    
    void clear_transactions() {
        error_transactions_.clear();
        total_error_count_ = 0;
        security_error_count_ = 0;
        performance_impact_ = sc_core::SC_ZERO_TIME;
    }

private:
    std::vector<ErrorTransaction> error_transactions_;
    uint32_t total_error_count_{0};
    uint32_t security_error_count_{0};
    sc_core::sc_time performance_impact_{sc_core::SC_ZERO_TIME};
};

/**
 * SystemC Error Handler Module
 * 
 * Provides centralized error handling for DTLS SystemC components
 * with timing-accurate modeling and TLM integration
 */
class SC_MODULE(dtls_error_handler_sc) {
public:
    // TLM interfaces
    tlm::tlm_target_socket<> error_reporting_socket;
    tlm::tlm_initiator_socket<> alert_output_socket;
    
    // SystemC ports for error events
    sc_core::sc_port<sc_core::sc_fifo_out_if<dtls_error_extension::ErrorTransaction>> error_out;
    sc_core::sc_port<sc_core::sc_fifo_in_if<dtls_error_extension::ErrorTransaction>> error_in;
    
    // Configuration and statistics ports
    sc_core::sc_export<sc_core::sc_signal_inout_if<bool>> dos_attack_detected;
    sc_core::sc_export<sc_core::sc_signal_inout_if<uint32_t>> error_count;
    sc_core::sc_export<sc_core::sc_signal_inout_if<double>> threat_level;
    
    SC_CTOR(dtls_error_handler_sc)
        : error_reporting_socket("error_reporting_socket")
        , alert_output_socket("alert_output_socket")
        , error_out("error_out")
        , error_in("error_in")
        , dos_attack_detected("dos_attack_detected")
        , error_count("error_count")
        , threat_level("threat_level") {
        
        // Initialize error handler with SystemC-aware configuration
        ErrorHandler::Configuration config;
        config.transport_type = ErrorHandler::Transport::CUSTOM;
        config.security_level = ErrorHandler::SecurityLevel::STANDARD;
        config.generate_alerts_on_invalid_records = true;  // Safe in SystemC simulation
        config.log_invalid_records = true;
        
        error_handler_ = std::make_unique<ErrorHandler>(config);
        
        // Initialize alert manager with secure transport (simulation is controlled)
        AlertManager::AlertPolicy alert_policy;
        alert_policy.transport_security = AlertManager::TransportSecurity::SECURE;
        alert_policy.generate_alerts_for_invalid_records = true;
        alert_policy.generate_alerts_for_auth_failures = true;
        
        alert_manager_ = std::make_unique<AlertManager>(alert_policy);
        
        // Initialize error reporter with detailed logging for simulation
        ErrorReporter::ReportingConfig reporter_config;
        reporter_config.minimum_level = ErrorReporter::LogLevel::DEBUG;
        reporter_config.format = ErrorReporter::OutputFormat::STRUCTURED;
        reporter_config.log_network_addresses = true;  // Safe in simulation
        reporter_config.log_connection_ids = true;
        reporter_config.include_stack_traces = true;
        
        error_reporter_ = std::make_unique<ErrorReporter>(reporter_config);
        
        // Wire up components
        error_handler_->set_alert_manager(alert_manager_);
        error_handler_->set_error_reporter(error_reporter_);
        
        // Register TLM transport method
        error_reporting_socket.register_b_transport(this, &dtls_error_handler_sc::b_transport);
        
        // Register SystemC processes
        SC_THREAD(error_processing_thread);
        SC_THREAD(monitoring_thread);
        SC_METHOD(update_statistics);
        sensitive << error_processing_event_;
        
        // Initialize signals
        dos_detected_signal_.write(false);
        error_count_signal_.write(0);
        threat_level_signal_.write(0.0);
        
        // Bind exports to signals
        dos_attack_detected(dos_detected_signal_);
        error_count(error_count_signal_);
        threat_level(threat_level_signal_);
    }
    
    // TLM transport interface for error reporting
    virtual void b_transport(tlm::tlm_generic_payload& trans, sc_core::sc_time& delay);
    
    // SystemC-specific error handling methods
    void report_error_sc(DTLSError error, 
                        const std::string& component_name,
                        const std::string& description = "",
                        bool is_security_relevant = false);
    
    void report_security_incident_sc(DTLSError error,
                                    const std::string& component_name,
                                    const std::string& attack_type,
                                    double confidence);
    
    void report_performance_issue_sc(DTLSError error,
                                   const std::string& component_name,
                                   const std::string& operation_name,
                                   sc_core::sc_time operation_duration);
    
    // SystemC timing models for error handling operations
    sc_core::sc_time calculate_error_processing_delay(DTLSError error) const;
    sc_core::sc_time calculate_alert_generation_delay(AlertDescription alert) const;
    sc_core::sc_time calculate_logging_delay(size_t message_size) const;
    
    // Statistics and monitoring for SystemC
    struct SystemCErrorStats {
        uint64_t total_transactions{0};
        uint64_t error_transactions{0};
        uint64_t security_incidents{0};
        uint64_t alerts_generated{0};
        uint64_t dos_attacks_detected{0};
        sc_core::sc_time total_processing_time{sc_core::SC_ZERO_TIME};
        sc_core::sc_time average_error_delay{sc_core::SC_ZERO_TIME};
    };
    
    const SystemCErrorStats& get_systemc_stats() const { return systemc_stats_; }
    void reset_systemc_stats();
    
    // Component identification for SystemC hierarchy
    void set_component_hierarchy(const std::string& hierarchy) {
        component_hierarchy_ = hierarchy;
    }
    
    std::string get_component_hierarchy() const {
        return component_hierarchy_;
    }

private:
    // Core error handling components
    std::unique_ptr<ErrorHandler> error_handler_;
    std::unique_ptr<AlertManager> alert_manager_;
    std::unique_ptr<ErrorReporter> error_reporter_;
    
    // SystemC-specific state
    SystemCErrorStats systemc_stats_;
    std::string component_hierarchy_;
    
    // SystemC synchronization
    sc_core::sc_event error_processing_event_;
    sc_core::sc_event alert_generation_event_;
    std::queue<dtls_error_extension::ErrorTransaction> pending_errors_;
    std::mutex error_queue_mutex_;
    
    // SystemC signals for monitoring
    sc_core::sc_signal<bool> dos_detected_signal_;
    sc_core::sc_signal<uint32_t> error_count_signal_;
    sc_core::sc_signal<double> threat_level_signal_;
    
    // SystemC processes
    void error_processing_thread();
    void monitoring_thread();
    void update_statistics();
    
    // Helper methods
    void process_error_transaction(const dtls_error_extension::ErrorTransaction& transaction);
    void update_threat_assessment();
    void generate_systemc_alert(const dtls_error_extension::ErrorTransaction& transaction);
    
    // Timing model parameters (configurable)
    static constexpr sc_core::sc_time ERROR_PROCESSING_BASE_DELAY{10, sc_core::SC_NS};
    static constexpr sc_core::sc_time ALERT_GENERATION_BASE_DELAY{50, sc_core::SC_NS};
    static constexpr sc_core::sc_time LOGGING_BASE_DELAY{5, sc_core::SC_NS};
    static constexpr sc_core::sc_time CRYPTO_ERROR_PENALTY{100, sc_core::SC_NS};
    static constexpr sc_core::sc_time SECURITY_ERROR_PENALTY{200, sc_core::SC_NS};
};

/**
 * SystemC Error Monitor Module
 * 
 * Monitors error patterns across the DTLS SystemC model and provides
 * system-wide error correlation and attack detection
 */
class SC_MODULE(dtls_error_monitor_sc) {
public:
    // TLM interfaces for collecting error data from multiple sources
    tlm::tlm_target_socket<> handshake_errors;
    tlm::tlm_target_socket<> record_errors;  
    tlm::tlm_target_socket<> crypto_errors;
    tlm::tlm_target_socket<> transport_errors;
    
    // Output interfaces for system-level responses
    tlm::tlm_initiator_socket<> security_response;
    tlm::tlm_initiator_socket<> performance_control;
    
    // SystemC monitoring outputs
    sc_core::sc_out<bool> global_dos_detected;
    sc_core::sc_out<double> system_threat_level;
    sc_core::sc_out<uint32_t> active_connections_with_errors;
    sc_core::sc_out<sc_dt::sc_uint<32>> error_pattern_signature;
    
    SC_CTOR(dtls_error_monitor_sc)
        : handshake_errors("handshake_errors")
        , record_errors("record_errors")
        , crypto_errors("crypto_errors")
        , transport_errors("transport_errors")
        , security_response("security_response")
        , performance_control("performance_control")
        , global_dos_detected("global_dos_detected")
        , system_threat_level("system_threat_level")
        , active_connections_with_errors("active_connections_with_errors")
        , error_pattern_signature("error_pattern_signature") {
        
        // Initialize error context manager
        context_manager_ = std::make_unique<ErrorContextManager>();
        
        // Register TLM transport methods
        handshake_errors.register_b_transport(this, &dtls_error_monitor_sc::handshake_b_transport);
        record_errors.register_b_transport(this, &dtls_error_monitor_sc::record_b_transport);
        crypto_errors.register_b_transport(this, &dtls_error_monitor_sc::crypto_b_transport);
        transport_errors.register_b_transport(this, &dtls_error_monitor_sc::transport_b_transport);
        
        // SystemC processes
        SC_THREAD(correlation_analysis_thread);
        SC_THREAD(threat_assessment_thread);
        SC_METHOD(update_global_statistics);
        sensitive << analysis_trigger_;
        
        // Initialize output signals
        global_dos_detected.write(false);
        system_threat_level.write(0.0);
        active_connections_with_errors.write(0);
        error_pattern_signature.write(0);
    }
    
    // TLM transport methods for different error sources
    void handshake_b_transport(tlm::tlm_generic_payload& trans, sc_core::sc_time& delay);
    void record_b_transport(tlm::tlm_generic_payload& trans, sc_core::sc_time& delay);
    void crypto_b_transport(tlm::tlm_generic_payload& trans, sc_core::sc_time& delay);
    void transport_b_transport(tlm::tlm_generic_payload& trans, sc_core::sc_time& delay);
    
    // System-wide error analysis
    void analyze_error_correlations();
    double assess_global_threat_level();
    uint32_t calculate_error_pattern_signature();
    
    // Configuration for SystemC simulation
    void configure_monitoring(const std::string& config_file = "");
    void set_analysis_period(sc_core::sc_time period);
    
    // Statistics export for SystemC testbenches
    void export_statistics(const std::string& filename) const;
    void generate_error_report(const std::string& filename) const;

private:
    std::unique_ptr<ErrorContextManager> context_manager_;
    
    // SystemC monitoring state
    sc_core::sc_event analysis_trigger_;
    sc_core::sc_time analysis_period_{1, sc_core::SC_MS};
    
    struct GlobalErrorState {
        uint32_t total_handshake_errors{0};
        uint32_t total_record_errors{0};
        uint32_t total_crypto_errors{0};
        uint32_t total_transport_errors{0};
        double current_threat_level{0.0};
        bool dos_attack_active{false};
        std::vector<std::string> compromised_connections;
    };
    GlobalErrorState global_state_;
    
    // SystemC processes
    void correlation_analysis_thread();
    void threat_assessment_thread();
    void update_global_statistics();
    
    // Helper methods
    void process_error_from_source(const dtls_error_extension::ErrorTransaction& transaction,
                                  const std::string& source_component);
    void update_connection_state(const std::string& connection_id,
                               const dtls_error_extension::ErrorTransaction& transaction);
    void trigger_security_response(double threat_level);
    void trigger_performance_adjustment(sc_core::sc_time performance_impact);
};

/**
 * SystemC Error Injection Module for Testing
 * 
 * Provides controlled error injection capabilities for testing
 * error handling robustness in SystemC DTLS models
 */
class SC_MODULE(dtls_error_injector_sc) {
public:
    // Control interfaces
    sc_core::sc_in<bool> enable_injection;
    sc_core::sc_in<uint32_t> injection_rate;  // Errors per second
    sc_core::sc_in<uint32_t> error_type_mask; // Which error types to inject
    
    // Output interface for injected errors
    tlm::tlm_initiator_socket<> injected_errors;
    
    SC_CTOR(dtls_error_injector_sc)
        : enable_injection("enable_injection")
        , injection_rate("injection_rate")
        , error_type_mask("error_type_mask")
        , injected_errors("injected_errors") {
        
        SC_THREAD(error_injection_thread);
        sensitive << enable_injection.pos();
        
        SC_METHOD(update_injection_parameters);
        sensitive << injection_rate << error_type_mask;
    }
    
    // Configuration methods
    void configure_injection_profile(const std::string& profile_name);
    void set_injection_scenario(const std::vector<DTLSError>& error_sequence,
                               const std::vector<sc_core::sc_time>& timing_sequence);
    
    // Statistical injection patterns for testing
    void enable_random_injection(double error_probability);
    void enable_burst_injection(uint32_t burst_size, sc_core::sc_time burst_interval);
    void enable_targeted_injection(DTLSError target_error, uint32_t frequency);

private:
    // Injection configuration
    struct InjectionConfig {
        bool random_injection_enabled{false};
        double error_probability{0.01};  // 1% error rate
        bool burst_injection_enabled{false};
        uint32_t burst_size{10};
        sc_core::sc_time burst_interval{1, sc_core::SC_MS};
        std::vector<DTLSError> error_sequence;
        std::vector<sc_core::sc_time> timing_sequence;
    } injection_config_;
    
    // SystemC processes
    void error_injection_thread();
    void update_injection_parameters();
    
    // Helper methods
    DTLSError select_error_for_injection();
    sc_core::sc_time calculate_next_injection_time();
    void inject_error_transaction(DTLSError error);
    
    // Statistics
    uint32_t errors_injected_{0};
    sc_core::sc_time last_injection_time_{sc_core::SC_ZERO_TIME};
};

} // namespace systemc
} // namespace v13
} // namespace dtls

#endif // DTLS_SYSTEMC_ERROR_HANDLING_H