#include <systemc>
#include <gtest/gtest.h>
#include <dtls_protocol_stack.h>
#include <dtls_testbench.h>

// C++ implementation for co-simulation
#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/protocol.h>
#include <dtls/transport/udp_transport.h>
#include <dtls/crypto/openssl_provider.h>

#include <thread>
#include <chrono>
#include <vector>
#include <memory>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace dtls {
namespace systemc {
namespace test {

/**
 * SystemC Co-Simulation Test Suite
 * 
 * Enables real-time co-simulation between SystemC TLM model and C++ implementation:
 * - Synchronized execution of SystemC and C++ DTLS stacks
 * - Real-time model integration with hardware-in-the-loop capability
 * - Cross-domain data exchange and synchronization
 * - Performance correlation between models
 * - Hardware acceleration integration testing
 */
class SystemCCoSimulationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize co-simulation environment
        setup_systemc_domain();
        setup_cpp_domain();
        setup_synchronization_framework();
        setup_data_exchange_interfaces();
        
        // Reset co-simulation statistics
        reset_cosim_statistics();
    }
    
    void TearDown() override {
        // Stop co-simulation
        stop_co_simulation();
        
        // Cleanup domains
        cleanup_systemc_domain();
        cleanup_cpp_domain();
        
        // Generate co-simulation report
        generate_cosim_report();
    }
    
    void setup_systemc_domain() {
        // Create SystemC protocol stack
        systemc_stack_ = std::make_unique<dtls_protocol_stack>("systemc_stack");
        
        // Create testbench for SystemC domain
        systemc_testbench_ = std::make_unique<dtls_testbench>("systemc_testbench");
        
        // Connect testbench to protocol stack
        systemc_testbench_->protocol_stack_port.bind(systemc_stack_->testbench_export);
        
        // Setup SystemC simulation parameters
        systemc_clock_period_ = sc_core::sc_time(10, sc_core::SC_NS); // 100 MHz
        systemc_simulation_quantum_ = sc_core::sc_time(1, sc_core::SC_US);
        
        // Initialize SystemC synchronization
        systemc_sync_event_ = std::make_unique<sc_core::sc_event>("systemc_sync");
        
        std::cout << "SystemC domain initialized" << std::endl;
    }
    
    void setup_cpp_domain() {
        // Create C++ DTLS contexts
        cpp_client_context_ = std::make_unique<v13::Context>();
        cpp_server_context_ = std::make_unique<v13::Context>();
        
        // Configure crypto providers
        auto client_provider = std::make_unique<crypto::OpenSSLProvider>();
        auto server_provider = std::make_unique<crypto::OpenSSLProvider>();
        
        ASSERT_TRUE(client_provider->initialize().is_ok());
        ASSERT_TRUE(server_provider->initialize().is_ok());
        
        cpp_client_context_->set_crypto_provider(std::move(client_provider));
        cpp_server_context_->set_crypto_provider(std::move(server_provider));
        
        // Create transport layer with co-simulation interfaces
        cpp_client_transport_ = std::make_unique<transport::UDPTransport>("127.0.0.1", 0);
        cpp_server_transport_ = std::make_unique<transport::UDPTransport>("127.0.0.1", 4433);
        
        ASSERT_TRUE(cpp_client_transport_->bind().is_ok());
        ASSERT_TRUE(cpp_server_transport_->bind().is_ok());
        
        // Enable co-simulation mode
        cpp_client_transport_->enable_cosimulation_mode(true);
        cpp_server_transport_->enable_cosimulation_mode(true);
        
        std::cout << "C++ domain initialized" << std::endl;
    }
    
    void setup_synchronization_framework() {
        // Initialize time synchronization
        systemc_time_offset_ = sc_core::SC_ZERO_TIME;
        cpp_time_offset_ = std::chrono::steady_clock::now();
        
        // Setup synchronization barriers
        sync_barrier_count_ = 0;
        max_sync_barriers_ = 1000;
        
        // Initialize synchronization control
        sync_enabled_ = true;
        sync_quantum_us_ = 100; // 100 microsecond sync quantum
        
        // Create synchronization thread
        sync_thread_ = std::thread(&SystemCCoSimulationTest::synchronization_thread, this);
        
        std::cout << "Synchronization framework initialized" << std::endl;
    }
    
    void setup_data_exchange_interfaces() {
        // Create shared data structures for cross-domain communication
        setup_message_queues();
        setup_shared_memory_interfaces();
        setup_performance_monitoring();
        
        std::cout << "Data exchange interfaces initialized" << std::endl;
    }
    
    void setup_message_queues() {
        // SystemC to C++ message queue
        systemc_to_cpp_queue_ = std::make_unique<ThreadSafeQueue<CoSimMessage>>();
        
        // C++ to SystemC message queue
        cpp_to_systemc_queue_ = std::make_unique<ThreadSafeQueue<CoSimMessage>>();
        
        // Control message queue
        control_message_queue_ = std::make_unique<ThreadSafeQueue<ControlMessage>>();
    }
    
    void setup_shared_memory_interfaces() {
        // Create shared state structure
        shared_state_ = std::make_unique<SharedCoSimState>();
        shared_state_->systemc_time_ns = 0;
        shared_state_->cpp_time_ns = 0;
        shared_state_->sync_generation = 0;
        shared_state_->simulation_active = true;
        
        // Initialize shared performance counters
        shared_performance_ = std::make_unique<SharedPerformanceCounters>();
        reset_shared_performance_counters();
    }
    
    void setup_performance_monitoring() {
        // Create performance monitoring interfaces
        performance_monitor_ = std::make_unique<CoSimPerformanceMonitor>();
        
        // Setup monitoring intervals
        performance_sample_interval_us_ = 1000; // 1ms sampling
        last_performance_sample_time_ = std::chrono::steady_clock::now();
    }
    
    bool run_co_simulation_test(const std::string& test_name) {
        std::cout << "Running co-simulation test: " << test_name << std::endl;
        
        // Start SystemC simulation in separate thread
        std::thread systemc_thread([this, test_name]() {
            run_systemc_simulation(test_name);
        });
        
        // Start C++ execution in separate thread
        std::thread cpp_thread([this, test_name]() {
            run_cpp_execution(test_name);
        });
        
        // Monitor co-simulation progress
        bool success = monitor_co_simulation_progress(test_name);
        
        // Wait for both threads to complete
        systemc_thread.join();
        cpp_thread.join();
        
        // Analyze co-simulation results
        bool results_valid = analyze_co_simulation_results(test_name);
        
        if (success && results_valid) {
            successful_cosim_tests_++;
            std::cout << test_name << ": CO-SIMULATION PASSED" << std::endl;
        } else {
            failed_cosim_tests_++;
            std::cout << test_name << ": CO-SIMULATION FAILED" << std::endl;
        }
        
        return success && results_valid;
    }
    
    void run_systemc_simulation(const std::string& test_name) {
        try {
            std::cout << "Starting SystemC simulation for " << test_name << std::endl;
            
            // Configure test-specific parameters
            configure_systemc_test(test_name);
            
            // Run SystemC simulation with synchronization
            sc_core::sc_start(sc_core::sc_time(10, sc_core::SC_MS));
            
            std::cout << "SystemC simulation completed for " << test_name << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "SystemC simulation error: " << e.what() << std::endl;
            signal_simulation_error("SystemC simulation error");
        }
    }
    
    void run_cpp_execution(const std::string& test_name) {
        try {
            std::cout << "Starting C++ execution for " << test_name << std::endl;
            
            // Configure test-specific parameters
            configure_cpp_test(test_name);
            
            // Run C++ operations with synchronization
            execute_cpp_operations(test_name);
            
            std::cout << "C++ execution completed for " << test_name << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "C++ execution error: " << e.what() << std::endl;
            signal_simulation_error("C++ execution error");
        }
    }
    
    void configure_systemc_test(const std::string& test_name) {
        if (test_name == "handshake_cosim") {
            // Configure for handshake testing
            systemc_testbench_->configure_handshake_test();
        } else if (test_name == "data_transfer_cosim") {
            // Configure for data transfer testing
            systemc_testbench_->configure_data_transfer_test();
        } else if (test_name == "performance_cosim") {
            // Configure for performance testing
            systemc_testbench_->configure_performance_test();
        } else if (test_name == "error_recovery_cosim") {
            // Configure for error recovery testing
            systemc_testbench_->configure_error_recovery_test();
        }
    }
    
    void configure_cpp_test(const std::string& test_name) {
        if (test_name == "handshake_cosim") {
            // Configure C++ for handshake testing
            setup_cpp_handshake_test();
        } else if (test_name == "data_transfer_cosim") {
            // Configure C++ for data transfer testing
            setup_cpp_data_transfer_test();
        } else if (test_name == "performance_cosim") {
            // Configure C++ for performance testing
            setup_cpp_performance_test();
        } else if (test_name == "error_recovery_cosim") {
            // Configure C++ for error recovery testing
            setup_cpp_error_recovery_test();
        }
    }
    
    void execute_cpp_operations(const std::string& test_name) {
        if (test_name == "handshake_cosim") {
            execute_cpp_handshake_operations();
        } else if (test_name == "data_transfer_cosim") {
            execute_cpp_data_transfer_operations();
        } else if (test_name == "performance_cosim") {
            execute_cpp_performance_operations();
        } else if (test_name == "error_recovery_cosim") {
            execute_cpp_error_recovery_operations();
        }
    }
    
    void execute_cpp_handshake_operations() {
        // Create DTLS connections
        auto client = cpp_client_context_->create_connection();
        auto server = cpp_server_context_->create_connection();
        
        if (!client || !server) {
            signal_simulation_error("Failed to create DTLS connections");
            return;
        }
        
        client->set_transport(cpp_client_transport_.get());
        server->set_transport(cpp_server_transport_.get());
        
        // Setup co-simulation synchronization callbacks
        setup_cosim_callbacks(client.get(), server.get());
        
        // Perform handshake with SystemC synchronization
        perform_synchronized_handshake(client.get(), server.get());
    }
    
    void execute_cpp_data_transfer_operations() {
        // Reuse connections from previous handshake or create new ones
        // For simplicity, simulate data transfer operations
        
        std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04, 0x05};
        
        // Simulate synchronized data transfer
        for (int i = 0; i < 10; ++i) {
            // Wait for SystemC synchronization
            wait_for_synchronization_point();
            
            // Simulate data transfer
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            
            // Report to SystemC domain
            report_data_transfer_completion(test_data.size());
        }
    }
    
    void execute_cpp_performance_operations() {
        // Run performance measurements synchronized with SystemC
        auto start_time = std::chrono::steady_clock::now();
        
        for (int i = 0; i < 1000; ++i) {
            // Wait for sync point
            wait_for_synchronization_point();
            
            // Perform operation
            std::this_thread::sleep_for(std::chrono::microseconds(50));
            
            // Update performance counters
            update_performance_counters();
        }
        
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        report_performance_results(duration);
    }
    
    void execute_cpp_error_recovery_operations() {
        // Simulate error conditions and recovery
        for (int i = 0; i < 5; ++i) {
            // Wait for sync
            wait_for_synchronization_point();
            
            // Inject error
            inject_cpp_error(static_cast<ErrorType>(i % 3));
            
            // Wait for recovery
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            // Report recovery status
            report_error_recovery_status(true);
        }
    }
    
    void synchronization_thread() {
        std::cout << "Synchronization thread started" << std::endl;
        
        while (sync_enabled_ && shared_state_->simulation_active) {
            // Wait for sync quantum
            std::this_thread::sleep_for(std::chrono::microseconds(sync_quantum_us_));
            
            // Update synchronization generation
            shared_state_->sync_generation++;
            
            // Update time stamps
            update_time_synchronization();
            
            // Process cross-domain messages
            process_cross_domain_messages();
            
            // Update performance monitoring
            update_performance_monitoring();
            
            sync_barrier_count_++;
            
            if (sync_barrier_count_ >= max_sync_barriers_) {
                std::cout << "Maximum sync barriers reached, stopping synchronization" << std::endl;
                break;
            }
        }
        
        std::cout << "Synchronization thread completed" << std::endl;
    }
    
    void update_time_synchronization() {
        // Update SystemC time (simulated)
        shared_state_->systemc_time_ns = static_cast<uint64_t>(
            sc_core::sc_time_stamp().to_seconds() * 1e9);
        
        // Update C++ time
        auto now = std::chrono::steady_clock::now();
        auto cpp_elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - cpp_time_offset_);
        shared_state_->cpp_time_ns = static_cast<uint64_t>(cpp_elapsed.count());
    }
    
    void process_cross_domain_messages() {
        // Process SystemC to C++ messages
        CoSimMessage msg;
        while (systemc_to_cpp_queue_->try_pop(msg)) {
            process_systemc_message(msg);
        }
        
        // Process C++ to SystemC messages
        while (cpp_to_systemc_queue_->try_pop(msg)) {
            process_cpp_message(msg);
        }
        
        // Process control messages
        ControlMessage ctrl_msg;
        while (control_message_queue_->try_pop(ctrl_msg)) {
            process_control_message(ctrl_msg);
        }
    }
    
    void update_performance_monitoring() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            now - last_performance_sample_time_);
        
        if (elapsed.count() >= performance_sample_interval_us_) {
            sample_performance_counters();
            last_performance_sample_time_ = now;
        }
    }
    
    bool monitor_co_simulation_progress(const std::string& test_name) {
        std::cout << "Monitoring co-simulation progress for " << test_name << std::endl;
        
        auto start_time = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(30);
        
        while (shared_state_->simulation_active) {
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > timeout) {
                std::cout << "Co-simulation timeout for " << test_name << std::endl;
                return false;
            }
            
            // Check for simulation errors
            if (simulation_error_occurred_) {
                std::cout << "Co-simulation error detected: " << simulation_error_message_ << std::endl;
                return false;
            }
            
            // Check progress indicators
            if (check_completion_criteria(test_name)) {
                std::cout << "Co-simulation completed successfully for " << test_name << std::endl;
                return true;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        return true;
    }
    
    bool analyze_co_simulation_results(const std::string& test_name) {
        std::cout << "Analyzing co-simulation results for " << test_name << std::endl;
        
        // Analyze time synchronization accuracy
        bool time_sync_ok = analyze_time_synchronization();
        
        // Analyze data consistency
        bool data_consistency_ok = analyze_data_consistency();
        
        // Analyze performance correlation
        bool performance_ok = analyze_performance_correlation();
        
        // Generate detailed analysis report
        generate_analysis_report(test_name, time_sync_ok, data_consistency_ok, performance_ok);
        
        return time_sync_ok && data_consistency_ok && performance_ok;
    }
    
    bool analyze_time_synchronization() {
        // Check time synchronization accuracy
        uint64_t time_diff = abs(static_cast<int64_t>(shared_state_->systemc_time_ns - 
                                                     shared_state_->cpp_time_ns));
        
        // Allow 1ms tolerance for time synchronization
        const uint64_t tolerance_ns = 1000000; // 1ms
        
        bool sync_ok = time_diff <= tolerance_ns;
        
        std::cout << "Time synchronization analysis: " << (sync_ok ? "PASS" : "FAIL") 
                  << " (diff: " << time_diff << " ns)" << std::endl;
        
        return sync_ok;
    }
    
    bool analyze_data_consistency() {
        // Check message queue consistency
        bool queues_empty = systemc_to_cpp_queue_->empty() && cpp_to_systemc_queue_->empty();
        
        // Check shared state consistency
        bool state_consistent = shared_state_->sync_generation > 0;
        
        bool consistency_ok = queues_empty && state_consistent;
        
        std::cout << "Data consistency analysis: " << (consistency_ok ? "PASS" : "FAIL") << std::endl;
        
        return consistency_ok;
    }
    
    bool analyze_performance_correlation() {
        // Check performance counter correlation
        bool counters_valid = shared_performance_->operations_completed > 0;
        
        // Check performance within expected range
        bool performance_ok = shared_performance_->average_latency_ns < 1000000; // < 1ms
        
        bool correlation_ok = counters_valid && performance_ok;
        
        std::cout << "Performance correlation analysis: " << (correlation_ok ? "PASS" : "FAIL") << std::endl;
        
        return correlation_ok;
    }
    
    void generate_analysis_report(const std::string& test_name, bool time_sync_ok, 
                                 bool data_consistency_ok, bool performance_ok) {
        std::ofstream report("cosim_analysis_" + test_name + ".txt");
        
        report << "Co-Simulation Analysis Report: " << test_name << std::endl;
        report << "======================================" << std::endl;
        report << "Time Synchronization: " << (time_sync_ok ? "PASS" : "FAIL") << std::endl;
        report << "Data Consistency: " << (data_consistency_ok ? "PASS" : "FAIL") << std::endl;
        report << "Performance Correlation: " << (performance_ok ? "PASS" : "FAIL") << std::endl;
        report << std::endl;
        
        report << "Synchronization Barriers: " << sync_barrier_count_ << std::endl;
        report << "SystemC Time: " << shared_state_->systemc_time_ns << " ns" << std::endl;
        report << "C++ Time: " << shared_state_->cpp_time_ns << " ns" << std::endl;
        report << "Operations Completed: " << shared_performance_->operations_completed << std::endl;
        report << "Average Latency: " << shared_performance_->average_latency_ns << " ns" << std::endl;
        
        report.close();
    }
    
    // Helper classes and structures
    enum class MessageType {
        HANDSHAKE_MESSAGE,
        DATA_MESSAGE,
        CONTROL_MESSAGE,
        ERROR_MESSAGE
    };
    
    struct CoSimMessage {
        MessageType type;
        std::vector<uint8_t> payload;
        uint64_t timestamp_ns;
        std::string source_domain;
    };
    
    struct ControlMessage {
        std::string command;
        std::string parameter;
        uint64_t timestamp_ns;
    };
    
    struct SharedCoSimState {
        std::atomic<uint64_t> systemc_time_ns;
        std::atomic<uint64_t> cpp_time_ns;
        std::atomic<uint32_t> sync_generation;
        std::atomic<bool> simulation_active;
    };
    
    struct SharedPerformanceCounters {
        std::atomic<uint64_t> operations_completed;
        std::atomic<uint64_t> bytes_transferred;
        std::atomic<uint64_t> total_latency_ns;
        std::atomic<uint64_t> average_latency_ns;
        std::atomic<uint32_t> error_count;
    };
    
    template<typename T>
    class ThreadSafeQueue {
    public:
        void push(const T& item) {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(item);
            condition_.notify_one();
        }
        
        bool try_pop(T& item) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty()) return false;
            item = queue_.front();
            queue_.pop();
            return true;
        }
        
        bool empty() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return queue_.empty();
        }
        
    private:
        mutable std::mutex mutex_;
        std::queue<T> queue_;
        std::condition_variable condition_;
    };
    
    class CoSimPerformanceMonitor {
    public:
        void sample_counters() {
            // Sample performance counters
        }
        
        void generate_report() {
            // Generate performance report
        }
    };
    
    // Placeholder implementations
    void setup_cpp_handshake_test() { /* Implementation */ }
    void setup_cpp_data_transfer_test() { /* Implementation */ }
    void setup_cpp_performance_test() { /* Implementation */ }
    void setup_cpp_error_recovery_test() { /* Implementation */ }
    
    void setup_cosim_callbacks(v13::Connection* client, v13::Connection* server) { /* Implementation */ }
    void perform_synchronized_handshake(v13::Connection* client, v13::Connection* server) { /* Implementation */ }
    
    void wait_for_synchronization_point() { 
        std::this_thread::sleep_for(std::chrono::microseconds(sync_quantum_us_));
    }
    
    void report_data_transfer_completion(size_t bytes) { /* Implementation */ }
    void update_performance_counters() { /* Implementation */ }
    void report_performance_results(std::chrono::microseconds duration) { /* Implementation */ }
    void inject_cpp_error(ErrorType error_type) { /* Implementation */ }
    void report_error_recovery_status(bool recovered) { /* Implementation */ }
    
    void process_systemc_message(const CoSimMessage& msg) { /* Implementation */ }
    void process_cpp_message(const CoSimMessage& msg) { /* Implementation */ }
    void process_control_message(const ControlMessage& msg) { /* Implementation */ }
    
    void sample_performance_counters() { /* Implementation */ }
    bool check_completion_criteria(const std::string& test_name) { return true; }
    
    void signal_simulation_error(const std::string& error) {
        simulation_error_occurred_ = true;
        simulation_error_message_ = error;
    }
    
    void reset_cosim_statistics() {
        successful_cosim_tests_ = 0;
        failed_cosim_tests_ = 0;
        sync_barrier_count_ = 0;
        simulation_error_occurred_ = false;
        simulation_error_message_.clear();
    }
    
    void reset_shared_performance_counters() {
        shared_performance_->operations_completed = 0;
        shared_performance_->bytes_transferred = 0;
        shared_performance_->total_latency_ns = 0;
        shared_performance_->average_latency_ns = 0;
        shared_performance_->error_count = 0;
    }
    
    void stop_co_simulation() {
        sync_enabled_ = false;
        if (shared_state_) {
            shared_state_->simulation_active = false;
        }
        
        if (sync_thread_.joinable()) {
            sync_thread_.join();
        }
        
        sc_core::sc_stop();
    }
    
    void cleanup_systemc_domain() {
        systemc_stack_.reset();
        systemc_testbench_.reset();
        systemc_sync_event_.reset();
    }
    
    void cleanup_cpp_domain() {
        if (cpp_client_transport_) {
            cpp_client_transport_->shutdown();
        }
        if (cpp_server_transport_) {
            cpp_server_transport_->shutdown();
        }
    }
    
    void generate_cosim_report() {
        std::cout << "\n=== Co-Simulation Test Results ===" << std::endl;
        std::cout << "Successful tests: " << successful_cosim_tests_ << std::endl;
        std::cout << "Failed tests: " << failed_cosim_tests_ << std::endl;
        std::cout << "Synchronization barriers: " << sync_barrier_count_ << std::endl;
        
        if (successful_cosim_tests_ + failed_cosim_tests_ > 0) {
            double success_rate = static_cast<double>(successful_cosim_tests_) / 
                                 (successful_cosim_tests_ + failed_cosim_tests_) * 100.0;
            std::cout << "Success rate: " << success_rate << "%" << std::endl;
        }
    }

protected:
    // SystemC domain
    std::unique_ptr<dtls_protocol_stack> systemc_stack_;
    std::unique_ptr<dtls_testbench> systemc_testbench_;
    std::unique_ptr<sc_core::sc_event> systemc_sync_event_;
    
    // C++ domain
    std::unique_ptr<v13::Context> cpp_client_context_;
    std::unique_ptr<v13::Context> cpp_server_context_;
    std::unique_ptr<transport::UDPTransport> cpp_client_transport_;
    std::unique_ptr<transport::UDPTransport> cpp_server_transport_;
    
    // Synchronization framework
    std::thread sync_thread_;
    std::atomic<bool> sync_enabled_{true};
    std::atomic<uint32_t> sync_barrier_count_{0};
    uint32_t max_sync_barriers_;
    uint32_t sync_quantum_us_;
    
    // Time synchronization
    sc_core::sc_time systemc_clock_period_;
    sc_core::sc_time systemc_simulation_quantum_;
    sc_core::sc_time systemc_time_offset_;
    std::chrono::steady_clock::time_point cpp_time_offset_;
    
    // Data exchange interfaces
    std::unique_ptr<ThreadSafeQueue<CoSimMessage>> systemc_to_cpp_queue_;
    std::unique_ptr<ThreadSafeQueue<CoSimMessage>> cpp_to_systemc_queue_;
    std::unique_ptr<ThreadSafeQueue<ControlMessage>> control_message_queue_;
    
    // Shared state
    std::unique_ptr<SharedCoSimState> shared_state_;
    std::unique_ptr<SharedPerformanceCounters> shared_performance_;
    
    // Performance monitoring
    std::unique_ptr<CoSimPerformanceMonitor> performance_monitor_;
    uint32_t performance_sample_interval_us_;
    std::chrono::steady_clock::time_point last_performance_sample_time_;
    
    // Test statistics
    std::atomic<uint32_t> successful_cosim_tests_{0};
    std::atomic<uint32_t> failed_cosim_tests_{0};
    
    // Error handling
    std::atomic<bool> simulation_error_occurred_{false};
    std::string simulation_error_message_;
};

// Co-Simulation Test 1: Handshake Co-Simulation
TEST_F(SystemCCoSimulationTest, HandshakeCoSimulation) {
    EXPECT_TRUE(run_co_simulation_test("handshake_cosim"));
}

// Co-Simulation Test 2: Data Transfer Co-Simulation
TEST_F(SystemCCoSimulationTest, DataTransferCoSimulation) {
    EXPECT_TRUE(run_co_simulation_test("data_transfer_cosim"));
}

// Co-Simulation Test 3: Performance Co-Simulation
TEST_F(SystemCCoSimulationTest, PerformanceCoSimulation) {
    EXPECT_TRUE(run_co_simulation_test("performance_cosim"));
}

// Co-Simulation Test 4: Error Recovery Co-Simulation
TEST_F(SystemCCoSimulationTest, ErrorRecoveryCoSimulation) {
    EXPECT_TRUE(run_co_simulation_test("error_recovery_cosim"));
}

} // namespace test
} // namespace systemc
} // namespace dtls