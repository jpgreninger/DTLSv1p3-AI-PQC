#include "dtls_protocol_stack.h"
#include "dtls_testbench.h"
#include <systemc>
#include <tlm.h>
#include <iostream>
#include <vector>
#include <chrono>

using namespace sc_core;
using namespace dtls::v13::systemc_tlm;

SC_MODULE(performance_test) {
    // Test infrastructure
    sc_clock clock;
    sc_signal<bool> reset;
    sc_signal<bool> test_complete;
    sc_signal<bool> enable_stack;
    sc_signal<uint32_t> max_connections;
    sc_signal<bool> hardware_acceleration_enabled;
    sc_signal<uint16_t> mtu_size;
    
    // Protocol stack under test
    dtls_protocol_stack* protocol_stack;
    
    // Performance test interface
    tlm_utils::simple_initiator_socket<performance_test> perf_socket;
    
    // Performance metrics
    struct PerformanceMetrics {
        sc_time test_start_time{0, SC_NS};
        sc_time test_end_time{0, SC_NS};
        uint64_t total_transactions{0};
        uint64_t successful_transactions{0};
        uint64_t total_bytes_processed{0};
        sc_time total_processing_time{0, SC_NS};
        sc_time min_transaction_time{0, SC_NS};
        sc_time max_transaction_time{0, SC_NS};
        double throughput_mbps{0.0};
        double transaction_rate{0.0};
        uint32_t peak_connections{0};
        double cpu_utilization{0.0};
        uint64_t memory_usage{0};
        
        void reset() {
            test_start_time = sc_time(0, SC_NS);
            test_end_time = sc_time(0, SC_NS);
            total_transactions = 0;
            successful_transactions = 0;
            total_bytes_processed = 0;
            total_processing_time = sc_time(0, SC_NS);
            min_transaction_time = sc_time(0, SC_NS);
            max_transaction_time = sc_time(0, SC_NS);
            throughput_mbps = 0.0;
            transaction_rate = 0.0;
            peak_connections = 0;
            cpu_utilization = 0.0;
            memory_usage = 0;
        }
    } metrics;
    
    SC_CTOR(performance_test) 
        : clock("clock", 10, SC_NS)
        , reset("reset")
        , test_complete("test_complete")
        , enable_stack("enable_stack")
        , max_connections("max_connections")
        , hardware_acceleration_enabled("hardware_acceleration_enabled")
        , mtu_size("mtu_size")
        , perf_socket("perf_socket")
    {
        // Create protocol stack
        protocol_stack = new dtls_protocol_stack("dtls_stack");
        
        // Connect configuration signals
        protocol_stack->enable_stack(enable_stack);
        protocol_stack->max_connections(max_connections);
        protocol_stack->hardware_acceleration_enabled(hardware_acceleration_enabled);
        protocol_stack->mtu_size(mtu_size);
        
        // Connect TLM socket
        perf_socket.bind(protocol_stack->application_target_socket);
        
        // Configure for performance testing
        enable_stack.write(true);
        max_connections.write(1000);
        hardware_acceleration_enabled.write(true); // Enable HW acceleration
        mtu_size.write(1500);
        
        // Register performance test processes
        SC_THREAD(run_throughput_benchmark);
        SC_THREAD(run_latency_benchmark);
        SC_THREAD(run_scalability_benchmark);
        SC_THREAD(run_concurrent_connections_benchmark);
        SC_THREAD(run_memory_usage_benchmark);
        SC_THREAD(monitor_system_performance);
        SC_THREAD(performance_test_manager);
        
        std::cout << "Performance Test Suite initialized" << std::endl;
    }
    
    ~performance_test() {
        delete protocol_stack;
    }
    
    void run_throughput_benchmark() {
        wait(100, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting throughput benchmark" << std::endl;
        
        metrics.test_start_time = sc_time_stamp();
        
        // Test different data sizes for throughput measurement
        const size_t data_sizes[] = {64, 256, 512, 1024, 2048, 4096};
        const size_t num_sizes = sizeof(data_sizes) / sizeof(data_sizes[0]);
        const size_t transactions_per_size = 500;
        
        for (size_t size_idx = 0; size_idx < num_sizes; ++size_idx) {
            size_t data_size = data_sizes[size_idx];
            std::vector<unsigned char> test_data(data_size);
            
            // Initialize test data with pattern
            for (size_t i = 0; i < data_size; ++i) {
                test_data[i] = static_cast<unsigned char>((i + size_idx) & 0xFF);
            }
            
            sc_time size_test_start = sc_time_stamp();
            uint64_t successful_for_size = 0;
            
            for (size_t trans_idx = 0; trans_idx < transactions_per_size; ++trans_idx) {
                sc_time trans_start = sc_time_stamp();
                
                tlm::tlm_generic_payload trans;
                sc_time delay = SC_ZERO_TIME;
                
                trans.set_data_ptr(test_data.data());
                trans.set_data_length(data_size);
                trans.set_command(tlm::TLM_WRITE_COMMAND);
                trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
                
                dtls_extension ext;
                ext.message_type = dtls_extension::APPLICATION_DATA;
                ext.connection_id = 1;
                ext.epoch = 1;
                ext.sequence_number = metrics.total_transactions + trans_idx;
                ext.priority = dtls_extension::HIGH;
                
                trans.set_extension(&ext);
                
                // Execute transaction
                perf_socket->b_transport(trans, delay);
                
                sc_time trans_end = sc_time_stamp();
                sc_time trans_duration = trans_end - trans_start + delay;
                
                metrics.total_transactions++;
                
                if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
                    metrics.successful_transactions++;
                    successful_for_size++;
                    metrics.total_bytes_processed += data_size;
                    metrics.total_processing_time += trans_duration;
                    
                    // Update min/max transaction times
                    if (metrics.min_transaction_time == sc_time(0, SC_NS) || 
                        trans_duration < metrics.min_transaction_time) {
                        metrics.min_transaction_time = trans_duration;
                    }
                    if (trans_duration > metrics.max_transaction_time) {
                        metrics.max_transaction_time = trans_duration;
                    }
                }
                
                // Yield occasionally to allow other processes
                if (trans_idx % 50 == 0) {
                    wait(1, SC_NS);
                }
            }
            
            sc_time size_test_end = sc_time_stamp();
            sc_time size_duration = size_test_end - size_test_start;
            
            // Calculate throughput for this data size
            double size_throughput = (successful_for_size * data_size * 8.0) / 
                                   (size_duration.to_seconds() * 1024.0 * 1024.0);
            
            std::cout << "[" << sc_time_stamp() << "] Throughput for " << data_size 
                      << " byte packets: " << size_throughput << " Mbps ("
                      << successful_for_size << "/" << transactions_per_size << " successful)" << std::endl;
        }
        
        std::cout << "[" << sc_time_stamp() << "] Throughput benchmark completed" << std::endl;
    }
    
    void run_latency_benchmark() {
        wait(2000, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting latency benchmark" << std::endl;
        
        // Test round-trip latency with small packets
        const size_t num_latency_tests = 1000;
        const size_t packet_size = 64; // Small packet for latency test
        
        std::vector<unsigned char> latency_data(packet_size, 0xCC);
        std::vector<sc_time> latencies;
        latencies.reserve(num_latency_tests);
        
        for (size_t i = 0; i < num_latency_tests; ++i) {
            sc_time request_start = sc_time_stamp();
            
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(latency_data.data());
            trans.set_data_length(packet_size);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 2;
            ext.epoch = 1;
            ext.sequence_number = i + 10000;
            ext.priority = dtls_extension::CRITICAL; // High priority for latency test
            
            trans.set_extension(&ext);
            
            perf_socket->b_transport(trans, delay);
            
            sc_time request_end = sc_time_stamp();
            sc_time latency = request_end - request_start + delay;
            
            if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
                latencies.push_back(latency);
            }
            
            // Small delay between requests
            wait(2, SC_NS);
        }
        
        // Calculate latency statistics
        if (!latencies.empty()) {
            std::sort(latencies.begin(), latencies.end());
            
            sc_time min_latency = latencies.front();
            sc_time max_latency = latencies.back();
            sc_time median_latency = latencies[latencies.size() / 2];
            sc_time p95_latency = latencies[static_cast<size_t>(latencies.size() * 0.95)];
            sc_time p99_latency = latencies[static_cast<size_t>(latencies.size() * 0.99)];
            
            // Calculate average
            sc_time total_latency(0, SC_NS);
            for (const auto& lat : latencies) {
                total_latency += lat;
            }
            sc_time avg_latency = total_latency / latencies.size();
            
            std::cout << "[" << sc_time_stamp() << "] Latency benchmark results:" << std::endl;
            std::cout << "  Successful requests: " << latencies.size() << "/" << num_latency_tests << std::endl;
            std::cout << "  Min latency: " << min_latency << std::endl;
            std::cout << "  Average latency: " << avg_latency << std::endl;
            std::cout << "  Median latency: " << median_latency << std::endl;
            std::cout << "  95th percentile: " << p95_latency << std::endl;
            std::cout << "  99th percentile: " << p99_latency << std::endl;
            std::cout << "  Max latency: " << max_latency << std::endl;
        }
        
        std::cout << "[" << sc_time_stamp() << "] Latency benchmark completed" << std::endl;
    }
    
    void run_scalability_benchmark() {
        wait(4000, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting scalability benchmark" << std::endl;
        
        // Test system behavior under increasing load
        const size_t load_levels[] = {10, 50, 100, 250, 500, 1000};
        const size_t num_load_levels = sizeof(load_levels) / sizeof(load_levels[0]);
        const size_t transactions_per_level = 100;
        const size_t data_size = 256;
        
        std::vector<unsigned char> scale_data(data_size, 0xDD);
        
        for (size_t level_idx = 0; level_idx < num_load_levels; ++level_idx) {
            size_t load_level = load_levels[level_idx];
            
            std::cout << "[" << sc_time_stamp() << "] Testing load level: " 
                      << load_level << " transactions" << std::endl;
            
            sc_time level_start = sc_time_stamp();
            uint64_t level_successful = 0;
            
            for (size_t trans_idx = 0; trans_idx < load_level && trans_idx < transactions_per_level; ++trans_idx) {
                tlm::tlm_generic_payload trans;
                sc_time delay = SC_ZERO_TIME;
                
                trans.set_data_ptr(scale_data.data());
                trans.set_data_length(data_size);
                trans.set_command(tlm::TLM_WRITE_COMMAND);
                trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
                
                dtls_extension ext;
                ext.message_type = dtls_extension::APPLICATION_DATA;
                ext.connection_id = 3;
                ext.epoch = 1;
                ext.sequence_number = trans_idx + 20000;
                ext.priority = dtls_extension::NORMAL;
                
                trans.set_extension(&ext);
                
                perf_socket->b_transport(trans, delay);
                
                if (trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
                    level_successful++;
                }
                
                // Reduce delay as load increases to simulate higher pressure
                wait(std::max(1, static_cast<int>(50 / load_level)), SC_NS);
            }
            
            sc_time level_end = sc_time_stamp();
            sc_time level_duration = level_end - level_start;
            
            double success_rate = (static_cast<double>(level_successful) / 
                                 std::min(load_level, transactions_per_level)) * 100.0;
            double throughput = (level_successful * data_size * 8.0) / 
                              (level_duration.to_seconds() * 1024.0 * 1024.0);
            
            std::cout << "  Load " << load_level << " results: " 
                      << level_successful << "/" << std::min(load_level, transactions_per_level) 
                      << " successful (" << success_rate << "%), "
                      << throughput << " Mbps" << std::endl;
            
            wait(100, SC_NS); // Recovery time between load levels
        }
        
        std::cout << "[" << sc_time_stamp() << "] Scalability benchmark completed" << std::endl;
    }
    
    void run_concurrent_connections_benchmark() {
        wait(6000, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting concurrent connections benchmark" << std::endl;
        
        // Test with multiple simultaneous connections
        const uint32_t num_connections = 50;
        const size_t transactions_per_connection = 20;
        const size_t data_size = 128;
        
        std::vector<unsigned char> conn_data(data_size, 0xEE);
        
        for (uint32_t conn_id = 100; conn_id < 100 + num_connections; ++conn_id) {
            // Establish connection first
            std::string handshake = "HANDSHAKE_CONN_" + std::to_string(conn_id);
            
            tlm::tlm_generic_payload hs_trans;
            sc_time delay = SC_ZERO_TIME;
            
            hs_trans.set_data_ptr(reinterpret_cast<unsigned char*>(const_cast<char*>(handshake.c_str())));
            hs_trans.set_data_length(handshake.length());
            hs_trans.set_command(tlm::TLM_WRITE_COMMAND);
            hs_trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension hs_ext;
            hs_ext.message_type = dtls_extension::HANDSHAKE;
            hs_ext.handshake_type = dtls_extension::CLIENT_HELLO;
            hs_ext.connection_id = conn_id;
            hs_ext.epoch = 0;
            hs_ext.sequence_number = 0;
            
            hs_trans.set_extension(&hs_ext);
            
            perf_socket->b_transport(hs_trans, delay);
            
            if (hs_trans.get_response_status() == tlm::TLM_OK_RESPONSE) {
                // Send data on this connection
                for (size_t trans_idx = 0; trans_idx < transactions_per_connection; ++trans_idx) {
                    tlm::tlm_generic_payload data_trans;
                    sc_time data_delay = SC_ZERO_TIME;
                    
                    data_trans.set_data_ptr(conn_data.data());
                    data_trans.set_data_length(data_size);
                    data_trans.set_command(tlm::TLM_WRITE_COMMAND);
                    data_trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
                    
                    dtls_extension data_ext;
                    data_ext.message_type = dtls_extension::APPLICATION_DATA;
                    data_ext.connection_id = conn_id;
                    data_ext.epoch = 1;
                    data_ext.sequence_number = trans_idx + 1;
                    
                    data_trans.set_extension(&data_ext);
                    
                    perf_socket->b_transport(data_trans, data_delay);
                    
                    wait(5, SC_NS);
                }
                
                metrics.peak_connections = std::max(metrics.peak_connections, conn_id - 99);
            }
            
            wait(20, SC_NS);
        }
        
        std::cout << "[" << sc_time_stamp() << "] Concurrent connections benchmark completed" << std::endl;
        std::cout << "  Peak concurrent connections handled: " << metrics.peak_connections << std::endl;
    }
    
    void run_memory_usage_benchmark() {
        wait(8000, SC_NS);
        
        std::cout << "[" << sc_time_stamp() << "] Starting memory usage benchmark" << std::endl;
        
        // Monitor memory usage under load
        auto initial_stats = protocol_stack->get_statistics();
        uint64_t initial_memory = initial_stats.current_memory_usage;
        
        // Create load to increase memory usage
        const size_t large_data_size = 8192;
        const size_t num_large_transactions = 100;
        
        std::vector<unsigned char> large_data(large_data_size, 0xFF);
        
        for (size_t i = 0; i < num_large_transactions; ++i) {
            tlm::tlm_generic_payload trans;
            sc_time delay = SC_ZERO_TIME;
            
            trans.set_data_ptr(large_data.data());
            trans.set_data_length(large_data_size);
            trans.set_command(tlm::TLM_WRITE_COMMAND);
            trans.set_response_status(tlm::TLM_INCOMPLETE_RESPONSE);
            
            dtls_extension ext;
            ext.message_type = dtls_extension::APPLICATION_DATA;
            ext.connection_id = 4;
            ext.epoch = 1;
            ext.sequence_number = i + 30000;
            
            trans.set_extension(&ext);
            
            perf_socket->b_transport(trans, delay);
            
            if (i % 10 == 0) {
                auto current_stats = protocol_stack->get_statistics();
                metrics.memory_usage = std::max(metrics.memory_usage, current_stats.current_memory_usage);
            }
            
            wait(10, SC_NS);
        }
        
        auto final_stats = protocol_stack->get_statistics();
        
        std::cout << "[" << sc_time_stamp() << "] Memory usage benchmark results:" << std::endl;
        std::cout << "  Initial memory usage: " << initial_memory << " bytes" << std::endl;
        std::cout << "  Peak memory usage: " << metrics.memory_usage << " bytes" << std::endl;
        std::cout << "  Final memory usage: " << final_stats.current_memory_usage << " bytes" << std::endl;
        std::cout << "  Memory increase: " << (final_stats.current_memory_usage - initial_memory) << " bytes" << std::endl;
        
        std::cout << "[" << sc_time_stamp() << "] Memory usage benchmark completed" << std::endl;
    }
    
    void monitor_system_performance() {
        while (true) {
            wait(500, SC_NS);
            
            auto stats = protocol_stack->get_statistics();
            metrics.cpu_utilization = std::max(metrics.cpu_utilization, stats.current_cpu_utilization);
            
            if (sc_time_stamp() > sc_time(5000, SC_NS)) {
                // Log periodic performance updates
                if (sc_time_stamp().value() % 2000000 == 0) { // Every 2000 NS
                    std::cout << "[" << sc_time_stamp() << "] Performance Monitor:" << std::endl;
                    std::cout << "  Active connections: " << stats.active_connections << std::endl;
                    std::cout << "  CPU utilization: " << stats.current_cpu_utilization << "%" << std::endl;
                    std::cout << "  Memory usage: " << stats.current_memory_usage << " bytes" << std::endl;
                    std::cout << "  Overhead: " << stats.overhead_percentage << "%" << std::endl;
                }
            }
        }
    }
    
    void performance_test_manager() {
        wait(10000, SC_NS);
        
        metrics.test_end_time = sc_time_stamp();
        sc_time total_test_time = metrics.test_end_time - metrics.test_start_time;
        
        // Calculate final performance metrics
        if (total_test_time > sc_time(0, SC_NS)) {
            metrics.throughput_mbps = (metrics.total_bytes_processed * 8.0) / 
                                    (total_test_time.to_seconds() * 1024.0 * 1024.0);
            metrics.transaction_rate = static_cast<double>(metrics.successful_transactions) / 
                                     total_test_time.to_seconds();
        }
        
        double success_rate = (static_cast<double>(metrics.successful_transactions) / 
                             metrics.total_transactions) * 100.0;
        
        std::cout << "\n======= PERFORMANCE TEST RESULTS =======" << std::endl;
        std::cout << "Test duration: " << total_test_time << std::endl;
        std::cout << "Total transactions: " << metrics.total_transactions << std::endl;
        std::cout << "Successful transactions: " << metrics.successful_transactions 
                  << " (" << success_rate << "%)" << std::endl;
        std::cout << "Total bytes processed: " << metrics.total_bytes_processed << std::endl;
        std::cout << "Average throughput: " << metrics.throughput_mbps << " Mbps" << std::endl;
        std::cout << "Transaction rate: " << metrics.transaction_rate << " trans/sec" << std::endl;
        std::cout << "Min transaction time: " << metrics.min_transaction_time << std::endl;
        std::cout << "Max transaction time: " << metrics.max_transaction_time << std::endl;
        std::cout << "Peak concurrent connections: " << metrics.peak_connections << std::endl;
        std::cout << "Peak CPU utilization: " << metrics.cpu_utilization << "%" << std::endl;
        std::cout << "Peak memory usage: " << metrics.memory_usage << " bytes" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        test_complete.write(true);
        sc_stop();
    }
};

int sc_main(int argc, char* argv[]) {
    // Create performance test
    performance_test test("performance_test");
    
    // Run simulation
    std::cout << "Starting DTLS v1.3 performance test simulation..." << std::endl;
    sc_start();
    
    std::cout << "Performance test simulation completed" << std::endl;
    return 0;
}