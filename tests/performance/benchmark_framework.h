/*
 * DTLS v1.3 Performance Benchmark Framework
 * Task 10: Performance Benchmarking - Core Infrastructure
 */

#pragma once

#include <chrono>
#include <vector>
#include <string>
#include <map>
#include <functional>
#include <memory>
#include <ostream>
#include <thread>
#include <atomic>

#ifdef DTLS_HAS_BENCHMARK
#include <benchmark/benchmark.h>
#endif

namespace dtls::v13::test::performance {

// ============================================================================
// Core Benchmark Types and Configuration
// ============================================================================

struct BenchmarkConfig {
    size_t iterations = 1000;
    size_t warmup_iterations = 100;
    std::chrono::milliseconds timeout{30000};
    bool measure_memory = true;
    bool measure_cpu = true;
    double error_threshold = 0.05; // 5% error threshold
    size_t thread_count = 1;
    
    // Data size configurations for throughput tests
    std::vector<size_t> data_sizes = {64, 256, 1024, 4096, 16384, 65536};
    
    // Connection configurations
    size_t concurrent_connections = 10;
    size_t max_connections = 1000;
};

struct BenchmarkResult {
    std::string name;
    size_t iterations = 0;
    double mean_time_ms;
    double min_time_ms;
    double max_time_ms;
    double std_deviation_ms;
    double operations_per_second;
    
    // Memory metrics
    size_t peak_memory_bytes = 0;
    size_t avg_memory_bytes = 0;
    
    // CPU metrics
    double avg_cpu_percent = 0.0;
    double peak_cpu_percent = 0.0;
    
    // Throughput metrics
    double throughput_mbps = 0.0;
    size_t total_bytes_processed = 0;
    
    // Error metrics
    size_t error_count = 0;
    double error_rate = 0.0;
    
    // Compliance metrics
    bool meets_latency_requirement = false;
    bool meets_throughput_requirement = false;
    bool meets_memory_requirement = false;
    bool meets_cpu_requirement = false;
    
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, double> custom_metrics;
};

struct PRDRequirements {
    double max_handshake_latency_ms = 10.0;
    double max_additional_latency_ms = 1.0;
    double min_throughput_percent = 90.0; // 90% of UDP throughput
    double max_overhead_percent = 5.0;     // <5% overhead vs plain UDP
    size_t max_memory_overhead_mb = 10;    // Additional memory usage
    double max_cpu_overhead_percent = 20.0; // CPU overhead
};

// ============================================================================
// Resource Monitoring
// ============================================================================

class ResourceMonitor {
public:
    ResourceMonitor();
    ~ResourceMonitor();
    
    void start_monitoring();
    void stop_monitoring();
    
    size_t get_peak_memory_usage() const;
    size_t get_average_memory_usage() const;
    double get_peak_cpu_usage() const;
    double get_average_cpu_usage() const;
    
    void reset();
    
private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

// ============================================================================
// Timer and Measurement Utilities
// ============================================================================

class HighResolutionTimer {
public:
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;
    using Duration = Clock::duration;
    
    HighResolutionTimer();
    
    void start();
    void stop();
    void reset();
    
    double elapsed_milliseconds() const;
    double elapsed_microseconds() const;
    Duration elapsed() const;
    
    bool is_running() const;
    
private:
    TimePoint start_time_;
    TimePoint end_time_;
    bool is_running_;
};

class StatisticalAccumulator {
public:
    StatisticalAccumulator();
    
    void add_sample(double value);
    void clear();
    
    size_t count() const;
    double mean() const;
    double min() const;
    double max() const;
    double variance() const;
    double standard_deviation() const;
    double percentile(double p) const;
    
    std::vector<double> get_samples() const;
    
private:
    std::vector<double> samples_;
    double sum_;
    double sum_squares_;
    double min_value_;
    double max_value_;
};

// ============================================================================
// Benchmark Execution Framework
// ============================================================================

class BenchmarkRunner {
public:
    explicit BenchmarkRunner(const BenchmarkConfig& config = BenchmarkConfig{});
    ~BenchmarkRunner();
    
    // Register benchmark functions
    using BenchmarkFunction = std::function<void()>;
    using SetupFunction = std::function<void()>;
    using TeardownFunction = std::function<void()>;
    
    void register_benchmark(const std::string& name, 
                          BenchmarkFunction benchmark_func,
                          SetupFunction setup_func = nullptr,
                          TeardownFunction teardown_func = nullptr);
    
    // Execution
    std::vector<BenchmarkResult> run_all_benchmarks();
    BenchmarkResult run_benchmark(const std::string& name);
    
    // Configuration
    void set_config(const BenchmarkConfig& config);
    const BenchmarkConfig& get_config() const;
    
    void set_prd_requirements(const PRDRequirements& requirements);
    const PRDRequirements& get_prd_requirements() const;
    
    // Results management
    void save_results(const std::vector<BenchmarkResult>& results, 
                     const std::string& filename);
    std::vector<BenchmarkResult> load_baseline(const std::string& filename);
    void compare_with_baseline(const std::vector<BenchmarkResult>& current,
                              const std::vector<BenchmarkResult>& baseline,
                              std::ostream& output);
    
    // Reporting
    void generate_report(const std::vector<BenchmarkResult>& results,
                        std::ostream& output);
    void generate_json_report(const std::vector<BenchmarkResult>& results,
                             const std::string& filename);
    void generate_csv_report(const std::vector<BenchmarkResult>& results,
                            const std::string& filename);
    
private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

// ============================================================================
// Specialized Benchmark Types
// ============================================================================

class HandshakeBenchmark {
public:
    explicit HandshakeBenchmark(const BenchmarkConfig& config = BenchmarkConfig{});
    ~HandshakeBenchmark(); // Destructor must be defined in .cpp where Impl is complete
    
    BenchmarkResult benchmark_full_handshake();
    BenchmarkResult benchmark_handshake_with_retry();
    BenchmarkResult benchmark_handshake_with_fragmentation();
    BenchmarkResult benchmark_resumption_handshake();
    BenchmarkResult benchmark_early_data_handshake();
    
    void set_certificate_chain_length(size_t length);
    void set_key_exchange_group(const std::string& group);
    void set_cipher_suite(uint16_t cipher_suite);
    
private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

// TODO: Re-enable when throughput_benchmarks.cpp is fixed
/*
class ThroughputBenchmark {
public:
    explicit ThroughputBenchmark(const BenchmarkConfig& config = BenchmarkConfig{});
    
    BenchmarkResult benchmark_application_data_throughput(size_t data_size);
    BenchmarkResult benchmark_concurrent_connections(size_t connection_count);
    BenchmarkResult benchmark_streaming_throughput(size_t stream_duration_ms);
    BenchmarkResult benchmark_udp_comparison(size_t data_size);
    
    void set_encryption_enabled(bool enabled);
    void set_compression_enabled(bool enabled);
    void set_packet_loss_rate(double loss_rate);
    
private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};
*/

// TODO: Re-enable when resource_benchmarks.cpp is fixed
/*
class MemoryBenchmark {
public:
    explicit MemoryBenchmark(const BenchmarkConfig& config = BenchmarkConfig{});
    
    BenchmarkResult benchmark_connection_memory_usage();
    BenchmarkResult benchmark_handshake_memory_overhead();
    BenchmarkResult benchmark_crypto_memory_usage();
    BenchmarkResult benchmark_buffer_management();
    BenchmarkResult benchmark_memory_leaks();
    
    void set_connection_count(size_t count);
    void enable_memory_tracking(bool enabled);
    
private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};
*/

// ============================================================================
// Integration with Google Benchmark (if available)
// ============================================================================

#ifdef DTLS_HAS_BENCHMARK

class GoogleBenchmarkAdapter {
public:
    static void register_dtls_benchmarks();
    static void configure_benchmark_settings();
    
    // Benchmark function templates
    template<typename BenchmarkFunc>
    static void benchmark_template(benchmark::State& state, BenchmarkFunc func);
    
private:
    static BenchmarkConfig default_config_;
};

// Macros for easy benchmark registration
#define DTLS_BENCHMARK(name, func) \
    BENCHMARK_CAPTURE(GoogleBenchmarkAdapter::benchmark_template, name, func)

#define DTLS_BENCHMARK_RANGE(name, func, start, end) \
    BENCHMARK_CAPTURE(GoogleBenchmarkAdapter::benchmark_template, name, func)->Range(start, end)

#endif // DTLS_HAS_BENCHMARK

// ============================================================================
// Utility Functions
// ============================================================================

// PRD compliance validation
bool validate_prd_compliance(const BenchmarkResult& result, 
                           const PRDRequirements& requirements);

std::string generate_prd_compliance_report(const std::vector<BenchmarkResult>& results,
                                          const PRDRequirements& requirements);

// Performance comparison utilities
double calculate_performance_delta(const BenchmarkResult& current,
                                 const BenchmarkResult& baseline);

bool detect_performance_regression(const BenchmarkResult& current,
                                 const BenchmarkResult& baseline,
                                 double threshold = 0.05);

// Data generation utilities
std::vector<uint8_t> generate_test_data(size_t size, uint32_t seed = 0);
std::vector<uint8_t> generate_compressible_data(size_t size);
std::vector<uint8_t> generate_random_data(size_t size);

// Platform-specific performance counters
namespace platform {
    uint64_t get_cpu_cycles();
    uint64_t get_cpu_frequency();
    size_t get_memory_usage();
    double get_cpu_utilization();
    bool is_high_resolution_timer_available();
}

} // namespace dtls::v13::test::performance