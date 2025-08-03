/*
 * DTLS v1.3 Performance Benchmark Framework Implementation
 * Task 10: Performance Benchmarking - Core Infrastructure
 */

#include "benchmark_framework.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <thread>
#include <future>

// Platform-specific includes
#ifdef __linux__
#include <sys/resource.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#endif

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace dtls::v13::test::performance {

// ============================================================================
// ResourceMonitor Implementation
// ============================================================================

class ResourceMonitor::Impl {
public:
    Impl() : monitoring_(false), peak_memory_(0), total_memory_(0), 
             sample_count_(0), peak_cpu_(0.0), total_cpu_(0.0) {}
    
    void start_monitoring() {
        if (monitoring_) return;
        
        monitoring_ = true;
        peak_memory_ = 0;
        total_memory_ = 0;
        sample_count_ = 0;
        peak_cpu_ = 0.0;
        total_cpu_ = 0.0;
        
        monitor_thread_ = std::thread([this]() {
            while (monitoring_) {
                size_t current_memory = get_current_memory_usage();
                double current_cpu = get_current_cpu_usage();
                
                peak_memory_ = std::max(peak_memory_.load(), current_memory);
                total_memory_ += current_memory;
                
                peak_cpu_ = std::max(peak_cpu_.load(), current_cpu);
                total_cpu_ += current_cpu;
                
                sample_count_++;
                
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }
    
    void stop_monitoring() {
        if (!monitoring_) return;
        
        monitoring_ = false;
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
    }
    
    size_t get_peak_memory_usage() const { return peak_memory_; }
    size_t get_average_memory_usage() const { 
        return sample_count_ > 0 ? total_memory_ / sample_count_ : 0; 
    }
    double get_peak_cpu_usage() const { return peak_cpu_; }
    double get_average_cpu_usage() const { 
        return sample_count_ > 0 ? total_cpu_ / sample_count_ : 0.0; 
    }
    
    void reset() {
        peak_memory_ = 0;
        total_memory_ = 0;
        sample_count_ = 0;
        peak_cpu_ = 0.0;
        total_cpu_ = 0.0;
    }
    
private:
    std::atomic<bool> monitoring_;
    std::thread monitor_thread_;
    
    std::atomic<size_t> peak_memory_;
    std::atomic<size_t> total_memory_;
    std::atomic<size_t> sample_count_;
    std::atomic<double> peak_cpu_;
    std::atomic<double> total_cpu_;
    
    size_t get_current_memory_usage() const {
#ifdef __linux__
        std::ifstream status("/proc/self/status");
        std::string line;
        while (std::getline(status, line)) {
            if (line.find("VmRSS:") == 0) {
                std::istringstream iss(line);
                std::string label;
                size_t value;
                std::string unit;
                iss >> label >> value >> unit;
                return value * 1024; // Convert KB to bytes
            }
        }
#endif
        return 0;
    }
    
    double get_current_cpu_usage() const {
        // Simplified CPU usage - platform-specific implementation needed
        return 0.0;
    }
};

ResourceMonitor::ResourceMonitor() : pimpl_(std::make_unique<Impl>()) {}
ResourceMonitor::~ResourceMonitor() = default;

void ResourceMonitor::start_monitoring() { pimpl_->start_monitoring(); }
void ResourceMonitor::stop_monitoring() { pimpl_->stop_monitoring(); }
size_t ResourceMonitor::get_peak_memory_usage() const { return pimpl_->get_peak_memory_usage(); }
size_t ResourceMonitor::get_average_memory_usage() const { return pimpl_->get_average_memory_usage(); }
double ResourceMonitor::get_peak_cpu_usage() const { return pimpl_->get_peak_cpu_usage(); }
double ResourceMonitor::get_average_cpu_usage() const { return pimpl_->get_average_cpu_usage(); }
void ResourceMonitor::reset() { pimpl_->reset(); }

// ============================================================================
// HighResolutionTimer Implementation
// ============================================================================

HighResolutionTimer::HighResolutionTimer() : is_running_(false) {}

void HighResolutionTimer::start() {
    start_time_ = Clock::now();
    is_running_ = true;
}

void HighResolutionTimer::stop() {
    if (is_running_) {
        end_time_ = Clock::now();
        is_running_ = false;
    }
}

void HighResolutionTimer::reset() {
    is_running_ = false;
}

double HighResolutionTimer::elapsed_milliseconds() const {
    auto end = is_running_ ? Clock::now() : end_time_;
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_time_);
    return duration.count() / 1000000.0;
}

double HighResolutionTimer::elapsed_microseconds() const {
    auto end = is_running_ ? Clock::now() : end_time_;
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_time_);
    return duration.count() / 1000.0;
}

HighResolutionTimer::Duration HighResolutionTimer::elapsed() const {
    auto end = is_running_ ? Clock::now() : end_time_;
    return end - start_time_;
}

bool HighResolutionTimer::is_running() const {
    return is_running_;
}

// ============================================================================
// StatisticalAccumulator Implementation
// ============================================================================

StatisticalAccumulator::StatisticalAccumulator() 
    : sum_(0.0), sum_squares_(0.0), min_value_(std::numeric_limits<double>::max()),
      max_value_(std::numeric_limits<double>::lowest()) {}

void StatisticalAccumulator::add_sample(double value) {
    samples_.push_back(value);
    sum_ += value;
    sum_squares_ += value * value;
    min_value_ = std::min(min_value_, value);
    max_value_ = std::max(max_value_, value);
}

void StatisticalAccumulator::clear() {
    samples_.clear();
    sum_ = 0.0;
    sum_squares_ = 0.0;
    min_value_ = std::numeric_limits<double>::max();
    max_value_ = std::numeric_limits<double>::lowest();
}

size_t StatisticalAccumulator::count() const {
    return samples_.size();
}

double StatisticalAccumulator::mean() const {
    return samples_.empty() ? 0.0 : sum_ / samples_.size();
}

double StatisticalAccumulator::min() const {
    return samples_.empty() ? 0.0 : min_value_;
}

double StatisticalAccumulator::max() const {
    return samples_.empty() ? 0.0 : max_value_;
}

double StatisticalAccumulator::variance() const {
    if (samples_.size() < 2) return 0.0;
    double m = mean();
    return (sum_squares_ - 2 * m * sum_ + samples_.size() * m * m) / (samples_.size() - 1);
}

double StatisticalAccumulator::standard_deviation() const {
    return std::sqrt(variance());
}

double StatisticalAccumulator::percentile(double p) const {
    if (samples_.empty()) return 0.0;
    
    auto sorted_samples = samples_;
    std::sort(sorted_samples.begin(), sorted_samples.end());
    
    double index = p * (sorted_samples.size() - 1);
    size_t lower = static_cast<size_t>(std::floor(index));
    size_t upper = static_cast<size_t>(std::ceil(index));
    
    if (lower == upper) {
        return sorted_samples[lower];
    }
    
    double weight = index - lower;
    return sorted_samples[lower] * (1.0 - weight) + sorted_samples[upper] * weight;
}

std::vector<double> StatisticalAccumulator::get_samples() const {
    return samples_;
}

// ============================================================================
// BenchmarkRunner Implementation
// ============================================================================

class BenchmarkRunner::Impl {
public:
    struct RegisteredBenchmark {
        std::string name;
        BenchmarkFunction benchmark_func;
        SetupFunction setup_func;
        TeardownFunction teardown_func;
    };
    
    BenchmarkConfig config_;
    PRDRequirements prd_requirements_;
    std::vector<RegisteredBenchmark> benchmarks_;
    
    BenchmarkResult run_single_benchmark(const RegisteredBenchmark& benchmark) {
        BenchmarkResult result;
        result.name = benchmark.name;
        result.iterations = config_.iterations;
        result.timestamp = std::chrono::system_clock::now();
        
        StatisticalAccumulator timer_stats;
        ResourceMonitor monitor;
        
        // Setup
        if (benchmark.setup_func) {
            benchmark.setup_func();
        }
        
        // Warmup
        for (size_t i = 0; i < config_.warmup_iterations; ++i) {
            benchmark.benchmark_func();
        }
        
        monitor.start_monitoring();
        
        // Actual benchmark runs
        size_t error_count = 0;
        for (size_t i = 0; i < config_.iterations; ++i) {
            HighResolutionTimer timer;
            
            try {
                timer.start();
                benchmark.benchmark_func();
                timer.stop();
                
                timer_stats.add_sample(timer.elapsed_milliseconds());
            } catch (const std::exception& e) {
                error_count++;
                std::cerr << "Benchmark error in iteration " << i << ": " << e.what() << std::endl;
            }
        }
        
        monitor.stop_monitoring();
        
        // Teardown
        if (benchmark.teardown_func) {
            benchmark.teardown_func();
        }
        
        // Calculate results
        result.mean_time_ms = timer_stats.mean();
        result.min_time_ms = timer_stats.min();
        result.max_time_ms = timer_stats.max();
        result.std_deviation_ms = timer_stats.standard_deviation();
        result.operations_per_second = result.mean_time_ms > 0 ? 1000.0 / result.mean_time_ms : 0.0;
        
        result.peak_memory_bytes = monitor.get_peak_memory_usage();
        result.avg_memory_bytes = monitor.get_average_memory_usage();
        result.peak_cpu_percent = monitor.get_peak_cpu_usage();
        result.avg_cpu_percent = monitor.get_average_cpu_usage();
        
        result.error_count = error_count;
        result.error_rate = static_cast<double>(error_count) / config_.iterations;
        
        // PRD compliance checks
        result.meets_latency_requirement = result.mean_time_ms <= prd_requirements_.max_handshake_latency_ms;
        result.meets_memory_requirement = (result.peak_memory_bytes / (1024 * 1024)) <= prd_requirements_.max_memory_overhead_mb;
        result.meets_cpu_requirement = result.avg_cpu_percent <= prd_requirements_.max_cpu_overhead_percent;
        
        return result;
    }
    
    void save_results_json(const std::vector<BenchmarkResult>& results, const std::string& filename) {
        std::ofstream file(filename);
        file << "{\n";
        file << "  \"timestamp\": \"" << std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() << "\",\n";
        file << "  \"results\": [\n";
        
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& result = results[i];
            file << "    {\n";
            file << "      \"name\": \"" << result.name << "\",\n";
            file << "      \"mean_time_ms\": " << result.mean_time_ms << ",\n";
            file << "      \"min_time_ms\": " << result.min_time_ms << ",\n";
            file << "      \"max_time_ms\": " << result.max_time_ms << ",\n";
            file << "      \"std_deviation_ms\": " << result.std_deviation_ms << ",\n";
            file << "      \"operations_per_second\": " << result.operations_per_second << ",\n";
            file << "      \"peak_memory_bytes\": " << result.peak_memory_bytes << ",\n";
            file << "      \"avg_memory_bytes\": " << result.avg_memory_bytes << ",\n";
            file << "      \"peak_cpu_percent\": " << result.peak_cpu_percent << ",\n";
            file << "      \"avg_cpu_percent\": " << result.avg_cpu_percent << ",\n";
            file << "      \"throughput_mbps\": " << result.throughput_mbps << ",\n";
            file << "      \"error_count\": " << result.error_count << ",\n";
            file << "      \"error_rate\": " << result.error_rate << ",\n";
            file << "      \"meets_latency_requirement\": " << (result.meets_latency_requirement ? "true" : "false") << ",\n";
            file << "      \"meets_throughput_requirement\": " << (result.meets_throughput_requirement ? "true" : "false") << ",\n";
            file << "      \"meets_memory_requirement\": " << (result.meets_memory_requirement ? "true" : "false") << ",\n";
            file << "      \"meets_cpu_requirement\": " << (result.meets_cpu_requirement ? "true" : "false") << "\n";
            file << "    }";
            if (i < results.size() - 1) file << ",";
            file << "\n";
        }
        
        file << "  ]\n";
        file << "}\n";
    }
    
    void generate_text_report(const std::vector<BenchmarkResult>& results, std::ostream& output) {
        output << "DTLS v1.3 Performance Benchmark Report\n";
        output << "======================================\n\n";
        
        output << "Test Configuration:\n";
        output << "  Iterations: " << config_.iterations << "\n";
        output << "  Warmup iterations: " << config_.warmup_iterations << "\n";
        output << "  Thread count: " << config_.thread_count << "\n";
        output << "  Timeout: " << config_.timeout.count() << "ms\n\n";
        
        output << "PRD Requirements:\n";
        output << "  Max handshake latency: " << prd_requirements_.max_handshake_latency_ms << "ms\n";
        output << "  Max additional latency: " << prd_requirements_.max_additional_latency_ms << "ms\n";
        output << "  Min throughput: " << prd_requirements_.min_throughput_percent << "% of UDP\n";
        output << "  Max overhead: " << prd_requirements_.max_overhead_percent << "%\n";
        output << "  Max memory overhead: " << prd_requirements_.max_memory_overhead_mb << "MB\n";
        output << "  Max CPU overhead: " << prd_requirements_.max_cpu_overhead_percent << "%\n\n";
        
        // Summary table
        output << "Benchmark Results:\n";
        output << std::setw(25) << "Test Name" 
               << std::setw(12) << "Mean (ms)"
               << std::setw(12) << "Min (ms)"
               << std::setw(12) << "Max (ms)"
               << std::setw(12) << "Std Dev"
               << std::setw(12) << "Ops/sec"
               << std::setw(10) << "Memory"
               << std::setw(8) << "CPU %"
               << std::setw(10) << "Status" << "\n";
        output << std::string(113, '-') << "\n";
        
        for (const auto& result : results) {
            std::string status = "PASS";
            if (!result.meets_latency_requirement || !result.meets_memory_requirement || 
                !result.meets_cpu_requirement || result.error_rate > 0.01) {
                status = "FAIL";
            }
            
            output << std::setw(25) << result.name
                   << std::setw(12) << std::fixed << std::setprecision(3) << result.mean_time_ms
                   << std::setw(12) << std::fixed << std::setprecision(3) << result.min_time_ms
                   << std::setw(12) << std::fixed << std::setprecision(3) << result.max_time_ms
                   << std::setw(12) << std::fixed << std::setprecision(3) << result.std_deviation_ms
                   << std::setw(12) << std::fixed << std::setprecision(1) << result.operations_per_second
                   << std::setw(10) << (result.peak_memory_bytes / 1024) << "KB"
                   << std::setw(8) << std::fixed << std::setprecision(1) << result.avg_cpu_percent
                   << std::setw(10) << status << "\n";
        }
        
        output << "\nDetailed Analysis:\n";
        for (const auto& result : results) {
            output << "\n" << result.name << ":\n";
            output << "  Performance: " << result.operations_per_second << " ops/sec\n";
            output << "  Memory usage: " << (result.peak_memory_bytes / 1024) << " KB peak, " 
                   << (result.avg_memory_bytes / 1024) << " KB average\n";
            output << "  CPU usage: " << result.peak_cpu_percent << "% peak, " 
                   << result.avg_cpu_percent << "% average\n";
            output << "  Error rate: " << (result.error_rate * 100) << "%\n";
            
            if (result.throughput_mbps > 0) {
                output << "  Throughput: " << result.throughput_mbps << " Mbps\n";
            }
            
            output << "  PRD Compliance:\n";
            output << "    Latency: " << (result.meets_latency_requirement ? "✓" : "✗") << "\n";
            output << "    Memory: " << (result.meets_memory_requirement ? "✓" : "✗") << "\n";
            output << "    CPU: " << (result.meets_cpu_requirement ? "✓" : "✗") << "\n";
        }
    }
};

BenchmarkRunner::BenchmarkRunner(const BenchmarkConfig& config) 
    : pimpl_(std::make_unique<Impl>()) {
    pimpl_->config_ = config;
}

BenchmarkRunner::~BenchmarkRunner() = default;

void BenchmarkRunner::register_benchmark(const std::string& name, 
                                        BenchmarkFunction benchmark_func,
                                        SetupFunction setup_func,
                                        TeardownFunction teardown_func) {
    pimpl_->benchmarks_.push_back({name, benchmark_func, setup_func, teardown_func});
}

std::vector<BenchmarkResult> BenchmarkRunner::run_all_benchmarks() {
    std::vector<BenchmarkResult> results;
    
    for (const auto& benchmark : pimpl_->benchmarks_) {
        std::cout << "Running benchmark: " << benchmark.name << "..." << std::endl;
        auto result = pimpl_->run_single_benchmark(benchmark);
        results.push_back(result);
        std::cout << "  Completed in " << result.mean_time_ms << "ms (avg)" << std::endl;
    }
    
    return results;
}

BenchmarkResult BenchmarkRunner::run_benchmark(const std::string& name) {
    auto it = std::find_if(pimpl_->benchmarks_.begin(), pimpl_->benchmarks_.end(),
                          [&name](const auto& b) { return b.name == name; });
    
    if (it == pimpl_->benchmarks_.end()) {
        throw std::runtime_error("Benchmark not found: " + name);
    }
    
    return pimpl_->run_single_benchmark(*it);
}

void BenchmarkRunner::set_config(const BenchmarkConfig& config) {
    pimpl_->config_ = config;
}

const BenchmarkConfig& BenchmarkRunner::get_config() const {
    return pimpl_->config_;
}

void BenchmarkRunner::set_prd_requirements(const PRDRequirements& requirements) {
    pimpl_->prd_requirements_ = requirements;
}

const PRDRequirements& BenchmarkRunner::get_prd_requirements() const {
    return pimpl_->prd_requirements_;
}

void BenchmarkRunner::save_results(const std::vector<BenchmarkResult>& results, 
                                  const std::string& filename) {
    pimpl_->save_results_json(results, filename);
}

void BenchmarkRunner::generate_report(const std::vector<BenchmarkResult>& results,
                                     std::ostream& output) {
    pimpl_->generate_text_report(results, output);
}

void BenchmarkRunner::generate_json_report(const std::vector<BenchmarkResult>& results,
                                          const std::string& filename) {
    pimpl_->save_results_json(results, filename);
}

void BenchmarkRunner::generate_csv_report(const std::vector<BenchmarkResult>& results,
                                         const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open CSV file for writing: " + filename);
    }
    
    // CSV header
    file << "Name,Iterations,MeanTime(ms),MinTime(ms),MaxTime(ms),StdDev(ms),"
         << "OpsPerSec,PeakMemory(KB),AvgCPU(%),ThroughputMbps,ErrorRate(%),Status\n";
    
    // CSV data rows
    for (const auto& result : results) {
        std::string status = "PASS";
        if (!result.meets_latency_requirement) status = "FAIL_LATENCY";
        else if (!result.meets_memory_requirement) status = "FAIL_MEMORY";
        else if (!result.meets_cpu_requirement) status = "FAIL_CPU";
        else if (result.error_rate >= 0.01) status = "FAIL_ERRORS";
        
        file << result.name << ","
             << result.iterations << ","
             << std::fixed << std::setprecision(3) << result.mean_time_ms << ","
             << std::fixed << std::setprecision(3) << result.min_time_ms << ","
             << std::fixed << std::setprecision(3) << result.max_time_ms << ","
             << std::fixed << std::setprecision(3) << result.std_deviation_ms << ","
             << std::fixed << std::setprecision(1) << result.operations_per_second << ","
             << (result.peak_memory_bytes / 1024) << ","
             << std::fixed << std::setprecision(1) << result.avg_cpu_percent << ","
             << std::fixed << std::setprecision(2) << result.throughput_mbps << ","
             << std::fixed << std::setprecision(2) << (result.error_rate * 100) << ","
             << status << "\n";
    }
    
    file.close();
}

// ============================================================================
// Utility Functions Implementation
// ============================================================================

bool validate_prd_compliance(const BenchmarkResult& result, 
                            const PRDRequirements& requirements) {
    return result.meets_latency_requirement && 
           result.meets_throughput_requirement && 
           result.meets_memory_requirement && 
           result.meets_cpu_requirement &&
           result.error_rate < 0.01; // Less than 1% error rate
}

std::string generate_prd_compliance_report(const std::vector<BenchmarkResult>& results,
                                          const PRDRequirements& requirements) {
    std::ostringstream report;
    
    report << "PRD Compliance Report\n";
    report << "====================\n\n";
    
    size_t total_tests = results.size();
    size_t compliant_tests = 0;
    
    for (const auto& result : results) {
        if (validate_prd_compliance(result, requirements)) {
            compliant_tests++;
        }
    }
    
    double compliance_rate = total_tests > 0 ? 
        static_cast<double>(compliant_tests) / total_tests * 100.0 : 0.0;
    
    report << "Overall Compliance: " << compliance_rate << "% (" 
           << compliant_tests << "/" << total_tests << " tests)\n\n";
    
    report << "Detailed Results:\n";
    for (const auto& result : results) {
        bool compliant = validate_prd_compliance(result, requirements);
        report << "  " << (compliant ? "✓" : "✗") << " " << result.name << "\n";
        
        if (!compliant) {
            if (!result.meets_latency_requirement) {
                report << "    - Latency: " << result.mean_time_ms << "ms > " 
                       << requirements.max_handshake_latency_ms << "ms\n";
            }
            if (!result.meets_memory_requirement) {
                report << "    - Memory: " << (result.peak_memory_bytes / (1024*1024)) 
                       << "MB > " << requirements.max_memory_overhead_mb << "MB\n";
            }
            if (!result.meets_cpu_requirement) {
                report << "    - CPU: " << result.avg_cpu_percent << "% > " 
                       << requirements.max_cpu_overhead_percent << "%\n";
            }
            if (result.error_rate >= 0.01) {
                report << "    - Error rate: " << (result.error_rate * 100) << "% >= 1%\n";
            }
        }
    }
    
    return report.str();
}

std::vector<uint8_t> generate_test_data(size_t size, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    std::vector<uint8_t> data;
    data.reserve(size);
    
    for (size_t i = 0; i < size; ++i) {
        data.push_back(dist(rng));
    }
    
    return data;
}

std::vector<uint8_t> generate_compressible_data(size_t size) {
    std::vector<uint8_t> data;
    data.reserve(size);
    
    // Generate repeating pattern that compresses well
    const std::string pattern = "DTLS v1.3 performance test data pattern ";
    
    for (size_t i = 0; i < size; ++i) {
        data.push_back(static_cast<uint8_t>(pattern[i % pattern.length()]));
    }
    
    return data;
}

std::vector<uint8_t> generate_random_data(size_t size) {
    return generate_test_data(size, std::random_device{}());
}

// ============================================================================
// Platform-specific implementations
// ============================================================================

namespace platform {

uint64_t get_cpu_cycles() {
#if defined(__x86_64__) || defined(_M_X64)
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0; // Fallback for other architectures
#endif
}

uint64_t get_cpu_frequency() {
    // Simplified implementation - should be platform-specific
    return 2400000000ULL; // Assume 2.4 GHz
}

size_t get_memory_usage() {
#ifdef __linux__
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("VmRSS:") == 0) {
            std::istringstream iss(line);
            std::string label;
            size_t value;
            std::string unit;
            iss >> label >> value >> unit;
            return value * 1024; // Convert KB to bytes
        }
    }
#endif
    return 0;
}

double get_cpu_utilization() {
    // Simplified implementation - should be platform-specific
    return 0.0;
}

bool is_high_resolution_timer_available() {
    return std::chrono::high_resolution_clock::is_steady;
}

} // namespace platform

} // namespace dtls::v13::test::performance