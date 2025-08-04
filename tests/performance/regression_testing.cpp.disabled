/*
 * DTLS v1.3 Performance Regression Testing Framework
 * Task 10: Performance Benchmarking - Regression Detection and Baseline Management
 */

#include "benchmark_framework.h"
#include "handshake_benchmarks.cpp"
#include "throughput_benchmarks.cpp"
#include "resource_benchmarks.cpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <map>
#include <cmath>

namespace dtls::v13::test::performance {

// ============================================================================
// Performance Baseline Management
// ============================================================================

class PerformanceBaseline {
public:
    struct BaselineEntry {
        std::string test_name;
        double mean_time_ms;
        double throughput_mbps;
        size_t peak_memory_bytes;
        double avg_cpu_percent;
        std::chrono::system_clock::time_point timestamp;
        std::string git_commit_hash;
        std::string build_config;
        std::map<std::string, double> custom_metrics;
        
        // Statistical data for trend analysis
        double std_deviation_ms;
        double confidence_interval_95;
        size_t sample_count;
    };
    
    explicit PerformanceBaseline(const std::string& baseline_file = "performance_baseline.json")
        : baseline_file_(baseline_file) {
        load_baseline();
    }
    
    void add_baseline_entry(const BenchmarkResult& result, const std::string& git_commit = "", 
                           const std::string& build_config = "Release") {
        BaselineEntry entry;
        entry.test_name = result.name;
        entry.mean_time_ms = result.mean_time_ms;
        entry.throughput_mbps = result.throughput_mbps;
        entry.peak_memory_bytes = result.peak_memory_bytes;
        entry.avg_cpu_percent = result.avg_cpu_percent;
        entry.timestamp = result.timestamp;
        entry.git_commit_hash = git_commit;
        entry.build_config = build_config;
        entry.custom_metrics = result.custom_metrics;
        entry.std_deviation_ms = result.std_deviation_ms;
        entry.sample_count = 1; // From single benchmark run
        
        // Calculate 95% confidence interval
        entry.confidence_interval_95 = calculate_confidence_interval(result.mean_time_ms, 
                                                                    result.std_deviation_ms, 
                                                                    entry.sample_count);
        
        baseline_entries_[result.name].push_back(entry);
        
        // Keep only last N entries for trend analysis
        const size_t max_entries = 100;
        if (baseline_entries_[result.name].size() > max_entries) {
            baseline_entries_[result.name].erase(baseline_entries_[result.name].begin());
        }
    }
    
    BaselineEntry get_latest_baseline(const std::string& test_name) const {
        auto it = baseline_entries_.find(test_name);
        if (it != baseline_entries_.end() && !it->second.empty()) {
            return it->second.back();
        }
        throw std::runtime_error("No baseline found for test: " + test_name);
    }
    
    std::vector<BaselineEntry> get_baseline_history(const std::string& test_name, size_t count = 10) const {
        auto it = baseline_entries_.find(test_name);
        if (it != baseline_entries_.end()) {
            const auto& entries = it->second;
            size_t start = entries.size() > count ? entries.size() - count : 0;
            return std::vector<BaselineEntry>(entries.begin() + start, entries.end());
        }
        return {};
    }
    
    void save_baseline() const {
        std::ofstream file(baseline_file_);
        file << "{\n";
        file << "  \"baseline_version\": \"1.0\",\n";
        file << "  \"generated_timestamp\": \"" << std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() << "\",\n";
        file << "  \"baselines\": {\n";
        
        bool first_test = true;
        for (const auto& [test_name, entries] : baseline_entries_) {
            if (!first_test) file << ",\n";
            first_test = false;
            
            file << "    \"" << test_name << "\": [\n";
            
            bool first_entry = true;
            for (const auto& entry : entries) {
                if (!first_entry) file << ",\n";
                first_entry = false;
                
                file << "      {\n";
                file << "        \"mean_time_ms\": " << entry.mean_time_ms << ",\n";
                file << "        \"throughput_mbps\": " << entry.throughput_mbps << ",\n";
                file << "        \"peak_memory_bytes\": " << entry.peak_memory_bytes << ",\n";
                file << "        \"avg_cpu_percent\": " << entry.avg_cpu_percent << ",\n";
                file << "        \"timestamp\": " << std::chrono::duration_cast<std::chrono::seconds>(
                    entry.timestamp.time_since_epoch()).count() << ",\n";
                file << "        \"git_commit_hash\": \"" << entry.git_commit_hash << "\",\n";
                file << "        \"build_config\": \"" << entry.build_config << "\",\n";
                file << "        \"std_deviation_ms\": " << entry.std_deviation_ms << ",\n";
                file << "        \"confidence_interval_95\": " << entry.confidence_interval_95 << ",\n";
                file << "        \"sample_count\": " << entry.sample_count;
                
                if (!entry.custom_metrics.empty()) {
                    file << ",\n        \"custom_metrics\": {\n";
                    bool first_metric = true;
                    for (const auto& [key, value] : entry.custom_metrics) {
                        if (!first_metric) file << ",\n";
                        first_metric = false;
                        file << "          \"" << key << "\": " << value;
                    }
                    file << "\n        }";
                }
                
                file << "\n      }";
            }
            
            file << "\n    ]";
        }
        
        file << "\n  }\n";
        file << "}\n";
    }
    
    void load_baseline() {
        if (!std::filesystem::exists(baseline_file_)) {
            return; // No baseline file exists yet
        }
        
        // Simplified JSON parsing for baseline data
        // In a production system, use a proper JSON library
        std::ifstream file(baseline_file_);
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        
        // Basic parsing - would use proper JSON library in production
        parse_baseline_json(content);
    }
    
private:
    std::string baseline_file_;
    std::map<std::string, std::vector<BaselineEntry>> baseline_entries_;
    
    double calculate_confidence_interval(double mean, double std_dev, size_t sample_count) const {
        // Simplified 95% confidence interval calculation
        // t-value for 95% confidence (approximation for large samples)
        double t_value = 1.96;
        if (sample_count < 30) {
            // Use t-distribution for small samples (simplified lookup)
            std::map<size_t, double> t_table = {
                {1, 12.71}, {2, 4.30}, {3, 3.18}, {4, 2.78}, {5, 2.57},
                {10, 2.23}, {15, 2.13}, {20, 2.09}, {25, 2.06}, {30, 2.04}
            };
            
            auto it = t_table.lower_bound(sample_count);
            if (it != t_table.end()) {
                t_value = it->second;
            }
        }
        
        return t_value * (std_dev / std::sqrt(static_cast<double>(sample_count)));
    }
    
    void parse_baseline_json(const std::string& content) {
        // Simplified JSON parsing - would use proper JSON library in production
        // This is a basic implementation for demonstration
        baseline_entries_.clear();
    }
};

// ============================================================================
// Regression Detection Engine
// ============================================================================

class RegressionDetector {
public:
    struct RegressionAlert {
        std::string test_name;
        std::string metric_name;
        double current_value;
        double baseline_value;
        double change_percent;
        double significance_level;
        std::string severity; // "CRITICAL", "WARNING", "INFO"
        std::string description;
        std::chrono::system_clock::time_point detected_at;
    };
    
    struct RegressionConfig {
        double critical_threshold = 10.0;  // 10% degradation = critical
        double warning_threshold = 5.0;    // 5% degradation = warning
        double improvement_threshold = -5.0; // 5% improvement = notable
        size_t trend_window = 5;            // Look at last 5 measurements for trends
        double confidence_level = 0.95;    // 95% confidence for statistical tests
        bool enable_trend_analysis = true;
        bool enable_statistical_tests = true;
    };
    
    explicit RegressionDetector(const RegressionConfig& config = RegressionConfig{})
        : config_(config) {}
    
    std::vector<RegressionAlert> detect_regressions(const std::vector<BenchmarkResult>& current_results,
                                                   const PerformanceBaseline& baseline) {
        std::vector<RegressionAlert> alerts;
        
        for (const auto& result : current_results) {
            try {
                auto baseline_entry = baseline.get_latest_baseline(result.name);
                auto test_alerts = analyze_single_test(result, baseline_entry, baseline);
                alerts.insert(alerts.end(), test_alerts.begin(), test_alerts.end());
            } catch (const std::exception& e) {
                // No baseline available for this test
                RegressionAlert alert;
                alert.test_name = result.name;
                alert.metric_name = "baseline";
                alert.severity = "INFO";
                alert.description = "No baseline available for comparison";
                alert.detected_at = std::chrono::system_clock::now();
                alerts.push_back(alert);
            }
        }
        
        return alerts;
    }
    
    std::vector<RegressionAlert> detect_trend_regressions(const PerformanceBaseline& baseline) {
        std::vector<RegressionAlert> alerts;
        
        // Analyze trends for each test that has sufficient history
        for (const auto& test_name : get_all_test_names(baseline)) {
            auto history = baseline.get_baseline_history(test_name, config_.trend_window * 2);
            if (history.size() >= config_.trend_window) {
                auto trend_alerts = analyze_performance_trends(test_name, history);
                alerts.insert(alerts.end(), trend_alerts.begin(), trend_alerts.end());
            }
        }
        
        return alerts;
    }
    
    void generate_regression_report(const std::vector<RegressionAlert>& alerts, std::ostream& output) {
        output << "Performance Regression Analysis Report\n";
        output << "=====================================\n\n";
        
        // Summary statistics
        size_t critical_count = std::count_if(alerts.begin(), alerts.end(),
            [](const RegressionAlert& alert) { return alert.severity == "CRITICAL"; });
        size_t warning_count = std::count_if(alerts.begin(), alerts.end(),
            [](const RegressionAlert& alert) { return alert.severity == "WARNING"; });
        size_t info_count = std::count_if(alerts.begin(), alerts.end(),
            [](const RegressionAlert& alert) { return alert.severity == "INFO"; });
        
        output << "Summary:\n";
        output << "  Critical regressions: " << critical_count << "\n";
        output << "  Warning regressions: " << warning_count << "\n";
        output << "  Informational alerts: " << info_count << "\n";
        output << "  Total alerts: " << alerts.size() << "\n\n";
        
        // Detailed alerts
        if (critical_count > 0) {
            output << "CRITICAL REGRESSIONS:\n";
            output << "====================\n";
            for (const auto& alert : alerts) {
                if (alert.severity == "CRITICAL") {
                    output << "🚨 " << alert.test_name << " - " << alert.metric_name << "\n";
                    output << "   Current: " << alert.current_value;
                    output << ", Baseline: " << alert.baseline_value;
                    output << ", Change: " << alert.change_percent << "%\n";
                    output << "   " << alert.description << "\n\n";
                }
            }
        }
        
        if (warning_count > 0) {
            output << "WARNING REGRESSIONS:\n";
            output << "===================\n";
            for (const auto& alert : alerts) {
                if (alert.severity == "WARNING") {
                    output << "⚠️  " << alert.test_name << " - " << alert.metric_name << "\n";
                    output << "   Current: " << alert.current_value;
                    output << ", Baseline: " << alert.baseline_value;
                    output << ", Change: " << alert.change_percent << "%\n";
                    output << "   " << alert.description << "\n\n";
                }
            }
        }
        
        // Performance improvements (positive news)
        auto improvements = std::count_if(alerts.begin(), alerts.end(),
            [](const RegressionAlert& alert) { 
                return alert.change_percent < -5.0; // 5% improvement
            });
        
        if (improvements > 0) {
            output << "PERFORMANCE IMPROVEMENTS:\n";
            output << "========================\n";
            for (const auto& alert : alerts) {
                if (alert.change_percent < -5.0) {
                    output << "✅ " << alert.test_name << " - " << alert.metric_name << "\n";
                    output << "   Improvement: " << std::abs(alert.change_percent) << "%\n";
                    output << "   " << alert.description << "\n\n";
                }
            }
        }
    }
    
private:
    RegressionConfig config_;
    
    std::vector<RegressionAlert> analyze_single_test(const BenchmarkResult& current,
                                                    const PerformanceBaseline::BaselineEntry& baseline,
                                                    const PerformanceBaseline& full_baseline) {
        std::vector<RegressionAlert> alerts;
        
        // Analyze latency regression
        if (current.mean_time_ms > 0 && baseline.mean_time_ms > 0) {
            double latency_change = calculate_change_percent(current.mean_time_ms, baseline.mean_time_ms);
            if (std::abs(latency_change) > config_.warning_threshold) {
                RegressionAlert alert;
                alert.test_name = current.name;
                alert.metric_name = "latency";
                alert.current_value = current.mean_time_ms;
                alert.baseline_value = baseline.mean_time_ms;
                alert.change_percent = latency_change;
                alert.detected_at = std::chrono::system_clock::now();
                
                if (latency_change > config_.critical_threshold) {
                    alert.severity = "CRITICAL";
                    alert.description = "Critical latency regression detected";
                } else if (latency_change > config_.warning_threshold) {
                    alert.severity = "WARNING";
                    alert.description = "Latency regression detected";
                } else {
                    alert.severity = "INFO";
                    alert.description = "Latency improvement detected";
                }
                
                alerts.push_back(alert);
            }
        }
        
        // Analyze throughput regression
        if (current.throughput_mbps > 0 && baseline.throughput_mbps > 0) {
            // For throughput, decrease is bad (negative change is regression)
            double throughput_change = calculate_change_percent(current.throughput_mbps, baseline.throughput_mbps);
            if (throughput_change < -config_.warning_threshold) {
                RegressionAlert alert;
                alert.test_name = current.name;
                alert.metric_name = "throughput";
                alert.current_value = current.throughput_mbps;
                alert.baseline_value = baseline.throughput_mbps;
                alert.change_percent = throughput_change;
                alert.detected_at = std::chrono::system_clock::now();
                
                if (throughput_change < -config_.critical_threshold) {
                    alert.severity = "CRITICAL";
                    alert.description = "Critical throughput regression detected";
                } else {
                    alert.severity = "WARNING";
                    alert.description = "Throughput regression detected";
                }
                
                alerts.push_back(alert);
            }
        }
        
        // Analyze memory regression
        if (current.peak_memory_bytes > 0 && baseline.peak_memory_bytes > 0) {
            double memory_change = calculate_change_percent(current.peak_memory_bytes, baseline.peak_memory_bytes);
            if (memory_change > config_.warning_threshold) {
                RegressionAlert alert;
                alert.test_name = current.name;
                alert.metric_name = "memory";
                alert.current_value = static_cast<double>(current.peak_memory_bytes);
                alert.baseline_value = static_cast<double>(baseline.peak_memory_bytes);
                alert.change_percent = memory_change;
                alert.detected_at = std::chrono::system_clock::now();
                
                if (memory_change > config_.critical_threshold) {
                    alert.severity = "CRITICAL";
                    alert.description = "Critical memory usage regression detected";
                } else {
                    alert.severity = "WARNING";
                    alert.description = "Memory usage regression detected";
                }
                
                alerts.push_back(alert);
            }
        }
        
        // Analyze CPU regression
        if (current.avg_cpu_percent > 0 && baseline.avg_cpu_percent > 0) {
            double cpu_change = calculate_change_percent(current.avg_cpu_percent, baseline.avg_cpu_percent);
            if (cpu_change > config_.warning_threshold) {
                RegressionAlert alert;
                alert.test_name = current.name;
                alert.metric_name = "cpu";
                alert.current_value = current.avg_cpu_percent;
                alert.baseline_value = baseline.avg_cpu_percent;
                alert.change_percent = cpu_change;
                alert.detected_at = std::chrono::system_clock::now();
                
                if (cpu_change > config_.critical_threshold) {
                    alert.severity = "CRITICAL";
                    alert.description = "Critical CPU usage regression detected";
                } else {
                    alert.severity = "WARNING";
                    alert.description = "CPU usage regression detected";
                }
                
                alerts.push_back(alert);
            }
        }
        
        return alerts;
    }
    
    std::vector<RegressionAlert> analyze_performance_trends(const std::string& test_name,
                                                           const std::vector<PerformanceBaseline::BaselineEntry>& history) {
        std::vector<RegressionAlert> alerts;
        
        if (history.size() < config_.trend_window) {
            return alerts;
        }
        
        // Analyze latency trend
        std::vector<double> latency_trend;
        for (const auto& entry : history) {
            latency_trend.push_back(entry.mean_time_ms);
        }
        
        double latency_slope = calculate_trend_slope(latency_trend);
        if (std::abs(latency_slope) > 0.1) { // More than 0.1ms increase per measurement
            RegressionAlert alert;
            alert.test_name = test_name;
            alert.metric_name = "latency_trend";
            alert.current_value = latency_trend.back();
            alert.baseline_value = latency_trend.front();
            alert.change_percent = calculate_change_percent(latency_trend.back(), latency_trend.front());
            alert.detected_at = std::chrono::system_clock::now();
            
            if (latency_slope > 0.5) {
                alert.severity = "CRITICAL";
                alert.description = "Critical latency degradation trend detected";
            } else if (latency_slope > 0.2) {
                alert.severity = "WARNING";
                alert.description = "Latency degradation trend detected";
            } else {
                alert.severity = "INFO";
                alert.description = "Latency improvement trend detected";
            }
            
            alerts.push_back(alert);
        }
        
        return alerts;
    }
    
    double calculate_change_percent(double current, double baseline) const {
        if (baseline == 0.0) return 0.0;
        return ((current - baseline) / baseline) * 100.0;
    }
    
    double calculate_trend_slope(const std::vector<double>& values) const {
        if (values.size() < 2) return 0.0;
        
        // Simple linear regression slope calculation
        double n = static_cast<double>(values.size());
        double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0;
        
        for (size_t i = 0; i < values.size(); ++i) {
            double x = static_cast<double>(i);
            double y = values[i];
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }
        
        double slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        return slope;
    }
    
    std::vector<std::string> get_all_test_names(const PerformanceBaseline& baseline) const {
        // Would extract test names from baseline in real implementation
        return {};
    }
};

// ============================================================================
// Comprehensive Regression Testing Framework
// ============================================================================

class PerformanceRegressionTester {
public:
    explicit PerformanceRegressionTester(const std::string& baseline_file = "performance_baseline.json")
        : baseline_(baseline_file), detector_() {}
    
    void run_full_regression_test(const std::string& git_commit = "", 
                                 const std::string& build_config = "Release") {
        std::cout << "Running comprehensive performance regression test..." << std::endl;
        
        // Configure for regression testing (fewer iterations for speed)
        BenchmarkConfig config;
        config.iterations = 100;  // Reduced for faster regression testing
        config.warmup_iterations = 20;
        
        // Run all benchmark suites
        std::vector<BenchmarkResult> all_results;
        
        // Handshake benchmarks
        std::cout << "Running handshake regression tests..." << std::endl;
        HandshakePerformanceTestSuite handshake_suite(config);
        auto handshake_results = handshake_suite.run_all_handshake_benchmarks();
        all_results.insert(all_results.end(), handshake_results.begin(), handshake_results.end());
        
        // Throughput benchmarks
        std::cout << "Running throughput regression tests..." << std::endl;
        ThroughputPerformanceTestSuite throughput_suite(config);
        auto throughput_results = throughput_suite.run_all_throughput_benchmarks();
        all_results.insert(all_results.end(), throughput_results.begin(), throughput_results.end());
        
        // Resource benchmarks
        std::cout << "Running resource regression tests..." << std::endl;
        ResourcePerformanceTestSuite resource_suite(config);
        auto resource_results = resource_suite.run_all_resource_benchmarks();
        all_results.insert(all_results.end(), resource_results.begin(), resource_results.end());
        
        // Detect regressions
        std::cout << "Analyzing results for regressions..." << std::endl;
        auto alerts = detector_.detect_regressions(all_results, baseline_);
        auto trend_alerts = detector_.detect_trend_regressions(baseline_);
        alerts.insert(alerts.end(), trend_alerts.begin(), trend_alerts.end());
        
        // Generate reports
        generate_regression_report(alerts, all_results);
        
        // Update baseline with current results
        for (const auto& result : all_results) {
            baseline_.add_baseline_entry(result, git_commit, build_config);
        }
        baseline_.save_baseline();
        
        std::cout << "Regression test completed. Check performance_regression_report.txt for details." << std::endl;
    }
    
    void generate_regression_report(const std::vector<RegressionDetector::RegressionAlert>& alerts,
                                   const std::vector<BenchmarkResult>& results) {
        // Generate text report
        std::ofstream report_file("performance_regression_report.txt");
        detector_.generate_regression_report(alerts, report_file);
        
        // Add summary statistics
        report_file << "\n\nPerformance Test Results Summary\n";
        report_file << "===============================\n\n";
        
        // Basic statistics
        if (!results.empty()) {
            double avg_latency = 0.0;
            double avg_throughput = 0.0;
            size_t avg_memory = 0;
            size_t latency_count = 0, throughput_count = 0, memory_count = 0;
            
            for (const auto& result : results) {
                if (result.mean_time_ms > 0) {
                    avg_latency += result.mean_time_ms;
                    latency_count++;
                }
                if (result.throughput_mbps > 0) {
                    avg_throughput += result.throughput_mbps;
                    throughput_count++;
                }
                if (result.peak_memory_bytes > 0) {
                    avg_memory += result.peak_memory_bytes;
                    memory_count++;
                }
            }
            
            if (latency_count > 0) avg_latency /= latency_count;
            if (throughput_count > 0) avg_throughput /= throughput_count;
            if (memory_count > 0) avg_memory /= memory_count;
            
            report_file << "Average Latency: " << avg_latency << " ms\n";
            report_file << "Average Throughput: " << avg_throughput << " Mbps\n";
            report_file << "Average Memory Usage: " << (avg_memory / 1024) << " KB\n";
        }
        
        // PRD compliance summary
        size_t compliant_tests = std::count_if(results.begin(), results.end(),
            [](const BenchmarkResult& result) {
                return result.meets_latency_requirement && 
                       result.meets_throughput_requirement && 
                       result.meets_memory_requirement &&
                       result.meets_cpu_requirement;
            });
        
        double compliance_rate = results.empty() ? 0.0 : 
            static_cast<double>(compliant_tests) / results.size() * 100.0;
        
        report_file << "\nPRD Compliance Rate: " << compliance_rate << "% (" 
                   << compliant_tests << "/" << results.size() << " tests)\n";
        
        report_file.close();
        
        // Generate JSON report for automated processing
        generate_json_regression_report(alerts, results);
    }
    
    void generate_json_regression_report(const std::vector<RegressionDetector::RegressionAlert>& alerts,
                                        const std::vector<BenchmarkResult>& results) {
        std::ofstream json_file("performance_regression_report.json");
        
        json_file << "{\n";
        json_file << "  \"timestamp\": \"" << std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() << "\",\n";
        json_file << "  \"regression_summary\": {\n";
        
        size_t critical_count = std::count_if(alerts.begin(), alerts.end(),
            [](const RegressionDetector::RegressionAlert& alert) { return alert.severity == "CRITICAL"; });
        size_t warning_count = std::count_if(alerts.begin(), alerts.end(),
            [](const RegressionDetector::RegressionAlert& alert) { return alert.severity == "WARNING"; });
        
        json_file << "    \"critical_regressions\": " << critical_count << ",\n";
        json_file << "    \"warning_regressions\": " << warning_count << ",\n";
        json_file << "    \"total_alerts\": " << alerts.size() << ",\n";
        json_file << "    \"total_tests\": " << results.size() << "\n";
        json_file << "  },\n";
        
        json_file << "  \"alerts\": [\n";
        for (size_t i = 0; i < alerts.size(); ++i) {
            const auto& alert = alerts[i];
            json_file << "    {\n";
            json_file << "      \"test_name\": \"" << alert.test_name << "\",\n";
            json_file << "      \"metric\": \"" << alert.metric_name << "\",\n";
            json_file << "      \"severity\": \"" << alert.severity << "\",\n";
            json_file << "      \"current_value\": " << alert.current_value << ",\n";
            json_file << "      \"baseline_value\": " << alert.baseline_value << ",\n";
            json_file << "      \"change_percent\": " << alert.change_percent << ",\n";
            json_file << "      \"description\": \"" << alert.description << "\"\n";
            json_file << "    }";
            if (i < alerts.size() - 1) json_file << ",";
            json_file << "\n";
        }
        json_file << "  ]\n";
        json_file << "}\n";
        
        json_file.close();
    }
    
private:
    PerformanceBaseline baseline_;
    RegressionDetector detector_;
};

} // namespace dtls::v13::test::performance