#pragma once

#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <sstream>

namespace entropy {

 
// Singleton Metrics Registry for operational visibility.
// Provides thread-safe counters and gauges that can be exported in Prometheus format.
class MetricsRegistry {
public:
    /**
     * Access the global instance of the metrics registry.
     */
    static MetricsRegistry& instance() {
        static MetricsRegistry instance;
        return instance;
    }

    // Increment a cumulative counter (Only increases).
    void increment_counter(const std::string& name, double value = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        counters_[name] += value;
    }

    // Sets a gauge to a specific instantaneous value.
    void set_gauge(const std::string& name, double value) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] = value;
    }
    
    // Adjusts a gauge by a specific offset.
    void increment_gauge(const std::string& name, double value = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] += value;
    }
    
    void decrement_gauge(const std::string& name, double value = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] -= value;
    }

    // Retrieves current value of a gauge.
    double get_gauge(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = gauges_.find(name);
        return (it != gauges_.end()) ? it->second : 0.0;
    }

    /**
     * Serializes all recorded metrics into Prometheus exposition format (text version 0.0.4).
     */
    std::string collect_prometheus() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::stringstream ss;
        
        for (const auto& [name, val] : counters_) {
            ss << "# TYPE " << name << " counter\n";
            ss << name << " " << val << "\n";
        }
        
        for (const auto& [name, val] : gauges_) {
            ss << "# TYPE " << name << " gauge\n";
            ss << name << " " << val << "\n";
        }
        
        return ss.str();
    }

private:
    MetricsRegistry() = default;
    
    std::map<std::string, double> counters_;
    std::map<std::string, double> gauges_;
    std::mutex mutex_; // Ensures consistency across high-concurrency threads
};

} 
