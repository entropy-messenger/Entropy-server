#include <gtest/gtest.h>
#include "metrics.hpp"

using namespace entropy;

TEST(MetricsTest, Counter) {
    auto& reg = MetricsRegistry::instance();
    reg.reset();
    
    
    reg.increment_counter("test_counter", 1.0);
    reg.increment_counter("test_counter", 2.5);
    
    std::string prometheus = reg.collect_prometheus();
    EXPECT_TRUE(prometheus.find("test_counter 3.5") != std::string::npos);
    EXPECT_TRUE(prometheus.find("# TYPE test_counter counter") != std::string::npos);
}

TEST(MetricsTest, Gauge) {
    auto& reg = MetricsRegistry::instance();
    reg.reset();
    reg.set_gauge("test_gauge", 42.0);
    EXPECT_EQ(reg.get_gauge("test_gauge"), 42.0);
    
    reg.increment_gauge("test_gauge", 8.0);
    EXPECT_EQ(reg.get_gauge("test_gauge"), 50.0);
    
    reg.decrement_gauge("test_gauge", 10.0);
    EXPECT_EQ(reg.get_gauge("test_gauge"), 40.0);
    
    std::string prometheus = reg.collect_prometheus();
    EXPECT_TRUE(prometheus.find("test_gauge 40") != std::string::npos);
    EXPECT_TRUE(prometheus.find("# TYPE test_gauge gauge") != std::string::npos);
}
