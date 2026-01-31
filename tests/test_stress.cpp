#include <gtest/gtest.h>
#include "connection_manager.hpp"
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

using namespace entropy;

TEST(StressTest, ConnectionManagerHighConcurrency) {
    ConnectionManager cm("stress_salt");
    const int num_threads = 8;
    const int conns_per_thread = 1000;
    std::atomic<int> success_count{0};
    
    auto worker = [&](int thread_id) {
        for (int i = 0; i < conns_per_thread; ++i) {
            std::string id = "user_" + std::to_string(thread_id) + "_" + std::to_string(i);
            
            
            
            
            if (!cm.blind_id(id).empty()) {
                success_count++;
            }
        }
    };
    
    std::vector<std::thread> threads;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, i);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    std::chrono::duration<double> diff = end - start;
    std::cout << "[*] Processed " << success_count << " blindings in " << diff.count() << "s" << std::endl;
    std::cout << "[*] Throughput: " << (success_count / diff.count()) << " ops/sec" << std::endl;
    
    EXPECT_EQ(success_count, num_threads * conns_per_thread);
}
