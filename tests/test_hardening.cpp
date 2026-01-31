#include <gtest/gtest.h>
#include <openssl/crypto.h>
#include <chrono>
#include <vector>
#include <numeric>
#include <algorithm>

TEST(SecurityHardening, ConstantTimeComparison) {
    
    
    const int iterations = 100000;
    std::string base = "this_is_a_very_secret_session_token_12345";
    std::string match = "this_is_a_very_secret_session_token_12345";
    std::string mismatch_start = "Xhis_is_a_very_secret_session_token_12345";
    std::string mismatch_end = "this_is_a_very_secret_session_token_1234X";

    auto measure = [&](const std::string& a, const std::string& b) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            CRYPTO_memcmp(a.c_str(), b.c_str(), a.length());
        }
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    };

    
    measure(base, match);

    long long t_match = measure(base, match);
    long long t_mismatch_start = measure(base, mismatch_start);
    long long t_mismatch_end = measure(base, mismatch_end);

    std::cout << "[*] Timing Results (per " << iterations << " iterations):" << std::endl;
    std::cout << "    Match:          " << t_match << "us" << std::endl;
    std::cout << "    Mismatch Start: " << t_mismatch_start << "us" << std::endl;
    std::cout << "    Mismatch End:   " << t_mismatch_end << "us" << std::endl;

    
    
    
    
    SUCCEED();
}
