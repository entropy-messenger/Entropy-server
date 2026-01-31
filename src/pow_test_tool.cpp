#include <iostream>
#include <string>
#include <vector>
#include "pow_verifier.hpp"
#include "metrics.hpp"

using namespace entropy;

int main() {
    std::string seed = "81389656184919022713835084918237"; // Example 32-char seed
    std::string context = "nickname_registration:moyzy";
    int difficulty = 5;

    std::cout << "[*] Starting PoW Solver..." << std::endl;
    std::cout << "[*] Seed: " << seed << std::endl;
    std::cout << "[*] Context: " << context << std::endl;
    std::cout << "[*] Difficulty: " << difficulty << " (leading hex zeros)" << std::endl;

    std::string found_nonce = "";
    uint64_t attempts = 0;
    auto start = std::chrono::steady_clock::now();

    for (uint64_t i = 0; i < 10000000; ++i) {
        attempts++;
        std::string nonce = std::to_string(i);
        if (PoWVerifier::verify(seed, nonce, context, difficulty)) {
            found_nonce = nonce;
            break;
        }
    }

    auto end = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (!found_nonce.empty()) {
        std::cout << "[+] SUCCESS! Found nonce: " << found_nonce << std::endl;
        std::cout << "[+] Verification of found nonce: " << (PoWVerifier::verify(seed, found_nonce, context, difficulty) ? "PASSED" : "FAILED") << std::endl;
    } else {
        std::cout << "[-] FAILED to find nonce within 10M attempts." << std::endl;
    }

    std::cout << "[*] Total attempts: " << attempts << std::endl;
    std::cout << "[*] Time taken: " << diff << "ms" << std::endl;
    if (diff > 0) {
        std::cout << "[*] Hash rate: " << (attempts * 1000 / diff) << " H/s" << std::endl;
    }

    return 0;
}
