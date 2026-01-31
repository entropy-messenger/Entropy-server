#pragma once

#include <string>
#include <cctype>
#include <algorithm>
#include <vector>
#include <boost/json.hpp>
#include <openssl/evp.h>

namespace entropy {

class InputValidator {
public:
// Comprehensive Input Validation and Cryptographic Verification.
class InputValidator {
public:
    /**
     * Verifies an Ed25519 Edwards-curve signature.
     * Used for authenticating identity uploads and account-burn requests.
     */
    static bool verify_ed25519(const std::vector<unsigned char>& pubkey,
                               const std::vector<unsigned char>& message,
                               const std::vector<unsigned char>& signature) {
        if (pubkey.size() != 32 || signature.size() != 64) return false;

        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey.data(), pubkey.size());
        if (!pkey) return false;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        bool result = false;

        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1) {
            if (EVP_DigestVerify(ctx, signature.data(), signature.size(), message.data(), message.size()) == 1) {
                result = true;
            }
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return result;
    }

    // Validates that a string is a correctly formatted hexadecimal sequence.
    static bool is_valid_hex(const std::string& str, size_t expected_length = 0) {
        if (str.empty()) return false;
        if (expected_length > 0 && str.length() != expected_length) return false;
        
        return std::all_of(str.begin(), str.end(), [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c));
        });
    }
    
    // Checks for a valid SHA256 hex hash (64 characters).
    static bool is_valid_hash(const std::string& hash) {
        return is_valid_hex(hash, 64);
    }
    
    // Checks for safe alphanumeric characters (including underscores and hyphens).
    static bool is_valid_alphanumeric(const std::string& str) {
        if (str.empty()) return false;
        return std::all_of(str.begin(), str.end(), [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-';
        });
    }
    
    static bool is_within_size_limit(size_t size, size_t max_size) {
        return size <= max_size;
    }

    /**
     * Authenticated JSON Parsing with recursion depth limits to prevent stack-exhaustion (DoS).
     */
    static boost::json::value safe_parse_json(const std::string& input) {
        boost::json::parse_options opt;
        opt.max_depth = 16; 
        return boost::json::parse(input, {}, opt);
    }
};

}
