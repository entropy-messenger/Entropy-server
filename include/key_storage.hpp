#pragma once

#include <string>
#include <map>
#include <mutex>
#include <vector>

namespace entropy {

 
// Abstract interface for persistent storage of cryptographic metadata.
// Primary implementation uses Redis for distributed access, but can be
// extended for local filesystem or database backups.
class KeyStorage {
public:
    virtual ~KeyStorage() = default;
    
    /**
     * Persistently stores a public key bundle for a specific identity.
     * @param user_hash Salted SHA256 of the identity public key.
     * @param bundle_json Complete JSON payload containing Pre-Keys and Signatures.
     * @return true if persistence was successful.
     */
    virtual bool store_bundle(const std::string& user_hash, const std::string& bundle_json) = 0;
    
    /**
     * Retrieves a public key bundle for a target identity.
     * @param user_hash Target identity hash.
     * @return Raw JSON bundle or empty string if not found.
     */
    virtual std::string get_bundle(const std::string& user_hash) = 0;
};

} 
