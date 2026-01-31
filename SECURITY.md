# Entropy Server - Security & Deployment Quick Reference

## Critical Security Fixes Implemented ✅

1. **Authentication Bypass** - Fixed: All WebSocket messages now require authentication
2. **Replay Attack Protection** - Enabled: Nonces are claimed and cannot be reused
3. **PoW Difficulty** - Hardened: Increased to **5** to prevent botting
4. **CORS Security** - Secured: Origins must be explicitly configured
5. **Input Validation** - Added: Centralized validation framework
6. **Message Size Limits** - Enforced: Max 5MB per WebSocket message
7. **Continuity Lock** - **Implemented**: Hash chaining prevents message drops and ghost devices
8. **Identity Verification** - **Implemented**: Server verifies SHA-256 of Identity Keys
9. **Secure Storage** - **Enhanced**: Removed insecure localStorage fallbacks for secrets
10. **Birational Key Mapping** - **Hardened**: Correct Montgomery conversion for cross-protocol compatibility
11. **Metadata Resistance** - **Hardened**: SOCKS5/Tor support + **Constant-Rate Clocked Tunneling** (500ms tick)
12. **Post-Quantum Security** - **Added**: PQ-Hybrid (X25519 + Kyber-1024) protecting against future quantum attacks
13. **Backend Hardening** - **Implemented**: Support for authenticated Redis clusters and volatile-only storage
14. **K-Anonymity Batches** - **Implemented**: Client requests multiple decoy keys to hide interest in peers
16. **Unbound PoW Mitigation** - **Fixed**: Proof-of-Work is now cryptographically bound to the user Identity or Alias, preventing mass account hijacking.
17. **DoS Amplification Protection** - **Implemented**: Strict caps on multicast (100) and group (100) recipients to prevent resource exhaustion attacks.
18. **Configuration Safety** - **Added**: Hardcoded startup check to prevent running with insecure default cryptographic salts.
19. **URL Injection Hardening** - **Fixed**: Strict hex validation on client-side hash inputs.
20. **CSPRNG Failure Mode** - **Hardened**: Server now terminates immediately if random number generation fails, preventing use of weak fallback values.
21. **Adaptive Pacing** - **Implemented**: Smart traffic masking that pauses dummy packets on idle connections to prevent self-DoS/bandwidth exhaustion.
22. **Cost-Based Rate Limiting** - **Implemented**: "Token buckets with weight" prevent multicast amplification attacks by charging more for expensive operations.
23. **Storage Resilience** - **Hardened**: Explicit error propagation when Redis storage fails, preventing silent data loss.

## Quick Start for Production

### 1. Environment Configuration

```bash
export ENTROPY_ALLOWED_ORIGINS="https://yourdomain.com,https://app.yourdomain.com"
export ENTROPY_PORT=8081
export ENTROPY_ADDR="0.0.0.0"
export ENTROPY_REDIS_URL="tcp://127.0.0.1:6379"
```

### 2. Build and Run

```bash
cd server
cmake -S . -B build
cmake --build build --target generate_certs  # Generate TLS certs
cmake --build build

# Production run (requires TLS)
./build/server

# Development run (no TLS - WARNING: NOT FOR PRODUCTION)
./build/server --no-tls
```

### 3. Verify Security Headers

```bash
# Check CORS
curl -i -H "Origin: https://yourdomain.com" http://localhost:8081/health

# Check security headers
curl -i https://localhost:8081/health | grep -E "(Strict-Transport|Content-Security|X-Frame)"
```

## Security Changes Summary

| Component | Before | After |
|-----------|--------|-------|
| **WebSocket Auth** | ❌ No checks before processing | ✅ Authenticated before relay |
| **Replay Protection** | ❌ Disabled | ✅ Nonce claiming enabled |
| **PoW Difficulty** | ⚠️ 2 (too weak) | ✅ 3 (balanced) |
| **CORS** | ❌ Wildcard `*` | ✅ Explicit allowlist |
| **Message Size** | ❌ No validation | ✅ 5MB limit enforced |
| **Security Headers** | ⚠️ Basic | ✅ HSTS, CSP, Permissions-Policy |
| **CORS Validation** | ❌ No validation | ✅ Origin checked against allowlist |
| **CORS Validation** | ❌ No validation | ✅ Origin checked against allowlist |
| **Security Logging** | ❌ None | ✅ Comprehensive event logging |
| **Traffic Pacing** | ⚠️ Constant/Wasteful | ✅ Adaptive (Smart Masking) |
| **Multicast Limits** | ⚠️ Global Count | ✅ Cost-Based (Per-Recipient Cost) |

## Security Event Types Logged

- `AUTH_SUCCESS` - Successful authentication
- `AUTH_FAILURE` - Failed authentication attempt
- `RATE_LIMIT` - Rate limit exceeded
- `INVALID_INPUT` - Malformed or oversized input
- `POW_FAILURE` - Proof-of-Work verification failed
- `REPLAY_ATTEMPT` - Nonce or seed reuse detected
- `SUSPICIOUS` - Suspicious activity (e.g., disallowed CORS origin)

## Configuration Warnings

The server will warn you if:
- No CORS origins are configured
- TLS certificates are missing (in TLS mode)
- Running without TLS

## Pre-Deployment Checklist

- [ ] `ENTROPY_ALLOWED_ORIGINS` set to production domains
- [ ] TLS certificates valid and not self-signed
- [ ] Redis secured with authentication
- [ ] Security logging enabled and monitored
- [ ] Rate limits configured appropriately
- [ ] Health checks configured in monitoring
- [ ] Graceful shutdown tested

## Common Issues

### Issue: "No CORS origins configured"
**Solution**: Set `ENTROPY_ALLOWED_ORIGINS` environment variable

### Issue: "TLS certificates not found"
**Solution**: Run `cmake --build build --target generate_certs` or use --no-tls for dev

### Issue: Authentication failures
**Check**: PoW difficulty is 3, ensure client is solving correctly

### Issue: CORS errors in browser
**Check**: Origin is in `ENTROPY_ALLOWED_ORIGINS` list

## Monitoring Recommendations

Monitor these security metrics:
- Authentication failure rate
- Replay attempt frequency
- Rate limit hits per endpoint
- Invalid input attempts
- Active connection count

## Next Steps for Hardening

1. Configure Redis with TLS and authentication
2. Implement per-IP connection limits
3. Add automated security testing
4. Set up log aggregation for security events
5. Enable systemd service with auto-restart
6. Configure firewall rules
7. Set up intrusion detection

---

**Note**: All critical security vulnerabilities have been addressed. The server is now production-ready with proper authentication, replay protection, CORS security, input validation, and comprehensive security logging.

## Discovery Obfuscation & K-Anonymity
Entropy implements **K-Anonymity** during discovery. Clients maintain a local **Decoy Pool** sourced from a server-side random sampler and natural message flow. This ensures lookups for peers are indistinguishable from noise.

## Forensic Remote Burn
Users can trigger an irreversible **Account Burn** that purges all Redis data (messages, sessions, bundles). This is protected by PoW and identity verification.
