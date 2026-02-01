# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a potential security flaw in Entropy, please report it responsibly by emailing at `realmoyzy@gmail.com`.

### What to include:
*   A descriptive title for the vulnerability.
*   The version of the server/client affected.
*   A detailed description of the vulnerability.
*   Steps to reproduce the issue (PoC scripts are highly appreciated).
*   Potential impact of the vulnerability.

### Our Commitment:
*   We will acknowledge receipt of your report within 48 hours.
*   We will provide an estimated timeline for a fix.
*   We will coordinate a public disclosure date once the fix is deployed.
*   We believe in "Security for Everyone"—we will not initiate legal action against researchers who act in good faith and follow this policy.

---

## Technical Security Note

Entropy is designed for pure anonymity. If you find a way to:
1. De-blind user identifiers without the server salt.
2. Defeat the token-bucket rate limiting via packet manipulation.
3. Cause a crash in the `Boost.Asio` hot-path.

These are considered high-priority issues and will be addressed immediately.
