# Contributing to Entropy

First off, thank you for considering contributing to Entropy! We need people like you to keep the messaging ecosystem private and resilient.

## Code of Conduct

By participating in this project, you agree to abide by our standards of professional and respectful collaboration.

## How Can I Contribute?

### Reporting Bugs
*   Check the Issues tab to see if the bug has already been reported.
*   If not, open a new issue. Include your environment details (OS, Compiler version, Redis version).
*   Provide a clear reproduction case.

### Suggesting Enhancements
*   Open an issue with the tag `enhancement`.
*   Explain why this feature is useful and how it aligns with Entropy's "Zero-Knowledge" philosophy.

### Pull Requests
1.  Fork the repo and create your branch from `main`.
2.  If you've added code that should be tested, add tests.
3.  If you've changed APIs, update the documentation.
4.  Ensure the test suite passes (`./run_all_tests.sh`).
5.  Make sure your code follows the existing style (Modern C++23 standards, clear naming, no "AI-style" redundant comments).

## Technical Standards

*   **Server**: C++23, Boost.Asio. Prefer smart pointers and `[[nodiscard]]` for any function returning status or data.
*   **Logging**: Use `SecurityLogger` for any events related to authentication or protocol violations.

## Style Guide

We prefer a clean, coding style:
*   Use Doxygen-style comments for complex architectural reasons.
*   Avoid commenting the obvious (e.g., `i++ // increment i`).
*   Keep functions focused and small.

---

*Entropy is a community-driven project. Your contributions help protect digital freedom for everyone.*
