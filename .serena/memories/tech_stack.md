# Technology Stack

## Core Technologies
- **Language**: C++20 (required), C++17 supported
- **Build System**: CMake 3.20+
- **Compiler Support**: GCC 7+, Clang 6+, MSVC 2019+

## Dependencies
### Required
- **OpenSSL**: 1.1.1+ or 3.0+ (primary crypto provider)
- **Threads**: POSIX threads support
- **CMake**: 3.20+ for build configuration

### Optional
- **Botan**: 2.0+ (alternative crypto provider)
- **SystemC**: 2.3.3+ (for SystemC modeling)
- **TLM**: 2.0.5+ (Transaction Level Modeling)
- **Google Test**: For unit testing (auto-downloaded if not found)

## Hardware Acceleration
- AES-NI, AVX, AVX2 instruction sets
- ARM NEON, ARM AES extensions
- Intel QAT support
- TPM 2.0 and HSM integration
- Secure enclave support

## Platform Support
- Linux (primary development platform)
- macOS (cross-platform CI)
- Windows (MSVC 2019+)
- ARM64 and x86_64 architectures

## Security Features
- AEAD encryption: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- Key exchange: ECDHE (P-256, P-384, P-521, X25519, X448), DHE, PSK
- Digital signatures: RSA-PSS, ECDSA, EdDSA (Ed25519, Ed448)
- Anti-replay protection with sliding window
- Perfect forward secrecy for all sessions