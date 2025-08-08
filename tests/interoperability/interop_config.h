/*
 * DTLS v1.3 Interoperability Test Configuration
 * Auto-generated from CMake configuration
 * Task 9: External library integration capabilities
 */

#pragma once

// External implementation availability
#define DTLS_INTEROP_OPENSSL_AVAILABLE
/* #undef DTLS_INTEROP_WOLFSSL_AVAILABLE */
/* #undef DTLS_INTEROP_GNUTLS_AVAILABLE */
/* #undef DTLS_INTEROP_DOCKER_AVAILABLE */

// Version information
#define DTLS_INTEROP_OPENSSL_VERSION "3.0.13"
#ifdef DTLS_INTEROP_GNUTLS_AVAILABLE
#define DTLS_INTEROP_GNUTLS_VERSION ""
#endif

// Test configuration
#define DTLS_INTEROP_DEFAULT_TIMEOUT_MS 10000
#define DTLS_INTEROP_DEFAULT_PORT_BASE 14433
#define DTLS_INTEROP_MAX_CONCURRENT_TESTS 8
#define DTLS_INTEROP_DOCKER_NETWORK "dtls_interop_net"

// RFC 9147 test vectors
#define DTLS_INTEROP_RFC_TEST_VECTORS_ENABLED 1
#define DTLS_INTEROP_PERFORMANCE_BENCHMARKS_ENABLED 1

// Docker container configurations
#ifdef DTLS_INTEROP_DOCKER_AVAILABLE
#define DTLS_INTEROP_OPENSSL_DOCKER_IMAGE "dtls_interop_openssl:latest"
#define DTLS_INTEROP_WOLFSSL_DOCKER_IMAGE "dtls_interop_wolfssl:latest"
#define DTLS_INTEROP_GNUTLS_DOCKER_IMAGE "dtls_interop_gnutls:latest"
#endif

// Supported cipher suites for interoperability testing
#define DTLS_INTEROP_CIPHER_SUITES { \
    0x1301, /* TLS_AES_128_GCM_SHA256 */ \
    0x1302, /* TLS_AES_256_GCM_SHA384 */ \
    0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */ \
    0x1304, /* TLS_AES_128_CCM_SHA256 */ \
    0x1305  /* TLS_AES_128_CCM_8_SHA256 */ \
}

// Supported named groups
#define DTLS_INTEROP_NAMED_GROUPS { \
    23, /* secp256r1 */ \
    24, /* secp384r1 */ \
    25, /* secp521r1 */ \
    29, /* x25519 */ \
    30  /* x448 */ \
}

// Test data sizes for compatibility testing
#define DTLS_INTEROP_TEST_DATA_SIZES { \
    64,    /* Minimal */ \
    512,   /* Small */ \
    1024,  /* Medium */ \
    4096,  /* Large */ \
    16384, /* Maximum fragment */ \
    32768  /* Multi-record */ \
}
