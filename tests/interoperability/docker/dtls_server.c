/*
 * OpenSSL DTLS v1.3 Server for Interoperability Testing
 * Task 9: Reference DTLS server implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 65536
#define MAX_CLIENTS 10

typedef struct {
    SSL_CTX *ctx;
    int sockfd;
    struct sockaddr_in addr;
} dtls_server_t;

static int verify_callback(int ok, X509_STORE_CTX *ctx) {
    return 1; // Accept all certificates for testing
}

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    // Simple cookie generation for testing
    static unsigned char cookie_secret[16] = {0};
    static int initialized = 0;
    
    if (!initialized) {
        RAND_bytes(cookie_secret, sizeof(cookie_secret));
        initialized = 1;
    }
    
    // Generate simple cookie (in production, use proper HMAC)
    memcpy(cookie, cookie_secret, 16);
    *cookie_len = 16;
    
    return 1;
}

static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char generated_cookie[16];
    unsigned int generated_len;
    
    if (generate_cookie(ssl, generated_cookie, &generated_len) &&
        cookie_len == generated_len &&
        memcmp(cookie, generated_cookie, cookie_len) == 0) {
        return 1;
    }
    
    return 0;
}

static SSL_CTX* create_dtls_context() {
    SSL_CTX *ctx;
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create DTLS context
    ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Set DTLS version to 1.3
    if (SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION) != 1) {
        printf("Warning: Could not set minimum DTLS version to 1.3\n");
    }
    
    if (SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION) != 1) {
        printf("Warning: Could not set maximum DTLS version to 1.3\n");
    }
    
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "/app/certs/server-cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, "/app/certs/server-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // Set cipher suites for DTLS v1.3
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1) {
        printf("Warning: Could not set cipher suites\n");
    }
    
    // Set verification mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
    
    // Set cookie callbacks for DTLS
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
    
    return ctx;
}

static int create_udp_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;
    int reuse = 1;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    printf("DTLS server listening on port %d\n", port);
    return sockfd;
}

static void handle_client(SSL_CTX *ctx, int sockfd, struct sockaddr_in *client_addr) {
    SSL *ssl;
    BIO *bio;
    char buffer[BUFFER_SIZE];
    int bytes;
    
    printf("Handling client connection from %s:%d\n", 
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    
    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return;
    }
    
    // Create BIO for DTLS
    bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
    if (!bio) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }
    
    // Set client address for BIO
    BIO_ctrl_set_connected(bio, client_addr);
    SSL_set_bio(ssl, bio, bio);
    
    // Perform DTLS handshake
    printf("Starting DTLS handshake...\n");
    int handshake_result = SSL_accept(ssl);
    
    if (handshake_result <= 0) {
        int ssl_error = SSL_get_error(ssl, handshake_result);
        printf("DTLS handshake failed: SSL error %d\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }
    
    printf("DTLS handshake completed successfully\n");
    
    // Print negotiated parameters
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        printf("Negotiated cipher: %s\n", SSL_CIPHER_get_name(cipher));
    }
    
    printf("DTLS version: %s\n", SSL_get_version(ssl));
    
    // Echo server loop
    printf("Starting echo server loop...\n");
    while (1) {
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received %d bytes: %s\n", bytes, buffer);
            
            // Echo back the data
            int sent = SSL_write(ssl, buffer, bytes);
            if (sent <= 0) {
                printf("Failed to send echo response\n");
                break;
            }
            printf("Echoed %d bytes back to client\n", sent);
            
            // Check for quit command
            if (strncmp(buffer, "quit", 4) == 0) {
                printf("Client requested quit\n");
                break;
            }
        } else {
            int ssl_error = SSL_get_error(ssl, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ) {
                // No data available, continue
                usleep(10000); // 10ms
                continue;
            } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                printf("Client disconnected\n");
                break;
            } else {
                printf("SSL_read error: %d\n", ssl_error);
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }
    
    printf("Closing client connection\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main(int argc, char *argv[]) {
    int port = 4433;
    SSL_CTX *ctx;
    int sockfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    printf("Starting OpenSSL DTLS v1.3 Server on port %d\n", port);
    
    // Create SSL context
    ctx = create_dtls_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create DTLS context\n");
        return 1;
    }
    
    // Create UDP socket
    sockfd = create_udp_socket(port);
    if (sockfd < 0) {
        SSL_CTX_free(ctx);
        return 1;
    }
    
    printf("Waiting for DTLS connections...\n");
    
    // Simple server loop - handle one client at a time for simplicity
    while (1) {
        // Wait for initial packet from client
        ssize_t received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&client_addr, &client_len);
        
        if (received > 0) {
            printf("Received initial packet from client, starting DTLS handshake\n");
            
            // Put the packet back by sending it to ourselves (hack for simplicity)
            sendto(sockfd, buffer, received, 0, 
                   (struct sockaddr*)&client_addr, client_len);
            
            // Handle this client
            handle_client(ctx, sockfd, &client_addr);
        }
    }
    
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    return 0;
}