# Makefile for DTLS Interoperability Test Programs
# Task 9: Build DTLS test applications

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I/usr/local/openssl/include
LDFLAGS = -L/usr/local/openssl/lib -lssl -lcrypto

all: dtls_server dtls_client

dtls_server: dtls_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

dtls_client: dtls_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f dtls_server dtls_client

.PHONY: all clean