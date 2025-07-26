# OpenSSL DTLS v1.3 Server for Interoperability Testing
# Task 9: Isolated OpenSSL DTLS server implementation

FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    openssl \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install OpenSSL 3.0+ with DTLS v1.3 support
RUN wget https://www.openssl.org/source/openssl-3.1.0.tar.gz && \
    tar -xzf openssl-3.1.0.tar.gz && \
    cd openssl-3.1.0 && \
    ./Configure --prefix=/usr/local/openssl --openssldir=/usr/local/openssl && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf openssl-3.1.0*

# Update library path
ENV LD_LIBRARY_PATH=/usr/local/openssl/lib:$LD_LIBRARY_PATH
ENV PATH=/usr/local/openssl/bin:$PATH

# Create test certificates
RUN mkdir -p /app/certs && \
    cd /app/certs && \
    /usr/local/openssl/bin/openssl genpkey -algorithm RSA -out server-key.pem -pkcs8 -pass pass:password && \
    /usr/local/openssl/bin/openssl req -new -x509 -key server-key.pem -out server-cert.pem -days 365 -subj "/C=US/ST=CA/L=Test/O=DTLS/CN=localhost" -passin pass:password

# Create DTLS server script
COPY dtls_server.c /app/
COPY Makefile /app/

WORKDIR /app

# Compile DTLS server
RUN make dtls_server

# Expose DTLS port
EXPOSE 4433/udp

# Run DTLS server
CMD ["./dtls_server", "4433"]