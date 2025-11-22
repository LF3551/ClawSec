FROM alpine:latest

# Install dependencies
RUN apk add --no-cache \
    openssl-dev \
    gcc \
    g++ \
    make \
    musl-dev

# Copy source
WORKDIR /app
COPY unix/ /app/unix/
COPY README.md SECURITY.md /app/

# Build
WORKDIR /app/unix
RUN make clean && \
    XFLAGS="-I/usr/include" XLIBS="-lssl -lcrypto -lstdc++" make generic

# Create non-root user
RUN adduser -D -u 1000 clawsec

# Set permissions
RUN chown -R clawsec:clawsec /app

USER clawsec
WORKDIR /app/unix

# Default: listen mode
ENTRYPOINT ["./clawsec"]
CMD ["-l", "-p", "8888", "-k", "ChangeMe"]
