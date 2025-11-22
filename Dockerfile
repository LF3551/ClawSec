FROM alpine:latest

# Install dependencies
RUN apk add --no-cache \
    openssl-dev \
    openssl-libs-static \
    gcc \
    g++ \
    make \
    musl-dev

# Copy source
WORKDIR /app
COPY unix/ ./unix/

# Build
WORKDIR /app/unix
RUN make clean && make alpine

# Create non-root user
RUN adduser -D -u 1000 clawsec && \
    chown -R clawsec:clawsec /app

USER clawsec
WORKDIR /app/unix

# Default: listen mode
ENTRYPOINT ["./clawsec"]
CMD ["-l", "-p", "8888", "-k", "ChangeMe"]
