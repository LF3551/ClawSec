FROM alpine:latest

RUN apk add --no-cache \
    openssl-dev \
    argon2-dev \
    zlib-dev \
    gcc \
    g++ \
    make \
    musl-dev \
    util-linux-dev \
    linux-headers

WORKDIR /app
COPY src/ ./src/
COPY tests/ ./tests/

WORKDIR /app/src
RUN make clean && make alpine

RUN adduser -D -u 1000 clawsec && \
    chown -R clawsec:clawsec /app

USER clawsec
WORKDIR /app/src

# The password comes from the CLAWSEC_PASSWORD environment variable (or a
# mounted --key-file); there is deliberately no default password:
#   docker run -e CLAWSEC_PASSWORD="$(openssl rand -base64 24)" -p 8888:8888 clawsec
ENTRYPOINT ["./clawsec"]
CMD ["-l", "-p", "8888"]
