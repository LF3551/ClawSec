FROM alpine:latest

RUN apk add --no-cache \
    openssl-dev \
    zlib-dev \
    gcc \
    g++ \
    make \
    musl-dev \
    util-linux-dev

WORKDIR /app
COPY src/ ./src/
COPY tests/ ./tests/

WORKDIR /app/src
RUN make clean && make alpine

RUN adduser -D -u 1000 clawsec && \
    chown -R clawsec:clawsec /app

USER clawsec
WORKDIR /app/src

ENTRYPOINT ["./clawsec"]
CMD ["-l", "-p", "8888", "-k", "ChangeMe"]
