# syntax=docker/dockerfile:1
#
# ClawSec container image: multi-stage (no compilers in the final image),
# base image pinned by digest (Dependabot keeps it current), non-root user.
#
#   docker run -e CLAWSEC_PASSWORD="$(openssl rand -base64 24)" -p 8888:8888 clawsec
#
# The password comes from CLAWSEC_PASSWORD (or a mounted --key-file); there is
# deliberately no default password. Files received with --recv go to /data.

ARG ALPINE=alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

FROM ${ALPINE} AS build
RUN apk add --no-cache build-base linux-headers openssl-dev argon2-dev zlib-dev
WORKDIR /build
COPY src/ ./src/
COPY tests/ ./tests/
RUN cd src && make clean && make alpine && ./clawsec --version

FROM ${ALPINE}
RUN apk add --no-cache libssl3 libcrypto3 argon2-libs zlib libstdc++ libgcc \
 && adduser -D -H -u 10001 clawsec \
 && install -d -o clawsec -g clawsec /data
COPY --from=build /build/src/clawsec /usr/local/bin/clawsec
USER clawsec
WORKDIR /data
EXPOSE 8888
ENTRYPOINT ["clawsec"]
CMD ["-l", "-p", "8888"]
