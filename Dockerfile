FROM rust:1.61 AS builder

WORKDIR /build

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --assume-yes protobuf-compiler

COPY . /build
RUN cargo build --release --workspace && mv /build/target/release/session-service /build/session-service && rm -rf /build/target

FROM debian:11
LABEL org.opencontainers.image.source https://github.com/tyorka-shop/session-service
COPY --from=builder /build/session-service /usr/local/bin/

CMD ["session-service"]