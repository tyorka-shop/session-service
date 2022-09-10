FROM rust:1.61 AS builder
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
      protobuf-compiler

COPY . /build
WORKDIR /build
RUN cargo build --release --workspace

FROM debian:11
COPY --from=builder /build/target/release/session-service /usr/local/bin/

CMD ["session-service"]