FROM rust:1-slim-noble AS builder

ARG BACKEND=onnx-fetch

WORKDIR /src
COPY . .

RUN cargo build --release --no-default-features --features "${BACKEND}"

FROM ubuntu:noble

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/parry-guard /usr/local/bin/parry-guard

ENTRYPOINT ["parry-guard"]
