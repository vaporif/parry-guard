FROM ubuntu:noble AS builder

RUN apt-get update && apt-get install -y --no-install-recommends curl gcc g++ libc-dev pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

ARG BACKEND=onnx-fetch

WORKDIR /src
COPY . .

RUN cargo build --release --no-default-features --features "${BACKEND}"

FROM ubuntu:noble

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/parry-guard /usr/local/bin/parry-guard

ENTRYPOINT ["parry-guard"]
