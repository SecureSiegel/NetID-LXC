FROM rust:1.75-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/netid-lxc /usr/local/bin/netid-lxc
ENTRYPOINT ["/usr/local/bin/netid-lxc"]
