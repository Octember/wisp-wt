FROM rust:1.91-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY relay/Cargo.toml relay/Cargo.lock* ./
COPY relay/src ./src
RUN cargo build --release --bin wisp-wt-relay --bin wisp-wt-bench

COPY bench/run-netem-bench.sh /usr/local/bin/run-netem-bench.sh
RUN chmod +x /usr/local/bin/run-netem-bench.sh

ENTRYPOINT ["/usr/local/bin/run-netem-bench.sh"]
