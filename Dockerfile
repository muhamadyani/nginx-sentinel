FROM rust:latest as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM ubuntu:latest
# Install dependensi runtime (ipset & iptables wajib ada)
RUN apt-get update && apt-get install -y ipset iptables iputils-ping && rm -rf /var/lib/apt/lists/*

# Buat folder log dummy
RUN mkdir -p /var/log/nginx && touch /var/log/nginx/access.log

WORKDIR /app
COPY --from=builder /usr/src/app/target/release/siesta-nginx-sentinel .
COPY --from=builder /usr/src/app/sentinel_config.yaml .

# Set environment variable log
ENV RUST_LOG=info
ENV SENTINEL_CONFIG=/app/sentinel_config.yaml

# Jalankan aplikasi
CMD ["./siesta-nginx-sentinel"]