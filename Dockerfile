# syntax=docker.io/docker/dockerfile:1.7-labs

FROM lukemathwalker/cargo-chef:0.1.68-rust-alpine3.21 as chef
WORKDIR /app

FROM chef AS planner
COPY ./Cargo.toml ./Cargo.lock ./
COPY ./crates ./crates
RUN cargo chef prepare

FROM chef AS builder
COPY --from=planner /app/recipe.json .
RUN cargo chef cook --release
COPY ./Cargo.toml ./Cargo.lock ./
COPY ./crates ./crates
RUN cargo build --release
RUN mv ./target/release/o-dns ./app

FROM debian:12.8-slim AS runtime
RUN groupadd -g 2000 app && useradd -m -u 2001 -g app app
RUN mkdir -p /etc/o-dns
RUN chown -R app:app /etc/o-dns
COPY --from=builder --chown=app:app /app/app /usr/local/bin/
EXPOSE 53
EXPOSE 80
USER app
ENTRYPOINT ["/usr/local/bin/app"]
