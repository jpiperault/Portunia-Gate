# Image de Portunia Gate : compilation dans une image Rust, exécution dans une Debian minimale.

FROM rust:1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations migrations
COPY src src
# Pages du portail web, embarquées dans le binaire.
COPY portail portail
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/portunia-gate /portunia-gate

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 990 --home /var/lib/portunia-gate portunia-gate \
    && install -d -o portunia-gate -g portunia-gate -m 700 /var/lib/portunia-gate
COPY --from=build /portunia-gate /usr/local/bin/portunia-gate
USER portunia-gate
VOLUME /var/lib/portunia-gate
EXPOSE 2222 8443
ENTRYPOINT ["portunia-gate"]
CMD ["serve"]
