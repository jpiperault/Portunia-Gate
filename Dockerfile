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
    cargo build --release --locked && cp target/release/heimdia /heimdia

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 990 --home /var/lib/heimdia heimdia \
    && install -d -o heimdia -g heimdia -m 700 /var/lib/heimdia
COPY --from=build /heimdia /usr/local/bin/heimdia
USER heimdia
VOLUME /var/lib/heimdia
EXPOSE 2222 8443
ENTRYPOINT ["heimdia"]
CMD ["serve"]
