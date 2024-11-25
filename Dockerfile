FROM rust:1.75-buster AS rust

WORKDIR /usr/app

COPY bindings bindings
COPY crates crates
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY config.toml config.toml
RUN cargo build --release --bin polysig-relay

CMD /usr/app/target/release/polysig-relay --bind 0.0.0.0:8080 /usr/app/config.toml
