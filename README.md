# Multi-party computation protocol

End-to-end encrypted relay service designed for MPC/TSS applications built using the [noise protocol][] and websockets for the transport layer.

The service facilitates secure communication between peers but it does not handle public key exchange nor meeting points.

For clients to use the relay service they must know the public key of the server and the public keys of all the participants for a session.

Creating a meeting point that shares the session identifier between participants to execute an MPC/TSS protocol is left up to the application. Typically, this can be achieved by encoding the session identifier in a URL and sharing the URL with all the participants.

## Features

### Protocols

* `cggmp`: Enable the CGGMP21 protocol using [synedrion](https://github.com/entropyxyz/synedrion).

### Signers

* `ecdsa`: Single-party signer compatible with Ethereum using [k256](https://docs.rs/k256/latest/k256/).
* `eddsa`: Single-party signer compatible with Solana using [ed25519](https://docs.rs/ed25519/latest/ed25519/) and [ed25519-dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/).
* `schnorr`: Single-party signer compatible with Bitcoin Taproot (BIP-340) using [k256](https://docs.rs/k256/latest/k256/).

## Bindings

### Webassembly

* [x] CGGMP
* [x] ECDSA
* [x] EdDSA
* [ ] FROST
* [x] Schnorr

### Node

* [ ] CGGMP
* [x] ECDSA
* [x] EdDSA
* [ ] FROST
* [x] Schnorr

## Server Installation

```
cargo install mpc-relay
```

## Documentation

* [protocol][] Message types and encoding
* [server][] Websocket server library
* [client][] Websocket client library
* [cli][] Command line interface for the server

The client implementation uses [web-sys][] for webassembly and [tokio-tungstenite][] for other platforms.

## Development

### Getting Started

You will need the [rust][] toolchain and a few other tools:

```
cargo install cargo-make
cargo install cargo-nextest
cargo install wasm-pack
```

Minimum supported rust version (MSRV) is 1.68.1.

Run the `gen-keys` task to setup keypairs for the server and test specs:

```
cargo make gen-keys
```

### Server

Start a server:

```
cargo run -- start config.toml
```

### Documentation

```
cargo make doc
```

### Tests

To run the integration tests using the native client:

```
cargo nextest run
```

For webassembly and node binding tests see the README files in the conformance directory.

## License

The bindings and driver crates are released under the GPLv3 license and all other code is either MIT or Apache-2.0.

[noise protocol]: https://noiseprotocol.org/
[rust]: https://www.rust-lang.org/
[playwright]: https://playwright.dev
[web-sys]: https://docs.rs/web-sys
[tokio-tungstenite]: https://docs.rs/tokio-tungstenite
[protocol]: https://docs.rs/mpc-protocol
[server]: https://docs.rs/mpc-relay-server
[client]: https://docs.rs/mpc-client
[cli]: https://docs.rs/mpc-relay
