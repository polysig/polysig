# CGGMP Signing Test (node)

## Prerequisites

* Node >= v20.11.0
* Rust toolchain (stable channel >= 1.82.0)

## Setup

Install dependencies for the node bindings, from the top-level of the repository:

```
(cd crates/bindings/node && npm install)
```

Build the templates and node bindings:

```
npm run build
```

Start a relay server:

```
npm run relay
```

Run the tests:

```
npm test
```
