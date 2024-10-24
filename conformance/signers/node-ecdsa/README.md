# ECDSA Signing Test (node)

## Prerequisites

* Node >= v20.11.0
* Rust toolchain (stable channel >= 1.82.0)

## Setup

Install dependencies for the node bindings, from the top-level of the repository:

```
(cd bindings/node && npm install)
```

Then in this directory build the bindings:

```
npm run build
```

Run the tests:

```
npm test
```