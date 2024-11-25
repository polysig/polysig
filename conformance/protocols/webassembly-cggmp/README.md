# CGGMP Signing Test (webassembly)

## Prerequisites

* Node >= v20.11.0
* Rust toolchain (stable channel >= 1.82.0)
* wasm-pack >= 0.13.0
* wasm-opt >= 116

## Setup

Install dependencies and browsers:

```
npm install
npx playwright install
```

Build the templates and webssembly bindings:

```
npm run build
```

Start a relay server:

```
npm run relay
```

Start a development server:

```
npm run dev
```

Run the tests:

```
npm test
```
