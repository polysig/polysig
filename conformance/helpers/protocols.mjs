// Helper functions and shared configuration for 
// the protocol conformance test specs.
import fs from 'fs';

export const URL = process.env.TEST_URL || "http://localhost:5173";

// Convert from a hex-encoded string.
export function fromHexString(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const serverKey = fs.readFileSync(
  "../../../crates/integration_tests/tests/server_public_key.txt", "utf8");

export const server = {
  serverUrl: "ws://127.0.0.1:8008",
  serverPublicKey: Array.from(fromHexString(serverKey)),
};

export const parameters = {
  parties: 3,
  threshold: 2,
};

export const cggmp = {
  // CGGMP requires a prehashed message
  message: "a3e6e406aeb475f43aa762bb752a8f9d57b7fa327a2a53c7ae00b13f8d116b38",
  dkgSessionIdSeed: Array.from(fromHexString("ee507039fb7b14bf8190f300c66732110b401a68ba8e0d3fa464809972d33489")),
  signSessionIdSeed: Array.from(fromHexString("289e497ac7c2640adda5bf9bf0e9a05833f1807d1c4dce3f73e3483513bfa25e")),
};

export const frost = {
  message: "a3e6e406aeb475f43aa762bb752a8f9d57b7fa327a2a53c7ae00b13f8d116b38",
  // FROST requires identifiers for each participant during dkg,
  // when signing we must also supply identifiers that match the 
  // identifiers in the key share for each participant
  identifiers: Array.apply(null, Array(parameters.parties)).map((_, i) => {
    return i + 1;
  }),
};

// Helper to proxy console logs from scripts to the 
// terminal in playwright.
export function proxyConsoleError(id, page) {
  // Proxy browser console.error()
  page.on("console", (message) => {
    if (message.type() === "error") {
      console.error("console.error: ", id, message.text());
    } else if (message.type() === "warn") {
      console.warn("console.warn: ", id, message.text());
    } else if (message.type() === "info") {
      console.info("console.info: ", id, message.text());
    } else if (message.type() === "log") {
      console.log("console.log: ", id, message.text());
    }
  });

  // Unhandled error
  page.on("pageerror", (err) => {
    console.error("unhandled error:", id, err);
  });
}
