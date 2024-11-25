import {
  Worker, isMainThread, parentPort, workerData,
} from 'node:worker_threads';
import fs from 'fs';

const dkgScript = './tests/dkg.js';
const signScript = './tests/sign.js';

// Convert from a hex-encoded string.
function fromHexString(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const dkgSessionIdSeed = "ee507039fb7b14bf8190f300c66732110b401a68ba8e0d3fa464809972d33489";
const signSessionIdSeed = "289e497ac7c2640adda5bf9bf0e9a05833f1807d1c4dce3f73e3483513bfa25e";
const serverKey = fs.readFileSync(
  "../../../integration_tests/tests/server_public_key.txt", "utf8");

const server = {
  serverUrl: "ws://127.0.0.1:8008",
  serverPublicKey: Array.from(fromHexString(serverKey)),
};
const parameters = {
  parties: 3,
  threshold: 2,
};

console.log("CGGMP, begin dkg...");

let tasks = [];

for (let i = 0;i < parameters.parties;i++) {
  tasks.push(new Promise((resolve, reject) => {
    const worker = new Worker(dkgScript, {
      workerData: {
        partyIndex: i,
        server,
        parameters,
        sessionIdSeed: Array.from(fromHexString(dkgSessionIdSeed)),
      }
    });

    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0)
        throw new Error(`Worker stopped with exit code ${code}`);
    });
  }));
}

const keyShares = await Promise.all(tasks);

console.assert(keyShares.length === parameters.parties);

console.log("CGGMP, dkg complete, begin signing...");
const message = "a3e6e406aeb475f43aa762bb752a8f9d57b7fa327a2a53c7ae00b13f8d116b38";

// Pick the signing parties
tasks = [];
const indices = [0, 2];
const signers = [
  keyShares[0].keyShare,
  keyShares[2].keyShare,
];

signers.forEach((keyShare, index) => {
  const partyIndex = indices[index];
  tasks.push(new Promise((resolve, reject) => {
    const worker = new Worker(signScript, {
      workerData: {
        partyIndex,
        indices,
        server,
        parameters,
        sessionIdSeed: Array.from(fromHexString(signSessionIdSeed)),
        keyShare,
        message,
      }
    });

    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0)
        throw new Error(`Worker stopped with exit code ${code}`);
    });
  }));
});

const signatures = await Promise.all(tasks);
console.assert(signatures.length === parameters.threshold);
console.log("CGGMP, signing complete, done.");
