import {
  Worker, isMainThread, parentPort, workerData,
} from 'node:worker_threads';

import {
  server,
  parameters,
  frost,
} from '../../../helpers/protocols.mjs';
const { message } = frost;

// Node requires an object with id field for the bindings
const identifiers = frost.identifiers.map((id) => {
  return { id };
});

const dkgScript = './tests/dkg.js';
const signScript = './tests/sign.js';

console.log("FROST Ed25519, begin dkg...");

let tasks = [];

for (let i = 0;i < parameters.parties;i++) {
  tasks.push(new Promise((resolve, reject) => {
    const worker = new Worker(dkgScript, {
      workerData: {
        partyIndex: i,
        server,
        parameters,
        identifiers,
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

console.log("FROST Ed25519, dkg complete, begin signing...");

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
        identifiers: indices.map((i) => identifiers[i]),
        parameters,
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
console.log("FROST Ed25519, signing complete, done.");
