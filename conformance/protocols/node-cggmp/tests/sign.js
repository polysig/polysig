import {
  parentPort,
  workerData,
} from 'node:worker_threads';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const polysig = require('../build/polysig.node');
const { partyIndex, server, parameters, sessionIdSeed, keyShare, indices, message } = workerData;
const partyKeys = require("./ecdsa.json").slice(0, parameters.parties);

const { CggmpProtocol } = polysig;

const publicKey = partyKeys[partyIndex].encrypt.public;

const participants = partyKeys.map((key) => {
  return key.encrypt.public;
});

const verifiers = partyKeys.map((key) => {
  return { sec1Bytes: key.sign.public };
});

const signer = partyKeys[partyIndex].sign.private;
const options = {
  keypair: partyKeys[partyIndex].encrypt,
  server,
  parameters
};

const party = {
  publicKey,
  participants: indices.map((i) => participants[i]),
  isInitiator: partyIndex == 0,
  verifiers: indices.map((i) => verifiers[i]),
  partyIndex,
};

const protocol = new CggmpProtocol(options, keyShare);
const signature = await protocol.sign(
  party,
  sessionIdSeed,
  signer,
  message,
);

await parentPort.postMessage({partyIndex, signature});
