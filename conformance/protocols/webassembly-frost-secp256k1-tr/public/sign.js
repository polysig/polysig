const module = await import("/pkg/polysig_webassembly_bindings.js");

// Initialize the webassembly
await module.default();

const { FrostSecp256K1TrProtocol: FrostProtocol } = module;

const params = new URLSearchParams(document.location.search);
const pageData = JSON.parse(params.get('data'));
const { partyIndex, server, parameters, identifiers, keyShare, indices, message } = pageData;
const partyKeys = JSON.parse(params.get('keys'));

const publicKey = partyKeys[partyIndex].encrypt.public;

const participants = partyKeys.map((key) => {
  return key.encrypt.public;
});

// Verifiers for Schnorr are JSON encoded as 
// strings so we need to convert from the bytes here
const verifiers = partyKeys.map((key) => {
  const arr = Uint8Array.from(key.sign.public);
  const json = new TextDecoder().decode(arr);
  return json.replace(/^"/, '').replace(/"$/, '');
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

const protocol = new FrostProtocol(options, keyShare);
const signature = await protocol.sign(
  party,
  signer,
  identifiers,
  message,
);

const el = document.querySelector("body");
el.innerHTML = `<p class="signature">${JSON.stringify({partyIndex, signature})}</p>`;
