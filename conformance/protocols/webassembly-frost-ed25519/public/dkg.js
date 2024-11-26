const module = await import("/pkg/polysig_webassembly_bindings.js");

// Initialize the webassembly
await module.default();

const { FrostEd25519Protocol: FrostProtocol } = module;

const params = new URLSearchParams(document.location.search);
const pageData = JSON.parse(params.get('data'));
const { partyIndex, server, parameters, identifiers } = pageData;
const partyKeys = JSON.parse(params.get('keys'));

const publicKey = partyKeys[partyIndex].encrypt.public;

const participants = partyKeys.map((key) => {
  return key.encrypt.public;
});

const verifiers = partyKeys.map((key) => {
  return key.sign.public;
});

const signer = partyKeys[partyIndex].sign.private;
const options = {
  keypair: partyKeys[partyIndex].encrypt,
  server,
  parameters
};

const party = {
  publicKey,
  participants,
  isInitiator: partyIndex == 0,
  verifiers,
  partyIndex,
};

const keyShare = await FrostProtocol.dkg(
  options,
  party,
  signer,
  identifiers,
);

const el = document.querySelector("body");
el.innerHTML = `<p class="key-share">${JSON.stringify({partyIndex, keyShare})}</p>`;
