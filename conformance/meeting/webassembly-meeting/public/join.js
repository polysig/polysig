const module = await import("/pkg/polysig_webassembly_bindings.js");

// Initialize the webassembly
await module.default();

const { MeetingRoom } = module;
const serverUrl = "ws://localhost:8008/";

const { search } = document.location;
const params = new URLSearchParams(search);
const meetingId = params.get("meetingId");
const index = parseInt(params.get("index"));

const userId = Array.from(new Uint8Array(32));
userId[0] = index;

const publicKey = new Uint8Array(32);
publicKey[0] = index;
const verifyingKey = new Uint8Array(32);
verifyingKey[0] = index;
const userData = {
  publicKey: Array.from(publicKey),
  verifyingKey: Array.from(verifyingKey),
  associatedData: null,
};

const room = new MeetingRoom(serverUrl);
const participants = await room.join(
  meetingId, userId, userData);

const el = document.getElementById("participants");
el.innerHTML = `
  <p class="participants">${JSON.stringify(participants)}</p>`;
