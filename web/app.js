// app.js — Azabache serverless mode + live presence.
// Two people trade a connect code by hand (any channel), then connect directly
// over WebRTC, end-to-end encrypted. No signaling server, nothing always-on.
//
// Presence has no server either: "online" simply means the P2P channel is alive.
// A heartbeat over the channel detects when the peer closes the app / powers off
// / loses the network, and flips them to "offline · last seen".

const ICE = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
const HEARTBEAT_MS = 3000;   // send a ping this often
const OFFLINE_MS = 7000;     // no sign of life for this long => offline

let me, pc, dc, sharedKey, peerNumber;
let lastSeen = 0, beatTimer = null, watchTimer = null;

const $ = (id) => document.getElementById(id);
const setStatus = (s) => { $('status').textContent = s; };
function logMsg(who, text) { const d = document.createElement('div'); d.textContent = who + ': ' + text; $('log').appendChild(d); }
function logImg(who, dataUrl) {
  const d = document.createElement('div');
  d.textContent = who + ': ';
  const img = document.createElement('img');
  img.src = dataUrl; img.style.maxWidth = '220px'; img.style.borderRadius = '8px'; img.style.verticalAlign = 'middle';
  d.appendChild(img); $('log').appendChild(d);
}
// persist a message to local history (text or photo dataURL)
async function record(dir, kind, body) {
  await Store.addMessage({ peer: peerNumber, dir, kind, body, ts: Date.now() });
}

// ---- photo transfer (chunked; each image already metadata-stripped) ----
const CHUNK = 16000;
let rx = null; // reassembly buffer for an incoming photo
function blobToDataURL(blob) { return new Promise((r) => { const f = new FileReader(); f.onload = () => r(f.result); f.readAsDataURL(blob); }); }

async function sendPhoto(file) {
  if (!dc || dc.readyState !== 'open') return;
  const clean = await Photo.stripImage(file);          // <-- metadata removed here
  const dataUrl = await blobToDataURL(clean);
  const enc = await Identity.encrypt(sharedKey, dataUrl); // {iv, ct}
  const total = Math.ceil(enc.ct.length / CHUNK);
  dc.send(JSON.stringify({ k: 'photo-start', iv: enc.iv, total }));
  for (let i = 0; i < total; i++) dc.send(JSON.stringify({ k: 'photo-part', seq: i, data: enc.ct.slice(i * CHUNK, (i + 1) * CHUNK) }));
  logImg('me', dataUrl);
  await record('out', 'photo', dataUrl);
}

async function onPhotoMessage(m) {
  markAlive();
  if (m.k === 'photo-start') { rx = { iv: m.iv, total: m.total, parts: [] }; return; }
  if (m.k === 'photo-part' && rx) {
    rx.parts[m.seq] = m.data;
    if (rx.parts.filter(Boolean).length === rx.total) {
      const ct = rx.parts.join('');
      const dataUrl = await Identity.decrypt(sharedKey, { iv: rx.iv, ct });
      logImg('them', dataUrl);
      await record('in', 'photo', dataUrl);
      rx = null;
    }
  }
}

function encodeCode(obj) { return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function decodeCode(s) { s = s.trim().replace(/-/g, '+').replace(/_/g, '/'); return JSON.parse(atob(s)); }

function waitIceComplete() {
  return new Promise((res) => {
    if (pc.iceGatheringState === 'complete') return res();
    const check = () => { if (pc.iceGatheringState === 'complete') { pc.removeEventListener('icegatheringstatechange', check); res(); } };
    pc.addEventListener('icegatheringstatechange', check);
  });
}

// ---- presence (no server: derived from the live channel) ----
function fmtTime(t) { return new Date(t).toLocaleTimeString(); }
function showOnline() { $('presence').textContent = '● online'; $('presence').style.color = '#7fd18b'; }
function showOffline() {
  $('presence').style.color = '#c77';
  $('presence').textContent = lastSeen ? '○ offline · last seen ' + fmtTime(lastSeen) : '○ offline';
}
function markAlive() { lastSeen = Date.now(); showOnline(); }
function stopPresence() { clearInterval(beatTimer); clearInterval(watchTimer); beatTimer = watchTimer = null; }
function startPresence() {
  markAlive();
  beatTimer = setInterval(() => { if (dc && dc.readyState === 'open') dc.send(JSON.stringify({ k: 'ping' })); }, HEARTBEAT_MS);
  watchTimer = setInterval(() => { if (Date.now() - lastSeen > OFFLINE_MS) showOffline(); }, 1000);
}
function goOffline() { stopPresence(); showOffline(); }

function newPeerConnection() {
  pc = new RTCPeerConnection(ICE);
  pc.onconnectionstatechange = () => {
    const s = pc.connectionState;
    if (s === 'disconnected' || s === 'failed' || s === 'closed') goOffline();
  };
}
function wireChannel(channel) {
  dc = channel;
  dc.onopen = () => { $('chat').hidden = false; setStatus('connected — end-to-end encrypted'); startPresence(); };
  dc.onclose = () => goOffline();
  dc.onmessage = async (e) => {
    const m = JSON.parse(e.data);
    if (m.k === 'ping') { markAlive(); if (dc.readyState === 'open') dc.send(JSON.stringify({ k: 'pong' })); return; }
    if (m.k === 'pong') { markAlive(); return; }
    if (m.k === 'photo-start' || m.k === 'photo-part') { return onPhotoMessage(m); }
    if (m.k === 'msg') { markAlive(); const txt = await Identity.decrypt(sharedKey, m.p); logMsg('them', txt); await record('in', 'text', txt); }
  };
}

async function trustPeer(pubB64) {
  const pub = await Identity.importPublicKey(pubB64);
  peerNumber = await Identity.numberFromPublicKey(pub);
  sharedKey = await Identity.deriveSharedKey(me.privateKey, pub);
  $('peer').textContent = peerNumber;
  // remember this contact locally, and show any past history with them
  const existing = await Store.getContact(peerNumber);
  await Store.saveContact({ number: peerNumber, name: (existing && existing.name) || peerNumber,
    pub: pubB64, lastSeen: Date.now() });
  await loadHistory(peerNumber);
  await renderContacts();
}

async function loadHistory(peer) {
  $('log').textContent = '';
  const past = await Store.history(peer);
  for (const m of past) {
    const who = m.dir === 'out' ? 'me' : 'them';
    if (m.kind === 'photo') logImg(who, m.body); else logMsg(who, m.body);
  }
}

async function renderContacts() {
  const list = await Store.getContacts();
  if (!list.length) return;
  $('contactsBox').hidden = false;
  const box = $('contacts'); box.textContent = '';
  for (const c of list) {
    const d = document.createElement('div');
    d.textContent = c.name + '  ·  last seen ' + new Date(c.lastSeen).toLocaleString();
    box.appendChild(d);
  }
}

async function createInvite() {
  newPeerConnection();
  wireChannel(pc.createDataChannel('chat'));
  await pc.setLocalDescription(await pc.createOffer());
  await waitIceComplete();
  $('outCode').value = encodeCode({ t: 'offer', sdp: { type: pc.localDescription.type, sdp: pc.localDescription.sdp }, pub: me.pub });
  setStatus('send that code to the other person, then paste their answer below');
}

async function useCode(raw) {
  const msg = decodeCode(raw);
  if (msg.t === 'offer') return acceptOffer(msg);
  if (msg.t === 'answer') return acceptAnswer(msg);
}
async function acceptOffer(msg) { // B
  await trustPeer(msg.pub);
  newPeerConnection();
  pc.ondatachannel = (e) => wireChannel(e.channel);
  await pc.setRemoteDescription(msg.sdp);
  await pc.setLocalDescription(await pc.createAnswer());
  await waitIceComplete();
  $('outCode').value = encodeCode({ t: 'answer', sdp: { type: pc.localDescription.type, sdp: pc.localDescription.sdp }, pub: me.pub });
  setStatus('send that answer code back to the other person');
}
async function acceptAnswer(msg) { // A
  await trustPeer(msg.pub);
  await pc.setRemoteDescription(msg.sdp);
}

async function send() {
  const t = $('msg').value.trim();
  if (!t || !dc || dc.readyState !== 'open') return;
  dc.send(JSON.stringify({ k: 'msg', p: await Identity.encrypt(sharedKey, t) }));
  logMsg('me', t);
  await record('out', 'text', t);
  $('msg').value = '';
}

(async () => {
  me = await Identity.generateIdentity();
  me.pub = await Identity.exportPublicKey(me.publicKey);
  $('myNumber').textContent = me.number;
  setStatus('ready — no server involved');
  await renderContacts();   // show saved contacts from previous sessions
})();

$('createBtn').onclick = createInvite;
$('useBtn').onclick = () => { const c = $('inCode').value.trim(); if (c) useCode(c); };
$('sendBtn').onclick = send;
$('msg').addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
$('photoBtn').onclick = () => $('photoFile').click();
$('photoFile').onchange = (e) => { const f = e.target.files[0]; if (f) sendPhoto(f); e.target.value = ''; };
$('wipeBtn').onclick = async () => {
  if (!confirm('Delete account? This erases ALL contacts and history on this device. No trace.')) return;
  await Store.wipe();
  location.reload();
};
