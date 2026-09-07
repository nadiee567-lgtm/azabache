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
// persist a message to the encrypted vault (no-op in decoy mode)
async function record(dir, kind, body) {
  await Session.addMessage({ peer: peerNumber, dir, kind, body, ts: Date.now() });
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

// ---- generic file transfer (any type; carries name + mime, encrypted) ----
let rxf = null;
async function sendFile(file) {
  if (!dc || dc.readyState !== 'open') return;
  const dataUrl = await blobToDataURL(file);            // data:<mime>;base64,...
  const enc = await Identity.encrypt(sharedKey, dataUrl);
  const total = Math.ceil(enc.ct.length / CHUNK);
  dc.send(JSON.stringify({ k: 'file-start', iv: enc.iv, total, name: file.name, size: file.size }));
  for (let i = 0; i < total; i++) dc.send(JSON.stringify({ k: 'file-part', seq: i, data: enc.ct.slice(i * CHUNK, (i + 1) * CHUNK) }));
  logFile('me', file.name, dataUrl);
  await record('out', 'file', JSON.stringify({ name: file.name, url: dataUrl }));
}
async function onFileMessage(m) {
  markAlive();
  if (m.k === 'file-start') { rxf = { iv: m.iv, total: m.total, name: m.name, parts: [] }; return; }
  if (m.k === 'file-part' && rxf) {
    rxf.parts[m.seq] = m.data;
    if (rxf.parts.filter(Boolean).length === rxf.total) {
      const dataUrl = await Identity.decrypt(sharedKey, { iv: rxf.iv, ct: rxf.parts.join('') });
      logFile('them', rxf.name, dataUrl);
      await record('in', 'file', JSON.stringify({ name: rxf.name, url: dataUrl }));
      rxf = null;
    }
  }
}
function logFile(who, name, dataUrl) {
  const d = document.createElement('div');
  d.textContent = who + ': ';
  const a = document.createElement('a');
  a.href = dataUrl; a.download = name; a.textContent = '📎 ' + name; a.style.color = '#8fb3d9';
  d.appendChild(a); $('log').appendChild(d);
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
    if (m.k === 'file-start' || m.k === 'file-part') { return onFileMessage(m); }
    if (m.k === 'msg') { markAlive(); const txt = await Identity.decrypt(sharedKey, m.p); logMsg('them', txt); await record('in', 'text', txt); }
  };
}

async function trustPeer(pubB64) {
  const pub = await Identity.importPublicKey(pubB64);
  peerNumber = await Identity.numberFromPublicKey(pub);
  sharedKey = await Identity.deriveSharedKey(me.privateKey, pub);
  $('peer').textContent = peerNumber;
  // remember this contact locally, and show any past history with them
  const existing = (Session.getData().contacts || []).find((c) => c.number === peerNumber);
  await Session.addContact({ number: peerNumber, name: (existing && existing.name) || peerNumber,
    pub: pubB64, lastSeen: Date.now() });
  await loadHistory(peerNumber);
  await renderContacts();
}

async function loadHistory(peer) {
  $('log').textContent = '';
  const past = Session.historyWith(peer);
  for (const m of past) {
    const who = m.dir === 'out' ? 'me' : 'them';
    if (m.kind === 'photo') logImg(who, m.body);
    else if (m.kind === 'file') { const f = JSON.parse(m.body); logFile(who, f.name, f.url); }
    else logMsg(who, m.body);
  }
}

async function renderContacts() {
  const list = Session.getData().contacts || [];
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

// ---- login gate (real password vs decoy) ----
async function startApp() {
  $('login').hidden = true;
  $('appMain').hidden = false;
  me = await Identity.generateIdentity();
  me.pub = await Identity.exportPublicKey(me.publicKey);
  $('myNumber').textContent = me.number;
  setStatus('ready — no server involved');
  await renderContacts();   // real mode: shows saved contacts; decoy: empty
}

(async () => {
  const first = await Session.isFirstRun();
  $('loginSub').textContent = first
    ? 'First time — create your REAL password (remember it; it cannot be recovered).'
    : 'Enter your password.';
  $('enterBtn').textContent = first ? 'create' : 'enter';
  $('enterBtn').onclick = async () => {
    const pw = $('pw').value;
    if (!pw) { $('loginMsg').textContent = 'type a password'; return; }
    if (first) { await Session.setup(pw); }
    else { await Session.unlock(pw); }   // real -> loads data; anything else -> empty decoy
    await startApp();
  };
  $('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('enterBtn').click(); });
})();

$('createBtn').onclick = createInvite;
$('useBtn').onclick = () => { const c = $('inCode').value.trim(); if (c) useCode(c); };
$('sendBtn').onclick = send;
$('msg').addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
$('photoBtn').onclick = () => $('photoFile').click();
$('photoFile').onchange = (e) => { const f = e.target.files[0]; if (f) sendPhoto(f); e.target.value = ''; };
$('fileBtn').onclick = () => $('anyFile').click();
$('anyFile').onchange = (e) => { const f = e.target.files[0]; if (f) sendFile(f); e.target.value = ''; };
$('wipeBtn').onclick = async () => {
  if (!confirm('Delete account? This erases ALL contacts and history on this device. No trace.')) return;
  await Store.wipe();
  location.reload();
};
