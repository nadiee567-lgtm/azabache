// mailbox.js — Azabache Teams: OPTIONAL self-hosted blind mailbox.
//
// A company/group runs this on their OWN machine. It is the piece that enables
// groups and "messages always arrive" (offline delivery). It stays true to the
// Law: it only ever stores CIPHERTEXT addressed to a public-key number. It
// cannot read a single message — no decryption key ever reaches it.
//
// What it does:
//   - Holds encrypted messages for a recipient number until they connect (WebSocket).
//   - Delivers everything queued on connect, then live from then on.
//   - The org controls retention: messages are dropped once delivered (default),
//     or kept if KEEP=1 is set (persistent group history the org can wipe).
//   - Wipe endpoint clears everything (the org's "delete = no trace").
//
// What it never sees: plaintext, and no private keys. Metadata (who/when/size)
// is visible to this server — that's the honest cost of offline delivery, and
// it's the org's OWN server, not a third party.
//
// One command, any OS:  node server/mailbox.js   (needs `npm i ws`)

const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8811;
const KEEP = process.env.KEEP === '1';          // keep delivered messages (group history)

// number -> live socket (present only while that client is connected)
const online = new Map();
// number -> [ {id, from, to, group, iv, ct, ts}, ... ] pending (and, if KEEP, delivered)
const queues = new Map();
let seq = 1;

const server = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200); return res.end('ok'); }
  res.writeHead(404); res.end();
});

const wss = new WebSocketServer({ server });

function enqueue(to, msg) {
  if (!queues.has(to)) queues.set(to, []);
  queues.get(to).push(msg);
}
function deliver(to) {
  const sock = online.get(to);
  if (!sock) return;
  const q = queues.get(to) || [];
  const pending = q.filter((m) => !m._sent);
  for (const m of pending) {
    sock.send(JSON.stringify({ type: 'msg', id: m.id, from: m.from, to: m.to, payload: m.payload, ts: m.ts }));
    m._sent = true;
  }
  if (!KEEP) queues.set(to, q.filter((m) => !m._sent)); // drop delivered unless KEEP
}

wss.on('connection', (ws) => {
  ws.number = null;
  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }

    // register: "I am this number" -> deliver anything waiting
    if (m.type === 'register' && m.number) {
      ws.number = m.number;
      online.set(m.number, ws);
      ws.send(JSON.stringify({ type: 'registered', number: m.number }));
      deliver(m.number);
      return;
    }

    // send: deliver one ENCRYPTED item per recipient. Each item is
    // { to, payload } where payload is an OPAQUE string the server never parses
    // (it holds the per-recipient ciphertext + key envelope). The server learns
    // nothing but routing metadata (from/to/time/size).
    if (m.type === 'send' && Array.isArray(m.items)) {
      const id = seq++;
      for (const it of m.items) {
        if (!it || !it.to) continue;
        enqueue(it.to, { id, from: ws.number, to: it.to, payload: it.payload, ts: Date.now() });
        deliver(it.to);
      }
      ws.send(JSON.stringify({ type: 'ack', id }));
      return;
    }

    // the org can wipe everything it stores (delete = no trace)
    if (m.type === 'wipe' && process.env.ALLOW_WIPE === '1') {
      queues.clear();
      ws.send(JSON.stringify({ type: 'wiped' }));
      return;
    }
  });
  ws.on('close', () => { if (ws.number && online.get(ws.number) === ws) online.delete(ws.number); });
});

server.listen(PORT, () => {
  console.log('[azabache-teams] blind mailbox on ws://localhost:' + PORT +
    (KEEP ? '  (KEEP: group history retained)' : '  (messages dropped after delivery)'));
});
