// teams.js — OPTIONAL group client over a self-hosted blind mailbox.
//
// This is off by default. Azabache stays serverless (P2P) unless the user points
// it at a mailbox URL. Then this connects, registers the user's number, and lets
// them send/receive GROUP messages. All content is end-to-end encrypted with
// group.js (fresh per-message key, wrapped per member). The mailbox only ever
// sees opaque payloads addressed to numbers.
//
// Usage:
//   const t = Teams.connect(url, me, { onMessage });  // me = {number, pub, privateKey}
//   t.setMembers([{number, pub}, ...]);               // current group roster
//   await t.send('hola equipo');                      // encrypts + fans out
//   t.close();

(function (root) {
  const Group = (typeof require !== 'undefined') ? require('./group.js') : root.Group;

  function connect(url, me, opts = {}) {
    const WS = (typeof WebSocket !== 'undefined') ? WebSocket : require('ws');
    const ws = new WS(url);
    let members = [];           // [{number, pub}] — the current roster (excludes me for fan-out)
    let ready = false;
    const onOpen = () => { ws.send(JSON.stringify({ type: 'register', number: me.number })); };
    ws.addEventListener ? ws.addEventListener('open', onOpen) : ws.on('open', onOpen);

    const handle = async (raw) => {
      let m; try { m = JSON.parse(raw.data !== undefined ? raw.data : raw); } catch { return; }
      if (m.type === 'registered') { ready = true; if (opts.onReady) opts.onReady(); return; }
      if (m.type === 'msg' && m.payload) {
        try {
          const packet = JSON.parse(m.payload);
          const text = await Group.decryptFromGroup(packet, me.privateKey, me.number);
          if (opts.onMessage) opts.onMessage({ from: m.from, group: packet.g || null, text, ts: m.ts });
        } catch (e) { /* not for us / undecryptable — ignore */ }
      }
    };
    ws.addEventListener ? ws.addEventListener('message', (e) => handle(e)) : ws.on('message', (d) => handle(d));

    // Encrypt one message and fan it out: each recipient gets ONLY their envelope.
    async function send(text, groupId) {
      const roster = members.filter((x) => x.number !== me.number);
      const pkt = await Group.encryptForGroup(text, roster);
      const items = roster.map((mbr) => ({
        to: mbr.number,
        payload: JSON.stringify({ iv: pkt.iv, ct: pkt.ct, eph: pkt.eph, g: groupId || null, wraps: { [mbr.number]: pkt.wraps[mbr.number] } })
      }));
      ws.send(JSON.stringify({ type: 'send', items }));
    }

    return {
      setMembers: (list) => { members = list; },
      send,
      isReady: () => ready,
      close: () => ws.close(),
      _ws: ws
    };
  }

  const api = { connect };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Teams = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
