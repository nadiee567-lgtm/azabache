// group.js — group messaging with per-message keys, wrapped to each member.
//
// Security model (envelope / ECIES with vetted primitives only — no home-made
// protocol): every message gets a FRESH random AES-256 key. The message is
// encrypted once with that key. The key is then "wrapped" (encrypted) separately
// for each current member, using an ephemeral ECDH handshake to that member's
// public key. The server fans out one ciphertext + the small per-member wraps,
// and can read none of it.
//
// Why this and not a static shared key:
//   - Per-message key: one message's key never reveals another's.
//   - Clean member removal: to remove someone, just stop wrapping to them. Future
//     messages are unreadable to them with NO global re-key ceremony.
//   - Ephemeral sender key per message: the long-term keys aren't used to encrypt
//     content directly.
//
// Honest limits (told plainly): this is NOT a ratchet (no perfect forward secrecy
// or post-compromise security like Signal/MLS). A member's leaked PRIVATE key can
// open messages that were wrapped to them. The relay still sees metadata. For a
// life-critical threat model, use an audited tool. This is strong, correct,
// hobby-grade group crypto — not a substitute for a security audit.

(function (root) {
  const ID = (typeof require !== 'undefined') ? require('./identity.js') : root.Identity;
  const subtle = crypto.subtle;
  const b64 = (buf) => { const a = new Uint8Array(buf); let s = ''; for (const x of a) s += String.fromCharCode(x); return btoa(s); };
  const unb64 = (s) => { const b = atob(s); const a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; };

  // Encrypt one message for the given members.
  // members: [{ number, pub }]  (pub = base64 raw public key)
  // returns { iv, ct, eph, wraps: { number: {iv, ct} } }  — all opaque to the server.
  async function encryptForGroup(plaintext, members) {
    // fresh per-message AES-256 key
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const msgKey = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, msgKey, new TextEncoder().encode(plaintext));

    // ephemeral ECDH keypair used only to wrap this message's key
    const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    const ephPub = await ID.exportPublicKey(eph.publicKey);

    const wraps = {};
    for (const m of members) {
      const memberPub = await ID.importPublicKey(m.pub);
      const wrapKey = await ID.deriveSharedKey(eph.privateKey, memberPub); // AES-GCM
      const wiv = crypto.getRandomValues(new Uint8Array(12));
      const wct = await subtle.encrypt({ name: 'AES-GCM', iv: wiv }, wrapKey, raw);
      wraps[m.number] = { iv: b64(wiv), ct: b64(wct) };
    }
    return { iv: b64(iv), ct: b64(ct), eph: ephPub, wraps };
  }

  // Decrypt a group message addressed to me. myPrivateKey = my ECDH private key.
  async function decryptFromGroup(packet, myPrivateKey, myNumber) {
    const wrap = packet.wraps[myNumber];
    if (!wrap) throw new Error('not a recipient'); // no envelope for us => cannot read
    const ephPub = await ID.importPublicKey(packet.eph);
    const wrapKey = await ID.deriveSharedKey(myPrivateKey, ephPub);
    const raw = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(wrap.iv) }, wrapKey, unb64(wrap.ct));
    const msgKey = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(packet.iv) }, msgKey, unb64(packet.ct));
    return new TextDecoder().decode(pt);
  }

  const api = { encryptForGroup, decryptFromGroup };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Group = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
