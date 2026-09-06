// identity.js — cryptographic identity core (runs in the browser AND in Node).
//
// A user's "number" is the fingerprint of their PUBLIC key: nobody can claim
// your number without holding your private key. Messages are end-to-end
// encrypted with a shared secret each side derives via ECDH (P-256), used as
// an AES-256-GCM key. No server ever sees a private key or a plaintext.
//
// No dependencies: only the Web Crypto API, present in modern browsers and Node.

(function (root) {
  const subtle = (globalThis.crypto || {}).subtle;

  // ---- tiny encoders (work in both environments) ----
  function bytesToB64(buf) {
    const arr = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin);
  }
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  // base32 (A-Z 2-7) for a human-readable, typo-resistant number
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function base32(bytes) {
    let bits = 0, value = 0, out = '';
    for (const b of bytes) {
      value = (value << 8) | b; bits += 8;
      while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out;
  }

  // Generate a fresh identity: an ECDH keypair + its derived number.
  async function generateIdentity() {
    const kp = await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const number = await numberFromPublicKey(kp.publicKey);
    return { publicKey: kp.publicKey, privateKey: kp.privateKey, number };
  }

  // The public key travels between peers (over signaling) as this string.
  async function exportPublicKey(publicKey) {
    return bytesToB64(await subtle.exportKey('raw', publicKey));
  }
  async function importPublicKey(b64) {
    return subtle.importKey('raw', b64ToBytes(b64),
      { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  }

  // number = SHA-256(raw public key), first 15 bytes as base32, grouped in 4s.
  // Deterministic: the same key always yields the same number.
  async function numberFromPublicKey(publicKey) {
    const raw = await subtle.exportKey('raw', publicKey);
    const hash = await subtle.digest('SHA-256', raw);
    return base32(new Uint8Array(hash).slice(0, 15)).match(/.{1,4}/g).join('-');
  }

  // Both peers derive the SAME AES key from (my private, their public).
  async function deriveSharedKey(privateKey, theirPublicKey) {
    return subtle.deriveKey(
      { name: 'ECDH', public: theirPublicKey }, privateKey,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function encrypt(sharedKey, plaintext) {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv },
      sharedKey, new TextEncoder().encode(plaintext));
    return { iv: bytesToB64(iv), ct: bytesToB64(ct) };
  }
  async function decrypt(sharedKey, packet) {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(packet.iv) },
      sharedKey, b64ToBytes(packet.ct));
    return new TextDecoder().decode(pt);
  }

  const api = { generateIdentity, exportPublicKey, importPublicKey,
    numberFromPublicKey, deriveSharedKey, encrypt, decrypt };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Identity = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
