// vault.js — password-based encryption for ANYONE, technical or not.
//
// Encrypt a message or a file with just a password. The output is a self-
// contained blob that only that password can open — paste it in any chat, email
// or file. This is the answer to "Chat Control": even if a platform is forced to
// scan messages, it only sees ciphertext.
//
// Key derivation: PBKDF2-SHA256, 250k iterations, random 16-byte salt per blob.
// Cipher: AES-256-GCM with a random 12-byte IV. No server, all in the browser.

(function (root) {
  const subtle = crypto.subtle;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = (buf) => { const a = new Uint8Array(buf); let s = ''; for (const x of a) s += String.fromCharCode(x); return btoa(s); };
  const unb64 = (s) => { const b = atob(s); const a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; };

  async function keyFromPassword(password, salt) {
    const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  // Encrypt bytes -> a compact JSON blob { v, salt, iv, ct }.
  async function encryptBytes(bytes, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await keyFromPassword(password, salt);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
  }
  async function decryptBytes(blob, password) {
    const o = JSON.parse(blob);
    const key = await keyFromPassword(password, unb64(o.salt));
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, key, unb64(o.ct));
    return new Uint8Array(pt);
  }

  // text helpers
  const encryptText = (text, pw) => encryptBytes(enc.encode(text), pw);
  const decryptText = async (blob, pw) => dec.decode(await decryptBytes(blob, pw));

  // file helpers (returns/takes a Blob)
  async function encryptFile(file, pw) {
    return encryptBytes(new Uint8Array(await file.arrayBuffer()), pw);
  }
  async function decryptToBlob(blob, pw) {
    return new Blob([await decryptBytes(blob, pw)]);
  }

  root.Vault = { encryptText, decryptText, encryptFile, decryptToBlob };
})(typeof globalThis !== 'undefined' ? globalThis : this);
