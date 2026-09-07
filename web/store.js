// store.js — local, private storage. No server, ever.
//
// Everything lives in this browser's own IndexedDB (private to this site, on
// THIS device). Nothing leaves the machine. "Delete account" wipes it all —
// contacts, history, and your saved identity — leaving no trace (the Law).
//
// Stores:
//   meta     -> your own identity (fixed mode): { id:'self', priv, pub, number }
//   contacts -> people you've talked to: { number, name, pub, lastSeen }
//   messages -> chat history: { id++, peer, dir:'in'|'out', kind:'text'|'photo', body, ts }

(function (root) {
  const DB = 'azabache';
  let db = null;

  function open() {
    return new Promise((res, rej) => {
      if (db) return res(db);
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => {
        const d = r.result;
        if (!d.objectStoreNames.contains('meta')) d.createObjectStore('meta', { keyPath: 'id' });
        if (!d.objectStoreNames.contains('contacts')) d.createObjectStore('contacts', { keyPath: 'number' });
        if (!d.objectStoreNames.contains('messages')) {
          const m = d.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
          m.createIndex('peer', 'peer', { unique: false });
        }
      };
      r.onsuccess = () => { db = r.result; res(db); };
      r.onerror = () => rej(r.error);
    });
  }

  function tx(store, mode, fn) {
    return open().then((d) => new Promise((res, rej) => {
      const t = d.transaction(store, mode);
      const out = fn(t.objectStore(store));
      // If fn returned an IDBRequest, resolve with its .result (which may be
      // undefined when a get finds nothing — that's a valid "not found").
      const isReq = out instanceof IDBRequest;
      t.oncomplete = () => res(isReq ? out.result : out);
      t.onerror = () => rej(t.error);
    }));
  }

  // ---- contacts ----
  const saveContact = (c) => tx('contacts', 'readwrite', (s) => s.put(c));
  const getContacts = () => tx('contacts', 'readonly', (s) => s.getAll());
  const getContact = (number) => tx('contacts', 'readonly', (s) => s.get(number));

  // ---- messages ----
  const addMessage = (m) => tx('messages', 'readwrite', (s) => s.add(m));
  function history(peer) {
    return open().then((d) => new Promise((res, rej) => {
      const out = [];
      const idx = d.transaction('messages', 'readonly').objectStore('messages').index('peer');
      const cur = idx.openCursor(IDBKeyRange.only(peer));
      cur.onsuccess = (e) => { const c = e.target.result; if (c) { out.push(c.value); c.continue(); } else res(out); };
      cur.onerror = () => rej(cur.error);
    }));
  }

  // ---- self identity (fixed mode) ----
  const saveSelf = (obj) => tx('meta', 'readwrite', (s) => s.put({ id: 'self', ...obj }));
  const getSelf = () => tx('meta', 'readonly', (s) => s.get('self'));

  // ---- encrypted vault (single blob; only the real password decrypts it) ----
  const setVault = (blob) => tx('meta', 'readwrite', (s) => s.put({ id: 'vault', blob }));
  const getVault = () => tx('meta', 'readonly', (s) => s.get('vault')).then((r) => r && r.blob);

  // ---- delete account = wipe everything, no trace ----
  // Clear every store in one transaction (deterministic — no deleteDatabase
  // "blocked" race), then drop the database itself for good measure.
  function wipe() {
    return open().then((d) => new Promise((res, rej) => {
      const t = d.transaction(['meta', 'contacts', 'messages'], 'readwrite');
      t.objectStore('meta').clear();
      t.objectStore('contacts').clear();
      t.objectStore('messages').clear();
      t.oncomplete = () => {
        d.close(); db = null;
        const r = indexedDB.deleteDatabase(DB);
        r.onsuccess = r.onerror = r.onblocked = () => res(true);
      };
      t.onerror = () => rej(t.error);
    }));
  }

  root.Store = { saveContact, getContacts, getContact, addMessage, history, saveSelf, getSelf, setVault, getVault, wipe };
})(typeof globalThis !== 'undefined' ? globalThis : this);
