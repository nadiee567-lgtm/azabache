// session.js — encrypted-at-rest vault with a decoy ("Google technique").
//
// There is only ONE encrypted blob: your real data. Nothing about a decoy is
// stored, so nothing can betray it.
//
//   - The REAL password decrypts the blob  -> your real contacts + messages.
//   - ANY OTHER password (your chosen decoy, or a wrong guess) -> a clean, empty
//     session, exactly like a freshly installed app. Real data is never touched
//     and its existence is never revealed.
//
// A decoy session is EPHEMERAL: nothing it does is written back to the real
// vault, so using the decoy can't corrupt or expose your real data.
//
// Honest limit: this defeats CASUAL inspection (someone grabbing your device),
// NOT a determined forensic examiner — a single encrypted blob still shows *an*
// account exists. Deniable enough for a coerced glance, not for a lab.

(function (root) {
  let mode = null;          // 'real' | 'decoy'
  let realPassword = null;  // held in memory only during a real session
  let data = { contacts: [], messages: [] };

  const empty = () => ({ contacts: [], messages: [] });

  // First run? (no vault yet)
  const isFirstRun = async () => !(await Store.getVault());

  // Create the real vault with the chosen real password.
  async function setup(password) {
    data = empty();
    realPassword = password;
    mode = 'real';
    await persist();
    return { mode };
  }

  // Try to unlock with a password.
  async function unlock(password) {
    const blob = await Store.getVault();
    if (!blob) return { firstRun: true };
    try {
      data = JSON.parse(await Vault.decryptText(blob, password));
      realPassword = password;
      mode = 'real';
      return { mode: 'real', data };
    } catch (e) {
      // wrong or decoy password -> empty, ephemeral session; real vault untouched
      data = empty();
      realPassword = null;
      mode = 'decoy';
      return { mode: 'decoy', data };
    }
  }

  // Save current data — ONLY in a real session (decoy never writes back).
  // Writes are SERIALIZED through a promise chain: rapid addContact/addMessage
  // calls would otherwise race, and a slower encrypt with stale data could clobber
  // a newer one (losing messages). The chain guarantees the last write wins.
  let writeChain = Promise.resolve();
  function persist() {
    if (mode !== 'real') return Promise.resolve(false);
    writeChain = writeChain.then(async () => {
      await Store.setVault(await Vault.encryptText(JSON.stringify(data), realPassword));
      return true;
    });
    return writeChain;
  }

  // data accessors used by the app
  const getData = () => data;
  async function addContact(c) {
    const i = data.contacts.findIndex((x) => x.number === c.number);
    if (i >= 0) data.contacts[i] = c; else data.contacts.push(c);
    await persist();
  }
  async function addMessage(m) { data.messages.push(m); await persist(); }
  const historyWith = (peer) => data.messages.filter((m) => m.peer === peer);
  const getMode = () => mode;

  root.Session = { isFirstRun, setup, unlock, persist, getData, addContact, addMessage, historyWith, getMode };
})(typeof globalThis !== 'undefined' ? globalThis : this);
