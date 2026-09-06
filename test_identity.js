// Proof that the identity core works: two people derive the same shared key
// from exchanged public keys, encrypt/decrypt end-to-end, the number is stable,
// and nobody else can hold your number. Run: node test_identity.js
const I = require('./web/identity.js');

(async () => {
  const alice = await I.generateIdentity();
  const bob = await I.generateIdentity();
  console.log('Alice number:', alice.number);
  console.log('Bob   number:', bob.number);

  // peers exchange public keys (this is what travels over signaling)
  const alicePub = await I.exportPublicKey(alice.publicKey);
  const bobPub = await I.exportPublicKey(bob.publicKey);

  // each imports the other's key and derives the SAME secret
  const kA = await I.deriveSharedKey(alice.privateKey, await I.importPublicKey(bobPub));
  const kB = await I.deriveSharedKey(bob.privateKey, await I.importPublicKey(alicePub));

  const packet = await I.encrypt(kA, 'hola bob, esto va cifrado E2E');
  console.log('what actually travels (ciphertext):', packet.ct.slice(0, 44) + '...');
  const decrypted = await I.decrypt(kB, packet);
  console.log('Bob decrypted:', JSON.stringify(decrypted));

  // number is deterministic from the public key
  const aliceAgain = await I.numberFromPublicKey(await I.importPublicKey(alicePub));
  console.log('number stable across export/import:', aliceAgain === alice.number);

  // impersonation check: a different key => a different number
  const mallory = await I.generateIdentity();
  console.log('Mallory cannot reuse Alice number:', mallory.number !== alice.number);

  const ok = decrypted === 'hola bob, esto va cifrado E2E'
    && aliceAgain === alice.number && mallory.number !== alice.number;
  console.log(ok ? '\nALL CHECKS PASSED' : '\nSOMETHING FAILED');
  process.exit(ok ? 0 : 1);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
