# Azabache

A minimal, private, peer-to-peer web messenger. **No server ever reads your
messages or stores your contacts.** Built for important, private conversations.

> Status: **identity core done and tested.** Signaling + WebRTC transport next.

## How it works

**Your number is your key.** Your identity is an ECDH (P-256) keypair generated
in your browser. The "number" other people add you by (`5KZG-AOJC-…`) is the
fingerprint (SHA-256) of your public key — so **nobody can claim your number
without your private key.** Impersonation is cryptographically impossible.

**Messages are end-to-end encrypted.** Both peers derive the same shared secret
from each other's public key (ECDH) and encrypt with AES-256-GCM. What travels
the network is ciphertext only.

## Two modes

- **Rotating** — a fresh ephemeral identity each time you open the app. When you
  close it, the keypair and all messages are wiped. For one-off, important talks.
- **Fixed** — a persistent identity. The private key is stored on your machine
  **encrypted with a password**; message history is kept in your own folder.
  The number stays the same because the key stays the same.

## Transport & privacy model

- **WebRTC data channel**, browser-to-browser, end-to-end encrypted.
- A small **blind presence/signaling server** only helps two peers find each
  other and shows who is online — it **never sees message content**, keyed only
  by public-key numbers.
- **Offline:** a sender-side outbox delivers when both peers are online (no
  message server at all). Honest tradeoff: delivery needs your online times to
  overlap at least once. Maximum privacy, in exchange for that.

## Run (same on every OS)

Needs [Node.js](https://nodejs.org). One command, one port — identical on any
Linux distro, Windows, or macOS:

```bash
npm install        # once (pulls the ws dependency)
node server.js     # then open the printed URL, e.g. http://localhost:8790
```

The chat itself runs in the **browser**, so anyone on any OS just opens the
page — nothing to install for the people chatting.

### Serverless mode (no server at all)

Open `manual.html` instead. One person clicks *create invite code* and sends
the code to the other by any channel; the other pastes it, sends back the
answer code, and they're connected — **directly, peer-to-peer, end-to-end
encrypted, with no signaling server and nothing always-on.** Messages live only
on the two devices; if both go offline, the message is gone and no one else ever
had access.

## Files

- `web/identity.js` — cryptographic identity core (keypair, number, E2E encrypt).
- `test_identity.js` — proof of the above (`node test_identity.js`).

No dependencies for the core: only the Web Crypto API built into browsers/Node.
