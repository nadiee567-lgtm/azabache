# Azabache Teams — self-hosted blind mailbox

**Optional.** Azabache is serverless by default. A company or group that wants
**groups** and **guaranteed offline delivery** ("messages always arrive") runs
this small server on their **own** machine. It stores only **ciphertext** it
cannot read — the same end-to-end privacy, now with a mailbox they control.

## Run (any OS)

```bash
npm install ws
node server/mailbox.js
```

Environment variables:

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `8811` | Port to listen on. |
| `KEEP` | off | `KEEP=1` retains delivered messages (persistent group history). Off = drop after delivery. |
| `ALLOW_WIPE` | off | `ALLOW_WIPE=1` enables the `wipe` command (delete everything the server stores). |

## What it sees, and what it doesn't

- **Never:** message plaintext, or any private key. It only relays/stores opaque
  `iv`/`ct` blobs addressed to public-key numbers.
- **Does see (honest cost of offline delivery):** metadata — which numbers talk,
  when, and message size. It's the org's OWN server, not a third party.

## Status

Verified: offline delivery on reconnect, live delivery, group fan-out, and
ciphertext-only relay. Next blocks: group key management (shared-key v1) and
wiring the web client to an optional mailbox URL.
