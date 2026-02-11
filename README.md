# XChat

End-to-end encrypted messenger with no server or transport layer. All message exchange happens via copy/paste — you encrypt a message, copy the ciphertext, and send it through any channel you like.

## How It Works

1. **Key Exchange** — Both parties generate X25519 key pairs and exchange public keys via copy/paste textareas.
2. **Handshake** — ECDH shared secret is computed, then deterministically split into send/receive chain keys.
3. **Messaging** — Messages are encrypted with XSalsa20-Poly1305 using keys derived from a Double Ratchet:
   - **Symmetric ratchet** — hash chain advanced per message (forward secrecy).
   - **DH ratchet** — each message includes a fresh ephemeral Curve25519 public key, incorporated into the chain for post-compromise security.

## Features

- Text messages, voice recordings, and images in a single encrypted JSON payload
- Voice recording via MediaRecorder API (Opus/WebM, max 60 seconds)
- Image attachments via drag & drop, file picker (multiple), or Ctrl+V paste
- Multiple attachments per message
- Double Ratchet (symmetric + DH) for forward secrecy
- Verbose `console.log()` at every cryptographic stage for transparency
- No backend, no WebSocket, no database — purely client-side

## Message Format

Each message is a JSON object encrypted as a whole:

```json
{
  "text": "Hello!",
  "attachments": [
    { "type": "image", "mime": "image/png", "data": "<base64>" },
    { "type": "audio", "mime": "audio/webm;codecs=opus", "data": "<base64>" }
  ],
  "ratchetKey": "<base64 ephemeral X25519 public key>"
}
```

The JSON is encrypted with `nacl.secretbox` (XSalsa20-Poly1305), and the output is `base64(nonce + ciphertext)`.

## Stack

- Vue 3 (Composition API, `<script setup>`)
- TypeScript
- Vite
- Tailwind CSS v4
- SCSS (sass-embedded)
- tweetnacl / tweetnacl-util

## Setup

```bash
npm install
npm run dev
```

Open two browser tabs, generate keys in both, exchange public keys, and start chatting.

## Build

```bash
npm run build
npm run preview
```
