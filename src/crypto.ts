import nacl from 'tweetnacl'
import { encodeBase64, decodeBase64 } from 'tweetnacl-util'

// ─── Types ───────────────────────────────────────────────────────

export interface Attachment {
  type: 'audio' | 'image'
  mime: string
  data: string // base64-encoded binary
}

export interface MessagePayload {
  text?: string
  attachments?: Attachment[]
  ratchetKey: string // base64 ephemeral public key for DH ratchet
}

// ─── Key Generation ───────────────────────────────────────────────

export function generateKeyPair() {
  const kp = nacl.box.keyPair()
  console.log('[KeyGen] Generated X25519 key pair')
  console.log('[KeyGen] Public key:', encodeBase64(kp.publicKey))
  console.log('[KeyGen] Secret key length:', kp.secretKey.length, 'bytes')
  return { publicKey: kp.publicKey, secretKey: kp.secretKey }
}

// ─── ECDH Shared Secret ──────────────────────────────────────────

export function computeSharedSecret(
  ourSecretKey: Uint8Array,
  theirPublicKey: Uint8Array
): Uint8Array {
  console.log('[ECDH] Computing shared secret...')
  console.log('[ECDH] Our secret key length:', ourSecretKey.length, 'bytes')
  console.log('[ECDH] Their public key:', encodeBase64(theirPublicKey))

  const shared = nacl.box.before(theirPublicKey, ourSecretKey)

  console.log('[ECDH] Shared secret computed:', encodeBase64(shared))
  console.log('[ECDH] Shared secret length:', shared.length, 'bytes')
  return shared
}

// ─── KDF (SHA-512 based) ─────────────────────────────────────────

function kdf(input: Uint8Array): Uint8Array {
  return nacl.hash(input).slice(0, 32)
}

// ─── Chain Key Derivation ────────────────────────────────────────

function compareKeys(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i]! < b[i]!) return -1
    if (a[i]! > b[i]!) return 1
  }
  return 0
}

export function deriveChainKeys(
  sharedSecret: Uint8Array,
  ourPublicKey: Uint8Array,
  theirPublicKey: Uint8Array
) {
  console.log('[ChainDerive] Deriving send/receive chain keys from shared secret...')

  const weAreSmaller = compareKeys(ourPublicKey, theirPublicKey) < 0
  console.log('[ChainDerive] Our public key is lexicographically', weAreSmaller ? 'SMALLER' : 'LARGER')

  const input1 = new Uint8Array(sharedSecret.length + 1)
  input1.set(sharedSecret)
  input1[sharedSecret.length] = 0x01

  const input2 = new Uint8Array(sharedSecret.length + 1)
  input2.set(sharedSecret)
  input2[sharedSecret.length] = 0x02

  const chain1 = kdf(input1)
  const chain2 = kdf(input2)

  const sendChain = weAreSmaller ? chain1 : chain2
  const recvChain = weAreSmaller ? chain2 : chain1

  console.log('[ChainDerive] Send chain key:', encodeBase64(sendChain))
  console.log('[ChainDerive] Recv chain key:', encodeBase64(recvChain))
  console.log('[ChainDerive] Chain keys derived successfully')

  return { sendChain, recvChain }
}

// ─── Symmetric Ratchet (Forward Secrecy) ─────────────────────────

export function ratchetStep(chainKey: Uint8Array): {
  nextChainKey: Uint8Array
  messageKey: Uint8Array
} {
  const ckInput = new Uint8Array(chainKey.length + 1)
  ckInput.set(chainKey)
  ckInput[chainKey.length] = 0x01

  const mkInput = new Uint8Array(chainKey.length + 1)
  mkInput.set(chainKey)
  mkInput[chainKey.length] = 0x02

  const nextChainKey = kdf(ckInput)
  const messageKey = kdf(mkInput)

  console.log('[Ratchet] Chain key advanced')
  console.log('[Ratchet] Previous chain key:', encodeBase64(chainKey))
  console.log('[Ratchet] New chain key:     ', encodeBase64(nextChainKey))
  console.log('[Ratchet] Message key:       ', encodeBase64(messageKey))

  return { nextChainKey, messageKey }
}

// ─── DH Ratchet ──────────────────────────────────────────────────
// Incorporates fresh ECDH material into a chain key.
// After each message, the chain is updated with DH(our_new_secret, peer_public)
// so future messages are protected even if current chain is compromised.

export function dhRatchet(
  chainKey: Uint8Array,
  ourSecretKey: Uint8Array,
  theirPublicKey: Uint8Array
): Uint8Array {
  console.log('[DH-Ratchet] Incorporating fresh ECDH into chain...')
  console.log('[DH-Ratchet] Their public key:', encodeBase64(theirPublicKey))

  const dhShared = nacl.box.before(theirPublicKey, ourSecretKey)
  console.log('[DH-Ratchet] DH shared:', encodeBase64(dhShared))

  const input = new Uint8Array(chainKey.length + dhShared.length)
  input.set(chainKey)
  input.set(dhShared, chainKey.length)

  const newChain = kdf(input)
  console.log('[DH-Ratchet] New chain key:', encodeBase64(newChain))

  return newChain
}

// ─── Encrypt (JSON envelope) ─────────────────────────────────────

export function encryptMessage(messageKey: Uint8Array, payload: MessagePayload): string {
  console.log('[Encrypt] Encrypting message...')
  console.log('[Encrypt] Text:', payload.text ? `${payload.text.length} chars` : 'none')
  console.log('[Encrypt] Attachments:', payload.attachments?.length ?? 0)
  payload.attachments?.forEach((a, i) => {
    console.log(`[Encrypt]   [${i}] ${a.type} (${a.mime}), data: ${a.data.length} base64 chars`)
  })
  console.log('[Encrypt] Ratchet key:', payload.ratchetKey.slice(0, 16) + '...')
  console.log('[Encrypt] Message key:', encodeBase64(messageKey))

  const json = JSON.stringify(payload)
  const plainBytes = new TextEncoder().encode(json)
  console.log(`[Encrypt] JSON payload: ${plainBytes.length} bytes`)

  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  console.log('[Encrypt] Nonce:', encodeBase64(nonce))

  const ciphertext = nacl.secretbox(plainBytes, nonce, messageKey)

  const combined = new Uint8Array(nonce.length + ciphertext.length)
  combined.set(nonce)
  combined.set(ciphertext, nonce.length)

  const encoded = encodeBase64(combined)
  console.log(`[Encrypt] Ciphertext: ${ciphertext.length} bytes → Base64: ${encoded.length} chars`)

  return encoded
}

// ─── Decrypt (JSON envelope) ─────────────────────────────────────

export function decryptMessage(messageKey: Uint8Array, encoded: string): MessagePayload | null {
  console.log('[Decrypt] Decrypting message...')
  console.log(`[Decrypt] Base64 input: ${encoded.length} chars`)
  console.log('[Decrypt] Message key:', encodeBase64(messageKey))

  const combined = decodeBase64(encoded)
  const nonce = combined.slice(0, nacl.secretbox.nonceLength)
  const ciphertext = combined.slice(nacl.secretbox.nonceLength)

  console.log('[Decrypt] Nonce:', encodeBase64(nonce))
  console.log(`[Decrypt] Ciphertext: ${ciphertext.length} bytes`)

  const plainBytes = nacl.secretbox.open(ciphertext, nonce, messageKey)
  if (!plainBytes) {
    console.error('[Decrypt] FAILED — authentication error (wrong key or tampered data)')
    return null
  }

  const json = new TextDecoder().decode(plainBytes)
  const payload: MessagePayload = JSON.parse(json)

  console.log('[Decrypt] Success!')
  console.log('[Decrypt] Text:', payload.text ? `${payload.text.length} chars` : 'none')
  console.log('[Decrypt] Attachments:', payload.attachments?.length ?? 0)
  payload.attachments?.forEach((a, i) => {
    console.log(`[Decrypt]   [${i}] ${a.type} (${a.mime}), data: ${a.data.length} base64 chars`)
  })
  console.log('[Decrypt] Ratchet key:', payload.ratchetKey.slice(0, 16) + '...')

  return payload
}

// ─── Helpers ─────────────────────────────────────────────────────

export function bytesToBase64(bytes: Uint8Array): string {
  return encodeBase64(bytes)
}

export function base64ToBytes(b64: string): Uint8Array {
  return decodeBase64(b64)
}

export { encodeBase64, decodeBase64 }
