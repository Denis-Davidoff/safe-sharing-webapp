<script setup lang="ts">
import { ref, reactive, computed, onBeforeUnmount } from 'vue'
import {
  generateKeyPair,
  computeSharedSecret,
  deriveChainKeys,
  ratchetStep,
  dhRatchet,
  encryptMessage,
  decryptMessage,
  bytesToBase64,
  base64ToBytes,
  encodeBase64,
  decodeBase64,
  type Attachment,
  type MessagePayload,
} from './crypto'

// ─── State ───────────────────────────────────────────────────────

type Phase = 'idle' | 'waiting' | 'ready'

const phase = ref<Phase>('idle')

// Identity keys (from handshake)
const keyPair = ref<{ publicKey: Uint8Array; secretKey: Uint8Array } | null>(null)
const peerPublicKey = ref<Uint8Array | null>(null)

// Chain keys (symmetric ratchet)
const sendChain = ref<Uint8Array | null>(null)
const recvChain = ref<Uint8Array | null>(null)

// DH ratchet keys
const ourRatchetKeyPair = ref<{ publicKey: Uint8Array; secretKey: Uint8Array } | null>(null)
const peerRatchetPublic = ref<Uint8Array | null>(null)

const sendMessageCount = ref(0)
const recvMessageCount = ref(0)

// UI fields
const peerPublicKeyInput = ref('')
const plaintextInput = ref('')
const encryptedOutput = ref('')
const peerEncryptedInput = ref('')

// Attachments (multiple)
interface UIAttachment {
  id: number
  type: 'audio' | 'image'
  data: Uint8Array
  mime: string
  previewUrl: string
}
let attachmentIdCounter = 0
const attachments = reactive<UIAttachment[]>([])

// Recording
const isRecording = ref(false)
const recordingSeconds = ref(0)
let mediaRecorder: MediaRecorder | null = null
let audioChunks: Blob[] = []
let recordingTimer: ReturnType<typeof setInterval> | null = null

// Drop zone
const isDragging = ref(false)

// Decrypted result
const decryptedResult = ref<{
  text?: string
  attachments?: Array<{ type: 'audio' | 'image'; blobUrl: string }>
} | null>(null)

// Message history
interface ChatMessage {
  direction: 'sent' | 'received'
  text?: string
  attachments?: Array<{ type: 'audio' | 'image'; blobUrl: string }>
}
const messages = reactive<ChatMessage[]>([])

// Blob URL tracking
const blobUrls: string[] = []
function createBlobUrl(blob: Blob): string {
  const url = URL.createObjectURL(blob)
  blobUrls.push(url)
  return url
}

const statusText = computed(() => {
  switch (phase.value) {
    case 'idle': return 'Click "Generate Keys" to start handshake'
    case 'waiting': return 'Exchange public keys with your peer'
    case 'ready': return 'Secure channel established — send encrypted messages'
  }
})

const canEncrypt = computed(() => {
  return attachments.length > 0 || plaintextInput.value.trim().length > 0
})

// ─── Handshake ───────────────────────────────────────────────────

function startHandshake() {
  console.log('═══════════════════════════════════════════')
  console.log('[Phase 1] Generating ECDH key pair (Curve25519)...')
  console.log('═══════════════════════════════════════════')

  keyPair.value = generateKeyPair()
  phase.value = 'waiting'

  console.log('[Phase 1] Key pair generated. Waiting for peer public key.')
}

function completeHandshake() {
  if (!keyPair.value || !peerPublicKeyInput.value.trim()) return

  console.log('═══════════════════════════════════════════')
  console.log('[Phase 2] Completing ECDH handshake...')
  console.log('═══════════════════════════════════════════')

  try {
    const theirPub = decodeBase64(peerPublicKeyInput.value.trim())
    peerPublicKey.value = theirPub

    const shared = computeSharedSecret(keyPair.value.secretKey, theirPub)

    console.log('═══════════════════════════════════════════')
    console.log('[Phase 3] Deriving chain keys for Forward Secrecy...')
    console.log('═══════════════════════════════════════════')

    const chains = deriveChainKeys(shared, keyPair.value.publicKey, theirPub)
    sendChain.value = chains.sendChain
    recvChain.value = chains.recvChain

    // Initialize DH ratchet with identity keys
    ourRatchetKeyPair.value = { publicKey: keyPair.value.publicKey, secretKey: keyPair.value.secretKey }
    peerRatchetPublic.value = theirPub

    phase.value = 'ready'

    console.log('[Phase 3] Secure channel established!')
    console.log('[Phase 3] DH ratchet initialized with identity keys.')
  } catch (e) {
    console.error('[Handshake] Error:', e)
    alert('Invalid public key format.')
  }
}

// ─── Voice Recording ─────────────────────────────────────────────

function getSupportedAudioMime(): string {
  const types = ['audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus']
  for (const t of types) {
    if (MediaRecorder.isTypeSupported(t)) return t
  }
  return ''
}

async function toggleRecording() {
  if (isRecording.value) {
    stopRecording()
  } else {
    await startRecording()
  }
}

async function startRecording() {
  console.log('[Audio] Requesting microphone access...')
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
    const mime = getSupportedAudioMime()
    console.log(`[Audio] Recording started (MIME: ${mime || 'default'})`)

    mediaRecorder = mime
      ? new MediaRecorder(stream, { mimeType: mime })
      : new MediaRecorder(stream)
    audioChunks = []

    mediaRecorder.ondataavailable = (e) => {
      if (e.data.size > 0) audioChunks.push(e.data)
    }

    mediaRecorder.onstop = async () => {
      const actualMime = mediaRecorder?.mimeType || 'audio/webm'
      const blob = new Blob(audioChunks, { type: actualMime })
      const buffer = await blob.arrayBuffer()

      console.log(`[Audio] Recording complete: ${buffer.byteLength} bytes, MIME: ${actualMime}`)

      attachments.push({
        id: ++attachmentIdCounter,
        type: 'audio',
        data: new Uint8Array(buffer),
        mime: actualMime,
        previewUrl: createBlobUrl(blob),
      })
      stream.getTracks().forEach(t => t.stop())
    }

    mediaRecorder.start()
    isRecording.value = true
    recordingSeconds.value = 0

    recordingTimer = setInterval(() => {
      recordingSeconds.value++
      if (recordingSeconds.value >= 60) {
        console.log('[Audio] Max 60s reached, stopping...')
        stopRecording()
      }
    }, 1000)
  } catch (e) {
    console.error('[Audio] Microphone access denied:', e)
    alert('Microphone access denied.')
  }
}

function stopRecording() {
  if (mediaRecorder && mediaRecorder.state !== 'inactive') {
    mediaRecorder.stop()
  }
  isRecording.value = false
  if (recordingTimer) {
    clearInterval(recordingTimer)
    recordingTimer = null
  }
}

// ─── Image Handling ──────────────────────────────────────────────

function handleImageFile(file: File) {
  if (!file.type.startsWith('image/')) {
    console.warn('[Image] Not an image file:', file.type)
    return
  }
  console.log(`[Image] Attaching: ${file.name} (${file.type}, ${file.size} bytes)`)

  const reader = new FileReader()
  reader.onload = () => {
    attachments.push({
      id: ++attachmentIdCounter,
      type: 'image',
      data: new Uint8Array(reader.result as ArrayBuffer),
      mime: file.type,
      previewUrl: createBlobUrl(file),
    })
    console.log(`[Image] Attached: ${(reader.result as ArrayBuffer).byteLength} bytes`)
  }
  reader.readAsArrayBuffer(file)
}

function onDrop(e: DragEvent) {
  e.preventDefault()
  isDragging.value = false
  const files = e.dataTransfer?.files
  if (files) {
    for (let i = 0; i < files.length; i++) {
      handleImageFile(files[i]!)
    }
  }
}

function onPaste(e: ClipboardEvent) {
  const items = e.clipboardData?.items
  if (!items) return
  for (const item of items) {
    if (item.type.startsWith('image/')) {
      e.preventDefault()
      const file = item.getAsFile()
      if (file) handleImageFile(file)
      return
    }
  }
}

function onFileInput(e: Event) {
  const input = e.target as HTMLInputElement
  const files = input.files
  if (files) {
    for (let i = 0; i < files.length; i++) {
      handleImageFile(files[i]!)
    }
  }
  input.value = ''
}

function removeAttachment(id: number) {
  const idx = attachments.findIndex(a => a.id === id)
  if (idx !== -1) attachments.splice(idx, 1)
  console.log('[Attachment] Removed')
}

// ─── Messaging ───────────────────────────────────────────────────

function encrypt() {
  if (!sendChain.value || !peerRatchetPublic.value || !canEncrypt.value) return

  const msgNum = sendMessageCount.value + 1
  console.log('═══════════════════════════════════════════')
  console.log(`[Send #${msgNum}] Encrypting with Double Ratchet...`)
  console.log('═══════════════════════════════════════════')

  // 1. Symmetric ratchet → message key
  const { nextChainKey, messageKey } = ratchetStep(sendChain.value)

  // 2. Generate new ephemeral ratchet key pair
  const newRatchetKP = generateKeyPair()
  console.log(`[Send #${msgNum}] New ephemeral ratchet key generated`)

  // 3. Build JSON payload
  const payloadAttachments: Attachment[] = attachments.map(a => ({
    type: a.type,
    mime: a.mime,
    data: bytesToBase64(a.data),
  }))

  const payload: MessagePayload = {
    ratchetKey: encodeBase64(newRatchetKP.publicKey),
  }
  if (plaintextInput.value.trim()) {
    payload.text = plaintextInput.value
  }
  if (payloadAttachments.length > 0) {
    payload.attachments = payloadAttachments
  }

  // 4. Encrypt
  console.log('[Send] JSON payload before encryption:', JSON.stringify(payload, null, 2))
  const encrypted = encryptMessage(messageKey, payload)
  encryptedOutput.value = encrypted

  // 5. DH ratchet: update send chain with fresh ECDH for NEXT message
  sendChain.value = dhRatchet(nextChainKey, newRatchetKP.secretKey, peerRatchetPublic.value)
  ourRatchetKeyPair.value = newRatchetKP
  sendMessageCount.value = msgNum

  console.log(`[Send #${msgNum}] Send chain updated with DH ratchet (post-compromise security)`)

  // 6. Save to history
  const historyAttachments = attachments.map(a => ({
    type: a.type as 'audio' | 'image',
    blobUrl: a.previewUrl,
  }))
  messages.push({
    direction: 'sent',
    text: plaintextInput.value.trim() || undefined,
    attachments: historyAttachments.length > 0 ? historyAttachments : undefined,
  })

  // 7. Clear inputs
  plaintextInput.value = ''
  attachments.length = 0
  console.log(`[Send #${msgNum}] Done — copy the encrypted output`)
}

function decrypt() {
  if (!recvChain.value || !ourRatchetKeyPair.value || !peerEncryptedInput.value.trim()) return

  const msgNum = recvMessageCount.value + 1
  console.log('═══════════════════════════════════════════')
  console.log(`[Recv #${msgNum}] Decrypting with Double Ratchet...`)
  console.log('═══════════════════════════════════════════')

  // 1. Symmetric ratchet → message key
  const { nextChainKey, messageKey } = ratchetStep(recvChain.value)

  // 2. Decrypt
  const payload = decryptMessage(messageKey, peerEncryptedInput.value.trim())
  if (!payload) {
    decryptedResult.value = { text: 'Decryption failed — wrong key or tampered data' }
    console.error(`[Recv #${msgNum}] Decryption FAILED`)
    return
  }

  console.log('[Recv] Decrypted JSON payload:', JSON.stringify(payload, null, 2))

  // 3. Extract peer's new ratchet key & DH ratchet recv chain
  const peerNewRatchetPub = decodeBase64(payload.ratchetKey)
  recvChain.value = dhRatchet(nextChainKey, ourRatchetKeyPair.value.secretKey, peerNewRatchetPub)
  peerRatchetPublic.value = peerNewRatchetPub
  recvMessageCount.value = msgNum

  console.log(`[Recv #${msgNum}] Recv chain updated with DH ratchet`)
  console.log(`[Recv #${msgNum}] Peer ratchet public key updated`)

  // 4. Build decrypted result
  const resultAttachments = payload.attachments?.map(a => {
    const bytes = base64ToBytes(a.data)
    const blob = new Blob([bytes.buffer as ArrayBuffer], { type: a.mime })
    return { type: a.type, blobUrl: createBlobUrl(blob) }
  })

  decryptedResult.value = {
    text: payload.text,
    attachments: resultAttachments,
  }

  messages.push({
    direction: 'received',
    text: payload.text,
    attachments: resultAttachments,
  })

  console.log(`[Recv #${msgNum}] Done`)
}

// ─── Clipboard ───────────────────────────────────────────────────

async function copyToClipboard(text: string) {
  await navigator.clipboard.writeText(text)
  console.log('[Clipboard] Copied to clipboard')
}

async function pasteFromClipboard(target: 'peerKey' | 'peerMessage') {
  const text = await navigator.clipboard.readText()
  if (target === 'peerKey') peerPublicKeyInput.value = text
  else peerEncryptedInput.value = text
  console.log('[Clipboard] Pasted from clipboard')
}

// ─── Helpers ─────────────────────────────────────────────────────

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function resetAll() {
  phase.value = 'idle'
  keyPair.value = null
  peerPublicKey.value = null
  sendChain.value = null
  recvChain.value = null
  ourRatchetKeyPair.value = null
  peerRatchetPublic.value = null
  sendMessageCount.value = 0
  recvMessageCount.value = 0
  peerPublicKeyInput.value = ''
  plaintextInput.value = ''
  encryptedOutput.value = ''
  peerEncryptedInput.value = ''
  decryptedResult.value = null
  attachments.length = 0
  messages.length = 0
  stopRecording()
  blobUrls.forEach(url => URL.revokeObjectURL(url))
  blobUrls.length = 0
  console.log('[Reset] All state cleared')
}

onBeforeUnmount(() => {
  stopRecording()
  blobUrls.forEach(url => URL.revokeObjectURL(url))
})
</script>

<template>
  <div class="min-h-screen bg-gray-950 text-gray-100 flex flex-col items-center p-4 sm:p-6">
    <div class="w-full max-w-2xl space-y-6">

      <!-- Header -->
      <div class="text-center space-y-2">
        <h1 class="text-3xl font-bold tracking-tight">XChat</h1>
        <p class="text-sm text-gray-400">E2E encrypted · Curve25519 · Double Ratchet</p>
        <div class="inline-block px-3 py-1 rounded-full text-xs font-medium"
          :class="{
            'bg-gray-800 text-gray-400': phase === 'idle',
            'bg-yellow-900/50 text-yellow-400': phase === 'waiting',
            'bg-green-900/50 text-green-400': phase === 'ready',
          }">
          {{ statusText }}
        </div>
      </div>

      <!-- ═══ Handshake Panel ═══ -->
      <div v-if="phase !== 'ready'" class="space-y-4 bg-gray-900 rounded-xl p-5 border border-gray-800">
        <h2 class="text-lg font-semibold">Key Exchange (ECDH · Curve25519)</h2>

        <div v-if="phase === 'idle'">
          <button @click="startHandshake"
            class="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 rounded-lg font-medium transition-colors cursor-pointer">
            Generate Keys
          </button>
        </div>

        <div v-if="phase === 'waiting'" class="space-y-4">
          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Your Public Key</label>
            <div class="flex gap-2">
              <textarea readonly
                :value="keyPair ? encodeBase64(keyPair.publicKey) : ''"
                class="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm font-mono resize-none h-16 focus:outline-none"
              />
              <button
                @click="copyToClipboard(encodeBase64(keyPair!.publicKey))"
                class="px-4 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors shrink-0 cursor-pointer">
                Copy
              </button>
            </div>
          </div>

          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Peer's Public Key</label>
            <div class="flex gap-2">
              <textarea
                v-model="peerPublicKeyInput"
                placeholder="Paste peer's public key here..."
                class="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm font-mono resize-none h-16 focus:outline-none focus:border-blue-500"
              />
              <button
                @click="pasteFromClipboard('peerKey')"
                class="px-4 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors shrink-0 cursor-pointer">
                Paste
              </button>
            </div>
          </div>

          <button @click="completeHandshake"
            :disabled="!peerPublicKeyInput.trim()"
            class="w-full py-2.5 px-4 bg-green-600 hover:bg-green-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition-colors cursor-pointer disabled:cursor-not-allowed">
            Complete Handshake
          </button>
        </div>
      </div>

      <!-- ═══ Chat Panel ═══ -->
      <div v-if="phase === 'ready'" class="space-y-5">

        <!-- ─── Send section ─── -->
        <div class="bg-gray-900 rounded-xl p-5 border border-gray-800 space-y-4">
          <h2 class="text-lg font-semibold text-blue-400">Send</h2>

          <!-- Plaintext textarea (Ctrl+V image detection) -->
          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Message text</label>
            <textarea
              v-model="plaintextInput"
              @paste="onPaste"
              placeholder="Type your message... (Ctrl+V to attach image)"
              class="w-full bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm resize-none h-24 focus:outline-none focus:border-blue-500"
            />
          </div>

          <!-- Attachment buttons + drop zone -->
          <div class="flex gap-2 items-center">
            <button @click="toggleRecording"
              class="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors shrink-0 cursor-pointer"
              :class="isRecording
                ? 'bg-red-600 hover:bg-red-500 text-white'
                : 'bg-gray-700 hover:bg-gray-600'">
              <span v-if="isRecording" class="w-2 h-2 rounded-full bg-white animate-pulse" />
              <span v-else>&#x1F3A4;</span>
              {{ isRecording ? `Stop ${formatTime(recordingSeconds)}` : 'Record' }}
            </button>

            <label class="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors cursor-pointer shrink-0">
              &#x1F5BC; Image
              <input type="file" accept="image/*" multiple class="hidden" @change="onFileInput" />
            </label>

            <span v-if="!isRecording" class="text-xs text-gray-600">max 60s</span>
          </div>

          <!-- Drop zone -->
          <div
            @dragover.prevent="isDragging = true"
            @dragleave="isDragging = false"
            @drop="onDrop"
            class="border-2 border-dashed rounded-lg p-3 text-center text-sm transition-colors"
            :class="isDragging ? 'border-blue-500 bg-blue-500/10 text-blue-300' : 'border-gray-700 text-gray-500'">
            Drop images here
          </div>

          <!-- Attachments preview list -->
          <div v-if="attachments.length" class="space-y-2">
            <div class="text-xs text-gray-400 font-medium">Attachments ({{ attachments.length }})</div>
            <div v-for="att in attachments" :key="att.id"
              class="relative bg-gray-800 rounded-lg p-3 border border-gray-700">
              <button @click="removeAttachment(att.id)"
                class="absolute top-2 right-2 w-6 h-6 flex items-center justify-center rounded-full bg-gray-700 hover:bg-red-600 text-xs transition-colors cursor-pointer z-10">
                &#x2715;
              </button>

              <!-- Audio -->
              <div v-if="att.type === 'audio'" class="flex items-center gap-3 pr-8">
                <span class="text-xl">&#x1F3A4;</span>
                <div class="flex-1 space-y-1 min-w-0">
                  <div class="text-sm font-medium">Voice message</div>
                  <div class="text-xs text-gray-400">{{ formatSize(att.data.length) }}</div>
                  <audio :src="att.previewUrl" controls class="w-full h-8" />
                </div>
              </div>

              <!-- Image -->
              <div v-if="att.type === 'image'" class="space-y-2 pr-8">
                <div class="flex items-center gap-2">
                  <span>&#x1F5BC;</span>
                  <span class="text-sm font-medium">Image</span>
                  <span class="text-xs text-gray-400">{{ formatSize(att.data.length) }} · {{ att.mime }}</span>
                </div>
                <img :src="att.previewUrl" class="max-h-36 rounded-lg object-contain" />
              </div>
            </div>
          </div>

          <!-- Encrypt button -->
          <button @click="encrypt"
            :disabled="!canEncrypt"
            class="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition-colors cursor-pointer disabled:cursor-not-allowed">
            Encrypt &amp; Send →
          </button>

          <!-- Encrypted output -->
          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Encrypted output (copy this)</label>
            <div class="flex gap-2">
              <textarea readonly
                :value="encryptedOutput"
                placeholder="Encrypted output will appear here..."
                class="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm font-mono resize-none h-24 focus:outline-none"
              />
              <button
                @click="copyToClipboard(encryptedOutput)"
                :disabled="!encryptedOutput"
                class="px-4 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-600 rounded-lg text-sm font-medium transition-colors shrink-0 self-start cursor-pointer disabled:cursor-not-allowed">
                Copy
              </button>
            </div>
          </div>
        </div>

        <!-- ─── Receive section ─── -->
        <div class="bg-gray-900 rounded-xl p-5 border border-gray-800 space-y-4">
          <h2 class="text-lg font-semibold text-emerald-400">Receive</h2>

          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Peer's encrypted message</label>
            <div class="flex gap-2">
              <textarea
                v-model="peerEncryptedInput"
                placeholder="Paste encrypted message from peer..."
                class="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm font-mono resize-none h-24 focus:outline-none focus:border-emerald-500"
              />
              <button
                @click="pasteFromClipboard('peerMessage')"
                class="px-4 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors shrink-0 self-start cursor-pointer">
                Paste
              </button>
            </div>
          </div>

          <button @click="decrypt"
            :disabled="!peerEncryptedInput.trim()"
            class="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition-colors cursor-pointer disabled:cursor-not-allowed">
            ← Decrypt
          </button>

          <!-- Decrypted result -->
          <div v-if="decryptedResult" class="space-y-3">
            <label class="block text-sm text-gray-400">Decrypted</label>

            <!-- Text -->
            <div v-if="decryptedResult.text"
              class="bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm whitespace-pre-wrap">
              {{ decryptedResult.text }}
            </div>

            <!-- Attachments -->
            <div v-for="(att, i) in decryptedResult.attachments" :key="i"
              class="bg-gray-800 border border-gray-700 rounded-lg p-3">
              <!-- Audio -->
              <div v-if="att.type === 'audio'" class="space-y-2">
                <div class="flex items-center gap-2 text-sm">
                  <span>&#x1F3A4;</span>
                  <span class="font-medium">Voice message</span>
                </div>
                <audio :src="att.blobUrl" controls class="w-full" />
              </div>
              <!-- Image -->
              <div v-else class="space-y-2">
                <div class="flex items-center gap-2 text-sm">
                  <span>&#x1F5BC;</span>
                  <span class="font-medium">Image</span>
                </div>
                <img :src="att.blobUrl" class="max-h-80 rounded-lg object-contain" />
              </div>
            </div>
          </div>
        </div>

        <!-- ─── Message History ─── -->
        <div v-if="messages.length" class="bg-gray-900 rounded-xl p-5 border border-gray-800 space-y-3">
          <h2 class="text-lg font-semibold text-gray-300">History</h2>
          <div class="space-y-2 max-h-96 overflow-y-auto">
            <div v-for="(msg, i) in messages" :key="i"
              class="text-sm px-3 py-2.5 rounded-lg space-y-2"
              :class="msg.direction === 'sent'
                ? 'bg-blue-900/30 border border-blue-800/50'
                : 'bg-emerald-900/30 border border-emerald-800/50'">

              <span class="text-xs font-medium uppercase tracking-wider"
                :class="msg.direction === 'sent' ? 'text-blue-500' : 'text-emerald-500'">
                {{ msg.direction === 'sent' ? 'You' : 'Peer' }}
              </span>

              <div v-if="msg.text" class="text-gray-200">{{ msg.text }}</div>

              <template v-if="msg.attachments">
                <div v-for="(att, j) in msg.attachments" :key="j">
                  <audio v-if="att.type === 'audio'" :src="att.blobUrl" controls class="w-full h-8" />
                  <img v-else :src="att.blobUrl" class="max-h-32 rounded object-contain" />
                </div>
              </template>
            </div>
          </div>
        </div>

        <!-- Stats & Reset -->
        <div class="flex items-center justify-between text-xs text-gray-500">
          <span>Sent: {{ sendMessageCount }} · Received: {{ recvMessageCount }}</span>
          <button @click="resetAll" class="text-red-400 hover:text-red-300 transition-colors cursor-pointer">
            Reset Session
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
