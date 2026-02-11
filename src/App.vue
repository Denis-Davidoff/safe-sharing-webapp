<script setup lang="ts">
import { ref, reactive, computed, watch, nextTick, onBeforeUnmount } from 'vue'
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
import DbSettings from './components/DbSettings.vue'
import { useSupabase } from './composables/useSupabase'
import type { DbMessageRow } from './types/db'

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
const joinMode = ref(false)
const joinResponseCode = ref('')
const connectionMode = ref<'manual' | 'supabase'>('manual')

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

// Message list auto-scroll
const messageListRef = ref<HTMLElement | null>(null)
watch(() => messages.length, () => {
  nextTick(() => {
    if (messageListRef.value) {
      messageListRef.value.scrollTop = messageListRef.value.scrollHeight
    }
  })
})

// Enter to send (Shift+Enter for newline)
function onInputKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault()
    encrypt()
  }
}

const statusText = computed(() => {
  switch (phase.value) {
    case 'idle': return joinMode.value ? 'Paste invite code to join' : 'Create or join a chat'
    case 'waiting': return 'Send invite code to your peer'
    case 'ready': return 'Secure channel established — send encrypted messages'
  }
})

const canEncrypt = computed(() => {
  return attachments.length > 0 || plaintextInput.value.trim().length > 0
})

// ─── Supabase ────────────────────────────────────────────────────

const fingerprint = computed(() => {
  if (!keyPair.value) return ''
  return encodeBase64(keyPair.value.publicKey).slice(0, 8)
})

const db = useSupabase({
  fingerprint,
  onMessages: handleDbMessages,
})

function handleDbMessages(rows: DbMessageRow[]) {
  if (!recvChain.value || !ourRatchetKeyPair.value) return

  for (const row of rows) {
    try {
      const envelope = JSON.parse(typeof row.data === 'string' ? row.data : JSON.stringify(row.data))
      const encryptedData: string = envelope.d

      const msgNum = recvMessageCount.value + 1
      console.log('═══════════════════════════════════════════')
      console.log(`[DB-Recv #${msgNum}] Auto-decrypting from Supabase...`)
      console.log('═══════════════════════════════════════════')

      // 1. Symmetric ratchet
      const { nextChainKey, messageKey } = ratchetStep(recvChain.value)

      // 2. Decrypt
      const payload = decryptMessage(messageKey, encryptedData)
      if (!payload) {
        console.error(`[DB-Recv #${msgNum}] Decryption FAILED — skipping`)
        db.deleteMessage(row.pk)
        continue
      }

      console.log('[DB-Recv] Decrypted JSON payload:', JSON.stringify(payload, null, 2))

      // 3. DH ratchet
      const peerNewRatchetPub = decodeBase64(payload.ratchetKey)
      recvChain.value = dhRatchet(nextChainKey, ourRatchetKeyPair.value.secretKey, peerNewRatchetPub)
      peerRatchetPublic.value = peerNewRatchetPub
      recvMessageCount.value = msgNum

      // 4. Build result and add to history
      const resultAttachments = payload.attachments?.map(a => {
        const bytes = base64ToBytes(a.data)
        const blob = new Blob([bytes.buffer as ArrayBuffer], { type: a.mime })
        return { type: a.type, blobUrl: createBlobUrl(blob) }
      })

      messages.push({
        direction: 'received',
        text: payload.text,
        attachments: resultAttachments,
      })

      console.log(`[DB-Recv #${msgNum}] Decrypted and added to history`)

      // 5. Delete from DB
      db.deleteMessage(row.pk)
    } catch (err: any) {
      console.error('[DB-Recv] Error processing message:', err.message)
      db.deleteMessage(row.pk)
    }
  }
}

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

    // Start Supabase message sync if configured
    if (db.isConfigured.value && !db.isSyncing.value) {
      db.startSync()
    }
  } catch (e) {
    console.error('[Handshake] Error:', e)
    alert('Invalid public key format.')
  }
}

function joinChat() {
  if (!peerPublicKeyInput.value.trim()) return

  console.log('═══════════════════════════════════════════')
  console.log('[Join] Generating keys and completing handshake...')
  console.log('═══════════════════════════════════════════')

  try {
    // 1. Generate our keys
    keyPair.value = generateKeyPair()

    // 2. Complete handshake with peer's invite key
    const theirPub = decodeBase64(peerPublicKeyInput.value.trim())
    peerPublicKey.value = theirPub

    const shared = computeSharedSecret(keyPair.value.secretKey, theirPub)
    const chains = deriveChainKeys(shared, keyPair.value.publicKey, theirPub)
    sendChain.value = chains.sendChain
    recvChain.value = chains.recvChain

    ourRatchetKeyPair.value = { publicKey: keyPair.value.publicKey, secretKey: keyPair.value.secretKey }
    peerRatchetPublic.value = theirPub

    // 3. Store response code for user to copy back
    joinResponseCode.value = encodeBase64(keyPair.value.publicKey)

    // 4. Start Supabase sync if configured
    if (db.isConfigured.value && !db.isSyncing.value) {
      db.startSync()
    }

    // 5. Go to ready (joiner has both keys)
    phase.value = 'ready'
    joinMode.value = false

    console.log('[Join] Secure channel established! Response code ready to copy.')
  } catch (e) {
    console.error('[Join] Error:', e)
    alert('Invalid invite code format.')
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

  // 7. Auto-send to Supabase if configured
  if (db.isConfigured.value) {
    db.sendMessage(encrypted).then(ok => {
      if (ok) console.log(`[Send #${msgNum}] Auto-sent to Supabase`)
    })
  }

  // 8. Clear inputs
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
  joinMode.value = false
  joinResponseCode.value = ''
  connectionMode.value = 'manual'
  attachments.length = 0
  messages.length = 0
  stopRecording()
  db.stopSync()
  blobUrls.forEach(url => URL.revokeObjectURL(url))
  blobUrls.length = 0
  console.log('[Reset] All state cleared')
}

onBeforeUnmount(() => {
  stopRecording()
  db.stopSync()
  blobUrls.forEach(url => URL.revokeObjectURL(url))
})
</script>

<template>
  <div class="h-screen bg-gray-950 text-gray-100 flex flex-col overflow-hidden">

    <!-- Supabase Settings Panel -->
    <DbSettings
      :settings="db.settings.value"
      :connection-state="db.connectionState.value"
      :connection-error="db.connectionError.value"
      :is-connected="db.isConnected.value"
      :is-configured="db.isConfigured.value"
      :is-syncing="db.isSyncing.value"
      :is-listening="db.isListening.value"
      :tables="db.tables.value"
      :columns="db.columns.value"
      :can-sync="phase === 'ready' || phase === 'waiting'"
      @connect="db.connect"
      @disconnect="db.disconnect"
      @start-sync="db.startSync"
      @stop-sync="db.stopSync"
      @update:settings="(s: any) => Object.assign(db.settings.value, s)"
      @fetch-columns="db.fetchColumns"
    />

    <!-- Header bar -->
    <div class="flex items-center justify-between px-4 py-2 border-b border-gray-800 shrink-0">
      <div class="flex items-center gap-3">
        <h1 class="text-lg font-bold tracking-tight">XChat</h1>
        <span class="text-xs text-gray-500">E2E · Curve25519 · Double Ratchet</span>
        <span v-if="db.isListening.value" class="text-xs text-emerald-400">· Realtime</span>
        <span v-else-if="db.isSyncing.value" class="text-xs text-yellow-400">· Polling</span>
      </div>
      <div class="px-2.5 py-0.5 rounded-full text-xs font-medium"
        :class="{
          'bg-gray-800 text-gray-400': phase === 'idle',
          'bg-yellow-900/50 text-yellow-400': phase === 'waiting',
          'bg-green-900/50 text-green-400': phase === 'ready',
        }">
        {{ statusText }}
      </div>
    </div>

    <!-- ═══ Handshake Panel (centered, before ready) ═══ -->
    <div v-if="phase !== 'ready'" class="flex-1 flex items-center justify-center p-4">
      <div class="w-full max-w-lg space-y-4 bg-gray-900 rounded-xl p-5 border border-gray-800">
        <h2 class="text-lg font-semibold">Key Exchange (ECDH · Curve25519)</h2>

        <!-- idle: choice screen -->
        <div v-if="phase === 'idle' && !joinMode" class="space-y-4">

          <!-- Mode tabs -->
          <div class="flex rounded-lg bg-gray-800 p-0.5">
            <button @click="connectionMode = 'manual'"
              :class="connectionMode === 'manual' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'"
              class="flex-1 py-1.5 text-sm font-medium rounded-md transition-colors cursor-pointer">
              Copy / Paste
            </button>
            <button @click="connectionMode = 'supabase'; joinMode = false"
              :class="connectionMode === 'supabase' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'"
              class="flex-1 py-1.5 text-sm font-medium rounded-md transition-colors cursor-pointer">
              Supabase
            </button>
          </div>

          <!-- ── Manual mode ── -->
          <template v-if="connectionMode === 'manual'">
            <button @click="startHandshake"
              class="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 rounded-lg font-medium transition-colors cursor-pointer">
              Create New Chat
            </button>
            <div class="text-center text-sm text-gray-500">or</div>
            <button @click="joinMode = true"
              class="w-full py-2.5 px-4 bg-gray-700 hover:bg-gray-600 rounded-lg font-medium transition-colors cursor-pointer">
              Join Existing Chat
            </button>
          </template>

          <!-- ── Supabase mode ── -->
          <template v-else>

            <!-- Step 1: Connect (not connected yet) -->
            <template v-if="!db.isConnected.value">
              <div class="space-y-1">
                <label class="block text-xs text-gray-400">Supabase URL</label>
                <input type="text"
                  :value="db.settings.value.url"
                  @input="db.settings.value.url = ($event.target as HTMLInputElement).value"
                  placeholder="https://xxx.supabase.co"
                  class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
              </div>
              <div class="space-y-1">
                <label class="block text-xs text-gray-400">Anon Key</label>
                <input type="password"
                  :value="db.settings.value.anonKey"
                  @input="db.settings.value.anonKey = ($event.target as HTMLInputElement).value"
                  placeholder="eyJhbGciOiJIUzI1NiIs..."
                  class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500" />
              </div>
              <div v-if="db.connectionError.value" class="text-xs text-red-400 bg-red-900/20 rounded-lg p-2">
                {{ db.connectionError.value }}
              </div>
              <button @click="db.connect"
                :disabled="!db.settings.value.url || !db.settings.value.anonKey || db.connectionState.value === 'connecting'"
                class="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition-colors cursor-pointer disabled:cursor-not-allowed">
                {{ db.connectionState.value === 'connecting' ? 'Connecting...' : 'Connect' }}
              </button>
            </template>

            <!-- Step 2: Configure table/column (connected but not configured) -->
            <template v-else-if="!db.isConfigured.value">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2 text-sm text-green-400">
                  <span class="w-2 h-2 rounded-full bg-green-500" />
                  Connected
                </div>
                <button @click="db.disconnect" class="text-xs text-gray-500 hover:text-gray-300 transition-colors cursor-pointer">
                  Disconnect
                </button>
              </div>

              <div class="space-y-1">
                <label class="block text-xs text-gray-400">Table</label>
                <select v-if="db.tables.value.length > 0"
                  :value="db.settings.value.table"
                  @change="db.settings.value.table = ($event.target as HTMLSelectElement).value; db.fetchColumns(db.settings.value.table)"
                  class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500">
                  <option value="">-- select table --</option>
                  <option v-for="t in db.tables.value" :key="t" :value="t">{{ t }}</option>
                </select>
                <input v-else type="text"
                  :value="db.settings.value.table"
                  @input="db.settings.value.table = ($event.target as HTMLInputElement).value"
                  @change="db.fetchColumns(db.settings.value.table)"
                  placeholder="messages"
                  class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
              </div>

              <div class="space-y-1">
                <label class="block text-xs text-gray-400">Message column</label>
                <select v-if="db.columns.value.length > 0"
                  :value="db.settings.value.column"
                  @change="db.settings.value.column = ($event.target as HTMLSelectElement).value"
                  class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500">
                  <option value="">-- select column --</option>
                  <option v-for="c in db.columns.value" :key="c" :value="c">{{ c }}</option>
                </select>
                <input v-else type="text"
                  :value="db.settings.value.column"
                  @input="db.settings.value.column = ($event.target as HTMLInputElement).value"
                  placeholder="payload"
                  class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
              </div>

              <div class="space-y-1">
                <label class="block text-xs text-gray-400">ID column</label>
                <input type="text"
                  :value="db.settings.value.idColumn"
                  @input="db.settings.value.idColumn = ($event.target as HTMLInputElement).value"
                  placeholder="id"
                  class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
              </div>
            </template>

            <!-- Step 3: Ready — create/join chat -->
            <template v-else>
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2 text-sm text-green-400">
                  <span class="w-2 h-2 rounded-full bg-green-500" />
                  {{ db.settings.value.table }} · {{ db.settings.value.column }}
                </div>
                <button @click="db.disconnect" class="text-xs text-gray-500 hover:text-gray-300 transition-colors cursor-pointer">
                  Disconnect
                </button>
              </div>

              <button @click="startHandshake"
                class="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 rounded-lg font-medium transition-colors cursor-pointer">
                Create New Chat
              </button>
              <div class="text-center text-sm text-gray-500">or</div>
              <button @click="joinMode = true"
                class="w-full py-2.5 px-4 bg-gray-700 hover:bg-gray-600 rounded-lg font-medium transition-colors cursor-pointer">
                Join Existing Chat
              </button>
              <p class="text-center text-xs text-gray-500">Messages will be delivered via Supabase after key exchange</p>
            </template>

          </template>
        </div>

        <!-- idle + joinMode: paste invite -->
        <div v-if="phase === 'idle' && joinMode" class="space-y-4">
          <div class="flex items-center gap-2">
            <button @click="joinMode = false"
              class="text-sm text-gray-400 hover:text-gray-200 transition-colors cursor-pointer">
              &larr; Back
            </button>
            <h3 class="text-sm font-medium">Join Chat</h3>
          </div>

          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Paste Invite Code</label>
            <div class="flex gap-2">
              <textarea
                v-model="peerPublicKeyInput"
                placeholder="Paste invite code from your partner..."
                class="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm font-mono resize-none h-20 focus:outline-none focus:border-green-500"
              />
              <button
                @click="pasteFromClipboard('peerKey')"
                class="px-4 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors shrink-0 cursor-pointer">
                Paste
              </button>
            </div>
          </div>

          <button @click="joinChat"
            :disabled="!peerPublicKeyInput.trim()"
            class="w-full py-2.5 px-4 bg-green-600 hover:bg-green-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium transition-colors cursor-pointer disabled:cursor-not-allowed">
            Join
          </button>
        </div>

        <!-- waiting: initiator view (always manual key exchange) -->
        <div v-if="phase === 'waiting'" class="space-y-4">
          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Your Invite Code</label>
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
            <p class="text-xs text-gray-500">Send this invite code to your chat partner</p>
          </div>

          <div class="space-y-1.5">
            <label class="block text-sm text-gray-400">Paste Partner's Response</label>
            <div class="flex gap-2">
              <textarea
                v-model="peerPublicKeyInput"
                placeholder="Paste response code from your partner..."
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
    </div>

    <!-- ═══ Chat View (when ready) ═══ -->
    <template v-else>

      <!-- Response code banner (shown after joining, dismissible) -->
      <div v-if="joinResponseCode" class="bg-yellow-900/30 border-b border-yellow-800 px-4 py-3 shrink-0">
        <p class="text-sm text-yellow-300 mb-2">Send this response code back to your partner:</p>
        <div class="flex items-center gap-2">
          <code class="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs font-mono truncate">{{ joinResponseCode }}</code>
          <button @click="copyToClipboard(joinResponseCode)"
            class="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm font-medium transition-colors cursor-pointer shrink-0">
            Copy
          </button>
          <button @click="joinResponseCode = ''"
            class="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-400 transition-colors cursor-pointer shrink-0">
            Dismiss
          </button>
        </div>
      </div>

      <!-- Split Layout -->
      <div class="flex-1 flex flex-col lg:flex-row min-h-0">

      <!-- ─── LEFT: Chat Panel ─── -->
      <div class="w-full lg:w-1/2 flex flex-col min-h-0 h-[60vh] lg:h-auto">

        <!-- Message list -->
        <div ref="messageListRef" class="flex-1 overflow-y-auto min-h-0 p-4 space-y-2">
          <!-- Empty state -->
          <div v-if="messages.length === 0" class="h-full flex items-center justify-center">
            <span class="text-sm text-gray-600">No messages yet</span>
          </div>

          <!-- Message bubbles -->
          <div v-for="(msg, i) in messages" :key="i"
            class="flex" :class="msg.direction === 'sent' ? 'justify-end' : 'justify-start'">
            <div class="max-w-[75%] px-3.5 py-2.5 space-y-2"
              :class="msg.direction === 'sent'
                ? 'bg-blue-600 rounded-2xl rounded-br-md'
                : 'bg-gray-800 rounded-2xl rounded-bl-md'">

              <div v-if="msg.text" class="text-sm whitespace-pre-wrap">{{ msg.text }}</div>

              <template v-if="msg.attachments">
                <div v-for="(att, j) in msg.attachments" :key="j">
                  <audio v-if="att.type === 'audio'" :src="att.blobUrl" controls class="w-full h-8" />
                  <img v-else :src="att.blobUrl" class="max-h-48 rounded-lg object-contain" />
                </div>
              </template>
            </div>
          </div>
        </div>

        <!-- Attachment preview strip -->
        <div v-if="attachments.length" class="flex gap-2 px-4 py-2 border-t border-gray-800 overflow-x-auto shrink-0">
          <div v-for="att in attachments" :key="att.id"
            class="relative flex items-center gap-2 bg-gray-800 rounded-lg px-2.5 py-1.5 shrink-0 border border-gray-700">
            <button @click="removeAttachment(att.id)"
              class="absolute -top-1.5 -right-1.5 w-5 h-5 flex items-center justify-center rounded-full bg-gray-700 hover:bg-red-600 text-xs transition-colors cursor-pointer z-10">
              &#x2715;
            </button>
            <!-- Audio chip -->
            <template v-if="att.type === 'audio'">
              <span class="text-sm">&#x1F3A4;</span>
              <span class="text-xs text-gray-300">Voice · {{ formatSize(att.data.length) }}</span>
            </template>
            <!-- Image chip -->
            <template v-else>
              <img :src="att.previewUrl" class="h-12 rounded object-contain" />
              <span class="text-xs text-gray-400">{{ formatSize(att.data.length) }}</span>
            </template>
          </div>
        </div>

        <!-- Input bar -->
        <div class="flex items-end gap-2 p-3 border-t border-gray-800 bg-gray-900 shrink-0"
          @dragover.prevent="isDragging = true"
          @dragleave="isDragging = false"
          @drop="onDrop"
          :class="isDragging ? 'ring-2 ring-blue-500 ring-inset' : ''">

          <!-- Attach file -->
          <label class="flex items-center justify-center w-10 h-10 rounded-full hover:bg-gray-800 transition-colors cursor-pointer shrink-0">
            <span class="text-lg text-gray-400">&#x1F4CE;</span>
            <input type="file" accept="image/*" multiple class="hidden" @change="onFileInput" />
          </label>

          <!-- Text input -->
          <textarea
            v-model="plaintextInput"
            @paste="onPaste"
            @keydown="onInputKeydown"
            placeholder="Message..."
            rows="1"
            class="flex-1 bg-gray-800 border border-gray-700 rounded-2xl px-4 py-2.5 text-sm resize-none max-h-32 focus:outline-none focus:border-blue-500 overflow-y-auto"
          />

          <!-- Record audio -->
          <button @click="toggleRecording"
            class="flex items-center justify-center w-10 h-10 rounded-full transition-colors cursor-pointer shrink-0"
            :class="isRecording ? 'bg-red-600 hover:bg-red-500' : 'hover:bg-gray-800'">
            <span v-if="isRecording" class="text-xs font-medium text-white">{{ formatTime(recordingSeconds) }}</span>
            <span v-else class="text-lg text-gray-400">&#x1F3A4;</span>
          </button>

          <!-- Send button -->
          <button @click="encrypt"
            :disabled="!canEncrypt"
            class="flex items-center justify-center w-10 h-10 rounded-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 transition-colors cursor-pointer disabled:cursor-not-allowed shrink-0">
            <span class="text-sm">&#x27A4;</span>
          </button>
        </div>
      </div>

      <!-- ─── RIGHT: Crypto Panels ─── -->
      <div class="w-full lg:w-1/2 flex flex-col min-h-0 border-t lg:border-t-0 lg:border-l border-gray-800 h-[40vh] lg:h-auto">
        <div class="flex-1 overflow-y-auto p-4 space-y-4">

          <!-- Encrypted output -->
          <div class="bg-gray-900 rounded-xl p-4 border border-gray-800 space-y-3">
            <h2 class="text-sm font-semibold text-blue-400">Encrypted output</h2>
            <div class="flex gap-2">
              <textarea readonly
                :value="encryptedOutput"
                placeholder="Encrypted output will appear here..."
                class="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-xs font-mono resize-none h-24 focus:outline-none"
              />
              <button
                @click="copyToClipboard(encryptedOutput)"
                :disabled="!encryptedOutput"
                class="px-3 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-600 rounded-lg text-sm font-medium transition-colors shrink-0 self-start cursor-pointer disabled:cursor-not-allowed">
                Copy
              </button>
            </div>
          </div>

          <!-- Receive / Decrypt -->
          <div class="bg-gray-900 rounded-xl p-4 border border-gray-800 space-y-3">
            <h2 class="text-sm font-semibold text-emerald-400">Receive &amp; Decrypt</h2>

            <div class="flex gap-2">
              <textarea
                v-model="peerEncryptedInput"
                placeholder="Paste encrypted message from peer..."
                class="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-xs font-mono resize-none h-24 focus:outline-none focus:border-emerald-500"
              />
              <button
                @click="pasteFromClipboard('peerMessage')"
                class="px-3 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors shrink-0 self-start cursor-pointer">
                Paste
              </button>
            </div>

            <button @click="decrypt"
              :disabled="!peerEncryptedInput.trim()"
              class="w-full py-2 px-4 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg text-sm font-medium transition-colors cursor-pointer disabled:cursor-not-allowed">
              Decrypt
            </button>

            <!-- Decrypted result -->
            <div v-if="decryptedResult" class="space-y-2">
              <label class="block text-xs text-gray-400">Decrypted</label>

              <div v-if="decryptedResult.text"
                class="bg-gray-800 border border-gray-700 rounded-lg p-3 text-sm whitespace-pre-wrap">
                {{ decryptedResult.text }}
              </div>

              <div v-for="(att, i) in decryptedResult.attachments" :key="i"
                class="bg-gray-800 border border-gray-700 rounded-lg p-3">
                <div v-if="att.type === 'audio'" class="space-y-2">
                  <div class="flex items-center gap-2 text-sm">
                    <span>&#x1F3A4;</span>
                    <span class="font-medium">Voice message</span>
                  </div>
                  <audio :src="att.blobUrl" controls class="w-full" />
                </div>
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

          <!-- Stats & Reset -->
          <div class="flex items-center justify-between text-xs text-gray-500 pt-2">
            <span>Sent: {{ sendMessageCount }} · Received: {{ recvMessageCount }}</span>
            <button @click="resetAll" class="text-red-400 hover:text-red-300 transition-colors cursor-pointer">
              Reset Session
            </button>
          </div>
        </div>
      </div>

    </div>

    </template>
  </div>
</template>
