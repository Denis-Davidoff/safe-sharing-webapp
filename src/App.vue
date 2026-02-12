<script setup lang="ts">
import { ref, reactive, computed, watch, nextTick, onBeforeUnmount } from 'vue'
import { useLocalStorage } from '@vueuse/core'
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
const connectionMode = ref<'manual' | 'supabase'>('manual')
const soundEnabled = useLocalStorage('xchat-sound-enabled', true)

// Session persistence
interface SessionData {
  v: 1
  kp: { pub: string; sec: string }
  peer: string
  sc: string
  rc: string
  rkp: { pub: string; sec: string }
  rp: string
  sn: number
  rn: number
  cm: 'manual' | 'supabase'
}
const savedSession = useLocalStorage<SessionData | null>('xchat-session', null, {
  serializer: {
    read: (v: string): SessionData | null => { try { return JSON.parse(v) } catch { return null } },
    write: (v: SessionData | null): string => JSON.stringify(v),
  },
})
const hasSavedSession = computed(() => savedSession.value !== null)

// Attachments (multiple)
const MAX_FILE_SIZE = 100 * 1024 * 1024 // 100 MB (chunked transfer handles large files)

interface UIAttachment {
  id: number
  type: 'audio' | 'image' | 'file'
  data: Uint8Array
  mime: string
  name: string
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
  attachments?: Array<{ type: 'audio' | 'image' | 'file'; blobUrl: string; name?: string; size?: number }>
} | null>(null)

// Message history
interface ChatMessage {
  id: number
  direction: 'sent' | 'received'
  text?: string
  attachments?: Array<{ type: 'audio' | 'image' | 'file'; blobUrl: string; name?: string; size?: number }>
}

// Image zoom
const zoomImageUrl = ref<string | null>(null)
let messageIdCounter = 0
const messages = reactive<ChatMessage[]>([])

// Audio player state
const audioStates = reactive<Record<string, { playing: boolean; currentTime: number; duration: number }>>({})
const audioRefs: Record<string, HTMLAudioElement> = {}

function initAudioState(key: string, el: HTMLAudioElement) {
  audioRefs[key] = el
  if (!audioStates[key]) {
    audioStates[key] = { playing: false, currentTime: 0, duration: isFinite(el.duration) ? el.duration : 0 }
  }
}

function onAudioMetadata(key: string, el: HTMLAudioElement) {
  if (audioStates[key] && isFinite(el.duration)) {
    audioStates[key].duration = el.duration
  }
}

function toggleAudio(key: string) {
  const el = audioRefs[key]
  if (!el) return
  const state = audioStates[key]
  if (!state) return
  if (state.playing) {
    el.pause()
    state.playing = false
  } else {
    // Pause any other playing audio
    for (const [k, s] of Object.entries(audioStates)) {
      if (s.playing && k !== key) {
        audioRefs[k]?.pause()
        s.playing = false
      }
    }
    el.play()
    state.playing = true
  }
}

function onAudioTimeUpdate(key: string, el: HTMLAudioElement) {
  if (audioStates[key]) audioStates[key].currentTime = el.currentTime
}

function onAudioEnded(key: string) {
  if (audioStates[key]) {
    audioStates[key].playing = false
    audioStates[key].currentTime = 0
  }
}

function audioProgress(key: string): number {
  const s = audioStates[key]
  if (!s || !s.duration) return 0
  return (s.currentTime / s.duration) * 100
}

function deleteMessage(idx: number) {
  const msg = messages[idx]
  if (!msg) return
  if (msg.attachments) {
    for (const att of msg.attachments) {
      URL.revokeObjectURL(att.blobUrl)
    }
  }
  // Clean up audio states for this message
  if (msg.attachments) {
    msg.attachments.forEach((_, j) => {
      const key = `${msg.id}-${j}`
      if (audioRefs[key]) {
        audioRefs[key].pause()
        delete audioRefs[key]
      }
      delete audioStates[key]
    })
  }
  messages.splice(idx, 1)
}

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
    case 'idle': return 'Create or join a chat'
    case 'waiting': return 'Send invite code to your peer'
    case 'ready': return 'Secure channel established — send encrypted messages'
  }
})

const isSending = ref(false)

// Progress tracking for large files
const sendProgress = ref<{ text: string; percent: number } | null>(null)

const canEncrypt = computed(() => {
  return !isSending.value && (attachments.length > 0 || plaintextInput.value.trim().length > 0)
})

// Yield to UI thread between heavy operations
function yieldToUI(): Promise<void> {
  return new Promise(r => setTimeout(r, 0))
}

// ─── Notification Sound ──────────────────────────────────────────

let audioCtx: AudioContext | null = null

function playNotificationSound() {
  if (!soundEnabled.value) return
  try {
    if (!audioCtx) audioCtx = new AudioContext()
    const ctx = audioCtx

    const osc1 = ctx.createOscillator()
    const osc2 = ctx.createOscillator()
    const gain = ctx.createGain()

    osc1.type = 'sine'
    osc1.frequency.setValueAtTime(880, ctx.currentTime)
    osc1.frequency.setValueAtTime(1047, ctx.currentTime + 0.08)

    osc2.type = 'sine'
    osc2.frequency.setValueAtTime(1320, ctx.currentTime + 0.08)

    gain.gain.setValueAtTime(0.15, ctx.currentTime)
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25)

    osc1.connect(gain)
    osc2.connect(gain)
    gain.connect(ctx.destination)

    osc1.start(ctx.currentTime)
    osc2.start(ctx.currentTime + 0.08)
    osc1.stop(ctx.currentTime + 0.25)
    osc2.stop(ctx.currentTime + 0.25)
  } catch {
    // Audio not available
  }
}

// ─── Supabase ────────────────────────────────────────────────────

const fingerprint = computed(() => {
  if (!keyPair.value) return ''
  return encodeBase64(keyPair.value.publicKey).slice(0, 8)
})

const peerFingerprint = computed(() => {
  if (!peerPublicKey.value) return ''
  return encodeBase64(peerPublicKey.value).slice(0, 8)
})

const db = useSupabase({
  fingerprint,
  peerFingerprint,
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
        const blob = new Blob([bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer], { type: a.mime })
        return { type: a.type, blobUrl: createBlobUrl(blob), name: a.name, size: bytes.byteLength }
      })

      messages.push({
        id: ++messageIdCounter,
        direction: 'received',
        text: payload.text,
        attachments: resultAttachments,
      })

      console.log(`[DB-Recv #${msgNum}] Decrypted and added to history`)
      playNotificationSound()

      // 5. Delete from DB
      db.deleteMessage(row.pk)
    } catch (err: any) {
      console.error('[DB-Recv] Error processing message:', err.message)
      db.deleteMessage(row.pk)
    }
  }
}

// ─── Handshake ───────────────────────────────────────────────────

function goBack() {
  if (phase.value === 'waiting') {
    keyPair.value = null
    peerPublicKeyInput.value = ''
    phase.value = 'idle'
  } else if (phase.value === 'idle' && connectionMode.value === 'supabase') {
    if (db.isConfigured.value) {
      db.settings.value.table = ''
      db.settings.value.column = ''
    } else if (db.isConnected.value) {
      db.disconnect()
    }
  }
}

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

// ─── Session Persistence ────────────────────────────────────────

function serializeSession(): SessionData | null {
  if (!keyPair.value || !peerPublicKey.value || !sendChain.value || !recvChain.value || !ourRatchetKeyPair.value || !peerRatchetPublic.value) return null
  return {
    v: 1,
    kp: { pub: encodeBase64(keyPair.value.publicKey), sec: encodeBase64(keyPair.value.secretKey) },
    peer: encodeBase64(peerPublicKey.value),
    sc: encodeBase64(sendChain.value),
    rc: encodeBase64(recvChain.value),
    rkp: { pub: encodeBase64(ourRatchetKeyPair.value.publicKey), sec: encodeBase64(ourRatchetKeyPair.value.secretKey) },
    rp: encodeBase64(peerRatchetPublic.value),
    sn: sendMessageCount.value,
    rn: recvMessageCount.value,
    cm: connectionMode.value,
  }
}

function restoreSession(data: SessionData) {
  keyPair.value = { publicKey: decodeBase64(data.kp.pub), secretKey: decodeBase64(data.kp.sec) }
  peerPublicKey.value = decodeBase64(data.peer)
  sendChain.value = decodeBase64(data.sc)
  recvChain.value = decodeBase64(data.rc)
  ourRatchetKeyPair.value = { publicKey: decodeBase64(data.rkp.pub), secretKey: decodeBase64(data.rkp.sec) }
  peerRatchetPublic.value = decodeBase64(data.rp)
  sendMessageCount.value = data.sn
  recvMessageCount.value = data.rn
  connectionMode.value = data.cm
  phase.value = 'ready'

  if (db.isConfigured.value && !db.isSyncing.value) {
    db.startSync()
  }
  console.log('[Session] Restored')
}

function saveSession() {
  const data = serializeSession()
  if (data) {
    savedSession.value = data
    console.log('[Session] Saved to localStorage')
  }
}

function loadSession() {
  if (!savedSession.value) return
  restoreSession(savedSession.value)
}

function deleteSession() {
  savedSession.value = null
  console.log('[Session] Deleted from localStorage')
}

async function exportSession() {
  const data = serializeSession()
  if (data) {
    await copyToClipboard(JSON.stringify(data))
    console.log('[Session] Exported to clipboard')
  }
}

async function importSession() {
  const text = await navigator.clipboard.readText()
  try {
    const data: SessionData = JSON.parse(text.trim())
    if (data.v !== 1 || !data.kp || !data.peer) throw new Error('Invalid format')
    restoreSession(data)
    savedSession.value = data
  } catch {
    alert('Invalid session data')
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
        name: 'voice.webm',
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

// ─── File Handling ───────────────────────────────────────────────

function handleFile(file: File) {
  if (file.size > MAX_FILE_SIZE) {
    alert(`File "${file.name}" is too large (${formatSize(file.size)}). Maximum size is ${formatSize(MAX_FILE_SIZE)}.`)
    return
  }
  const type: 'audio' | 'image' | 'file' = file.type.startsWith('image/') ? 'image'
    : file.type.startsWith('audio/') ? 'audio' : 'file'

  console.log(`[File] Attaching: ${file.name} (${file.type || 'unknown'}, ${file.size} bytes, type: ${type})`)

  const reader = new FileReader()
  reader.onload = () => {
    attachments.push({
      id: ++attachmentIdCounter,
      type,
      data: new Uint8Array(reader.result as ArrayBuffer),
      mime: file.type || 'application/octet-stream',
      name: file.name,
      previewUrl: createBlobUrl(file),
    })
    console.log(`[File] Attached: ${file.name} (${(reader.result as ArrayBuffer).byteLength} bytes)`)
  }
  reader.readAsArrayBuffer(file)
}

function onDrop(e: DragEvent) {
  e.preventDefault()
  isDragging.value = false
  const files = e.dataTransfer?.files
  if (files) {
    for (let i = 0; i < files.length; i++) {
      handleFile(files[i]!)
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
      if (file) handleFile(file)
      return
    }
  }
}

function onFileInput(e: Event) {
  const input = e.target as HTMLInputElement
  const files = input.files
  if (files) {
    for (let i = 0; i < files.length; i++) {
      handleFile(files[i]!)
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

async function encrypt() {
  if (!sendChain.value || !peerRatchetPublic.value || !canEncrypt.value) return

  isSending.value = true

  const msgNum = sendMessageCount.value + 1
  const totalDataSize = attachments.reduce((sum, a) => sum + a.data.length, 0)
  const isLarge = totalDataSize > 512 * 1024 // show progress for >512KB

  console.log('═══════════════════════════════════════════')
  console.log(`[Send #${msgNum}] Encrypting with Double Ratchet...`)
  console.log('═══════════════════════════════════════════')

  // Save ratchet state for rollback on send failure
  const prevSendChain = sendChain.value
  const prevOurRatchetKeyPair = ourRatchetKeyPair.value
  const prevSendMessageCount = sendMessageCount.value

  // 1. Symmetric ratchet → message key
  if (isLarge) { sendProgress.value = { text: 'Preparing...', percent: 0 }; await yieldToUI() }

  const { nextChainKey, messageKey } = ratchetStep(sendChain.value)

  // 2. Generate new ephemeral ratchet key pair
  const newRatchetKP = generateKeyPair()
  console.log(`[Send #${msgNum}] New ephemeral ratchet key generated`)

  // 3. Build JSON payload
  if (isLarge) { sendProgress.value = { text: 'Encoding...', percent: 5 }; await yieldToUI() }

  const payloadAttachments: Attachment[] = attachments.map(a => ({
    type: a.type,
    mime: a.mime,
    data: bytesToBase64(a.data),
    name: a.type === 'file' || a.type === 'image' ? a.name : undefined,
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
  if (isLarge) { sendProgress.value = { text: 'Encrypting...', percent: 20 }; await yieldToUI() }

  console.log('[Send] JSON payload before encryption:', JSON.stringify(payload, null, 2))
  const encrypted = encryptMessage(messageKey, payload)
  encryptedOutput.value = encrypted

  // 5. DH ratchet: update send chain with fresh ECDH for NEXT message
  sendChain.value = dhRatchet(nextChainKey, newRatchetKP.secretKey, peerRatchetPublic.value)
  ourRatchetKeyPair.value = newRatchetKP
  sendMessageCount.value = msgNum

  console.log(`[Send #${msgNum}] Send chain updated with DH ratchet (post-compromise security)`)

  // 6. Auto-send to Supabase if configured — await and rollback on failure
  if (db.isConfigured.value) {
    if (isLarge) { sendProgress.value = { text: 'Uploading...', percent: 30 }; await yieldToUI() }

    const ok = await db.sendMessage(encrypted, (sent, total) => {
      const uploadPercent = 30 + Math.round((sent / total) * 70)
      sendProgress.value = { text: `Uploading ${sent}/${total}...`, percent: uploadPercent }
    })
    if (!ok) {
      console.error(`[Send #${msgNum}] Supabase send failed — rolling back ratchet`)
      sendChain.value = prevSendChain
      ourRatchetKeyPair.value = prevOurRatchetKeyPair
      sendMessageCount.value = prevSendMessageCount
      encryptedOutput.value = ''
      isSending.value = false
      sendProgress.value = null
      return
    }
    console.log(`[Send #${msgNum}] Auto-sent to Supabase`)
  }

  // 7. Save to history
  const historyAttachments = attachments.map(a => ({
    type: a.type,
    blobUrl: a.previewUrl,
    name: a.name,
    size: a.data.length,
  }))
  messages.push({
    id: ++messageIdCounter,
    direction: 'sent',
    text: plaintextInput.value.trim() || undefined,
    attachments: historyAttachments.length > 0 ? historyAttachments : undefined,
  })

  // 8. Clear inputs
  plaintextInput.value = ''
  attachments.length = 0
  isSending.value = false
  sendProgress.value = null
  console.log(`[Send #${msgNum}] Done — copy the encrypted output`)
}

function decrypt() {
  if (!recvChain.value || !ourRatchetKeyPair.value || !peerEncryptedInput.value.trim()) return

  decryptedResult.value = null
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
    const blob = new Blob([bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer], { type: a.mime })
    return { type: a.type, blobUrl: createBlobUrl(blob), name: a.name, size: bytes.byteLength }
  })

  decryptedResult.value = {
    text: payload.text,
    attachments: resultAttachments,
  }

  messages.push({
    id: ++messageIdCounter,
    direction: 'received',
    text: payload.text,
    attachments: resultAttachments,
  })

  // Clear input so user can't accidentally decrypt again (ratchet has advanced)
  peerEncryptedInput.value = ''

  playNotificationSound()
  console.log(`[Recv #${msgNum}] Done`)
}

// ─── Download ────────────────────────────────────────────────────

function downloadFile(blobUrl: string, name: string) {
  const a = document.createElement('a')
  a.href = blobUrl
  a.download = name
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
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
  const total = Math.floor(seconds)
  const m = Math.floor(total / 60)
  const s = total % 60
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
  connectionMode.value = 'manual'
  zoomImageUrl.value = null
  attachments.length = 0
  // Clean up audio players
  for (const [k, el] of Object.entries(audioRefs)) {
    el.pause()
    delete audioRefs[k]
  }
  for (const k of Object.keys(audioStates)) delete audioStates[k]
  messages.length = 0
  stopRecording()
  db.stopSync()
  blobUrls.forEach(url => URL.revokeObjectURL(url))
  blobUrls.length = 0
  deleteSession()
  console.log('[Reset] All state cleared')
}

onBeforeUnmount(() => {
  stopRecording()
  db.stopSync()
  blobUrls.forEach(url => URL.revokeObjectURL(url))
})
</script>

<template>
  <div class="h-screen bg-gray-950 text-gray-100 flex flex-col overflow-hidden"
    @keydown.escape="zoomImageUrl = null">

    <!-- Image Zoom Modal -->
    <div v-if="zoomImageUrl" class="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 cursor-pointer"
      @click="zoomImageUrl = null">
      <img :src="zoomImageUrl" class="max-w-[90vw] max-h-[90vh] object-contain rounded-lg shadow-2xl" @click.stop />
      <button @click="zoomImageUrl = null"
        class="absolute top-4 right-4 w-10 h-10 flex items-center justify-center rounded-full bg-gray-900/80 hover:bg-gray-800 text-xl transition-colors cursor-pointer">
        &#x2715;
      </button>
    </div>

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
      <div class="flex items-center gap-2">
        <div class="px-2.5 py-0.5 rounded-full text-xs font-medium"
          :class="{
            'bg-gray-800 text-gray-400': phase === 'idle',
            'bg-yellow-900/50 text-yellow-400': phase === 'waiting',
            'bg-green-900/50 text-green-400': phase === 'ready',
          }">
          {{ statusText }}
        </div>
        <button v-if="phase === 'ready'" @click="soundEnabled = !soundEnabled"
          class="w-7 h-7 flex items-center justify-center rounded-full hover:bg-gray-800 transition-colors cursor-pointer"
          :title="soundEnabled ? 'Mute notifications' : 'Unmute notifications'">
          <span v-if="soundEnabled" class="text-sm">&#x1F514;</span>
          <span v-else class="text-sm opacity-40">&#x1F515;</span>
        </button>
        <button v-if="phase === 'ready'" @click="saveSession"
          title="Save session"
          class="w-7 h-7 flex items-center justify-center rounded-full hover:bg-gray-800 transition-colors cursor-pointer">
          <span class="text-sm">&#x1F4BE;</span>
        </button>
        <button v-if="phase === 'ready'" @click="exportSession"
          title="Export session to clipboard"
          class="w-7 h-7 flex items-center justify-center rounded-full hover:bg-gray-800 transition-colors cursor-pointer">
          <span class="text-sm">&#x1F4CB;</span>
        </button>
        <button v-if="phase === 'ready'" @click="resetAll"
          class="text-xs text-red-400 hover:text-red-300 transition-colors cursor-pointer">
          Reset
        </button>
      </div>
    </div>

    <!-- ═══ Handshake Panel (centered, before ready) ═══ -->
    <div v-if="phase !== 'ready'" class="flex-1 flex items-center justify-center p-4">
      <div class="w-full max-w-lg space-y-4 bg-gray-900 rounded-xl p-5 border border-gray-800">
        <div class="flex items-center gap-2">
          <button v-if="phase === 'waiting' || (phase === 'idle' && connectionMode === 'supabase' && db.isConnected.value)"
            @click="goBack"
            class="text-gray-400 hover:text-gray-200 transition-colors cursor-pointer text-lg leading-none">
            &larr;
          </button>
          <h2 class="text-lg font-semibold">Key Exchange (ECDH · Curve25519)</h2>
        </div>

        <!-- idle: choice screen -->
        <div v-if="phase === 'idle'" class="space-y-4">

          <!-- Mode tabs -->
          <div class="flex rounded-lg bg-gray-800 p-0.5">
            <button @click="connectionMode = 'manual'"
              :class="connectionMode === 'manual' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'"
              class="flex-1 py-1.5 text-sm font-medium rounded-md transition-colors cursor-pointer">
              Copy / Paste
            </button>
            <button @click="connectionMode = 'supabase'"
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
            <button @click="startHandshake"
              class="w-full py-2.5 px-4 bg-gray-700 hover:bg-gray-600 rounded-lg font-medium transition-colors cursor-pointer">
              Join Existing Chat
            </button>

            <!-- Session restore -->
            <div v-if="hasSavedSession" class="border-t border-gray-700 pt-3 mt-1">
              <button @click="loadSession"
                class="w-full py-2 px-4 bg-emerald-700 hover:bg-emerald-600 rounded-lg text-sm font-medium transition-colors cursor-pointer">
                Resume Saved Session
              </button>
            </div>
            <button @click="importSession"
              class="w-full py-2 px-4 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors cursor-pointer">
              Import Session
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
              <button @click="startHandshake"
                class="w-full py-2.5 px-4 bg-gray-700 hover:bg-gray-600 rounded-lg font-medium transition-colors cursor-pointer">
                Join Existing Chat
              </button>
              <p class="text-center text-xs text-gray-500">Messages will be delivered via Supabase after key exchange</p>

              <!-- Session restore -->
              <div v-if="hasSavedSession" class="border-t border-gray-700 pt-3 mt-1">
                <button @click="loadSession"
                  class="w-full py-2 px-4 bg-emerald-700 hover:bg-emerald-600 rounded-lg text-sm font-medium transition-colors cursor-pointer">
                  Resume Saved Session
                </button>
              </div>
              <button @click="importSession"
                class="w-full py-2 px-4 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors cursor-pointer">
                Import Session
              </button>
            </template>

          </template>
        </div>

        <!-- waiting: key exchange view (same for create & join) -->
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

      <!-- Split Layout -->
      <div class="flex-1 flex flex-col lg:flex-row min-h-0" :class="connectionMode === 'supabase' ? 'justify-center' : ''">

      <!-- ─── LEFT: Chat Panel ─── -->
      <div class="flex flex-col min-h-0" :class="connectionMode === 'supabase' ? 'w-full max-w-2xl mx-auto h-full' : 'w-full lg:w-1/2 h-[60vh] lg:h-auto'">

        <!-- Message list -->
        <div ref="messageListRef" class="flex-1 overflow-y-auto min-h-0 p-4 space-y-2 bg-gray-900">
          <!-- Empty state -->
          <div v-if="messages.length === 0" class="h-full flex items-center justify-center">
            <span class="text-sm text-gray-600">No messages yet</span>
          </div>

          <!-- Message bubbles -->
          <div v-for="(msg, i) in messages" :key="msg.id"
            class="flex group" :class="msg.direction === 'sent' ? 'justify-end' : 'justify-start'">
            <div class="relative max-w-[75%] px-3.5 py-2.5 space-y-2"
              :class="msg.direction === 'sent'
                ? 'bg-blue-600 rounded-2xl rounded-br-md'
                : 'bg-gray-800 rounded-2xl rounded-bl-md'">

              <!-- Delete button (hover) -->
              <button @click="deleteMessage(i)"
                class="absolute -top-2 opacity-0 group-hover:opacity-100 w-5 h-5 flex items-center justify-center rounded-full bg-gray-900 border border-gray-700 hover:bg-red-600 hover:border-red-600 text-[10px] transition-all cursor-pointer z-10"
                :class="msg.direction === 'sent' ? '-left-2' : '-right-2'">
                &#x2715;
              </button>

              <div v-if="msg.text" class="text-sm whitespace-pre-wrap">{{ msg.text }}</div>

              <template v-if="msg.attachments">
                <div v-for="(att, j) in msg.attachments" :key="j">

                  <!-- Audio player -->
                  <div v-if="att.type === 'audio'" class="space-y-1">
                    <div class="flex items-center gap-2.5 min-w-[200px]">
                      <audio :src="att.blobUrl"
                        :ref="(el: any) => { if (el) initAudioState(`${msg.id}-${j}`, el) }"
                        @loadedmetadata="onAudioMetadata(`${msg.id}-${j}`, $event.target as HTMLAudioElement)"
                        @timeupdate="onAudioTimeUpdate(`${msg.id}-${j}`, $event.target as HTMLAudioElement)"
                        @ended="onAudioEnded(`${msg.id}-${j}`)"
                        preload="metadata"
                        class="hidden" />

                      <!-- Play/Pause -->
                      <button @click="toggleAudio(`${msg.id}-${j}`)"
                        class="w-8 h-8 flex items-center justify-center rounded-full shrink-0 cursor-pointer transition-colors"
                        :class="msg.direction === 'sent' ? 'bg-blue-500 hover:bg-blue-400' : 'bg-gray-700 hover:bg-gray-600'">
                        <span v-if="audioStates[`${msg.id}-${j}`]?.playing" class="text-sm leading-none">&#x23F8;</span>
                        <span v-else class="text-[10px] leading-none ml-0.5">&#x25B6;</span>
                      </button>

                      <!-- Progress + Duration -->
                      <div class="flex-1 min-w-0 space-y-1">
                        <div class="h-1 rounded-full overflow-hidden"
                          :class="msg.direction === 'sent' ? 'bg-blue-500/40' : 'bg-gray-600'">
                          <div class="h-full rounded-full transition-[width] duration-200"
                            :class="msg.direction === 'sent' ? 'bg-white/70' : 'bg-gray-400'"
                            :style="{ width: audioProgress(`${msg.id}-${j}`) + '%' }" />
                        </div>
                        <span class="text-[10px] opacity-60">
                          {{ formatTime(audioStates[`${msg.id}-${j}`]?.currentTime ?? 0) }}
                          / {{ formatTime(audioStates[`${msg.id}-${j}`]?.duration ?? 0) }}
                        </span>
                      </div>
                    </div>
                    <button @click="downloadFile(att.blobUrl, att.name || 'audio.webm')"
                      class="text-[10px] opacity-50 hover:opacity-80 transition-opacity cursor-pointer">
                      &#x2B07; Save
                    </button>
                  </div>

                  <!-- Image (clickable for zoom) -->
                  <div v-else-if="att.type === 'image'" class="space-y-1">
                    <img :src="att.blobUrl" class="max-h-48 rounded-lg object-contain cursor-pointer hover:opacity-90 transition-opacity"
                      @click="zoomImageUrl = att.blobUrl" />
                    <button @click="downloadFile(att.blobUrl, att.name || 'image.png')"
                      class="text-[10px] opacity-50 hover:opacity-80 transition-opacity cursor-pointer">
                      &#x2B07; Save
                    </button>
                  </div>

                  <!-- Generic file -->
                  <div v-else class="flex items-center gap-2.5 min-w-[180px] py-1">
                    <span class="text-2xl shrink-0">&#x1F4C4;</span>
                    <div class="flex-1 min-w-0">
                      <div class="text-sm truncate">{{ att.name || 'file' }}</div>
                      <div class="text-[10px] opacity-50">{{ att.size ? formatSize(att.size) : '' }}</div>
                    </div>
                    <button @click="downloadFile(att.blobUrl, att.name || 'file')"
                      class="w-7 h-7 flex items-center justify-center rounded-full shrink-0 cursor-pointer transition-colors"
                      :class="msg.direction === 'sent' ? 'bg-blue-500 hover:bg-blue-400' : 'bg-gray-700 hover:bg-gray-600'">
                      <span class="text-xs">&#x2B07;</span>
                    </button>
                  </div>
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
            <template v-else-if="att.type === 'image'">
              <img :src="att.previewUrl" class="h-12 rounded object-contain" />
              <span class="text-xs text-gray-400">{{ formatSize(att.data.length) }}</span>
            </template>
            <!-- File chip -->
            <template v-else>
              <span class="text-sm">&#x1F4C4;</span>
              <span class="text-xs text-gray-300 max-w-[120px] truncate">{{ att.name }}</span>
              <span class="text-xs text-gray-500">{{ formatSize(att.data.length) }}</span>
            </template>
          </div>
        </div>

        <!-- Send progress bar -->
        <div v-if="sendProgress" class="px-4 py-2 border-t border-gray-800 bg-gray-900/50 shrink-0">
          <div class="flex items-center justify-between text-xs text-gray-400 mb-1">
            <span>{{ sendProgress.text }}</span>
            <span>{{ sendProgress.percent }}%</span>
          </div>
          <div class="h-1.5 bg-gray-800 rounded-full overflow-hidden">
            <div class="h-full bg-blue-500 rounded-full transition-[width] duration-300"
              :style="{ width: sendProgress.percent + '%' }" />
          </div>
        </div>

        <!-- Chunk receiving progress -->
        <div v-if="db.chunkProgress.value" class="px-4 py-2 border-t border-gray-800 bg-gray-900/50 shrink-0">
          <div class="flex items-center justify-between text-xs text-gray-400 mb-1">
            <span>Receiving file {{ db.chunkProgress.value.received }}/{{ db.chunkProgress.value.total }}...</span>
            <span>{{ Math.round((db.chunkProgress.value.received / db.chunkProgress.value.total) * 100) }}%</span>
          </div>
          <div class="h-1.5 bg-gray-800 rounded-full overflow-hidden">
            <div class="h-full bg-emerald-500 rounded-full transition-[width] duration-300"
              :style="{ width: (db.chunkProgress.value.received / db.chunkProgress.value.total * 100) + '%' }" />
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
            <input type="file" multiple class="hidden" @change="onFileInput" />
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

      <!-- ─── RIGHT: Crypto Panels (hidden in Supabase mode) ─── -->
      <div v-if="connectionMode !== 'supabase'" class="w-full lg:w-1/2 flex flex-col min-h-0 border-t lg:border-t-0 lg:border-l border-gray-800 h-[40vh] lg:h-auto">
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
                  <div class="flex items-center justify-between text-sm">
                    <div class="flex items-center gap-2">
                      <span>&#x1F3A4;</span>
                      <span class="font-medium">Voice message</span>
                    </div>
                    <button @click="downloadFile(att.blobUrl, att.name || 'audio.webm')" class="text-xs text-gray-400 hover:text-gray-200 cursor-pointer">&#x2B07; Save</button>
                  </div>
                  <audio :src="att.blobUrl" controls class="w-full" />
                </div>
                <div v-else-if="att.type === 'image'" class="space-y-2">
                  <div class="flex items-center justify-between text-sm">
                    <div class="flex items-center gap-2">
                      <span>&#x1F5BC;</span>
                      <span class="font-medium">Image</span>
                    </div>
                    <button @click="downloadFile(att.blobUrl, att.name || 'image.png')" class="text-xs text-gray-400 hover:text-gray-200 cursor-pointer">&#x2B07; Save</button>
                  </div>
                  <img :src="att.blobUrl" class="max-h-80 rounded-lg object-contain cursor-pointer hover:opacity-90" @click="zoomImageUrl = att.blobUrl" />
                </div>
                <div v-else class="flex items-center justify-between">
                  <div class="flex items-center gap-2 text-sm min-w-0">
                    <span>&#x1F4C4;</span>
                    <span class="font-medium truncate">{{ att.name || 'file' }}</span>
                    <span class="text-xs text-gray-500 shrink-0">{{ att.size ? formatSize(att.size) : '' }}</span>
                  </div>
                  <button @click="downloadFile(att.blobUrl, att.name || 'file')" class="text-xs text-gray-400 hover:text-gray-200 cursor-pointer shrink-0 ml-2">&#x2B07; Save</button>
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
