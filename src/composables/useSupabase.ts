import { ref, computed, type Ref } from 'vue'
import { useLocalStorage } from '@vueuse/core'
import { createClient, type SupabaseClient, type RealtimeChannel } from '@supabase/supabase-js'
import type { DbSettings, DbConnectionState, DbMessageEnvelope, DbChunkEnvelope, DbMessageRow } from '../types/db'

const REALTIME_BACKUP_INTERVAL = 5 * 60 * 1000 // 5 minutes
const CHUNK_SIZE = 750_000 // ~750KB base64 chars per chunk (safe for Realtime + API)
const CHUNK_TIMEOUT = 5 * 60 * 1000 // 5 min — discard incomplete chunks after this

const DEFAULT_SETTINGS: DbSettings = {
  url: '',
  anonKey: '',
  table: '',
  column: '',
  idColumn: 'id',
  pollInterval: 30000,
}

export function useSupabase(options: {
  fingerprint: Ref<string>
  onMessages: (messages: DbMessageRow[]) => void
}) {
  // ─── Persisted Settings ──────────────────────────────────
  const settings = useLocalStorage<DbSettings>('xchat-db-settings', { ...DEFAULT_SETTINGS })

  // ─── State ───────────────────────────────────────────────
  const connectionState = ref<DbConnectionState>('disconnected')
  const connectionError = ref('')
  const tables = ref<string[]>([])
  const columns = ref<string[]>([])

  let client: SupabaseClient | null = null
  let pollTimer: ReturnType<typeof setTimeout> | null = null
  let realtimeChannel: RealtimeChannel | null = null

  const isConnected = computed(() => connectionState.value === 'connected')
  const isConfigured = computed(() =>
    isConnected.value &&
    settings.value.table !== '' &&
    settings.value.column !== '' &&
    settings.value.idColumn !== ''
  )
  const isSyncing = ref(false)
  const isListening = ref(false)

  // Chunk receiving progress (exposed for UI)
  const chunkProgress = ref<{ mid: string; received: number; total: number } | null>(null)

  // ─── Chunk Reassembly Buffer ───────────────────────────────
  // Map<mid, { total, receivedAt, chunks: Map<seq, data>, pks: (string|number)[] }>
  const chunkBuffer = new Map<string, {
    total: number
    receivedAt: number
    chunks: Map<number, string>
    pks: (string | number)[]
  }>()

  function cleanupStaleChunks() {
    const now = Date.now()
    for (const [mid, buf] of chunkBuffer) {
      if (now - buf.receivedAt > CHUNK_TIMEOUT) {
        console.warn(`[Supabase] Chunk buffer expired for mid=${mid} (${buf.chunks.size}/${buf.total} received)`)
        // Delete stale chunk rows from DB
        for (const pk of buf.pks) {
          deleteMessage(pk)
        }
        chunkBuffer.delete(mid)
      }
    }
  }

  // ─── Connect ─────────────────────────────────────────────
  async function connect(): Promise<boolean> {
    connectionState.value = 'connecting'
    connectionError.value = ''

    try {
      // Auto-parse URL: extract base URL and table name if user pasted full link
      const parsed = new URL(settings.value.url)
      const pathParts = parsed.pathname.split('/').filter(Boolean)
      if (pathParts.length > 0) {
        if (!settings.value.table) {
          settings.value.table = pathParts[0]!
        }
        settings.value.url = parsed.origin
        console.log(`[Supabase] Auto-parsed URL → base: ${settings.value.url}, table: ${settings.value.table}`)
      }

      // Close previous client if any
      if (client) {
        await client.auth.signOut().catch(() => {})
        client = null
      }

      client = createClient(settings.value.url, settings.value.anonKey, {
        auth: {
          storageKey: `xchat-${Math.random().toString(36).slice(2, 8)}`,
          persistSession: false,
        },
      })

      const { error } = await client.auth.getSession()
      if (error) throw new Error(error.message)

      connectionState.value = 'connected'
      console.log('[Supabase] Connected to', settings.value.url)

      await fetchTables()
      return true
    } catch (err: any) {
      connectionState.value = 'error'
      connectionError.value = err.message
      client = null
      console.error('[Supabase] Connection failed:', err.message)
      return false
    }
  }

  // ─── Disconnect ──────────────────────────────────────────
  function disconnect() {
    stopSync()
    client = null
    connectionState.value = 'disconnected'
    connectionError.value = ''
    tables.value = []
    columns.value = []
    chunkBuffer.clear()
    console.log('[Supabase] Disconnected')
  }

  // ─── Fetch Tables (via RPC or fallback) ──────────────────
  async function fetchTables() {
    if (!client) return
    try {
      const { data, error } = await client.rpc('list_tables')
      if (error) throw error
      tables.value = (data as { table_name: string }[]).map(r => r.table_name)
      console.log(`[Supabase] Found ${tables.value.length} tables`)
    } catch {
      tables.value = []
      console.log('[Supabase] list_tables() RPC not available — use manual table name input')
    }
  }

  // ─── Fetch Columns ──────────────────────────────────────
  async function fetchColumns(table: string) {
    if (!client) return
    columns.value = []
    try {
      const { data, error } = await client.rpc('list_columns', { p_table: table })
      if (error) throw error
      columns.value = (data as { column_name: string }[]).map(r => r.column_name)
      console.log(`[Supabase] Table "${table}" columns:`, columns.value)
    } catch {
      try {
        const { data } = await client!.from(table).select('*').limit(1)
        if (data && data.length > 0) {
          columns.value = Object.keys(data[0])
          console.log(`[Supabase] Discovered columns from data:`, columns.value)
        } else {
          console.log('[Supabase] Table is empty — type column name manually')
        }
      } catch (e: any) {
        console.error('[Supabase] Failed to fetch columns:', e.message)
      }
    }
  }

  // ─── Send Message (auto-chunks if needed) ──────────────
  async function sendMessage(
    encryptedBase64: string,
    onProgress?: (sent: number, total: number) => void
  ): Promise<boolean> {
    if (!client || !isConfigured.value || !options.fingerprint.value) return false

    // If small enough, send as single message
    if (encryptedBase64.length <= CHUNK_SIZE) {
      onProgress?.(1, 1)
      return sendSingleMessage(encryptedBase64)
    }

    // Otherwise, split into chunks
    return sendChunked(encryptedBase64, onProgress)
  }

  async function sendSingleMessage(encryptedBase64: string): Promise<boolean> {
    const envelope: DbMessageEnvelope = {
      s: options.fingerprint.value,
      d: encryptedBase64,
    }

    const row = { [settings.value.column]: JSON.stringify(envelope) }

    const { error } = await client!.from(settings.value.table).insert(row)
    if (error) {
      console.error('[Supabase] Insert failed:', error.message)
      return false
    }

    console.log('[Supabase] Message sent to DB')
    return true
  }

  async function sendChunked(
    encryptedBase64: string,
    onProgress?: (sent: number, total: number) => void
  ): Promise<boolean> {
    const mid = Math.random().toString(36).slice(2, 8)
    const totalChunks = Math.ceil(encryptedBase64.length / CHUNK_SIZE)
    const BATCH_SIZE = 10

    console.log(`[Supabase] Sending chunked message: mid=${mid}, ${totalChunks} chunks, total ${encryptedBase64.length} chars`)

    // Build all chunk rows
    const allRows: Record<string, string>[] = []
    for (let seq = 0; seq < totalChunks; seq++) {
      const start = seq * CHUNK_SIZE
      const chunkData = encryptedBase64.slice(start, start + CHUNK_SIZE)

      const envelope: DbChunkEnvelope = {
        s: options.fingerprint.value,
        t: 'chunk',
        mid,
        seq,
        total: totalChunks,
        d: chunkData,
      }

      allRows.push({ [settings.value.column]: JSON.stringify(envelope) })
    }

    // Send in batches for progress + reliability
    let sent = 0
    for (let i = 0; i < allRows.length; i += BATCH_SIZE) {
      const batch = allRows.slice(i, i + BATCH_SIZE)
      const { error } = await client!.from(settings.value.table).insert(batch)
      if (error) {
        console.error(`[Supabase] Chunked insert failed at batch ${Math.floor(i / BATCH_SIZE) + 1}:`, error.message)
        return false
      }
      sent += batch.length
      onProgress?.(sent, totalChunks)
      console.log(`[Supabase] Chunks sent: ${sent}/${totalChunks} (mid=${mid})`)
    }

    console.log(`[Supabase] All ${totalChunks} chunks sent (mid=${mid})`)
    return true
  }

  // ─── Process Incoming Row ─────────────────────────────────
  // Returns: 'message' row for immediate delivery, 'chunk' buffered, or null if skipped
  function processIncomingRow(rec: Record<string, any>): { type: 'message'; row: DbMessageRow } | { type: 'assembled'; data: string; pks: (string | number)[] } | null {
    const { column, idColumn } = settings.value
    const raw = rec[column]
    if (!raw) return null

    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw

    // Skip our own messages
    if (parsed.s === options.fingerprint.value) return null

    // Chunk envelope
    if (parsed.t === 'chunk') {
      const chunk = parsed as DbChunkEnvelope
      const pk = rec[idColumn]

      let buf = chunkBuffer.get(chunk.mid)
      if (!buf) {
        buf = { total: chunk.total, receivedAt: Date.now(), chunks: new Map(), pks: [] }
        chunkBuffer.set(chunk.mid, buf)
      }

      buf.chunks.set(chunk.seq, chunk.d)
      buf.pks.push(pk)
      buf.receivedAt = Date.now()

      console.log(`[Supabase] Chunk ${chunk.seq + 1}/${chunk.total} for mid=${chunk.mid}`)

      // Update progress for UI
      chunkProgress.value = { mid: chunk.mid, received: buf.chunks.size, total: buf.total }

      // Check if complete
      if (buf.chunks.size === buf.total) {
        // Reassemble in order
        let assembled = ''
        for (let i = 0; i < buf.total; i++) {
          assembled += buf.chunks.get(i) || ''
        }
        const pks = [...buf.pks]
        chunkBuffer.delete(chunk.mid)
        chunkProgress.value = null

        console.log(`[Supabase] All chunks received for mid=${chunk.mid} — assembled ${assembled.length} chars`)
        return { type: 'assembled', data: assembled, pks }
      }

      return null // Still waiting for more chunks
    }

    // Regular message envelope
    if (parsed.s && parsed.d) {
      return { type: 'message', row: { pk: rec[idColumn], data: raw } }
    }

    return null
  }

  // ─── Poll Messages ──────────────────────────────────────
  async function pollOnce() {
    if (!client || !isConfigured.value || !options.fingerprint.value) return

    // Cleanup stale chunk buffers
    cleanupStaleChunks()

    const { table, column, idColumn } = settings.value

    const { data, error } = await client
      .from(table)
      .select(`${idColumn}, ${column}`)
      .order(idColumn, { ascending: true })

    if (error) {
      console.error('[Supabase] Poll failed:', error.message)
      return
    }

    if (!data || data.length === 0) return

    const incoming: DbMessageRow[] = []
    for (const row of data) {
      try {
        const rec = row as Record<string, any>
        const result = processIncomingRow(rec)
        if (!result) continue

        if (result.type === 'message') {
          incoming.push(result.row)
        } else if (result.type === 'assembled') {
          // Create a synthetic message row with the reassembled data
          const envelope: DbMessageEnvelope = {
            s: '', // fingerprint already checked in processIncomingRow
            d: result.data,
          }
          incoming.push({ pk: result.pks[0]!, data: JSON.stringify(envelope) })
          // Delete all chunk rows from DB
          for (const pk of result.pks) {
            deleteMessage(pk)
          }
        }
      } catch {
        // skip malformed rows
      }
    }

    if (incoming.length > 0) {
      console.log(`[Supabase] Polled ${incoming.length} new message(s)`)
      options.onMessages(incoming)
    }
  }

  // ─── Delete Message ─────────────────────────────────────
  async function deleteMessage(pk: string | number) {
    if (!client || !isConfigured.value) return

    const { error } = await client
      .from(settings.value.table)
      .delete()
      .eq(settings.value.idColumn, pk)

    if (error) {
      console.error('[Supabase] Delete failed:', error.message)
    } else {
      console.log(`[Supabase] Deleted message ${settings.value.idColumn}=${pk}`)
    }
  }

  // ─── Polling Engine ────────────────────────────────────
  function schedulePoll(interval: number) {
    if (!isSyncing.value) return
    pollTimer = setTimeout(async () => {
      await pollOnce()
      // Re-check: if Realtime is active, use backup interval; otherwise user interval
      const nextInterval = isListening.value ? REALTIME_BACKUP_INTERVAL : settings.value.pollInterval
      schedulePoll(nextInterval)
    }, interval)
  }

  function startPollLoop(interval: number) {
    stopPollLoop()
    console.log(`[Supabase] Poll loop started (interval: ${Math.round(interval / 1000)}s)`)
    pollOnce()
    schedulePoll(interval)
  }

  function stopPollLoop() {
    if (pollTimer) {
      clearTimeout(pollTimer)
      pollTimer = null
    }
  }

  // ─── Realtime Subscription ────────────────────────────────
  function tryRealtime() {
    if (!client || !isConfigured.value || !options.fingerprint.value) return

    const { table } = settings.value

    realtimeChannel = client
      .channel(`xchat-${table}`)
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table },
        (payload) => {
          try {
            const rec = payload.new as Record<string, any>
            const result = processIncomingRow(rec)
            if (!result) return

            if (result.type === 'message') {
              console.log('[Supabase] Realtime: new message received')
              options.onMessages([result.row])
            } else if (result.type === 'assembled') {
              console.log('[Supabase] Realtime: chunked message fully assembled')
              const envelope: DbMessageEnvelope = {
                s: '',
                d: result.data,
              }
              options.onMessages([{ pk: result.pks[0]!, data: JSON.stringify(envelope) }])
              for (const pk of result.pks) {
                deleteMessage(pk)
              }
            }
          } catch {
            // skip malformed realtime events
          }
        }
      )
      .subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          isListening.value = true
          console.log('[Supabase] Realtime active — switching poll to backup (5 min)')
          // Switch polling to 5 min backup interval
          stopPollLoop()
          startPollLoop(REALTIME_BACKUP_INTERVAL)
        } else if (status === 'CHANNEL_ERROR') {
          console.warn('[Supabase] Realtime unavailable — polling at configured interval')
          isListening.value = false
          // Keep polling at user's configured interval (already running or restart)
          stopPollLoop()
          startPollLoop(settings.value.pollInterval)
        }
      })
  }

  function stopRealtime() {
    if (realtimeChannel && client) {
      client.removeChannel(realtimeChannel)
      realtimeChannel = null
    }
    isListening.value = false
  }

  // ─── Unified Sync Control ────────────────────────────────
  function startSync() {
    if (!isConfigured.value) return

    isSyncing.value = true
    console.log('[Supabase] Starting sync...')

    // Start polling immediately at user interval
    startPollLoop(settings.value.pollInterval)

    // Try Realtime — if it succeeds, polling switches to 5 min backup
    tryRealtime()
  }

  function stopSync() {
    isSyncing.value = false
    stopRealtime()
    stopPollLoop()
    chunkBuffer.clear()
    console.log('[Supabase] Sync stopped')
  }

  return {
    settings,
    connectionState,
    connectionError,
    isConnected,
    isConfigured,
    isSyncing,
    isListening,
    chunkProgress,
    tables,
    columns,

    connect,
    disconnect,
    fetchTables,
    fetchColumns,
    sendMessage,
    pollOnce,
    deleteMessage,
    startSync,
    stopSync,
  }
}
