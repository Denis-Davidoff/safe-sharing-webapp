export interface DbSettings {
  url: string        // Supabase URL (https://xxx.supabase.co)
  anonKey: string    // Supabase anon/public key
  table: string      // Table name
  column: string     // Column for encrypted message
  idColumn: string   // Primary key column (default: 'id')
  pollInterval: number // ms
}

export interface DbMessageEnvelope {
  s: string // sender fingerprint (first 8 chars of base64 public key)
  d: string // encrypted base64 ciphertext
}

export interface DbChunkEnvelope {
  s: string  // sender fingerprint
  t: 'chunk' // type discriminator
  mid: string // message ID (random 6-char string)
  seq: number // chunk sequence number (0-based)
  total: number // total number of chunks
  d: string  // chunk data (piece of encrypted base64 string)
}

export interface DbMessageRow {
  pk: string | number
  data: string
}

export type DbConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error'
