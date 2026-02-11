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

export interface DbMessageRow {
  pk: string | number
  data: string
}

export type DbConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error'
