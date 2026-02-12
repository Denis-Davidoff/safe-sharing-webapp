<script setup lang="ts">
import { ref, watch } from 'vue'
import type { DbSettings, DbConnectionState } from '../types/db'

const props = defineProps<{
  settings: DbSettings
  connectionState: DbConnectionState
  connectionError: string
  isConnected: boolean
  isConfigured: boolean
  isSyncing: boolean
  isListening: boolean
  tables: string[]
  columns: string[]
  canSync: boolean
}>()

const emit = defineEmits<{
  connect: []
  disconnect: []
  startSync: []
  stopSync: []
  'update:settings': [settings: DbSettings]
  fetchColumns: [table: string]
}>()

const isOpen = ref(false)

function update(field: keyof DbSettings, value: string | number) {
  emit('update:settings', { ...props.settings, [field]: value })
}

// When table changes, fetch columns
watch(() => props.settings.table, (t) => {
  if (t && props.isConnected) emit('fetchColumns', t)
})

const stateColor: Record<DbConnectionState, string> = {
  disconnected: 'bg-gray-500',
  connecting: 'bg-yellow-500 animate-pulse',
  connected: 'bg-green-500',
  error: 'bg-red-500',
}
</script>

<template>
  <!-- Gear button -->
  <button @click="isOpen = !isOpen"
    class="fixed top-[61px] right-4 z-50 w-10 h-10 flex items-center justify-center rounded-full bg-gray-800 border border-gray-700 hover:bg-gray-700 transition-colors cursor-pointer">
    <span class="text-lg">&#x2699;</span>
    <span v-if="isConnected" class="absolute -top-0.5 -right-0.5 w-3 h-3 rounded-full bg-green-500 border-2 border-gray-950" />
  </button>

  <!-- Panel overlay -->
  <div v-if="isOpen" class="fixed inset-0 z-40 flex justify-end">
    <div class="absolute inset-0 bg-black/40" @click="isOpen = false" />

    <div class="relative w-full max-w-sm bg-gray-900 border-l border-gray-800 p-5 overflow-y-auto space-y-5">

      <div class="flex items-center justify-between">
        <h2 class="text-lg font-semibold">Supabase Settings</h2>
        <button @click="isOpen = false" class="text-gray-400 hover:text-gray-200 cursor-pointer text-xl">&times;</button>
      </div>

      <!-- Connection Status -->
      <div class="flex items-center gap-2 text-sm">
        <span class="w-2.5 h-2.5 rounded-full" :class="stateColor[connectionState]" />
        <span class="text-gray-400">
          {{ connectionState === 'disconnected' ? 'Not connected' :
             connectionState === 'connecting' ? 'Connecting...' :
             connectionState === 'connected' ? 'Connected' : 'Connection error' }}
        </span>
      </div>
      <div v-if="connectionError" class="text-xs text-red-400 bg-red-900/20 rounded-lg p-2">
        {{ connectionError }}
      </div>

      <!-- Connection form -->
      <div class="space-y-3">
        <div class="space-y-1">
          <label class="block text-xs text-gray-400">Supabase URL</label>
          <input type="text"
            :value="settings.url"
            @input="update('url', ($event.target as HTMLInputElement).value)"
            placeholder="https://xxx.supabase.co"
            :disabled="isConnected"
            class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50" />
        </div>

        <div class="space-y-1">
          <label class="block text-xs text-gray-400">Anon Key</label>
          <input type="password"
            :value="settings.anonKey"
            @input="update('anonKey', ($event.target as HTMLInputElement).value)"
            placeholder="eyJhbGciOiJIUzI1NiIs..."
            :disabled="isConnected"
            class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500 disabled:opacity-50" />
        </div>

        <button v-if="!isConnected"
          @click="emit('connect')"
          :disabled="!settings.url || !settings.anonKey || connectionState === 'connecting'"
          class="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg text-sm font-medium transition-colors cursor-pointer disabled:cursor-not-allowed">
          Connect
        </button>
        <button v-else
          @click="emit('disconnect')"
          class="w-full py-2 bg-red-600 hover:bg-red-500 rounded-lg text-sm font-medium transition-colors cursor-pointer">
          Disconnect
        </button>
      </div>

      <!-- Table & Column selection (only when connected) -->
      <template v-if="isConnected">
        <div class="border-t border-gray-800 pt-4 space-y-3">
          <h3 class="text-sm font-medium text-gray-300">Table &amp; Column</h3>

          <div class="space-y-1">
            <label class="block text-xs text-gray-400">Table name</label>
            <div v-if="tables.length > 0">
              <select
                :value="settings.table"
                @change="update('table', ($event.target as HTMLSelectElement).value)"
                class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500">
                <option value="">-- select table --</option>
                <option v-for="t in tables" :key="t" :value="t">{{ t }}</option>
              </select>
            </div>
            <input v-else type="text"
              :value="settings.table"
              @input="update('table', ($event.target as HTMLInputElement).value)"
              placeholder="messages"
              class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
          </div>

          <div class="space-y-1">
            <label class="block text-xs text-gray-400">Message column</label>
            <div v-if="columns.length > 0">
              <select
                :value="settings.column"
                @change="update('column', ($event.target as HTMLSelectElement).value)"
                class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500">
                <option value="">-- select column --</option>
                <option v-for="c in columns" :key="c" :value="c">{{ c }}</option>
              </select>
            </div>
            <input v-else type="text"
              :value="settings.column"
              @input="update('column', ($event.target as HTMLInputElement).value)"
              placeholder="payload"
              class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
          </div>

          <div class="space-y-1">
            <label class="block text-xs text-gray-400">ID column (primary key)</label>
            <input type="text"
              :value="settings.idColumn"
              @input="update('idColumn', ($event.target as HTMLInputElement).value)"
              placeholder="id"
              class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
          </div>

          <div class="space-y-1">
            <label class="block text-xs text-gray-400">Sender column (for server-side filtering)</label>
            <input type="text"
              :value="settings.senderColumn"
              @input="update('senderColumn', ($event.target as HTMLInputElement).value)"
              placeholder="sender"
              class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
            <p class="text-xs text-gray-600">Leave empty to skip server-side filtering</p>
          </div>
        </div>

        <!-- Sync controls (only when configured + handshake done) -->
        <div v-if="isConfigured" class="border-t border-gray-800 pt-4 space-y-3">
          <h3 class="text-sm font-medium text-gray-300">Message Sync</h3>

          <div class="space-y-1">
            <label class="block text-xs text-gray-400">Poll interval (used when Realtime is unavailable)</label>
            <select
              :value="settings.pollInterval"
              @change="update('pollInterval', Number(($event.target as HTMLSelectElement).value))"
              :disabled="isSyncing"
              class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50">
              <option :value="10000">10 seconds</option>
              <option :value="15000">15 seconds</option>
              <option :value="20000">20 seconds</option>
              <option :value="30000">30 seconds</option>
              <option :value="60000">1 minute</option>
              <option :value="120000">2 minutes</option>
            </select>
          </div>

          <button v-if="!canSync"
            disabled
            class="w-full py-2 bg-gray-700 text-gray-500 rounded-lg text-sm font-medium cursor-not-allowed">
            Complete handshake first
          </button>
          <button v-else-if="!isSyncing"
            @click="emit('startSync')"
            class="w-full py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm font-medium transition-colors cursor-pointer">
            Start Sync
          </button>
          <button v-else
            @click="emit('stopSync')"
            class="w-full py-2 bg-yellow-600 hover:bg-yellow-500 rounded-lg text-sm font-medium transition-colors cursor-pointer">
            Stop Sync
          </button>

          <!-- Sync status -->
          <div v-if="isSyncing" class="space-y-1">
            <div v-if="isListening" class="flex items-center gap-2 text-xs text-emerald-400">
              <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              Realtime active + backup poll every 5 min
            </div>
            <div v-else class="flex items-center gap-2 text-xs text-yellow-400">
              <span class="w-2 h-2 rounded-full bg-yellow-500 animate-pulse" />
              Polling every {{ settings.pollInterval / 1000 }}s (Realtime unavailable)
            </div>
          </div>
        </div>

        <!-- Helper SQL -->
        <div class="border-t border-gray-800 pt-4 space-y-2">
          <details class="text-xs text-gray-500">
            <summary class="cursor-pointer hover:text-gray-300">SQL for table setup &amp; RPC functions</summary>
            <pre class="mt-2 bg-gray-800 rounded-lg p-3 overflow-x-auto text-gray-400 whitespace-pre">-- Create a messages table
CREATE TABLE messages (
  id BIGSERIAL PRIMARY KEY,
  payload TEXT,
  sender TEXT  -- fingerprint for server-side filtering
);

-- Index for fast sender filtering
CREATE INDEX idx_messages_sender ON messages (sender);

-- Enable RLS and allow all operations
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow_all" ON messages
  FOR ALL USING (true) WITH CHECK (true);

-- Enable Realtime (instant delivery via WebSocket)
ALTER PUBLICATION supabase_realtime ADD TABLE messages;

-- Optional: RPC to list tables
CREATE OR REPLACE FUNCTION list_tables()
RETURNS TABLE(table_name text) AS $$
  SELECT table_name::text
  FROM information_schema.tables
  WHERE table_schema = 'public'
    AND table_type = 'BASE TABLE'
$$ LANGUAGE sql SECURITY DEFINER;

-- Optional: RPC to list columns
CREATE OR REPLACE FUNCTION list_columns(p_table text)
RETURNS TABLE(column_name text) AS $$
  SELECT column_name::text
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND table_name = p_table
$$ LANGUAGE sql SECURITY DEFINER;</pre>
          </details>
        </div>
      </template>

    </div>
  </div>
</template>
