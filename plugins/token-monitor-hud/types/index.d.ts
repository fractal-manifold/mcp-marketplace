/**
 * One quota window. `kind` is unique across providers (`five_hour`,
 * `codex:weekly`, `agy:Gemini`) and keys the samples and the alerts.
 */
export type Window = {
  kind: string
  /** short text before the bar: `5h`, `7d`, `Gemini` */
  label: string
  percentUsed: number
  resetsAt?: string
  /** the window's length, when known; drives the average rate and the pace */
  windowMs?: number
}

/** What Claude Code itself reports for this session. */
export type Snapshot = {
  windows: Window[]
  ctxTokens?: number
  ctxWindow: number
  ctxPercent?: number
  usd?: number
}

export type ProviderId = 'codex' | 'antigravity'

/**
 * - `ok`: fresh windows
 * - `degraded`: reached the provider but its quota call failed (no numbers)
 * - `absent`: not signed in on this machine; not shown
 * - `login`: credentials there but expired or refused
 * - `rate_limited` / `unavailable`: transient; the last windows stay, stale
 */
export type ProviderStatus = 'ok' | 'degraded' | 'absent' | 'login' | 'rate_limited' | 'unavailable'

/** The last reading of one provider. Never holds a credential. */
export type ProviderReading = {
  provider: ProviderId
  status: ProviderStatus
  windows: Window[]
  tier?: string
  /** when `windows` were fetched (ms); absent before the first success */
  fetchedAt?: number
  /** when the provider was last asked (ms) */
  checkedAt: number
  /** don't ask again before this (ms), unless the pane asks for a refresh */
  nextAt: number
}

/** One reading of a window's percent (or of the session's $), for the burn rate. */
export type Sample = { t: number; kind: string; pct: number }

declare module 'claude-code' {
  interface PluginState {
    'token-monitor-hud': {
      snapshot: Snapshot | null
      samples: Sample[]
      isBandHidden: boolean
      /** highest alert threshold already toasted, per window kind */
      alerted: Record<string, number>
      providers: ProviderReading[]
    }
  }
}
