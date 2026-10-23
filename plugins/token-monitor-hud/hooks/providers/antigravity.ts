// Antigravity (agy) quota, read the way tokenmonitor-mcp reads it: a port of
// `AntigravityFetcher`, `normalizeKeyringToken` and `antigravityApplyQuota` in
// plugins/tokenmonitor/server/js/src/usage.js, spec in the monorepo's
// compat/USAGE_WIRE.md ("Antigravity"). A change to the host, the User-Agent,
// the request bodies or the group mapping there belongs here too.

import type { EngineInterface } from 'claude-code'

import type { Window } from '../../types'
import { b64urlDecode, type Fetched, isObject, parseJSON, retryAfterMs, round1 } from './common'

// The grouped weekly quota is served from the `daily-` host; prod 403s it.
const HOST = 'https://daily-cloudcode-pa.googleapis.com/v1internal:'
export const LOAD_CODE_ASSIST_URL = HOST + 'loadCodeAssist'
export const QUOTA_URL = HOST + 'retrieveUserQuotaSummary'
// The quota RPC is gated on agy's registered User-Agent (403 without it).
const UA = 'antigravity/cli/1.0.13 (aidev_client; os_type=linux; arch=amd64)'
const WEEKLY_MS = 7 * 86400 * 1000
// agy keeps its consumer token under this keyring service (macOS: account "antigravity").
const KEYRING_SERVICE = 'gemini'
const KEYCHAIN_ACCOUNT = 'antigravity'
const MACOS_SECURITY = '/usr/bin/security'

export type KeyringToken = { access_token: string; expiry: string }

/**
 * agy's keyring secret → its token. Linux libsecret holds the JSON
 * {token:{access_token,expiry}}; the macOS Keychain holds
 * `<id>:<base64url(JSON)>`; a top-level {access_token} is accepted too.
 */
export function normalizeKeyringToken(raw: string | undefined | null): KeyringToken | null {
  if (!raw) return null
  const s = String(raw).trim()
  const parse = (text: string): KeyringToken | null => {
    const d = parseJSON(text)
    if (!isObject(d)) return null
    const tok = isObject(d.token) ? d.token : d
    return typeof tok.access_token === 'string' && tok.access_token
      ? { access_token: tok.access_token, expiry: typeof tok.expiry === 'string' ? tok.expiry : '' }
      : null
  }
  const direct = parse(s)
  if (direct) return direct
  if (s.includes(':')) {
    for (const seg of s.split(':')) {
      if (seg.length < 16) continue
      const t = parse(b64urlDecode(seg))
      if (t) return t
    }
  }
  return null
}

/** "Gemini Models" → "Gemini", "Claude and GPT models" → "Claude and GPT". */
export function groupLabel(displayName: unknown): string {
  const s = String(displayName || '').trim().replace(/\s+models$/i, '')
  return s ? Array.from(s).slice(0, 15).join('') : 'Quota'
}

const usedPct = (remainingFraction: unknown) => {
  let r = Number(remainingFraction)
  if (!Number.isFinite(r) || r < 0) r = 0
  else if (r > 1) r = 1
  return round1((1 - r) * 100)
}

/** retrieveUserQuotaSummary → one weekly window per quota group. */
export function antigravityWindows(quota: unknown): Window[] {
  const groups = isObject(quota) && Array.isArray(quota.groups) ? quota.groups : []
  const windows: Window[] = []
  for (const g of groups) {
    if (!isObject(g)) continue
    const buckets = (Array.isArray(g.buckets) ? g.buckets : []).filter(isObject)
    const b = buckets.find(x => x.window === 'weekly') ?? buckets[0]
    if (!b) continue
    const label = groupLabel(g.displayName)
    const reset = typeof b.resetTime === 'string' && Number.isFinite(Date.parse(b.resetTime)) ? b.resetTime : undefined
    windows.push({ kind: `agy:${label}`, label, percentUsed: usedPct(b.remainingFraction), resetsAt: reset, windowMs: WEEKLY_MS })
  }
  return windows
}

const tierOf = (doc: Record<string, unknown>) =>
  isObject(doc.paidTier) ? String(doc.paidTier.id || 'paid') : isObject(doc.currentTier) ? String(doc.currentTier.id || 'unknown') : undefined

/**
 * agy's secret: the text, `missing` when the keyring holds none (the tool ran
 * and found nothing), `failed` when the tool didn't run (not installed, a
 * locked keyring timing out after suspend).
 */
async function readKeyring($: EngineInterface): Promise<string | 'missing' | 'failed'> {
  const argv = (await $.fs.exists(MACOS_SECURITY))
    ? [MACOS_SECURITY, 'find-generic-password', '-s', KEYRING_SERVICE, '-a', KEYCHAIN_ACCOUNT, '-w']
    : ['secret-tool', 'lookup', 'service', KEYRING_SERVICE]
  try {
    const r = await $.process.run(argv, { timeoutMs: 5000 })
    return r.exitCode === 0 ? r.stdout : 'missing'
  } catch {
    return 'failed'
  }
}

/**
 * One reading. Read-only on the token, like the broker: agy keeps it fresh
 * while it runs, and an expired one is `login`. The token is read from the
 * keyring for each reading and lives only in this call.
 */
export async function fetchAntigravity($: EngineInterface, now: number): Promise<Fetched> {
  const secret = await readKeyring($)
  if (secret === 'failed') return { status: 'absent', isTransient: true }
  const tok = normalizeKeyringToken(secret === 'missing' ? undefined : secret)
  if (!tok) return { status: 'absent' }
  const expMs = Date.parse(tok.expiry) || 0
  if (expMs && expMs - now < 60_000) return { status: 'login' }
  const headers = {
    Authorization: `Bearer ${tok.access_token}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'User-Agent': UA,
  }

  let resp
  try {
    // agy sends exactly this; the answer names the project the quota call needs.
    resp = await $.http.fetch(LOAD_CODE_ASSIST_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({ metadata: { ideType: 'ANTIGRAVITY' } }),
    })
  } catch {
    return { status: 'unavailable' }
  }
  if (resp.status === 401) return { status: 'login' }
  if (resp.status === 429) return { status: 'rate_limited', retryAfterMs: retryAfterMs(resp.headers, now) }
  if (!resp.ok) return { status: 'unavailable' }
  const doc = parseJSON(resp.text)
  if (!isObject(doc)) return { status: 'unavailable' }
  const tier = tierOf(doc)

  // The quota call wants a top-level `project` and nothing else.
  const project = String(doc.cloudaicompanionProject || '')
  try {
    const q = await $.http.fetch(QUOTA_URL, { method: 'POST', headers, body: JSON.stringify(project ? { project } : {}) })
    const windows = q.ok ? antigravityWindows(parseJSON(q.text)) : []
    // Reached the provider but no quota: say so rather than show a made-up 0%.
    return windows.length > 0 ? { status: 'ok', windows, tier } : { status: 'degraded', tier }
  } catch {
    return { status: 'degraded', tier }
  }
}
