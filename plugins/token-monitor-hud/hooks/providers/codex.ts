// Codex quota, read the way tokenmonitor-mcp reads it: a port of
// `CodexFetcher` and `loadCodex` in plugins/tokenmonitor/server/js/src/
// {usage,creds}.js, spec in the monorepo's compat/USAGE_WIRE.md ("Codex").
// A change to the endpoint, headers or window mapping there belongs here too.

import type { EngineInterface } from 'claude-code'

import type { Window } from '../../types'
import { windowLabel } from '../forecast'
import { b64urlDecode, type Fetched, isObject, parseJSON, retryAfterMs, round1 } from './common'

export const CODEX_URL = 'https://chatgpt.com/backend-api/wham/usage'

// Windows are classified by DURATION, not by position: OpenAI has already
// swapped which one sits in primary_window (2026-07).
const SESSION_MAX = 5 * 3600 // ≤ 5h → session
const WEEKLY_MAX = 14 * 86400 // ≤ 2wk → weekly; above → monthly
const SESSION_FALLBACK = 5 * 3600
const WEEKLY_FALLBACK = 7 * 86400

export type CodexCreds = { accessToken: string; accountId: string; expiresAtMs: number }

/** A JWT's `exp` claim in ms, or 0. */
function jwtExpMs(token: string): number {
  const parts = token.split('.')
  if (parts.length !== 3) return 0
  const claims = parseJSON(b64urlDecode(parts[1]!))
  const exp = isObject(claims) ? claims.exp : undefined
  if (typeof exp !== 'number') return 0
  return exp < 1e12 ? exp * 1000 : exp
}

/** auth.json → credentials, or undefined when it holds none usable. */
export function parseCodexAuth(text: string): CodexCreds | undefined {
  const doc = parseJSON(text)
  if (!isObject(doc)) return undefined
  const tokens = isObject(doc.tokens) ? doc.tokens : {}
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  const accessToken = str(tokens.access_token) || str(doc.access_token)
  const accountId = str(tokens.account_id) || str(doc.account_id)
  if (!accessToken || !accountId) return undefined
  let expiresAtMs = 0
  const raw = doc.expires_at
  if (typeof raw === 'string' && raw) {
    const t = Date.parse(raw)
    if (Number.isFinite(t)) expiresAtMs = t
  } else if (typeof raw === 'number') {
    expiresAtMs = raw < 1e12 ? raw * 1000 : raw
  }
  if (!expiresAtMs) expiresAtMs = jwtExpMs(accessToken)
  if (!expiresAtMs) expiresAtMs = jwtExpMs(str(tokens.id_token) || str(doc.id_token))
  if (!expiresAtMs) return undefined
  return { accessToken, accountId, expiresAtMs }
}

type Bucket = 'session' | 'weekly' | 'monthly'

const classify = (seconds: number): Bucket | undefined =>
  !(seconds > 0) ? undefined : seconds <= SESSION_MAX ? 'session' : seconds <= WEEKLY_MAX ? 'weekly' : 'monthly'

function etaSeconds(w: Record<string, unknown>, now: number): number {
  if (typeof w.reset_after_seconds === 'number') return Math.max(0, Math.floor(w.reset_after_seconds))
  if (typeof w.reset_at === 'number') return Math.max(0, Math.floor(w.reset_at) - Math.floor(now / 1000))
  return 0
}

/** wham/usage → windows in Session / Weekly / Monthly order, and the plan. */
export function codexWindows(doc: unknown, now: number): { windows: Window[]; tier: string } {
  const d = isObject(doc) ? doc : {}
  const rl = isObject(d.rate_limit) ? d.rate_limit : {}
  const present = [rl.primary_window, rl.secondary_window, rl.tertiary_window].filter(isObject)
  const buckets: Partial<Record<Bucket, Window>> = {}
  const claim = (b: Bucket, w: Record<string, unknown>, seconds: number) => {
    if (buckets[b]) return
    const eta = etaSeconds(w, now)
    buckets[b] = {
      kind: `codex:${b}`,
      label: windowLabel(seconds),
      percentUsed: round1(Number(w.used_percent || 0)),
      resetsAt: eta > 0 ? new Date(now + eta * 1000).toISOString() : undefined,
      windowMs: seconds * 1000,
    }
  }
  present.forEach((w, i) => {
    const lim = Math.floor(Number(w.limit_window_seconds))
    const seconds = Number.isFinite(lim) && lim > 0 ? lim : 0
    const b = classify(seconds)
    if (b) claim(b, w, seconds)
    // No duration: a lone window is the weekly cap; with several, the first is the session.
    else if (present.length === 1 || i > 0) claim('weekly', w, WEEKLY_FALLBACK)
    else claim('session', w, SESSION_FALLBACK)
  })
  const windows = (['session', 'weekly', 'monthly'] as const).flatMap(b => (buckets[b] ? [buckets[b]] : []))
  return { windows, tier: String(d.plan_type || 'unknown') }
}

/** `$CODEX_HOME/auth.json`, else `~/.codex/auth.json`. */
async function authPath($: EngineInterface): Promise<string | undefined> {
  const codexHome = await $.env.get('CODEX_HOME')
  if (codexHome) return `${codexHome}/auth.json`
  const home = (await $.env.get('HOME')) || (await $.env.get('USERPROFILE'))
  return home ? `${home}/.codex/auth.json` : undefined
}

/**
 * One reading. Never refreshes the token: the Codex CLI owns auth.json and
 * racing its writes could corrupt it; an expired one is `login`.
 */
export async function fetchCodex($: EngineInterface, now: number): Promise<Fetched> {
  const path = await authPath($)
  if (!path || !(await $.fs.exists(path))) return { status: 'absent' }
  let creds: CodexCreds | undefined
  try {
    creds = parseCodexAuth(await $.fs.read(path))
  } catch {
    return { status: 'absent' }
  }
  // no tokens (an API-key login) or a file caught mid-rewrite: not signed in here
  if (!creds) return { status: 'absent' }
  if (now >= creds.expiresAtMs) return { status: 'login' }

  let resp
  try {
    resp = await $.http.fetch(CODEX_URL, {
      headers: {
        Authorization: `Bearer ${creds.accessToken}`,
        'ChatGPT-Account-Id': creds.accountId,
        Accept: 'application/json',
        'User-Agent': 'tokenmonitor-mcp/usage',
        'OpenAI-Beta': 'chatgpt-account=enabled',
      },
    })
  } catch {
    return { status: 'unavailable' }
  }
  if (resp.status === 401) return { status: 'login' }
  if (resp.status === 429) return { status: 'rate_limited', retryAfterMs: retryAfterMs(resp.headers, now) }
  if (!resp.ok) return { status: 'unavailable' }
  const doc = parseJSON(resp.text)
  if (!isObject(doc)) return { status: 'unavailable' }
  return { status: 'ok', ...codexWindows(doc, now) }
}
