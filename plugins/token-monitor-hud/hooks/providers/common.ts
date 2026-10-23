import type { ProviderStatus, Window } from '../../types'

/**
 * What one fetch of a provider came to. `windows` only on `ok`; a credential
 * never leaves the fetch.
 */
export type Fetched = {
  status: ProviderStatus
  windows?: Window[]
  tier?: string
  /** on `rate_limited`: the upstream Retry-After, in ms */
  retryAfterMs?: number
  /** on `absent`: the check itself failed, so a provider that was signed in keeps its last reading */
  isTransient?: boolean
}

/** base64url (padded or not) → UTF-8 text; '' when it isn't base64. */
export function b64urlDecode(s: string): string {
  try {
    const b = s.replace(/-/g, '+').replace(/_/g, '/')
    const bin = atob(b + '='.repeat((4 - (b.length % 4)) % 4))
    return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0)))
  } catch {
    return ''
  }
}

/** Retry-After (seconds or an HTTP date) in ms; 0 when absent or past. */
export function retryAfterMs(headers: Record<string, string>, now: number): number {
  const v = headers['retry-after']
  if (!v) return 0
  const n = Number(v)
  if (Number.isFinite(n) && n > 0) return Math.floor(n) * 1000
  const t = Date.parse(v)
  return Number.isFinite(t) && t > now ? t - now : 0
}

export function parseJSON(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

export const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

/** Percent rounded to one decimal, so 44.99999999999999 reads 45. */
export const round1 = (pct: number) => Math.round(pct * 10) / 10
