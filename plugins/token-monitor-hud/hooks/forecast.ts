import type { Sample, Window } from '../types'

export const BURN_WINDOW_MS = 30 * 60 * 1000 // burn rate over the last 30 min
const SHORT_WINDOW_MS = 5 * 3_600_000 // up to this, the recent rate leads the projection

export const colorFor = (pct: number) => (pct >= 85 ? 'red' : pct >= 60 ? 'yellow' : 'green')
export const dot = (pct: number) => (pct >= 85 ? '🔴' : pct >= 60 ? '🟡' : '🟢')

export const bar = (pct: number, width: number) => {
  const filled = Math.max(0, Math.min(width, Math.round((pct / 100) * width)))
  return '█'.repeat(filled) + '░'.repeat(width - filled)
}

export const fmtPct = (pct: number) => `${Math.round(pct * 10) / 10}%`

export const fmtDuration = (ms: number) => {
  if (ms <= 0) return 'now'
  const m = Math.round(ms / 60000)
  const d = Math.floor(m / 1440)
  const h = Math.floor((m % 1440) / 60)
  const mm = m % 60
  if (d > 0) return `${d}d${h}h`
  if (h > 0) return `${h}h${String(mm).padStart(2, '0')}m`
  return `${mm}m`
}

export const fmtTokens = (n?: number) =>
  n === undefined ? '–' : n >= 1e6 ? `${(n / 1e6).toFixed(2)}M` : `${Math.round(n / 1000)}k`

/** `5h`, `7d`, `30d` for a window length in seconds. */
export const windowLabel = (seconds: number) =>
  seconds % 86400 === 0 ? `${seconds / 86400}d` : seconds % 3600 === 0 ? `${seconds / 3600}h` : `${Math.round(seconds / 3600)}h`

export const resetIn = (w: Window, now: number) =>
  w.resetsAt ? Date.parse(w.resetsAt) - now : undefined

/** %/hour over the recent samples of one window, or undefined if too little data. */
export const burnRate = (list: Sample[], kind: string, now: number) => {
  const recent = list.filter(s => s.kind === kind && now - s.t <= BURN_WINDOW_MS)
  if (recent.length < 2) return undefined
  const first = recent[0]!
  const last = recent[recent.length - 1]!
  const dt = last.t - first.t
  if (dt < 60_000) return undefined
  return ((last.pct - first.pct) / dt) * 3_600_000
}

export type Forecast = {
  /** %/h over the last 30 min */
  recent?: number
  /** %/h averaged since the window opened */
  avg?: number
  /** the rate the projection uses */
  rate?: number
  /** % the window will be at when it resets, at that rate */
  projected?: number
  /** ms until 100%, when that comes before the reset */
  eta?: number
  /** points ahead (+) or behind (−) of a linear spend of the window */
  pace?: number
}

export const isShort = (w: Window) => w.windowMs !== undefined && w.windowMs <= SHORT_WINDOW_MS

/**
 * Projection for one window. A short (≤ 5h) window: the last 30 min if there
 * is a reading (it reacts to what you are doing now), else the window average.
 * A long one: the window average (30 min is noise at weekly scale, and nights
 * count).
 */
export function forecast(w: Window, list: Sample[], now: number): Forecast {
  const reset = resetIn(w, now)
  const len = w.windowMs
  const recent = burnRate(list, w.kind, now)
  let avg: number | undefined
  let pace: number | undefined
  if (reset !== undefined && len !== undefined) {
    const elapsed = Math.max(0, len - reset)
    if (elapsed >= 10 * 60_000) avg = (w.percentUsed / elapsed) * 3_600_000
    pace = w.percentUsed - (100 * elapsed) / len
  }
  const rate = isShort(w) ? (recent ?? avg) : (avg ?? recent)
  if (rate === undefined || reset === undefined) return { recent, avg, rate, pace }
  const projected = w.percentUsed + Math.max(0, rate) * (reset / 3_600_000)
  const eta = rate > 0 && projected > 100 ? ((100 - w.percentUsed) / rate) * 3_600_000 : undefined
  return { recent, avg, rate, projected, eta, pace }
}

/** $/h over the last 30 min of session cost. */
export const spendRate = (list: Sample[], now: number) => burnRate(list, 'usd', now)

const fmtRate = (r?: number) => (r === undefined ? '–' : `${r.toFixed(1)}%/h`)
const fmtPace = (p?: number) => {
  if (p === undefined) return ''
  const r = Math.round(p)
  return ` · pace ${r > 0 ? '+' : r < 0 ? '−' : '±'}${Math.abs(r)} pts`
}

export const fmtProjection = (f: Forecast) =>
  f.projected === undefined ? '' : `→ ${Math.round(f.projected)}% at reset ${f.projected > 100 ? '⚠️' : '✅'}`

export const detailLine = (w: Window, f: Forecast, now: number) => {
  const r = resetIn(w, now)
  return (
    `reset ${r !== undefined ? 'in ' + fmtDuration(r) : '–'}` +
    (isShort(w) ? ` · now ${fmtRate(f.recent)}` : '') +
    ` · avg ${fmtRate(f.avg)}` +
    fmtPace(f.pace) +
    (f.eta !== undefined ? ` · full in ${fmtDuration(f.eta)}` : '')
  )
}

/**
 * The samples after one more reading of `windows` at `now`: older than the
 * burn window dropped, and a window whose percent fell (it reset) starting over.
 */
export function addSamples(list: Sample[], windows: Window[], now: number, usd?: number): Sample[] {
  let next = list.filter(s => now - s.t <= BURN_WINDOW_MS)
  for (const w of windows) {
    const prev = [...next].reverse().find(s => s.kind === w.kind)
    if (prev && w.percentUsed < prev.pct) next = next.filter(s => s.kind !== w.kind)
    next.push({ t: now, kind: w.kind, pct: w.percentUsed })
  }
  if (usd !== undefined) next.push({ t: now, kind: 'usd', pct: usd })
  return next.slice(-500)
}
