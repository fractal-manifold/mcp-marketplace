import { atom, read, update } from 'claude-code'
import type { EngineInterface, PluginOptions, Register, SessionMeasureInput, SessionUsage } from 'claude-code'

import type { ProviderId, ProviderReading, Sample, Snapshot, Window } from '../types'
import {
  addSamples,
  bar,
  colorFor,
  detailLine,
  dot,
  fmtDuration,
  fmtPct,
  fmtProjection,
  fmtTokens,
  forecast,
  resetIn,
  spendRate,
} from './forecast'
import { fetchAntigravity } from './providers/antigravity'
import { fetchCodex } from './providers/codex'
import type { Fetched } from './providers/common'

const PANE = 'token-monitor-hud'
const ALERTS = [80, 95] // toast when a window crosses these %
const TICK_MS = 30_000 // keeps the reset countdowns ticking, and checks what is due
const POLL_MS = 5 * 60_000 // Codex / Antigravity, while all is well
const ABSENT_RETRY_MS = 15 * 60_000 // not signed in, or signed out: look again this often
const PANE_REFRESH_MS = 60_000 // opening the pane refreshes, at most this often

const snapshot = atom({ plugin: 'token-monitor-hud', key: 'snapshot' } as const, null)
const samples = atom({ plugin: 'token-monitor-hud', key: 'samples' } as const, [])
const isBandHidden = atom({ plugin: 'token-monitor-hud', key: 'isBandHidden' } as const, false)
const alerted = atom({ plugin: 'token-monitor-hud', key: 'alerted' } as const, {})
const providers = atom({ plugin: 'token-monitor-hud', key: 'providers' } as const, [])

// ---------- Claude, from the session itself ----------

const CLAUDE_LABEL: Record<string, string> = { five_hour: '5h', seven_day: '7d', spend_limit: '$' }
const CLAUDE_LEN: Record<string, number> = { five_hour: 5 * 3_600_000, seven_day: 7 * 24 * 3_600_000 }

const toSnapshot = (u: SessionUsage | SessionMeasureInput): Snapshot => ({
  windows: u.rateLimits.map(r => ({
    kind: r.kind,
    label: CLAUDE_LABEL[r.kind] ?? r.kind,
    percentUsed: r.percentUsed,
    resetsAt: r.resetsAt,
    windowMs: CLAUDE_LEN[r.kind],
  })),
  ctxTokens: u.context.tokens,
  ctxWindow: u.context.window,
  ctxPercent: u.context.percent,
  usd: u.cost?.usd,
})

const spendLine = (snap: Snapshot, list: Sample[], now: number) => {
  if (snap.usd === undefined) return undefined
  const rate = spendRate(list, now)
  const five = snap.windows.find(w => w.kind === 'five_hour')
  const r = five ? resetIn(five, now) : undefined
  const proj = rate !== undefined && r !== undefined ? snap.usd + Math.max(0, rate) * (r / 3_600_000) : undefined
  return (
    `session $${snap.usd.toFixed(2)}` +
    (rate !== undefined ? ` · $${rate.toFixed(2)}/h` : '') +
    (proj !== undefined ? ` · → $${proj.toFixed(2)} by 5h reset` : '')
  )
}

/** Toasts each window that crossed a threshold since the last reading; the record lives in $.state, so a reload doesn't repeat them. */
async function alert($: EngineInterface, windows: Window[], who: string) {
  // decided against the value update() writes over, so a retry after another
  // dispatch's write neither loses its record nor toasts on stale data
  let crossed: Window[] = []
  await update($, alerted, cur => {
    crossed = []
    const next = { ...cur }
    for (const w of windows) {
      const hit = ALERTS.filter(a => w.percentUsed >= a).pop() ?? 0
      if (hit > (cur[w.kind] ?? 0)) crossed.push(w)
      next[w.kind] = hit
    }
    return next
  })
  for (const w of crossed) {
    $.ui.toast(`TokenMonitor: ${who}${w.label} window at ${fmtPct(w.percentUsed)}`, { timeoutMs: 8000 })
  }
}

async function ingest($: EngineInterface, snap: Snapshot) {
  const now = await $.clock.now()
  await update($, snapshot, () => snap)
  await update($, samples, list => addSamples(list, snap.windows, now, snap.usd))
  await alert($, snap.windows, '')
}

// ---------- Codex and Antigravity, from their own sign-ins ----------

const PROVIDERS: readonly ProviderId[] = ['codex', 'antigravity']
const NAME: Record<ProviderId, string> = { codex: 'Codex', antigravity: 'Antigravity' }
const TAG: Record<ProviderId, string> = { codex: 'codex', antigravity: 'agy' }
const LOGIN_HINT: Record<ProviderId, string> = {
  codex: 'run `codex login`',
  antigravity: 'open agy to refresh its sign-in',
}

const enabled = (options: PluginOptions) => PROVIDERS.filter(p => options[p] !== false)

/** The readings to show: enabled providers that are signed in on this machine. */
const shown = (list: ProviderReading[], options: PluginOptions) =>
  enabled(options).flatMap(p => list.filter(r => r.provider === p && r.status !== 'absent'))

function nextReading(prev: ProviderReading | undefined, provider: ProviderId, fetched: Fetched, now: number): ProviderReading {
  // A check that failed outright says nothing about the sign-in: a provider
  // that had a reading is unreachable for now, not signed out.
  const got: Fetched =
    fetched.isTransient && prev !== undefined && prev.windows.length > 0 ? { status: 'unavailable' } : fetched
  // A transient failure keeps the last windows, shown with their age.
  const keep = got.status === 'rate_limited' || got.status === 'unavailable'
  const wait =
    got.status === 'rate_limited'
      ? Math.max(POLL_MS, got.retryAfterMs ?? 0)
      : got.status === 'absent' || got.status === 'login'
        ? ABSENT_RETRY_MS
        : POLL_MS
  return {
    provider,
    status: got.status,
    windows: got.windows ?? (keep ? (prev?.windows ?? []) : []),
    tier: got.tier ?? prev?.tier,
    fetchedAt: got.windows ? now : keep ? prev?.fetchedAt : undefined,
    checkedAt: now,
    nextAt: now + wait,
  }
}

/** Asks the provider if it is due; resolves the reading it wrote, or undefined when it wasn't due. */
async function refresh($: EngineInterface, p: ProviderId, force: boolean): Promise<ProviderReading | undefined> {
  const now = await $.clock.now()
  const prev = (await read($, providers)).find(r => r.provider === p)
  const due =
    !prev ||
    now >= prev.nextAt ||
    (force && prev.status !== 'rate_limited' && prev.status !== 'absent' && now - prev.checkedAt >= PANE_REFRESH_MS)
  if (!due) return undefined
  let got: Fetched
  try {
    got = p === 'codex' ? await fetchCodex($, now) : await fetchAntigravity($, now)
  } catch {
    got = { status: 'unavailable' }
  }
  const reading = nextReading(prev, p, got, now)
  await update($, providers, list =>
    [...list.filter(r => r.provider !== p), reading].sort((a, b) => PROVIDERS.indexOf(a.provider) - PROVIDERS.indexOf(b.provider)),
  )
  if (got.windows) {
    await update($, samples, list => addSamples(list, got.windows ?? [], now))
    await alert($, got.windows, `${NAME[p]} `)
  }
  return reading
}

// The refresh of a provider under way: a second caller (the tick, the pane,
// the text report) waits for it rather than asking twice. It takes the
// reading from the promise, not from $.state: a dispatch's reads stand at one
// moment, so a write another dispatch made meanwhile isn't visible to it.
const inFlight = new Map<ProviderId, Promise<ProviderReading | undefined>>()

function poll($: EngineInterface, p: ProviderId, force: boolean): Promise<ProviderReading | undefined> {
  const running = inFlight.get(p)
  if (running) return running
  const job = refresh($, p, force).finally(() => inFlight.delete(p))
  inFlight.set(p, job)
  return job
}

/** Each enabled provider that is due; one failing never holds up the other. Resolves the fresh readings. */
const pollAll = ($: EngineInterface, options: PluginOptions, force: boolean) =>
  Promise.all(enabled(options).map(p => poll($, p, force).catch(() => undefined)))

/** The stored readings with the fresh ones laid over them. */
const latest = (stored: ProviderReading[], fresh: (ProviderReading | undefined)[]) =>
  PROVIDERS.flatMap(p => {
    const r = fresh.find(f => f?.provider === p) ?? stored.find(s => s.provider === p)
    return r ? [r] : []
  })

function statusLine(r: ProviderReading, now: number): string | undefined {
  const age = r.fetchedAt !== undefined ? ` · reading from ${fmtDuration(now - r.fetchedAt)} ago` : ''
  switch (r.status) {
    case 'login':
      return `sign-in expired: ${LOGIN_HINT[r.provider]}`
    case 'degraded':
      return 'reached, but its quota is unavailable right now'
    case 'rate_limited':
      return `rate limited, retrying in ${fmtDuration(r.nextAt - now)}${age}`
    case 'unavailable':
      return `unreachable, retrying in ${fmtDuration(r.nextAt - now)}${age}`
    default:
      return r.windows.length === 0 ? 'no quota windows on this plan' : undefined
  }
}

const heading = (r: ProviderReading) => NAME[r.provider] + (r.tier && r.tier !== 'unknown' ? ` · ${r.tier}` : '')

// ---------- text report ----------

const windowLines = (w: Window, list: Sample[], now: number) => {
  const f = forecast(w, list, now)
  return [
    `${dot(w.percentUsed)} ${w.label} ${bar(w.percentUsed, 10)} ${fmtPct(w.percentUsed)} ${fmtProjection(f)}`.trimEnd(),
    `   ${detailLine(w, f, now)}`,
  ]
}

/** The pane's content as plain text, for surfaces without panes. */
export function report(snap: Snapshot | null, others: ProviderReading[], list: Sample[], now: number): string {
  const lines = ['TokenMonitor']
  if (!snap) lines.push('Claude: waiting for the first API response.')
  else {
    lines.push('Claude')
    if (snap.windows.length === 0) lines.push('No rate-limit windows yet: they come with the first reply (an API key has none)')
    for (const w of snap.windows) lines.push(...windowLines(w, list, now))
    const ctx = snap.ctxPercent ?? 0
    lines.push(`${dot(ctx)} ctx ${bar(ctx, 10)} ${snap.ctxPercent ?? '–'}% (${fmtTokens(snap.ctxTokens)} / ${fmtTokens(snap.ctxWindow)})`)
    const spend = spendLine(snap, list, now)
    if (spend) lines.push(`💵 ${spend}`)
  }
  for (const r of others) {
    lines.push(heading(r))
    for (const w of r.windows) lines.push(...windowLines(w, list, now))
    const status = statusLine(r, now)
    if (status) lines.push(`   ${status}`)
  }
  return lines.join('\n')
}

// ---------- the mod ----------

export const register: Register = (on, options) => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'token-monitor-hud',
      description: 'TokenMonitor pane (text report where panes are not shown). Args: band | text',
      argumentHint: '[band|text]',
    })
    await ingest($, toSnapshot(await $.session.usage()))
    // first Codex / Antigravity reading off the start path, then on the tick
    $.clock.after(1000, () => void pollAll($, options, false))
    $.clock.every(TICK_MS, () => {
      $.ui.invalidate('ui.render')
      void pollAll($, options, false)
    })
    return next(e)
  })

  on('session.measure', async ($, e, next) => {
    await ingest($, toSnapshot(e))
    return next(e)
  })

  on('command.run', { command: 'token-monitor-hud' }, async ($, e) => {
    const arg = e.args.trim()
    if (arg === 'band') {
      const hidden = !(await read($, isBandHidden))
      await update($, isBandHidden, () => hidden)
      return { text: hidden ? 'TokenMonitor band hidden.' : 'TokenMonitor band shown.' }
    }
    // Fresh reading, so the text report is current even before any measure event
    await ingest($, toSnapshot(await $.session.usage()))
    if (arg !== 'text') {
      const placed = await $.ui.open({ id: PANE, title: 'TokenMonitor', closeOnEscape: true })
      if (placed.isPlaced) {
        // the pane redraws as the readings land
        $.clock.after(0, () => void pollAll($, options, true))
        return {}
      }
    }
    // Surfaces that place no pane (the mobile app) get the report as text
    const fresh = await pollAll($, options, true)
    const others = shown(latest(await read($, providers), fresh), options)
    return { text: report(await read($, snapshot), others, await read($, samples), await $.clock.now()) }
  })

  // ---------- compact band above the prompt ----------
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const snap = await read($, snapshot)
    if (e.props.hasSurvey || !snap || (await read($, isBandHidden))) return next(e)

    const { Box, Text } = $.ui.resolve(e)
    const now = await $.clock.now()
    const list = await read($, samples)
    const narrow = (e.props.bodyColumns ?? 80) < 70
    const others = shown(await read($, providers), options).filter(r => r.windows.length > 0)

    const part = (w: Window, barW: number) => {
      const r = resetIn(w, now)
      const f = forecast(w, list, now)
      return (
        <Box key={w.kind} flexDirection="row" columnGap={1}>
          <Text dimColor>{w.label}</Text>
          {barW > 0 && <Text color={colorFor(w.percentUsed)}>{bar(w.percentUsed, barW)}</Text>}
          <Text color={colorFor(w.percentUsed)}>{fmtPct(w.percentUsed)}</Text>
          {f.projected !== undefined && <Text color={colorFor(f.projected)}>{`→${Math.round(f.projected)}%`}</Text>}
          {r !== undefined && <Text dimColor>{`↻${fmtDuration(r)}`}</Text>}
        </Box>
      )
    }

    const claudeRow = (
      <Box key="claude" flexDirection="row" columnGap={2}>
        {snap.windows.length === 0 && <Text dimColor>quota: no reading yet</Text>}
        {snap.windows.map(w => part(w, narrow ? 6 : 10))}
        {snap.ctxPercent !== undefined && <Text color={colorFor(snap.ctxPercent)}>{`ctx ${snap.ctxPercent}%`}</Text>}
        {snap.usd !== undefined && !narrow && <Text dimColor>{`$${snap.usd.toFixed(2)}`}</Text>}
      </Box>
    )
    if (others.length === 0 || (e.props.maxRows ?? 3) < 2) return claudeRow

    return (
      <Box flexDirection="column">
        {claudeRow}
        <Box key="others" flexDirection="row" columnGap={2}>
          {others.map(r => (
            <Box key={r.provider} flexDirection="row" columnGap={1}>
              <Text dimColor>{TAG[r.provider]}</Text>
              {r.windows.map(w => part(w, narrow ? 0 : 6))}
            </Box>
          ))}
        </Box>
      </Box>
    )
  })

  // ---------- full pane ----------
  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const snap = await read($, snapshot)
    const list = await read($, samples)
    const others = shown(await read($, providers), options)
    const now = await $.clock.now()
    const barW = Math.max(10, Math.min(40, (e.props.bodyColumns ?? 40) - 14))

    const windowRow = (w: Window) => {
      const f = forecast(w, list, now)
      return (
        <Box key={w.kind} flexDirection="column">
          <Box flexDirection="row" columnGap={1}>
            <Text weight="semibold">{w.label.padEnd(3)}</Text>
            <Text color={colorFor(w.percentUsed)}>{bar(w.percentUsed, barW)}</Text>
            <Text color={colorFor(w.percentUsed)} weight="semibold">{fmtPct(w.percentUsed)}</Text>
            {f.projected !== undefined && <Text color={colorFor(f.projected)}>{fmtProjection(f)}</Text>}
          </Box>
          <Text dimColor>{`    ${detailLine(w, f, now)}`}</Text>
        </Box>
      )
    }

    const claude = !snap ? (
      <Text key="claude" dimColor>Claude: waiting for the first API response…</Text>
    ) : (
      <Box key="claude" flexDirection="column" rowGap={1}>
        <Text weight="semibold">Claude</Text>
        {snap.windows.length === 0 && <Text dimColor>No rate-limit windows yet: they come with the first reply (an API key has none)</Text>}
        {snap.windows.map(windowRow)}
        <Box flexDirection="column">
          <Box flexDirection="row" columnGap={1}>
            <Text weight="semibold">ctx</Text>
            <Text color={colorFor(snap.ctxPercent ?? 0)}>{bar(snap.ctxPercent ?? 0, barW)}</Text>
            <Text color={colorFor(snap.ctxPercent ?? 0)} weight="semibold">{`${snap.ctxPercent ?? '–'}%`}</Text>
          </Box>
          <Text dimColor>{`    ${fmtTokens(snap.ctxTokens)} / ${fmtTokens(snap.ctxWindow)} tokens`}</Text>
        </Box>
        {spendLine(snap, list, now) !== undefined && <Text>{spendLine(snap, list, now)}</Text>}
      </Box>
    )

    return (
      <Box flexDirection="column" rowGap={1}>
        {claude}
        {others.map(r => {
          const status = statusLine(r, now)
          return (
            <Box key={r.provider} flexDirection="column" rowGap={1}>
              <Text weight="semibold">{heading(r)}</Text>
              {r.windows.map(windowRow)}
              {status !== undefined && <Text dimColor>{status}</Text>}
            </Box>
          )
        })}
        <Text dimColor>/token-monitor-hud band — toggle the band · Esc closes</Text>
      </Box>
    )
  })
}
