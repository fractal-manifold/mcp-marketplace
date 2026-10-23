import { expect, test } from 'claude-code/testing'
import type { TestBody } from 'claude-code/testing'

import { antigravityWindows, normalizeKeyringToken } from './providers/antigravity'
import { codexWindows, parseCodexAuth } from './providers/codex'

const T0 = Date.parse('2026-10-23T10:00:00Z')
const HOME = '/home/u'
const CODEX_AUTH = `${HOME}/.codex/auth.json`

const usage = (fivePct: number, sevenPct: number) => ({
  startedAt: T0,
  context: { tokens: 120_000, window: 200_000, percent: 60 },
  rateLimits: [
    { kind: 'five_hour', percentUsed: fivePct, resetsAt: '2026-10-23T12:30:00Z' },
    { kind: 'seven_day', percentUsed: sevenPct, resetsAt: '2026-10-26T10:00:00Z' },
  ],
  cost: { usd: 1.23 },
})

const BAND = {
  plugin: 'token-monitor-hud',
  component: 'AbovePrompt',
  props: { hasSurvey: false, isWorking: false, maxRows: 3, bodyColumns: 120, scroll: { offset: 0, bodyRows: 3 }, view: {} },
} as const

const PANE = {
  plugin: 'token-monitor-hud',
  component: 'Pane',
  requestId: 'token-monitor-hud',
  props: { title: 'TokenMonitor', isFocused: false, bodyColumns: 60, placement: 'dock', scroll: { offset: 0, bodyRows: 30 }, view: {} },
} as const

const b64url = (s: string) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const jwt = (exp: number) => `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify({ exp }))}.sig`

type Http = { status: number; body: unknown; headers?: Record<string, string> }
type Machine = {
  /** let `$.clock.after` fire (the start-up refresh); `every` never does */
  timers?: boolean
  files?: Record<string, string>
  keyring?: string
  /** the keyring tool fails to run (a locked keyring timing out) */
  keyringFails?: boolean
  http?: (url: string) => Http
}
type Sent = { url: string; headers: Record<string, string>; body?: string }

/** The engine beneath the mod, with this machine's files, keyring and network. */
function engine(on: Parameters<TestBody>[1], m: Machine, clock: { now: number; usage?: [number, number]; ticks?: number }) {
  const toasts: string[] = []
  const sent: Sent[] = []
  const ran: string[][] = []
  on('clock.now', () => ({ value: clock.now }))
  // no timers: the readings a test checks come from the command, awaited
  // `clock.ticks` periods of the interval run (when session.start registers it), then it ends
  on('clock.every', () => {
    if (!clock.ticks) return { deny: 'no timers in tests' }
    clock.ticks--
    return { value: undefined }
  })
  on('clock.after', () => (m.timers ? { value: undefined } : { deny: 'no timers in tests' }))
  on('command.register', () => ({ value: { command: 'token-monitor-hud' } }))
  on('session.usage', () => ({ value: usage(...(clock.usage ?? [40, 18])) }))
  on('ui.toast', (_, e) => {
    toasts.push(String((e as { text: string }).text))
    return { value: undefined }
  })
  on('ui.open', () => ({ value: { isPlaced: false, reason: 'mobile' } }))
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('session.measure', (_, e) => ({ changed: e.changed }))
  on('env.get', (_, e) => ({ value: e.name === 'HOME' ? HOME : undefined }))
  on('fs.exists', (_, e) => ({ value: (e as { path: string }).path in (m.files ?? {}) }))
  on('fs.read', (_, e) => {
    const text = m.files?.[e.path]
    if (text === undefined) throw new Error('ENOENT')
    return { value: text }
  })
  on('process.run', (_, e) => {
    ran.push([...e.argv])
    if (m.keyringFails) throw new Error('timed out')
    const found = m.keyring !== undefined
    return { value: { exitCode: found ? 0 : 1, stdout: m.keyring ?? '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
  })
  on('http.fetch', (_, e) => {
    sent.push({ url: e.url, headers: e.init?.headers ?? {}, body: e.init?.body })
    const r = m.http?.(e.url) ?? { status: 404, body: {} }
    const status = r.status
    return { value: { status, ok: status >= 200 && status < 300, headers: r.headers ?? {}, text: JSON.stringify(r.body) } }
  })
  return { toasts, sent, ran }
}

const textReport = async ($: Parameters<TestBody>[0], args = 'text') => {
  const out = await $.command.run({ command: 'token-monitor-hud', args } as Parameters<typeof $.command.run>[0])
  return String((out as { text?: string }).text)
}

// ---------- Claude, from the session ----------

test('band shows both windows, context and cost; pane shows burn rate and ETA', async ($, on) => {
  const clock = { now: T0 }
  const { toasts } = engine(on, {}, clock)

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const band = await $.ui.mount({ ...BAND, surface: 'terminal' })
  expect((await band.find({ type: 'Text', text: '40%' }))?.text).toBe('40%')
  expect((await band.find({ type: 'Text', text: /ctx/ }))?.text).toBe('ctx 60%')
  expect((await band.find({ type: 'Text', text: /\$/ }))?.text).toBe('$1.23')
  expect(await band.find({ type: 'Text', text: 'codex' })).toBeUndefined()
  await band.unmount()

  // 20 minutes later the 5h window went from 40% to 85%: 135%/h, crosses 80%
  clock.now = T0 + 20 * 60_000
  await $.session.measure({ ...usage(85, 19), changed: ['rateLimits'] })
  expect(toasts.some(t => t.includes('5h window at 85%'))).toBe(true)

  const pane = await $.ui.mount({ ...PANE, surface: 'terminal' })
  const detail = await pane.find({ type: 'Text', text: /now 135\.0%\/h/ })
  expect(detail?.text).toContain('full in 7m')
  // 85% + 135%/h × 2h10m to reset
  expect((await pane.find({ type: 'Text', text: /at reset/ }))?.text).toBe('→ 378% at reset ⚠️')
  await pane.unmount()
})

test('where no pane is placed (mobile), the command answers with a text report', async ($, on) => {
  const { sent, ran } = engine(on, {}, { now: T0 })

  await $.session.start({ cwd: '/', surface: 'mobile', isInteractive: true })
  const text = await textReport($, '')
  // 40% after 2.5h of the 5h window: avg 16%/h, 2.5h left → 80% at reset, 10 pts under a linear pace
  expect(text).toContain('5h ████░░░░░░ 40% → 80% at reset ✅')
  expect(text).toContain('reset in 2h30m · now – · avg 16.0%/h · pace −10 pts')
  // 18% after 4 of 7 days: avg 0.19%/h, 3 days left → 32%, 39 pts under pace
  expect(text).toContain('7d ██░░░░░░░░ 18% → 32% at reset ✅')
  expect(text).toContain('pace −39 pts')
  expect(text).toContain('ctx ██████░░░░ 60% (120k / 200k)')
  // signed in to neither: nothing requested, nothing shown
  expect(sent.length).toBe(0)
  expect(ran.length).toBe(1)
  expect(text).not.toContain('Codex')
  expect(text).not.toContain('Antigravity')
})

test('a toast fires once per crossing, survives a restart, and comes back after a reset', async ($, on) => {
  const clock: { now: number; usage?: [number, number] } = { now: T0 }
  const { toasts } = engine(on, {}, clock)
  const at = (n: number) => toasts.filter(t => t.includes('5h window at')).length

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  clock.now = T0 + 10 * 60_000
  await $.session.measure({ ...usage(85, 19), changed: ['rateLimits'] })
  expect(at(0)).toBe(1)
  await $.session.measure({ ...usage(86, 19), changed: ['rateLimits'] })
  expect(at(0)).toBe(1)

  // the session starts again (a reload runs register and session.start anew): $.state remembers
  clock.usage = [86, 19]
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  expect(at(0)).toBe(1)

  // the window reset: its old samples go, so the burn rate doesn't read negative
  clock.now = T0 + 20 * 60_000
  await $.session.measure({ ...usage(2, 19), changed: ['rateLimits'] })
  clock.now = T0 + 25 * 60_000
  await $.session.measure({ ...usage(4, 19), changed: ['rateLimits'] })
  const pane = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await pane.find({ type: 'Text', text: /now 24\.0%\/h/ }))).toBeDefined()
  await pane.unmount()

  clock.now = T0 + 60 * 60_000
  await $.session.measure({ ...usage(81, 19), changed: ['rateLimits'] })
  expect(at(0)).toBe(2)
})

// ---------- Codex ----------

test('codex mapping classifies windows by duration (parity with the broker)', () => {
  // single weekly window (OpenAI, 2026-07)
  const single = codexWindows(
    { plan_type: 'plus', rate_limit: { primary_window: { used_percent: 1, limit_window_seconds: 604800, reset_after_seconds: 602722 }, secondary_window: null } },
    T0,
  )
  expect(single.tier).toBe('plus')
  expect(single.windows.map(w => [w.kind, w.label, w.percentUsed])).toEqual([['codex:weekly', '7d', 1]])
  expect(single.windows[0]?.resetsAt).toBe(new Date(T0 + 602722_000).toISOString())

  // inverted: weekly in primary, 5h in secondary
  const inverted = codexWindows(
    {
      rate_limit: {
        primary_window: { used_percent: 6, limit_window_seconds: 604800, reset_after_seconds: 582744 },
        secondary_window: { used_percent: 33, limit_window_seconds: 18000, reset_after_seconds: 14007 },
      },
    },
    T0,
  )
  expect(inverted.windows.map(w => [w.label, w.percentUsed])).toEqual([['5h', 33], ['7d', 6]])

  // a monthly (> 2 weeks) window, and a fractional duration that floors
  const monthly = codexWindows(
    {
      rate_limit: {
        primary_window: { used_percent: 20, limit_window_seconds: 18000.5, reset_after_seconds: 3600 },
        secondary_window: { used_percent: 42, limit_window_seconds: 2592000, reset_after_seconds: 1000000 },
      },
    },
    T0,
  )
  expect(monthly.windows.map(w => [w.kind, w.label, w.windowMs])).toEqual([
    ['codex:session', '5h', 18000_000],
    ['codex:monthly', '30d', 2592000_000],
  ])

  // no duration given: falls back to position
  const legacy = codexWindows({ rate_limit: { primary_window: { used_percent: 9 }, secondary_window: { used_percent: 3 } } }, T0)
  expect(legacy.windows.map(w => w.kind)).toEqual(['codex:session', 'codex:weekly'])
})

test('codex auth.json: tokens nested or top level, expiry from expires_at or the JWT', () => {
  const exp = Math.floor(T0 / 1000) + 3600
  expect(parseCodexAuth(JSON.stringify({ tokens: { access_token: jwt(exp), account_id: 'acct' } }))).toEqual({
    accessToken: jwt(exp),
    accountId: 'acct',
    expiresAtMs: exp * 1000,
  })
  expect(parseCodexAuth(JSON.stringify({ access_token: 'opaque', account_id: 'a', expires_at: '2026-10-24T00:00:00Z' }))?.expiresAtMs).toBe(
    Date.parse('2026-10-24T00:00:00Z'),
  )
  expect(parseCodexAuth(JSON.stringify({ tokens: { access_token: 'opaque', account_id: 'a' } }))).toBeUndefined()
  expect(parseCodexAuth('not json')).toBeUndefined()
})

const WHAM = {
  plan_type: 'plus',
  rate_limit: { primary_window: { used_percent: 42, limit_window_seconds: 604800, reset_after_seconds: 3 * 86400 }, secondary_window: null },
}

test('signed in to Codex: its quota joins the report and the band', async ($, on) => {
  const exp = Math.floor(T0 / 1000) + 3600
  const { sent } = engine(
    on,
    {
      files: { [CODEX_AUTH]: JSON.stringify({ tokens: { access_token: jwt(exp), account_id: 'acct-1' } }) },
      http: url => (url.includes('wham/usage') ? { status: 200, body: WHAM } : { status: 404, body: {} }),
    },
    { now: T0 },
  )

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const text = await textReport($)
  expect(text).toContain('Codex · plus')
  expect(text).toContain('7d ████░░░░░░ 42%')
  expect(sent.length).toBe(1)
  expect(sent[0]?.url).toBe('https://chatgpt.com/backend-api/wham/usage')
  expect(sent[0]?.headers.Authorization).toBe(`Bearer ${jwt(exp)}`)
  expect(sent[0]?.headers['ChatGPT-Account-Id']).toBe('acct-1')

  const band = await $.ui.mount({ ...BAND, surface: 'terminal' })
  expect((await band.find({ type: 'Text', text: 'codex' }))?.text).toBe('codex')
  expect((await band.find({ type: 'Text', text: '42%' }))?.text).toBe('42%')
  await band.unmount()

  // asked again within the minute: no second request
  await textReport($)
  expect(sent.length).toBe(1)
})

test('a report asked while a refresh is under way waits for it, and asks once', async ($, on) => {
  const exp = Math.floor(T0 / 1000) + 3600
  const { sent } = engine(
    on,
    {
      files: { [CODEX_AUTH]: JSON.stringify({ tokens: { access_token: jwt(exp), account_id: 'a' } }) },
      http: () => ({ status: 200, body: WHAM }),
    },
    { now: T0 },
  )
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  // as when the start-up refresh and the command overlap
  const [a, b] = await Promise.all([textReport($), textReport($)])
  expect(a).toContain('Codex · plus')
  expect(b).toContain('Codex · plus')
  expect(sent.length).toBe(1)
})

test('a Codex API-key login (no tokens in auth.json) is left out, not called expired', async ($, on) => {
  const { sent } = engine(on, { files: { [CODEX_AUTH]: JSON.stringify({ auth_mode: 'apikey', OPENAI_API_KEY: 'sk-test' }) } }, { now: T0 })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const text = await textReport($)
  expect(text).not.toContain('Codex')
  expect(sent.length).toBe(0)
})

test('the tick honours the backoffs: Retry-After for a 429, 15 min for a provider not signed in', async ($, on) => {
  const exp = Math.floor(T0 / 1000) + 7200
  let limited = false
  const clock: { now: number; ticks?: number } = { now: T0 }
  const { sent, ran } = engine(
    on,
    {
      files: { [CODEX_AUTH]: JSON.stringify({ tokens: { access_token: jwt(exp), account_id: 'a' } }) },
      http: () => (limited ? { status: 429, body: {}, headers: { 'retry-after': '900' } } : { status: 200, body: WHAM }),
    },
    clock,
  )
  const tick = async (at: number) => {
    clock.now = at
    clock.ticks = 1
    await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
    const band = await $.ui.mount({ ...BAND, surface: 'terminal' }) // lets the tick's refresh settle
    await band.unmount()
  }
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await textReport($) // Codex read; agy not signed in (one keyring look)
  limited = true
  clock.now = T0 + 6 * 60_000
  await textReport($) // Codex 429, Retry-After 15 min; agy's 15 min not up, even for the pane
  expect([sent.length, ran.length]).toEqual([2, 1])

  await tick(T0 + 10 * 60_000) // neither is due
  expect([sent.length, ran.length]).toEqual([2, 1])

  limited = false
  await tick(T0 + 22 * 60_000) // both are
  expect([sent.length, ran.length]).toEqual([3, 2])
})

test('a keyring that fails to answer keeps the last Antigravity reading', async ($, on) => {
  const m: Machine = { keyring: JSON.stringify(INNER), http: agyHttp(200) }
  const clock = { now: T0 }
  engine(on, m, clock)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  expect(await textReport($)).toContain('Gemini █████░░░░░ 50%')
  m.keyringFails = true
  clock.now = T0 + 6 * 60_000
  const text = await textReport($)
  expect(text).toContain('Gemini █████░░░░░ 50%')
  expect(text).toContain('unreachable, retrying in 5m · reading from 6m ago')
})

test('the start-up refresh, made from a timer, reaches the band', async ($, on) => {
  const exp = Math.floor(T0 / 1000) + 3600
  const { sent } = engine(
    on,
    {
      timers: true,
      files: { [CODEX_AUTH]: JSON.stringify({ tokens: { access_token: jwt(exp), account_id: 'a' } }) },
      http: () => ({ status: 200, body: WHAM }),
    },
    { now: T0 },
  )
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const band = await $.ui.mount({ ...BAND, surface: 'terminal' })
  expect(sent.length).toBe(1)
  expect((await band.find({ type: 'Text', text: 'codex' }))?.text).toBe('codex')
  await band.unmount()
})

test('an expired Codex sign-in says how to fix it and requests nothing', async ($, on) => {
  const { sent } = engine(
    on,
    { files: { [CODEX_AUTH]: JSON.stringify({ tokens: { access_token: jwt(Math.floor(T0 / 1000) - 60), account_id: 'a' } }) } },
    { now: T0 },
  )
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const text = await textReport($)
  expect(text).toContain('Codex')
  expect(text).toContain('sign-in expired: run `codex login`')
  expect(sent.length).toBe(0)
})

test('a 429 keeps the last Codex reading and backs off', async ($, on) => {
  const exp = Math.floor(T0 / 1000) + 7200
  let limited = false
  const clock = { now: T0 }
  const { sent } = engine(
    on,
    {
      files: { [CODEX_AUTH]: JSON.stringify({ tokens: { access_token: jwt(exp), account_id: 'a' } }) },
      http: () => (limited ? { status: 429, body: {}, headers: { 'retry-after': '900' } } : { status: 200, body: WHAM }),
    },
    clock,
  )
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await textReport($)
  limited = true
  clock.now = T0 + 6 * 60_000
  const text = await textReport($)
  expect(text).toContain('42%')
  expect(text).toContain('rate limited, retrying in 15m · reading from 6m ago')
  // the pane's refresh does not override a Retry-After
  clock.now = T0 + 8 * 60_000
  await textReport($)
  expect(sent.length).toBe(2)
})

test('with the codex option off, auth.json is never read', { options: { codex: false } }, async ($, on) => {
  const { sent } = engine(on, { files: { [CODEX_AUTH]: '{}' }, http: () => ({ status: 200, body: WHAM }) }, { now: T0 })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const text = await textReport($)
  expect(text).not.toContain('Codex')
  expect(sent.length).toBe(0)
})

// ---------- Antigravity ----------

const INNER = { token: { access_token: 'AT123', expiry: '2026-10-24T00:00:00Z' } }

test('agy keyring token: Linux JSON, macOS id:base64url, top level; anything else is null', () => {
  expect(normalizeKeyringToken(JSON.stringify(INNER))).toEqual({ access_token: 'AT123', expiry: '2026-10-24T00:00:00Z' })
  expect(normalizeKeyringToken('someid1234567890:' + b64url(JSON.stringify(INNER)))?.access_token).toBe('AT123')
  expect(normalizeKeyringToken(JSON.stringify({ access_token: 'AT9', expiry: '' }))?.access_token).toBe('AT9')
  expect(normalizeKeyringToken('not a token with spaces')).toBeNull()
  expect(normalizeKeyringToken('eyJhbGciOiJub25lIn0.eyJleHAiOjF9.sig')).toBeNull()
  expect(normalizeKeyringToken('')).toBeNull()
})

const QUOTA = {
  groups: [
    { displayName: 'Gemini Models', buckets: [{ bucketId: 'gemini-weekly', window: 'weekly', resetTime: '2026-10-26T10:00:00Z', remainingFraction: 0.5 }] },
    { displayName: 'Claude and GPT models', buckets: [{ window: 'weekly', resetTime: '2026-10-26T10:00:00Z', remainingFraction: 0.75 }] },
  ],
}

test('agy quota: one weekly window per group, labels trimmed', () => {
  expect(antigravityWindows(QUOTA).map(w => [w.kind, w.label, w.percentUsed])).toEqual([
    ['agy:Gemini', 'Gemini', 50],
    ['agy:Claude and GPT', 'Claude and GPT', 25],
  ])
  // remainingFraction 0.55 → 45, not 44.99999999999999
  expect(antigravityWindows({ groups: [{ displayName: 'X', buckets: [{ remainingFraction: 0.55 }] }] })[0]?.percentUsed).toBe(45)
  expect(antigravityWindows({})).toEqual([])
})

const agyHttp = (quotaStatus: number) => (url: string): Http =>
  url.endsWith('loadCodeAssist')
    ? { status: 200, body: { cloudaicompanionProject: 'proj-123', currentTier: { id: 'free-tier' } } }
    : { status: quotaStatus, body: quotaStatus === 200 ? QUOTA : { error: 'boom' } }

test('signed in to agy: both groups in the report and the band', async ($, on) => {
  const { sent, ran } = engine(on, { keyring: JSON.stringify(INNER), http: agyHttp(200) }, { now: T0 })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const text = await textReport($)
  expect(ran[0]).toEqual(['secret-tool', 'lookup', 'service', 'gemini'])
  expect(text).toContain('Antigravity · free-tier')
  expect(text).toContain('Gemini █████░░░░░ 50%')
  expect(text).toContain('Claude and GPT ███░░░░░░░ 25%')
  expect(sent.map(s => s.url.split(':').pop())).toEqual(['loadCodeAssist', 'retrieveUserQuotaSummary'])
  expect(sent[0]?.headers['User-Agent']).toContain('antigravity/cli/')
  expect(sent[1]?.body).toBe(JSON.stringify({ project: 'proj-123' }))

  const band = await $.ui.mount({ ...BAND, surface: 'terminal' })
  expect((await band.find({ type: 'Text', text: 'agy' }))?.text).toBe('agy')
  expect((await band.find({ type: 'Text', text: 'Gemini' }))?.text).toBe('Gemini')
  await band.unmount()
})

test('when the agy quota call fails, it says so instead of showing 0%', async ($, on) => {
  engine(on, { keyring: JSON.stringify(INNER), http: agyHttp(500) }, { now: T0 })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const text = await textReport($)
  expect(text).toContain('Antigravity · free-tier')
  expect(text).toContain('reached, but its quota is unavailable right now')
  expect(text).not.toContain('Gemini')

  const band = await $.ui.mount({ ...BAND, surface: 'terminal' })
  expect(await band.find({ type: 'Text', text: 'agy' })).toBeUndefined()
  await band.unmount()
})
