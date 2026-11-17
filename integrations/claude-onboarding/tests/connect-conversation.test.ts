/**
 * Independent section-54 conformance (one consent to connect a conversation, P4)
 * on Claude Code 2.1.303. Written from the contract alone: public native effects
 * only, no product imports, authentication or inference. Host responses follow
 * sections 3 and 5 (review digests included); scoped HTTP follows sections 6-8.
 * The contract names labels and host calls, not how a checkbox is drawn, so the
 * Incoming messages/tasks settings are found by their names and read as on/off
 * from their shown text or Select value. A plugin reload is a fresh test module
 * over retained host state; actual reload and host restart remain separate checks.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-10-29T12:00:00Z')
const HOST = 'host_' + 'a'.repeat(64)
const ROOT = '/private project/Native $(literal)'
const BASENAME = 'Native $(literal)'
const NATIVE = 'private-native-adapter-conversation'
const TOKEN = 'token_' + 'b'.repeat(64)
const SOCKET = '/private host state/adapter.sock'
const RAW = 'PRIVATE_PROVIDER_ERROR token_DO_NOT_ECHO /private/provider-path'
const READY = 'mcp__peerspan__adapter_ready'
const SEEN = 'mcp__peerspan__message_seen'
const REPLY = 'mcp__peerspan__message_reply'
const ACCEPT = 'mcp__peerspan__task_accept'
const TASK_NEXT = '/adapter/v1/tasks/next'
const CANCEL_NEXT = '/adapter/v1/tasks/cancels/next'
const CONSENT = 'Connect this conversation'
const MINUTE = 60_000, HOUR = 3_600_000
const id = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(32, '0')
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))
const stamp = (milliseconds: number) => new Date(milliseconds).toISOString().replace('.000Z', 'Z')
const second = (milliseconds: number) => Math.floor(milliseconds / 1000) * 1000
const quote = (value: string) => JSON.stringify(value).replace(/[​‪-‮]/g,
  character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
const contextOf = (root = ROOT, native = NATIVE) => ({ project_root: root, native_session_id: native, integration: 'claude-code' })
const context = (parent: any) => ({ project_flow_id: parent.flow_id, project_review_id: parent.review_id,
  project_root: parent.review.project_root, native_session_id: parent.review.native_session_id, integration: 'claude-code' })
const projectEffects = (create: boolean) => ({ register_agent: create, attach_session: true, issue_adapter_credential: false,
  grant_network_access: false, share_files: false, share_conversation: false, capability_calls: false })
const adapterEffects = { issue_adapter_credential: true, receive_authorized_work: true, reply_to_authorized_work: true,
  handle_authorized_tasks: true, task_artifacts: true, register_agent: false, attach_session: false,
  grant_network_access: false, directory_access: false, outbound_routes: false, capability_calls: false,
  share_files: false, share_conversation: false }
const registryAgent = (n: number, name = 'Choice ' + n, owner = 'Owner ' + n, capabilities: string[] = []) => ({
  id: id('agent', n), name, owner, capabilities, created_at: stamp(NOW - 1000) })

function canonical(value: any): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value !== null && typeof value === 'object') return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
  return JSON.stringify(value)
}
async function digest(domain: string, review: any) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain + '\n' + canonical(review))))
  return 'review_' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}
const PROJECT_DOMAIN = 'peerspan-project-review-v1', ADAPTER_DOMAIN = 'peerspan-adapter-review-v1'
// A section 3 flow. `agent` is the registry record without created_at.
async function projectFlow(n: number, agent: any, create: boolean, now: number, options: any = {}) {
  const review = { version: 1, kind: 'attach_project', flow_id: id('flow', n), host_id: HOST, ...(options.context ?? contextOf()),
    create_agent: create, agent: { id: agent.id, name: agent.name, owner: agent.owner, capabilities: [...agent.capabilities] },
    session_id: id('session', n), expires_at: stamp(options.expires ?? second(now) + 15 * MINUTE), effects: projectEffects(create) }
  const state = options.state ?? 'review'
  return { version: 1, flow_id: review.flow_id, state, review_id: await digest(PROJECT_DOMAIN, review), review,
    attachment: state === 'attached' || options.attached ? { agent_id: agent.id, session_id: review.session_id } : null,
    next_action: state === 'review' ? 'review' : state === 'attached' ? 'continue_adapter_setup' : 'restart_review' }
}
function connection(child: any, now: number, options: any = {}) {
  const ready = options.ready ?? false
  const verified = options.verified ?? false
  return { adapter_id: child.review.adapter_id, session_id: child.review.session_id,
    state: ready ? 'ready' : 'registered', recoverable: ready,
    lease_expires_at: ready ? stamp(Math.min(now + 15_000, Date.parse(child.review.credential_expires_at))) : null,
    last_seen_at: ready ? stamp(now) : null, channel: ready ? verified ? 'verified' : 'unverified' : null,
    channel_verified_at: verified ? stamp(now) : null, protocol_version: ready ? 'claude-mod-v1' : null }
}
// A section 5 flow: review 15 minutes and credential 24 hours after preparation.
async function adapterFlow(parent: any, n: number, now: number, options: any = {}) {
  const prepared = second(now)
  const review = { version: 1, kind: 'authorize_adapter', flow_id: id('flow', n), host_id: parent.review.host_id,
    ...context(parent), agent: clone(parent.review.agent), session_id: parent.review.session_id, adapter_id: id('adapter', n),
    expires_at: stamp(prepared + 15 * MINUTE), credential_expires_at: stamp(prepared + 24 * HOUR),
    renewable: false, effects: clone(adapterEffects) }
  const state = options.state ?? 'review'
  const flow: any = { version: 1, flow_id: review.flow_id, state, review_id: await digest(ADAPTER_DOMAIN, review), review,
    authorization: null, connection: null,
    next_action: state === 'review' ? 'review' : state === 'authorized' ? 'connect_adapter' : 'restart_review' }
  if (state === 'authorized' || options.issued) {
    flow.authorization = { adapter_id: review.adapter_id, session_id: review.session_id, agent_id: review.agent.id,
      expires_at: review.credential_expires_at, renewable: false }
    flow.connection = connection(flow, now)
  }
  return flow
}
async function transport(child: any) {
  // Standard HMAC-SHA256 over the section 6 instance message, keyed by the
  // fixture token's 32 bytes (0xbb), built from digest as the runtime lacks HMAC.
  const innerPad = new Uint8Array(64).fill(0x36), outerPad = new Uint8Array(64).fill(0x5c)
  for (let index = 0; index < 32; index++) { innerPad[index] ^= 0xbb; outerPad[index] ^= 0xbb }
  const message = 'peerspan-guided-adapter-instance-v1\n' + child.flow_id + '\n' + child.review_id
  const bytes = new TextEncoder().encode(message), inner = new Uint8Array(64 + bytes.length)
  inner.set(innerPad); inner.set(bytes, 64)
  const innerHash = new Uint8Array(await crypto.subtle.digest('SHA-256', inner))
  const outer = new Uint8Array(64 + innerHash.length); outer.set(outerPad); outer.set(innerHash, 64)
  const signature = new Uint8Array(await crypto.subtle.digest('SHA-256', outer))
  return { version: 1, adapter_id: child.review.adapter_id, session_id: child.review.session_id, token: TOKEN,
    instance_id: 'instance_' + Array.from(signature, byte => byte.toString(16).padStart(2, '0')).join(''), adapter_socket: SOCKET }
}

function fixture(on: On) {
  const clock = mock.clock(on, { now: NOW })
  const w = { clock, started: false, root: ROOT, native: NATIVE, surface: 'terminal' as string | null,
    agents: [] as any[], parent: null as any, adapters: {} as Record<string, any>, sequence: 20,
    // A live credential of the same agent elsewhere: section 5 refuses a new authorization.
    refuseAdapter: false,
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], pending: 0,
    tasks: [] as any[], messages: [] as any[],
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    register: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  const child = () => w.parent ? w.adapters[w.parent.flow_id] ?? null : null
  w.run = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: stamp(clock.now()), host_id: HOST, networks: [],
      agents: w.agents.map(a => ({ id: a.id, name: a.name, sessions: [] })), requests: [], attention: [] }
    if (kind === 'project.lookup') return { version: 1, host_id: HOST, context: payload, flow: w.parent, agents: w.agents }
    if (kind === 'project.prepare') {
      const existing = payload.agent.kind === 'existing'
      let agent = existing ? w.agents.find(a => a.id === payload.agent.id) : null
      if (!existing) {
        agent = registryAgent(++w.sequence, payload.agent.name.trim(), payload.agent.owner.trim())
        w.agents = [...w.agents, agent]
      }
      w.parent = await projectFlow(++w.sequence, agent, !existing, clock.now(), { context: {
        project_root: payload.project_root, native_session_id: payload.native_session_id, integration: payload.integration } })
      return w.parent
    }
    if (kind === 'project.inspect') return w.parent
    if (kind === 'project.decide') {
      const approve = payload.decision === 'approve'
      w.parent = { ...w.parent, state: approve ? 'attached' : 'declined',
        attachment: approve ? { agent_id: w.parent.review.agent.id, session_id: w.parent.review.session_id } : null,
        next_action: approve ? 'continue_adapter_setup' : 'restart_review' }
      return w.parent
    }
    if (kind === 'adapter.lookup') return { version: 1, host_id: HOST, context: payload, flow: w.adapters[payload.project_flow_id] ?? null }
    if (kind === 'adapter.prepare') {
      if (w.refuseAdapter) return { fixtureExit: 1 }
      const flow = await adapterFlow(w.parent, ++w.sequence, clock.now())
      w.adapters[w.parent.flow_id] = flow; return flow
    }
    if (kind === 'adapter.inspect') return Object.values(w.adapters).find((flow: any) => flow.flow_id === payload) ?? child()
    if (kind === 'adapter.decide') {
      const current = child(), approve = payload.decision === 'approve'
      const next: any = { ...current, state: approve ? 'authorized' : 'declined',
        next_action: approve ? 'connect_adapter' : 'restart_review',
        authorization: approve ? { adapter_id: current.review.adapter_id, session_id: current.review.session_id,
          agent_id: current.review.agent.id, expires_at: current.review.credential_expires_at, renewable: false } : null }
      next.connection = approve ? connection(next, clock.now()) : null
      w.adapters[w.parent.flow_id] = next; return next
    }
    if (kind === 'adapter.transport') { const value = await transport(child()); w.materials.push(clone(value)); return value }
    throw Error('Unexpected public process operation')
  }
  w.fetch = async e => {
    const path = e.url.replace('http://peerspan', '')
    let value: any = null
    if (path === '/adapter/v1/connect' || path === '/adapter/v1/ready') {
      const current = child()
      value = connection(current, clock.now(), { ready: true,
        verified: path.endsWith('/ready') || current.connection?.channel === 'verified' })
      w.adapters[w.parent.flow_id] = { ...current, connection: value }
    } else if (path === '/adapter/v1/next') value = w.messages.shift() ?? null
    else if (path === TASK_NEXT) value = w.tasks.shift() ?? null
    else if (path === CANCEL_NEXT) value = null
    else throw Error('Unexpected scoped route')
    return { status: 200, ok: true, headers: {}, text: JSON.stringify(value) }
  }
  on('session.start', ($, e) => { w.started = true; return { cwd: e.cwd } })
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('classic.CwdChanged', () => ({}))
  on('session.root', () => { w.trace.push({ kind: 'root' }); return { value: w.root } })
  on('session.id', () => { w.trace.push({ kind: 'native' }); return { value: w.native } })
  on('session.cwd', () => ({ value: '/different-shell-cwd' }))
  on('session.surface', () => ({ value: w.surface }))
  on('session.surfaces', () => ({ value: w.surface ? [w.surface] : [] }))
  on('command.register', () => ({ value: undefined }))
  on('tool.register', async ($, e) => {
    w.tools.push(e); w.trace.push({ kind: 'tool', name: e.name })
    return (await w.register(e))?.fixtureDeny ? { deny: RAW } : { value: undefined }
  })
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unregistered fixture tool' }))
  on('process.run', async ($, e) => {
    const tail = e.argv.slice(e.argv.indexOf('onboarding') + 1)
    const kind = tail.length ? tail[0] + '.' + tail[1] : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : kind.endsWith('.inspect') ? e.argv.at(-1) : undefined
    w.calls.push({ ...e, kind, payload }); w.trace.push({ kind, payload }); w.pending++
    try {
      const value = await w.run(kind, payload, e)
      if (value?.fixtureDeny) return { deny: RAW }
      if (value?.fixtureExit) return { value: { exitCode: value.fixtureExit, stdout: '', stderr: 'Error: flow_conflict ' + RAW } }
      if (value?.fixtureRaw) return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
      return { value: { exitCode: 0, stdout: JSON.stringify(value), stderr: '' } }
    } finally { w.pending-- }
  })
  on('http.fetch', async ($, e) => {
    w.httpCalls.push(clone(e)); w.trace.push({ kind: 'http', path: e.url.replace('http://peerspan', '') }); w.pending++
    try { const value = await w.fetch(e); return value?.fixtureDeny ? { deny: RAW } : { value } }
    finally { w.pending-- }
  })
  on('ui.open', () => ({ value: { isPlaced: w.surface === 'terminal' } }))
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  on('ui.toast', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.log', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.status', ($, e) => { w.outside.push(String(e.text ?? '')); return { value: undefined } })
  on('prompt.submit', async ($, e) => { w.prompts.push(clone(e)); w.trace.push({ kind: 'prompt' }); return w.submit(e) })
  on('store.set', () => { w.forbidden.push('store.set'); return { deny: 'no persistence' } })
  on('fs.write', () => { w.forbidden.push('fs.write'); return { deny: 'no files' } })
  on('process.spawn', async function* () { w.forbidden.push('process.spawn'); throw Error('no spawn') })
  on('model.complete', () => { w.forbidden.push('model.complete'); return { deny: 'no inference' } })
  on('session.send', () => { w.forbidden.push('session.send'); return { isDelivered: false } })
  return w
}
type World = ReturnType<typeof fixture>
type Pane = Mounted<'terminal', 'Pane'>

const count = (w: World, kind: string) => w.calls.filter(call => call.kind === kind).length
const last = (w: World, kind: string) => w.calls.filter(call => call.kind === kind).at(-1)
const pathOf = (e: any) => e.url.replace('http://peerspan', '')
const requests = (w: World, path: string) => w.httpCalls.filter(e => pathOf(e) === path)
const connects = (w: World) => requests(w, '/adapter/v1/connect')
const readyCalls = (w: World) => requests(w, '/adapter/v1/ready')
const messageClaims = (w: World) => requests(w, '/adapter/v1/next')
const taskClaims = (w: World) => requests(w, TASK_NEXT).length + requests(w, CANCEL_NEXT).length
const taskTools = (w: World) => w.tools.filter(tool => tool.name.startsWith('task_'))
const MUTATIONS = ['project.prepare', 'project.decide', 'adapter.prepare', 'adapter.decide', 'adapter.transport']
const mutations = (w: World) => w.calls.filter(call => MUTATIONS.includes(call.kind))
const realTurn = () => new Promise<void>(resolve => setTimeout(resolve, 2))

async function text(ui: Pane) { return (await ui.findAll({})).map(element => element.text).join('\n') }
async function visible(ui: Pane) {
  return (await text(ui)) + '\n' + (await ui.findAll({ type: 'Input' })).map(input => String(input.props.value ?? '')).join('\n')
}
async function button(ui: Pane, label: string | RegExp) {
  return ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
}
async function press(ui: Pane, label: string | RegExp) {
  const found = await button(ui, label); expect(found, String(label)).toBeDefined()
  return ui.press({ key: found!.key! })
}
// Waits until no host operation is in flight and the calls and drawing stay
// unchanged for a short real-time period, without advancing the native clock.
async function finished(w: World, ui: Pane) {
  const end = performance.now() + 20_000
  let before = '', since = performance.now(), turns = 0
  while (performance.now() < end) {
    await w.clock.settle(); await realTurn()
    const now = w.trace.length + '\n' + (await text(ui))
    if (now !== before || w.pending > 0) { before = now; since = performance.now(); turns = 0; continue }
    if (++turns >= 15 && performance.now() - since >= 120) return
  }
}
async function advance(w: World, ui: Pane, ms: number) {
  for (let left = ms; left > 0; left -= 5000) { await w.clock.advance(Math.min(5000, left)); await finished(w, ui) }
}
async function mount($: Engine, w: World): Promise<Pane> {
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  return $.ui.mount({ plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 80,
      placement: 'inline', scroll: { offset: 0, bodyRows: 30 }, view: {} } })
}
// The entry: one explicit Connect this conversation from the initial pane.
async function review($: Engine, w: World) {
  const ui = await mount($, w)
  await press(ui, CONSENT); await finished(w, ui)
  return ui
}
// The press on the review screen. It carries the entry's label; if both were
// drawn, the review's own control is the later one.
async function consent(w: World, ui: Pane) {
  const found = await ui.findAll({ type: 'Button', text: new RegExp('^' + CONSENT + '$') })
  expect(found.length, 'Connect this conversation press').toBeGreaterThan(0)
  await ui.press({ key: found.at(-1)!.key! }); await finished(w, ui)
}
function nonce(w: World, at = 0) {
  const match = w.prompts[at]?.text.match(/\b[0-9a-f]{32}\b/g)
  expect(match?.length, 'one public readiness nonce').toBe(1)
  return match![0]
}
function resultOf(answer: any): any {
  expect(typeof answer?.result, 'successful native tool result').toBe('string')
  return JSON.parse(answer.result)
}
function denied(answer: any) {
  expect(typeof answer?.deny === 'string' || answer?.isError === true, 'controlled native refusal').toBe(true)
  expect(JSON.stringify(answer)).not.toContain(RAW)
}
// The model's turn after the hello: the exact acknowledgment of section 7.
async function acknowledge($: Engine, w: World, ui: Pane, at = 0) {
  expect(resultOf(await $.tool.call({ tool: READY, nonce: nonce(w, at) }))).toEqual({ ready: true })
  await finished(w, ui)
}

// The two settings. A Select labelled with the setting, or a Button (or other
// element) whose shown text carries the setting's name; Enable/Stop/Retry
// controls of sections 7 and 8 are not the setting.
const OFF = /\[ \]|☐|□|⬜|\b(?:off|no|unchecked|not checked|disabled|unavailable|false)\b/i
const ON = /\[[xX✓✔]\]|☑|✅|✓|✔|■|\b(?:on|yes|checked|enabled|true)\b/i
async function setting(ui: Pane, name: string) {
  const select = (await ui.findAll({ type: 'Select' })).find(e => String(e.props.label ?? '').includes(name))
  if (select) return select
  return (await ui.findAll({ type: 'Button' })).find(e => e.text.includes(name) && !/^(?:Enable|Stop|Retry)\b/.test(e.text))
}
async function isOn(ui: Pane, name: string) {
  const found = await setting(ui, name)
  if (!found) return false
  if (found.type === 'Select') {
    const options = (found.props.options as any[]) ?? [], value = found.props.value
    const chosen = options.find(option => option.value === value)
    const shown = String(chosen?.label ?? value ?? '')
    return !OFF.test(shown) && ON.test(shown)
  }
  const shown = found.text.replace(name, '')
  return !OFF.test(shown) && ON.test(shown)
}
async function choose(w: World, ui: Pane, name: string, on: boolean) {
  for (let attempt = 0; attempt < 3 && (await isOn(ui, name)) !== on; attempt++) {
    const found = await setting(ui, name); expect(found, name + ' setting').toBeDefined()
    if (found!.type === 'Select') {
      const options = (found!.props.options as any[]) ?? []
      const target = options.find(option => { const shown = String(option.label ?? option.value); return on ? !OFF.test(shown) && ON.test(shown) : OFF.test(shown) })
      expect(target, name + ' option').toBeDefined()
      await ui.select({ key: found!.key!, value: target.value })
    } else await ui.press({ key: found!.key! })
    await finished(w, ui)
  }
  expect(await isOn(ui, name), name + (on ? ' checked' : ' unchecked')).toBe(on)
}
async function input(ui: Pane, pattern: RegExp) {
  return (await ui.findAll({ type: 'Input' })).find(e => pattern.test(String(e.props.label ?? '')))
}
// The explicit existing-agent choice is a control carrying that agent's quoted
// name. The contract does not say whether choosing and the press are one control:
// a choice labelled as a connection ("Connect ...") is taken as the press itself;
// otherwise the choice is followed by the Connect this conversation press.
async function connectWith(w: World, ui: Pane, agent: any) {
  const found = (await ui.findAll({ type: 'Button' })).find(e => e.text.includes(quote(agent.name)) && e.text !== CONSENT)
  expect(found, 'explicit existing-agent choice').toBeDefined()
  await ui.press({ key: found!.key! }); await finished(w, ui)
  if (!/^Connect\b/.test(found!.text)) {
    expect(mutations(w), 'choosing an agent prepares nothing').toEqual([])
    await consent(w, ui)
  }
}
function privacy(w: World, shown = '') {
  expect(w.forbidden).toEqual([])
  const values = [TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', NATIVE, ...w.materials.map(value => value.instance_id)]
  for (const value of values) {
    expect(shown).not.toContain(value); expect(w.outside.join('\n')).not.toContain(value)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(value)
  }
  expect(w.outside.join('\n')).not.toContain(ROOT)
  for (const call of w.calls) {
    expect(call.init?.timeoutMs).toBe(5000)
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET]) expect(call.argv).not.toContain(value)
  }
  for (const e of w.httpCalls) {
    expect(e.init.socketPath).toBe(SOCKET); expect(e.init.method).toBe('POST')
    const headers = Object.fromEntries(Object.entries(e.init.headers).map(([key, value]) => [key.toLowerCase(), value]))
    expect(headers.authorization).toBe('Bearer ' + TOKEN)
  }
}
// The first index in the trace of each step's effect, for ordering.
function firstIndex(w: World, match: (e: any) => boolean) { return w.trace.findIndex(match) }
const isKind = (kind: string) => (e: any) => e.kind === kind
const isPath = (path: string) => (e: any) => e.kind === 'http' && e.path === path

// A new agent, the default settings, and the whole press up to the model turn.
async function connectNew($: Engine, w: World) {
  const ui = await review($, w)
  await consent(w, ui)
  return ui
}

test('entry Refresh and reopening only look up and show one review with every listed term and both disclosures', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  for (const args of ['connect', '--approve', 'connect this conversation']) await $.command.run({ command: 'peerspan', args })
  expect(mutations(w)).toEqual([]); expect(w.httpCalls).toEqual([])
  const ui = await review($, w)
  expect(await button(ui, CONSENT), 'the review offers its Connect this conversation press').toBeDefined()
  expect(count(w, 'project.lookup')).toBe(1); expect(last(w, 'project.lookup').payload).toEqual(contextOf())
  const shown = await visible(ui)
  expect(shown).toContain(ROOT)
  expect(shown).toMatch(/current conversation/i)
  // A new agent with an editable name (default the root's basename) and owner label.
  const name = await input(ui, /name/i), owner = await input(ui, /owner/i)
  expect(name, 'editable new agent name').toBeDefined(); expect(owner, 'editable owner label').toBeDefined()
  expect(name!.props.value).toBe(BASENAME)
  // Section 3's attachment effects, its review lifetime and section 5's adapter effects.
  expect(shown).toMatch(/attach/i); expect(shown).toMatch(/register|new agent/i)
  expect(shown).toMatch(/15 minutes/i)
  expect(shown).toMatch(/credential/i); expect(shown).toMatch(/24 hours/i)
  expect(shown).toMatch(/not renewable|nonrenewable|non-renewable/i)
  expect(shown).toMatch(/memory/i)
  // Both settings, checked by default, beside sections 7 and 8's words.
  expect(await setting(ui, 'Incoming messages'), 'Incoming messages setting').toBeDefined()
  expect(await setting(ui, 'Incoming tasks'), 'Incoming tasks setting').toBeDefined()
  expect(await isOn(ui, 'Incoming messages')).toBe(true); expect(await isOn(ui, 'Incoming tasks')).toBe(true)
  expect(shown).toMatch(/one model turn now|model turn now/i); expect(shown).toMatch(/verif/i)
  expect(shown).toMatch(/each message can start a model turn/i); expect(shown).toMatch(/allowance/i)
  expect(shown).toMatch(/each task can start a model turn/i)
  expect(shown).toMatch(/no local tool or file permission|no (?:new )?local (?:tool|file)[^\n]{0,30}permission/i)
  // Editing the draft, Refresh and reopening prepare nothing.
  await ui.input({ key: name!.key!, text: 'Edited agent', kind: 'change' })
  await press(ui, 'Refresh'); await finished(w, ui); await advance(w, ui, 20_000)
  await press(ui, 'Close'); await ui.unmount()
  const again = await review($, w); await advance(w, again, 20_000)
  expect(mutations(w)).toEqual([]); expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  for (const call of w.calls) expect(['snapshot', 'project.lookup', 'project.inspect', 'adapter.lookup', 'adapter.inspect']).toContain(call.kind)
  privacy(w, await visible(again))
})

test('Incoming tasks is unavailable while Incoming messages is unchecked', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const ui = await review($, w)
  await choose(w, ui, 'Incoming messages', false)
  expect(await isOn(ui, 'Incoming tasks'), 'tasks cannot stay chosen without messages').toBe(false)
  const tasks = await setting(ui, 'Incoming tasks')
  if (tasks?.type === 'Button') { await ui.press({ key: tasks.key! }); await finished(w, ui) }
  if (tasks?.type === 'Select') {
    for (const option of (tasks.props.options as any[]) ?? []) {
      await ui.select({ key: tasks.key!, value: option.value }).catch(() => undefined); await finished(w, ui)
    }
  }
  expect(await isOn(ui, 'Incoming tasks'), 'tasks cannot be chosen without messages').toBe(false)
  await choose(w, ui, 'Incoming messages', true)
  expect(mutations(w)).toEqual([]); expect(w.httpCalls).toEqual([])
  privacy(w, await visible(ui))
})

test('one press runs attachment prepare approve adapter prepare approve Connect message enable with its handshake then task enable in order', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const ui = await review($, w)
  const owner = String((await input(ui, /owner/i))!.props.value ?? '')
  await consent(w, ui)
  // The press itself stops at the model turn: no task enable before ready.
  expect(w.prompts.length).toBe(1); expect(readyCalls(w)).toEqual([])
  expect(taskTools(w)).toEqual([]); expect(taskClaims(w)).toBe(0)
  await acknowledge($, w, ui)
  const parent = w.parent, child = w.adapters[parent.flow_id]
  expect(count(w, 'project.prepare')).toBe(1); expect(count(w, 'project.decide')).toBe(1)
  expect(count(w, 'adapter.prepare')).toBe(1); expect(count(w, 'adapter.decide')).toBe(1)
  expect(count(w, 'adapter.transport')).toBe(1); expect(readyCalls(w).length).toBe(1)
  expect(last(w, 'project.prepare').payload).toEqual({ ...contextOf(), agent: { kind: 'new', name: BASENAME, owner } })
  expect(last(w, 'project.decide').payload).toEqual({ flow_id: parent.flow_id, review_id: parent.review_id, ...contextOf(), decision: 'approve' })
  expect(last(w, 'adapter.prepare').payload).toEqual({ context: context(parent) })
  expect(last(w, 'adapter.decide').payload).toEqual({ flow_id: child.flow_id, context: context(parent), review_id: child.review_id, decision: 'approve' })
  expect(last(w, 'adapter.transport').payload).toEqual({ flow_id: child.flow_id, context: context(parent), review_id: child.review_id })
  expect(JSON.parse(connects(w)[0].init.body)).toEqual({ adapter_id: child.review.adapter_id, session_id: child.review.session_id,
    instance_id: w.materials[0].instance_id, protocol_version: 'claude-mod-v1' })
  expect(w.prompts[0].text).toContain(READY)
  expect(JSON.parse(readyCalls(w)[0].init.body)).toEqual({ nonce: nonce(w) })
  expect(taskTools(w).length).toBe(5); expect(taskClaims(w)).toBeGreaterThan(0)
  const order = [firstIndex(w, isKind('project.prepare')), firstIndex(w, isKind('project.decide')),
    firstIndex(w, isKind('adapter.prepare')), firstIndex(w, isKind('adapter.decide')),
    firstIndex(w, isKind('adapter.transport')), firstIndex(w, isPath('/adapter/v1/connect')),
    firstIndex(w, isKind('prompt')), firstIndex(w, isPath('/adapter/v1/ready')),
    firstIndex(w, e => e.kind === 'tool' && e.name.startsWith('task_')),
    firstIndex(w, e => e.kind === 'http' && (e.path === TASK_NEXT || e.path === CANCEL_NEXT))]
  expect(order.every(index => index >= 0), 'every step ran').toBe(true)
  expect([...order].sort((a, b) => a - b)).toEqual(order)
  const shown = await text(ui)
  expect(shown).toContain('Adapter: connected'); expect(shown).toContain('Incoming delivery: verified (messages)')
  expect(shown).toContain('Incoming tasks: enabled')
  // Nothing repeats by itself.
  await advance(w, ui, 30_000)
  for (const kind of MUTATIONS) expect(count(w, kind), kind).toBe(1)
  expect(w.prompts.length).toBe(1); expect(readyCalls(w).length).toBe(1)
  privacy(w, await visible(ui))
})

test('a difference in each checked attachment term stops before approval and offers the attachment control', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on), normal = w.run
  const variants: [string, (flow: any) => void][] = [
    ['root', f => { f.review.project_root = '/other/project' }],
    ['conversation', f => { f.review.native_session_id = 'other-native-conversation' }],
    ['new or existing', f => { f.review.create_agent = false; f.review.effects.register_agent = false }],
    ['name', f => { f.review.agent.name = 'Different agent' }],
    ['owner', f => { f.review.agent.owner = 'Different owner' }],
    ['capabilities', f => { f.review.agent.capabilities = ['unreviewed metadata'] }],
    ['effects', f => { f.review.effects.share_files = true }],
    ['expiry beyond 15 minutes', f => { f.review.expires_at = stamp(second(w.clock.now()) + 16 * MINUTE) }],
    ['expiry an hour away', f => { f.review.expires_at = stamp(second(w.clock.now()) + 60 * MINUTE) }],
    ['expiry before the press', f => { f.review.expires_at = stamp(second(w.clock.now()) - 1000) }],
  ]
  const unoffered: string[] = [], proceeded: string[] = []
  for (const [label, change] of variants) {
    w.parent = null; w.adapters = {}; w.httpCalls = []; w.prompts = []
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind !== 'project.prepare') return value
      const changed = clone(value); change(changed); changed.review_id = await digest(PROJECT_DOMAIN, changed.review)
      w.parent = changed; return changed
    }
    const ui = await review($, w), before = w.calls.length
    await consent(w, ui); await advance(w, ui, 10_000)
    const after = w.calls.slice(before).map(call => call.kind)
    expect(after.filter(kind => kind === 'project.prepare'), label).toHaveLength(1)
    if (after.includes('project.decide')) proceeded.push(label)
    else {
      for (const kind of ['adapter.prepare', 'adapter.decide', 'adapter.transport']) expect(after, label).not.toContain(kind)
      expect(w.httpCalls, label).toEqual([]); expect(w.prompts, label).toEqual([])
    }
    if (!(await ui.findAll({ type: 'Button' })).some(e => /^(?:Approve attachment|Review a replacement|Review new agent|Review agent .+)$/.test(e.text))) unoffered.push(label)
    privacy(w, await visible(ui))
    await press(ui, 'Close'); await ui.unmount()
  }
  expect(proceeded, 'differences that were approved anyway').toEqual([])
  expect(unoffered, 'differences without the attachment step control').toEqual([])
})

test('an attachment approval that records a different agent or session stops before the adapter step', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const field of ['agent_id', 'session_id']) {
    w.parent = null
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'project.decide') value.attachment[field] = id(field.split('_')[0], 999)
      return value
    }
    const ui = await review($, w), before = w.calls.length
    await consent(w, ui); await advance(w, ui, 10_000)
    const after = w.calls.slice(before).map(call => call.kind)
    expect(after.filter(kind => kind === 'project.decide'), field).toHaveLength(1)
    for (const kind of ['adapter.prepare', 'adapter.decide', 'adapter.transport']) expect(after, field).not.toContain(kind)
    expect(w.httpCalls).toEqual([])
    await press(ui, 'Close'); await ui.unmount()
  }
  privacy(w)
})

test('a difference in each checked adapter term stops before approval and offers the adapter step control', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on), normal = w.run
  const variants: [string, (flow: any) => void][] = [
    ['agent', f => { f.review.agent.name = 'Different agent' }],
    ['session', f => { f.review.session_id = id('session', 999) }],
    ['context', f => { f.review.project_review_id = 'review_' + 'f'.repeat(64) }],
    ['effects', f => { f.review.effects.directory_access = true }],
    ['renewable', f => { f.review.renewable = true }],
    ['credential end', f => { f.review.credential_expires_at = stamp(Date.parse(f.review.credential_expires_at) + HOUR) }],
    ['credential before the press', f => { f.review.credential_expires_at = stamp(second(w.clock.now()) - 1000) }],
  ]
  const unoffered: string[] = []
  for (const [label, change] of variants) {
    w.parent = null; w.adapters = {}
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind !== 'adapter.prepare') return value
      const changed = clone(value); change(changed); changed.review_id = await digest(ADAPTER_DOMAIN, changed.review)
      w.adapters[w.parent.flow_id] = changed; return changed
    }
    const ui = await review($, w), before = w.calls.length
    await consent(w, ui); await advance(w, ui, 10_000)
    const after = w.calls.slice(before).map(call => call.kind)
    for (const kind of ['project.prepare', 'project.decide', 'adapter.prepare']) expect(after.filter(k => k === kind), label + ' ' + kind).toHaveLength(1)
    for (const kind of ['adapter.decide', 'adapter.transport']) expect(after, label).not.toContain(kind)
    expect(w.httpCalls, label).toEqual([]); expect(w.prompts, label).toEqual([])
    if (!(await ui.findAll({ type: 'Button' })).some(e => /^(?:Review adapter connection|Approve adapter|Review adapter permissions|Review a replacement adapter)$/.test(e.text))) unoffered.push(label)
    privacy(w, await visible(ui))
    await press(ui, 'Close'); await ui.unmount()
  }
  expect(unoffered, 'differences without the adapter step control').toEqual([])
})

test('an adapter approval that is not an exact authorization stops before Connect', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on), normal = w.run
  w.run = async (kind, payload, e) => {
    const value = clone(await normal(kind, payload, e))
    if (kind === 'adapter.decide') value.authorization.adapter_id = id('adapter', 999)
    return value
  }
  const ui = await connectNew($, w); await advance(w, ui, 10_000)
  expect(count(w, 'adapter.decide')).toBe(1); expect(count(w, 'adapter.transport')).toBe(0)
  expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
  expect(await text(ui)).not.toContain('Adapter: connected')
  privacy(w, await visible(ui))
})

const STEPS = ['project.prepare', 'project.decide', 'adapter.prepare', 'adapter.decide', 'adapter.transport', 'connect', 'hello', 'ready', 'tasks'] as const
for (const step of STEPS) {
  test(`an unknown ${step.replace('.', ' ')} outcome stops at that step and nothing repeats`, { timeoutMs: 30000 }, async ($, on) => {
    const w = fixture(on), normalRun = w.run, normalFetch = w.fetch
    if (STEPS.indexOf(step) <= 4) w.run = async (kind, payload, e) => {
      if (kind !== step) return normalRun(kind, payload, e)
      await normalRun(kind, payload, e); return { fixtureDeny: true }
    }
    if (step === 'connect') w.fetch = async e => pathOf(e) === '/adapter/v1/connect' ? { fixtureDeny: true } : normalFetch(e)
    if (step === 'ready') w.fetch = async e => pathOf(e) === '/adapter/v1/ready' ? { fixtureDeny: true } : normalFetch(e)
    if (step === 'hello') w.submit = async () => ({ drop: RAW })
    if (step === 'tasks') w.register = async e => e.name.startsWith('task_') ? { fixtureDeny: true } : undefined
    const ui = await connectNew($, w)
    if (step === 'ready') denied(await $.tool.call({ tool: READY, nonce: nonce(w) }))
    if (step === 'tasks') await acknowledge($, w, ui)
    await finished(w, ui)
    const snapshot = { calls: MUTATIONS.map(kind => count(w, kind)), prompts: w.prompts.length, ready: readyCalls(w).length,
      connects: connects(w).length, taskTools: taskTools(w).length }
    const index = STEPS.indexOf(step)
    // Earlier steps ran once; later steps did not run.
    for (const [position, kind] of MUTATIONS.entries()) expect(count(w, kind), kind).toBe(position <= Math.min(index, 4) ? 1 : 0)
    if (index <= 4) expect(w.httpCalls, step).toEqual([])
    if (index <= 5) { expect(w.prompts, step).toEqual([]); expect(await text(ui)).not.toContain('Adapter: connected') }
    if (index <= 7) { expect(taskClaims(w), step).toBe(0); expect(await text(ui)).not.toContain('Incoming tasks: enabled') }
    if (step === 'hello' || step === 'ready') expect(await text(ui)).not.toContain('Incoming delivery: verified (messages)')
    if (step === 'tasks') expect(taskClaims(w)).toBe(0)
    // No step repeats by itself; a connected lease still renews.
    await advance(w, ui, 70_000)
    expect(MUTATIONS.map(kind => count(w, kind))).toEqual(snapshot.calls)
    expect(w.prompts.length).toBe(snapshot.prompts); expect(readyCalls(w).length).toBe(snapshot.ready)
    if (index <= 5) expect(connects(w).length).toBe(snapshot.connects)
    expect(taskTools(w).length).toBe(snapshot.taskTools)
    if (index <= 7) expect(taskClaims(w)).toBe(0)
    // That step's existing control is offered where the contract names one.
    if (step === 'connect') expect(await button(ui, 'Connect adapter'), 'Connect adapter').toBeDefined()
    if (step === 'hello' || step === 'ready') expect(await button(ui, 'Retry incoming messages'), 'Retry incoming messages').toBeDefined()
    if (step === 'tasks') expect(await button(ui, /^(?:Retry|Enable) incoming tasks$/), 'task step control').toBeDefined()
    privacy(w, await visible(ui))
  })
}

test('an existing agent with a live adapter elsewhere stops at the adapter step with the refusal', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const chosen = registryAgent(5, 'Existing "agent"', 'Existing owner', ['metadata one']), other = registryAgent(6, 'Other agent')
  w.agents = [other, chosen]; w.refuseAdapter = true
  const ui = await review($, w)
  // Before any press the screen shows the explicit choice and the existing-agent resumption wording.
  const shown = await visible(ui)
  expect(shown).toContain(quote(chosen.name)); expect(shown).toContain(quote(chosen.owner))
  // Checked at the end, so a missing disclosure does not hide the adapter-step stop.
  const disclosed = /resume/i.test(shown) && /at once|immediately/i.test(shown)
  expect(mutations(w)).toEqual([])
  await connectWith(w, ui, chosen); await advance(w, ui, 30_000)
  expect(last(w, 'project.prepare').payload).toEqual({ ...contextOf(), agent: { kind: 'existing', id: chosen.id } })
  expect(count(w, 'project.prepare')).toBe(1); expect(count(w, 'project.decide')).toBe(1)
  expect(count(w, 'adapter.prepare')).toBe(1); expect(count(w, 'adapter.decide')).toBe(0); expect(count(w, 'adapter.transport')).toBe(0)
  expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
  expect(await text(ui)).not.toContain('Adapter: connected')
  privacy(w, await visible(ui))
  expect(disclosed, 'existing-agent resumption wording shown before the press').toBe(true)
})

test('messages only enables messages and no tasks', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const ui = await review($, w)
  await choose(w, ui, 'Incoming tasks', false); expect(await isOn(ui, 'Incoming messages')).toBe(true)
  await consent(w, ui); await acknowledge($, w, ui); await advance(w, ui, 10_000)
  expect(readyCalls(w).length).toBe(1); expect(messageClaims(w).length).toBeGreaterThan(0)
  expect(taskTools(w)).toEqual([]); expect(taskClaims(w)).toBe(0)
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  expect(await text(ui)).not.toContain('Incoming tasks: enabled')
  denied(await $.tool.call({ tool: ACCEPT, task_id: id('task', 1) }))
  privacy(w, await visible(ui))
})

test('both settings off record the attachment and authorization without connecting', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const ui = await review($, w)
  await choose(w, ui, 'Incoming messages', false); expect(await isOn(ui, 'Incoming tasks')).toBe(false)
  await consent(w, ui); await advance(w, ui, 30_000)
  expect(count(w, 'project.prepare')).toBe(1); expect(count(w, 'project.decide')).toBe(1)
  expect(count(w, 'adapter.prepare')).toBe(1); expect(count(w, 'adapter.decide')).toBe(1)
  expect(w.parent.state).toBe('attached'); expect(w.adapters[w.parent.flow_id].state).toBe('authorized')
  expect(count(w, 'adapter.transport')).toBe(0); expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  expect(await text(ui)).not.toContain('Adapter: connected')
  privacy(w, await visible(ui))
})

test('Stop incoming messages stops messages and tasks keeps the adapter connected and message tools then refuse', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const ui = await connectNew($, w); await acknowledge($, w, ui); await advance(w, ui, 5000)
  expect(await text(ui)).toContain('Incoming tasks: enabled')
  await press(ui, 'Stop incoming messages'); await finished(w, ui)
  const messages = messageClaims(w).length, tasks = taskClaims(w), leases = connects(w).length
  w.messages = [{ unexpected: 'not claimed after Stop' }]
  await advance(w, ui, 30_000)
  expect(messageClaims(w).length).toBe(messages); expect(taskClaims(w)).toBe(tasks)
  expect(connects(w).length, 'the adapter lease keeps renewing').toBeGreaterThan(leases)
  const shown = await text(ui)
  expect(shown).toContain('Adapter: connected')
  expect(shown).not.toContain('Incoming delivery: verified (messages)'); expect(shown).not.toContain('Incoming tasks: enabled')
  expect(await button(ui, 'Enable incoming messages'), 'explicit Enable incoming messages').toBeDefined()
  const before = w.httpCalls.length
  denied(await $.tool.call({ tool: READY, nonce: nonce(w) }))
  denied(await $.tool.call({ tool: SEEN, delivery_id: id('delivery', 1) }))
  denied(await $.tool.call({ tool: REPLY, delivery_id: id('delivery', 1), content: 'reply' }))
  denied(await $.tool.call({ tool: ACCEPT, task_id: id('task', 1) }))
  expect(w.httpCalls.slice(before).filter(e => pathOf(e) !== '/adapter/v1/connect')).toEqual([])
  expect(w.prompts.length).toBe(1)
  privacy(w, await visible(ui))
})

test('after a plugin reload the press reconnects the retained authorization without a new review', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const agent = registryAgent(7, 'Retained agent', 'Retained owner')
  w.agents = [agent]
  w.parent = await projectFlow(8, agent, true, NOW - 10 * MINUTE, { state: 'attached' })
  w.adapters[w.parent.flow_id] = await adapterFlow(w.parent, 9, NOW - 9 * MINUTE, { state: 'authorized' })
  const child = clone(w.adapters[w.parent.flow_id])
  const ui = await review($, w)
  expect(mutations(w)).toEqual([]); expect(w.httpCalls).toEqual([])
  await consent(w, ui); await acknowledge($, w, ui)
  for (const kind of ['project.prepare', 'project.decide', 'adapter.prepare', 'adapter.decide']) expect(count(w, kind), kind).toBe(0)
  expect(count(w, 'adapter.transport')).toBe(1)
  expect(last(w, 'adapter.transport').payload).toEqual({ flow_id: child.flow_id, context: context(w.parent), review_id: child.review_id })
  expect(connects(w).length).toBeGreaterThan(0); expect(readyCalls(w).length).toBe(1)
  expect(taskTools(w).length).toBe(5)
  const order = [firstIndex(w, isKind('adapter.transport')), firstIndex(w, isPath('/adapter/v1/connect')),
    firstIndex(w, isKind('prompt')), firstIndex(w, isPath('/adapter/v1/ready')), firstIndex(w, e => e.kind === 'tool' && e.name.startsWith('task_'))]
  expect([...order].sort((a, b) => a - b)).toEqual(order)
  expect(await text(ui)).toContain('Adapter: connected'); expect(await text(ui)).toContain('Incoming tasks: enabled')
  privacy(w, await visible(ui))
})

test('after a host restart the earlier agent is offered as existing and a live earlier credential stops at the adapter step until revoked', { timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const earlier = registryAgent(11, 'Earlier "agent"', 'Earlier owner'), other = registryAgent(12, 'Unrelated agent')
  w.agents = [other, earlier]
  // The earlier press created this agent; restart detached its attachment.
  const old = await projectFlow(13, earlier, true, NOW - 2 * HOUR, { state: 'invalidated', attached: true })
  const oldAdapter = await adapterFlow(old, 14, NOW - 2 * HOUR, { state: 'invalidated', issued: true })
  w.parent = old; w.adapters[old.flow_id] = oldAdapter; w.refuseAdapter = true
  const ui = await review($, w)
  const shown = await visible(ui)
  expect(shown).toContain(quote(earlier.name)); expect(shown).not.toContain(quote(other.name) + ' (new)')
  expect(shown).toMatch(/resume/i); expect(shown).toMatch(/at once|immediately/i)
  expect(mutations(w)).toEqual([])
  await connectWith(w, ui, earlier); await advance(w, ui, 10_000)
  expect(last(w, 'project.prepare').payload).toEqual({ ...contextOf(), agent: { kind: 'existing', id: earlier.id }, replace_flow_id: old.flow_id })
  expect(count(w, 'project.prepare')).toBe(1); expect(count(w, 'project.decide')).toBe(1)
  expect(count(w, 'adapter.prepare')).toBe(1); expect(count(w, 'adapter.decide')).toBe(0); expect(w.httpCalls).toEqual([])
  // The view names the earlier adapter, its credential end and the revoke control
  // (checked after the rest of the case so a naming miss does not hide it).
  const stopped = await text(ui)
  const unnamed = [['peerspan adapter revoke ' + oldAdapter.review.adapter_id, 'earlier adapter and its revoke control'],
    [oldAdapter.authorization.expires_at, 'its credential end']].filter(([value]) => !stopped.includes(value)).map(([, label]) => label)
  // After revocation the next press continues from the adapter step.
  w.refuseAdapter = false
  let next = (await ui.findAll({ type: 'Button', text: new RegExp('^' + CONSENT + '$') })).length > 0 ? ui : null
  if (!next) { await press(ui, 'Close'); await ui.unmount(); next = await review($, w) }
  // The attachment is now recorded for that agent, so the press continues from the adapter step.
  await consent(w, next); await acknowledge($, w, next)
  expect(count(w, 'project.prepare')).toBe(1); expect(count(w, 'project.decide')).toBe(1)
  expect(count(w, 'adapter.prepare')).toBe(2); expect(count(w, 'adapter.decide')).toBe(1)
  expect(connects(w).length).toBeGreaterThan(0); expect(await text(next)).toContain('Adapter: connected')
  privacy(w, await visible(next))
  expect(unnamed, 'terms the adapter-step stop did not name').toEqual([])
})

test('show_each_step restores the per-step connect controls', { options: { show_each_step: 'true' }, timeoutMs: 30000 }, async ($, on) => {
  const w = fixture(on)
  const ui = await mount($, w)
  expect(await button(ui, CONSENT)).toBeUndefined()
  await press(ui, 'Connect this project'); await finished(w, ui)
  expect(await button(ui, 'Review new agent'), 'Review new agent').toBeDefined()
  expect(await button(ui, CONSENT)).toBeUndefined()
  await press(ui, 'Review new agent'); await finished(w, ui)
  expect(count(w, 'project.prepare')).toBe(1); expect(count(w, 'project.decide')).toBe(0)
  await press(ui, 'Approve attachment'); await finished(w, ui)
  expect(await text(ui)).toContain('Project: attachment recorded')
  await press(ui, 'Review adapter connection'); await finished(w, ui)
  expect(count(w, 'adapter.prepare')).toBe(1); expect(count(w, 'adapter.decide')).toBe(0)
  await press(ui, 'Approve adapter'); await finished(w, ui)
  expect(w.httpCalls).toEqual([])
  await press(ui, 'Connect adapter'); await finished(w, ui)
  expect(w.prompts).toEqual([])
  await press(ui, 'Enable incoming messages'); await finished(w, ui); await acknowledge($, w, ui)
  expect(taskTools(w)).toEqual([])
  expect(await button(ui, 'Enable incoming tasks'), 'Enable incoming tasks').toBeDefined()
  privacy(w, await visible(ui))
})
