/**
 * Independent section-6 protocol fixtures on Claude Code 2.1.303.
 * Public native effects only; no product imports, authentication or inference.
 * Original 52 cases are unchanged. Actual reload/terminal/daemon acceptance is
 * separate: fresh test modules establish only volatile initial state here.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted, TestOptions } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-10-29T12:00:00Z')
const HOST = 'host_' + 'a'.repeat(64)
const ROOT = '/private project/Native $(literal)'
const NATIVE = 'private-native-adapter-conversation'
const TOKEN = 'token_' + 'b'.repeat(64)
const SOCKET = '/private host state/adapter.sock'
const RAW = 'PRIVATE_PROVIDER_ERROR token_DO_NOT_ECHO /private/provider-path'
const id = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(32, '0')
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))
const stamp = (milliseconds: number) => new Date(milliseconds).toISOString().replace('.000Z', 'Z')
const quote = (value: string) => JSON.stringify(value).replace(/[\u200b\u202a-\u202e]/g,
  character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
const context = (parent: any) => ({ project_flow_id: parent.flow_id, project_review_id: parent.review_id,
  project_root: parent.review.project_root, native_session_id: parent.review.native_session_id, integration: 'claude-code' })
const effects = { issue_adapter_credential: true, receive_authorized_work: true, reply_to_authorized_work: true,
  handle_authorized_tasks: true, task_artifacts: true, register_agent: false, attach_session: false,
  grant_network_access: false, directory_access: false, outbound_routes: false, capability_calls: false,
  share_files: false, share_conversation: false }

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
async function parentFlow(options: any = {}) {
  const n = options.n ?? 1
  const review = { version: 1, kind: 'attach_project', flow_id: id('flow', n), host_id: options.host ?? HOST,
    project_root: options.root ?? ROOT, native_session_id: options.native ?? NATIVE, integration: 'claude-code',
    create_agent: false, agent: options.agent ?? { id: id('agent', n), name: 'Reviewed native agent', owner: 'Reviewed owner', capabilities: [] },
    session_id: id('session', n), expires_at: stamp(NOW + 900_000),
    effects: { register_agent: false, attach_session: true, issue_adapter_credential: false, grant_network_access: false,
      share_files: false, share_conversation: false, capability_calls: false } }
  const state = options.state ?? 'attached'
  return { version: 1, flow_id: review.flow_id, state, review_id: await digest('peerspan-project-review-v1', review), review,
    attachment: state === 'attached' ? { agent_id: review.agent.id, session_id: review.session_id } : null,
    next_action: state === 'attached' ? 'continue_adapter_setup' : state === 'review' ? 'review' : 'restart_review' }
}
function connection(child: any, now: number, options: any = {}) {
  const ready = options.ready ?? false
  const verified = options.verified ?? false
  return { adapter_id: child.review.adapter_id, session_id: child.review.session_id,
    state: ready ? 'ready' : 'registered', recoverable: ready,
    lease_expires_at: ready ? stamp(options.lease ?? Math.min(now + 15_000, Date.parse(child.review.credential_expires_at))) : null,
    last_seen_at: ready ? stamp(now) : null, channel: ready ? verified ? 'verified' : 'unverified' : null,
    channel_verified_at: verified ? stamp(now) : null, protocol_version: ready ? 'claude-mod-v1' : null }
}
async function adapterFlow(parent: any, options: any = {}) {
  const n = options.n ?? 10
  const review = { version: 1, kind: 'authorize_adapter', flow_id: id('flow', n), host_id: parent.review.host_id,
    ...context(parent), agent: clone(parent.review.agent), session_id: parent.review.session_id, adapter_id: id('adapter', n),
    expires_at: stamp(options.expires ?? NOW + 900_000),
    credential_expires_at: stamp(options.credentialExpires ?? (options.expires ?? NOW + 900_000) + 85_500_000),
    renewable: false, effects: clone(effects) }
  const state = options.state ?? 'review'
  const flow: any = { version: 1, flow_id: review.flow_id, state,
    review_id: await digest('peerspan-adapter-review-v1', review), review, authorization: null, connection: null,
    next_action: state === 'review' ? 'review' : state === 'authorized' ? 'connect_adapter' : 'restart_review' }
  if (state === 'authorized' || options.issued) {
    flow.authorization = { adapter_id: review.adapter_id, session_id: review.session_id, agent_id: review.agent.id,
      expires_at: review.credential_expires_at, renewable: false }
    flow.connection = connection(flow, NOW)
  }
  return flow
}
async function transport(child: any) {
  // The pinned mod runtime exposes digest, not importKey/sign. This is the
  // standard SHA256 HMAC construction for this fixture's 32-byte token key.
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
  const w = { clock, started: false, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, child: null as any, sequence: 20,
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined }
  w.run = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: stamp(clock.now()), host_id: w.host,
      networks: [], agents: [], requests: [], attention: [] }
    if (kind === 'project.lookup') return { version: 1, host_id: w.host, context: payload, flow: w.parent,
      agents: w.parent ? [{ ...w.parent.review.agent, created_at: stamp(NOW - 1000) }] : [] }
    if (kind === 'project.inspect') return w.parent
    if (kind === 'adapter.lookup') return { version: 1, host_id: w.host, context: payload, flow: w.child }
    if (kind === 'adapter.prepare') { w.child = await adapterFlow(w.parent, { n: ++w.sequence }); return w.child }
    if (kind === 'adapter.inspect') return w.child
    if (kind === 'adapter.decide') {
      const choice = payload.decision
      w.child = { ...w.child, state: choice === 'approve' ? 'authorized' : 'declined',
        next_action: choice === 'approve' ? 'connect_adapter' : 'restart_review',
        authorization: choice === 'approve' ? { adapter_id: w.child.review.adapter_id, session_id: w.child.review.session_id,
          agent_id: w.child.review.agent.id, expires_at: w.child.review.credential_expires_at, renewable: false } : null }
      w.child.connection = choice === 'approve' ? connection(w.child, clock.now()) : null
      return w.child
    }
    if (kind === 'adapter.transport') { const value = await transport(w.child); w.materials.push(clone(value)); return value }
    throw Error('Unexpected public process operation')
  }
  w.fetch = async () => {
    const value = connection(w.child, clock.now(), { ready: true })
    w.child = { ...w.child, connection: value }
    return { status: 200, ok: true, headers: {}, text: JSON.stringify(value) }
  }
  on('session.start', ($, e) => { w.started = true; return { cwd: e.cwd } })
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('classic.CwdChanged', () => ({}))
  on('session.root', () => { w.trace.push({ kind: 'root', value: w.root }); return { value: w.root } })
  on('session.id', () => { w.trace.push({ kind: 'native', value: w.native }); return { value: w.native } })
  on('session.cwd', () => ({ value: '/different-shell-cwd' }))
  on('session.surface', () => ({ value: w.surface }))
  on('session.surfaces', () => { w.trace.push({ kind: 'surfaces' }); return { value: w.surfaces } })
  on('command.register', () => ({ value: undefined }))
  on('tool.register', ($, e) => { w.tools.push(e); return { value: undefined } })
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unregistered fixture tool' }))
  on('process.run', async ($, e) => {
    const tail = e.argv.slice(e.argv.indexOf('onboarding') + 1)
    const kind = tail.length ? tail[0] + '.' + tail[1] : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    w.calls.push({ ...e, kind, payload }); w.trace.push({ kind, payload })
    const value = await w.run(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureRaw) return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
    return { value: { exitCode: 0, stdout: JSON.stringify(value), stderr: '' } }
  })
  on('http.fetch', async ($, e) => {
    w.httpCalls.push(clone(e)); w.trace.push({ kind: 'http' }); w.inFlight++
    w.maxInFlight = Math.max(w.maxInFlight, w.inFlight)
    try { const value = await w.fetch(e); return value?.fixtureDeny ? { deny: RAW } : { value } }
    finally { w.inFlight-- }
  })
  on('ui.open', () => ({ value: { isPlaced: w.surface === 'terminal' } }))
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  on('ui.toast', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.log', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.status', ($, e) => { w.outside.push(String(e.text ?? '')); return { value: undefined } })
  on('prompt.submit', ($, e) => { w.prompts.push(e); return { text: e.text, origin: e.origin } })
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
async function text(ui: Pane) { return (await ui.findAll({})).map(element => element.text).join('\n') }
async function key(ui: Pane, label: string) {
  const found = await ui.find({ type: 'Button', text: new RegExp('^' + label + '$') })
  expect(found, label).toBeDefined(); return found!.key!
}
async function press(ui: Pane, label: string) { return ui.press({ key: await key(ui, label) }) }
async function noDecision(ui: Pane) {
  for (const label of ['Approve adapter', 'Decline adapter']) expect(await ui.find({ type: 'Button', text: new RegExp('^' + label + '$') })).toBeUndefined()
}
async function enter($: Engine, w: World): Promise<Pane> {
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  return $.ui.mount({ plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 80,
      placement: 'inline', scroll: { offset: 0, bodyRows: 30 }, view: {} } })
}
async function open($: Engine, w: World, adapter = true) {
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w)
  await press(ui, 'Connect this project')
  if (adapter) await press(ui, 'Review adapter connection')
  return ui
}
function privacy(w: World, uiText = '') {
  expect(w.forbidden).toEqual([]); expect(w.prompts).toEqual([])
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  const references = [w.parent?.flow_id, w.parent?.review_id, w.child?.flow_id, w.child?.review_id,
    w.child?.review.adapter_id, w.parent?.review.session_id, w.parent?.review.agent.id].filter(Boolean)
  for (const value of [TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path', NATIVE,
    ...references, ...w.materials.map(value => value.instance_id)]) {
    expect(uiText).not.toContain(value); expect(w.outside.join('\n')).not.toContain(value)
  }
  expect(w.outside.join('\n')).not.toContain(ROOT); expect(w.outside.join('\n')).not.toContain(w.root)
  for (const call of w.calls) {
    const index = call.argv.indexOf('onboarding')
    const tail = call.argv.slice(index + 1)
    expect(call.init?.timeoutMs).toBe(5000)
    if (call.kind.endsWith('.inspect')) {
      expect(tail).toEqual([call.kind.split('.')[0], 'inspect', call.argv.at(-1)])
      expect(call.init?.stdin).toBeUndefined()
    } else if (call.kind !== 'snapshot') expect(tail).toEqual([...call.kind.split('.'), '--stdin'])
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, ...w.materials.map(value => value.instance_id)]) expect(call.argv).not.toContain(value)
  }
  for (const request of w.httpCalls) {
    expect(request.url).toBe('http://peerspan/adapter/v1/connect')
    expect(Object.keys(request.init).sort()).toEqual(['body', 'headers', 'method', 'socketPath'])
    expect(request.init.method).toBe('POST'); expect(request.init.socketPath).toBe(SOCKET)
    const body = JSON.parse(request.init.body)
    const material = w.materials.find(value => value.adapter_id === body.adapter_id && value.instance_id === body.instance_id)
    expect(material).toBeDefined()
    expect(body).toEqual({ adapter_id: material.adapter_id, session_id: material.session_id,
      instance_id: material.instance_id, protocol_version: 'claude-mod-v1' })
    expect(Object.fromEntries(Object.entries(request.init.headers).map(([name, value]) => [name.toLowerCase(), value])))
      .toEqual({ authorization: 'Bearer ' + TOKEN, 'x-peerspan-instance': material.instance_id, 'content-type': 'application/json' })
  }
}

test('initial, headless and unknown-argument entry cannot start adapter preparation or a runtime', async ($, on) => {
  const w = fixture(on)
  w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  expect(w.calls).toEqual([]); expect(w.httpCalls).toEqual([])
  for (const args of ['adapter', '--connect', 'approve']) await $.command.run({ command: 'peerspan', args })
  expect(w.calls).toEqual([])
  const ui = await enter($, w)
  await press(ui, 'Refresh')
  expect(w.calls.map(call => call.kind)).toEqual(['snapshot', 'snapshot'])
  expect(await ui.find({ type: 'Button', text: /^Review adapter connection$/ })).toBeUndefined()
  w.surface = null; w.surfaces = []
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'sdk' } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  expect(w.calls.map(call => call.kind)).toEqual(['snapshot', 'snapshot', 'snapshot'])
  expect(w.httpCalls).toEqual([])
  privacy(w, await text(ui))
})

test('only attached projects offer adapter review; desktop rendering stays private even alongside terminal', async ($, on) => {
  const w = fixture(on)
  w.parent = await parentFlow({ state: 'review' })
  const ui = await open($, w, false)
  expect(await ui.find({ type: 'Button', text: /^Review adapter connection$/ })).toBeUndefined()
  expect(count(w, 'adapter.lookup')).toBe(0)
  await press(ui, 'Close'); await ui.unmount()
  w.parent = await parentFlow(); w.child = await adapterFlow(w.parent)
  const terminal = await open($, w)
  expect(await terminal.find({ type: 'Button', text: /^Approve adapter$/ })).toBeDefined()
  w.surfaces = ['terminal', 'desktop']; w.surface = 'desktop'
  const desktop = await $.ui.mount({ plugin: 'peerspan', surface: 'desktop', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 80,
      placement: 'inline', scroll: { offset: 0, bodyRows: 30 }, view: {} } })
  for (const label of ['Approve adapter', 'Decline adapter', 'Connect adapter', 'Review adapter connection', 'Review adapter permissions']) {
    expect(await desktop.find({ type: 'Button', text: new RegExp('^' + label + '$') })).toBeUndefined()
  }
  const shown = (await desktop.findAll({})).map(element => element.text).join('\n')
  expect(shown).not.toContain(ROOT); expect(shown).not.toContain(w.parent.review.agent.owner)
  expect(count(w, 'adapter.decide')).toBe(0); expect(w.httpCalls).toEqual([])
  privacy(w, shown)
})

test('explicit Review inspects parent before lookup/prepare; active Refresh never prepares an empty result', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow()
  const ui = await open($, w)
  const kinds = w.calls.map(call => call.kind)
  expect(kinds.indexOf('project.inspect') < kinds.indexOf('adapter.lookup')).toBe(true)
  expect(kinds.indexOf('adapter.lookup') < kinds.indexOf('adapter.prepare')).toBe(true)
  expect(last(w, 'adapter.lookup').payload).toEqual(context(w.parent))
  expect(last(w, 'adapter.prepare').payload).toEqual({ context: context(w.parent) })
  expect(count(w, 'adapter.prepare')).toBe(1)
  w.child = null
  await press(ui, 'Refresh')
  expect(count(w, 'adapter.prepare')).toBe(1)
  await noDecision(ui)
  await press(ui, 'Review adapter permissions')
  expect(count(w, 'adapter.prepare')).toBe(2)
  expect(count(w, 'adapter.decide')).toBe(0); expect(count(w, 'adapter.transport')).toBe(0)
  privacy(w, await text(ui))
})

test('retained adapter review shows complete reversible terms, fixed lifetime and every effect without references', async ($, on) => {
  const w = fixture(on)
  const agent = { id: id('agent', 1), name: 'Full-' + 'n'.repeat(90) + '"\\\u202e',
    owner: 'Owner "東京"\\\u200b', capabilities: ['metadata "one"', 'second descriptive label'] }
  w.parent = await parentFlow({ agent }); w.child = await adapterFlow(w.parent)
  const ui = await open($, w)
  const shown = (await text(ui)).replace(/\\u([0-9a-fA-F]{4})/g, (_, digits) => '\\u' + digits.toLowerCase())
  expect(count(w, 'adapter.prepare')).toBe(0)
  for (const value of [quote(ROOT), quote(agent.name), quote(agent.owner), ...agent.capabilities.map(quote),
    w.child.review.expires_at, w.child.review.credential_expires_at, 'Conversation: current conversation']) expect(shown).toContain(value)
  for (const meaning of [/credential/i, /existing.*session/i, /receiv[\s\S]*authorized/i, /repl[\s\S]*authorized/i,
    /tasks/i, /artifacts/i, /(?:existing|already) authorized work/i, /no new agent|new agents?(?: or sessions?)?:\s*none/i,
    /no new.*session|new sessions?:\s*none|new agents? or sessions?:\s*none/i,
    /no.*(?:membership|access grant)|(?:membership|access grant).*none/i,
    /directory.*none|no directory/i, /outbound.*none|no outbound/i,
    /capability.*none|no capability/i, /file.*none|no automatic sharing[\s\S]*files/i,
    /conversation.*none|no automatic sharing[\s\S]*conversation/i, /ordinary.*permissions|local harness permissions.*govern/i,
    /nonrenew|not renewable|renewable:\s*false|renewal:\s*none/i]) expect(shown).toMatch(meaning)
  for (const value of [w.parent.flow_id, w.parent.review_id, w.child.flow_id, w.child.review_id,
    w.child.review.adapter_id, agent.id, w.child.review.session_id]) expect(shown).not.toContain(value)
  expect(shown).not.toMatch(/[\u202a-\u202e\u200b]/)
  expect(await ui.find({ type: 'Button', text: /^Approve adapter$/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /^Decline adapter$/ })).toBeDefined()
  privacy(w, shown)
})

test('malformed hidden changed or private-looking adapter terms cannot offer an owner decision', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); const valid = await adapterFlow(w.parent)
  w.child = valid; const ui = await open($, w)
  for (const mutate of [
    (f: any) => { f.version = 2 }, (f: any) => { f.extra = true }, (f: any) => { f.review.extra = true },
    (f: any) => { f.review.agent.extra = true }, (f: any) => { f.review.effects.extra = false },
    (f: any) => { f.review.effects.directory_access = true }, (f: any) => { f.review.renewable = true },
    (f: any) => { f.review.agent.owner = 'different owner' }, (f: any) => { f.review.session_id = id('session', 99) },
    (f: any) => { f.review.project_review_id = 'review_' + 'f'.repeat(64) },
    (f: any) => { f.review.host_id = 'host_' + 'f'.repeat(64) }, (f: any) => { f.review.kind = 'other' },
    (f: any) => { f.review.agent.name = 'x'.repeat(129) },
    (f: any) => { f.review.agent.capabilities = Array.from({ length: 101 }, () => 'metadata') },
    (f: any) => { f.authorization = {} }, (f: any) => { f.next_action = 'connect_adapter' },
  ]) {
    w.child = clone(valid); mutate(w.child)
    await press(ui, 'Refresh'); await noDecision(ui)
  }
  for (const prefix of ['psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.', 'peerspan-person-invite-v1.', 'token_', 'instance_']) {
    w.child = clone(valid)
    w.child.review.agent.owner = '\x1b]0;' + prefix.slice(0, 2) + '\u202e\x1b[31m' + prefix.slice(2) + 'SHORTSECRET\x07visible'
    await press(ui, 'Refresh'); await noDecision(ui)
    expect(await text(ui)).not.toContain('SHORTSECRET'); expect(await text(ui)).not.toContain(prefix)
  }
  expect(count(w, 'adapter.decide')).toBe(0); expect(w.httpCalls).toEqual([])
  privacy(w, await text(ui))
})

for (const state of ['declined', 'expired', 'invalidated']) {
  test(`retained ${state} requires exact explicit adapter replacement and fresh consent`, async ($, on) => {
    const w = fixture(on); w.parent = await parentFlow()
    w.child = await adapterFlow(w.parent, { state, expires: state === 'expired' ? NOW - 1000 : NOW + 900_000 })
    const captured = clone(w.child); const ui = await open($, w)
    await noDecision(ui); expect(count(w, 'adapter.prepare')).toBe(0)
    await press(ui, 'Review a replacement adapter')
    expect(last(w, 'adapter.prepare').payload).toEqual({ context: context(w.parent), replace_flow_id: captured.flow_id })
    expect(count(w, 'adapter.prepare')).toBe(1); expect(count(w, 'adapter.decide')).toBe(0)
    expect(await ui.find({ type: 'Button', text: /^Approve adapter$/ })).toBeDefined()
    privacy(w, await text(ui))
  })
}

for (const choice of ['approve', 'decline']) {
  test(`exact ${choice} inspects both captured reviews and rechecks native context without retrieving or connecting`, async ($, on) => {
    const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent)
    const captured = clone(w.child); const ui = await open($, w); const before = w.trace.length
    await press(ui, choice === 'approve' ? 'Approve adapter' : 'Decline adapter')
    expect(count(w, 'adapter.decide')).toBe(1)
    expect(last(w, 'adapter.decide').payload).toEqual({ flow_id: captured.flow_id, context: context(w.parent), review_id: captured.review_id, decision: choice })
    const trace = w.trace.slice(before), first = trace.findIndex(item => item.kind.endsWith('.inspect'))
    const lastRead = Math.max(trace.findIndex(item => item.kind === 'project.inspect'), trace.findIndex(item => item.kind === 'adapter.inspect'))
    const sent = trace.findIndex(item => item.kind === 'adapter.decide')
    for (const kind of ['root', 'native']) {
      expect(trace.slice(0, first).some(item => item.kind === kind)).toBe(true)
      expect(trace.slice(lastRead + 1, sent).some(item => item.kind === kind)).toBe(true)
    }
    expect(last(w, 'project.inspect').argv.at(-1)).toBe(w.parent.flow_id)
    expect(last(w, 'adapter.inspect').argv.at(-1)).toBe(captured.flow_id)
    expect(count(w, 'adapter.transport')).toBe(0); expect(w.httpCalls).toEqual([])
    privacy(w, await text(ui))
  })
}

test('double approval queues one exact decision and lost approval is resolved read-only without retry', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent)
  const normal = w.run
  w.run = async (kind, payload, e) => {
    if (kind === 'adapter.inspect') await w.clock.sleep(1000)
    const response = await normal(kind, payload, e)
    return kind === 'adapter.decide' ? { fixtureDeny: true } : response
  }
  const ui = await open($, w), button = await key(ui, 'Approve adapter')
  const first = ui.press({ key: button }); void first.catch(() => undefined)
  const second = ui.press({ key: button }).catch(() => undefined)
  await w.clock.settle(); await w.clock.advance(1000); await Promise.all([first, second])
  expect(count(w, 'adapter.decide')).toBe(1)
  expect(await text(ui)).toMatch(/unknown|uncertain/i); await noDecision(ui)
  await w.clock.advance(10_000)
  expect(count(w, 'adapter.decide')).toBe(1)
  await press(ui, 'Refresh')
  expect(await ui.find({ type: 'Button', text: /^Connect adapter$/ })).toBeDefined()
  expect(count(w, 'adapter.transport')).toBe(0); expect(w.httpCalls).toEqual([])
  privacy(w, await text(ui))
})

test('changed parent child terms hashes scope host or native context prevent owner decisions', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); const parent = clone(w.parent)
  const child = await adapterFlow(parent); w.child = child; const normal = w.run
  for (const mode of ['parent-review', 'parent-hash', 'child-review', 'child-hash', 'scope', 'host', 'context-before', 'context-after', 'read-failure']) {
    w.parent = clone(parent); w.child = clone(child); w.root = ROOT; w.native = NATIVE; w.run = normal
    const ui = await open($, w)
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'project.inspect' && mode === 'parent-review') value.review.agent.owner = 'changed'
      if (kind === 'project.inspect' && mode === 'parent-hash') value.review_id = 'review_' + 'f'.repeat(64)
      if (kind === 'adapter.inspect') {
        if (mode === 'child-review') value.review.credential_expires_at = stamp(NOW + 90_000_000)
        if (mode === 'child-hash') value.review_id = 'review_' + 'f'.repeat(64)
        if (mode === 'scope') value.review.effects.outbound_routes = true
        if (mode === 'host') value.review.host_id = 'host_' + 'f'.repeat(64)
        if (mode === 'context-after') w.native = 'other-conversation-after-inspection'
        if (mode === 'read-failure') return { fixtureDeny: true }
      }
      return value
    }
    if (mode === 'context-before') w.root = '/other/native/root'
    await press(ui, 'Approve adapter')
    expect(count(w, 'adapter.decide')).toBe(0); await noDecision(ui)
    await press(ui, 'Close'); await ui.unmount()
  }
  privacy(w)
})

test('adapter review deadline blocks a pending inspection and late callbacks cannot approve a reopened view', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { expires: NOW + 1000 })
  const normal = w.run
  w.run = async (kind, payload, e) => {
    const value = clone(await normal(kind, payload, e))
    if (kind === 'adapter.inspect') await w.clock.sleep(1500)
    return value
  }
  const ui = await open($, w)
  const pending = ui.press({ key: await key(ui, 'Approve adapter') }); void pending.catch(() => undefined)
  await w.clock.settle(); await w.clock.advance(1000)
  await noDecision(ui); expect(await text(ui)).toMatch(/deadline|expir/i)
  await press(ui, 'Close'); await ui.unmount()
  w.child = await adapterFlow(w.parent, { n: 99 })
  const fresh = await enter($, w); await press(fresh, 'Connect this project'); await press(fresh, 'Review adapter connection')
  await w.clock.advance(500); await pending
  expect(count(w, 'adapter.decide')).toBe(0)
  expect(await fresh.find({ type: 'Button', text: /^Approve adapter$/ })).toBeDefined()
  privacy(w, await text(fresh))
})

const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private host state/$(literal)' },
}
test('only explicit Connect retrieves exact private transport and sends bounded Unix-scoped HTTP', configured, async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const captured = clone(w.child); const ui = await open($, w)
  expect(count(w, 'adapter.transport')).toBe(0); expect(w.httpCalls).toEqual([])
  const before = w.trace.length
  await press(ui, 'Connect adapter')
  expect(count(w, 'adapter.decide')).toBe(0); expect(count(w, 'adapter.transport')).toBe(1)
  expect(last(w, 'adapter.transport').payload).toEqual({ flow_id: captured.flow_id, context: context(w.parent), review_id: captured.review_id })
  for (const call of w.calls) expect(call.argv.slice(0, 3)).toEqual([configured.options.executable, '--state', configured.options.state])
  const trace = w.trace.slice(before), sent = trace.findIndex(item => item.kind === 'http')
  const material = trace.findIndex(item => item.kind === 'adapter.transport')
  expect(trace.slice(0, material).some(item => item.kind === 'project.inspect')).toBe(true)
  expect(trace.slice(0, material).some(item => item.kind === 'adapter.inspect')).toBe(true)
  for (const kind of ['root', 'native']) expect(trace.slice(material + 1, sent).some(item => item.kind === kind)).toBe(true)
  expect(w.httpCalls.length).toBe(1)
  for (const value of ['Adapter: connected', 'Incoming delivery: not verified', 'Peer exchange: not verified']) expect(await text(ui)).toContain(value)
  privacy(w, await text(ui))
})

test('malformed private material and unsupported Unix socket paths never reach HTTP', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const normal = w.run; const ui = await open($, w)
  const changes = [
    (m: any) => { m.version = 2 }, (m: any) => { m.extra = RAW }, (m: any) => { delete m.token },
    (m: any) => { m.adapter_id = id('adapter', 999) }, (m: any) => { m.session_id = id('session', 999) },
    (m: any) => { m.token = 'token_' + 'A'.repeat(64) }, (m: any) => { m.instance_id = 'instance_bad' },
    ...['relative/adapter.sock', '/private//adapter.sock', '/private/./adapter.sock', '/private/../adapter.sock',
      '/private\n/adapter.sock', '/private/owner.sock', '/' + 'é'.repeat(48) + '/adapter.sock'].map(path => (m: any) => { m.adapter_socket = path }),
  ]
  for (const change of changes) {
    w.run = normal; await press(ui, 'Refresh')
    w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e)); if (kind === 'adapter.transport') change(value); return value }
    await press(ui, 'Connect adapter')
    expect(w.httpCalls).toEqual([])
    expect(await text(ui)).not.toContain('Adapter: connected')
    expect(await text(ui)).not.toContain(RAW)
  }
  privacy(w, await text(ui))
})

test('ineligible inspections or context changes before transport and after retrieval cannot connect', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); const parent = await parentFlow(); const child = await adapterFlow(parent, { state: 'authorized' })
  const normal = w.run
  for (const mode of ['parent-state', 'child-state', 'child-hash', 'parent-scope', 'context-before', 'context-after-inspect', 'context-after-transport']) {
    w.root = ROOT; w.native = NATIVE; w.parent = clone(parent); w.child = clone(child); w.run = normal
    const ui = await open($, w)
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'project.inspect' && mode === 'parent-state') { value.state = 'invalidated'; value.next_action = 'restart_review' }
      if (kind === 'project.inspect' && mode === 'parent-scope') value.review.effects.share_files = true
      if (kind === 'adapter.inspect' && mode === 'child-state') { value.state = 'invalidated'; value.next_action = 'restart_review' }
      if (kind === 'adapter.inspect' && mode === 'child-hash') value.review_id = 'review_' + 'f'.repeat(64)
      if (kind === 'adapter.inspect' && mode === 'context-after-inspect') w.native = 'changed-after-inspection'
      if (kind === 'adapter.transport' && mode === 'context-after-transport') w.root = '/changed-after-private-retrieval'
      return value
    }
    if (mode === 'context-before') w.native = 'changed-before-connect'
    await press(ui, 'Connect adapter')
    expect(w.httpCalls).toEqual([])
    expect(await text(ui)).not.toContain('Adapter: connected')
    await press(ui, 'Close'); await ui.unmount()
  }
  privacy(w)
})

test('denied failed malformed and mismatched scoped responses never report connected or retry', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const ui = await open($, w)
  const mutations = [
    (c: any) => { c.extra = true }, (c: any) => { c.adapter_id = id('adapter', 999) },
    (c: any) => { c.session_id = id('session', 999) }, (c: any) => { c.state = 'offline' },
    (c: any) => { c.lease_expires_at = stamp(w.clock.now()) },
    (c: any) => { c.lease_expires_at = stamp(NOW + 90_000_000) },
    (c: any) => { c.recoverable = 'yes' }, (c: any) => { c.channel = 'unknown' },
    (c: any) => { delete c.protocol_version },
  ]
  for (const mutate of mutations) {
    await press(ui, 'Refresh')
    w.fetch = async () => { const value = connection(w.child, w.clock.now(), { ready: true }); mutate(value)
      return { status: 200, ok: true, headers: {}, text: JSON.stringify(value) } }
    await press(ui, 'Connect adapter')
    expect(await text(ui)).not.toContain('Adapter: connected')
    const calls = w.httpCalls.length; await w.clock.advance(6000); expect(w.httpCalls.length).toBe(calls)
  }
  for (const response of [{ fixtureDeny: true }, { status: 503, ok: false, headers: {}, text: RAW },
    { status: 200, ok: true, headers: {}, text: '{broken ' + RAW }]) {
    await press(ui, 'Refresh'); w.fetch = async () => response
    await press(ui, 'Connect adapter')
    expect(await text(ui)).not.toContain('Adapter: connected'); expect(await text(ui)).not.toContain(RAW)
    const calls = w.httpCalls.length; await w.clock.advance(6000); expect(w.httpCalls.length).toBe(calls)
  }
  privacy(w, await text(ui))
})

test('a saved verified channel never becomes native incoming proof and healthy renewal is single-flight', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  let responses = 0
  w.fetch = async () => {
    if (++responses > 1) await w.clock.sleep(1000)
    const value = connection(w.child, w.clock.now(), { ready: true, verified: true })
    w.child = { ...w.child, connection: value }
    return { status: 200, ok: true, headers: {}, text: JSON.stringify(value) }
  }
  const ui = await open($, w); await press(ui, 'Connect adapter')
  expect(await text(ui)).toContain('Incoming delivery: not verified')
  expect(await text(ui)).toContain('Peer exchange: not verified')
  await w.clock.advance(4999); expect(w.httpCalls.length).toBe(1)
  const traceBefore = w.trace.length
  await w.clock.advance(1); expect(w.httpCalls.length).toBe(2)
  await w.clock.advance(1000); expect(w.maxInFlight).toBe(1)
  await w.clock.advance(4999); expect(w.httpCalls.length).toBe(2)
  await w.clock.advance(1); expect(w.httpCalls.length).toBe(3)
  expect(count(w, 'adapter.transport')).toBe(1); expect(count(w, 'adapter.decide')).toBe(0)
  const trace = w.trace.slice(traceBefore)
  expect(trace.some(item => item.kind === 'surfaces')).toBe(true)
  expect(trace.some(item => item.kind === 'project.inspect')).toBe(true)
  expect(trace.some(item => item.kind === 'adapter.inspect')).toBe(true)
  expect(new Set(w.httpCalls.map(request => request.init.body)).size).toBe(1)
  await w.clock.advance(1000); await press(ui, 'Stop adapter')
  privacy(w, await text(ui))
})

test('double Connect queues once; its five-second deadline discards late HTTP and old timers after explicit reconnect', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const normal = w.fetch; let requests = 0
  w.fetch = async e => { const response = clone(await normal(e)); if (++requests === 1) await w.clock.sleep(6000); return response }
  const ui = await open($, w), button = await key(ui, 'Connect adapter')
  const first = ui.press({ key: button }); void first.catch(() => undefined)
  const second = ui.press({ key: button }).catch(() => undefined)
  await w.clock.settle(); expect(w.httpCalls.length).toBe(1)
  await w.clock.advance(4999); expect(await text(ui)).not.toContain('Adapter: connected')
  await w.clock.advance(1); await Promise.all([first, second])
  expect(await text(ui)).not.toContain('Adapter: connected')
  expect(await text(ui)).toMatch(/unknown|unavailable|timed|timeout/i)
  expect(count(w, 'adapter.transport')).toBe(1)
  await press(ui, 'Refresh'); await press(ui, 'Connect adapter')
  expect(w.httpCalls.length).toBe(2); expect(await text(ui)).toContain('Adapter: connected')
  await w.clock.advance(1000) // the timed-out response can complete, with no authority
  expect(w.httpCalls.length).toBe(2)
  await w.clock.advance(4000); expect(w.httpCalls.length).toBe(3)
  await w.clock.advance(1000); expect(w.httpCalls.length).toBe(3)
  expect(new Set(w.httpCalls.map(request => JSON.parse(request.init.body).instance_id)).size).toBe(1)
  await press(ui, 'Stop adapter'); await w.clock.advance(20_000)
  expect(w.httpCalls.length).toBe(3)
  privacy(w, await text(ui))
})

for (const leave of ['Close', 'Back to Peerspan']) {
  test(`${leave} cancels a pending initial connection and its late response cannot create renewal`, async ($, on) => {
    const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
    const normal = w.fetch
    w.fetch = async e => { const response = clone(await normal(e)); await w.clock.sleep(1000); return response }
    const ui = await open($, w)
    const pending = ui.press({ key: await key(ui, 'Connect adapter') }); void pending.catch(() => undefined)
    await w.clock.settle(); expect(w.httpCalls.length).toBe(1)
    await press(ui, leave)
    if (leave === 'Close') await ui.unmount()
    await w.clock.advance(1000); await pending
    await w.clock.advance(15_000); expect(w.httpCalls.length).toBe(1)
    expect(count(w, 'adapter.decide')).toBe(0)
    privacy(w)
  })
}

test('an established runtime survives Back and pane Close but explicit Stop forgets it without host mutation', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const ui = await open($, w); await press(ui, 'Connect adapter')
  await press(ui, 'Back to Peerspan'); await w.clock.advance(5000)
  expect(w.httpCalls.length).toBe(2)
  await press(ui, 'Close'); await ui.unmount(); await w.clock.advance(5000)
  expect(w.httpCalls.length).toBe(3)
  const fresh = await enter($, w)
  expect(await text(fresh)).toContain('Adapter: connected')
  await press(fresh, 'Stop adapter'); await w.clock.advance(30_000)
  expect(w.httpCalls.length).toBe(3)
  expect(await text(fresh)).not.toContain('Adapter: connected')
  expect(count(w, 'adapter.transport')).toBe(1); expect(count(w, 'adapter.decide')).toBe(0)
  expect(count(w, 'adapter.prepare')).toBe(0)
  privacy(w, await text(fresh))
})

test('session end root change terminal loss and changed parent child scope or host stop renewal', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); const parent = await parentFlow(); const child = await adapterFlow(parent, { state: 'authorized' })
  for (const mode of ['root-event', 'root-without-event', 'conversation', 'terminal-loss', 'parent', 'child', 'scope', 'host', 'revocation', 'session-end']) {
    w.parent = clone(parent); w.child = clone(child); w.root = ROOT; w.native = NATIVE; w.surfaces = ['terminal']; w.surface = 'terminal'
    const ui = await open($, w); await press(ui, 'Connect adapter')
    const before = w.httpCalls.length
    if (mode === 'session-end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    if (mode === 'root-event') { w.root = '/different-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'root-without-event') w.root = '/different-root-without-event'
    if (mode === 'conversation') w.native = 'different-native-conversation'
    if (mode === 'terminal-loss') { w.surfaces = []; w.surface = null }
    if (mode === 'parent') { w.parent.state = 'invalidated'; w.parent.next_action = 'restart_review' }
    if (mode === 'child' || mode === 'revocation') { w.child.state = 'invalidated'; w.child.next_action = 'restart_review' }
    if (mode === 'scope') w.child.review.effects.outbound_routes = true
    if (mode === 'host') w.parent.review.host_id = 'host_' + 'f'.repeat(64)
    if (mode === 'session-end' || mode === 'root-event') expect(await text(ui), mode + ': immediate clearing').not.toContain('Adapter: connected')
    await w.clock.advance(5000)
    expect(w.httpCalls.length, mode + ': first renewal').toBe(before)
    expect(await text(ui), mode + ': cleared connected status').not.toContain('Adapter: connected')
    await w.clock.advance(20_000); expect(w.httpCalls.length, mode + ': no later renewal').toBe(before)
    // Restore only the fixture's current native context so a new explicit user
    // intent can exercise the next independent stopping condition.
    w.surfaces = ['terminal']; w.surface = 'terminal'
    const close = await ui.find({ type: 'Button', text: /^Close$/ })
    if (close) await ui.press({ key: close.key! })
    await ui.unmount()
  }
  expect(count(w, 'adapter.decide')).toBe(0)
  privacy(w)
})

test('credential deadline and last accepted lease deadline independently clear connected status', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow()
  w.child = await adapterFlow(w.parent, { state: 'authorized', expires: NOW + 6000 - 85_500_000, credentialExpires: NOW + 6000 })
  const ui = await open($, w); await press(ui, 'Connect adapter')
  expect(await text(ui)).toContain('Adapter: connected')
  await w.clock.advance(6000)
  expect(await text(ui)).not.toContain('Adapter: connected')
  const before = w.httpCalls.length; await w.clock.advance(20_000); expect(w.httpCalls.length).toBe(before)
  privacy(w, await text(ui))
})

test('lease expiry while inspection is pending stops old runtime and cannot replace a newer connection', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const normalRun = w.run; const normalFetch = w.fetch
  w.fetch = async () => { const value = connection(w.child, w.clock.now(), { ready: true, lease: NOW + 7000 })
    w.child = { ...w.child, connection: value }; return { status: 200, ok: true, headers: {}, text: JSON.stringify(value) } }
  w.run = async (kind, payload, e) => { const value = clone(await normalRun(kind, payload, e))
    if (kind === 'project.inspect' && w.httpCalls.length > 0) await w.clock.sleep(4000)
    return value }
  const ui = await open($, w); await press(ui, 'Connect adapter')
  await w.clock.advance(5000); expect(w.httpCalls.length).toBe(1)
  await w.clock.advance(2000); expect(await text(ui)).not.toContain('Adapter: connected')
  w.run = normalRun; w.fetch = normalFetch; w.child.connection = connection(w.child, w.clock.now())
  await press(ui, 'Refresh'); await press(ui, 'Connect adapter')
  expect(w.httpCalls.length).toBe(2)
  await w.clock.advance(2000) // the old inspection finishes after its lease died
  expect(w.httpCalls.length).toBe(2); expect(await text(ui)).toContain('Adapter: connected')
  await w.clock.advance(3000); expect(w.httpCalls.length).toBe(3)
  await press(ui, 'Stop adapter')
  privacy(w, await text(ui))
})

test('a failed established renewal stops without retry even while the old accepted lease remains valid', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const ui = await open($, w); await press(ui, 'Connect adapter')
  w.fetch = async () => ({ fixtureDeny: true })
  await w.clock.advance(5000)
  expect(w.httpCalls.length).toBe(2); expect(await text(ui)).not.toContain('Adapter: connected')
  expect(await text(ui)).not.toContain(RAW)
  await w.clock.advance(30_000); expect(w.httpCalls.length).toBe(2)
  privacy(w, await text(ui))
})

test('a changed native conversation while HTTP is pending cannot become connected from its late response', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  const normal = w.fetch
  w.fetch = async e => { const value = clone(await normal(e)); await w.clock.sleep(1000); return value }
  const ui = await open($, w)
  const pending = ui.press({ key: await key(ui, 'Connect adapter') }); void pending.catch(() => undefined)
  await w.clock.settle(); w.native = 'different-native-while-http-pending'
  await w.clock.advance(1000); await pending
  expect(await text(ui)).not.toContain('Adapter: connected')
  await w.clock.advance(20_000); expect(w.httpCalls.length).toBe(1)
  privacy(w, await text(ui))
})

test('a late already-sent adapter decision cannot replace a newer human review after Close', async ($, on) => {
  const w = fixture(on); w.parent = await parentFlow(); w.child = await adapterFlow(w.parent)
  const normal = w.run
  w.run = async (kind, payload, e) => { const response = clone(await normal(kind, payload, e))
    if (kind === 'adapter.decide') await w.clock.sleep(1000); return response }
  const ui = await open($, w)
  const pending = ui.press({ key: await key(ui, 'Approve adapter') }); void pending.catch(() => undefined)
  await w.clock.settle(); expect(count(w, 'adapter.decide')).toBe(1)
  await press(ui, 'Close'); await ui.unmount()
  w.child = await adapterFlow(w.parent, { n: 99 })
  const fresh = await enter($, w); await press(fresh, 'Connect this project'); await press(fresh, 'Review adapter connection')
  await w.clock.advance(1000); await pending
  expect(await fresh.find({ type: 'Button', text: /^Approve adapter$/ })).toBeDefined()
  expect(await fresh.find({ type: 'Button', text: /^Connect adapter$/ })).toBeUndefined()
  expect(count(w, 'adapter.transport')).toBe(0); expect(w.httpCalls).toEqual([])
  privacy(w, await text(fresh))
})

for (const phase of ['adapter.lookup', 'adapter.prepare', 'adapter.transport']) {
  test(`a late ${phase} after Close cannot replace a different native context or start scoped HTTP`, async ($, on) => {
    const w = fixture(on); w.parent = await parentFlow()
    if (phase === 'adapter.transport') w.child = await adapterFlow(w.parent, { state: 'authorized' })
    const normal = w.run; let delayed = true
    w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e))
      if (kind === phase && delayed) { delayed = false; await w.clock.sleep(1000) }; return value }
    const ui = await open($, w, false)
    if (phase === 'adapter.transport') await press(ui, 'Review adapter connection')
    const pending = ui.press({ key: await key(ui, phase === 'adapter.transport' ? 'Connect adapter' : 'Review adapter connection') })
    void pending.catch(() => undefined); await w.clock.settle()
    await press(ui, 'Close'); await ui.unmount()
    w.root = '/different/private/new-project'; w.native = 'different-native-for-new-view'
    w.parent = await parentFlow({ n: 2, root: w.root, native: w.native }); w.child = await adapterFlow(w.parent, { n: 99 })
    const fresh = await enter($, w); await press(fresh, 'Connect this project'); await press(fresh, 'Review adapter connection')
    await w.clock.advance(1000); await pending
    expect(await text(fresh)).toContain(JSON.stringify(w.root)); expect(await text(fresh)).not.toContain(JSON.stringify(ROOT))
    expect(await fresh.find({ type: 'Button', text: /^Approve adapter$/ })).toBeDefined()
    expect(count(w, 'adapter.decide')).toBe(0); expect(w.httpCalls).toEqual([])
    privacy(w, await text(fresh))
  })
}
