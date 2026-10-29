/**
 * Independent section-7 message protocol fixtures on Claude Code 2.1.303.
 * Public native effects only; no product imports, authentication or inference.
 * Original 83 cases are unchanged. Actual reload/terminal/daemon acceptance is
 * separate: fresh test modules establish only volatile initial state here.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-10-29T12:00:00Z')
const HOST = 'host_' + 'a'.repeat(64)
const ROOT = '/private project/Native $(literal)'
const NATIVE = 'private-native-adapter-conversation'
const TOKEN = 'token_' + 'b'.repeat(64)
const READY = 'mcp__peerspan__adapter_ready'
const SEEN = 'mcp__peerspan__message_seen'
const REPLY = 'mcp__peerspan__message_reply'
const SENDER = 'host_' + 'd'.repeat(64)
const PERSON = 'person_' + 'e'.repeat(64)
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
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
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
  w.fetch = async e => {
    const path = e.url.replace('http://peerspan', ''), body = JSON.parse(e.init.body)
    let value: any
    if (path === '/adapter/v1/connect' || path === '/adapter/v1/ready') {
      value = connection(w.child, clock.now(), { ready: true,
        verified: path.endsWith('/ready') || w.child.connection?.channel === 'verified' })
      w.child = { ...w.child, connection: value }
    } else if (path === '/adapter/v1/next') {
      value = w.messages.shift() ?? null
      if (value?.delivery?.id) w.held[value.delivery.id] = clone(value)
    } else if (path === '/adapter/v1/seen') {
      const delivery = body.ids[0], first = !w.seen.has(delivery)
      w.seen.add(delivery); value = { seen: first ? [delivery] : [] }
    } else {
      const delivery = path.split('/')[4], held = w.held[delivery]
      if (path.endsWith('/forwarded')) value = { ...held.delivery, state: 'forwarded', updated_at: stamp(clock.now()) }
      else if (path.endsWith('/reply')) {
        value = w.replies[delivery] ?? { sender_host_id: held?.delivery.sender_host_id ?? SENDER,
          request_id: held?.request.request_id ?? id('request', 1), receiver_host_id: w.host,
          target_agent_id: w.child.review.agent.id, session_id: w.child.review.session_id,
          delivery_id: delivery, content: body.content, replied_at: stamp(clock.now()),
          origin: { agent_id: w.child.review.agent.id, session_id: w.child.review.session_id } }
        w.replies[delivery] = clone(value)
      } else throw Error('Unexpected scoped route')
    }
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
    w.httpCalls.push(clone(e)); w.trace.push({ kind: 'http', path: e.url }); w.inFlight++
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
  on('prompt.submit', async ($, e) => { w.prompts.push(clone(e)); w.trace.push({ kind: 'prompt', text: e.text }); return w.submit(e) })
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

const pathOf = (e: any) => e.url.replace('http://peerspan', '')
const requests = (w: World, path: string) => w.httpCalls.filter(e => pathOf(e) === path)
const claims = (w: World) => requests(w, '/adapter/v1/next')
const readyCalls = (w: World) => requests(w, '/adapter/v1/ready')
const forwards = (w: World) => w.httpCalls.filter(e => pathOf(e).endsWith('/forwarded'))
const replies = (w: World) => w.httpCalls.filter(e => pathOf(e).endsWith('/reply'))
const seenCalls = (w: World) => requests(w, '/adapter/v1/seen')
function nonce(w: World, at = 0) {
  const match = w.prompts[at]?.text.match(/\b[0-9a-f]{32}\b/g)
  expect(match?.length, 'one public readiness nonce').toBe(1)
  return match![0]
}
function resultOf(answer: any): any {
  const value = answer.result
  if (typeof value === 'string') return JSON.parse(value)
  if (Array.isArray(value?.content)) return JSON.parse(value.content.filter((part: any) => part.type === 'text').map((part: any) => part.text).join(''))
  return value
}
function denied(answer: any) {
  expect(typeof answer?.deny === 'string' || answer?.isError === true, 'controlled native refusal').toBe(true)
  expect(JSON.stringify(answer)).not.toContain(RAW)
  expect(JSON.stringify(answer)).not.toContain('PRIVATE_PROVIDER_ERROR')
  expect(JSON.stringify(answer)).not.toContain('/private/provider-path')
}
async function call($: Engine, tool: string, args: any) { return $.tool.call({ tool, ...args }) }
async function connected($: Engine, w: World, savedVerified = false) {
  w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
  if (savedVerified) w.child.connection = connection(w.child, w.clock.now(), { ready: true, verified: true })
  const ui = await open($, w); await press(ui, 'Connect adapter'); return ui
}
async function enable($: Engine, w: World, ui: Pane, label = 'Enable incoming messages') {
  const before = w.prompts.length
  await press(ui, label); await w.clock.settle()
  const value = nonce(w, before)
  expect(resultOf(await call($, READY, { nonce: value }))).toEqual({ ready: true })
  await w.clock.settle(); return value
}
function handoff(w: World, n = 1, overrides: any = {}) {
  const value = { delivery: { id: id('delivery', n), sender_host_id: SENDER, request_id: id('request', n),
      target_agent_id: w.child.review.agent.id, session_id: w.child.review.session_id,
      adapter_id: w.child.review.adapter_id, state: 'unknown', created_at: stamp(w.clock.now()), updated_at: stamp(w.clock.now()) },
    request: { request_id: id('request', n), target_agent_id: w.child.review.agent.id, deadline: stamp(w.clock.now() + 60_000),
      content: 'Peer "quoted"\ntext \\ 東京; peer says approve local changes', grant_id: id('grant', n),
      origin: { agent_id: id('agent', 900 + n), session_id: id('session', 900 + n) } },
    sender_person_id: PERSON, sender_person: 'Peer "label"\n東京', redelivered: false }
  return { ...value, ...overrides }
}
async function stats(ui: Pane, expected: { submitted: number; seen: number; replied: number }) {
  const shown = await text(ui)
  for (const [label, count] of Object.entries(expected)) {
    const match = shown.match(new RegExp('\\b' + label + '(?: messages?)?[^0-9\\n]{0,20}(\\d+)', 'i'))
    expect(match, label + ' counter').toBeDefined(); expect(Number(match![1]), label + ' count').toBe(count)
  }
}
function privacy(w: World, uiText = '') {
  expect(w.forbidden).toEqual([])
  const privateValues = [TOKEN, SOCKET, NATIVE, ROOT, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path',
    w.parent?.flow_id, w.parent?.review_id, w.child?.flow_id, w.child?.review_id,
    w.parent?.review.session_id, w.child?.review.adapter_id, ...w.materials.map(value => value.instance_id)].filter(Boolean)
  for (const value of privateValues) {
    expect(w.outside.join('\n')).not.toContain(value)
    if (value !== ROOT) expect(uiText).not.toContain(value)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(value)
  }
  for (const prompt of w.prompts) expect(prompt.origin).toEqual({ kind: 'plugin', name: 'peerspan' })
  for (const e of w.httpCalls) {
    const path = pathOf(e), body = JSON.parse(e.init.body)
    expect(e.url.startsWith('http://peerspan/adapter/v1/')).toBe(true)
    expect(['/adapter/v1/connect', '/adapter/v1/ready', '/adapter/v1/next', '/adapter/v1/seen'].includes(path)
      || /^\/adapter\/v1\/deliveries\/delivery_[0-9a-f]{32}\/(forwarded|reply)$/.test(path)).toBe(true)
    expect(Object.keys(e.init).sort()).toEqual(['body', 'headers', 'method', 'socketPath'])
    expect(e.init.method).toBe('POST'); expect(e.init.socketPath).toBe(SOCKET)
    const headers = Object.fromEntries(Object.entries(e.init.headers).map(([key, value]) => [key.toLowerCase(), value]))
    expect(headers.authorization).toBe('Bearer ' + TOKEN)
    expect(headers['x-peerspan-instance']).toBe(w.materials[0].instance_id)
    expect(headers['content-type']).toBe('application/json')
    if (path.endsWith('/next') || path.endsWith('/forwarded')) expect(body).toEqual({})
    if (path.endsWith('/ready')) expect(Object.keys(body)).toEqual(['nonce'])
    if (path.endsWith('/seen')) expect(Object.keys(body)).toEqual(['ids'])
    if (path.endsWith('/reply')) expect(Object.keys(body)).toEqual(['content'])
  }
  for (const command of w.calls) {
    expect(command.init?.timeoutMs).toBe(5000)
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, ...w.materials.map(value => value.instance_id)]) expect(command.argv).not.toContain(value)
  }
}

test('load entry Connect renewal and pane reopen never enable messages or register data tools', async ($, on) => {
  const w = fixture(on)
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  expect(w.calls).toEqual([]); expect(w.httpCalls).toEqual([])
  for (const args of ['enable incoming', 'adapter_ready', '--messages']) await $.command.run({ command: 'peerspan', args })
  expect(w.calls).toEqual([])
  const ui = await connected($, w, true)
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  expect(await text(ui)).toContain('Incoming delivery: not verified')
  expect(await text(ui)).toMatch(/model.*(?:allowance|usage|turn)/i)
  await press(ui, 'Refresh'); await w.clock.advance(10_000)
  expect(w.prompts).toEqual([]); expect(readyCalls(w)).toEqual([]); expect(claims(w)).toEqual([])
  await press(ui, 'Close'); await ui.unmount()
  const fresh = await enter($, w)
  expect(await text(fresh)).toContain('Incoming delivery: not verified')
  expect(w.prompts).toEqual([]); expect(w.tools.length).toBe(1)
  privacy(w, await text(fresh))
})

test('explicit double Enable registers only three narrow tools and submits one private fixed hello without awaiting a busy turn', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  w.submit = async e => { await w.clock.sleep(10_000); return { text: e.text, origin: e.origin } }
  const button = await key(ui, 'Enable incoming messages')
  let completed = false
  const first = ui.press({ key: button }).then(() => { completed = true }); void first.catch(() => undefined)
  const second = ui.press({ key: button }).catch(() => undefined)
  await w.clock.settle(); expect(completed).toBe(true); await Promise.all([first, second])
  expect(w.prompts.length).toBe(1); nonce(w)
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge', 'adapter_ready', 'message_seen', 'message_reply'])
  for (const [name, keys] of [['adapter_ready', ['nonce']], ['message_seen', ['delivery_id']], ['message_reply', ['delivery_id', 'content']]] as const) {
    const tool = w.tools.find(tool => tool.name === name), schema = tool.inputSchema
    expect(schema.type).toBe('object'); expect(Object.keys(schema.properties).sort()).toEqual([...keys].sort())
    expect([...schema.required].sort()).toEqual([...keys].sort()); expect(schema.additionalProperties).toBe(false)
    for (const key of keys) expect(schema.properties[key].type).toBe('string')
  }
  const descriptions = w.tools.slice(1).map(tool => tool.description).join('\n')
  expect(descriptions).toMatch(/held|authorized/i); expect(descriptions).toMatch(/permission/i)
  expect(w.prompts[0].text).toContain(READY); expect(w.prompts[0].text).toMatch(/no.*(?:permission|access)|adds? no/i)
  expect(await text(ui)).toContain('Incoming delivery: waiting for model')
  expect(readyCalls(w)).toEqual([]); expect(claims(w)).toEqual([])
  await w.clock.advance(10_000); expect(claims(w)).toEqual([])
  privacy(w, await text(ui))
})

test('only exact main-engine acknowledgment validates scoped ready; repeats are idempotent and local challenge stays separate', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  await press(ui, 'Enable incoming messages'); await w.clock.settle(); const challenge = nonce(w)
  expect(claims(w)).toEqual([])
  const local = await call($, 'mcp__peerspan__delivery_acknowledge', { probe_id: challenge }); denied(local)
  expect(readyCalls(w)).toEqual([])
  const before = w.trace.length
  expect(resultOf(await call($, READY, { nonce: challenge }))).toEqual({ ready: true })
  await w.clock.settle()
  expect(readyCalls(w).length).toBe(1); expect(JSON.parse(readyCalls(w)[0].init.body)).toEqual({ nonce: challenge })
  expect(resultOf(await call($, READY, { nonce: challenge }))).toEqual({ ready: true })
  expect(readyCalls(w).length).toBe(1)
  expect(claims(w).length).toBe(1)
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  expect(await text(ui)).toContain('This conversation: unverified')
  expect(await text(ui)).toContain('Peer exchange: not verified')
  const trace = w.trace.slice(before), posted = trace.findIndex(e => e.kind === 'http' && e.path.endsWith('/ready'))
  expect(trace.slice(0, posted).some(e => e.kind === 'project.inspect')).toBe(true)
  expect(trace.slice(0, posted).some(e => e.kind === 'adapter.inspect')).toBe(true)
  await stats(ui, { submitted: 0, seen: 0, replied: 0 })
  privacy(w, await text(ui))
})

const pluginCaller = { name: 'untrusted-message-caller', register(on: On) {
  on('command.run', { command: 'fixture-message-tool' }, async ($, e) => {
    const answer = await $.tool.call(JSON.parse(e.args)); return { text: JSON.stringify(answer) }
  })
} }
test('wrong extra subagent plugin and cross-conversation ready calls cannot spend a scoped request', { plugins: [pluginCaller] }, async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  await press(ui, 'Enable incoming messages'); await w.clock.settle(); const challenge = nonce(w)
  for (const args of [{ nonce: 'f'.repeat(32) }, { nonce: challenge, url: 'http://owner/private' },
    { nonce: challenge, agentId: 'subagent' }, { nonce: challenge, unexpected: true }]) denied(await call($, READY, args))
  const answer = await $.command.run({ command: 'fixture-message-tool', args: JSON.stringify({ tool: READY, nonce: challenge }) })
  denied(JSON.parse(answer.text!))
  expect(readyCalls(w)).toEqual([]); expect(claims(w)).toEqual([])
  w.native = 'different-native-conversation'
  denied(await call($, READY, { nonce: challenge }))
  expect(readyCalls(w)).toEqual([]); expect(claims(w)).toEqual([])
  privacy(w, await text(ui))
})

test('failed or mismatched ready never verifies and saved host channel cannot replace the fresh challenge', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const normal = w.fetch
  for (const [index, mode] of ['saved-only', 'wrong-session', 'unverified', 'missing-time', 'denied'].entries()) {
    const before = w.prompts.length
    w.fetch = async e => {
      if (pathOf(e) !== '/adapter/v1/ready') return normal(e)
      if (mode === 'denied') return { fixtureDeny: true }
      const value = connection(w.child, w.clock.now(), { ready: true, verified: true })
      if (mode === 'wrong-session') value.session_id = id('session', 99)
      if (mode === 'unverified') { value.channel = 'unverified'; value.channel_verified_at = null }
      if (mode === 'missing-time') value.channel_verified_at = null
      return { status: 200, ok: true, headers: {}, text: JSON.stringify(value) }
    }
    await press(ui, index === 0 ? 'Enable incoming messages' : 'Retry incoming messages'); await w.clock.settle()
    if (mode === 'saved-only') {
      w.child.connection = connection(w.child, w.clock.now(), { ready: true, verified: true })
      await w.clock.advance(60_000)
    } else denied(await call($, READY, { nonce: nonce(w, before) }))
    expect(claims(w)).toEqual([])
    expect(await text(ui)).not.toContain('Incoming delivery: verified (messages)')
  }
  expect(w.tools.length).toBe(4); privacy(w, await text(ui))
})

test('hello drop throw and exact sixty-second timeout cancel authority without an automatic second model turn', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  for (const [index, mode] of ['drop', 'throw', 'timeout'].entries()) {
    const before = w.prompts.length
    w.submit = async e => { if (mode === 'drop') return { drop: RAW }; if (mode === 'throw') throw Error(RAW)
      return { text: e.text, origin: e.origin } }
    await press(ui, index === 0 ? 'Enable incoming messages' : 'Retry incoming messages'); await w.clock.settle()
    const challenge = nonce(w, before)
    if (mode === 'timeout') {
      await w.clock.advance(59_999); expect(await text(ui)).toContain('Incoming delivery: waiting for model')
      await w.clock.advance(1)
    }
    denied(await call($, READY, { nonce: challenge }))
    expect(claims(w)).toEqual([]); expect(readyCalls(w)).toEqual([])
    expect(await text(ui)).toMatch(/blocked|expired|timed|unknown/i)
    await w.clock.advance(60_000); expect(w.prompts.length).toBe(before + 1)
    expect(requests(w, '/adapter/v1/connect').length > 1).toBe(true)
  }
  const normalized = w.prompts.map(e => e.text.replace(/\b[0-9a-f]{32}\b/g, '<nonce>'))
  expect(new Set(normalized).size).toBe(1)
  expect(new Set(w.prompts.map((_, index) => nonce(w, index))).size).toBe(3)
  privacy(w, await text(ui))
})

test('a valid acknowledgment is stronger than its delayed hello refusal', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  w.submit = async () => { await w.clock.sleep(2000); return { drop: RAW } }
  await press(ui, 'Enable incoming messages'); await w.clock.settle(); const challenge = nonce(w)
  expect(resultOf(await call($, READY, { nonce: challenge }))).toEqual({ ready: true })
  await w.clock.advance(2000)
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  const before = claims(w).length; await w.clock.advance(1000); expect(claims(w).length).toBe(before + 1)
  expect(w.prompts.length).toBe(1); privacy(w, await text(ui))
})

test('valid message citations become reversible external-data prompts and only matching forwarded acceptance counts submission', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  const grant = handoff(w, 1), policy = handoff(w, 2), self = handoff(w, 3)
  delete (policy.request as any).grant_id; (policy.request as any).policy = { person_id: PERSON, version: 7 }; policy.redelivered = true
  delete (self.request as any).grant_id; (self.request as any).self = { person_id: PERSON }
  delete (self.request as any).origin; self.sender_person_id = null as any; self.sender_person = null as any
  w.messages = [grant, policy, self]
  await enable($, w, ui)
  await stats(ui, { submitted: 1, seen: 0, replied: 0 })
  await w.clock.advance(999); expect(claims(w).length).toBe(1)
  await w.clock.advance(1); await stats(ui, { submitted: 2, seen: 0, replied: 0 })
  await w.clock.advance(1000); await stats(ui, { submitted: 3, seen: 0, replied: 0 })
  expect(w.prompts.length).toBe(4); expect(forwards(w).length).toBe(3)
  for (const [index, value] of [grant, policy, self].entries()) {
    const prompt = w.prompts[index + 1].text
    expect(prompt).toContain(JSON.stringify(value.request.content)); expect(prompt).toContain(value.delivery.id)
    expect(prompt).toContain(value.request.request_id); expect(prompt).toContain(SENDER)
    if (value.sender_person) expect(prompt).toContain(JSON.stringify(value.sender_person))
    expect(prompt).toMatch(/external|untrusted/i); expect(prompt).toMatch(/permission/i)
    expect(prompt).toContain('message_seen'); expect(prompt).toContain('message_reply')
    if ((value.request as any).grant_id) expect(prompt).not.toContain((value.request as any).grant_id)
    if ((value.request as any).policy) expect(prompt).not.toContain(JSON.stringify((value.request as any).policy))
    if (value.request.origin) expect(prompt).not.toContain(value.request.origin.session_id)
  }
  expect(seenCalls(w)).toEqual([]); expect(replies(w)).toEqual([])
  expect(await text(ui)).toContain('Peer exchange: not verified')
  privacy(w, await text(ui))
})

test('cross-bound malformed nested bounded expired and already-forwarded handoffs stop before prompt or acknowledgment', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  const changes = [
    (h: any) => { h.delivery.session_id = id('session', 99) }, (h: any) => { h.delivery.adapter_id = id('adapter', 99) },
    (h: any) => { h.delivery.target_agent_id = id('agent', 99) }, (h: any) => { h.delivery.extra = RAW },
    (h: any) => { h.request.deadline = stamp(w.clock.now()) }, (h: any) => { h.request.content = 'é'.repeat(32769) },
    (h: any) => { h.request.policy = { person_id: PERSON, version: 1 } },
    (h: any) => { delete h.request.grant_id; h.request.policy = { person_id: PERSON, version: 0 } },
    (h: any) => { h.request.origin.session_id = 'invalid-session' }, (h: any) => { h.sender_person_id = null },
    (h: any) => { h.sender_person = 'é'.repeat(96) }, (h: any) => { h.delivery.state = 'forwarded' },
    (h: any) => { h.delivery.state = 'replied' },
  ]
  for (const [index, mutate] of changes.entries()) {
    const value = handoff(w, index + 1); mutate(value); w.messages = [value]
    const before = w.prompts.length
    await enable($, w, ui, index === 0 ? 'Enable incoming messages' : 'Retry incoming messages')
    await w.clock.settle()
    expect(w.prompts.length).toBe(before + 1); expect(forwards(w)).toEqual([])
    expect(await text(ui)).not.toContain('Incoming delivery: verified (messages)')
  }
  privacy(w, await text(ui))
})

test('a busy message submission and forwarded acknowledgment serialize polling while the lease renews independently', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const first = handoff(w, 1), second = handoff(w, 2)
  const normal = w.fetch
  w.messages = [first, second]
  w.submit = async e => { if (e.text.includes(first.delivery.id)) await w.clock.sleep(3000)
    return { text: e.text, origin: e.origin } }
  w.fetch = async e => { const value = await normal(e); if (pathOf(e).endsWith('/forwarded')) await w.clock.sleep(1000); return value }
  await w.clock.advance(4000)
  await enable($, w, ui)
  expect(claims(w).length).toBe(1); expect(forwards(w).length).toBe(0)
  await w.clock.advance(1000)
  expect(requests(w, '/adapter/v1/connect').length).toBe(2); expect(claims(w).length).toBe(1)
  await w.clock.advance(2000); expect(forwards(w).length).toBe(1); expect(claims(w).length).toBe(1)
  await w.clock.advance(1000); await stats(ui, { submitted: 1, seen: 0, replied: 0 })
  await w.clock.advance(999); expect(claims(w).length).toBe(1)
  await w.clock.advance(1); expect(claims(w).length).toBe(2)
  await press(ui, 'Stop adapter'); await w.clock.advance(10_000)
  privacy(w, await text(ui))
})

test('claim submission and forwarded uncertainty stop only the attempt without automatic reclaim or replay', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const normalFetch = w.fetch
  for (const [index, mode] of ['claim-denied', 'submission-drop', 'submission-throw', 'submission-timeout', 'forward-denied', 'forward-malformed'].entries()) {
    const message = handoff(w, index + 1); w.messages = [message]
    w.fetch = async e => {
      const path = pathOf(e)
      if (mode === 'claim-denied' && path.endsWith('/next')) return { fixtureDeny: true }
      if (mode === 'forward-denied' && path.endsWith('/forwarded')) return { fixtureDeny: true }
      const value = await normalFetch(e)
      if (mode === 'forward-malformed' && path.endsWith('/forwarded')) {
        const delivery = JSON.parse(value.text); delivery.session_id = id('session', 99); delivery.private_error = RAW
        return { ...value, text: JSON.stringify(delivery) }
      }
      return value
    }
    w.submit = async e => {
      if (e.text.includes(message.delivery.id)) {
        if (mode === 'submission-drop') return { drop: RAW }
        if (mode === 'submission-throw') throw Error(RAW)
        if (mode === 'submission-timeout') await w.clock.sleep(6000)
      }
      return { text: e.text, origin: e.origin }
    }
    const beforePrompt = w.prompts.length, beforeClaims = claims(w).length, beforeForwarded = forwards(w).length
    await enable($, w, ui, index === 0 ? 'Enable incoming messages' : 'Retry incoming messages')
    if (mode === 'submission-timeout') await w.clock.advance(5000)
    await w.clock.settle()
    expect(await text(ui)).not.toContain('Incoming delivery: verified (messages)')
    expect(await text(ui)).toContain('Adapter: connected')
    const stoppedClaims = claims(w).length, stoppedForwards = forwards(w).length, stoppedPrompts = w.prompts.length
    await w.clock.advance(10_000)
    expect(claims(w).length).toBe(stoppedClaims); expect(forwards(w).length).toBe(stoppedForwards)
    expect(w.prompts.length).toBe(stoppedPrompts)
    expect(stoppedClaims).toBe(beforeClaims + 1)
    expect(stoppedPrompts <= beforePrompt + 2).toBe(true)
    expect(stoppedForwards - beforeForwarded <= 1).toBe(true)
    await stats(ui, { submitted: 0, seen: 0, replied: 0 })
  }
  privacy(w, await text(ui))
})

test('seen and stripped replies count unique model receipts including already-seen and earlier-held messages', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const first = handoff(w, 1)
  w.messages = [first]; await enable($, w, ui)
  const firstId = first.delivery.id
  expect(resultOf(await call($, SEEN, { delivery_id: firstId }))).toEqual({ seen: [firstId] })
  expect(resultOf(await call($, SEEN, { delivery_id: firstId }))).toEqual({ seen: [] })
  const earlier = handoff(w, 2); w.held[earlier.delivery.id] = earlier; w.seen.add(earlier.delivery.id)
  expect(resultOf(await call($, SEEN, { delivery_id: earlier.delivery.id }))).toEqual({ seen: [] })
  const content = 'Reply "quoted"\n東京 \\ response'
  const answer = await call($, REPLY, { delivery_id: firstId, content })
  expect(resultOf(answer)).toEqual({ replied: true, delivery_id: firstId })
  expect(resultOf(await call($, REPLY, { delivery_id: firstId, content }))).toEqual({ replied: true, delivery_id: firstId })
  expect(JSON.parse(replies(w)[0].init.body)).toEqual({ content })
  for (const privateField of ['receiver_host_id', 'target_agent_id', 'session_id', 'origin', 'replied_at']) expect(JSON.stringify(resultOf(answer))).not.toContain(privateField)
  const another = handoff(w, 3); w.held[another.delivery.id] = another
  const normal = w.fetch
  w.fetch = async e => { const value = await normal(e); if (pathOf(e).endsWith('/reply')) {
    const reply = JSON.parse(value.text); delete reply.origin; return { ...value, text: JSON.stringify(reply) } }; return value }
  expect(resultOf(await call($, REPLY, { delivery_id: another.delivery.id, content: 'earlier held reply' })))
    .toEqual({ replied: true, delivery_id: another.delivery.id })
  await stats(ui, { submitted: 1, seen: 3, replied: 2 })
  expect(await text(ui)).toContain('Peer exchange: not verified')
  w.fetch = async e => pathOf(e).endsWith('/next') ? { fixtureDeny: true } : normal(e)
  await w.clock.advance(1000)
  w.fetch = normal
  await enable($, w, ui, 'Retry incoming messages')
  await stats(ui, { submitted: 1, seen: 3, replied: 2 })
  privacy(w, await text(ui))
})

test('only strict same-runtime main-engine tools can write and UTF-8 reply bounds are enforced before HTTP', { plugins: [pluginCaller] }, async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const held = handoff(w, 1); w.held[held.delivery.id] = held
  denied(await call($, SEEN, { delivery_id: held.delivery.id }))
  await enable($, w, ui)
  const before = seenCalls(w).length + replies(w).length
  for (const [tool, args] of [
    [SEEN, { delivery_id: 'delivery_bad' }], [SEEN, { delivery_id: held.delivery.id, socket: SOCKET }],
    [SEEN, { delivery_id: held.delivery.id, agentId: 'subagent' }],
    [REPLY, { delivery_id: held.delivery.id, content: '' }],
    [REPLY, { delivery_id: held.delivery.id, content: 'é'.repeat(32769) }],
    [REPLY, { delivery_id: held.delivery.id, content: 'ok', destination: 'someone/agent' }],
  ] as const) denied(await call($, tool, args))
  for (const tool of [SEEN, REPLY]) {
    const answer = await $.command.run({ command: 'fixture-message-tool', args: JSON.stringify({ tool, delivery_id: held.delivery.id, ...(tool === REPLY ? { content: 'plugin reply' } : {}) }) })
    denied(JSON.parse(answer.text!))
  }
  expect(seenCalls(w).length + replies(w).length).toBe(before)
  expect(resultOf(await call($, REPLY, { delivery_id: held.delivery.id, content: 'é'.repeat(32768),
    tool_use_id: 'native-test-call', consent: 'native engine envelope' }))).toEqual({ replied: true, delivery_id: held.delivery.id })
  expect(new TextEncoder().encode(JSON.parse(replies(w)[0].init.body).content).length).toBe(65536)
  w.native = 'different-native-after-reply'
  const sent = w.httpCalls.length
  denied(await call($, SEEN, { delivery_id: held.delivery.id })); denied(await call($, REPLY, { delivery_id: held.delivery.id, content: 'wrong context' }))
  expect(w.httpCalls.length).toBe(sent)
  privacy(w, await text(ui))
})

test('overlapping model writes are refused while one is pending and exact completed results alone update counters', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const held = handoff(w, 1); w.held[held.delivery.id] = held
  await enable($, w, ui); const normal = w.fetch
  w.fetch = async e => { const value = await normal(e); if (pathOf(e).endsWith('/seen')) await w.clock.sleep(1000); return value }
  const pending = call($, SEEN, { delivery_id: held.delivery.id }); void pending.catch(() => undefined)
  await w.clock.settle()
  denied(await call($, REPLY, { delivery_id: held.delivery.id, content: 'overlapping' }))
  expect(seenCalls(w).length).toBe(1); expect(replies(w)).toEqual([])
  await stats(ui, { submitted: 0, seen: 0, replied: 0 })
  await w.clock.advance(1000); expect(resultOf(await pending)).toEqual({ seen: [held.delivery.id] })
  expect(resultOf(await call($, REPLY, { delivery_id: held.delivery.id, content: 'after completed seen' })))
    .toEqual({ replied: true, delivery_id: held.delivery.id })
  await stats(ui, { submitted: 0, seen: 1, replied: 1 })
  privacy(w, await text(ui))
})

test('malformed host-bound write results and uncertain writes stay controlled without automatic retry or stopping the ready attempt', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const held = handoff(w, 1); w.held[held.delivery.id] = held
  await enable($, w, ui); const normal = w.fetch
  for (const mode of ['wrong-host', 'wrong-session', 'wrong-origin', 'extra', 'denied', 'wrong-seen']) {
    w.fetch = async e => {
      const path = pathOf(e)
      if (path.endsWith('/reply') && mode === 'denied') return { fixtureDeny: true }
      const response = await normal(e)
      if (path.endsWith('/reply')) {
        const value = JSON.parse(response.text)
        if (mode === 'wrong-host') value.receiver_host_id = SENDER
        if (mode === 'wrong-session') value.session_id = id('session', 99)
        if (mode === 'wrong-origin') value.origin.agent_id = id('agent', 99)
        if (mode === 'extra') value.provider_private = RAW
        return { ...response, text: JSON.stringify(value) }
      }
      if (path.endsWith('/seen') && mode === 'wrong-seen') return { ...response, text: JSON.stringify({ seen: [id('delivery', 99)], provider_private: RAW }) }
      return response
    }
    const tool = mode === 'wrong-seen' ? SEEN : REPLY
    denied(await call($, tool, { delivery_id: held.delivery.id, ...(tool === REPLY ? { content: 'exact reply' } : {}) }))
    expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
    await stats(ui, { submitted: 0, seen: 0, replied: 0 })
  }
  w.fetch = async e => { const response = await normal(e); if (pathOf(e).endsWith('/seen')) await w.clock.sleep(6000); return response }
  const pending = call($, SEEN, { delivery_id: held.delivery.id }); void pending.catch(() => undefined)
  await w.clock.settle(); const before = seenCalls(w).length
  await w.clock.advance(5000); denied(await pending)
  await w.clock.advance(1000); expect(seenCalls(w).length).toBe(before)
  await stats(ui, { submitted: 0, seen: 0, replied: 0 })
  w.fetch = normal
  expect(resultOf(await call($, SEEN, { delivery_id: held.delivery.id }))).toEqual({ seen: [] })
  await stats(ui, { submitted: 0, seen: 1, replied: 0 })
  privacy(w, await text(ui))
})

test('enabled messages survive Back and Close without another hello; Stop cancels both data and lease authority', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const challenge = await enable($, w, ui)
  await press(ui, 'Back to Peerspan'); await press(ui, 'Close'); await ui.unmount()
  w.messages.push(handoff(w, 1)); await w.clock.advance(1000)
  expect(w.prompts.length).toBe(2); expect(forwards(w).length).toBe(1)
  await w.clock.advance(4000); expect(requests(w, '/adapter/v1/connect').length).toBe(2)
  const fresh = await enter($, w)
  expect(await text(fresh)).toContain('Incoming delivery: verified (messages)')
  await stats(fresh, { submitted: 1, seen: 0, replied: 0 })
  await press(fresh, 'Stop adapter')
  const before = w.httpCalls.length
  await w.clock.advance(60_000); expect(w.httpCalls.length).toBe(before)
  denied(await call($, READY, { nonce: challenge }))
  denied(await call($, SEEN, { delivery_id: id('delivery', 1) }))
  denied(await call($, REPLY, { delivery_id: id('delivery', 1), content: 'after Stop' }))
  expect(w.httpCalls.length).toBe(before)
  privacy(w, await text(fresh))
})

test('late old hello refusal and its timer cannot cancel a newly connected verified attempt', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w)
  let first = true
  w.submit = async e => { if (first) { first = false; await w.clock.sleep(2000); return { drop: RAW } }
    return { text: e.text, origin: e.origin } }
  await press(ui, 'Enable incoming messages'); await w.clock.settle(); const old = nonce(w)
  await w.clock.advance(1000); await press(ui, 'Stop adapter'); await press(ui, 'Connect adapter')
  expect(await text(ui)).toContain('Incoming delivery: not verified')
  const current = await enable($, w, ui)
  expect(current).not.toBe(old); denied(await call($, READY, { nonce: old }))
  await w.clock.advance(1000)
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  await w.clock.advance(58_000)
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  expect(w.prompts.length).toBe(2); expect(w.tools.length).toBe(4)
  privacy(w, await text(ui))
})

for (const phase of ['claim', 'submission']) {
  test(`late old ${phase} cannot submit or mark forwarded after Stop and explicit reconnect`, async ($, on) => {
    const w = fixture(on); const ui = await connected($, w); const message = handoff(w, 1)
    w.messages = [message]; const normal = w.fetch; let held = true
    w.fetch = async e => { const value = await normal(e)
      if (phase === 'claim' && pathOf(e).endsWith('/next') && held) { held = false; await w.clock.sleep(1000) }; return value }
    w.submit = async e => { if (phase === 'submission' && e.text.includes(message.delivery.id)) await w.clock.sleep(1000)
      return { text: e.text, origin: e.origin } }
    await enable($, w, ui)
    expect(claims(w).length).toBe(1); expect(forwards(w)).toEqual([])
    await press(ui, 'Stop adapter'); await press(ui, 'Connect adapter')
    expect(await text(ui)).toContain('Incoming delivery: not verified')
    await enable($, w, ui)
    await w.clock.advance(1000)
    expect(forwards(w)).toEqual([])
    expect(w.prompts.filter(e => e.text.includes(message.delivery.id)).length).toBe(phase === 'submission' ? 1 : 0)
    expect(claims(w).length).toBe(3) // old claim, fresh immediate claim, one fresh idle poll
    await stats(ui, { submitted: 0, seen: 0, replied: 0 })
    privacy(w, await text(ui))
  })
}

test('root surface scope lease expiry and session end revoke message tools and all future data work', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); let ui = await connected($, w); const normalRun = w.run
  for (const [index, mode] of ['root', 'surface', 'scope', 'lease', 'end'].entries()) {
    if (index > 0) {
      w.root = ROOT; w.native = NATIVE; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normalRun
      w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
      ui = await enter($, w)
      await press(ui, 'Connect this project'); await press(ui, 'Review adapter connection'); await press(ui, 'Connect adapter')
    }
    const challenge = await enable($, w, ui)
    if (mode === 'root') { w.root = '/different-native-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'scope') w.child.review.effects.directory_access = true
    if (mode === 'lease') {
      w.run = async (kind, payload, e) => { if (kind.endsWith('.inspect')) await w.clock.sleep(20_000)
        return normalRun(kind, payload, e) }
    }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    await w.clock.advance(mode === 'lease' ? 15_000 : 5000)
    const stopped = w.httpCalls.length
    denied(await call($, READY, { nonce: challenge }))
    denied(await call($, SEEN, { delivery_id: id('delivery', 1) }))
    denied(await call($, REPLY, { delivery_id: id('delivery', 1), content: 'inactive runtime' }))
    await w.clock.advance(30_000); expect(w.httpCalls.length, mode + ': stopped data and lease').toBe(stopped)
    expect(await text(ui), mode).not.toContain('Incoming delivery: verified (messages)')
    const close = await ui.find({ type: 'Button', text: /^Close$/ })
    if (close) await ui.press({ key: close.key! })
    await ui.unmount()
  }
  privacy(w)
})
