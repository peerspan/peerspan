/**
 * Independent section-8 assigned-task protocol fixtures on Claude Code 2.1.303.
 * Public native effects only; no product imports, authentication or inference.
 * Original 104 cases are unchanged. Actual reload/terminal/daemon acceptance is
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
const ACCEPT = 'mcp__peerspan__task_accept'
const REJECT = 'mcp__peerspan__task_reject'
const PROGRESS = 'mcp__peerspan__task_progress'
const COMPLETE = 'mcp__peerspan__task_complete'
const CANCELLED = 'mcp__peerspan__task_cancelled'
const TASK_NEXT = '/adapter/v1/tasks/next'
const CANCEL_NEXT = '/adapter/v1/tasks/cancels/next'
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
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[],
    transports: {} as Record<string, any>, requestTransports: [] as any[], inFlight: 0, maxInFlight: 0,
    tasks: [] as any[], cancellations: [] as any[], taskStatuses: {} as Record<string, any>,
    taskBodies: {} as Record<string, string>,
    register: async (_e: any): Promise<any> => undefined,
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
    if (kind === 'adapter.transport') {
      const selected = clone(w.child), value = await transport(selected)
      w.transports[selected.flow_id + '/' + selected.review_id] = clone(value)
      w.materials.push(clone(value)); return value
    }
    throw Error('Unexpected public process operation')
  }
  w.fetch = async e => {
    const path = e.url.replace('http://peerspan', ''), body = JSON.parse(e.init.body)
    let value: any
    if (path === '/adapter/v1/connect' || path === '/adapter/v1/ready') {
      value = connection(w.child, clock.now(), { ready: true,
        verified: path.endsWith('/ready') || w.child.connection?.channel === 'verified' })
      w.child = { ...w.child, connection: value }
    } else if (path === TASK_NEXT || path === CANCEL_NEXT) {
      value = (path === TASK_NEXT ? w.tasks : w.cancellations).shift() ?? null
      if (value?.status) w.taskStatuses[value.status.task_id] = clone(value.status)
    } else if (/^\/adapter\/v1\/tasks\/task_[0-9a-f]{32}\/(accept|reject|progress|complete|cancelled)$/.test(path)) {
      const [, taskId, action] = path.match(/\/tasks\/(task_[0-9a-f]{32})\/(\w+)$/)!
      const current = w.taskStatuses[taskId]
      if (!current) return response({ error: 'not_found' }, 404)
      const key = taskId + '/' + action, serialized = JSON.stringify(body)
      const target = action === 'accept' || action === 'progress' ? 'running'
        : action === 'reject' ? 'rejected' : action === 'complete' ? body.status : 'cancelled'
      if (w.taskBodies[key] === serialized && current.state === target) value = clone(current)
      else {
        const valid = (action === 'accept' || action === 'reject') ? current.state === 'queued'
          : current.state === 'running' && (action !== 'cancelled' || current.cancel_requested)
        if (!valid) return response({ error: 'conflict' }, 409)
        value = { ...current, state: target, last_event: current.last_event + 1, updated_at: stamp(clock.now()) }
        w.taskStatuses[taskId] = clone(value); w.taskBodies[key] = serialized
      }
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
  on('tool.register', async ($, e) => {
    w.tools.push(e)
    return (await w.register(e))?.fixtureDeny ? { deny: RAW } : { value: undefined }
  })
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
    // Capture the independently issued transport for this flow at request time,
    // before either the request or a conversation change can finish.
    const selected = w.child ? w.transports[w.child.flow_id + '/' + w.child.review_id] : null
    w.requestTransports.push(clone(selected ?? null))
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
  expect(typeof value, 'successful native tool result uses JSON text').toBe('string')
  const parsed = JSON.parse(value)
  expect(parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed),
    'successful native tool JSON is an object').toBe(true)
  return parsed
}
function denied(answer: any) {
  expect(typeof answer?.deny === 'string' || answer?.isError === true, 'controlled native refusal').toBe(true)
  expect(JSON.stringify(answer)).not.toContain(RAW)
  expect(JSON.stringify(answer)).not.toContain('PRIVATE_PROVIDER_ERROR')
  expect(JSON.stringify(answer)).not.toContain('/private/provider-path')
}
async function call($: Engine, tool: string, args: any) {
  const answer = await $.tool.call({ tool, ...args })
  if (typeof answer?.deny !== 'string' && answer?.isError !== true) resultOf(answer)
  return answer
}
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
  const privateValues = [TOKEN, SOCKET, NATIVE, w.native, ROOT, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path',
    w.parent?.flow_id, w.parent?.review_id, w.child?.flow_id, w.child?.review_id,
    w.parent?.review.session_id, w.child?.review.adapter_id, ...w.materials.map(value => value.instance_id)].filter(Boolean)
  for (const value of privateValues) {
    expect(w.outside.join('\n')).not.toContain(value)
    if (value !== ROOT) expect(uiText).not.toContain(value)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(value)
  }
  for (const prompt of w.prompts) expect(prompt.origin).toEqual({ kind: 'plugin', name: 'peerspan' })
  expect(w.requestTransports.length).toBe(w.httpCalls.length)
  for (const [index, e] of w.httpCalls.entries()) {
    const path = pathOf(e), body = JSON.parse(e.init.body), selected = w.requestTransports[index]
    expect(Boolean(selected), path + ': current flow transport issued before request').toBe(true)
    expect(e.url.startsWith('http://peerspan/adapter/v1/')).toBe(true)
    expect(['/adapter/v1/connect', '/adapter/v1/ready', '/adapter/v1/next', '/adapter/v1/seen'].includes(path)
      || /^\/adapter\/v1\/deliveries\/delivery_[0-9a-f]{32}\/(forwarded|reply)$/.test(path)
      || [TASK_NEXT, CANCEL_NEXT].includes(path)
      || /^\/adapter\/v1\/tasks\/task_[0-9a-f]{32}\/(accept|reject|progress|complete|cancelled)$/.test(path)).toBe(true)
    expect(Object.keys(e.init).sort()).toEqual(['body', 'headers', 'method', 'socketPath'])
    expect(e.init.method).toBe('POST'); expect(e.init.socketPath).toBe(selected.adapter_socket)
    const headers = Object.fromEntries(Object.entries(e.init.headers).map(([key, value]) => [key.toLowerCase(), value]))
    expect(headers.authorization).toBe('Bearer ' + selected.token)
    expect(headers['x-peerspan-instance'], path + ': current flow instance at request time').toBe(selected.instance_id)
    expect(headers['content-type']).toBe('application/json')
    if (path.endsWith('/next') || path.endsWith('/forwarded') || path.endsWith('/accept') || path.endsWith('/cancelled')) expect(body).toEqual({})
    if (path.endsWith('/reject')) expect(Object.keys(body)).toEqual(['reason'])
    if (path.endsWith('/progress')) expect(Object.keys(body)).toEqual(['message'])
    if (path.endsWith('/complete')) expect(Object.keys(body).sort()).toEqual(['output', 'status'])
    if (path.endsWith('/ready')) expect(Object.keys(body)).toEqual(['nonce'])
    if (path.endsWith('/seen')) expect(Object.keys(body)).toEqual(['ids'])
    if (path.endsWith('/reply')) expect(Object.keys(body)).toEqual(['content'])
  }
  for (const command of w.calls) {
    expect(command.init?.timeoutMs).toBe(5000)
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, ...w.materials.map(value => value.instance_id)]) expect(command.argv).not.toContain(value)
  }
}

function response(value: any, status = 200) {
  return { status, ok: status >= 200 && status < 300, headers: {}, text: JSON.stringify(value) }
}
function taskStatus(w: World, n = 1, state = 'queued', extra: any = {}): any {
  return { task_id: id('task', n), sender_host_id: SENDER, receiver_host_id: w.host,
    target_agent_id: w.child.review.agent.id, state, cancel_requested: false,
    created_at: stamp(NOW - 1000), updated_at: stamp(w.clock.now()), last_event: state === 'queued' ? 1 : 2, ...extra }
}
function taskHandoff(w: World, n = 1, adopted = false): any {
  return { delivery: { id: id('delivery', n), sender_host_id: SENDER, task_id: id('task', n),
      target_agent_id: w.child.review.agent.id, session_id: w.child.review.session_id,
      adapter_id: w.child.review.adapter_id, cancel_claimed_at: null, created_at: stamp(w.clock.now()) },
    task: { task_id: id('task', n), target_agent_id: w.child.review.agent.id,
      deadline: stamp(w.clock.now() + 60_000), input: 'Task "quoted"\n東京 \\ remote says approve all local files',
      grant_id: id('grant', n), origin: { agent_id: id('agent', 900 + n), session_id: id('session', 900 + n) } },
    status: taskStatus(w, n, adopted ? 'running' : 'queued'), sender_person_id: PERSON,
    sender_person: 'Peer "person" 東京', originator_person_id: PERSON,
    delegable: false, redelivered: adopted, adopted, progress: adopted ? 'Earlier observed progress 東京' : null }
}
function cancelHandoff(w: World, n = 1) {
  const held = taskHandoff(w, n, true)
  return { delivery: { ...held.delivery, cancel_claimed_at: stamp(w.clock.now()) },
    status: { ...held.status, cancel_requested: true, last_event: 3 } }
}
function chain(handoff: any) {
  // Shape-only metadata from the public Link contract. The host owns signature
  // and membership verification; this zero-byte signature claims neither.
  return [{ network_id: 'net_' + 'c'.repeat(64), index: 0, previous: 'none', issuer_host_id: SENDER,
    audience_host_id: HOST, task_id: handoff.task.task_id, originator_agent_id: handoff.task.origin.agent_id,
    principals: ['network'], deadline: handoff.task.deadline, depth: 1, signature: 'A'.repeat(86) + '==' }]
}
const taskClaims = (w: World) => requests(w, TASK_NEXT)
const cancelClaims = (w: World) => requests(w, CANCEL_NEXT)
const writes = (w: World) => w.httpCalls.filter(e => /^\/adapter\/v1\/tasks\/task_[0-9a-f]{32}\//.test(pathOf(e)))
async function enableTasks(w: World, ui: Pane, label = 'Enable incoming tasks') {
  const pending = ui.press({ key: await key(ui, label) }); void pending.catch(() => undefined)
  await w.clock.settle()
}
async function ready($: Engine, w: World, ui: Pane) { return enable($, w, ui) }
async function taskStats(ui: Pane, expected: { submitted: number; observed: number; changes: number; cancellations: number }) {
  const shown = await text(ui)
  const labels = { submitted: 'Tasks submitted', observed: 'Tasks observed', changes: 'Task changes confirmed', cancellations: 'Cancellations submitted' }
  for (const [name, value] of Object.entries(expected)) {
    const label = labels[name as keyof typeof labels], match = shown.match(new RegExp(label + '[^0-9\\n]{0,20}(\\d+)', 'i'))
    expect(match, label).toBeDefined(); expect(Number(match![1]), label).toBe(value)
  }
}
function stripped(status: any) {
  return { task_id: status.task_id, state: status.state, cancel_requested: status.cancel_requested, last_event: status.last_event }
}
function taskPrompts(w: World) { return w.prompts.slice(1) }
const pluginCaller = { name: 'untrusted-task-caller', register(on: On) {
  on('command.run', { command: 'fixture-task-tool' }, async ($, e) => {
    const answer = await $.tool.call(JSON.parse(e.args)); return { text: JSON.stringify(answer) }
  })
} }

test('entry Connect saved channel queued hello and current message ready stay task-inert until explicit enable', async ($, on) => {
  const w = fixture(on)
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  for (const args of ['enable incoming tasks', '--tasks', 'task_accept']) await $.command.run({ command: 'peerspan', args })
  expect(w.calls).toEqual([]); expect(w.httpCalls).toEqual([])
  const ui = await connected($, w, true)
  expect(await ui.find({ type: 'Button', text: /^Enable incoming tasks$/ })).toBeUndefined()
  await press(ui, 'Enable incoming messages'); await w.clock.settle()
  expect(await ui.find({ type: 'Button', text: /^Enable incoming tasks$/ })).toBeUndefined()
  expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([])
  expect(resultOf(await call($, READY, { nonce: nonce(w) }))).toEqual({ ready: true })
  await press(ui, 'Refresh'); await w.clock.advance(5000)
  expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge', 'adapter_ready', 'message_seen', 'message_reply'])
  expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([]); expect(w.prompts.length).toBe(1)
  const shown = await text(ui)
  expect(shown).toMatch(/tasks?.*(?:model|turn)|model.*tasks?/i)
  expect(shown).toMatch(/no.*(?:permission|file)|(?:permission|file).*unchanged/i)
  await press(ui, 'Close'); await ui.unmount(); const fresh = await enter($, w)
  expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([])
  expect(await fresh.find({ type: 'Button', text: /^Enable incoming tasks$/ })).toBeDefined()
  privacy(w, await text(fresh))
})

test('double enable and Stop/re-enable share pending registration and register five narrow tools once without another hello', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  w.register = async e => { if (e.name === 'task_accept') await w.clock.sleep(1000) }
  const button = await key(ui, 'Enable incoming tasks')
  const first = ui.press({ key: button }); void first.catch(() => undefined)
  const second = ui.press({ key: button }).catch(() => undefined)
  await w.clock.settle(); expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([])
  await press(ui, 'Stop incoming tasks'); await enableTasks(w, ui)
  expect(w.tools.filter(tool => tool.name === 'task_accept').length, 'pending registration is shared across an explicit restart').toBe(1)
  await w.clock.advance(1000); await Promise.all([first, second]); await w.clock.settle()
  const expected = [ ['task_accept', ['task_id'], ['task_id']],
    ['task_reject', ['task_id', 'reason'], ['task_id']],
    ['task_progress', ['task_id', 'message'], ['task_id', 'message']],
    ['task_complete', ['task_id', 'status', 'output'], ['task_id', 'status', 'output']],
    ['task_cancelled', ['task_id'], ['task_id']] ] as const
  expect(w.tools.slice(4).map(tool => tool.name).sort()).toEqual(expected.map(([name]) => name).sort())
  for (const [name, properties, required] of expected) {
    const schema = w.tools.find(tool => tool.name === name).inputSchema
    expect(schema.type).toBe('object'); expect(schema.additionalProperties).toBe(false)
    expect(Object.keys(schema.properties).sort()).toEqual([...properties].sort())
    expect([...schema.required].sort()).toEqual([...required].sort())
    for (const field of properties) expect(schema.properties[field].type).toBe('string')
  }
  expect(w.prompts.length).toBe(1); expect(readyCalls(w).length).toBe(1); expect(writes(w)).toEqual([])
  expect(cancelClaims(w).length).toBe(1); expect(taskClaims(w).length).toBe(1)
  expect(await text(ui)).toContain('Incoming tasks: enabled')
  await taskStats(ui, { submitted: 0, observed: 0, changes: 0, cancellations: 0 })
  privacy(w, await text(ui))
})

test('context changed during task registration prevents every task claim after the asynchronous enable check', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  w.register = async e => { if (e.name === 'task_accept') { await w.clock.sleep(1000); w.native = 'changed-during-registration' } }
  const pending = press(ui, 'Enable incoming tasks'); void pending.catch(() => undefined)
  await w.clock.settle(); await w.clock.advance(1000); await pending
  expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([]); expect(writes(w)).toEqual([])
  denied(await call($, ACCEPT, { task_id: id('task', 1) }))
  expect(w.prompts.length).toBe(1); privacy(w, await text(ui))
})

test('cancellations then tasks serialize each prompt and schedule from completion while messages and lease progress independently', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  await w.clock.advance(4000)
  const cancel = cancelHandoff(w, 1), task = taskHandoff(w, 2)
  w.cancellations = [cancel]; w.tasks = [task]
  let submitted = 0
  w.submit = async e => { submitted++; await w.clock.sleep(submitted === 1 ? 1000 : 2000); return { text: e.text, origin: e.origin } }
  const messageBefore = claims(w).length, leaseBefore = requests(w, '/adapter/v1/connect').length
  await enableTasks(w, ui)
  expect(cancelClaims(w).length).toBe(1); expect(taskClaims(w)).toEqual([])
  await w.clock.advance(1000)
  expect(taskClaims(w).length).toBe(1); expect(taskPrompts(w).length).toBe(2)
  expect(claims(w).length > messageBefore).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leaseBefore + 1)
  await w.clock.advance(1999); expect(cancelClaims(w).length).toBe(1)
  await w.clock.advance(1); await taskStats(ui, { submitted: 1, observed: 0, changes: 0, cancellations: 1 })
  await w.clock.advance(999); expect(cancelClaims(w).length).toBe(1); expect(taskClaims(w).length).toBe(1)
  await w.clock.advance(1); expect(cancelClaims(w).length).toBe(2); expect(taskClaims(w).length).toBe(2)
  const taskPaths = w.httpCalls.map(pathOf).filter(path => path === TASK_NEXT || path === CANCEL_NEXT)
  expect(taskPaths).toEqual([CANCEL_NEXT, TASK_NEXT, CANCEL_NEXT, TASK_NEXT]); expect(writes(w)).toEqual([])
  privacy(w, await text(ui))
})

test('queued redelivered policy self and adopted offset-deadline tasks project only reversible untrusted public metadata', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  const queued = taskHandoff(w, 1), policy = taskHandoff(w, 2), adopted = taskHandoff(w, 3, true)
  queued.task.artifacts = [{ name: 'report 東京.txt', size: 0, sha256: 'f'.repeat(64), media_type: 'text/plain' }]
  queued.task.delegation = chain(queued); queued.delegable = true
  policy.redelivered = true; delete policy.task.grant_id
  policy.task.policy = { person_id: PERSON, version: 1 }; policy.task.artifacts = []
  policy.task.deadline = stamp(w.clock.now() + 60_000 + 330 * 60_000).replace('Z', '+05:30')
  delete adopted.task.grant_id; adopted.task.self = { person_id: PERSON }
  adopted.task.deadline = stamp(w.clock.now() - 1000).replace('Z', '+00:00')
  w.tasks = [queued, policy, adopted]
  await enableTasks(w, ui); await w.clock.advance(2000)
  expect(taskPrompts(w).length).toBe(3); expect(writes(w)).toEqual([])
  for (const [index, value] of [queued, policy, adopted].entries()) {
    const prompt = taskPrompts(w)[index].text
    expect(prompt).toContain(JSON.stringify(value.task.input)); expect(prompt).toContain(JSON.stringify(value.sender_person))
    expect(prompt).toContain(value.task.task_id); expect(prompt).toContain(SENDER)
    expect(prompt).toContain(value.task.origin.agent_id); expect(prompt).toContain(value.task.deadline)
    expect(prompt).toMatch(/external|untrusted/i); expect(prompt).toMatch(/no.*(?:local|permission)|(?:not|never).*permission/i)
    for (const tool of [ACCEPT, REJECT, PROGRESS, COMPLETE, CANCELLED]) expect(prompt).toContain(tool)
    expect(prompt).not.toContain(value.task.origin.session_id); expect(prompt).not.toContain(value.delivery.id)
    expect(prompt).not.toContain('\"grant_id\"'); expect(prompt).not.toContain('\"policy\"'); expect(prompt).not.toContain('\"self\"')
  }
  const artifactPrompt = taskPrompts(w)[0].text
  expect(artifactPrompt).toContain('report 東京.txt'); expect(artifactPrompt).toContain('f'.repeat(64))
  expect(artifactPrompt).toMatch(/metadata/i); expect(artifactPrompt).toMatch(/(?:cannot|not|no).*transfer|transfer.*(?:unavailable|not)/i)
  expect(artifactPrompt).toMatch(/delegat.*(?:unavailable|not|no)|(?:cannot|no).*delegat/i)
  expect(artifactPrompt).not.toContain(queued.task.delegation[0].signature)
  expect(taskPrompts(w)[2].text).toContain(adopted.progress)
  expect(taskPrompts(w)[2].text).toMatch(/running|resum/i)
  await taskStats(ui, { submitted: 3, observed: 0, changes: 0, cancellations: 0 })
  expect(await text(ui)).toContain('Peer exchange: not verified'); privacy(w, await text(ui))
})

test('task handoff bindings exact shapes states UTF-8 and artifact/delegation metadata are checked before any prompt', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  const cases: [string, (h: any) => void][] = [
    ['session', h => { h.delivery.session_id = id('session', 99) }],
    ['adapter', h => { h.delivery.adapter_id = id('adapter', 99) }],
    ['agent', h => { h.delivery.target_agent_id = id('agent', 99) }],
    ['sender', h => { h.status.sender_host_id = 'host_' + '9'.repeat(64) }],
    ['host', h => { h.status.receiver_host_id = SENDER }],
    ['task', h => { h.task.task_id = id('task', 99) }],
    ['extra-top', h => { h.private_error = RAW }],
    ['extra-nested', h => { h.task.origin.path = '/private/remote-path' }],
    ['final', h => { h.status.state = 'succeeded' }],
    ['elapsed-offset', h => { h.task.deadline = stamp(w.clock.now() - 1000 + 330 * 60_000).replace('Z', '+05:30') }],
    ['running-not-adopted', h => { h.status.state = 'running' }],
    ['adopted-queued', h => { h.adopted = true }],
    ['unsafe-event', h => { h.status.last_event = Number.MAX_SAFE_INTEGER + 1 }],
    ['input-empty', h => { h.task.input = '' }],
    ['input-utf8', h => { h.task.input = 'é'.repeat(32769) }],
    ['progress-utf8', h => { h.progress = 'é'.repeat(32769) }],
    ['person', h => { h.sender_person_id = null }],
    ['citation', h => { h.task.policy = { person_id: PERSON, version: 1 } }],
    ['artifact-name', h => { h.task.artifacts = [{ name: '../private', size: 1, sha256: 'f'.repeat(64), media_type: 'text/plain' }] }],
    ['artifact-duplicate', h => { const item = { name: 'same', size: 1, sha256: 'f'.repeat(64), media_type: 'text/plain' }; h.task.artifacts = [item, clone(item)] }],
    ['chain-audience', h => { h.task.delegation = chain(h); h.task.delegation[0].audience_host_id = SENDER }],
    ['chain-signature', h => { h.task.delegation = chain(h); h.task.delegation[0].signature = 'not-canonical' }],
  ]
  for (const [index, [name, mutate]] of cases.entries()) {
    const value = taskHandoff(w, index + 1); mutate(value); w.tasks = [value]
    const before = w.prompts.length
    await enableTasks(w, ui, index === 0 ? 'Enable incoming tasks' : 'Retry incoming tasks')
    expect(w.prompts.length, name + ': no task prompt').toBe(before)
    expect(await text(ui), name).not.toContain('Incoming tasks: enabled')
    expect(await text(ui), name).toContain('Incoming delivery: verified (messages)')
    expect(await text(ui), name).toContain('Adapter: connected')
  }
  expect(writes(w)).toEqual([]); await taskStats(ui, { submitted: 0, observed: 0, changes: 0, cancellations: 0 })
  privacy(w, await text(ui))
})

test('one delivery may yield one task and one cancellation notice without automatically accepting or stopping work', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  const task = taskHandoff(w, 1); w.tasks = [task]; await enableTasks(w, ui)
  expect(resultOf(await call($, ACCEPT, { task_id: task.task.task_id }))).toEqual(stripped(w.taskStatuses[task.task.task_id]))
  const cancel = cancelHandoff(w, 1); w.cancellations = [cancel]; await w.clock.advance(1000)
  expect(taskPrompts(w).length).toBe(2)
  const notice = taskPrompts(w)[1].text
  expect(notice).toContain(task.task.task_id); expect(notice).toContain(SENDER)
  expect(notice).toMatch(/request/i); expect(notice).toMatch(/(?:actually|really).*stop|stop.*(?:actually|confirmed)|work.*stopped/i)
  expect(notice).toContain(CANCELLED); expect(notice).toContain(COMPLETE)
  expect(writes(w).length).toBe(1); expect(w.taskStatuses[task.task.task_id].state).toBe('running')
  await taskStats(ui, { submitted: 1, observed: 1, changes: 1, cancellations: 1 })
  expect(resultOf(await call($, CANCELLED, { task_id: task.task.task_id }))).toEqual(stripped(w.taskStatuses[task.task.task_id]))
  await taskStats(ui, { submitted: 1, observed: 1, changes: 2, cancellations: 1 })
  privacy(w, await text(ui))
})

test('unbound malformed final and unrequested cancellation claims stop only task delivery without a notice', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  const changes = [ (h: any) => { h.delivery.cancel_claimed_at = null },
    (h: any) => { h.status.cancel_requested = false }, (h: any) => { h.status.state = 'cancelled' },
    (h: any) => { h.delivery.sender_host_id = 'host_' + '9'.repeat(64) },
    (h: any) => { h.delivery.adapter_id = id('adapter', 99) }, (h: any) => { h.task = {} } ]
  for (const [index, mutate] of changes.entries()) {
    const value = cancelHandoff(w, index + 1); mutate(value); w.cancellations = [value]
    const before = w.prompts.length
    await enableTasks(w, ui, index === 0 ? 'Enable incoming tasks' : 'Retry incoming tasks')
    expect(w.prompts.length).toBe(before); expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  }
  expect(writes(w)).toEqual([]); privacy(w, await text(ui))
})

test('five scoped lifecycle tools address earlier held tasks and count unique sender/task/events without grant reads', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui); await enableTasks(w, ui)
  for (const n of [1, 2, 3, 4]) w.taskStatuses[id('task', n)] = taskStatus(w, n, n > 2 ? 'running' : 'queued',
    n === 3 ? { cancel_requested: true, last_event: 3 } : {})
  const sequence: [string, any][] = [
    [ACCEPT, { task_id: id('task', 1) }], [ACCEPT, { task_id: id('task', 1) }],
    [PROGRESS, { task_id: id('task', 1), message: 'Accepted work continues after peer grant revocation 東京' }],
    [PROGRESS, { task_id: id('task', 1), message: 'Accepted work continues after peer grant revocation 東京' }],
    [COMPLETE, { task_id: id('task', 1), status: 'succeeded', output: 'Real completed outcome' }],
    [COMPLETE, { task_id: id('task', 1), status: 'succeeded', output: 'Real completed outcome' }],
    [REJECT, { task_id: id('task', 2) }], [REJECT, { task_id: id('task', 2), reason: '' }],
    [CANCELLED, { task_id: id('task', 3) }], [CANCELLED, { task_id: id('task', 3) }],
    [COMPLETE, { task_id: id('task', 4), status: 'failed', output: 'Observed failure' }],
  ]
  for (const [tool, args] of sequence) {
    const answer = resultOf(await call($, tool, args))
    expect(answer).toEqual(stripped(w.taskStatuses[args.task_id]))
    expect(Object.keys(answer).sort()).toEqual(['cancel_requested', 'last_event', 'state', 'task_id'])
  }
  expect(JSON.parse(writes(w).find(e => pathOf(e).endsWith('/reject')).init.body)).toEqual({ reason: '' })
  await taskStats(ui, { submitted: 0, observed: 4, changes: 6, cancellations: 0 })
  expect(taskPrompts(w)).toEqual([])
  expect(w.calls.every(e => ['snapshot', 'project.lookup', 'project.inspect', 'adapter.lookup', 'adapter.inspect', 'adapter.transport'].includes(e.kind))).toBe(true)
  expect(await text(ui)).toContain('Peer exchange: not verified')
  privacy(w, await text(ui))
})

test('task model tools reject plugin subagent extra selectors and UTF-8 overflow before HTTP but allow exact byte bounds', { plugins: [pluginCaller] }, async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); const taskId = id('task', 1)
  w.taskStatuses[taskId] = taskStatus(w, 1)
  denied(await call($, ACCEPT, { task_id: taskId })); await ready($, w, ui)
  denied(await call($, ACCEPT, { task_id: taskId })); await enableTasks(w, ui)
  const before = writes(w).length
  const bad: [string, any][] = [
    [ACCEPT, { task_id: 'task_../owner' }], [ACCEPT, { task_id: taskId, agentId: 'subagent' }],
    [ACCEPT, { task_id: taskId, sender_host_id: SENDER }], [REJECT, { task_id: taskId, file: '/private/task' }],
    [REJECT, { task_id: taskId, reason: 'é'.repeat(32769) }],
    [PROGRESS, { task_id: taskId, message: '' }], [PROGRESS, { task_id: taskId, message: 'é'.repeat(32769) }],
    [COMPLETE, { task_id: taskId, status: 'running', output: 'bad status' }],
    [COMPLETE, { task_id: taskId, status: 'succeeded', output: '' }],
    [COMPLETE, { task_id: taskId, status: 'failed', output: 'é'.repeat(32769) }],
    [COMPLETE, { task_id: taskId, status: 'failed', output: 'no artifacts', artifacts: [] }],
    [CANCELLED, { task_id: taskId, owner: true }],
  ]
  for (const [tool, args] of bad) denied(await call($, tool, args))
  for (const tool of [ACCEPT, REJECT, PROGRESS, COMPLETE, CANCELLED]) {
    const args = { tool, task_id: taskId, ...(tool === PROGRESS ? { message: 'plugin' } : {}),
      ...(tool === COMPLETE ? { status: 'succeeded', output: 'plugin' } : {}) }
    denied(JSON.parse((await $.command.run({ command: 'fixture-task-tool', args: JSON.stringify(args) })).text!))
  }
  expect(writes(w).length).toBe(before)
  expect(resultOf(await call($, ACCEPT, { task_id: taskId, tool_use_id: 'native-task-call', consent: 'native envelope' })).state).toBe('running')
  const bound = 'é'.repeat(32768)
  expect(resultOf(await call($, PROGRESS, { task_id: taskId, message: bound })).state).toBe('running')
  expect(resultOf(await call($, COMPLETE, { task_id: taskId, status: 'succeeded', output: bound })).state).toBe('succeeded')
  w.taskStatuses[id('task', 2)] = taskStatus(w, 2)
  expect(resultOf(await call($, REJECT, { task_id: id('task', 2), reason: bound })).state).toBe('rejected')
  for (const action of ['progress', 'complete', 'reject']) {
    const body = JSON.parse(writes(w).find(e => pathOf(e).endsWith('/' + action)).init.body)
    expect(new TextEncoder().encode(body.message ?? body.output ?? body.reason).length).toBe(65536)
  }
  privacy(w, await text(ui))
})

test('bound expected statuses and controlled uncertain writes leave task authority usable without false evidence or auto retry', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui); await enableTasks(w, ui)
  const taskId = id('task', 1), normal = w.fetch
  w.taskStatuses[taskId] = taskStatus(w, 1)
  for (const mode of ['denied', 'invalid-json', 'wrong-task', 'wrong-sender', 'wrong-host', 'wrong-agent', 'wrong-state', 'unsafe-event', 'extra']) {
    w.fetch = async e => {
      if (!pathOf(e).endsWith('/accept')) return normal(e)
      if (mode === 'denied') return { fixtureDeny: true }
      if (mode === 'invalid-json') return { status: 200, ok: true, headers: {}, text: RAW }
      const value = { ...taskStatus(w, 1, 'running'), private_error: undefined }
      if (mode === 'wrong-task') value.task_id = id('task', 99)
      if (mode === 'wrong-sender') value.sender_host_id = 'host_malformed'
      if (mode === 'wrong-host') value.receiver_host_id = SENDER
      if (mode === 'wrong-agent') value.target_agent_id = id('agent', 99)
      if (mode === 'wrong-state') value.state = 'queued'
      if (mode === 'unsafe-event') value.last_event = Number.MAX_SAFE_INTEGER + 1
      if (mode === 'extra') value.private_error = RAW
      return response(value)
    }
    denied(await call($, ACCEPT, { task_id: taskId }))
    expect(await text(ui), mode).toContain('Incoming tasks: enabled')
    await taskStats(ui, { submitted: 0, observed: 0, changes: 0, cancellations: 0 })
  }
  w.fetch = async e => { const value = await normal(e); if (pathOf(e).endsWith('/accept')) await w.clock.sleep(6000); return value }
  const pending = call($, ACCEPT, { task_id: taskId }); void pending.catch(() => undefined)
  await w.clock.settle(); const before = writes(w).length
  await w.clock.advance(5000); denied(await pending)
  await w.clock.advance(1000); expect(writes(w).length).toBe(before)
  await taskStats(ui, { submitted: 0, observed: 0, changes: 0, cancellations: 0 })
  w.fetch = normal
  expect(resultOf(await call($, ACCEPT, { task_id: taskId }))).toEqual(stripped(w.taskStatuses[taskId]))
  await taskStats(ui, { submitted: 0, observed: 1, changes: 1, cancellations: 0 })
  privacy(w, await text(ui))
})

test('one pending task write synchronously refuses overlapping writes and confirms only the completed status', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui); await enableTasks(w, ui)
  const taskId = id('task', 1); w.taskStatuses[taskId] = taskStatus(w, 1)
  const normal = w.fetch
  w.fetch = async e => { const value = await normal(e); if (pathOf(e).endsWith('/accept')) await w.clock.sleep(1000); return value }
  const pending = call($, ACCEPT, { task_id: taskId }); void pending.catch(() => undefined)
  await w.clock.settle()
  denied(await call($, PROGRESS, { task_id: taskId, message: 'overlapping' }))
  expect(writes(w).length).toBe(1); await taskStats(ui, { submitted: 0, observed: 0, changes: 0, cancellations: 0 })
  await w.clock.advance(1000); expect(resultOf(await pending)).toEqual(stripped(w.taskStatuses[taskId]))
  expect(resultOf(await call($, PROGRESS, { task_id: taskId, message: 'after accept' })).state).toBe('running')
  expect(writes(w).length).toBe(2); await taskStats(ui, { submitted: 0, observed: 1, changes: 2, cancellations: 0 })
  privacy(w, await text(ui))
})

test('Stop incoming tasks during asynchronous inspection prevents a scoped write while messages remain ready', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui); await enableTasks(w, ui)
  const taskId = id('task', 1); w.taskStatuses[taskId] = taskStatus(w, 1)
  const normal = w.run; let inspecting = false
  w.run = async (kind, payload, e) => {
    if (kind === 'project.inspect' && !inspecting) { inspecting = true; await w.clock.sleep(1000) }
    return normal(kind, payload, e)
  }
  const pending = call($, ACCEPT, { task_id: taskId }); void pending.catch(() => undefined)
  await w.clock.settle(); expect(inspecting).toBe(true)
  await press(ui, 'Stop incoming tasks'); await w.clock.advance(1000); denied(await pending)
  expect(writes(w)).toEqual([])
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  const stopped = taskClaims(w).length + cancelClaims(w).length, messages = claims(w).length
  await w.clock.advance(5000)
  expect(taskClaims(w).length + cancelClaims(w).length).toBe(stopped); expect(claims(w).length > messages).toBe(true)
  expect(await text(ui)).toContain('Adapter: connected'); privacy(w, await text(ui))
})

test('claim and submission uncertainty stop tasks alone with explicit retry and no replay of uncertain task or cancellation IDs', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  const normalFetch = w.fetch
  for (const [index, mode] of ['claim-denied', 'claim-timeout', 'submission-drop', 'submission-timeout'].entries()) {
    const task = taskHandoff(w, index + 1)
    w.tasks = mode === 'submission-drop' ? [] : [task]
    w.cancellations = mode === 'submission-drop' ? [cancelHandoff(w, index + 1)] : []
    w.fetch = async e => {
      if (pathOf(e) === TASK_NEXT && mode === 'claim-denied') return { fixtureDeny: true }
      const value = await normalFetch(e)
      if (pathOf(e) === TASK_NEXT && mode === 'claim-timeout') await w.clock.sleep(6000)
      return value
    }
    w.submit = async e => {
      if (mode === 'submission-drop') return { drop: RAW }
      if (mode === 'submission-timeout') await w.clock.sleep(6000)
      return { text: e.text, origin: e.origin }
    }
    const before = w.prompts.length
    await enableTasks(w, ui, index === 0 ? 'Enable incoming tasks' : 'Retry incoming tasks')
    if (mode.endsWith('timeout')) {
      const messageBefore = claims(w).length
      await w.clock.advance(4000); expect(claims(w).length > messageBefore, mode + ': message polling remains independent').toBe(true)
      await w.clock.advance(1000)
    }
    expect(await text(ui), mode).not.toContain('Incoming tasks: enabled')
    expect(await text(ui), mode).toContain('Incoming delivery: verified (messages)')
    expect(await text(ui), mode).toContain('Adapter: connected')
    const stopped = taskClaims(w).length + cancelClaims(w).length, prompts = w.prompts.length
    await w.clock.advance(6000)
    expect(taskClaims(w).length + cancelClaims(w).length, mode).toBe(stopped); expect(w.prompts.length).toBe(prompts)
    expect(prompts - before <= 1).toBe(true)
  }
  w.fetch = normalFetch; w.submit = async e => ({ text: e.text, origin: e.origin })
  const heldTask = taskHandoff(w, 20), heldCancel = cancelHandoff(w, 21)
  w.tasks = [heldTask]; w.cancellations = [heldCancel]
  await enableTasks(w, ui, 'Retry incoming tasks')
  await taskStats(ui, { submitted: 1, observed: 0, changes: 0, cancellations: 1 })
  // Fail an idle claim, then force both previously uncertain records. A retry
  // may skip or block them, but must never offer either to the model again.
  w.fetch = async e => pathOf(e) === TASK_NEXT ? { fixtureDeny: true } : normalFetch(e)
  await w.clock.advance(1000); const offered = w.prompts.length
  w.fetch = normalFetch; w.tasks = [taskHandoff(w, 4)]; w.cancellations = [cancelHandoff(w, 3)]
  await enableTasks(w, ui, 'Retry incoming tasks'); await w.clock.advance(1000)
  expect(w.prompts.length).toBe(offered)
  await taskStats(ui, { submitted: 1, observed: 0, changes: 0, cancellations: 1 })
  expect(writes(w)).toEqual([]); privacy(w, await text(ui))
})

test('Back and Close preserve established task polling while Stop tasks preserves message and lease authority only', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui); await enableTasks(w, ui)
  await press(ui, 'Back to Peerspan'); await press(ui, 'Close'); await ui.unmount()
  w.tasks = [taskHandoff(w, 1)]; await w.clock.advance(1000)
  expect(taskPrompts(w).length).toBe(1)
  const fresh = await enter($, w); expect(await text(fresh)).toContain('Incoming tasks: enabled')
  await press(fresh, 'Stop incoming tasks')
  const before = taskClaims(w).length + cancelClaims(w).length, messages = claims(w).length
  w.tasks = [taskHandoff(w, 2)]; await w.clock.advance(5000)
  expect(taskClaims(w).length + cancelClaims(w).length).toBe(before)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/connect').length > 1).toBe(true)
  denied(await call($, ACCEPT, { task_id: id('task', 1) }))
  expect(await text(fresh)).toContain('Incoming delivery: verified (messages)')
  expect(writes(w)).toEqual([]); expect(w.prompts.length).toBe(2)
  await press(fresh, 'Stop adapter'); const stopped = w.httpCalls.length
  await w.clock.advance(10_000); expect(w.httpCalls.length).toBe(stopped)
  await press(fresh, 'Connect this project'); await press(fresh, 'Review adapter connection')
  await press(fresh, 'Connect adapter'); await ready($, w, fresh)
  await taskStats(fresh, { submitted: 0, observed: 0, changes: 0, cancellations: 0 })
  expect(await text(fresh)).not.toContain('Incoming tasks: enabled')
  privacy(w, await text(fresh))
})

test('loss of the captured message proof stops task authority and a fresh message proof still needs explicit task enable', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  w.tasks = [taskHandoff(w, 1)]; await enableTasks(w, ui)
  const normal = w.fetch
  w.fetch = async e => pathOf(e) === '/adapter/v1/next' ? { fixtureDeny: true } : normal(e)
  await w.clock.advance(1000)
  const stopped = taskClaims(w).length + cancelClaims(w).length
  denied(await call($, ACCEPT, { task_id: id('task', 1) }))
  expect(await text(ui)).not.toContain('Incoming tasks: enabled'); expect(writes(w)).toEqual([])
  w.fetch = normal; await enable($, w, ui, 'Retry incoming messages')
  await w.clock.advance(1000)
  expect(taskClaims(w).length + cancelClaims(w).length).toBe(stopped)
  expect(await text(ui)).not.toContain('Incoming tasks: enabled')
  w.tasks = [taskHandoff(w, 2)]; await enableTasks(w, ui)
  expect(taskPrompts(w).filter(e => e.text.includes(id('task', 2))).length).toBe(1)
  await taskStats(ui, { submitted: 2, observed: 0, changes: 0, cancellations: 0 })
  expect(w.tools.filter(e => e.name.startsWith('task_')).length).toBe(5)
  privacy(w, await text(ui))
})

for (const phase of ['claim', 'submission']) {
  test(`late old task ${phase} cannot submit count or cancel a newer explicitly enabled attempt`, async ($, on) => {
    const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
    const old = taskHandoff(w, 1); w.tasks = [old]
    const normal = w.fetch; let delay = true
    w.fetch = async e => { const value = await normal(e)
      if (phase === 'claim' && pathOf(e) === TASK_NEXT && delay) { delay = false; await w.clock.sleep(2000) }
      return value }
    w.submit = async e => { if (phase === 'submission' && e.text.includes(old.task.task_id)) {
      await w.clock.sleep(2000); return { drop: RAW } }; return { text: e.text, origin: e.origin } }
    await enableTasks(w, ui)
    await press(ui, 'Stop incoming tasks'); w.tasks = [taskHandoff(w, 2)]
    await enableTasks(w, ui, 'Enable incoming tasks')
    await w.clock.advance(2000)
    expect(await text(ui)).toContain('Incoming tasks: enabled')
    expect(taskPrompts(w).filter(e => e.text.includes(old.task.task_id)).length).toBe(phase === 'claim' ? 0 : 1)
    await taskStats(ui, { submitted: 1, observed: 0, changes: 0, cancellations: 0 })
    expect(writes(w)).toEqual([]); privacy(w, await text(ui))
  })
}

test('late task write completion cannot update counters or replace a newer task attempt', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui); await enableTasks(w, ui)
  const taskId = id('task', 1); w.taskStatuses[taskId] = taskStatus(w, 1)
  const normal = w.fetch
  w.fetch = async e => { const value = await normal(e); if (pathOf(e).endsWith('/accept')) await w.clock.sleep(2000); return value }
  const pending = call($, ACCEPT, { task_id: taskId }); void pending.catch(() => undefined)
  await w.clock.settle(); expect(writes(w).length).toBe(1)
  await press(ui, 'Stop incoming tasks'); await enableTasks(w, ui)
  await w.clock.advance(2000); denied(await pending)
  expect(await text(ui)).toContain('Incoming tasks: enabled')
  await taskStats(ui, { submitted: 0, observed: 0, changes: 0, cancellations: 0 })
  w.fetch = normal
  expect(resultOf(await call($, PROGRESS, { task_id: taskId, message: 'Host confirms accepted work is still running' })).state).toBe('running')
  await taskStats(ui, { submitted: 0, observed: 1, changes: 1, cancellations: 0 })
  privacy(w, await text(ui))
})

test('context scope lease expiry and session end stop all task authority and future work', { timeoutMs: 15_000 }, async ($, on) => {
  const w = fixture(on); let ui = await connected($, w); const normalRun = w.run
  for (const [index, mode] of ['root', 'native', 'surface', 'scope', 'lease', 'end'].entries()) {
    if (index > 0) {
      w.root = ROOT; w.native = NATIVE; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normalRun
      w.parent = await parentFlow(); w.child = await adapterFlow(w.parent, { state: 'authorized' })
      ui = await enter($, w); await press(ui, 'Connect this project'); await press(ui, 'Review adapter connection'); await press(ui, 'Connect adapter')
    }
    await ready($, w, ui); await enableTasks(w, ui)
    if (mode === 'root') { w.root = '/different-native-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'different-native-task-session'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'scope') w.child.review.effects.directory_access = true
    if (mode === 'lease') w.run = async (kind, payload, e) => {
      if (kind.endsWith('.inspect')) await w.clock.sleep(20_000)
      return normalRun(kind, payload, e)
    }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    await w.clock.advance(mode === 'lease' ? 15_000 : 5000)
    const stopped = w.httpCalls.length
    for (const [tool, args] of [[ACCEPT, {}], [REJECT, { reason: '' }], [PROGRESS, { message: 'stopped' }],
      [COMPLETE, { status: 'failed', output: 'stopped' }], [CANCELLED, {}]] as const) {
      denied(await call($, tool, { task_id: id('task', 1), ...args }))
    }
    await w.clock.advance(30_000); expect(w.httpCalls.length, mode + ': all future work stopped').toBe(stopped)
    expect(await text(ui), mode).not.toContain('Incoming tasks: enabled')
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! })
    await ui.unmount()
  }
  privacy(w)
})

test('an old pending inspection failure cannot stop the lease or a newer task attempt under the same message proof', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui); await enableTasks(w, ui)
  const normal = w.run; let delayed = false
  w.run = async (kind, payload, e) => {
    if (kind === 'project.inspect' && !delayed) {
      delayed = true; await w.clock.sleep(1000); return { fixtureDeny: true }
    }
    return normal(kind, payload, e)
  }
  const pending = call($, ACCEPT, { task_id: id('task', 1) }); void pending.catch(() => undefined)
  await w.clock.settle(); expect(delayed).toBe(true)
  await press(ui, 'Stop incoming tasks'); await enableTasks(w, ui)
  const before = taskClaims(w).length
  await w.clock.advance(1000); denied(await pending)
  expect(await text(ui)).toContain('Incoming tasks: enabled')
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  expect(await text(ui)).toContain('Adapter: connected')
  expect(taskClaims(w).length > before).toBe(true); expect(writes(w)).toEqual([])
  await w.clock.advance(4000); expect(requests(w, '/adapter/v1/connect').length).toBe(2)
  privacy(w, await text(ui))
})


test('a stale task enable control cannot activate tasks after terminal support disappears', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  const button = await key(ui, 'Enable incoming tasks')
  w.surface = 'desktop'; w.surfaces = ['desktop']
  await ui.press({ key: button }); await w.clock.settle()
  expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([])
  expect(w.tools.filter(e => e.name.startsWith('task_'))).toEqual([])
  expect(w.prompts.length).toBe(1)
  denied(await call($, ACCEPT, { task_id: id('task', 1) }))
  privacy(w, await text(ui))
})


test('late registration from an ended conversation cannot populate or duplicate the next conversation task registry', async ($, on) => {
  const w = fixture(on); let ui = await connected($, w); await ready($, w, ui)
  let delayed = false
  w.register = async e => {
    if (e.name === 'task_accept' && !delayed) { delayed = true; await w.clock.sleep(1000) }
  }
  await enableTasks(w, ui); expect(delayed).toBe(true); expect(taskClaims(w)).toEqual([])
  await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } }); await ui.unmount()
  w.native = 'new-private-native-task-conversation'
  w.parent = await parentFlow({ native: w.native }); w.child = await adapterFlow(w.parent, { state: 'authorized', n: 11 })
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  const nextSession = w.tools.length
  ui = await open($, w); await press(ui, 'Connect adapter'); await ready($, w, ui); await enableTasks(w, ui)
  expect(w.materials.at(-1).instance_id, 'new conversation has a distinct scoped instance').not.toBe(w.materials[0].instance_id)
  const names = () => w.tools.slice(nextSession).filter(tool => tool.name.startsWith('task_')).map(tool => tool.name).sort()
  const expected = ['task_accept', 'task_cancelled', 'task_complete', 'task_progress', 'task_reject']
  expect(names(), 'new conversation has its own registration before the old one finishes').toEqual(expected)
  expect(await text(ui)).toContain('Incoming tasks: enabled')
  await w.clock.advance(1000)
  expect(names(), 'old completion adds no new-conversation registration').toEqual(expected)
  await press(ui, 'Stop incoming tasks'); await enableTasks(w, ui)
  expect(names(), 'same-conversation restart reuses exactly its own registered tools').toEqual(expected)
  w.taskStatuses[id('task', 1)] = taskStatus(w, 1)
  expect(resultOf(await call($, ACCEPT, { task_id: id('task', 1) })).state).toBe('running')
  await taskStats(ui, { submitted: 0, observed: 1, changes: 1, cancellations: 0 })
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  privacy(w, await text(ui))
})


test('explicit registration Retry repeats only a failed tool and shares its pending retry while retaining successful tools', async ($, on) => {
  const w = fixture(on); const ui = await connected($, w); await ready($, w, ui)
  let attempted = 0, failed = '', failOnce = true
  const successful = new Set<string>()
  w.register = async e => {
    if (!e.name.startsWith('task_')) return
    attempted++
    if (!failed && attempted === 3) failed = e.name
    if (e.name === failed) {
      if (failOnce) { failOnce = false; return { fixtureDeny: true } }
      await w.clock.sleep(1000)
    }
    successful.add(e.name)
  }
  await enableTasks(w, ui)
  expect(failed, 'the fixture refused one registration after earlier successful registrations').not.toBe('')
  expect(successful.size >= 2, 'earlier registrations succeeded').toBe(true)
  expect(await text(ui)).not.toContain('Incoming tasks: enabled')
  expect(await text(ui)).toContain('Incoming delivery: verified (messages)')
  expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([])
  const successfulBeforeRetry = [...successful]
  const registrations = (name: string) => w.tools.filter(tool => tool.name === name).length
  expect(registrations(failed)).toBe(1)
  await enableTasks(w, ui, 'Retry incoming tasks')
  expect(registrations(failed), 'explicit Retry retries the refused registration').toBe(2)
  expect(taskClaims(w)).toEqual([]); expect(cancelClaims(w)).toEqual([])
  for (const name of successfulBeforeRetry) expect(registrations(name), name + ': earlier successful registration is retained').toBe(1)
  await press(ui, 'Stop incoming tasks'); await enableTasks(w, ui)
  expect(registrations(failed), 'restart shares the still-pending retry instead of registering twice').toBe(2)
  await w.clock.advance(1000)
  for (const name of ['task_accept', 'task_reject', 'task_progress', 'task_complete', 'task_cancelled']) {
    expect(registrations(name), name + ': only the failed entry is repeated').toBe(name === failed ? 2 : 1)
  }
  expect(await text(ui)).toContain('Incoming tasks: enabled')
  expect(taskClaims(w).length).toBe(1); expect(cancelClaims(w).length).toBe(1)
  expect(w.prompts.length).toBe(1); expect(readyCalls(w).length).toBe(1)
  w.taskStatuses[id('task', 1)] = taskStatus(w, 1)
  expect(resultOf(await call($, ACCEPT, { task_id: id('task', 1) })).state).toBe('running')
  await taskStats(ui, { submitted: 0, observed: 1, changes: 1, cancellations: 0 })
  privacy(w, await text(ui))
})
