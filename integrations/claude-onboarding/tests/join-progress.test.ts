/**
 * Independent section-15 published-request progress fixtures on Claude Code 2.1.303.
 * Public native effects only; no product imports, authentication or inference.
 * Original 200 cases are unchanged. Actual reload/terminal/daemon acceptance is
 * separate: fresh test modules establish only volatile initial state here.
 * The kit presses the current drawing; old-render closures remain source/manual
 * evidence. No native model receipt or invitation signature validity is claimed.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted, TestOptions } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-10-29T12:00:00Z')
const HOST = 'host_75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a'
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
const CODE = 'psi2-UFJJVkFURV9JTlZJVEVfU0VDUkVU'
const CODE2 = 'psi2-UFJJVkFURV9TRUNPTkRfU0VDUkVU'
const KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
const GENESIS_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
const INVITER_KEY = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
const RELAY_KEY = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
const HELPER_KEY = 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ='
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
    networks: [] as any[], invitation: null as any, previewValue: null as any, joining: null as any, identities: [{ public_key: KEY, sources: ["generated"] }] as any[], code: CODE, codes: [CODE, CODE2],
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  w.run = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: stamp(clock.now()), host_id: w.host,
      networks: w.networks, agents: [], requests: [], attention: [] }
    if (kind === 'join.progress') return await progressResponse(w)
    if (kind === 'join.lookup') return { version: 1, host_id: w.host, context: payload.context, flow: w.joining }
    if (kind === 'join.identities') return { version: 1, host_id: w.host, context: payload.context, identities: clone(w.identities) }
    if (kind === 'join.inspect') return w.joining
    if (kind === 'join.prepare') {
      if (w.joining && !payload.replace_flow_id) return w.joining
      w.joining = await joinFlow(w.parent, w.previewValue ?? await previewResponse(w), payload.person_public_key, { n: ++w.sequence })
      return w.joining
    }
    if (kind === 'join.decide') {
      const approved = payload.decision === 'approve'
      w.joining = { ...w.joining, state: approved ? 'requested' : 'declined',
        outcome: approved ? { request_id: id64('link', w.sequence), network_id: w.joining.review.invitation.network.id,
          context_id: w.joining.review.invitation.network.context_id, person_public_key: w.joining.review.person_public_key } : null,
        next_action: approved ? 'await_participant_reviews' : 'none' }
      return w.joining
    }
    if (kind === 'invitation.preview') return w.previewValue ?? await previewResponse(w)
    if (kind === 'invitation.lookup') return { version: 1, host_id: w.host, context: payload.context, flow: w.invitation }
    if (kind === 'invitation.prepare') {
      w.invitation = await invitationFlow(w.parent, w.networks.find(network => network.id === payload.network_id),
        { n: ++w.sequence, member: payload.member.trim(), pin: payload.expected_person_public_key,
          expires: clock.now() + 900_000, invitationExpires: clock.now() + 3_600_000 })
      return w.invitation
    }
    if (kind === 'invitation.inspect') return w.invitation
    if (kind === 'invitation.decide') {
      w.invitation = { ...w.invitation, state: payload.decision === 'approve' ? 'issued' : 'declined',
        invitation: payload.decision === 'approve' ? { invitation_id: id64('di', w.sequence), expires_at: w.invitation.review.invitation_expires_at } : null,
        next_action: payload.decision === 'approve' ? 'share_private_invitation' : 'restart_review' }
      return w.invitation
    }
    if (kind === 'invitation.handoff') return privateHandoff(w.invitation, w.code)
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
    } else if (['/adapter/v1/tasks/next', '/adapter/v1/tasks/cancels/next'].includes(path)) {
      value = null
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
    // Capture the serialized request independently of synthetic response
    // mutations; a real process stdout cannot mutate its already-sent stdin.
    const sent = payload === undefined ? undefined : clone(payload)
    w.calls.push({ ...e, kind, payload: sent }); w.trace.push({ kind, payload: sent })
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
  on('ui.notice', ($, e) => { w.outside.push(JSON.stringify(e)); return { value: undefined } })
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
async function key(ui: Pane, label: string | RegExp) {
  const found = await ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
  expect(found, String(label)).toBeDefined(); return found!.key!
}
async function press(ui: Pane, label: string | RegExp) { return ui.press({ key: await key(ui, label) }) }
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

const id64 = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(64, '0')
const invitationEffects = { create_contact_invitation: true, receive_join_requests: true, grant_membership: false,
  grant_agent_access: false, approve_machine: false, share_files: false, share_conversation: false, capability_calls: false }
function network(n = 1, name = 'Network "東京"'): any {
  return { id: id64('net', n), name, mode: 'decentralized', context_id: id64('ctx', n), genesis_root_public_key: GENESIS_KEY,
    root_state_id: id64('drs', n), root_public_key: GENESIS_KEY, root_epoch: 0, member: 'local owner', host_public_key: INVITER_KEY,
    person_public_key: KEY, provider: null, provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'usable', not_after: stamp(NOW + 86_400_000), required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: stamp(NOW - 1000) }
}
async function invitationFlow(parent: any, selected: any, options: any = {}) {
  const n = options.n ?? 30, state = options.state ?? 'review'
  const review = { version: 1, kind: 'create_contact_invitation', flow_id: id('flow', n), host_id: parent.review.host_id,
    context: context(parent), agent: clone(parent.review.agent),
    network: { id: selected.id, name: selected.name, context_id: selected.context_id, genesis_root_public_key: selected.genesis_root_public_key },
    inviter_host_public_key: selected.host_public_key, member: options.member ?? 'Teammate "é東京"',
    expected_person_public_key: options.pin ?? '-',
    transport: { bootstrap_addresses: ['127.0.0.1:443', 'peer.example:8443'], quic_addresses: ['[::1]:443'],
      relays: [{ address: 'relay.example:444', public_key: RELAY_KEY }], helpers: [{ address: 'helper.example:445', public_key: HELPER_KEY }] },
    expires_at: stamp(options.expires ?? (state === 'expired' ? NOW - 1000 : NOW + 900_000)),
    invitation_expires_at: stamp(options.invitationExpires ?? (state === 'expired' ? NOW + 2_699_000 : NOW + 3_600_000)),
    effects: clone(invitationEffects) }
  return { version: 1, flow_id: review.flow_id, state, review_id: await digest('peerspan-invitation-review-v1', review), review,
    invitation: state === 'issued' || options.issued ? { invitation_id: id64('di', n), expires_at: review.invitation_expires_at } : null,
    next_action: state === 'review' ? 'review' : state === 'issued' ? 'share_private_invitation' : 'restart_review' }
}
function privateHandoff(flow: any, code = CODE) {
  return { version: 1, flow_id: flow.flow_id, review_id: flow.review_id, network_id: flow.review.network.id,
    context_id: flow.review.network.context_id, invitation_id: flow.invitation.invitation_id,
    invitation: code, expires_at: flow.invitation.expires_at }
}
async function setup($: Engine, w: World, state: string | null = null, options: any = {}) {
  w.networks = options.networks ?? [network()]
  w.parent = await parentFlow({ agent: { id: id('agent', 1), name: 'Agent "東京"', owner: 'Owner \\é', capabilities: ['capability "metadata"'] } })
  if (state) w.invitation = await invitationFlow(w.parent, w.networks[0], { ...options, state })
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w); await press(ui, 'Connect this project'); return ui
}
async function visible(ui: Pane) {
  return (await text(ui)) + '\n' + (await ui.findAll({ type: 'Input' })).map(input => input.props.value ?? '').join('\n')
}
async function selectNetwork(ui: Pane, selected: any) {
  const found = (await ui.findAll({ type: 'Button' })).find(element => element.text.includes(selected.id))
  expect(found, 'explicit full-ID network choice').toBeDefined()
  expect(found!.text).toContain(quote(selected.name))
  await ui.press({ key: found!.key! })
}
async function inputField(ui: Pane, label: string) {
  const found = (await ui.findAll({ type: 'Input' })).find(element => element.props.label === label)
  expect(found, label).toBeDefined(); return found!
}
async function edit(ui: Pane, label: string, value: string) {
  await ui.input({ key: (await inputField(ui, label)).key!, text: value, kind: 'change' })
}
async function noInvitationAuthority(ui: Pane) {
  for (const name of ['Approve invitation', 'Decline invitation', 'Reveal private invitation']) {
    expect(await ui.find({ type: 'Button', text: new RegExp('^' + name + '$') })).toBeUndefined()
  }
}
async function begin(w: World, ui: Pane) {
  // Explicit fixture navigation back to the attached project after Back.
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Invite someone'); await w.clock.settle()
}
async function draft(w: World, ui: Pane, selected = w.networks[0], label = 'Teammate "é東京"', pin = '-') {
  await selectNetwork(ui, selected); await edit(ui, 'Invitee label', label); await edit(ui, 'Expected person public key', pin)
}
async function back(ui: Pane) {
  const found = await ui.find({ type: 'Button', text: /^Back\b/ }); expect(found).toBeDefined(); await ui.press({ key: found!.key! })
}
function invitationCalls(w: World) { return w.calls.filter(call => call.kind.startsWith('invitation.')) }
function safe(w: World, uiText = '', reveal = false, runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  for (const code of w.codes) {
    expect(w.outside.join('\n')).not.toContain(code)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(code)
    if (!reveal) expect(uiText).not.toContain(code)
  }
  for (const value of [NATIVE, RAW, w.parent?.flow_id, w.parent?.review_id, w.invitation?.flow_id, w.invitation?.review_id].filter(Boolean)) {
    expect(w.outside.join('\n')).not.toContain(value); expect(uiText).not.toContain(value)
  }
  expect(w.outside.join('\n') + uiText).not.toContain('PRIVATE_PROVIDER_ERROR')
  expect(w.outside.join('\n')).not.toContain(ROOT)
  expect(uiText).not.toMatch(/\b(?:flow_[0-9a-f]{32}|review_[0-9a-f]{64}|session_[0-9a-f]{32}|adapter_[0-9a-f]{32})\b/)
  for (const native of w.trace.filter(event => event.kind === 'native').map(event => event.value)) {
    expect(uiText).not.toContain(native); expect(w.outside.join('\n')).not.toContain(native)
  }
  for (const command of w.calls) {
    const [noun, verb] = command.kind.split('.')
    const prefix = [executable, ...(state ? ['--state', state] : []), 'onboarding']
    const suffix = command.kind === 'snapshot' ? [] : [noun, verb, ...(verb === 'inspect' ? [command.argv.at(-1)] : ['--stdin'])]
    expect(command.argv).toEqual([...prefix, ...suffix])
    expect(command.init?.timeoutMs).toBe(command.kind === 'join.identities' ? 15000 : 5000)
    for (const code of w.codes) expect(command.argv.join('\n')).not.toContain(code)
    expect(command.argv).not.toContain(ROOT); expect(command.argv).not.toContain(NATIVE)
    if (command.kind.startsWith('invitation.') && verb !== 'inspect') expect(typeof command.init.stdin).toBe('string')
    if (noun === 'invitation') expect(['lookup', 'prepare', 'inspect', 'decide', 'handoff', 'preview']).toContain(verb)
  }
  if (!runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  }
}

const previewEffects = { verify_contact_signature: true, create_identity: false, create_link_request: false,
  select_owner: false, grant_membership: false, grant_agent_access: false, approve_machine: false,
  share_files: false, share_conversation: false, capability_calls: false }
async function previewResponse(w: World, options: any = {}) {
  const selected = w.networks[0] ?? network()
  const review = { version: 1, kind: 'inspect_contact_invitation', host_id: w.host, context: context(w.parent),
    agent: clone(w.parent.review.agent),
    network: { id: selected.id, name: selected.name, context_id: selected.context_id,
      genesis_root_public_key: selected.genesis_root_public_key },
    inviter_host_public_key: INVITER_KEY,
    invitation: { id: id64('di', options.n ?? 30), member: options.member ?? 'Invited "é東京" member',
      expected_person_public_key: options.pin ?? KEY, issued_at: stamp(options.issued ?? NOW - 60_000),
      expires_at: stamp(options.expires ?? NOW + 3_540_000), automatic_return: options.automaticReturn ?? true },
    // Old contacts remain signed hints. The u64 boundary is a string, not a JS number.
    contacts: [
      { sequence: '0', issued_at: stamp(NOW - 600_000), expires_at: stamp(NOW - 300_000),
        quic_addresses: ['[::1]:443'], bootstrap_addresses: ['127.0.0.1:443'],
        relays: [{ address: 'relay.example:444', public_key: RELAY_KEY }] },
      { sequence: '18446744073709551615', issued_at: stamp(NOW - 590_000), expires_at: stamp(NOW - 290_000),
        quic_addresses: ['peer.example:8443'], bootstrap_addresses: [], relays: [] },
    ], helpers: [{ address: 'helper.example:445', public_key: HELPER_KEY }], effects: clone(previewEffects) }
  return { version: 1, host_id: w.host, context: context(w.parent),
    review_id: await digest('peerspan-invitation-preview-v1', review), review, next_action: 'choose_join_identity' }
}
const previewCalls = (w: World) => w.calls.filter(command => command.kind === 'invitation.preview')
async function recipientEntry(w: World, ui: Pane) {
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Review an invitation'); await w.clock.settle()
}
async function emptyDraft(ui: Pane) {
  expect((await inputField(ui, 'Private invitation code')).props.value ?? '').toBe('')
}
async function inspect(w: World, ui: Pane, code = CODE) {
  await edit(ui, 'Private invitation code', code); await press(ui, 'Inspect invitation'); await w.clock.settle()
}
async function unverified(ui: Pane, label = '') {
  expect(await visible(ui), label).not.toContain('Invitation: signature verified')
  for (const name of ['Approve invitation', 'Join', 'Continue']) {
    expect(await ui.find({ type: 'Button', text: new RegExp('^' + name + '$') }), label).toBeUndefined()
  }
}
async function currentProject(ui: Pane) {
  const previous = await ui.find({ type: 'Button', text: /^Back\b/ })
  if (previous) await ui.press({ key: previous.key! })
}

const joinEffects = { create_identity: false, create_link_request: true, publish_request: true,
  select_owner: false, grant_membership: false, grant_agent_access: false, approve_machine: false,
  share_files: false, share_conversation: false, capability_calls: false }
async function joinFlow(parent: any, preview: any, person = KEY, options: any = {}) {
  const n = options.n ?? 60, state = options.state ?? 'review'
  const review = { version: 1, kind: 'create_join_request', flow_id: id('flow', n), host_id: parent.review.host_id,
    context: context(parent), agent: clone(parent.review.agent), invitation_review_id: preview.review_id,
    invitation: clone(preview.review), person_public_key: person,
    expires_at: stamp(options.expires ?? Math.min(NOW + 900_000, Date.parse(preview.review.invitation.expires_at))),
    effects: clone(joinEffects) }
  const outcome = state === 'requested' || options.requested ? { request_id: id64('link', n),
    network_id: review.invitation.network.id, context_id: review.invitation.network.context_id, person_public_key: person } : null
  const actions: Record<string, string> = { review: 'approve_join_request', declined: 'none', requested: 'await_participant_reviews',
    expired: 'review_replacement', invalidated: 'review_replacement', replaced: 'review_replacement' }
  return { version: 1, host_id: review.host_id, flow_id: review.flow_id,
    review_id: await digest('peerspan-join-review-v1', review), state, review, outcome, next_action: actions[state] }
}
const joinCalls = (w: World) => w.calls.filter(command => command.kind.startsWith('join.'))
const identityButtons = async (ui: Pane) => ui.findAll({ type: 'Button', text: /^Review identity / })
async function joinEntry(w: World, ui: Pane) {
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Join a network'); await w.clock.settle()
}
async function joinDraft(ui: Pane, code = CODE, kind: 'change' | 'submit' = 'change') {
  await ui.input({ key: (await inputField(ui, 'Private invitation for joining')).key!, text: code, kind })
}
async function joiningIdentities(w: World, ui: Pane, code = CODE) {
  await joinDraft(ui, code); await press(ui, 'Review joining identities'); await w.clock.settle()
}
async function choose(w: World, ui: Pane, person = KEY) {
  await press(ui, 'Review identity ' + person); await w.clock.settle()
}
async function noJoinDecision(ui: Pane, label = '') {
  expect(await ui.find({ type: 'Button', text: /^Approve join request$/ }), label).toBeUndefined()
}
async function joinReview($: Engine, w: World) {
  const ui = await setup($, w); await joinEntry(w, ui); await joiningIdentities(w, ui); await choose(w, ui); return ui
}
function scopedIdentityPrivacy(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  safe(w, shown, false, runtime, executable, state)
  for (const e of w.calls.filter(command => command.kind === 'join.identities')) expect(e.payload).toEqual({ context: context(w.parent) })
  for (const e of joinCalls(w)) expect(['lookup', 'identities', 'prepare', 'inspect', 'decide', 'progress']).toContain(e.kind.split('.')[1])
}
function publicKey(n: number) {
  // Canonical32-byte public-format fixtures; no possession/crypto claim from stubs.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const bytes = Array.from({ length: 32 }, () => n), result: string[] = []
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index], b = bytes[index + 1] ?? 0, c = bytes[index + 2] ?? 0
    result.push(alphabet[a >> 2], alphabet[((a & 3) << 4) | (b >> 4)], alphabet[((b & 15) << 2) | (c >> 6)], index + 2 < bytes.length ? alphabet[c & 63] : '=')
  }
  return result.join('')
}
async function fullTerms(ui: Pane, review: any) {
  const invitation = review.invitation, shown = await visible(ui)
  for (const term of [ROOT, quote(review.agent.name), quote(review.agent.owner), ...review.agent.capabilities.map(quote),
    quote(invitation.network.name), invitation.network.id, invitation.network.context_id, invitation.network.genesis_root_public_key,
    invitation.inviter_host_public_key, invitation.invitation.id, quote(invitation.invitation.member),
    invitation.invitation.expected_person_public_key, invitation.invitation.issued_at, invitation.invitation.expires_at,
    ...invitation.contacts.flatMap((contact: any) => [contact.sequence, contact.issued_at, contact.expires_at, ...contact.quic_addresses,
      ...contact.bootstrap_addresses, ...contact.relays.flatMap((relay: any) => [relay.address, relay.public_key])]),
    ...invitation.helpers.flatMap((helper: any) => [helper.address, helper.public_key])]) expect(shown).toContain(term)
  for (const word of ['identity', 'request', 'owner', 'membership', 'agent access', 'machine', 'files', 'conversation', 'capability']) expect(shown.toLowerCase()).toContain(word)
}

const mapping: Record<string, [string, string]> = {
  pending: ['person_owner', 'review_owner_offer'], needs_selection: ['requesting_machine', 'review_owner_selection'],
  needs_administrator: ['network_administrator', 'review_admission'], needs_owner_finalization: ['person_owner', 'review_owner_finalization'],
  needs_commit: ['requesting_machine', 'review_final_commit'], finalizing: ['host', 'await_local_application'],
  linked: ['requesting_machine', 'inspect_access_readiness'], cancelled: ['requesting_machine', 'review_replacement'],
  expired: ['requesting_machine', 'review_replacement'], blocked: ['local_owner', 'inspect_advanced_status'],
}
const stages = ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered', 'owner_finalized', 'commit_persisted', 'locally_applied']
const stageMeaning: Record<string, RegExp> = {
  request_created: /Request created/i,
  owner_offered: /Owner offer (?:recorded|received)/i,
  owner_selected: /Owner (?:selection recorded|selected)/i,
  administrator_offered: /Administrator offer (?:recorded|received)/i,
  owner_finalized: /Owner finali[sz]ation (?:recorded|complete)/i,
  commit_persisted: /Final commit (?:recorded|persisted)/i,
  locally_applied: /Local application recorded/i,
}
async function progressResponse(w: World, state = 'pending') {
  const order = ['pending', 'needs_selection', 'needs_administrator', 'needs_owner_finalization', 'needs_commit', 'finalizing', 'linked']
  const level = Math.max(0, order.indexOf(state)), outcome = w.joining.outcome
  const request = { request_id: outcome.request_id, role: 'requester', mode: 'new', state,
    network_id: outcome.network_id, context_id: outcome.context_id, migration_proposal_id: '-', person_public_key: outcome.person_public_key,
    // HOST is SHA256 of this canonical32-byte public key (bytes0x02).
    host_public_key: INVITER_KEY, device_public_key: RELAY_KEY,
    created_at: stamp(state === 'expired' ? NOW - 3_601_000 : NOW - 30_000), expires_at: stamp(state === 'expired' ? NOW - 1000 : NOW + 3_570_000),
    request_packet_id: id64('dpk', 60), owner_offer_id: level >= 1 ? id64('dpk', 61) : '-',
    selection_id: level >= 2 ? id64('dpk', 62) : '-', administrator_offer_id: level >= 3 ? id64('dpk', 63) : '-',
    owner_finalization_id: level >= 4 ? id64('dpk', 64) : '-', manifest_id: level >= 4 ? id64('dm', 65) : '-',
    activation_id: level >= 5 ? id64('da', 66) : '-', outcome_id: level >= 6 ? id64('dpk', 67) : '-',
    selection_approved: level >= 2, commit_approved: level >= 5, completed: stages.slice(0, level + 1),
    attention: ['delivery_pending', 'UNTRUSTED_ATTENTION_RUN_THIS'], next: ['UNTRUSTED_NEXT_SIGN_NOW'] }
  return { version: 1, host_id: w.host, flow_id: w.joining.flow_id, review_id: w.joining.review_id,
    context: context(w.parent), observed_at: stamp(Math.floor(w.clock.now() / 1000) * 1000), outcome: clone(outcome), request,
    next_participant: mapping[state][0], next_action: mapping[state][1] }
}
async function published($: Engine, w: World, flowState = 'requested') {
  const ui = await setup($, w)
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: flowState })
  await joinEntry(w, ui); return ui
}
async function noProgress(ui: Pane, label = '') {
  expect(await visible(ui), label).not.toMatch(/Join progress: /)
}
function progressPrivacy(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  scopedIdentityPrivacy(w, shown, runtime, executable, state)
  expect(shown).not.toContain('UNTRUSTED_ATTENTION_RUN_THIS'); expect(shown).not.toContain('UNTRUSTED_NEXT_SIGN_NOW')
  expect(count(w, 'join.identities')).toBe(0); expect(count(w, 'join.create-identity')).toBe(0)
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0)
  for (const command of w.calls.filter(e => e.kind === 'join.progress')) {
    expect(command.payload).toEqual({ flow_id: command.payload.flow_id, context: context(w.parent), review_id: command.payload.review_id })
  }
}

test('publication entry outcome lookup Refresh and nonrequested reviews never implicitly check progress', async ($, on) => {
  const w = fixture(on); const ui = await published($, w)
  expect(await ui.find({ type: 'Button', text: /^Check join progress$/ })).toBeDefined()
  expect(await visible(ui)).toContain('Join request: publication recorded'); await noProgress(ui)
  await press(ui, 'Refresh'); await w.clock.advance(5000); expect(count(w, 'join.progress')).toBe(0)
  for (const state of ['review', 'declined', 'expired', 'invalidated']) {
    await currentProject(ui)
    w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state, expires: state === 'expired' ? NOW - 1000 : NOW + 900_000 })
    await joinEntry(w, ui)
    expect(await ui.find({ type: 'Button', text: /^Check join progress$/ }), state).toBeUndefined()
  }
  expect(count(w, 'join.progress')).toBe(0); progressPrivacy(w, await visible(ui))
})

test('all ten recorded states show exact public progress consent stages and honest next-participant limits', async ($, on) => {
  const w = fixture(on); const ui = await published($, w), normal = w.run
  for (const state of Object.keys(mapping)) {
    const value = await progressResponse(w, state)
    w.run = async (kind, payload, e) => kind === 'join.progress' ? value : normal(kind, payload, e)
    await press(ui, 'Check join progress'); await w.clock.settle()
    const shown = await visible(ui)
    expect(shown).toContain(state === 'linked' ? 'Join progress: Local application recorded' : 'Join progress: ' + state)
    for (const term of [value.observed_at, value.request.network_id, value.request.person_public_key, value.request.host_public_key, value.request.device_public_key]) expect(shown).toContain(term)
    for (const stage of value.request.completed) expect(shown, stage + ': recorded human meaning').toMatch(stageMeaning[stage])
    expect(shown).toMatch(new RegExp('Requester owner selection approved[^\\n]{0,12}\\b' + (value.request.selection_approved ? 'yes' : 'no') + '\\b', 'i'))
    expect(shown).toMatch(new RegExp('Requester final commit approved[^\\n]{0,12}\\b' + (value.request.commit_approved ? 'yes' : 'no') + '\\b', 'i'))
    for (const word of ['advanced', 'snapshot', 'authority', 'agent access', 'reachability', 'model receipt']) expect(shown.toLowerCase()).toContain(word)
    expect(shown).toMatch(/not verified|not establish|unverified/i)
    expect(shown.toLowerCase()).toContain('transport')
    for (const label of [/^Approve/, /^Resume/, /^Commit/, /^Select/]) expect(await ui.find({ type: 'Button', text: label })).toBeUndefined()
    expect(await ui.find({ type: 'Button', text: /^Check join progress$/ })).toBeDefined()
    progressPrivacy(w, shown)
  }
  expect(count(w, 'join.progress')).toBe(10)
})

const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private host state/$(literal)' },
}
test('explicit double Check clears old confirmation synchronously rechecks parent flow host and sends one exact5s private command', configured, async ($, on) => {
  const w = fixture(on); const ui = await published($, w); await press(ui, 'Check join progress')
  const normal = w.run
  w.run = async (kind, payload, e) => { if (kind === 'join.inspect') await w.clock.sleep(1000); return normal(kind, payload, e) }
  const before = count(w, 'join.progress'), at = w.trace.length, button = await key(ui, 'Check join progress')
  const first = ui.press({ key: button }); void first.catch(() => undefined)
  const second = ui.press({ key: button }).catch(() => undefined)
  await w.clock.settle(); await noProgress(ui); expect(await visible(ui)).toContain('Join request: publication recorded')
  expect(count(w, 'join.progress')).toBe(before)
  await w.clock.advance(1000); await Promise.all([first, second]); await w.clock.settle()
  expect(count(w, 'join.progress')).toBe(before + 1)
  expect(last(w, 'join.progress').payload).toEqual({ flow_id: w.joining.flow_id, context: context(w.parent), review_id: w.joining.review_id })
  const trace = w.trace.slice(at), sent = trace.findIndex(event => event.kind === 'join.progress')
  for (const kind of ['project.inspect', 'join.inspect', 'snapshot', 'root', 'native']) expect(trace.slice(0, sent).some(event => event.kind === kind)).toBe(true)
  progressPrivacy(w, await visible(ui), false, configured.options.executable, configured.options.state)
})

test('malformed wrapper LINK_VIEW pins host-key hash mapping booleans stages bounds and private metadata cannot confirm progress', { timeoutMs: 15000 }, async ($, on) => {
  const w = fixture(on); const ui = await published($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['extra', v => { v.private_provider = RAW }], ['host', v => { v.host_id = 'host_' + '9'.repeat(64) }],
    ['context', v => { v.context.native_session_id = 'different-private-native' }], ['flow', v => { v.flow_id = id('flow', 99) }],
    ['review', v => { v.review_id = id64('review', 99) }], ['outcome', v => { v.outcome.request_id = id64('link', 99) }],
    ['request', v => { v.request.request_id = id64('link', 99) }], ['person', v => { v.request.person_public_key = GENESIS_KEY }],
    ['network', v => { v.request.network_id = id64('net', 99) }], ['context-id', v => { v.request.context_id = id64('ctx', 99) }],
    ['role', v => { v.request.role = 'approver' }], ['mode', v => { v.request.mode = 'renew' }], ['migration', v => { v.request.migration_proposal_id = id64('ds', 99) }],
    ['host-hash', v => { v.request.host_public_key = GENESIS_KEY }], ['device-key', v => { v.request.device_public_key = 'bad-key' }],
    ['packet-id', v => { v.request.request_packet_id = id64('dp', 99) }], ['display', v => { v.request.display_code = CODE }],
    ['unknown-state', v => { v.request.state = 'migration_prepared' }], ['participant', v => { v.next_participant = 'network_administrator' }],
    ['action', v => { v.next_action = 'review_final_commit' }], ['boolean', v => { v.request.selection_approved = 'false' }],
    ['duplicate-stage', v => { v.request.completed.push('request_created') }], ['stage-order', v => { v.request.completed = ['owner_offered', 'request_created'] }],
    ['missing-created', v => { v.request.completed = [] }], ['attention-bound', v => { v.request.attention = Array(33).fill('bounded') }],
    ['utf8-bound', v => { v.request.next = ['é'.repeat(513)] }], ['control', v => { v.request.attention = ['bad\ncontrol'] }],
    ['private-osc', v => { v.request.attention = ['\x1b]0;token_\u202eSHORTSECRET\x07visible'] }],
    ['time', v => { v.observed_at = 'not-utc-time' }],
  ]
  for (const [name, mutate] of variants) {
    const value = await progressResponse(w); mutate(value)
    w.run = async (kind, payload, e) => kind === 'join.progress' ? value : normal(kind, payload, e)
    await press(ui, 'Check join progress'); await w.clock.settle(); await noProgress(ui, name)
    expect(await visible(ui), name).toContain('Join progress unavailable')
    expect(await visible(ui), name).toContain('Join request: publication recorded')
    expect(await visible(ui), name).not.toContain('SHORTSECRET'); expect(w.outside.join('\n'), name).not.toContain('SHORTSECRET')
    progressPrivacy(w, await visible(ui))
  }
})

test('maximum bounded attention and next remain data while only delivery_pending is a transport observation', async ($, on) => {
  const w = fixture(on); const ui = await published($, w), normal = w.run, value = await progressResponse(w)
  value.request.attention = ['delivery_pending', ...Array.from({ length: 31 }, (_, n) => 'UNTRUSTED_ATTENTION_' + n)]
  value.request.next = ['é'.repeat(512), ...Array.from({ length: 31 }, (_, n) => 'UNTRUSTED_NEXT_' + n)]
  w.run = async (kind, payload, e) => kind === 'join.progress' ? value : normal(kind, payload, e)
  await press(ui, 'Check join progress'); expect(await visible(ui)).toContain('Join progress: pending')
  expect(await visible(ui)).not.toContain('UNTRUSTED_ATTENTION_'); expect(await visible(ui)).not.toContain('UNTRUSTED_NEXT_')
  expect(await visible(ui)).not.toContain('é'.repeat(512)); progressPrivacy(w, await visible(ui))
})

test('changed parent retained flow outcome host root conversation or surface prevents a captured Check', async ($, on) => {
  const w = fixture(on); const ui = await published($, w), parent = clone(w.parent), normal = w.run
  for (const [index, mode] of ['parent', 'flow', 'outcome', 'host', 'root', 'native', 'surface'].entries()) {
    if (index) await currentProject(ui)
    w.parent = clone(parent); w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
    w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' })
    if (index) await joinEntry(w, ui)
    const button = await key(ui, 'Check join progress'), before = count(w, 'join.progress')
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'flow') w.joining.review_id = id64('review', 99)
    if (mode === 'outcome') w.joining.outcome.request_id = id64('link', 99)
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (['root', 'native', 'surface'].includes(mode)) w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.inspect') {
        if (mode === 'root') w.root = '/changed-private-root'
        if (mode === 'native') w.native = 'changed-private-native'
        if (mode === 'surface') { w.surface = null; w.surfaces = [] }
      }
      return value
    }
    await ui.press({ key: button }).catch(() => undefined); await w.clock.settle()
    expect(count(w, 'join.progress'), mode).toBe(before); await noProgress(ui, mode)
  }
  progressPrivacy(w, await visible(ui))
})

test('denied or raw reads clear old progress preserve publication and require an explicit Check without automatic retry', async ($, on) => {
  const w = fixture(on); const ui = await published($, w), normal = w.run
  for (const mode of ['denied', 'raw']) {
    w.run = normal; await press(ui, 'Check join progress'); expect(await visible(ui)).toContain('Join progress: pending')
    w.run = async (kind, payload, e) => kind === 'join.progress' ? mode === 'denied' ? { fixtureDeny: true } : { fixtureRaw: CODE + RAW } : normal(kind, payload, e)
    await press(ui, 'Check join progress'); await noProgress(ui)
    expect(await visible(ui)).toContain('Join progress unavailable'); expect(await visible(ui)).toContain('Join request: publication recorded')
    const before = count(w, 'join.progress'); await w.clock.advance(5000); expect(count(w, 'join.progress')).toBe(before)
    progressPrivacy(w, await visible(ui))
  }
})

test('Refresh Back Close and reopening discard confirmations without progress polling or loss of public outcome', async ($, on) => {
  const w = fixture(on); let ui = await published($, w); const retained = clone(w.joining)
  for (const mode of ['refresh', 'back', 'close']) {
    await press(ui, 'Check join progress'); const before = count(w, 'join.progress')
    if (mode === 'refresh') await press(ui, 'Refresh')
    if (mode === 'back') { await back(ui); await joinEntry(w, ui) }
    if (mode === 'close') { await press(ui, 'Close'); await ui.unmount(); ui = await enter($, w); await joinEntry(w, ui) }
    await noProgress(ui, mode); expect(await visible(ui)).toContain('Join request: publication recorded')
    expect(count(w, 'join.progress')).toBe(before); expect(w.joining).toEqual(retained)
  }
  progressPrivacy(w, await visible(ui))
})

test('late old progress cannot replace a newer requested outcome confirmation after navigation', async ($, on) => {
  const w = fixture(on); const ui = await published($, w), normal = w.run; let first = true
  let signalOldDelayStarted!: () => void
  const oldDelayStarted = new Promise<void>(resolve => { signalOldDelayStarted = resolve })
  w.run = async (kind, payload, e) => {
    if (kind === 'join.progress') {
      const value = await progressResponse(w, first ? 'linked' : 'cancelled')
      if (first) { first = false; const delay = w.clock.sleep(1000); signalOldDelayStarted(); await delay }
      return value
    }
    return normal(kind, payload, e)
  }
  const pending = press(ui, 'Check join progress'); void pending.catch(() => undefined)
  // The response digest uses real async work. Synchronize after the virtual
  // sleep is registered, before navigation or advancing that same test clock.
  await oldDelayStarted; await w.clock.settle()
  await back(ui); w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: 99 })
  await joinEntry(w, ui); await press(ui, 'Check join progress')
  expect(await visible(ui)).toContain('Join progress: cancelled')
  await w.clock.advance(1000); await pending
  expect(await visible(ui)).toContain('Join progress: cancelled'); expect(await visible(ui)).not.toContain('Local application recorded')
  progressPrivacy(w, await visible(ui))
})

test('historical requested review expiry keeps explicit Check and a snapshot never automatically becomes a live status', async ($, on) => {
  const w = fixture(on); const ui = await published($, w)
  await w.clock.advance(900_001); await press(ui, 'Check join progress')
  expect(await visible(ui)).toContain('Join progress: pending')
  const observed = stamp(Math.floor(w.clock.now() / 1000) * 1000), before = count(w, 'join.progress')
  await w.clock.advance(120_000)
  expect(await visible(ui)).toContain(observed); expect(count(w, 'join.progress')).toBe(before)
  expect(await visible(ui)).toMatch(/snapshot/i); progressPrivacy(w, await visible(ui))
})

test('root conversation host parent surface and session end clear pending progress authority without erasing durable outcomes', async ($, on) => {
  const w = fixture(on); let ui = await published($, w); const parent = clone(w.parent), normal = w.run
  for (const [index, mode] of ['root', 'native', 'host', 'parent', 'surface', 'end'].entries()) {
    if (index) {
      w.parent = clone(parent); w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
      ui = await enter($, w); await joinEntry(w, ui)
    }
    const retained = clone(w.joining), identities = clone(w.identities)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.progress') await w.clock.sleep(1000); return value }
    const pending = press(ui, 'Check join progress'); void pending.catch(() => undefined); await w.clock.settle()
    if (mode === 'root') { w.root = '/changed-private-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'changed-private-native'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    if (mode !== 'root' && mode !== 'end') {
      const refresh = await ui.find({ type: 'Button', text: /^Refresh$/ })
      if (refresh) { const action = ui.press({ key: refresh.key! }); void action.catch(() => undefined); await w.clock.settle() }
    }
    await w.clock.advance(1000); await pending; await noProgress(ui, mode)
    expect(w.joining, mode).toEqual(retained); expect(w.identities, mode).toEqual(identities)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! })
    await ui.unmount()
  }
  progressPrivacy(w)
})

test('explicit progress and pane navigation preserve established message task lease and durable inviter outcomes', async ($, on) => {
  const w = fixture(on); w.networks = [network()]
  const ui = await connected($, w); await enable($, w, ui); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  w.invitation = await invitationFlow(w.parent, w.networks[0], { state: 'issued' }); const issued = clone(w.invitation)
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' }); const requested = clone(w.joining)
  const prompts = w.prompts.length, tools = w.tools.map(tool => tool.name), ready = readyCalls(w).length
  await back(ui); await joinEntry(w, ui); await press(ui, 'Check join progress'); await back(ui); await begin(w, ui)
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length, leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.prompts.length).toBe(prompts); expect(readyCalls(w).length).toBe(ready); expect(w.tools.map(tool => tool.name)).toEqual(tools)
  expect(w.joining).toEqual(requested); expect(w.invitation).toEqual(issued)
  progressPrivacy(w, await visible(ui), true)
})
