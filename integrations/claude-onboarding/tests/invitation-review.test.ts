/**
 * Independent section-10 invitation review fixtures on Claude Code 2.1.303.
 * Public native effects only; no product imports, authentication or inference.
 * Original 128 cases are unchanged. Actual reload/terminal/daemon acceptance is
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
    networks: [] as any[], invitation: null as any, code: CODE, codes: [CODE, CODE2],
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  w.run = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: stamp(clock.now()), host_id: w.host,
      networks: w.networks, agents: [], requests: [], attention: [] }
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
async function visible(ui: Pane) { return text(ui) }
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
    expect(command.argv).toEqual([...prefix, ...suffix]); expect(command.init?.timeoutMs).toBe(5000)
    for (const code of w.codes) expect(command.argv.join('\n')).not.toContain(code)
    expect(command.argv).not.toContain(ROOT); expect(command.argv).not.toContain(NATIVE)
    if (command.kind.startsWith('invitation.') && verb !== 'inspect') expect(typeof command.init.stdin).toBe('string')
    if (noun === 'invitation') expect(['lookup', 'prepare', 'inspect', 'decide', 'handoff']).toContain(verb)
  }
  if (!runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  }
}

test('load headless entry Refresh model arguments and unattached projects never begin an invitation', async ($, on) => {
  const w = fixture(on)
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  for (const args of ['invite someone', '--approve-invitation', CODE]) await $.command.run({ command: 'peerspan', args })
  expect(w.calls).toEqual([])
  let ui = await enter($, w); await press(ui, 'Refresh')
  expect(await ui.find({ type: 'Button', text: /^Invite someone$/ })).toBeUndefined()
  const answer = await $.tool.call({ tool: 'mcp__peerspan__invite', invitation: CODE })
  denied(answer); expect(invitationCalls(w)).toEqual([])
  w.parent = await parentFlow({ state: 'review' }); await press(ui, 'Connect this project')
  expect(await ui.find({ type: 'Button', text: /^Invite someone$/ })).toBeUndefined()
  await press(ui, 'Close'); await ui.unmount()
  w.surface = null; w.surfaces = []
  const summary = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'sdk' } })
  w.outside.push(summary.text ?? '', ...(summary.context ?? []))
  expect(invitationCalls(w)).toEqual([]); safe(w)
})

test('attached explicit entry checks current parent and context then performs lookup before a fresh network choice', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w)
  expect(invitationCalls(w)).toEqual([])
  const at = w.trace.length; await begin(w, ui)
  expect(last(w, 'invitation.lookup').payload).toEqual({ context: context(w.parent) })
  const trace = w.trace.slice(at), lookup = trace.findIndex(e => e.kind === 'invitation.lookup')
  expect(trace.slice(0, lookup).some(e => e.kind === 'project.inspect')).toBe(true)
  expect(trace.slice(0, lookup).some(e => e.kind === 'root' && e.value === ROOT)).toBe(true)
  expect(trace.slice(0, lookup).some(e => e.kind === 'native' && e.value === NATIVE)).toBe(true)
  expect(count(w, 'invitation.prepare')).toBe(0); expect(count(w, 'invitation.decide')).toBe(0)
  expect(count(w, 'invitation.handoff')).toBe(0); await noInvitationAuthority(ui)
  safe(w, await visible(ui))
})

test('empty networks require existing administration and duplicate names remain distinct explicit ten-per-page choices', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w, null, { networks: [] }); await begin(w, ui)
  expect(await visible(ui)).toMatch(/network/i); expect(await visible(ui)).toMatch(/creat|administration/i)
  expect(count(w, 'invitation.prepare')).toBe(0); await noInvitationAuthority(ui)
  await back(ui)
  w.networks = Array.from({ length: 12 }, (_, index) => network(index + 1, 'Same "network"'))
  await begin(w, ui)
  const choices = async () => (await ui.findAll({ type: 'Button' })).filter(e => /net_[0-9a-f]{64}/.test(e.text))
  expect((await choices()).length).toBe(10)
  await press(ui, /(?:More|Next).*networks?/i); expect((await choices()).length).toBe(2)
  await press(ui, /Previous.*networks?/i); expect((await choices()).length).toBe(10)
  expect(count(w, 'invitation.prepare')).toBe(0)
  await press(ui, /(?:More|Next).*networks?/i); await selectNetwork(ui, w.networks[10])
  expect((await inputField(ui, 'Invitee label')).props.value).toBe('')
  expect((await inputField(ui, 'Expected person public key')).props.value).toBe('-')
  await edit(ui, 'Invitee label', 'Selected teammate'); await press(ui, 'Review invitation')
  expect(last(w, 'invitation.prepare').payload).toEqual({ context: context(w.parent), network_id: w.networks[10].id,
    member: 'Selected teammate', expected_person_public_key: '-' })
  expect(await visible(ui)).toContain(w.networks[10].id); safe(w, await visible(ui))
})

// Supported by pinned303 despite its published TestOptions declaration omitting options.
const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private host state/$(literal)' },
}
test('draft validation trims Unicode whitespace and only explicit Review sends literal configured argv and private stdin', configured, async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); await begin(w, ui); await selectNetwork(ui, w.networks[0])
  for (const [label, pin] of [['', '-'], ['   ', '-'], ['bad\nlabel', '-'], ['é'.repeat(65), '-'],
    ['valid', 'not-base64'], ['valid', KEY.slice(0, -1)], ['valid', 'AAAAAAAA=']]) {
    await edit(ui, 'Invitee label', label); await edit(ui, 'Expected person public key', pin)
    const review = await ui.find({ type: 'Button', text: /^Review invitation$/ })
    if (review) await ui.press({ key: review.key! })
    expect(count(w, 'invitation.prepare'), 'invalid draft sends nothing').toBe(0)
  }
  await edit(ui, 'Invitee label', '\u2003 Teammate "東京" \u00a0'); await edit(ui, 'Expected person public key', KEY)
  expect(count(w, 'invitation.prepare')).toBe(0)
  await press(ui, 'Review invitation')
  expect(last(w, 'invitation.prepare').payload).toEqual({ context: context(w.parent), network_id: w.networks[0].id,
    member: 'Teammate "東京"', expected_person_public_key: KEY })
  const shown = await visible(ui), review = w.invitation.review
  for (const value of [ROOT, quote(review.agent.name), quote(review.agent.owner), quote(review.agent.capabilities[0]),
    quote(review.network.name), review.network.id, review.network.context_id, review.network.genesis_root_public_key,
    review.inviter_host_public_key, KEY, quote(review.member), review.expires_at,
    review.invitation_expires_at, ...review.transport.bootstrap_addresses, ...review.transport.quic_addresses,
    review.transport.relays[0].address, review.transport.relays[0].public_key,
    review.transport.helpers[0].address, review.transport.helpers[0].public_key]) expect(shown).toContain(value)
  expect(shown).toMatch(/current conversation|this conversation/i)
  for (const label of ['invitation', 'join request', 'membership', 'agent access', 'machine', 'files', 'conversation', 'capability']) expect(shown.toLowerCase()).toContain(label)
  expect(await ui.find({ type: 'Button', text: /^Approve invitation$/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /^Decline invitation$/ })).toBeDefined()
  expect(count(w, 'invitation.decide')).toBe(0); expect(count(w, 'invitation.handoff')).toBe(0)
  safe(w, shown, false, false, configured.options.executable, configured.options.state)
})

test('malformed duplicate network IDs and private metadata cannot become network choices or review authority', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w)
  for (const [index, mode] of ['invalid-id', 'duplicate-id', 'private-name'].entries()) {
    if (index) await back(ui)
    const selected = network()
    if (mode === 'invalid-id') selected.id = 'net_INVALID'
    if (mode === 'private-name') selected.name = '\x1b]0;peerspan-person-\u202einvite-v1.SHORTSECRET\x07visible'
    w.networks = mode === 'duplicate-id' ? [selected, { ...selected, name: 'same ID different name' }] : [selected]
    await begin(w, ui)
    expect((await ui.findAll({ type: 'Button' })).filter(e => /net_[0-9a-f]{64}/.test(e.text)).length).toBe(0)
    expect(await visible(ui)).not.toContain('SHORTSECRET'); await noInvitationAuthority(ui)
  }
  expect(count(w, 'invitation.prepare')).toBe(0); safe(w, await visible(ui))
})

test('lookup and exact review shape binding effects and private-looking hints are validated before decision controls', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w)
  const normal = w.run
  const changes: [string, (flow: any) => void][] = [
    ['extra', f => { f.extra_private = RAW }], ['context', f => { f.review.context.native_session_id = 'other-native' }],
    ['agent', f => { f.review.agent.id = id('agent', 99) }], ['network', f => { f.review.network.id = 'net_BAD' }],
    ['signer-key', f => { f.review.inviter_host_public_key = 'bad-key' }], ['scope', f => { f.review.effects.grant_membership = true }],
    ['unknown-effect', f => { f.review.effects.extra = false }], ['deadline-gap', f => { f.review.invitation_expires_at = stamp(NOW + 1000) }],
    ['result-state', f => { f.state = 'issued'; f.next_action = 'share_private_invitation' }],
    ['private-hint', f => { f.review.transport.helpers[0].address = '\x1b]8;;token_\u202eSHORTSECRET\x07visible\x1b]8;;\x07' }],
    ['unknown-transport', f => { f.review.transport.token = RAW }],
    ['noncanonical-ipv6', f => { f.review.transport.quic_addresses = ['[0:0:0:0:0:0:0:1]:443'] }],
    ['invalid-ipv6', f => { f.review.transport.bootstrap_addresses = ['[2001:db8:::1]:443'] }],
    ['invalid-endpoint', f => { f.review.transport.bootstrap_addresses = ['https://peer.example:443/path'] }],
    ['invalid-relay-key', f => { f.review.transport.relays[0].public_key = 'bad-key' }],
  ]
  for (const [index, [name, mutate]] of changes.entries()) {
    if (index) await back(ui)
    const value = await invitationFlow(w.parent, w.networks[0]); mutate(value)
    value.review_id = await digest('peerspan-invitation-review-v1', value.review)
    w.run = async (kind, payload, e) => kind === 'invitation.lookup'
      ? { version: 1, host_id: HOST, context: context(w.parent), flow: value } : normal(kind, payload, e)
    await begin(w, ui); await noInvitationAuthority(ui)
    expect(await visible(ui), name).not.toContain('SHORTSECRET'); expect(await visible(ui), name).not.toContain(RAW)
  }
  expect(count(w, 'invitation.decide')).toBe(0); expect(count(w, 'invitation.handoff')).toBe(0)
  safe(w, await visible(ui))
})

test('a prepared response must retain the chosen network normalized label and pin without replacing them', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); const normal = w.run
  for (const [index, mode] of ['network', 'member', 'pin'].entries()) {
    if (index) await back(ui)
    w.invitation = null; await begin(w, ui); await draft(w, ui)
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'invitation.prepare') {
        if (mode === 'network') value.review.network.id = id64('net', 99)
        if (mode === 'member') value.review.member = 'different teammate'
        if (mode === 'pin') value.review.expected_person_public_key = KEY
        value.review_id = await digest('peerspan-invitation-review-v1', value.review)
      }
      return value
    }
    await press(ui, 'Review invitation'); await noInvitationAuthority(ui)
    expect(count(w, 'invitation.decide')).toBe(0); expect(count(w, 'invitation.handoff')).toBe(0)
  }
  safe(w, await visible(ui))
})

test('exact double approve or decline reinspects parent and invitation and sends one captured decision without revealing', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w, 'review'); const normal = w.run
  for (const [index, choice] of ['approve', 'decline'].entries()) {
    if (index) { await back(ui); w.invitation = await invitationFlow(w.parent, w.networks[0], { n: 31 }) }
    await begin(w, ui); const captured = clone(w.invitation), at = w.trace.length, before = count(w, 'invitation.decide')
    w.run = async (kind, payload, e) => { if (kind === 'invitation.inspect') await w.clock.sleep(1000); return normal(kind, payload, e) }
    const button = await key(ui, choice === 'approve' ? 'Approve invitation' : 'Decline invitation')
    const first = ui.press({ key: button }); void first.catch(() => undefined)
    const second = ui.press({ key: button }).catch(() => undefined)
    await w.clock.settle(); expect(count(w, 'invitation.decide')).toBe(before)
    await w.clock.advance(1000); await Promise.all([first, second])
    expect(count(w, 'invitation.decide')).toBe(before + 1)
    expect(last(w, 'invitation.decide').payload).toEqual({ flow_id: captured.flow_id, context: context(w.parent),
      review_id: captured.review_id, decision: choice })
    const trace = w.trace.slice(at), sent = trace.findIndex(e => e.kind === 'invitation.decide')
    expect(trace.slice(0, sent).some(e => e.kind === 'project.inspect')).toBe(true)
    expect(trace.slice(0, sent).some(e => e.kind === 'invitation.inspect')).toBe(true)
    const inspected = trace.findIndex(e => e.kind === 'invitation.inspect')
    expect(trace.slice(inspected + 1, sent).some(e => e.kind === 'root')).toBe(true)
    expect(trace.slice(inspected + 1, sent).some(e => e.kind === 'native')).toBe(true)
    expect(w.invitation.state).toBe(choice === 'approve' ? 'issued' : 'declined')
    expect(count(w, 'invitation.handoff')).toBe(0); expect(await visible(ui)).not.toContain(CODE)
    w.run = normal
  }
  safe(w, await visible(ui))
})

test('changed parent review root host terminal or elapsed deadline cannot send the captured decision', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); const originalParent = clone(w.parent)
  for (const [index, mode] of ['parent', 'review', 'root', 'host', 'terminal', 'deadline'].entries()) {
    if (index) {
      // Context loss may already have cleared the private project view.
      const previous = await ui.find({ type: 'Button', text: /^Back\b/ })
      if (previous) await ui.press({ key: previous.key! })
    }
    w.parent = clone(originalParent); w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']
    w.invitation = await invitationFlow(w.parent, w.networks[0]); await begin(w, ui)
    const button = await key(ui, 'Approve invitation'), before = count(w, 'invitation.decide')
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'review') { w.invitation.review.member = 'changed exact review'; w.invitation.review_id = await digest('peerspan-invitation-review-v1', w.invitation.review) }
    if (mode === 'root') w.root = '/changed-private-root'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'terminal') { w.surface = null; w.surfaces = [] }
    if (mode === 'deadline') await w.clock.advance(900_000)
    await ui.press({ key: button }).catch(() => undefined); await w.clock.settle()
    expect(count(w, 'invitation.decide'), mode).toBe(before); expect(count(w, 'invitation.handoff')).toBe(0)
    await noInvitationAuthority(ui)
  }
  safe(w, await visible(ui))
})

test('lost committed decision is unknown until read-only Refresh recovers its retained result without another mint', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w, 'review'); await begin(w, ui); const normal = w.run
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); return kind === 'invitation.decide' ? { fixtureDeny: true } : value }
  await press(ui, 'Approve invitation')
  expect(w.invitation.state).toBe('issued'); expect(await visible(ui)).toMatch(/unknown|unavailable|uncertain/i)
  expect(count(w, 'invitation.decide')).toBe(1); expect(count(w, 'invitation.handoff')).toBe(0)
  w.run = normal; await press(ui, 'Refresh')
  expect(await ui.find({ type: 'Button', text: /^Reveal private invitation$/ })).toBeDefined()
  expect(count(w, 'invitation.prepare')).toBe(0); expect(count(w, 'invitation.decide')).toBe(1)
  expect(count(w, 'invitation.handoff')).toBe(0); safe(w, await visible(ui))
})

test('retained terminal outcomes resume before another explicit proposal and capture exact latest replacement flow', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w)
  for (const [index, state] of ['issued', 'declined', 'expired', 'invalidated'].entries()) {
    if (index) await back(ui)
    w.invitation = await invitationFlow(w.parent, w.networks[0], { n: 40 + index, state })
    const retained = clone(w.invitation); await begin(w, ui)
    expect(count(w, 'invitation.prepare')).toBe(index)
    expect(count(w, 'invitation.decide')).toBe(0); expect(count(w, 'invitation.handoff')).toBe(0)
    await press(ui, state === 'issued' ? 'Invite another person' : 'Review a replacement invitation')
    expect(count(w, 'invitation.prepare')).toBe(index)
    if (state === 'issued') expect(await visible(ui)).toMatch(/(?:not|doesn.t).*revok|older.*(?:valid|expir)|original.*expir/i)
    await draft(w, ui, w.networks[0], 'Next teammate ' + index); await press(ui, 'Review invitation')
    expect(last(w, 'invitation.prepare').payload.replace_flow_id).toBe(retained.flow_id)
  }
  safe(w, await visible(ui))
})

test('issued-only explicit reveal reinspects captured bindings and shows the complete original code only in its terminal drawing', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w, 'issued'); await begin(w, ui)
  expect(await visible(ui)).not.toContain(CODE)
  expect(await visible(ui)).toMatch(/privat/i); expect(await visible(ui)).toMatch(/(?:not|never|don.t).*agent.*conversation|do not paste/i)
  expect(await visible(ui)).toMatch(/(?:no|not).*membership|grants?.*no/i)
  const at = w.trace.length; await press(ui, 'Reveal private invitation')
  expect(await visible(ui)).toContain(CODE)
  expect(last(w, 'invitation.handoff').payload).toEqual({ flow_id: w.invitation.flow_id, context: context(w.parent), review_id: w.invitation.review_id })
  const trace = w.trace.slice(at), retrieved = trace.findIndex(e => e.kind === 'invitation.handoff')
  expect(trace.slice(0, retrieved).some(e => e.kind === 'project.inspect')).toBe(true)
  expect(trace.slice(0, retrieved).some(e => e.kind === 'invitation.inspect')).toBe(true)
  safe(w, await visible(ui), true)
  await press(ui, 'Hide private invitation'); expect(await visible(ui)).not.toContain(CODE)
  await press(ui, 'Reveal private invitation'); expect(await visible(ui)).toContain(CODE)
  expect(count(w, 'invitation.handoff')).toBe(2); expect(count(w, 'invitation.decide')).toBe(0)
  await press(ui, 'Hide private invitation'); safe(w, await visible(ui))
})

test('private handoff version references expiry unknown fields and bounded code syntax must validate before any reveal', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w, 'issued'); await begin(w, ui); const normal = w.run
  const changes: [string, (value: any) => void][] = [
    ['version', v => { v.version = 2 }], ['flow', v => { v.flow_id = id('flow', 99) }],
    ['review', v => { v.review_id = id64('review', 99) }], ['network', v => { v.network_id = id64('net', 99) }],
    ['context', v => { v.context_id = id64('ctx', 99) }], ['invitation', v => { v.invitation_id = id64('di', 99) }],
    ['expiry', v => { v.expires_at = stamp(NOW + 7_200_000) }], ['unknown', v => { v.return_secret = RAW }],
    ['empty', v => { v.invitation = 'psi2-' }], ['padding', v => { v.invitation = CODE + '=' }],
    ['alphabet', v => { v.invitation = 'psi2-SHORTSECRET!' }],
    ['bound', v => { v.invitation = 'psi2-SHORTSECRET' + 'A'.repeat(32768) }],
  ]
  for (const [name, mutate] of changes) {
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'invitation.handoff') mutate(value)
      return value
    }
    await press(ui, 'Reveal private invitation')
    expect(await visible(ui), name).not.toContain('SHORTSECRET'); expect(w.outside.join('\n'), name).not.toContain('SHORTSECRET')
    expect(await visible(ui), name).not.toContain(CODE)
    expect(await visible(ui), name).not.toContain(RAW)
    w.run = normal; await press(ui, 'Refresh')
  }
  w.code = 'psi2-' + 'A'.repeat(32768 - 5); w.codes.push(w.code)
  await press(ui, 'Reveal private invitation'); expect(await visible(ui)).toContain(w.code)
  safe(w, await visible(ui), true); await press(ui, 'Hide private invitation'); safe(w, await visible(ui))
})

async function returnToInvitation($: Engine, w: World, ui?: Pane) {
  const current = ui ?? await enter($, w)
  const connect = await current.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await current.press({ key: connect.key! })
  await begin(w, current); return current
}

test('Hide Refresh Back and Close clear private text and recovery always looks up rather than preparing or deciding', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w, 'issued'); await begin(w, ui)
  await press(ui, 'Reveal private invitation'); await press(ui, 'Hide private invitation')
  expect(await visible(ui)).not.toContain(CODE)
  await press(ui, 'Reveal private invitation'); const normal = w.run
  w.run = async (kind, payload, e) => { if (kind === 'invitation.lookup') await w.clock.sleep(1000); return normal(kind, payload, e) }
  const refresh = press(ui, 'Refresh'); void refresh.catch(() => undefined)
  await w.clock.settle(); expect(await visible(ui)).not.toContain(CODE)
  await w.clock.advance(1000); await refresh; w.run = normal
  expect(count(w, 'invitation.handoff')).toBe(2); expect(await visible(ui)).not.toContain(CODE)
  await press(ui, 'Reveal private invitation'); await back(ui)
  expect(await visible(ui)).not.toContain(CODE)
  ui = await returnToInvitation($, w, ui); expect(await visible(ui)).not.toContain(CODE)
  await press(ui, 'Reveal private invitation'); await press(ui, 'Close')
  expect(await visible(ui)).not.toContain(CODE); await ui.unmount()
  ui = await returnToInvitation($, w); expect(await visible(ui)).not.toContain(CODE)
  expect(count(w, 'invitation.prepare')).toBe(0); expect(count(w, 'invitation.decide')).toBe(0)
  expect(count(w, 'invitation.handoff')).toBe(4); safe(w, await visible(ui))
})

test('denied malformed or raw private process results remain controlled and never appear in errors or transcript', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w, 'issued'); await begin(w, ui); const normal = w.run
  for (const mode of ['denied', 'raw']) {
    w.run = async (kind, payload, e) => kind === 'invitation.handoff'
      ? mode === 'denied' ? { fixtureDeny: true } : { fixtureRaw: CODE + RAW } : normal(kind, payload, e)
    await press(ui, 'Reveal private invitation')
    expect(await visible(ui)).not.toContain(CODE); expect(await visible(ui)).not.toContain(RAW)
    expect(await visible(ui)).toMatch(/unavailable|unknown|invalid|failed/i)
    w.run = normal; await press(ui, 'Refresh')
  }
  safe(w, await visible(ui))
})

test('a late old reveal cannot publish private data or clear a newly opened invitation view', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w, 'issued'); await begin(w, ui)
  const normal = w.run; let first = true
  let signalOldHandoffStarted!: () => void
  const oldHandoffStarted = new Promise<void>(resolve => { signalOldHandoffStarted = resolve })
  w.run = async (kind, payload, e) => {
    const value = await normal(kind, payload, e)
    if (kind === 'invitation.handoff' && first) {
      first = false; const delay = w.clock.sleep(1000)
      signalOldHandoffStarted(); await delay
    }
    return value
  }
  const pending = press(ui, 'Reveal private invitation'); void pending.catch(() => undefined)
  await oldHandoffStarted; await w.clock.settle(); await back(ui)
  w.invitation = await invitationFlow(w.parent, w.networks[0], { n: 99, state: 'issued' }); w.code = CODE2
  ui = await returnToInvitation($, w, ui); await press(ui, 'Reveal private invitation')
  expect(await visible(ui)).toContain(CODE2); expect(await visible(ui)).not.toContain(CODE)
  await w.clock.advance(1000); await pending
  expect(await visible(ui)).toContain(CODE2); expect(await visible(ui)).not.toContain(CODE)
  expect(count(w, 'invitation.decide')).toBe(0); safe(w, await visible(ui), true)
  await press(ui, 'Hide private invitation'); safe(w, await visible(ui))
})

test('revealed issued material uses its invitation deadline after review expiry and obsolete timers cannot hide a newer code', async ($, on) => {
  const w = fixture(on)
  const ui = await setup($, w, 'issued', { expires: NOW - 2_697_000, invitationExpires: NOW + 3000 })
  await begin(w, ui); await press(ui, 'Reveal private invitation')
  expect(await visible(ui)).toContain(CODE)
  await w.clock.advance(1000); await press(ui, 'Hide private invitation')
  w.invitation = await invitationFlow(w.parent, w.networks[0], { n: 99, state: 'issued', expires: NOW - 2_690_000, invitationExpires: NOW + 10_000 })
  w.code = CODE2; await press(ui, 'Refresh'); await press(ui, 'Reveal private invitation')
  await w.clock.advance(2000)
  expect(await visible(ui), 'old deadline cannot hide the newer code').toContain(CODE2)
  await w.clock.advance(6999); expect(await visible(ui)).toContain(CODE2)
  await w.clock.advance(1); expect(await visible(ui)).not.toContain(CODE2)
  const before = count(w, 'invitation.handoff')
  expect(await ui.find({ type: 'Button', text: /^Reveal private invitation$/ })).toBeUndefined()
  await w.clock.advance(60_000); expect(count(w, 'invitation.handoff')).toBe(before)
  safe(w, await visible(ui))
})

test('root conversation host terminal loss and session end hide code and prevent a pending response from restoring it', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w, 'issued'); const normal = w.run
  for (const [index, mode] of ['root', 'native', 'host', 'terminal', 'end'].entries()) {
    if (index) {
      w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
      ui = await enter($, w); await press(ui, 'Connect this project')
    }
    w.invitation = await invitationFlow(w.parent, w.networks[0], { n: 50 + index, state: 'issued' }); await begin(w, ui)
    await press(ui, 'Reveal private invitation'); expect(await visible(ui)).toContain(CODE)
    let pending: Promise<unknown> | null = null
    if (mode === 'native') {
      await press(ui, 'Hide private invitation')
      w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
        if (kind === 'invitation.handoff') await w.clock.sleep(1000); return value }
      pending = press(ui, 'Reveal private invitation'); void pending.catch(() => undefined); await w.clock.settle()
    }
    if (mode === 'root') { w.root = '/different-private-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'different-private-conversation'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'terminal') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    if (mode !== 'root' && mode !== 'end') {
      const refresh = await ui.find({ type: 'Button', text: /^Refresh$/ })
      if (refresh) { const action = ui.press({ key: refresh.key! }); void action.catch(() => undefined); await w.clock.settle() }
    }
    expect(await visible(ui), mode + ': cleared immediately on detected loss').not.toContain(CODE)
    await w.clock.advance(1000); if (pending) await pending
    expect(await visible(ui), mode + ': old result cannot restore code').not.toContain(CODE)
    expect(count(w, 'invitation.decide')).toBe(0)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! })
    await ui.unmount()
  }
  safe(w)
})

test('invitation navigation and private reveal preserve established message task and lease runtimes without additional model work', async ($, on) => {
  const w = fixture(on); w.networks = [network()]
  let ui = await connected($, w); await enable($, w, ui); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  w.invitation = await invitationFlow(w.parent, w.networks[0], { state: 'issued' })
  const hello = w.prompts.length, readyBefore = readyCalls(w).length
  await back(ui); ui = await returnToInvitation($, w, ui)
  await press(ui, 'Reveal private invitation'); await press(ui, 'Hide private invitation'); await back(ui)
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length
  const leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true)
  expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.prompts.length).toBe(hello); expect(readyCalls(w).length).toBe(readyBefore)
  expect(w.tools.length).toBe(9); expect(count(w, 'invitation.prepare')).toBe(0); expect(count(w, 'invitation.decide')).toBe(0)
  safe(w, await visible(ui), false, true)
})

test('an old pending decision inspection cannot approve a different view after Back and a new retained review', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w, 'review'); await begin(w, ui)
  const original = clone(w.invitation), normal = w.run; let held = true
  w.run = async (kind, payload, e) => {
    const value = await normal(kind, payload, e)
    if (kind === 'invitation.inspect' && held) { held = false; await w.clock.sleep(1000) }
    return value
  }
  const pending = press(ui, 'Approve invitation'); void pending.catch(() => undefined)
  await w.clock.settle(); expect(held).toBe(false); await back(ui)
  w.invitation = await invitationFlow(w.parent, w.networks[0], { n: 99 })
  ui = await returnToInvitation($, w, ui); await press(ui, 'Decline invitation')
  expect(count(w, 'invitation.decide')).toBe(1)
  expect(last(w, 'invitation.decide').payload.flow_id).toBe(w.invitation.flow_id)
  expect(last(w, 'invitation.decide').payload.flow_id).not.toBe(original.flow_id)
  expect(last(w, 'invitation.decide').payload.decision).toBe('decline')
  await w.clock.advance(1000); await pending
  expect(count(w, 'invitation.decide')).toBe(1); expect(w.invitation.state).toBe('declined')
  expect(count(w, 'invitation.handoff')).toBe(0); safe(w, await visible(ui))
})
