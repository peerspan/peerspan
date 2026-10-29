/**
 * Independent section-14 new-original creation fixtures on Claude Code 2.1.303.
 * Public native effects only; no product imports, authentication or inference.
 * Original 184 cases are unchanged. Actual reload/terminal/daemon acceptance is
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
    networks: [] as any[], invitation: null as any, previewValue: null as any, joining: null as any, identities: [] as any[], code: CODE, codes: [CODE, CODE2],
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  w.run = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: stamp(clock.now()), host_id: w.host,
      networks: w.networks, agents: [], requests: [], attention: [] }
    if (kind === 'join.create-identity') {
      w.identities = [{ public_key: KEY, sources: ['generated'] }]
      return { version: 1, host_id: w.host, context: payload.context, identity: clone(w.identities[0]) }
    }
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
    expect(command.init?.timeoutMs).toBe(['join.identities', 'join.create-identity'].includes(command.kind) ? 15000 : 5000)
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
  for (const e of joinCalls(w)) expect(['lookup', 'identities', 'create-identity', 'prepare', 'inspect', 'decide']).toContain(e.kind.split('.')[1])
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

async function creationChooser($: Engine, w: World, existing?: Pane, options: any = {}) {
  const ui = existing ?? await setup($, w)
  w.previewValue = await previewResponse(w, { pin: '-', ...options })
  await joinEntry(w, ui); await joiningIdentities(w, ui); return ui
}
async function creationReview($: Engine, w: World, existing?: Pane, options: any = {}) {
  const ui = await creationChooser($, w, existing, options)
  await press(ui, 'Create a new original identity'); return ui
}
async function noCreation(ui: Pane, label = '') {
  for (const text of [/^Create a new original identity$/, /^Create and save identity$/]) {
    expect(await ui.find({ type: 'Button', text }), label).toBeUndefined()
  }
}
async function noRetry(ui: Pane) {
  expect(await ui.find({ type: 'Button', text: /^Retry\b/i })).toBeUndefined()
  await noCreation(ui); await noJoinDecision(ui)
}

test('only empty unpinned explicit joining offers creation review without generating selecting preparing or publishing', async ($, on) => {
  const w = fixture(on)
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  for (const args of ['create identity', '--create-new-identity', CODE]) await $.command.run({ command: 'peerspan', args })
  denied(await $.tool.call({ tool: 'mcp__peerspan__create_identity', decision: 'create_new_identity' }))
  expect(w.calls).toEqual([])
  const ui = await creationChooser($, w)
  expect(await ui.find({ type: 'Button', text: /^Create a new original identity$/ })).toBeDefined()
  expect(w.identities).toEqual([]); expect(count(w, 'join.create-identity')).toBe(0)
  await press(ui, 'Create a new original identity')
  expect(count(w, 'join.create-identity')).toBe(0); expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0)
  expect(w.identities).toEqual([]); expect(await visible(ui)).not.toContain(KEY)
  expect(await ui.find({ type: 'Button', text: /^Create and save identity$/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /^Cancel identity creation$/ })).toBeDefined()
  await fullTerms(ui, { agent: w.parent.review.agent, invitation: w.previewValue.review })
  const shown = (await visible(ui)).toLowerCase()
  for (const word of ['original', 'computer', 'private', 'save', 'backup', 'copy', 'import', 'link', 'request', 'readiness']) expect(shown).toContain(word)
  expect(shown).toMatch(/back|close/); expect(shown).toMatch(/surviv|remain|persist|still.*sav/)
  scopedIdentityPrivacy(w, await visible(ui))
})

test('available originals pinned invitations and elapsed previews never offer a new-person creation action', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w)
  const variants = [
    { identities: [{ public_key: KEY, sources: ['generated'] }], pin: '-' },
    { identities: [], pin: KEY },
    { identities: [{ public_key: KEY, sources: ['ssh_agent'] }], pin: KEY },
    { identities: [], pin: '-', expires: NOW },
  ]
  for (const [index, variant] of variants.entries()) {
    if (index) await currentProject(ui)
    w.identities = variant.identities
    await creationChooser($, w, ui, variant); await noCreation(ui)
    expect(count(w, 'join.create-identity')).toBe(0); expect(count(w, 'join.prepare')).toBe(0)
  }
  scopedIdentityPrivacy(w, await visible(ui))
})

test('Cancel discards the complete private creation attempt and reopening requires empty fresh input', async ($, on) => {
  const w = fixture(on); const ui = await creationReview($, w)
  const inventory = count(w, 'join.identities')
  await press(ui, 'Cancel identity creation'); await w.clock.settle()
  expect(w.identities).toEqual([]); expect(count(w, 'join.create-identity')).toBe(0)
  expect(await visible(ui)).not.toContain(CODE); await noJoinDecision(ui)
  await currentProject(ui); await joinEntry(w, ui)
  expect((await inputField(ui, 'Private invitation for joining')).props.value ?? '').toBe('')
  expect(count(w, 'join.identities')).toBe(inventory); scopedIdentityPrivacy(w, await visible(ui))
})

const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private host state/$(literal)' },
}
test('double explicit save rechecks zero inventory then sends one exact15s private creation command and only returns public choices', configured, async ($, on) => {
  const w = fixture(on); const ui = await creationReview($, w), normal = w.run
  let waiting = false
  w.run = async (kind, payload, e) => {
    if (kind === 'join.identities' && !waiting) { waiting = true; await w.clock.sleep(1000) }
    return normal(kind, payload, e)
  }
  const at = w.trace.length, before = count(w, 'join.identities'), button = await key(ui, 'Create and save identity')
  const first = ui.press({ key: button }); void first.catch(() => undefined)
  const second = ui.press({ key: button }).catch(() => undefined)
  await w.clock.settle(); expect(waiting).toBe(true); expect(count(w, 'join.create-identity')).toBe(0)
  await w.clock.advance(1000); await Promise.all([first, second]); await w.clock.settle()
  expect(count(w, 'join.create-identity')).toBe(1)
  expect(last(w, 'join.create-identity').payload).toEqual({ context: context(w.parent), decision: 'create_new_identity' })
  expect(count(w, 'join.identities') >= before + 2).toBe(true)
  const trace = w.trace.slice(at), created = trace.findIndex(event => event.kind === 'join.create-identity')
  expect(trace.slice(0, created).some(event => event.kind === 'project.inspect')).toBe(true)
  expect(trace.slice(0, created).some(event => event.kind === 'join.identities')).toBe(true)
  expect(trace.slice(0, created).some(event => event.kind === 'snapshot')).toBe(true)
  expect(trace.slice(created + 1).some(event => event.kind === 'join.identities')).toBe(true)
  expect(await visible(ui)).toContain('New original identity saved'); expect(await visible(ui)).toContain(KEY)
  expect(await ui.find({ type: 'Button', text: new RegExp('^Review identity ' + KEY.replace(/[+]/g, '\\+') + '$') })).toBeDefined()
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0); await noJoinDecision(ui)
  scopedIdentityPrivacy(w, await visible(ui), false, configured.options.executable, configured.options.state)
})

test('post-save inventory accepts generated inclusion plus concurrent agent provenance and other public choices without selecting', async ($, on) => {
  const w = fixture(on); const ui = await creationReview($, w), normal = w.run
  w.run = async (kind, payload, e) => {
    const value = await normal(kind, payload, e)
    if (kind === 'join.create-identity') w.identities = [{ public_key: KEY, sources: ['generated', 'ssh_agent'] }, { public_key: GENESIS_KEY, sources: ['ssh_agent'] }]
    return value
  }
  await press(ui, 'Create and save identity'); await w.clock.settle()
  expect(await visible(ui)).toContain('New original identity saved'); expect(await identityButtons(ui)).toHaveLength(2)
  expect(await visible(ui)).toContain(KEY); expect(await visible(ui)).toContain(GENESIS_KEY)
  expect(count(w, 'join.prepare')).toBe(0); await noJoinDecision(ui); await noCreation(ui)
  scopedIdentityPrivacy(w, await visible(ui))
})

test('saved identity requires separate explicit key choice and publication consent and survives later decline', async ($, on) => {
  const w = fixture(on); const ui = await creationReview($, w)
  await press(ui, 'Create and save identity'); await w.clock.settle()
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0)
  await choose(w, ui); await fullTerms(ui, w.joining.review)
  expect(count(w, 'join.prepare')).toBe(1); expect(count(w, 'join.decide')).toBe(0)
  await press(ui, 'Decline join request'); expect(w.joining.state).toBe('declined')
  expect(w.identities).toEqual([{ public_key: KEY, sources: ['generated'] }])
  await currentProject(ui); w.joining = null; await joinEntry(w, ui); await joiningIdentities(w, ui); await choose(w, ui)
  await press(ui, 'Approve join request'); expect(w.joining.state).toBe('requested')
  expect(await visible(ui)).toContain('Join request: publication recorded')
  expect(count(w, 'join.create-identity')).toBe(1); expect(count(w, 'join.decide')).toBe(2)
  scopedIdentityPrivacy(w, await visible(ui))
})

test('creation reply exact shape host context key provenance and post-save key binding must validate before reporting saved', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w), normal = w.run
  const variants: [string, (value: any) => void][] = [
    ['version', v => { v.version = 2 }], ['extra', v => { v.private_provider = RAW }],
    ['host', v => { v.host_id = 'host_' + '9'.repeat(64) }], ['context', v => { v.context.native_session_id = 'other-private-native' }],
    ['identity-extra', v => { v.identity.path = RAW }], ['key', v => { v.identity.public_key = 'bad-key' }],
    ['different-key', v => { v.identity.public_key = GENESIS_KEY }],
    ['source', v => { v.identity.sources = ['ssh_agent'] }], ['source-extra', v => { v.identity.sources = ['generated', 'ssh_agent'] }],
  ]
  for (const [index, [name, mutate]] of variants.entries()) {
    if (index) await currentProject(ui)
    w.identities = []; w.joining = null
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.create-identity') mutate(value); return value }
    await creationReview($, w, ui); await press(ui, 'Create and save identity'); await w.clock.settle()
    expect(await visible(ui), name).not.toContain('New original identity saved'); await noRetry(ui)
    expect(await visible(ui), name).not.toContain(RAW); expect(count(w, 'join.prepare')).toBe(0)
    expect(w.identities, name + ': invalid reply never erases a saved key').toEqual([{ public_key: KEY, sources: ['generated'] }])
    scopedIdentityPrivacy(w, await visible(ui))
  }
})

test('failed post-save inventory leaves an uncertain nonretrying state and never adopts a key without generated provenance', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w), normal = w.run
  for (const [index, mode] of ['missing', 'agent-only', 'denied'].entries()) {
    if (index) await currentProject(ui)
    w.identities = []; let created = false
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.create-identity') created = true
      if (kind === 'join.identities' && created) return mode === 'denied' ? { fixtureDeny: true }
        : { ...value, identities: mode === 'missing' ? [] : [{ public_key: KEY, sources: ['ssh_agent'] }] }
      return value
    }
    await creationReview($, w, ui); await press(ui, 'Create and save identity'); await w.clock.settle()
    expect(await visible(ui), mode).not.toContain('New original identity saved'); await noRetry(ui)
    expect(await visible(ui), mode).toMatch(/may.*sav|might.*sav|saved.*(?:unknown|unavailable|check)|uncertain/i)
    const before = count(w, 'join.create-identity'); await w.clock.advance(3000); expect(count(w, 'join.create-identity')).toBe(before)
    expect(w.identities).toEqual([{ public_key: KEY, sources: ['generated'] }]); scopedIdentityPrivacy(w, await visible(ui))
  }
})

test('changed zero inventory parent host root conversation surface or elapsed deadline prevents captured creation dispatch', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w), original = clone(w.parent), normal = w.run
  for (const [index, mode] of ['inventory', 'parent', 'host', 'root', 'native', 'surface', 'deadline'].entries()) {
    if (index) await currentProject(ui)
    w.parent = clone(original); w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.identities = []; w.run = normal
    await creationReview($, w, ui)
    const button = await key(ui, 'Create and save identity'), before = count(w, 'join.create-identity')
    if (mode === 'inventory') w.identities = [{ public_key: KEY, sources: ['ssh_agent'] }]
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (['root', 'native', 'surface'].includes(mode)) w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'join.identities') {
        if (mode === 'root') w.root = '/changed-private-root'
        if (mode === 'native') w.native = 'changed-private-native'
        if (mode === 'surface') { w.surface = null; w.surfaces = [] }
      }
      return value
    }
    if (mode === 'deadline') await w.clock.advance(3_540_000)
    await ui.press({ key: button }).catch(() => undefined); await w.clock.settle()
    expect(count(w, 'join.create-identity'), mode).toBe(before); expect(await visible(ui), mode).not.toContain(CODE)
  }
  scopedIdentityPrivacy(w, await visible(ui))
})

test('denied and raw private creation failures require explicit fresh read-only recovery and never automatically retry', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w), normal = w.run
  for (const [index, mode] of ['denied', 'raw'].entries()) {
    if (index) await currentProject(ui)
    w.identities = []
    w.run = async (kind, payload, e) => {
      if (kind !== 'join.create-identity') return normal(kind, payload, e)
      if (mode === 'denied') return { fixtureDeny: true }
      await normal(kind, payload, e); return { fixtureRaw: CODE + RAW }
    }
    await creationReview($, w, ui); await press(ui, 'Create and save identity'); await w.clock.settle(); await noRetry(ui)
    expect(await visible(ui)).toMatch(/unavailable|unknown|uncertain|may.*sav|might.*sav/i)
    expect(await visible(ui)).not.toContain(CODE); expect(await visible(ui)).not.toContain(RAW)
    const calls = w.calls.length; await w.clock.advance(3000); expect(w.calls.length).toBe(calls)
    scopedIdentityPrivacy(w, await visible(ui))
  }
  w.run = normal; await currentProject(ui); await joinEntry(w, ui)
  expect((await inputField(ui, 'Private invitation for joining')).props.value ?? '').toBe('')
  const before = count(w, 'join.create-identity'); await joiningIdentities(w, ui)
  expect(await identityButtons(ui)).toHaveLength(1); await noCreation(ui)
  expect(count(w, 'join.create-identity')).toBe(before); expect(count(w, 'join.prepare')).toBe(0)
  scopedIdentityPrivacy(w, await visible(ui))
})

test('Cancel during pending zero-inventory recheck cancels write authority before dispatch', async ($, on) => {
  const w = fixture(on); const ui = await creationReview($, w), normal = w.run
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.identities') await w.clock.sleep(1000); return value }
  const pending = press(ui, 'Create and save identity'); void pending.catch(() => undefined)
  await w.clock.settle(); expect(count(w, 'join.create-identity')).toBe(0)
  await press(ui, 'Cancel identity creation'); await w.clock.advance(1000); await pending
  expect(count(w, 'join.create-identity')).toBe(0); expect(w.identities).toEqual([])
  expect(await visible(ui)).not.toContain(CODE); scopedIdentityPrivacy(w, await visible(ui))
})

test('Back and Close after dispatch may preserve the approved key but old callbacks cannot populate a newer joining view', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w); const normal = w.run
  for (const [index, mode] of ['back', 'close'].entries()) {
    if (index) await currentProject(ui)
    w.identities = []; w.joining = null; w.run = normal
    await creationReview($, w, ui)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.create-identity') await w.clock.sleep(1000); return value }
    const pending = press(ui, 'Create and save identity'); void pending.catch(() => undefined); await w.clock.settle()
    expect(w.identities).toEqual([{ public_key: KEY, sources: ['generated'] }])
    if (mode === 'back') await back(ui)
    else { await press(ui, 'Close'); await ui.unmount(); ui = await enter($, w) }
    w.previewValue = await previewResponse(w, { pin: '-', member: 'Newer visible attempt' })
    await joinEntry(w, ui); expect((await inputField(ui, 'Private invitation for joining')).props.value ?? '').toBe('')
    await joiningIdentities(w, ui, CODE2)
    expect(await visible(ui)).toContain(quote('Newer visible attempt'))
    await w.clock.advance(1000); await pending
    expect(await visible(ui)).toContain(quote('Newer visible attempt'))
    expect(await visible(ui)).not.toContain('New original identity saved'); expect(await identityButtons(ui)).toHaveLength(1)
    expect(count(w, 'join.prepare')).toBe(0); expect(w.identities).toEqual([{ public_key: KEY, sources: ['generated'] }])
    scopedIdentityPrivacy(w, await visible(ui))
  }
})

test('Refresh abandons the creation review and private code without dispatch or automatic inventory', async ($, on) => {
  const w = fixture(on); const ui = await creationReview($, w)
  const before = count(w, 'join.identities'); await press(ui, 'Refresh'); await w.clock.settle()
  expect(count(w, 'join.create-identity')).toBe(0); expect(count(w, 'join.identities')).toBe(before)
  await noCreation(ui); await noJoinDecision(ui)
  expect((await inputField(ui, 'Private invitation for joining')).props.value ?? '').toBe('')
  scopedIdentityPrivacy(w, await visible(ui))
})

test('fixed invitation expiry clears creation controls and old timers cannot cancel a newer creation review', async ($, on) => {
  const w = fixture(on); const ui = await creationReview($, w, undefined, { expires: NOW + 3000 })
  await w.clock.advance(1000); await back(ui)
  await creationReview($, w, ui, { n: 31, member: 'Newer creation review', expires: NOW + 10_000 })
  await w.clock.advance(2000)
  expect(await visible(ui)).toContain(quote('Newer creation review'))
  expect(await ui.find({ type: 'Button', text: /^Create and save identity$/ })).toBeDefined()
  await w.clock.advance(6999); expect(await ui.find({ type: 'Button', text: /^Create and save identity$/ })).toBeDefined()
  await w.clock.advance(1); await noCreation(ui)
  expect(await visible(ui)).not.toContain(quote('Newer creation review'))
  expect(count(w, 'join.create-identity')).toBe(0); scopedIdentityPrivacy(w, await visible(ui))
})

test('context host parent surface or end after dispatched persistence cannot erase a saved key or revive its old confirmation', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w); const original = clone(w.parent), normal = w.run
  for (const [index, mode] of ['root', 'native', 'host', 'surface', 'parent', 'end'].entries()) {
    if (index) {
      w.parent = clone(original); w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.identities = []; w.joining = null; w.run = normal
      ui = await enter($, w)
    }
    await creationReview($, w, ui)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.create-identity') await w.clock.sleep(1000); return value }
    const pending = press(ui, 'Create and save identity'); void pending.catch(() => undefined); await w.clock.settle()
    expect(w.identities).toEqual([{ public_key: KEY, sources: ['generated'] }])
    if (mode === 'root') { w.root = '/changed-private-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'changed-private-native'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    if (mode !== 'root' && mode !== 'end') {
      const refresh = await ui.find({ type: 'Button', text: /^Refresh$/ })
      if (refresh) { const action = ui.press({ key: refresh.key! }); void action.catch(() => undefined); await w.clock.settle() }
    }
    await w.clock.advance(1000); await pending; await noCreation(ui, mode)
    expect(await visible(ui), mode).not.toContain('New original identity saved')
    expect(w.identities, mode).toEqual([{ public_key: KEY, sources: ['generated'] }]); expect(count(w, 'join.prepare')).toBe(0)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! })
    await ui.unmount()
  }
  scopedIdentityPrivacy(w)
})

test('ordinary creation review save and pane navigation preserve durable inviter and established delivery runtimes', async ($, on) => {
  const w = fixture(on); w.networks = [network()]
  const ui = await connected($, w); await enable($, w, ui); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  w.invitation = await invitationFlow(w.parent, w.networks[0], { state: 'issued' }); const issued = clone(w.invitation)
  const prompts = w.prompts.length, tools = w.tools.map(tool => tool.name), ready = readyCalls(w).length
  await back(ui); await creationReview($, w, ui); await press(ui, 'Create and save identity'); await w.clock.settle()
  await back(ui); await begin(w, ui)
  expect(w.invitation).toEqual(issued); expect(await ui.find({ type: 'Button', text: /^Reveal private invitation$/ })).toBeDefined()
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length, leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.prompts.length).toBe(prompts); expect(readyCalls(w).length).toBe(ready); expect(w.tools.map(tool => tool.name)).toEqual(tools)
  expect(w.identities).toEqual([{ public_key: KEY, sources: ['generated'] }])
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0); expect(count(w, 'invitation.decide')).toBe(0)
  scopedIdentityPrivacy(w, await visible(ui), true)
})
