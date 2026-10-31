/**
 * Independent section40 pinned existing-person machine-request fixtures,303.
 * Contracts11/12/15/40 and independent native fixtures only; no product imports.
 * No real process, network, host, signing, model or installed acceptance here.
 * All381 old native cases and30 host/helper files remain byte-for-byte exact.
 * Actual delayed effects signal dispatch plus virtual-sleep registration.
 * Obsolete drawn closures/microscopic digest-await boundaries and actual reload
 * remain source/manual evidence; fresh modules prove only volatile initial state.
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
  const w = { clock, started: false, starts: 0, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, guardedParent: null as any, child: null as any, sequence: 20,
    networks: [] as any[], previewValue: null as any, joining: null as any, identities: [{ public_key: KEY, sources: ["generated"] }] as any[], code: CODE, codes: [CODE, CODE2],
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
    if (kind === 'join.lookup') return { version: 1, host_id: w.host, context: payload.context, flow: clone(w.joining) }
    if (kind === 'join.identities') return { version: 1, host_id: w.host, context: payload.context, identities: clone(w.identities) }
    if (kind === 'join.inspect') return clone(w.joining)
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
  on('session.start', ($, e) => { w.started = true; w.starts++; return { cwd: e.cwd } })
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
    w.calls.push({ ...e, kind, payload: sent, expectedContext: w.guardedParent ? clone(context(w.guardedParent)) : null,
      expectedProject: w.guardedParent?.flow_id, expectedFlow: w.joining?.flow_id, expectedReview: w.joining?.review_id, expectedAdapter: w.child?.flow_id }); w.trace.push({ kind, payload: sent })
    const value = await w.run(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureExit) return { value: { exitCode: 124, stdout: '', stderr: RAW } }
    if (typeof value?.fixtureRaw === 'string') return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
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
  on('fs.read', () => { w.forbidden.push('fs.read'); return { deny: 'no key reads' } })
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
async function call($: Engine, tool: string, args: any) { return $.tool.call({ tool, ...args }) }
async function connected($: Engine, w: World, savedVerified = false) {
  w.parent = await parentFlow(); w.guardedParent = clone(w.parent); w.child = await adapterFlow(w.parent, { state: 'authorized' })
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
const id64 = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(64, '0')
function network(n = 1, name = 'Network "東京"'): any {
  return { id: id64('net', n), name, mode: 'decentralized', context_id: id64('ctx', n), genesis_root_public_key: GENESIS_KEY,
    root_state_id: id64('drs', n), root_public_key: GENESIS_KEY, root_epoch: 0, member: 'local owner', host_public_key: INVITER_KEY,
    person_public_key: KEY, provider: null, provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'usable', not_after: stamp(NOW + 86_400_000), required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: stamp(NOW - 1000) }
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

const joinCalls = (w: World) => w.calls.filter(e => e.kind.startsWith('join.'))
const previewCalls = (w: World) => w.calls.filter(e => e.kind === 'invitation.preview')
async function button(ui: Pane, label: string | RegExp) {
  return ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
}
async function field(ui: Pane, label: string) {
  const found = (await ui.findAll({ type: 'Input' })).find(e => e.props.label === label)
  expect(found, label).toBeDefined(); return found!
}
async function visible(ui: Pane) { return (await text(ui)) + '\n' + (await ui.findAll({ type: 'Input' })).map(e => e.props.value ?? '').join('\n') }
async function draft(ui: Pane, code = CODE, label = 'Private invitation for this computer', kind: 'change' | 'submit' = 'change') {
  await ui.input({ key: (await field(ui, label)).key!, text: code, kind })
}
async function setup($: Engine, w: World) {
  w.networks = [network()]
  w.parent ??= await parentFlow({ agent: { id: id('agent', 1), name: 'Agent "東京"', owner: 'Owner \\é', capabilities: ['public "metadata"'] } })
  w.guardedParent = clone(w.parent); return open($, w, false)
}
async function project(ui: Pane) {
  const back = await button(ui, /^Back\b/); if (back) await ui.press({ key: back.key! })
  const connect = await button(ui, 'Connect this project'); if (connect) await ui.press({ key: connect.key! })
}
async function machineEntry(ui: Pane) {
  const connect = await button(ui, 'Connect this project'); if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Connect this computer')
}
async function machinePreview(ui: Pane, code = CODE) {
  await draft(ui, code); await press(ui, "Review this computer's identity")
}
async function machineReview($: Engine, w: World) {
  const ui = await setup($, w); await machineEntry(ui); await machinePreview(ui); await press(ui, 'Review machine request'); return ui
}
async function close(ui: Pane) { if (await button(ui, 'Close')) await press(ui, 'Close'); await ui.unmount() }
async function noApprove(ui: Pane, label = '') { expect(await button(ui, 'Approve machine request'), label).toBeUndefined() }
async function noOriginalControls(ui: Pane) {
  for (const label of ['Review owner powers', 'Approve owner powers', 'Sign original owner offer', 'Review original finalization',
    'Sign original finalization', 'Review requester commit', 'Approve requester commit', 'Complete requester commit',
    'Create a new original identity', 'Review joining identities']) expect(await button(ui, label), label).toBeUndefined()
}
async function previewTerms(ui: Pane, review: any) {
  const shown = await visible(ui)
  for (const value of [quote(ROOT), quote(review.agent.name), quote(review.agent.owner), ...review.agent.capabilities.map(quote),
    review.network.id, quote(review.network.name), review.network.context_id, review.network.genesis_root_public_key,
    review.inviter_host_public_key, review.invitation.id, quote(review.invitation.member), review.invitation.expected_person_public_key,
    review.invitation.issued_at, review.invitation.expires_at,
    ...review.contacts.flatMap((c: any) => [c.sequence, c.issued_at, c.expires_at, ...c.quic_addresses, ...c.bootstrap_addresses,
      ...c.relays.flatMap((r: any) => [r.address, r.public_key])]), ...review.helpers.flatMap((h: any) => [h.address, h.public_key])]) expect(shown).toContain(value)
  expect(shown).toContain('Existing person public key')
  expect(shown).toMatch(/pin[\s\S]*(?:not|does not|doesn't)[\s\S]*(?:ownership|own|authority)/i)
  expect(shown).toMatch(/automatic[\s\S]*return/i)
}
async function reviewTerms(ui: Pane, w: World) {
  const review = w.joining.review
  await previewTerms(ui, review.invitation)
  const shown = await visible(ui)
  expect(shown).toContain(review.expires_at); expect(shown).toContain(review.person_public_key)
  expect(shown).toContain('Original person key stays on the existing computer')
  expect(shown).toMatch(/publish|publication/i)
  for (const meaning of ['request', 'owner', 'membership', 'agent access', 'machine', 'files', 'conversation', 'capability'])
    expect(shown.toLowerCase()).toContain(meaning)
  await noOriginalControls(ui)
}
async function recorded(ui: Pane, w: World) {
  const shown = await visible(ui)
  expect(shown).toContain('Machine request: publication recorded')
  expect(shown).toContain('Approval on the existing computer is still required')
  for (const value of Object.values(w.joining.outcome)) expect(shown).toContain(value)
  expect(shown).toMatch(/(?:not|no)[\s\S]*(?:membership|ownership)/i)
  expect(shown).toMatch(/(?:not|no)[\s\S]*(?:permission|access|ready|readiness)/i)
  expect(shown).not.toMatch(/Local application: recorded|Machine (?:connection|request): (?:ready|connected|linked)/i)
  expect(await button(ui, 'Check machine request progress')).toBeDefined(); await noOriginalControls(ui)
}
function privacy(w: World, shown = '', options: { runtime?: boolean; original?: boolean; executable?: string; state?: string } = {}) {
  expect(w.forbidden).toEqual([])
  if (!options.runtime) { expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(t => t.name)).toEqual(Array(w.starts).fill('delivery_acknowledge')) }
  if (!options.original) { expect(count(w, 'join.identities')).toBe(0); expect(count(w, 'join.create-identity')).toBe(0) }
  const outside = w.outside.join('\n') + '\n' + w.prompts.map(p => p.text).join('\n')
  for (const code of w.codes) { expect(shown).not.toContain(code); expect(outside).not.toContain(code) }
  for (const secret of [NATIVE, TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path',
    w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id, w.child?.flow_id, w.child?.review_id,
    w.child?.review.adapter_id, ...w.materials.map(m => m.instance_id)].filter(Boolean)) {
    expect(shown).not.toContain(secret); expect(outside).not.toContain(secret)
  }
  expect(outside).not.toContain(ROOT)
  expect(shown).not.toMatch(/\b(?:flow_[0-9a-f]{32}|review_[0-9a-f]{64}|session_[0-9a-f]{32}|adapter_[0-9a-f]{32})\b/)
  for (const e of w.calls) {
    const prefix = [options.executable ?? 'peerspan', ...(options.state ? ['--state', options.state] : []), 'onboarding']
    const [noun, verb] = e.kind.split('.')
    expect(e.argv).toEqual([...prefix, ...(e.kind === 'snapshot' ? [] : [noun, verb,
      ...(verb === 'inspect' ? [noun === 'project' ? e.expectedProject : noun === 'join' ? e.expectedFlow : e.expectedAdapter] : ['--stdin'])])])
    expect(e.init?.timeoutMs).toBe(e.kind === 'join.identities' ? 15000 : 5000)
    for (const secret of [ROOT, NATIVE, TOKEN, SOCKET, RAW, ...w.codes]) expect(e.argv.join('\n')).not.toContain(secret)
    expect(['snapshot', 'project.lookup', 'project.inspect', 'invitation.preview', 'join.lookup', 'join.inspect', 'join.prepare', 'join.decide', 'join.progress',
      ...(options.original ? ['join.identities'] : []), ...(options.runtime ? ['adapter.lookup', 'adapter.inspect', 'adapter.prepare', 'adapter.decide', 'adapter.transport'] : [])]).toContain(e.kind)
    if (e.kind === 'join.lookup') expect(e.payload).toEqual({ context: e.expectedContext })
    if (e.kind === 'invitation.preview') expect(e.payload).toEqual({ context: e.expectedContext, invitation: e.payload.invitation })
    if (e.kind === 'join.prepare') expect(e.payload).toEqual({ context: e.expectedContext, invitation: e.payload.invitation,
      person_public_key: e.payload.person_public_key, ...(e.payload.replace_flow_id ? { replace_flow_id: e.expectedFlow } : {}) })
    if (e.kind === 'join.decide') expect(e.payload).toEqual({ flow_id: e.expectedFlow, context: e.expectedContext,
      review_id: e.expectedReview, decision: e.payload.decision, ...(e.payload.decision === 'approve' ? { invitation: e.payload.invitation } : {}) })
    if (e.kind === 'join.progress') expect(e.payload).toEqual({ flow_id: e.expectedFlow, context: e.expectedContext, review_id: e.expectedReview })
  }
}
function delayed(w: World, ms = 1000) {
  let signal!: () => void; const started = new Promise<void>(resolve => { signal = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(ms); signal(); return pending } }
}
async function progressResponse(w: World, state = 'pending') {
  const outcome = w.joining.outcome, selected = state === 'needs_selection'
  return { version: 1, host_id: w.host, flow_id: w.joining.flow_id, review_id: w.joining.review_id, context: context(w.parent),
    observed_at: stamp(Math.floor(w.clock.now() / 1000) * 1000), outcome: clone(outcome), request: {
      request_id: outcome.request_id, role: 'requester', mode: 'new', state, network_id: outcome.network_id, context_id: outcome.context_id,
      migration_proposal_id: '-', person_public_key: outcome.person_public_key, host_public_key: INVITER_KEY, device_public_key: RELAY_KEY,
      created_at: stamp(NOW - 30_000), expires_at: stamp(NOW + 3_570_000), request_packet_id: id64('dpk', 60),
      owner_offer_id: selected ? id64('dpk', 61) : '-', selection_id: '-', administrator_offer_id: '-', owner_finalization_id: '-',
      manifest_id: '-', activation_id: '-', outcome_id: '-', selection_approved: false, commit_approved: false,
      completed: selected ? ['request_created', 'owner_offered'] : ['request_created'], attention: [], next: [] },
    next_participant: selected ? 'requesting_machine' : 'person_owner', next_action: selected ? 'review_owner_selection' : 'review_owner_offer' }
}

// 1. This lane is an explicit attached-terminal choice, separate from originals.
test('attached terminal entry is lookup-first and original joining keeps its own inventory requirement', async ($, on) => {
  const w = fixture(on); await $.session.start({ cwd: '/shell', surface: 'terminal', isInteractive: true })
  let ui = await enter($, w)
  expect(await button(ui, 'Connect this computer')).toBeUndefined(); expect(joinCalls(w)).toEqual([]); await close(ui)
  ui = await setup($, w)
  expect(await button(ui, 'Join a network')).toBeDefined(); expect(await button(ui, 'Connect this computer')).toBeDefined()
  expect(joinCalls(w)).toEqual([]); await machineEntry(ui)
  expect(joinCalls(w).map(e => e.kind)).toEqual(['join.lookup'])
  expect((await field(ui, 'Private invitation for this computer')).props.value ?? '').toBe('')
  expect(await visible(ui)).toMatch(/original[\s\S]*(?:existing|other) computer/i)
  expect(previewCalls(w)).toEqual([]); await noOriginalControls(ui)
  await project(ui); await press(ui, 'Join a network'); await draft(ui, CODE, 'Private invitation for joining')
  await press(ui, 'Review joining identities')
  expect(count(w, 'join.identities')).toBe(1); expect(count(w, 'join.prepare')).toBe(0)
  expect(await button(ui, 'Review identity ' + KEY)).toBeDefined()
  await close(ui); w.surface = 'desktop'; w.surfaces = ['desktop']
  const at = w.calls.length
  await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 100 } })
  expect(w.calls.slice(at).filter(e => ['join.lookup', 'invitation.preview', 'join.prepare'].includes(e.kind))).toEqual([])
  privacy(w, '', { original: true })
})

// 2. Enter edits only; one explicit private preview has literal configured argv.
const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private machine state/$(literal)' } }
test('draft Enter is inert and explicit review clears code before one private5s preview with full pinned terms', configured, async ($, on) => {
  const w = fixture(on), ui = await setup($, w); await machineEntry(ui)
  const at = w.calls.length; await draft(ui); await draft(ui, CODE, 'Private invitation for this computer', 'submit')
  expect(w.calls).toHaveLength(at); expect(await visible(ui)).toContain(CODE)
  const normal = w.run, delay = delayed(w)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'invitation.preview') await delay.wait(); return value }
  const pending = press(ui, "Review this computer's identity"); void pending.catch(() => undefined); await delay.started
  expect(await visible(ui)).not.toContain(CODE); expect(previewCalls(w)).toHaveLength(1)
  await w.clock.advance(1000); await pending
  await previewTerms(ui, (await previewResponse(w)).review)
  expect(await button(ui, 'Review machine request')).toBeDefined(); await noApprove(ui)
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.identities')).toBe(0)
  expect(last(w, 'invitation.preview').payload).toEqual({ context: context(w.parent), invitation: CODE })
  privacy(w, await visible(ui), configured.options)
})

// 3. The signed pin is mandatory; lexical and public-time/privacy gates fail closed.
test('invalid oversized unpinned elapsed future or private invitation cannot prepare or repair an identity', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w)
  for (const code of ['psi2-AAA=', ' ' + CODE, 'psi2-' + 'A'.repeat(32764)]) {
    w.codes.push(code); await machineEntry(ui); await draft(ui, code)
    const action = await button(ui, "Review this computer's identity"); if (action) await ui.press({ key: action.key! })
    for (const input of await ui.findAll({ type: 'Input' })) expect(input.props.value ?? '').toBe('')
    expect(previewCalls(w)).toEqual([]); await noApprove(ui); await close(ui); ui = await setup($, w)
  }
  const variants = [
    ['unpinned', { pin: '-' }], ['expired', { expires: NOW - 1000 }],
    ['future', { issued: NOW + 31_000, expires: NOW + 3_631_000 }], ['private', { member: 'token_SHORTMACHINE' }],
  ] as const
  for (const [label, options] of variants) {
    w.previewValue = await previewResponse(w, options); await machineEntry(ui); await machinePreview(ui)
    await noApprove(ui, label); expect(await button(ui, 'Review machine request'), label).toBeUndefined()
    expect(await visible(ui), label).not.toContain('token_SHORTMACHINE')
    if (label === 'unpinned') expect(await visible(ui)).toMatch(/pinned[\s\S]*(?:invitation|existing computer)|(?:invitation|existing computer)[\s\S]*pinned/i)
    await close(ui); ui = await setup($, w)
  }
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0)
  expect(w.outside.join('\n')).not.toContain('SHORTMACHINE'); privacy(w)
})

// 4. Preview never prepares; the separate proposal binds all nested public terms.
test('separate machine review prepares exact preview pin and rejects closed digest or person substitutions', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w); await machineEntry(ui); await machinePreview(ui)
  expect(count(w, 'join.prepare')).toBe(0)
  await press(ui, 'Review machine request'); await reviewTerms(ui, w)
  expect(last(w, 'join.prepare').payload).toEqual({ context: context(w.parent), invitation: CODE, person_public_key: KEY })
  expect(await button(ui, 'Approve machine request')).toBeDefined(); expect(await button(ui, 'Decline machine request')).toBeDefined()
  const normal = w.run
  const variants: [string, (v: any) => void | Promise<void>][] = [
    ['closed', v => { v.extra = true }],
    ['nested-digest', v => { v.review.invitation_review_id = 'review_' + '9'.repeat(64) }],
    ['person', async v => { v.review.person_public_key = GENESIS_KEY; v.review_id = await digest('peerspan-join-review-v1', v.review) }],
  ]
  for (const [label, mutate] of variants) {
    await close(ui); w.joining = null; ui = await setup($, w); await machineEntry(ui); await machinePreview(ui)
    w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e)); if (kind === 'join.prepare') await mutate(value); return value }
    await press(ui, 'Review machine request'); await noApprove(ui, label)
    expect(await visible(ui), label).toMatch(/unavailable|changed|unknown/i); w.run = normal
  }
  expect(count(w, 'join.decide')).toBe(0); privacy(w, await visible(ui))
})

// 5. Publication needs no local original and double press cannot duplicate it.
test('exact one approval without any local original records immutable publication and no ownership or readiness', async ($, on) => {
  const w = fixture(on); w.identities = []
  const ui = await machineReview($, w), review = clone(w.joining.review), normal = w.run, delay = delayed(w)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.decide') await delay.wait(); return value }
  const chosen = await key(ui, 'Approve machine request'), pending = ui.press({ key: chosen })
  void pending.catch(() => undefined); await delay.started
  expect(await visible(ui)).not.toContain(CODE); await ui.press({ key: chosen }).catch(() => undefined)
  await w.clock.advance(1000); await pending
  expect(count(w, 'join.decide')).toBe(1)
  expect(last(w, 'join.decide').payload).toEqual({ flow_id: w.joining.flow_id, context: context(w.parent), review_id: w.joining.review_id,
    decision: 'approve', invitation: CODE })
  expect(w.joining.review).toEqual(review); await recorded(ui, w)
  expect(count(w, 'join.identities')).toBe(0); expect(count(w, 'join.progress')).toBe(0); privacy(w, await visible(ui))
})

// 6. Decline needs no secret; unknown publication always needs explicit lookup.
test('decline without code is single-flight and denied nonzero or lost replies never automatically retry publication', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w)
  w.joining = await joinFlow(w.parent, await previewResponse(w)); await machineEntry(ui)
  await noApprove(ui); const normal = w.run, delay = delayed(w)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.decide') await delay.wait(); return value }
  const chosen = await key(ui, 'Decline machine request'), first = ui.press({ key: chosen }); void first.catch(() => undefined); await delay.started
  await ui.press({ key: chosen }).catch(() => undefined); await w.clock.advance(1000); await first
  expect(last(w, 'join.decide').payload).toEqual({ flow_id: w.joining.flow_id, context: context(w.parent), review_id: w.joining.review_id, decision: 'decline' })
  expect(count(w, 'join.prepare')).toBe(0); expect(w.joining.state).toBe('declined'); expect(count(w, 'join.decide')).toBe(1)
  for (const fault of ['deny', 'nonzero', 'lost']) {
    await close(ui); w.run = normal; w.joining = null; ui = await machineReview($, w)
    const before = count(w, 'join.decide')
    w.run = async (kind, payload, e) => {
      if (kind !== 'join.decide') return normal(kind, payload, e)
      if (fault === 'lost') { await normal(kind, payload, e); return { fixtureRaw: RAW } }
      return fault === 'deny' ? { fixtureDeny: true } : { fixtureExit: true }
    }
    await press(ui, 'Approve machine request'); await noApprove(ui, fault)
    expect(await visible(ui)).not.toContain(CODE)
    const at = w.calls.length; await w.clock.advance(1000); expect(w.calls).toHaveLength(at); expect(count(w, 'join.decide')).toBe(before + 1)
    await close(ui); w.run = normal; const recover = w.calls.length; ui = await setup($, w); await machineEntry(ui)
    expect(w.calls.slice(recover).filter(e => ['join.prepare', 'join.decide', 'invitation.preview', 'join.identities'].includes(e.kind))).toEqual([])
    expect(count(w, 'join.decide')).toBe(before + 1)
  }
  privacy(w, await visible(ui))
})

// 7. Retained review recovery is exact identical prepare, never another preview.
test('retained live review needs exact code reentry and unpinned or mismatched history cannot become machine consent', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w)
  w.joining = await joinFlow(w.parent, await previewResponse(w)); const original = clone(w.joining)
  await machineEntry(ui); await noApprove(ui); expect(await button(ui, 'Decline machine request')).toBeDefined()
  const normal = w.run
  w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e))
    if (kind === 'join.prepare') { value.review.expires_at = stamp(Date.parse(value.review.expires_at) - 1000)
      value.review_id = await digest('peerspan-join-review-v1', value.review) } return value }
  await draft(ui); await press(ui, 'Check invitation for this machine request'); await noApprove(ui)
  expect(w.joining).toEqual(original); await close(ui); w.run = normal; ui = await setup($, w); await machineEntry(ui)
  await draft(ui); await press(ui, 'Check invitation for this machine request')
  expect(previewCalls(w)).toEqual([]); expect(w.joining).toEqual(original); expect(count(w, 'join.prepare')).toBe(2)
  expect(last(w, 'join.prepare').payload).toEqual({ context: context(w.parent), invitation: CODE, person_public_key: KEY })
  expect(await button(ui, 'Approve machine request')).toBeDefined(); await press(ui, 'Approve machine request'); await recorded(ui, w)
  for (const [pin, person] of [['-', KEY], [KEY, GENESIS_KEY]]) {
    await close(ui); const preview = await previewResponse(w, { pin }); w.joining = await joinFlow(w.parent, preview, person, { state: 'requested' })
    const retained = clone(w.joining), at = w.calls.length; ui = await setup($, w); await machineEntry(ui)
    await noApprove(ui); expect(await visible(ui)).toMatch(/pinned|mismatch|unavailable|changed/i)
    expect(w.joining).toEqual(retained)
    expect(w.calls.slice(at).filter(e => ['join.prepare', 'join.decide', 'invitation.preview', 'join.identities'].includes(e.kind))).toEqual([])
  }
  privacy(w, await visible(ui))
})

// 8. Public recovery is read-only and every reopening makes the lane explicit.
test('Refresh Close and reopen recover only public pinned state without code inventory preparation or original controls', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w)
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' }); const retained = clone(w.joining)
  await machineEntry(ui); await recorded(ui, w)
  const at = w.calls.length; await press(ui, 'Refresh'); await recorded(ui, w)
  expect(w.calls.slice(at).filter(e => ['join.prepare', 'join.decide', 'invitation.preview', 'join.progress', 'join.identities'].includes(e.kind))).toEqual([])
  await close(ui); ui = await setup($, w)
  expect(await button(ui, 'Connect this computer')).toBeDefined()
  expect(await visible(ui)).not.toContain('Machine request: publication recorded')
  await machineEntry(ui); await recorded(ui, w); expect(w.joining).toEqual(retained)
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0); privacy(w, await visible(ui))
})

// 9. Progress only observes. A replacement is a separate explicit latest-ID act.
test('explicit pure progress shows next participant and replacement preserves the earlier request with exact latest ID', async ($, on) => {
  const w = fixture(on), ui = await setup($, w)
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' }); const previous = clone(w.joining)
  await machineEntry(ui); const normal = w.run, at = w.calls.length
  await press(ui, 'Check machine request progress')
  expect(count(w, 'join.progress')).toBe(1); expect(await visible(ui)).toMatch(/person owner|original owner|existing (?:person|computer)/i)
  expect(w.calls.slice(at).filter(e => !['snapshot', 'project.inspect', 'join.inspect', 'join.progress'].includes(e.kind))).toEqual([])
  w.run = async (kind, payload, e) => kind === 'join.progress' ? progressResponse(w, 'needs_selection') : normal(kind, payload, e)
  await press(ui, 'Check machine request progress'); await noOriginalControls(ui)
  expect(await visible(ui)).toMatch(/requesting (?:machine|computer)|this (?:machine|computer)/i)
  await press(ui, 'Review another machine request')
  expect((await field(ui, 'Private invitation for this computer')).props.value ?? '').toBe('')
  expect(await visible(ui)).toMatch(/(?:not|does not|doesn't)[\s\S]*(?:cancel|revoke)/i)
  await machinePreview(ui, CODE2); await press(ui, 'Review machine request')
  expect(last(w, 'join.prepare').payload).toEqual({ context: context(w.parent), invitation: CODE2, person_public_key: KEY, replace_flow_id: previous.flow_id })
  expect(w.joining.flow_id).not.toBe(previous.flow_id); expect(previous.outcome).toEqual({ request_id: id64('link', 60),
    network_id: previous.review.invitation.network.id, context_id: previous.review.invitation.network.context_id, person_public_key: KEY })
  expect(count(w, 'join.decide')).toBe(0); await reviewTerms(ui, w); privacy(w, await visible(ui))
})

// 10. Original deadlines stay fixed through actual guarded async intervals.
test('fixed invitation and review expiry forbid late approval and old delayed preparation cannot restore a newer draft', async ($, on) => {
  const w = fixture(on); let ui = await setup($, w)
  w.previewValue = await previewResponse(w, { expires: NOW + 2000 }); await machineEntry(ui); await machinePreview(ui)
  const first = w.calls.length; await w.clock.advance(2000)
  expect(await button(ui, 'Review machine request')).toBeUndefined(); await noApprove(ui); expect(w.calls).toHaveLength(first)
  await close(ui); w.previewValue = null; w.joining = null; ui = await setup($, w); await machineEntry(ui); await machinePreview(ui)
  const normal = w.run
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
    if (kind === 'join.prepare') { w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { expires: w.clock.now() + 2000 }); return clone(w.joining) } return value }
  await press(ui, 'Review machine request'); const delay = delayed(w, 3000), before = count(w, 'join.decide'); let gated = false
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
    if (kind === 'project.inspect' && !gated) { gated = true; await delay.wait() } return value }
  const pending = press(ui, 'Approve machine request'); void pending.catch(() => undefined); await delay.started
  await w.clock.advance(3000); await pending; await noApprove(ui); expect(count(w, 'join.decide')).toBe(before)
  await close(ui); w.run = normal; w.joining = null
  w.previewValue = await previewResponse(w, { expires: w.clock.now() + 2000 }); ui = await setup($, w); await machineEntry(ui); await machinePreview(ui)
  const late = delayed(w, 3000)
  w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e)); if (kind === 'join.prepare') await late.wait(); return value }
  const old = press(ui, 'Review machine request'); void old.catch(() => undefined); await late.started
  await close(ui); w.run = normal; w.joining = null; w.previewValue = await previewResponse(w, { n: 31, expires: w.clock.now() + 60_000 })
  ui = await setup($, w); await machineEntry(ui); await machinePreview(ui, CODE2)
  await w.clock.advance(3000); await old
  expect(await button(ui, 'Review machine request')).toBeDefined(); await noApprove(ui)
  expect(await visible(ui)).not.toContain(CODE); expect(await visible(ui)).not.toContain(CODE2); privacy(w, await visible(ui))
})

// 11. Every stimulus awaits real dispatch; no invented retained handler is used.
test('pending root conversation parent host terminal and end changes discard callback authority without mutation or secret echo', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['root', 'native', 'parent', 'host', 'surface', 'end']) {
    w.run = normal; w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.parent = await parentFlow(); w.joining = null
    const ui = await setup($, w); await machineEntry(ui); await draft(ui)
    const delay = delayed(w)
    w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e)); if (kind === 'invitation.preview') await delay.wait(); return value }
    const pending = press(ui, "Review this computer's identity"); void pending.catch(() => undefined); await delay.started
    if (mode === 'root') w.root = '/different-machine-root'
    if (mode === 'native') w.native = 'different-machine-conversation'
    if (mode === 'parent') w.parent = await parentFlow({ n: 99 })
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') { await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } }); w.started = false }
    await w.clock.advance(1000); await pending
    expect(await button(ui, 'Review machine request'), mode).toBeUndefined(); await noApprove(ui, mode)
    expect(await visible(ui), mode).not.toContain(CODE); await close(ui)
  }
  expect(count(w, 'join.prepare')).toBe(0); expect(count(w, 'join.decide')).toBe(0); privacy(w)
})

// 12. Optional human request work cannot widen or restart the established runtime.
test('machine publication progress and navigation preserve established message task and lease behavior without extra tools or model work', async ($, on) => {
  const w = fixture(on), ui = await connected($, w); await enable($, w, ui)
  await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  const prompts = w.prompts.length, tools = w.tools.map(t => t.name), ready = readyCalls(w).length
  const child = clone(w.child.review), material = clone(w.materials[0])
  await press(ui, /^Back to project$/); await machineEntry(ui); await machinePreview(ui); await press(ui, 'Review machine request')
  await press(ui, 'Approve machine request'); await recorded(ui, w); await press(ui, 'Check machine request progress')
  await noOriginalControls(ui); await project(ui)
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length, leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.prompts).toHaveLength(prompts); expect(readyCalls(w)).toHaveLength(ready); expect(w.tools.map(t => t.name)).toEqual(tools)
  expect(w.child.review).toEqual(child); expect(w.materials).toEqual([material]); expect(w.joining.state).toBe('requested')
  for (const e of w.httpCalls) {
    expect(e.init.socketPath).toBe(SOCKET); expect(e.url.startsWith('http://peerspan/adapter/v1/')).toBe(true)
    const headers = Object.fromEntries(Object.entries(e.init.headers).map(([key, value]) => [key.toLowerCase(), value]))
    expect(headers.authorization).toBe('Bearer ' + TOKEN); expect(headers['x-peerspan-instance']).toBe(material.instance_id)
  }
  privacy(w, await visible(ui), { runtime: true })
})
