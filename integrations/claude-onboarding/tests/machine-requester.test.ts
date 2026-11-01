/**
 * Independent GU.impl48 native public-mock conformance, pinned303.
 * Sections45–48 and independent native test foundations only; no product
 * imports, hosts/processes/network/signing/model execution or storage.
 * All415 old cases and all host/helper/native files remain byte-exact.
 * Mocks exercise closed projections/digests/pins and explicit UI effects;
 * real crypto/persistence/installed/reload/two-machine/model acceptance,
 * microscopic final-await races and obsolete rendered handlers remain
 * host/source/manual limits. Delays signal actual dispatch+sleep registration.
 * Public receipt/intent/digests are human-pane terms; join/project/session
 * plumbing and all private material stay out of the pane and outside output.
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
    consentValue: null as any, lastInspection: null as any, requestState: 'needs_commit',
    requestCreated: NOW - 30_000, requestExpiry: NOW + 3_570_000, stageDeadline: NOW + 570_000,
    powersEnd: NOW + 2 * 86_400_000, providerKind: 'device', folded: true, reused: false, observed: null as number | null,
    networks: [] as any[], previewValue: null as any, joining: null as any, identities: [{ public_key: KEY, sources: ["generated"] }] as any[], code: CODE, codes: [CODE, CODE2],
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  w.run = async (kind, payload) => {
    if (kind === LOOKUP) return machineResponse(w)
    if (kind === INSPECT) { w.lastInspection = await machineInspection(w); return clone(w.lastInspection) }
    if (kind === PREPARE) { w.consentValue ??= await consentRecord(w); return machineResponse(w) }
    if (kind === APPROVE) {
      w.consentValue = { ...w.consentValue, state: 'approved', next_action: 'follow_machine_link' }
      return machineResponse(w)
    }
    if (kind === COMPLETE) {
      w.requestState = 'linked'; const value = await machineResponse(w)
      return { ...value, completion: { state: 'locally_applied', review_id: w.consentValue.review_id,
        manifest_id: value.request.manifest_id, activation_id: value.request.activation_id, outcome_id: value.request.outcome_id,
        participant_delivery: 'not_verified', agent_access: 'not_verified', connection_readiness: 'not_verified' } }
    }
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
    const kind = tail[0] === 'join' && tail[1] === 'machine-commit' ? tail.slice(0, 3).join('.') : tail.length ? tail[0] + '.' + tail[1] : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    // Capture the serialized request independently of synthetic response
    // mutations; a real process stdout cannot mutate its already-sent stdin.
    const sent = payload === undefined ? undefined : clone(payload)
    w.calls.push({ ...e, kind, payload: sent, expectedContext: w.guardedParent ? clone(context(w.guardedParent)) : null,
      expectedProject: w.guardedParent?.flow_id, expectedFlow: w.joining?.flow_id, expectedReview: w.joining?.review_id, expectedAdapter: w.child?.flow_id, expectedInspection: w.lastInspection?.review_id, expectedConsent: w.consentValue?.review_id }); w.trace.push({ kind, payload: sent })
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
    inviter_host_public_key: HELPER_KEY,
    invitation: { id: id64('di', options.n ?? 30), member: options.member ?? 'Invited "é東京" member',
      expected_person_public_key: options.pin ?? KEY, issued_at: stamp(options.issued ?? Math.min(NOW - 120_000, w.requestCreated - 1000)),
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

const LOOKUP = 'join.machine-commit.lookup', INSPECT = 'join.machine-commit.inspect'
const PREPARE = 'join.machine-commit.prepare', APPROVE = 'join.machine-commit.approve', COMPLETE = 'join.machine-commit.complete'
const inspectionEffects = { verify_existing_owner: true, verify_requester_selection: true,
  verify_host_admission: true, verify_owner_finalization: true, prepare_commit_intent: false,
  approve_commit_intent: false, sign_requester_commit: false, publish_requester_commit: false,
  apply_network: false, grant_membership: false, grant_machine_powers: false, grant_agent_access: false,
  share_files: false, share_conversation: false, capability_calls: false }
const consentEffects = { approve_commit_intent: true, authorize_binding_host_signature: true,
  authorize_requester_commit_signatures: true, authorize_commit_publication: true, authorize_local_application: true,
  grant_agent_access: false, share_files: false, share_conversation: false, capability_calls: false }
const observed = (w: World) => stamp(w.observed ?? Math.floor(w.clock.now() / 1000) * 1000)
function requestView(w: World) {
  const terminal = ['expired', 'cancelled', 'blocked'].includes(w.requestState)
  const order = ['pending', 'needs_selection', 'needs_owner_finalization', 'needs_commit', 'finalizing', 'linked']
  const level = terminal ? 3 : Math.max(0, order.indexOf(w.requestState)), outcome = w.joining.outcome
  const completed = ['request_created', ...(level >= 1 ? ['owner_offered'] : []), ...(level >= 2 ? ['owner_selected'] : []),
    ...(!w.folded && level >= 3 ? ['administrator_offered'] : []), ...(level >= 3 ? ['owner_finalized'] : []),
    ...(level >= 4 ? ['commit_persisted'] : []), ...(level >= 5 ? ['locally_applied'] : [])]
  return { request_id: outcome.request_id, role: 'requester', mode: 'new', state: w.requestState,
    network_id: outcome.network_id, context_id: outcome.context_id, migration_proposal_id: '-',
    person_public_key: outcome.person_public_key, host_public_key: INVITER_KEY, device_public_key: RELAY_KEY,
    created_at: stamp(w.requestCreated), expires_at: stamp(w.requestExpiry), request_packet_id: id64('dpk', 60),
    owner_offer_id: level >= 1 ? id64('dpk', 61) : '-', selection_id: level >= 2 ? id64('dpk', 62) : '-',
    administrator_offer_id: !w.folded && level >= 3 ? id64('dpk', 63) : '-', owner_finalization_id: level >= 3 ? id64('dpk', 64) : '-',
    manifest_id: level >= 4 ? id64('dm', 65) : '-', activation_id: level >= 4 ? id64('da', 66) : '-',
    outcome_id: level >= 5 ? id64('dpk', 67) : '-', selection_approved: level >= 2,
    commit_approved: w.consentValue?.state === 'approved' || level >= 4, completed, attention: [], next: [] }
}
async function progressResponse(w: World) {
  const mapping: Record<string, [string, string]> = { pending: ['person_owner', 'review_owner_offer'],
    needs_selection: ['requesting_machine', 'review_owner_selection'], needs_owner_finalization: ['person_owner', 'review_owner_finalization'],
    needs_commit: ['requesting_machine', 'review_final_commit'], finalizing: ['host', 'await_local_application'],
    linked: ['requesting_machine', 'inspect_access_readiness'], expired: ['requesting_machine', 'review_replacement'],
    cancelled: ['requesting_machine', 'review_replacement'], blocked: ['local_owner', 'inspect_advanced_status'] }
  return { version: 1, host_id: w.host, flow_id: w.joining.flow_id, review_id: w.joining.review_id,
    context: context(w.parent), observed_at: observed(w), outcome: clone(w.joining.outcome), request: requestView(w),
    next_participant: mapping[w.requestState][0], next_action: mapping[w.requestState][1] }
}
async function machineInspection(w: World) {
  const request = requestView(w), invitation = w.joining.review.invitation
  const original = w.providerKind === 'original_person'
  const review = { version: 1, kind: 'inspect_existing_person_requester_commit', host_id: w.host,
    context: context(w.parent), agent: clone(w.parent.review.agent), flow_id: w.joining.flow_id,
    join_review_id: w.joining.review_id, request_id: request.request_id, network: clone(invitation.network),
    member: invitation.invitation.member, person_public_key: request.person_public_key,
    host_public_key: request.host_public_key, device_public_key: request.device_public_key,
    request_packet_id: request.request_packet_id, owner_offer_id: request.owner_offer_id, selection_id: request.selection_id,
    administrator_offer_id: request.administrator_offer_id, owner_finalization_id: request.owner_finalization_id,
    owner_root_state_id: id64('ds', 101), root_state_id: id64('ds', 101), person_lease_id: id64('ds', 102),
    host_lease_id: id64('ds', 103), binding_lease_id: id64('ds', 104), device_lease_id: id64('ds', 105),
    owner_provider: { kind: w.providerKind, person_public_key: request.person_public_key, host_public_key: HELPER_KEY,
      device_public_key: original ? '-' : GENESIS_KEY, lease_id: id64('ds', original ? 102 : 150),
      root_state_id: id64('ds', 101), scopes: w.folded ? 15 : 7, not_after: stamp(w.powersEnd) },
    host_admission: w.folded ? 'folded_owner' : 'separate_administrator', reused_binding: w.reused,
    scopes: 7, binding_scopes: 2, not_after: stamp(Math.min(w.requestCreated + 7 * 86_400_000, w.powersEnd)),
    created_at: request.created_at, expires_at: request.expires_at, request_stage_deadline: stamp(w.stageDeadline),
    effects: clone(inspectionEffects) }
  return { version: 1, host_id: w.host, context: context(w.parent), flow_id: w.joining.flow_id,
    join_review_id: w.joining.review_id, observed_at: observed(w), request,
    review_id: await digest('peerspan-machine-requester-inspection-v1', review), review,
    next_action: 'review_machine_requester_consent' }
}
async function consentRecord(w: World, options: any = {}) {
  const inspection = w.lastInspection ?? await machineInspection(w), created = options.created ?? NOW - 1000
  const review = { version: 1, kind: 'approve_existing_person_requester_commit', consent_id: id('dint', options.n ?? 81),
    host_id: w.host, context: context(w.parent), agent: clone(w.parent.review.agent), flow_id: w.joining.flow_id,
    join_review_id: w.joining.review_id, request_id: w.joining.outcome.request_id, intent_id: id('dint', options.n ? options.n + 1 : 82),
    inspection_review_id: inspection.review_id, inspection: clone(inspection.review), created_at: stamp(created),
    expires_at: stamp(Math.min(created + 900_000, w.requestExpiry, w.stageDeadline, Date.parse(inspection.review.not_after))),
    effects: clone(consentEffects) }
  const state = options.state ?? 'review'
  return { consent_id: review.consent_id, review_id: await digest('peerspan-machine-requester-consent-v1', review), review, state,
    next_action: state === 'review' ? 'approve_machine_requester_commit' : state === 'approved' ? 'follow_machine_link' : 'inspect_machine_link' }
}
async function machineResponse(w: World) {
  const consent = clone(w.consentValue)
  if (consent?.state === 'review' && Date.parse(consent.review.expires_at) <= w.clock.now()) {
    consent.state = 'expired'; consent.next_action = 'inspect_machine_link'
  }
  return { version: 1, host_id: w.host, context: context(w.parent), flow_id: w.joining.flow_id,
    join_review_id: w.joining.review_id, observed_at: observed(w), request: requestView(w), consent }
}
const countMachine = (w: World, operation?: string) => w.calls.filter(e => operation ? e.kind === 'join.machine-commit.' + operation : e.kind.startsWith('join.machine-commit.'))
const mutations = (w: World) => w.calls.filter(e => [PREPARE, APPROVE, COMPLETE].includes(e.kind))
const button = (ui: Pane, label: string) => ui.find({ type: 'Button', text: new RegExp('^' + label + '$') })
const visible = text
async function close(ui: Pane) { if (await button(ui, 'Close')) await press(ui, 'Close'); await ui.unmount() }
function delayed(w: World, ms = 1000) {
  let signal!: () => void; const started = new Promise<void>(resolve => { signal = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(ms); signal(); return pending } }
}
async function published($: Engine, w: World, options: any = {}) {
  if (options.deadline) { w.requestExpiry = options.deadline; w.requestCreated = options.deadline - 3_600_000 }
  if (options.stageDeadline) w.stageDeadline = options.stageDeadline
  w.requestState = options.requestState ?? 'needs_commit'
  w.parent ??= await parentFlow({ agent: { id: id('agent', 1), name: 'Agent "東京"', owner: 'Owner \\é', capabilities: ['public "metadata"'] } })
  w.guardedParent = clone(w.parent)
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: options.n ?? 60 })
  if (options.consent) w.consentValue = await consentRecord(w, { state: options.consent, ...options })
  const ui = await open($, w, false); await press(ui, 'Connect this computer'); return ui
}
async function review(ui: Pane) { await press(ui, 'Review machine link') }
async function prepared($: Engine, w: World, options: any = {}) {
  const ui = await published($, w, options); await review(ui)
  if (!w.consentValue) await press(ui, 'Review machine requester consent')
  return ui
}
async function check(ui: Pane, w: World) {
  const at = mutations(w).length
  await press(ui, 'Check machine requester consent'); expect(mutations(w)).toHaveLength(at)
}
async function inactive(ui: Pane, label = '') {
  for (const control of ['Review machine requester consent', 'Approve machine requester commit', 'Complete machine requester commit'])
    expect(await button(ui, control), label).toBeUndefined()
}
async function unknown(ui: Pane, w: World) {
  await inactive(ui); expect(await visible(ui)).toMatch(/unknown|unavailable|not confirmed/i)
  expect(await button(ui, 'Check machine requester consent')).toBeDefined()
  expect(await visible(ui)).not.toContain('Local application: recorded'); safe(w, await visible(ui))
}
function safe(w: World, shown = '', options: any = {}) {
  expect(w.forbidden).toEqual([])
  const outside = w.outside.join('\n') + '\n' + w.prompts.map(p => p.text).join('\n')
  for (const value of [NATIVE, TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path', ...w.codes,
    w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id, w.joining?.flow_id, w.joining?.review_id,
    w.child?.flow_id, w.child?.review_id, w.child?.review.adapter_id].filter(Boolean)) {
    expect(shown).not.toContain(value); expect(outside).not.toContain(value)
  }
  expect(outside).not.toContain(ROOT)
  for (const value of [w.consentValue?.consent_id, w.consentValue?.review_id,
    w.consentValue?.review.intent_id, w.consentValue?.review.inspection_review_id].filter(Boolean)) expect(outside).not.toContain(value)
  for (const e of w.calls) {
    const prefix = [options.executable ?? 'peerspan', ...(options.state ? ['--state', options.state] : []), 'onboarding']
    expect(e.init?.timeoutMs, e.kind).toBe(e.kind === COMPLETE ? 95000 : 5000)
    if (e.kind === 'snapshot') expect(e.argv).toEqual(prefix)
    else if (['project.inspect', 'join.inspect', 'adapter.inspect'].includes(e.kind)) {
      const ref = e.kind === 'project.inspect' ? e.expectedProject : e.kind === 'join.inspect' ? e.expectedFlow : e.expectedAdapter
      expect(e.argv).toEqual([...prefix, e.kind.split('.')[0], 'inspect', ref])
    } else expect(e.argv).toEqual([...prefix, ...e.kind.split('.'), '--stdin'])
    expect(e.kind).not.toMatch(/identit|owner|\.commit\.|resume|\.sign$/)
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, ...w.codes, w.consentValue?.consent_id, w.consentValue?.review_id].filter(Boolean))
      expect(e.argv.join('\n')).not.toContain(value)
    if (e.kind.startsWith('join.machine-commit.')) {
      expect(e.payload).toEqual({ context: e.expectedContext, flow_id: e.expectedFlow, join_review_id: e.expectedReview,
        ...(e.kind === PREPARE ? { inspection_review_id: e.expectedInspection } : {}),
        ...([APPROVE, COMPLETE].includes(e.kind) ? { consent_review_id: e.expectedConsent } : {}),
        ...(e.kind === COMPLETE ? { decision: 'complete_machine_requester_commit' } : {}) })
      expect(e.init.stdin).toBe(JSON.stringify(e.payload))
    }
  }
  if (!options.runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(t => t.name)).toEqual(Array(w.starts).fill('delivery_acknowledge'))
  }
}
async function terms(ui: Pane, w: World) {
  const inspection = (w.consentValue?.review.inspection ?? w.lastInspection?.review)!, shown = await visible(ui)
  for (const value of [quote(ROOT), quote(inspection.agent.name), quote(inspection.agent.owner), quote(inspection.member),
    quote(inspection.network.name), inspection.network.id, inspection.network.context_id, inspection.network.genesis_root_public_key,
    inspection.person_public_key, inspection.host_public_key, inspection.device_public_key, inspection.request_id,
    inspection.request_packet_id, inspection.owner_offer_id, inspection.selection_id, inspection.owner_finalization_id,
    inspection.owner_root_state_id, inspection.root_state_id, inspection.person_lease_id, inspection.host_lease_id,
    inspection.binding_lease_id, inspection.device_lease_id, inspection.not_after, inspection.created_at,
    inspection.expires_at, inspection.request_stage_deadline,
    ...Object.entries(inspection.owner_provider).filter(([field]) => field !== 'kind').map(([, value]) => value)]) expect(shown).toContain(String(value))
  expect(shown).toMatch(w.providerKind === 'original_person' ? /original[ _-]*person/i : /device/i)
  if (!w.folded) expect(shown).toContain(inspection.administrator_offer_id)
  for (const meaning of [/(?:profile|powers|scopes)[^\n]{0,60}7|7[^\n]{0,60}(?:profile|powers|scopes)/i,
    /policy[^\n]{0,60}1|1[^\n]{0,60}policy/i, /binding[^\n]{0,60}2|2[^\n]{0,60}binding/i,
    /device[^\n]{0,80}4|4[^\n]{0,80}device/i, /administrator[^\n]{0,80}8|8[^\n]{0,80}administrator/i,
    /original[^\n]{0,100}existing|existing[^\n]{0,100}original/i, /agent access/i, /files/i, /conversation/i, /capabilit/i])
    expect(shown).toMatch(meaning)
  if (w.consentValue) for (const value of [w.consentValue.consent_id, w.consentValue.review_id, w.consentValue.review.intent_id,
    w.consentValue.review.inspection_review_id, w.consentValue.review.created_at, w.consentValue.review.expires_at]) expect(shown).toContain(value)
  safe(w, shown)
}
async function recorded(ui: Pane) { expect(await visible(ui)).toMatch(/consent[^\n]*recorded/i) }
async function applied(ui: Pane, w: World, options: any = {}) {
  const shown = await visible(ui); expect(shown).toContain('Local application: recorded')
  for (const ref of [id64('dm', 65), id64('da', 66), id64('dpk', 67)]) expect(shown).toContain(ref)
  for (const meaning of [/participant/i, /delivery/i, /agent access/i, /connection/i, /not verified|not confirmed|unverified/i]) expect(shown).toMatch(meaning)
  expect(shown).not.toMatch(/(?:this pane|this interface|this frontend) (?:completed|applied|linked)/i)
  expect(await button(ui, 'Complete machine requester commit')).toBeUndefined(); safe(w, shown, options)
}
const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private machine requester state/$(literal)' } }

async function leave(ui: Pane) { if (await button(ui, 'Leave machine requester review')) await press(ui, 'Leave machine requester review') }
async function reopen(ui: Pane) { await leave(ui); await review(ui) }

test('published machine entry is explicit lookup-only and missing F Check never prepares or inventories originals', async ($, on) => {
  const w = fixture(on), ui = await published($, w, { requestState: 'pending' })
  expect(await button(ui, 'Review machine link')).toBeDefined(); expect(countMachine(w)).toHaveLength(0)
  await review(ui); expect(countMachine(w).map(e => e.kind)).toEqual([LOOKUP]); await inactive(ui)
  await check(ui, w); expect(countMachine(w, 'inspect')).toHaveLength(0); expect(mutations(w)).toHaveLength(0)
  await leave(ui); w.requestState = 'needs_commit'; await review(ui)
  expect(countMachine(w).slice(-2).map(e => e.kind)).toEqual([LOOKUP, INSPECT])
  expect(await button(ui, 'Review machine requester consent')).toBeDefined(); expect(mutations(w)).toHaveLength(0)
  await terms(ui, w); safe(w, await visible(ui))
})

test('remote original and device terms retain separate or folded admission reused binding and inherited finite cap', async ($, on) => {
  const w = fixture(on)
  for (const [provider, folded, reused] of [['original_person', true, false], ['device', false, true]] as const) {
    w.providerKind = provider; w.folded = folded; w.reused = reused; w.lastInspection = null
    const ui = await published($, w); await review(ui); await terms(ui, w)
    const r = w.lastInspection.review
    expect(r.owner_provider.host_public_key).not.toBe(r.host_public_key)
    expect(r.scopes).toBe(7); expect(r.binding_scopes).toBe(2)
    expect(Date.parse(r.not_after)).toBe(Math.min(w.requestCreated + 7 * 86_400_000, w.powersEnd))
    expect(requestView(w).completed.includes('administrator_offered')).toBe(!folded)
    expect(await visible(ui)).toMatch(folded ? /fold/i : /separate[\s\S]*administrator|administrator[\s\S]*separate/i)
    if (reused) expect(await visible(ui)).toMatch(/reus/i)
    expect(mutations(w)).toHaveLength(0); await close(ui)
  }
  safe(w)
})

test('separate double Prepare rechecks inspection then sends exact configured5s private stdin once', configured, async ($, on) => {
  const w = fixture(on), ui = await published($, w); await review(ui)
  const captured = clone(w.lastInspection), normal = w.run, delay = delayed(w), at = w.calls.length
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === LOOKUP) await delay.wait(); return value }
  const control = await key(ui, 'Review machine requester consent'), first = ui.press({ key: control }); void first.catch(() => undefined)
  await delay.started; await ui.press({ key: control }).catch(() => undefined)
  expect(countMachine(w, 'prepare')).toHaveLength(0); await w.clock.advance(1000); await first
  expect(countMachine(w, 'prepare')).toHaveLength(1); expect(countMachine(w, 'approve')).toHaveLength(0)
  expect(last(w, PREPARE).payload.inspection_review_id).toBe(captured.review_id)
  const sequence = w.calls.slice(at).map(e => e.kind), sent = sequence.indexOf(PREPARE)
  expect(sequence.slice(0, sent)).toContain(LOOKUP); expect(sequence.slice(0, sent)).toContain(INSPECT)
  await terms(ui, w); safe(w, await visible(ui), configured.options)
})

test('receipt appearing during Prepare preflight is shown read-only without preparation or silent replacement', async ($, on) => {
  const w = fixture(on), ui = await published($, w); await review(ui)
  w.consentValue = await consentRecord(w, { state: 'approved' }); const saved = clone(w.consentValue)
  await press(ui, 'Review machine requester consent'); await recorded(ui)
  expect(w.consentValue).toEqual(saved); expect(mutations(w)).toHaveLength(0)
  expect(await button(ui, 'Complete machine requester commit')).toBeDefined(); safe(w, await visible(ui))
})

test('changed inspected provider lease request F or effects cannot be silently adopted by Prepare preflight', async ($, on) => {
  const w = fixture(on), ui = await published($, w), normal = w.run
  const changes = [
    (v: any) => { v.review.owner_provider.lease_id = id64('ds', 999) },
    (v: any) => { v.review.owner_finalization_id = v.request.owner_finalization_id = id64('dpk', 999) },
    (v: any) => { v.review.effects.apply_network = true },
  ]
  for (const change of changes) {
    w.run = normal; await review(ui)
    w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e)); if (kind === INSPECT) {
      change(value); value.review_id = await digest('peerspan-machine-requester-inspection-v1', value.review) } return value }
    await press(ui, 'Review machine requester consent'); expect(mutations(w)).toHaveLength(0); await inactive(ui)
    await leave(ui)
  }
  safe(w, await visible(ui))
})

test('explicit double Approve uses unchanged displayed consent and one configured5s call without completion', configured, async ($, on) => {
  const w = fixture(on), ui = await prepared($, w), captured = clone(w.consentValue), normal = w.run, delay = delayed(w)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === LOOKUP) await delay.wait(); return value }
  const control = await key(ui, 'Approve machine requester commit'), first = ui.press({ key: control }); void first.catch(() => undefined)
  await delay.started; await ui.press({ key: control }).catch(() => undefined)
  expect(countMachine(w, 'approve')).toHaveLength(0); await w.clock.advance(1000); await first
  expect(countMachine(w, 'approve')).toHaveLength(1); expect(countMachine(w, 'complete')).toHaveLength(0)
  expect(last(w, APPROVE).payload.consent_review_id).toBe(captured.review_id)
  expect(w.consentValue.review).toEqual(captured.review); await recorded(ui)
  expect(await button(ui, 'Complete machine requester commit')).toBeDefined(); safe(w, await visible(ui), configured.options)
})

test('separate double Complete sends one configured95s exact decision and requires bound application evidence', configured, async ($, on) => {
  const w = fixture(on), ui = await prepared($, w, { consent: 'approved' }), captured = clone(w.consentValue), normal = w.run, delay = delayed(w)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === LOOKUP) await delay.wait(); return value }
  const control = await key(ui, 'Complete machine requester commit'), first = ui.press({ key: control }); void first.catch(() => undefined)
  await delay.started; await ui.press({ key: control }).catch(() => undefined)
  expect(countMachine(w, 'complete')).toHaveLength(0); await w.clock.advance(1000); await first
  expect(countMachine(w, 'complete')).toHaveLength(1); expect(countMachine(w, 'approve')).toHaveLength(0)
  expect(last(w, COMPLETE).payload).toEqual({ context: context(w.parent), flow_id: w.joining.flow_id,
    join_review_id: w.joining.review_id, consent_review_id: captured.review_id, decision: 'complete_machine_requester_commit' })
  expect(w.consentValue).toEqual(captured); await applied(ui, w, configured.options)
})

test('already approved or applied preflight recovers pure global facts without another mutation or invented marker', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w)
  w.consentValue.state = 'approved'; w.consentValue.next_action = 'follow_machine_link'
  await press(ui, 'Approve machine requester commit'); await recorded(ui); expect(countMachine(w, 'approve')).toHaveLength(0)
  w.requestState = 'linked'; await press(ui, 'Complete machine requester commit')
  expect(countMachine(w, 'complete')).toHaveLength(0); await applied(ui, w)
  const at = countMachine(w).length; await check(ui, w)
  expect(countMachine(w).slice(at).map(e => e.kind)).toEqual([LOOKUP]); await applied(ui, w)
  w.requestState = 'finalizing'; await check(ui, w); await inactive(ui)
  expect(countMachine(w, 'complete')).toHaveLength(0)
})

test('expired cancelled and invalidated receipts stay lookup-only even after advanced ordinary application', async ($, on) => {
  const w = fixture(on)
  for (const state of ['expired', 'cancelled', 'invalidated']) {
    w.lastInspection = null; w.consentValue = null
    const ui = await published($, w, { consent: state, requestState: state === 'invalidated' ? 'linked' : state })
    if (state === 'expired') await w.clock.advance(Date.parse(w.consentValue.review.expires_at) - w.clock.now() + 1)
    await review(ui); const saved = clone(w.consentValue), at = countMachine(w).length
    await inactive(ui); await check(ui, w)
    expect(countMachine(w).slice(at).map(e => e.kind)).toEqual([LOOKUP]); expect(w.consentValue).toEqual(saved)
    expect(mutations(w)).toHaveLength(0); safe(w, await visible(ui)); await close(ui)
  }
})

test('lost Prepare Approve and Complete replies require explicit matching Lookup and never repeat mutation', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const [kind, label, state] of [[PREPARE, 'Review machine requester consent', null],
    [APPROVE, 'Approve machine requester commit', 'review'], [COMPLETE, 'Complete machine requester commit', 'approved']] as const) {
    w.run = normal; w.consentValue = null; w.lastInspection = null
    const ui = await published($, w, { consent: state }); await review(ui)
    w.run = async (operation, payload, e) => { const value = await normal(operation, payload, e); return operation === kind ? { fixtureExit: true } : value }
    const at = w.calls.filter(e => e.kind === kind).length
    await press(ui, label); await unknown(ui, w)
    expect(w.calls.filter(e => e.kind === kind)).toHaveLength(at + 1)
    w.run = normal; const saved = clone(w.consentValue); await check(ui, w)
    expect(w.consentValue).toEqual(saved); expect(w.calls.filter(e => e.kind === kind)).toHaveLength(at + 1)
    if (kind === COMPLETE) await applied(ui, w)
    else expect(await button(ui, kind === PREPARE ? 'Approve machine requester commit' : 'Complete machine requester commit')).toBeDefined()
    await close(ui)
  }
  safe(w)
})

test('changed receipt intent frozen root or request target refuses old Approve without a replacement action', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w), normal = w.run
  const changes = [(v: any) => { v.consent.review.intent_id = id('dint', 999) },
    (v: any) => { v.consent.review.inspection.root_state_id = id64('ds', 999) },
    (v: any) => { v.request.device_public_key = HELPER_KEY }]
  for (const change of changes) {
    w.run = normal
    w.run = async (kind, payload, e) => { const v = clone(await normal(kind, payload, e)); if (kind === LOOKUP) {
      change(v); v.consent.review.inspection_review_id = await digest('peerspan-machine-requester-inspection-v1', v.consent.review.inspection)
      v.consent.review_id = await digest('peerspan-machine-requester-consent-v1', v.consent.review) } return v }
    await press(ui, 'Approve machine requester commit'); await inactive(ui); expect(countMachine(w, 'approve')).toHaveLength(0)
    w.run = normal; await reopen(ui)
  }
  safe(w, await visible(ui))
})

test('closed inspection rejects local provider substituted powers and invalid inherited deadline even with recomputed hash', async ($, on) => {
  const w = fixture(on), ui = await published($, w), normal = w.run
  const changes = [(v: any) => { v.review.owner_provider.host_public_key = INVITER_KEY },
    (v: any) => { v.review.scopes = 15 },
    (v: any) => { v.review.not_after = stamp(w.powersEnd + 1000) }]
  for (const change of changes) {
    w.run = async (kind, payload, e) => { const v = clone(await normal(kind, payload, e)); if (kind === INSPECT) {
      change(v); v.review_id = await digest('peerspan-machine-requester-inspection-v1', v.review) } return v }
    await review(ui); await inactive(ui); expect(mutations(w)).toHaveLength(0); await leave(ui)
  }
  safe(w, await visible(ui))
})

test('unknown wrapper nested effects or false folded administrator prefix never become actionable inspection', async ($, on) => {
  const w = fixture(on), ui = await published($, w), normal = w.run
  const changes = [(v: any) => { v.extra = true }, (v: any) => { v.review.effects.unreviewed = false },
    (v: any) => { v.request.completed.splice(3, 0, 'administrator_offered') }, (v: any) => { v.fixtureWrongDomain = true }]
  for (const change of changes) {
    w.run = async (kind, payload, e) => { const v = clone(await normal(kind, payload, e)); if (kind === INSPECT) {
      change(v); const wrong = v.fixtureWrongDomain; delete v.fixtureWrongDomain
      v.review_id = await digest(wrong ? 'peerspan-machine-requester-consent-v1' : 'peerspan-machine-requester-inspection-v1', v.review) } return v }
    await review(ui); await inactive(ui); expect(mutations(w)).toHaveLength(0); await leave(ui)
  }
  safe(w, await visible(ui))
})

test('completion requires closed exact approved marker references and all three not_verified fields', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w, { consent: 'approved' }), normal = w.run
  const changes = [(v: any) => { v.completion.outcome_id = id64('dpk', 999) },
    (v: any) => { v.completion.review_id = 'review_' + '9'.repeat(64) },
    (v: any) => { v.completion.participant_delivery = 'verified'; v.completion.agent_access = 'verified'; v.completion.connection_readiness = 'verified' }]
  for (const change of changes) {
    w.requestState = 'needs_commit'
    w.run = async (kind, payload, e) => { const v = await normal(kind, payload, e); if (kind === COMPLETE) change(v); return v }
    await press(ui, 'Complete machine requester commit'); await unknown(ui, w)
    w.run = normal; w.requestState = 'needs_commit'; await reopen(ui)
  }
  expect(countMachine(w, 'complete')).toHaveLength(3); safe(w, await visible(ui))
})

test('private control and oversized public results fail closed without leaking raw stdout stderr or labels', async ($, on) => {
  const w = fixture(on), ui = await published($, w), normal = w.run
  const changes = [(v: any) => { v.review.member = 'token_SHORT_PRIVATE' },
    (v: any) => { v.review.network.name = '\u001b]52;c;PRIVATE_MACHINE\u0007' },
    (_v: any) => ({ fixtureRaw: JSON.stringify({ padding: 'x'.repeat(2 * 1024 * 1024 + 1) }) })]
  for (const change of changes) {
    w.run = async (kind, payload, e) => { const v = await normal(kind, payload, e); if (kind !== INSPECT) return v
      const replacement = change(v); if (replacement) return replacement
      v.review_id = await digest('peerspan-machine-requester-inspection-v1', v.review); return v }
    await review(ui); await inactive(ui); expect(await visible(ui)).not.toMatch(/SHORT_PRIVATE|PRIVATE_MACHINE|padding/)
    expect(mutations(w)).toHaveLength(0); await leave(ui)
  }
  expect(w.outside.join('\n')).not.toMatch(/SHORT_PRIVATE|PRIVATE_MACHINE/); safe(w, await visible(ui))
})

test('premature manifest activation or outcome in approved pre-commit prefix stops Complete before dispatch', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w, { consent: 'approved' }), normal = w.run
  for (const [field, kind] of [['manifest_id', 'dm'], ['activation_id', 'da'], ['outcome_id', 'dpk']]) {
    w.run = async (operation, payload, e) => { const v = await normal(operation, payload, e); if (operation === LOOKUP) v.request[field] = id64(kind, 999); return v }
    await press(ui, 'Complete machine requester commit'); await inactive(ui); expect(countMachine(w, 'complete')).toHaveLength(0)
    w.run = normal; await reopen(ui)
  }
  safe(w, await visible(ui))
})

test('raw rollback effective future history and future observations never authorize fresh mutation', async ($, on) => {
  const w = fixture(on), ui = await published($, w, { consent: 'approved' }); w.observed = NOW + 600_000
  await review(ui); await recorded(ui); await inactive(ui); expect(mutations(w)).toHaveLength(0)
  await check(ui, w); await inactive(ui); expect(countMachine(w, 'inspect')).toHaveLength(0)
  await leave(ui); w.observed = NOW + 31_000; w.consentValue = null
  await review(ui); await inactive(ui); expect(mutations(w)).toHaveLength(0)
  await leave(ui); w.observed = null; w.consentValue = await consentRecord(w, { created: NOW + 1000 })
  await review(ui); await inactive(ui); expect(mutations(w)).toHaveLength(0); safe(w, await visible(ui))
})

test('earliest frozen review stage timer removes authority at exact boundary without automatic reads or renewal', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w, { stageDeadline: NOW + 2000 })
  const calls = w.calls.length, end = Date.parse(w.consentValue.review.expires_at)
  await w.clock.advance(end - w.clock.now() - 1); expect(await button(ui, 'Approve machine requester commit')).toBeDefined()
  await w.clock.advance(1); await inactive(ui); expect(w.calls).toHaveLength(calls)
  expect(await button(ui, 'Check machine requester consent')).toBeDefined(); safe(w, await visible(ui))
})

test('registered Prepare Approve and Complete preflight delays cannot dispatch after original signed deadline', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const [kind, label, state] of [[PREPARE, 'Review machine requester consent', null],
    [APPROVE, 'Approve machine requester commit', 'review'], [COMPLETE, 'Complete machine requester commit', 'approved']] as const) {
    w.run = normal; w.consentValue = null; w.lastInspection = null
    const ui = await published($, w, { consent: state, deadline: w.clock.now() + 1000 }); await review(ui)
    const delay = delayed(w, 2000), before = mutations(w).length
    w.run = async (operation, payload, e) => { const v = await normal(operation, payload, e); if (operation === LOOKUP) await delay.wait(); return v }
    const pending = press(ui, label); void pending.catch(() => undefined); await delay.started
    await w.clock.advance(2000); await pending
    expect(mutations(w), kind).toHaveLength(before); await inactive(ui); await close(ui)
  }
  safe(w)
})

test('already persisted approved work survives human expiry while dispatched valid application remains historical', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w, { consent: 'approved', requestState: 'finalizing', stageDeadline: NOW + 2000 })
  const calls = w.calls.length; await w.clock.advance(2001)
  expect(await button(ui, 'Complete machine requester commit')).toBeDefined(); expect(w.calls).toHaveLength(calls)
  const normal = w.run, delay = delayed(w, 1000)
  w.run = async (kind, payload, e) => { const v = await normal(kind, payload, e); if (kind === COMPLETE) await delay.wait(); return v }
  const pending = press(ui, 'Complete machine requester commit'); void pending.catch(() => undefined); await delay.started
  await w.clock.advance(w.requestExpiry - w.clock.now() + 1); await pending
  expect(countMachine(w, 'complete')).toHaveLength(1); await applied(ui, w)
  w.run = normal; await check(ui, w); await applied(ui, w)
})

test('fresh parent host root and conversation are revalidated after actual held preflight before mutation', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['parent', 'host', 'root', 'native']) {
    w.host = HOST; w.root = ROOT; w.native = NATIVE; w.parent = null; w.lastInspection = null; w.consentValue = null; w.run = normal
    const ui = await prepared($, w, { consent: 'approved' }), delay = delayed(w)
    w.run = async (kind, payload, e) => { const v = await normal(kind, payload, e); if (kind === LOOKUP) await delay.wait(); return v }
    const pending = press(ui, 'Complete machine requester commit'); void pending.catch(() => undefined); await delay.started
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'root') w.root = '/different-machine-root'
    if (mode === 'native') w.native = 'different-machine-conversation'
    await w.clock.advance(1000); await pending; await inactive(ui, mode); expect(countMachine(w, 'complete')).toHaveLength(0)
    await close(ui)
  }
  safe(w)
})

test('Leave Refresh Close and session end discard dispatched late application without retracting global evidence', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['leave', 'refresh', 'close', 'end']) {
    w.run = normal; w.requestState = 'needs_commit'; w.consentValue = null; w.lastInspection = null
    const ui = await prepared($, w, { consent: 'approved' }), delay = delayed(w)
    w.run = async (kind, payload, e) => { const v = await normal(kind, payload, e); if (kind === COMPLETE) await delay.wait(); return v }
    const pending = press(ui, 'Complete machine requester commit'); void pending.catch(() => undefined); await delay.started
    if (mode === 'leave') await press(ui, 'Leave machine requester review')
    if (mode === 'refresh') await press(ui, 'Refresh')
    if (mode === 'close') await press(ui, 'Close')
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    await w.clock.advance(1000); await pending; await inactive(ui, mode)
    expect(await visible(ui), mode).not.toContain('Local application: recorded')
    expect(w.requestState).toBe('linked'); expect(w.consentValue.state).toBe('approved'); await close(ui)
  }
  expect(countMachine(w, 'complete')).toHaveLength(4); safe(w)
})

test('Leave clears all review panes and an older request timer cannot clear a new explicit machine review', async ($, on) => {
  const w = fixture(on), ui = await prepared($, w, { consent: 'approved', deadline: NOW + 2000 }), normal = w.run, delay = delayed(w)
  w.run = async (kind, payload, e) => { const v = await normal(kind, payload, e); if (kind === LOOKUP) await delay.wait(); return v }
  const pending = press(ui, 'Complete machine requester commit'); void pending.catch(() => undefined); await delay.started
  await leave(ui); expect(await button(ui, 'Review machine link')).toBeDefined(); await inactive(ui)
  w.run = normal; w.requestExpiry = NOW + 3_570_000; w.requestCreated = NOW - 30_000
  w.lastInspection = null; w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: 91 })
  w.consentValue = await consentRecord(w, { state: 'approved', n: 91 })
  await press(ui, 'Close'); await ui.unmount()
  const next = await enter($, w); await press(next, 'Connect this project'); await press(next, 'Connect this computer'); await review(next)
  const current = clone(w.consentValue); await w.clock.advance(1000); await pending; await w.clock.advance(1001)
  expect(countMachine(w, 'complete')).toHaveLength(0); expect(w.consentValue).toEqual(current)
  expect(await button(next, 'Complete machine requester commit')).toBeDefined(); safe(w, await visible(next))
})

test('ordinary machine-pane leave preserves authorized message task and lease runtime without new prompts or tools', async ($, on) => {
  const w = fixture(on), ui = await connected($, w)
  await enable($, w, ui); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' })
  w.consentValue = await consentRecord(w, { state: 'approved' })
  const tools = w.tools.map(t => t.name), prompts = w.prompts.length, readiness = readyCalls(w).length
  await press(ui, /^Back to project$/); await press(ui, 'Connect this computer'); await review(ui)
  await check(ui, w); await leave(ui)
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length, leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.tools.map(t => t.name)).toEqual(tools); expect(w.prompts).toHaveLength(prompts); expect(readyCalls(w)).toHaveLength(readiness)
  expect(mutations(w)).toHaveLength(0); safe(w, await visible(ui), { runtime: true })
})
