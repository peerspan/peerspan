/**
 * Independent section26 original-finalization controls on pinnedClaude2.1.303.
 * Public effects and contract-derived closed projections only; no production
 * imports, real signing, inference, terminal action or persistence. All existing
 * 272 native files/assertions/stimuli/delays/default timeouts remain unchanged.
 * Host suites independently verify crypto, exact safe key use and persistence.
 * Every delayed effect signals actual dispatch plus registered virtual sleep.
 * Current-drawing callbacks cannot prove obsolete retained closures; microscopic
 * final-check/dispatch, actual reload/installed/physical/model acceptance and
 * real process cancellation/deadlines remain source or separate live limits.
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
    ownerValue: null as any, finalizationValue: null as any, lastInspection: null as any, requestState: 'pending', requestCreated: NOW - 30_000, requestExpiry: NOW + 3_570_000, networks: [] as any[], invitation: null as any, previewValue: null as any, joining: null as any, identities: [{ public_key: KEY, sources: ["generated"] }] as any[], code: CODE, codes: [CODE, CODE2],
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  w.run = async (kind, payload) => {
    if (kind === 'join.owner.finalization.inspect') {
      const value = clone(w.finalizationValue ?? await finalizationInspection(w)); w.lastInspection = clone(value); return value
    }
    if (kind === 'join.owner.finalization.sign') return finalizationSuccess(w)
    if (kind === 'join.owner.sign') throw Error('original offer signing outside this slice')
    if (kind === 'join.owner.lookup') return ownerResponse(w)
    if (kind === 'join.owner.prepare') { w.ownerValue ??= await ownerRecord(w); return ownerResponse(w) }
    if (kind === 'join.owner.approve') {
      w.ownerValue = { ...w.ownerValue, state: 'approved', next_action: w.requestState === 'pending' ? 'provide_original_signature' : 'follow_join_progress' }
      return ownerResponse(w)
    }
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
    const kind = tail[0] === 'join' && tail[1] === 'owner' ? tail.slice(0, tail[2] === 'finalization' ? 4 : 3).join('.') : tail.length ? tail[0] + '.' + tail[1] : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    // Capture the serialized request independently of synthetic response
    // mutations; a real process stdout cannot mutate its already-sent stdin.
    const sent = payload === undefined ? undefined : clone(payload)
    w.calls.push({ ...e, kind, payload: sent, expectedContext: w.parent ? clone(context(w.parent)) : undefined,
      expectedProjectFlow: w.parent?.flow_id, expectedAdapterFlow: w.child?.flow_id,
      expectedFlow: w.joining?.flow_id, expectedJoinReview: w.joining?.review_id,
      expectedOwnerReview: w.ownerValue?.review_id }); w.trace.push({ kind, payload: sent })
    const value = await w.run(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureExit) return { value: { exitCode: 124, stdout: '', stderr: RAW } }
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
async function back(ui: Pane) {
  const found = await ui.find({ type: 'Button', text: /^Back\b/ }); expect(found).toBeDefined(); await ui.press({ key: found!.key! })
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
async function joinEntry(w: World, ui: Pane) {
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  await press(ui, 'Join a network'); await w.clock.settle()
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
const ownerEffects = { approve_owner_intent: true, authorize_original_signature: true,
  authorize_bounded_owner_finalization: true, auto_select_single_offer_after_signature: true,
  publish_owner_offer_after_signature: true, grant_membership: false, grant_agent_access: false,
  approve_network_administrator: false, commit_request: false, share_files: false,
  share_conversation: false, capability_calls: false }
async function ownerRecord(w: World, options: any = {}) {
  const request = await requestView(w)
  const state = options.state ?? 'review', n = options.n ?? 70
  const review = { version: 1, kind: 'approve_new_original_owner', host_id: w.host, context: context(w.parent),
    flow_id: w.joining.flow_id, join_review_id: w.joining.review_id, request_id: request.request_id,
    intent_id: id('dint', n), network: clone(w.joining.review.invitation.network),
    member: w.joining.review.invitation.invitation.member, person_public_key: w.joining.review.person_public_key,
    host_public_key: request.host_public_key, device_public_key: request.device_public_key,
    proposed_owner_offer_id: id64('dpk', 61), scopes: 7,
    not_after: stamp(Date.parse(request.created_at) + 7 * 86_400_000),
    expires_at: stamp(Math.floor((options.expires ?? (state === 'expired' ? NOW - 1000 : NOW + 900_000)) / 1000) * 1000), effects: clone(ownerEffects) }
  return { review_id: await digest('peerspan-onboarding-original-owner-review-v1', review), review, state,
    next_action: state === 'review' ? 'approve_owner_intent' : state === 'approved'
      ? request.owner_offer_id === '-' ? 'provide_original_signature' : 'follow_join_progress' : 'inspect_join_progress' }
}
async function ownerResponse(w: World) {
  const request = await requestView(w)
  const owner = clone(w.ownerValue)
  if (owner?.state === 'review' && Date.parse(owner.review.expires_at) <= w.clock.now()) {
    owner.state = 'expired'; owner.next_action = 'inspect_join_progress'
  }
  return { version: 1, host_id: w.host, flow_id: w.joining.flow_id, join_review_id: w.joining.review_id,
    context: context(w.parent), observed_at: stamp(Math.floor(w.clock.now() / 1000) * 1000), request, owner }
}
async function ownerPublished($: Engine, w: World, options: any = {}) {
  const ui = await setup($, w, null, { networks: [] })
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: options.flow ?? 60 })
  if (options.state) w.ownerValue = await ownerRecord(w, options)
  await joinEntry(w, ui); return ui
}
async function reviewOwner(ui: Pane) { await press(ui, 'Review owner powers') }
const ownerCalls = (w: World, op?: string) => w.calls.filter(call => call.kind === (op ? 'join.owner.' + op : call.kind) && call.kind.startsWith('join.owner.'))
function delaySignal(w: World, milliseconds: number) {
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(milliseconds); entered(); return pending } }
}
async function leaveIfPresent(ui: Pane) {
  const leave = await ui.find({ type: 'Button', text: /^Leave owner review$/ })
  if (leave) await ui.press({ key: leave.key! })
}
async function requestView(w: World) {
  const request = (await progressResponse(w, w.requestState)).request
  return { ...request, created_at: stamp(w.requestCreated), expires_at: stamp(w.requestExpiry) }
}
const FINAL_INSPECT = 'join.owner.finalization.inspect'
const FINAL_SIGN = 'join.owner.finalization.sign'
const finalEffects = { verify_original_owner: true, verify_requester_selection: true,
  verify_administrator_admission: true, verify_owner_finalization_bounds: true,
  prepare_finalization: false, sign_original: false, publish_finalization: false,
  commit_request: false, grant_membership: false, grant_agent_access: false,
  share_files: false, share_conversation: false, capability_calls: false }
async function finalizationInspection(w: World) {
  const request = await requestView(w), owner = w.ownerValue.review
  const review = { version: 1, kind: 'inspect_new_original_finalization', host_id: w.host,
    context: context(w.parent), flow_id: w.joining.flow_id, join_review_id: w.joining.review_id,
    owner_review_id: w.ownerValue.review_id, request_id: request.request_id, intent_id: owner.intent_id,
    network: clone(owner.network), member: owner.member, person_public_key: owner.person_public_key,
    host_public_key: owner.host_public_key, device_public_key: owner.device_public_key,
    request_packet_id: request.request_packet_id, owner_offer_id: request.owner_offer_id,
    selection_id: request.selection_id, administrator_offer_id: request.administrator_offer_id,
    root_state_id: id64('ds', 101), person_lease_id: id64('ds', 102), host_lease_id: id64('ds', 103),
    administrator: { signer_public_key: GENESIS_KEY, host_public_key: HELPER_KEY, signature_format: 'ed25519', issuer_id: id64('ds', 101) },
    scopes: 7, binding_scopes: 2, not_after: owner.not_after, created_at: request.created_at,
    expires_at: request.expires_at, effects: clone(finalEffects) }
  return { version: 1, host_id: w.host, flow_id: w.joining.flow_id, join_review_id: w.joining.review_id,
    owner_review_id: w.ownerValue.review_id, context: context(w.parent), observed_at: stamp(Math.floor(w.clock.now() / 1000) * 1000),
    request, review_id: await digest('peerspan-original-finalization-inspection-v1', review), review,
    next_action: 'review_original_finalization' }
}
async function finalizationSuccess(w: World, state = 'needs_commit') {
  const reviewed = clone(w.lastInspection ?? await finalizationInspection(w))
  w.requestState = state
  return { ...await ownerResponse(w), original_finalization: { state: 'recorded', review_id: reviewed.review_id,
    packet_id: id64('dpk', 64) } }
}
const finalCalls = (w: World, op?: 'inspect' | 'sign') => w.calls.filter(e => op ? e.kind === 'join.owner.finalization.' + op : e.kind.startsWith('join.owner.finalization.'))
async function noFinalSign(ui: Pane, why = '') {
  expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ }), why).toBeUndefined()
}
async function noFinalRecord(ui: Pane, why = '') {
  expect(await visible(ui), why).not.toContain('Original finalization: recorded')
}
async function leaveFinal(ui: Pane) {
  const leave = await ui.find({ type: 'Button', text: /^Leave finalization review$/ })
  if (leave) await ui.press({ key: leave.key! })
}
async function finalEligible($: Engine, w: World, options: any = {}) {
  w.requestState = options.requestState ?? 'needs_owner_finalization'
  if (options.deadline) { w.requestExpiry = options.deadline; w.requestCreated = options.deadline - 3_600_000 }
  const ui = await ownerPublished($, w, { state: 'approved', ...options,
    expires: options.expires ?? Math.min(NOW + 900_000, w.requestExpiry) })
  await reviewOwner(ui)
  return ui
}
async function finalReview(ui: Pane, w: World) {
  await press(ui, 'Review original finalization'); await w.clock.settle()
}
async function reopenFinal(ui: Pane, w: World) {
  await leaveFinal(ui); await leaveIfPresent(ui); await reviewOwner(ui); await finalReview(ui, w)
}
function finalPrivacy(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  for (const privateValue of [TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path', NATIVE,
    ...w.codes, w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id,
    w.child?.flow_id, w.child?.review_id, w.child?.review.adapter_id,
    w.joining?.flow_id, w.joining?.review_id, w.ownerValue?.review_id, w.ownerValue?.review.intent_id,
    w.lastInspection?.review_id].filter(Boolean)) {
    expect(w.outside.join('\n')).not.toContain(privateValue); expect(shown).not.toContain(privateValue)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(privateValue)
  }
  expect(shown).not.toMatch(/\b(?:flow_[0-9a-f]{32}|review_[0-9a-f]{64}|dint_[0-9a-f]{32}|session_[0-9a-f]{32}|adapter_[0-9a-f]{32})\b/)
  expect(w.outside.join('\n')).not.toContain(ROOT)
  for (const e of w.calls) {
    const prefix = [executable, ...(state ? ['--state', state] : []), 'onboarding']
    expect(e.init?.timeoutMs).toBe(e.kind === FINAL_SIGN ? 95000 : 5000)
    const inspection = ({ 'project.inspect': e.expectedProjectFlow, 'join.inspect': e.expectedFlow,
      'adapter.inspect': e.expectedAdapterFlow } as Record<string, string | undefined>)[e.kind]
    if (inspection) expect(e.argv).toEqual([...prefix, e.kind.split('.')[0], 'inspect', inspection])
    else if (e.kind === 'snapshot') expect(e.argv).toEqual(prefix)
    else expect(e.argv).toEqual([...prefix, ...e.kind.split('.'), '--stdin'])
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, ...w.codes]) expect(e.argv).not.toContain(value)
    const args = inspection ? e.argv.slice(0, -1) : e.argv
    for (const value of [e.expectedFlow, e.expectedJoinReview, e.expectedOwnerReview].filter(Boolean)) expect(args).not.toContain(value)
    expect(e.kind).not.toMatch(/identit|create-identity|resume|selection|admi|commit/)
    expect(e.kind).not.toBe('join.owner.sign')
    if (e.kind.startsWith('join.owner.')) {
      const signing = e.kind === FINAL_SIGN, inspecting = e.kind === FINAL_INSPECT
      expect(e.payload).toEqual({ flow_id: e.expectedFlow, context: e.expectedContext, join_review_id: e.expectedJoinReview,
        ...((signing || inspecting || e.kind === 'join.owner.approve') ? { owner_review_id: e.expectedOwnerReview } : {}),
        ...(signing ? { finalization_review_id: e.payload.finalization_review_id, decision: 'sign_original_finalization' } : {}) })
      expect(JSON.parse(e.init.stdin)).toEqual(e.payload)
      if (signing) expect(e.payload.finalization_review_id).toMatch(/^review_[0-9a-f]{64}$/)
    }
  }
  if (!runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  }
}
async function finalTerms(ui: Pane, w: World) {
  const view = w.lastInspection, review = view.review, shown = await visible(ui)
  for (const term of [quote(ROOT), quote(review.network.name), quote(review.member), review.network.id, review.network.context_id,
    review.network.genesis_root_public_key, review.person_public_key, review.host_public_key, review.device_public_key,
    review.owner_offer_id, review.selection_id, review.administrator_offer_id, review.root_state_id, review.person_lease_id,
    review.host_lease_id, review.administrator.signer_public_key, review.administrator.host_public_key,
    review.administrator.signature_format, review.not_after, review.expires_at]) expect(shown).toContain(term)
  for (const meaning of [/owner consent|original consent/i, /profile[^\n]{0,30}7|7[^\n]{0,30}profile/i,
    /binding[^\n]{0,40}2|2[^\n]{0,40}binding/i, /generated/i, /ssh.?agent/i,
    /(?:two|2)[^\n]{0,40}batch|batch[^\n]{0,40}(?:two|2)/i,
    /(?:three|3)[^\n]{0,40}signature|signature[^\n]{0,40}(?:three|3)/i,
    /(?:no|never|not)[^\n]{0,70}(?:creat|cop|import)|(?:creat|cop|import)[^\n]{0,70}(?:no|never|not)/i,
    /commit/i, /agent access/i, /files/i, /conversation/i, /capabilit/i, /readiness/i,
    /leav|navigat/i, /retract|already.*dispatch/i]) expect(shown).toMatch(meaning)
  expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ })).toBeDefined()
  finalPrivacy(w, shown)
}
async function recorded(ui: Pane, w: World, runtime = false) {
  const shown = await visible(ui)
  expect(shown).toContain('Original finalization: recorded'); expect(shown).toContain(id64('dpk', 64))
  expect(shown).not.toMatch(/(?:this pane|this frontend|this conversation) (?:signed|created|recorded)/i)
  await noFinalSign(ui); finalPrivacy(w, shown, runtime)
}
async function unknown(ui: Pane, w: World, why = '') {
  await noFinalRecord(ui, why); await noFinalSign(ui, why)
  expect(await visible(ui), why).toMatch(/unknown|not confirmed|unavailable/i)
  expect(await visible(ui), why).toContain('Join request: publication recorded')
  expect(await ui.find({ type: 'Button', text: /^Check original finalization$/ }), why).toBeDefined()
  finalPrivacy(w, await visible(ui))
}
const configuredFinalization: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private finalization state/$(literal)' },
}

// Group1: explicit entry and complete meaning, never read-as-sign.
test('entry owner approval progress Check Refresh and reentry are finalization inert', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w, { state: 'review', requestState: 'pending' })
  await press(ui, 'Approve owner powers'); expect(finalCalls(w)).toHaveLength(0)
  // Separate already-approved ordinary work supplies the verified prefix.
  w.requestState = 'needs_owner_finalization'; w.ownerValue.next_action = 'follow_join_progress'
  await press(ui, 'Check owner consent'); expect(finalCalls(w)).toHaveLength(0)
  await press(ui, 'Leave owner review'); await press(ui, 'Check join progress'); await press(ui, 'Refresh')
  await w.clock.advance(1000); expect(finalCalls(w)).toHaveLength(0)
  await back(ui); await joinEntry(w, ui); expect(finalCalls(w)).toHaveLength(0)
  await reviewOwner(ui); expect(await ui.find({ type: 'Button', text: /^Review original finalization$/ })).toBeDefined()
  expect(finalCalls(w)).toHaveLength(0); finalPrivacy(w, await visible(ui))
})

test('only exact approved live requester four-stage prefix offers finalization review', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['unapproved', v => { v.owner.state = 'review'; v.owner.next_action = 'approve_owner_intent' }],
    ['missing owner', v => { v.owner = null }], ['owner stage', v => { v.request.state = 'needs_administrator'; v.request.administrator_offer_id = '-'; v.request.completed.pop() }],
    ['role', v => { v.request.role = 'owner' }], ['renew', v => { v.request.mode = 'renew' }],
    ['migration', v => { v.request.migration_proposal_id = id64('ds', 99) }], ['selection', v => { v.request.selection_approved = false }],
    ['commit', v => { v.request.commit_approved = true }], ['missing stage', v => { v.request.completed = v.request.completed.slice(0, 3) }],
  ]
  for (const [label, change] of variants) {
    await leaveIfPresent(ui)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === 'join.owner.lookup' || (label === 'missing owner' && kind === 'join.owner.prepare')) change(value)
      return value }
    await reviewOwner(ui)
    expect(await ui.find({ type: 'Button', text: /^Review original finalization$/ }), label).toBeUndefined(); await noFinalSign(ui, label)
  }
  expect(finalCalls(w)).toHaveLength(0); finalPrivacy(w, await visible(ui))
})

test('explicit pure inspection displays complete quoted targets parents bounded effects and separate commit access readiness', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w)
  await finalReview(ui, w); expect(finalCalls(w, 'inspect')).toHaveLength(1); expect(finalCalls(w, 'sign')).toHaveLength(0)
  await finalTerms(ui, w)
  expect(ownerCalls(w, 'prepare')).toHaveLength(0); expect(ownerCalls(w, 'approve')).toHaveLength(0)
})

// Group2: fresh pinned preflight and one literal bounded command.
test('double Sign freshly checks parent flow host owner and inspection then sends one exact configured95s stdin call', configuredFinalization, async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w); await finalReview(ui, w)
  const captured = clone(w.lastInspection), normal = w.run, delayed = delaySignal(w, 1000), at = w.trace.length
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.lookup') await delayed.wait(); return value }
  const button = await key(ui, 'Sign original finalization'), pending = ui.press({ key: button }); void pending.catch(() => undefined)
  await delayed.started; const second = ui.press({ key: button }).catch(() => undefined)
  expect(finalCalls(w, 'sign')).toHaveLength(0); await noFinalRecord(ui)
  await w.clock.advance(1000); await Promise.all([pending, second])
  expect(finalCalls(w, 'sign')).toHaveLength(1)
  expect(finalCalls(w, 'sign')[0].payload).toEqual({ flow_id: w.joining.flow_id, context: context(w.parent),
    join_review_id: w.joining.review_id, owner_review_id: w.ownerValue.review_id,
    finalization_review_id: captured.review_id, decision: 'sign_original_finalization' })
  const trace = w.trace.slice(at), sent = trace.findIndex(e => e.kind === FINAL_SIGN)
  for (const kind of ['project.inspect', 'join.inspect', 'snapshot', 'join.owner.lookup', FINAL_INSPECT, 'root', 'native'])
    expect(trace.slice(0, sent).some(e => e.kind === kind), kind).toBe(true)
  expect(finalCalls(w, 'inspect')).toHaveLength(2)
  expect(await visible(ui)).toContain('Original finalization: recorded'); await noFinalSign(ui)
  finalPrivacy(w, await visible(ui), false, configuredFinalization.options.executable, configuredFinalization.options.state)
})

test('changed owner consent immutable request keys or selected prefix stop preflight before signing', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['intent', v => { v.owner.review.intent_id = id('dint', 99) }], ['unapproved', v => { v.owner.state = 'invalidated'; v.owner.next_action = 'inspect_join_progress' }],
    ['request', v => { v.request.request_packet_id = id64('dpk', 99) }], ['offer', v => { v.request.owner_offer_id = id64('dpk', 99) }],
    ['selection', v => { v.request.selection_id = id64('dpk', 99) }], ['administrator', v => { v.request.administrator_offer_id = id64('dpk', 99) }],
    ['host', v => { v.request.host_public_key = GENESIS_KEY }], ['creation', v => { v.request.created_at = stamp(NOW - 31_000) }],
    ['deadline', v => { v.request.expires_at = stamp(NOW + 3_560_000) }], ['stage', v => { v.request.state = 'blocked' }],
  ]
  for (const [label, change] of variants) {
    w.run = normal; await finalReview(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.lookup') {
      change(value); if (value.owner) value.owner.review_id = await digest('peerspan-onboarding-original-owner-review-v1', value.owner.review)
    } return value }
    await press(ui, 'Sign original finalization'); expect(finalCalls(w, 'sign'), label).toHaveLength(0); await noFinalRecord(ui, label)
    await leaveFinal(ui); w.run = normal; await reviewOwner(ui)
  }
  finalPrivacy(w, await visible(ui))
})

test('fresh reinspection cannot silently rebind digest root P H administrator or fixed powers', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['digest', v => { v.review_id = id64('review', 99) }], ['root', v => { v.review.root_state_id = id64('ds', 99) }],
    ['P', v => { v.review.person_lease_id = id64('ds', 99) }], ['H', v => { v.review.host_lease_id = id64('ds', 99) }],
    ['administrator signer', v => { v.review.administrator.signer_public_key = RELAY_KEY }],
    ['administrator writer', v => { v.review.administrator.host_public_key = RELAY_KEY }],
    ['profile', v => { v.review.scopes = 15 }], ['lifetime', v => { v.review.not_after = stamp(NOW + 8 * 86_400_000) }],
  ]
  for (const [label, change] of variants) {
    w.run = normal; await finalReview(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_INSPECT) {
      change(value); if (label !== 'digest') value.review_id = await digest('peerspan-original-finalization-inspection-v1', value.review)
    } return value }
    await press(ui, 'Sign original finalization'); expect(finalCalls(w, 'sign'), label).toHaveLength(0); await noFinalRecord(ui, label)
    await leaveFinal(ui); w.run = normal; await reviewOwner(ui)
  }
  finalPrivacy(w, await visible(ui))
})

test('authoritative parent flow host and native context are rechecked after inspection IO before controls or sign', async ($, on) => {
  const w = fixture(on); let ui = await finalEligible($, w); const normal = w.run
  const parent = clone(w.parent), joining = clone(w.joining), retained = clone(w.ownerValue)
  for (const [index, mode] of ['parent', 'flow', 'host', 'root', 'native', 'surface'].entries()) {
    if (index) { w.parent = clone(parent); w.joining = clone(joining); w.ownerValue = clone(retained)
      w.host = HOST; w.root = ROOT; w.native = NATIVE; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
      ui = await enter($, w); await joinEntry(w, ui); await reviewOwner(ui) }
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_INSPECT) {
      if (mode === 'parent') w.parent.state = 'invalidated'
      if (mode === 'flow') w.joining.outcome.request_id = id64('link', 99)
      if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
      if (mode === 'root') w.root = '/changed-finalization-root'
      if (mode === 'native') w.native = 'changed-finalization-native'
      if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    } return value }
    await finalReview(ui, w); await noFinalSign(ui, mode); await noFinalRecord(ui, mode)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  expect(finalCalls(w, 'sign')).toHaveLength(0); finalPrivacy(w)
})

test('just recorded exact F on Review Sign and Check is lookup-only global recovery without inspection or signing', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  for (const mode of ['review', 'sign', 'check']) {
    w.run = normal; w.requestState = 'needs_owner_finalization'
    if (mode !== 'review') await finalReview(ui, w)
    if (mode === 'check') { w.run = async (kind, payload, e) => kind === FINAL_SIGN ? { fixtureExit: true } : normal(kind, payload, e)
      await press(ui, 'Sign original finalization'); w.run = normal }
    const before = finalCalls(w, 'inspect').length
    w.requestState = 'needs_commit'
    await press(ui, mode === 'review' ? 'Review original finalization' : mode === 'sign' ? 'Sign original finalization' : 'Check original finalization')
    expect(finalCalls(w, 'inspect').length, mode).toBe(before); await recorded(ui, w)
    await leaveFinal(ui); w.requestState = 'needs_owner_finalization'; await reviewOwner(ui)
  }
  expect(finalCalls(w, 'sign')).toHaveLength(1); finalPrivacy(w, await visible(ui))
})

// Group3: independently closed public projection/result validation.
test('closed inspection wrapper request mapping dates and binding corpus cannot install Sign', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['top extra', v => { v.extra = RAW }], ['version', v => { v.version = true }], ['action', v => { v.next_action = 'sign_now' }],
    ['digest', v => { v.review_id = id64('review', 99) }], ['context', v => { v.context.native_session_id = 'other-native' }],
    ['owner binding', v => { v.owner_review_id = id64('review', 99) }], ['request extra', v => { v.request.provider = RAW }],
    ['state', v => { v.request.state = 'needs_commit' }], ['stage order', v => { v.request.completed.reverse() }],
    ['host key hash', v => { v.request.host_public_key = GENESIS_KEY }], ['commit', v => { v.request.commit_approved = true }],
    ['noncanonical date', v => { v.observed_at = '2026-10-29T12:00:00+00:00' }],
    ['future observation', v => { v.observed_at = stamp(NOW + 31_000) }],
  ]
  for (const [label, change] of variants) {
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_INSPECT) change(value); return value }
    await finalReview(ui, w); await noFinalSign(ui, label); await noFinalRecord(ui, label)
    await leaveFinal(ui); w.run = normal; await reviewOwner(ui)
  }
  expect(finalCalls(w, 'sign')).toHaveLength(0); finalPrivacy(w, await visible(ui))
})

test('closed review effects canonical keys parent IDs and raw or decorated private terms are refused without echo', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['null', v => { v.review = null }], ['extra', v => { v.review.extra = RAW }], ['effect', v => { v.review.effects.commit_request = true }],
    ['unknown effect', v => { v.review.effects.extra = false }], ['profile type', v => { v.review.scopes = '7' }],
    ['binding', v => { v.review.binding_scopes = 7 }], ['key', v => { v.review.person_public_key = KEY.slice(1) }],
    ['same P H', v => { v.review.person_lease_id = v.review.host_lease_id }], ['root type', v => { v.review.root_state_id = id64('drs', 101) }],
    ['administrator extra', v => { v.review.administrator.provider = RAW }], ['administrator null', v => { v.review.administrator = null }],
    ['fixed created', v => { v.review.created_at = stamp(NOW - 31_000) }], ['private', v => { v.review.member = 'psi2-SHORT_FINAL_SECRET' }],
    ['private OSC', v => { v.review.network.name = '\x1b]0;tok\u202e\x1b[31men_SHORT_FINAL_SECRET\x07visible' }],
  ]
  for (const [label, change] of variants) {
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_INSPECT) {
      change(value); value.review_id = await digest('peerspan-original-finalization-inspection-v1', value.review)
    } return value }
    await finalReview(ui, w); await noFinalSign(ui, label); await noFinalRecord(ui, label)
    expect(await visible(ui)).not.toContain('SHORT_FINAL_SECRET'); expect(await visible(ui)).not.toContain('token_')
    await leaveFinal(ui); w.run = normal; await reviewOwner(ui)
  }
  expect(finalCalls(w, 'sign')).toHaveLength(0); finalPrivacy(w, await visible(ui))
})

test('bare null extra malformed or wrong exact signing markers never confirm F', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['bare', v => { delete v.original_finalization }], ['null', v => { v.original_finalization = null }],
    ['extra marker', v => { v.original_finalization.extra = RAW }], ['state', v => { v.original_finalization.state = 'signed' }],
    ['wrong review', v => { v.original_finalization.review_id = id64('review', 99) }],
    ['wrong packet', v => { v.original_finalization.packet_id = id64('dpk', 99) }],
    ['bad packet', v => { v.original_finalization.packet_id = id('dpk', 64) }], ['extra wrapper', v => { v.provider = RAW }],
  ]
  for (const [label, change] of variants) {
    w.run = normal; w.requestState = 'needs_owner_finalization'; await finalReview(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_SIGN) change(value); return value }
    await press(ui, 'Sign original finalization'); await unknown(ui, w, label)
    await leaveFinal(ui); w.run = normal; w.requestState = 'needs_owner_finalization'; await reviewOwner(ui)
  }
  expect(finalCalls(w, 'sign')).toHaveLength(variants.length); finalPrivacy(w, await visible(ui))
})

test('success still binds approved original digest request keys dates selected prefix and private-free public terms', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['unapproved', v => { v.owner.state = 'review'; v.owner.next_action = 'approve_owner_intent' }],
    ['owner digest', v => { v.owner.review_id = id64('review', 99) }], ['owner terms', v => { v.owner.review.scopes = 15 }],
    ['request', v => { v.request.request_id = id64('link', 99) }], ['offer', v => { v.request.owner_offer_id = id64('dpk', 99) }],
    ['selection', v => { v.request.selection_id = id64('dpk', 99) }], ['administrator', v => { v.request.administrator_offer_id = id64('dpk', 99) }],
    ['host', v => { v.request.host_public_key = GENESIS_KEY }], ['request expiry', v => { v.request.expires_at = stamp(NOW + 3_560_000) }],
    ['date', v => { v.observed_at = 'invalid' }], ['stages', v => { v.request.completed.reverse() }],
    ['private', v => { v.owner.review.member = 'peerspan-person-invite-v1.SHORT_FINAL_SECRET' }],
  ]
  for (const [label, change] of variants) {
    w.run = normal; w.requestState = 'needs_owner_finalization'; await finalReview(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_SIGN) {
      change(value); if (label !== 'owner digest') value.owner.review_id = await digest('peerspan-onboarding-original-owner-review-v1', value.owner.review)
    } return value }
    await press(ui, 'Sign original finalization'); await unknown(ui, w, label)
    expect(await visible(ui)).not.toContain('SHORT_FINAL_SECRET')
    await leaveFinal(ui); w.run = normal; w.requestState = 'needs_owner_finalization'; await reviewOwner(ui)
  }
  expect(finalCalls(w, 'sign')).toHaveLength(variants.length); finalPrivacy(w, await visible(ui))
})

test('same-context later valid stages confirm exact retained F without claiming requester commit access or pane attribution', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  for (const state of ['needs_commit', 'finalizing', 'linked']) {
    w.run = normal; w.requestState = 'needs_owner_finalization'; await finalReview(ui, w)
    w.run = async (kind, payload, e) => {
      if (kind !== FINAL_SIGN) return normal(kind, payload, e)
      const value = await finalizationSuccess(w, state); if (state === 'linked') w.networks = [network()]; return value
    }
    await press(ui, 'Sign original finalization'); await recorded(ui, w)
    const shown = await visible(ui)
    expect(shown).not.toMatch(/(?:adapter|channel|model)(?: is|:) ready|agent access granted/i)
    await leaveFinal(ui); w.run = normal; w.networks = []; w.requestState = 'needs_owner_finalization'; await reviewOwner(ui)
  }
  expect(finalCalls(w, 'sign')).toHaveLength(3); finalPrivacy(w, await visible(ui))
})

// Group4: native timers use request/fixed terms, not the historical approval window.
test('expired owner review window preserves Sign while exact request deadline removes controls without IO', async ($, on) => {
  const w = fixture(on); w.requestCreated = NOW - 1_200_000; w.requestExpiry = NOW + 2_400_000
  const ui = await finalEligible($, w, { expires: NOW - 300_000 }); await finalReview(ui, w)
  expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ })).toBeDefined()
  const at = finalCalls(w).length; await w.clock.advance(900_001)
  expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ })).toBeDefined()
  await w.clock.advance(w.requestExpiry - w.clock.now() - 1)
  expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ })).toBeDefined()
  await w.clock.advance(1); await noFinalSign(ui); expect(finalCalls(w)).toHaveLength(at)
  expect(await visible(ui)).toContain('Join request: publication recorded'); finalPrivacy(w, await visible(ui))
})

test('registered preflight delay crossing request deadline or future owner observation prevents sign dispatch', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w, { deadline: NOW + 1000 }), normal = w.run
  await finalReview(ui, w); const delayed = delaySignal(w, 1000)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_INSPECT) await delayed.wait(); return value }
  const pending = press(ui, 'Sign original finalization'); void pending.catch(() => undefined); await delayed.started
  await w.clock.advance(1001); await pending; expect(finalCalls(w, 'sign')).toHaveLength(0); await noFinalRecord(ui)
  await leaveFinal(ui); await back(ui); w.requestExpiry = NOW + 3_570_000; w.requestCreated = NOW - 30_000; w.run = normal
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: 96 })
  w.ownerValue = await ownerRecord(w, { state: 'approved', n: 96 }); await joinEntry(w, ui); await reviewOwner(ui); await finalReview(ui, w)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.lookup') value.observed_at = stamp(Math.floor(w.clock.now() / 1000) * 1000 + 31_000); return value }
  await press(ui, 'Sign original finalization'); expect(finalCalls(w, 'sign')).toHaveLength(0); await noFinalRecord(ui)
  finalPrivacy(w, await visible(ui))
})

test('request expiry after actual dispatch can still confirm retained historical F', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w, { deadline: NOW + 1000 }); await finalReview(ui, w)
  const normal = w.run, delayed = delaySignal(w, 2000)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_SIGN) {
    await delayed.wait(); value.request.state = 'expired'
  } return value }
  const pending = press(ui, 'Sign original finalization'); void pending.catch(() => undefined); await delayed.started
  await w.clock.advance(2000); await pending; await recorded(ui, w)
  expect(finalCalls(w, 'sign')).toHaveLength(1); finalPrivacy(w, await visible(ui))
})

// Group5: unknown is never a hidden retry or a claim that B/D do not exist.
test('denied nonzero raw and mismatched results stay unknown and Check only reads eligible or completed evidence', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w), normal = w.run
  for (const [index, mode] of ['deny', 'timeout', 'raw', 'mismatch'].entries()) {
    w.run = normal; w.requestState = 'needs_owner_finalization'; await finalReview(ui, w)
    w.run = async (kind, payload, e) => {
      if (kind === FINAL_SIGN) {
        if (mode === 'deny') return { fixtureDeny: true }
        if (mode === 'timeout') return { fixtureExit: true }
        if (mode === 'raw') return { fixtureRaw: RAW + CODE }
        const value = await normal(kind, payload, e); value.original_finalization.review_id = id64('review', 99); return value
      }
      return normal(kind, payload, e)
    }
    const before = finalCalls(w, 'sign').length; await press(ui, 'Sign original finalization'); await unknown(ui, w, mode)
    await w.clock.advance(1000); expect(finalCalls(w, 'sign').length).toBe(before + 1)
    w.run = normal; const inspected = finalCalls(w, 'inspect').length
    w.requestState = index === 1 ? 'needs_commit' : 'needs_owner_finalization'
    const lookup = ownerCalls(w, 'lookup').length; await press(ui, 'Check original finalization')
    expect(ownerCalls(w, 'lookup').length).toBe(lookup + 1); expect(finalCalls(w, 'sign').length).toBe(before + 1)
    expect(finalCalls(w, 'inspect').length).toBe(inspected + (index === 1 ? 0 : 1))
    if (index === 1) await recorded(ui, w)
    else {
      expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ })).toBeDefined()
      const shown = await visible(ui)
      expect(shown).not.toMatch(/\b(?:no|absent|missing) (?:binding|device|original) signatures?\b/i)
      expect(shown).toMatch(/partial|may[^\n]{0,80}(?:sign|binding|device)|already[^\n]{0,80}(?:sign|submi)/i)
    }
    await leaveFinal(ui); w.requestState = 'needs_owner_finalization'; await reviewOwner(ui)
  }
  expect(ownerCalls(w, 'prepare')).toHaveLength(0); expect(ownerCalls(w, 'approve')).toHaveLength(0)
  finalPrivacy(w, await visible(ui))
})

// Group6: synchronized late callbacks/timers and independent runtime invariants.
test('Leave during preflight or signing clears authority and old result or timer cannot replace a newer review', async ($, on) => {
  const w = fixture(on), ui = await finalEligible($, w, { deadline: NOW + 2000 }), normal = w.run
  for (const op of ['lookup', 'sign']) {
    w.run = normal; w.requestState = 'needs_owner_finalization'; await finalReview(ui, w)
    const delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === (op === 'lookup' ? 'join.owner.lookup' : FINAL_SIGN)) await delayed.wait(); return value }
    const before = finalCalls(w, 'sign').length, pending = press(ui, 'Sign original finalization'); void pending.catch(() => undefined); await delayed.started
    await press(ui, 'Leave finalization review'); await noFinalSign(ui); await noFinalRecord(ui)
    expect(await visible(ui)).toContain('Join request: publication recorded')
    w.run = normal; w.requestState = 'needs_owner_finalization'
    w.requestExpiry = NOW + 3_570_000; w.requestCreated = NOW - 30_000
    await back(ui)
    const n = op === 'lookup' ? 91 : 92
    w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n })
    w.ownerValue = await ownerRecord(w, { state: 'approved', n })
    await joinEntry(w, ui); await reviewOwner(ui); await finalReview(ui, w); const current = clone(w.lastInspection)
    await w.clock.advance(1000); await pending
    expect(finalCalls(w, 'sign').length).toBe(before + (op === 'sign' ? 1 : 0)); await noFinalRecord(ui)
    expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ })).toBeDefined()
    expect(w.lastInspection.review_id).toBe(current.review_id)
    await leaveFinal(ui); await reviewOwner(ui)
  }
  await finalReview(ui, w); const at = finalCalls(w).length; await w.clock.advance(1001)
  expect(await ui.find({ type: 'Button', text: /^Sign original finalization$/ })).toBeDefined()
  expect(finalCalls(w)).toHaveLength(at); finalPrivacy(w, await visible(ui))
})

test('Back Close Refresh root conversation host parent surface and end revoke dispatched callbacks without retraction', async ($, on) => {
  const w = fixture(on); let ui = await finalEligible($, w); const normal = w.run
  const parent = clone(w.parent), joining = clone(w.joining), retained = clone(w.ownerValue)
  for (const [index, mode] of ['back', 'close', 'refresh', 'root', 'native', 'host', 'parent', 'surface', 'end'].entries()) {
    if (index) { w.parent = clone(parent); w.joining = clone(joining); w.ownerValue = clone(retained); w.requestState = 'needs_owner_finalization'
      w.host = HOST; w.root = ROOT; w.native = NATIVE; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
      ui = await enter($, w); await joinEntry(w, ui); await reviewOwner(ui) }
    await finalReview(ui, w); const delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === FINAL_SIGN) await delayed.wait(); return value }
    const pending = press(ui, 'Sign original finalization'); void pending.catch(() => undefined); await delayed.started
    if (mode === 'back') await back(ui)
    if (mode === 'close') await press(ui, 'Close')
    if (mode === 'refresh') await press(ui, 'Refresh')
    if (mode === 'root') { w.root = '/departed-finalization-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'departed-finalization-conversation'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    await w.clock.advance(1000); await pending; await noFinalRecord(ui, mode); await noFinalSign(ui, mode)
    expect(w.ownerValue).toEqual(retained)
    const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  expect(finalCalls(w, 'sign')).toHaveLength(9); finalPrivacy(w)
})

test('finalization navigation and Check preserve established message task lease and durable invitation without new tools or prompts', async ($, on) => {
  const w = fixture(on), ui = await connected($, w)
  await enable($, w, ui); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  w.invitation = await invitationFlow(w.parent, network(9), { state: 'issued' }); const issued = clone(w.invitation)
  w.networks = []; w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' })
  w.requestState = 'needs_owner_finalization'; w.ownerValue = await ownerRecord(w, { state: 'approved' })
  await press(ui, /^Back to project$/); await joinEntry(w, ui); await reviewOwner(ui)
  const tools = w.tools.map(tool => tool.name), prompts = w.prompts.length, ready = readyCalls(w).length
  await finalReview(ui, w); await press(ui, 'Sign original finalization'); await press(ui, 'Check original finalization')
  await recorded(ui, w, true); await press(ui, 'Leave finalization review')
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length, leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.prompts.length).toBe(prompts); expect(readyCalls(w).length).toBe(ready); expect(w.tools.map(tool => tool.name)).toEqual(tools)
  expect(w.invitation).toEqual(issued); expect(finalCalls(w, 'sign')).toHaveLength(1); finalPrivacy(w, await visible(ui), true)
})
