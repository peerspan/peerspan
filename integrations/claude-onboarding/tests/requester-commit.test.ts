/**
 * Independent section29 requester-consent/completion native fixtures, pinned303.
 * Public effects and sections27/28 closed projections; no product imports,
 * real keys, process/network execution, persistence, inference or terminal probe.
 * Existing292 files/assertions/stimuli/delays/default timeouts and24 host suites
 * remain unchanged. Delays signal actual dispatch plus registered virtual sleep.
 * Host suites separately prove protocol/crypto/persistence. The current-drawing
 * kit cannot deliver obsolete rendered closures: that boundary, microscopic
 * final-check/dispatch and actual reload/installed/physical/model acceptance
 * remain source/manual limits. These tests do not prove process termination or
 * receipt/readiness from consent/application. Shared public fixture foundation
 * is copied from earlier independently authored suites, never production hooks.
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
    ownerValue: null as any, commitValue: null as any, lastCommit: null as any, finalizationValue: null as any, lastInspection: null as any, requestState: 'pending', requestCreated: NOW - 30_000, requestExpiry: NOW + 3_570_000, networks: [] as any[], invitation: null as any, previewValue: null as any, joining: null as any, identities: [{ public_key: KEY, sources: ["generated"] }] as any[], code: CODE, codes: [CODE, CODE2],
    calls: [] as any[], trace: [] as any[], httpCalls: [] as any[], outside: [] as string[], tools: [] as any[],
    forbidden: [] as string[], prompts: [] as any[], materials: [] as any[], inFlight: 0, maxInFlight: 0,
    messages: [] as any[], held: {} as Record<string, any>, seen: new Set<string>(), replies: {} as Record<string, any>,
    run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined,
    fetch: async (_e: any): Promise<any> => undefined,
    submit: async (e: any): Promise<any> => ({ text: e.text, origin: e.origin }) }
  w.run = async (kind, payload) => {
    if (kind === COMMIT_LOOKUP) return commitResponse(w)
    if (kind === COMMIT_PREPARE) { w.commitValue ??= await commitRecord(w); return commitResponse(w) }
    if (kind === COMMIT_APPROVE) {
      w.commitValue = { ...w.commitValue, state: 'approved', next_action: 'follow_join_progress' }
      return commitResponse(w)
    }
    if (kind === COMMIT_COMPLETE) {
      w.requestState = 'linked'
      const value = await commitResponse(w)
      return { ...value, completion: { state: 'locally_applied', review_id: w.commitValue.review_id,
        manifest_id: value.request.manifest_id, activation_id: value.request.activation_id, outcome_id: value.request.outcome_id,
        participant_delivery: 'not_verified', agent_access: 'not_verified', connection_readiness: 'not_verified' } }
    }
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
    const kind = tail[0] === 'join' && (tail[1] === 'owner' || tail[1] === 'commit') ? tail.slice(0, tail[2] === 'finalization' ? 4 : 3).join('.') : tail.length ? tail[0] + '.' + tail[1] : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    // Capture the serialized request independently of synthetic response
    // mutations; a real process stdout cannot mutate its already-sent stdin.
    const sent = payload === undefined ? undefined : clone(payload)
    w.calls.push({ ...e, kind, payload: sent, expectedContext: w.parent ? clone(context(w.parent)) : undefined,
      expectedProjectFlow: w.parent?.flow_id, expectedAdapterFlow: w.child?.flow_id,
      expectedFlow: w.joining?.flow_id, expectedJoinReview: w.joining?.review_id,
      expectedOwnerReview: w.ownerValue?.review_id, expectedCommitReview: w.commitValue?.review_id }); w.trace.push({ kind, payload: sent })
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
  const retainedState = ['expired', 'cancelled', 'blocked'].includes(w.requestState) ? 'needs_commit' : w.requestState
  const request = (await progressResponse(w, retainedState)).request
  const committed = ['finalizing', 'linked'].includes(w.requestState)
  return { ...request, state: w.requestState, created_at: stamp(w.requestCreated), expires_at: stamp(w.requestExpiry),
    manifest_id: committed ? id64('dm', 65) : '-', activation_id: committed ? id64('da', 66) : '-',
    outcome_id: w.requestState === 'linked' ? id64('dpk', 67) : '-',
    commit_approved: w.commitValue?.state === 'approved' || committed, attention: [], next: [] }

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

const COMMIT_LOOKUP = 'join.commit.lookup'
const COMMIT_PREPARE = 'join.commit.prepare'
const COMMIT_APPROVE = 'join.commit.approve'
const COMMIT_COMPLETE = 'join.commit.complete'
const commitEffects = { approve_commit_intent: true, authorize_binding_host_signature: true,
  authorize_requester_commit_signatures: true, authorize_commit_publication: true, authorize_local_application: true,
  grant_agent_access: false, share_files: false, share_conversation: false, capability_calls: false }
const commitCalls = (w: World, op?: string) => w.calls.filter(e => op ? e.kind === 'join.commit.' + op : e.kind.startsWith('join.commit.'))
const mutations = (w: World) => w.calls.filter(e => [COMMIT_APPROVE, COMMIT_COMPLETE].includes(e.kind))
const button = (ui: Pane, label: string) => ui.find({ type: 'Button', text: new RegExp('^' + label + '$') })

async function commitRecord(w: World, options: any = {}) {
  const request = await requestView(w), original = w.ownerValue.review
  const created = options.created ?? NOW - 1000
  const review = { version: 1, kind: 'approve_new_original_requester_commit', host_id: w.host, context: context(w.parent),
    flow_id: w.joining.flow_id, join_review_id: w.joining.review_id, owner_review_id: w.ownerValue.review_id,
    request_id: request.request_id, intent_id: id('dint', options.n ?? 80), network: clone(original.network), member: original.member,
    person_public_key: original.person_public_key, host_public_key: original.host_public_key, device_public_key: original.device_public_key,
    request_packet_id: request.request_packet_id, owner_offer_id: request.owner_offer_id, selection_id: request.selection_id,
    administrator_offer_id: request.administrator_offer_id, owner_finalization_id: request.owner_finalization_id,
    root_state_id: id64('ds', 101), person_lease_id: id64('ds', 102), host_lease_id: id64('ds', 103),
    binding_lease_id: id64('ds', 104), device_lease_id: id64('ds', 105), scopes: 7, binding_scopes: 2,
    not_after: original.not_after, provider: { kind: 'requester', host_public_key: original.host_public_key,
      device_public_key: original.device_public_key, signature_format: 'ed25519' }, created_at: stamp(created),
    expires_at: stamp(Math.min(created + 900_000, w.requestExpiry, Date.parse(original.not_after))), effects: clone(commitEffects) }
  const state = options.state ?? 'review'
  return { review_id: await digest('peerspan-requester-commit-review-v1', review), review, state,
    next_action: state === 'review' ? 'approve_requester_commit' : state === 'approved' ? 'follow_join_progress' : 'inspect_join_progress' }
}
async function commitResponse(w: World) {
  const commit = clone(w.commitValue)
  if (commit?.state === 'review' && Date.parse(commit.review.expires_at) <= w.clock.now()) {
    commit.state = 'expired'; commit.next_action = 'inspect_join_progress'
  }
  const value = { version: 1, host_id: w.host, flow_id: w.joining.flow_id, join_review_id: w.joining.review_id,
    context: context(w.parent), observed_at: stamp(Math.floor(w.clock.now() / 1000) * 1000),
    request: await requestView(w), commit }
  w.lastCommit = clone(value); return value
}
async function commitEligible($: Engine, w: World, options: any = {}) {
  w.requestState = options.requestState ?? 'needs_commit'
  if (options.deadline) { w.requestExpiry = options.deadline; w.requestCreated = options.deadline - 3_600_000 }
  if (options.created) w.requestCreated = options.created
  const ui = await ownerPublished($, w, { state: 'approved', flow: options.flow ?? 60 })
  if (options.commitState) w.commitValue = await commitRecord(w, { ...options, state: options.commitState })
  await reviewOwner(ui); return ui
}
async function reviewCommit(ui: Pane, w: World) {
  await press(ui, 'Review requester commit'); await w.clock.settle()
}
async function checkConsent(ui: Pane, w: World) {
  const at = w.calls.length
  await press(ui, 'Check requester consent')
  expect(w.calls.slice(at).filter(e => e.kind.startsWith('join.') &&
    !['join.inspect', 'join.lookup', 'join.owner.lookup', COMMIT_LOOKUP].includes(e.kind))).toEqual([])
}
async function leaveCommit(ui: Pane) {
  const leave = await button(ui, 'Leave requester review'); if (leave) await ui.press({ key: leave.key! })
}
async function reopenCommit(ui: Pane, w: World) {
  await leaveCommit(ui); await reviewOwner(ui); await reviewCommit(ui, w)
}
async function noMutations(ui: Pane, reason = '') {
  expect(await button(ui, 'Approve requester commit'), reason).toBeUndefined()
  expect(await button(ui, 'Complete requester commit'), reason).toBeUndefined()
}
async function unknownCommit(ui: Pane, w: World, reason = '') {
  await noMutations(ui, reason)
  expect(await visible(ui), reason).toMatch(/unknown|not confirmed|unavailable/i)
  expect(await visible(ui), reason).not.toContain('Local application: recorded')
  expect(await button(ui, 'Check requester consent'), reason).toBeDefined()
  expect(await visible(ui), reason).toContain('Join request: publication recorded')
  privacy(w, await visible(ui))
}
function privacy(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  for (const value of [TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path', NATIVE, ...w.codes,
    w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id, w.child?.flow_id, w.child?.review_id,
    w.joining?.flow_id, w.joining?.review_id, w.ownerValue?.review_id, w.ownerValue?.review.intent_id,
    w.commitValue?.review_id, w.commitValue?.review.intent_id, state].filter(Boolean)) {
    expect(shown).not.toContain(value); expect(w.outside.join('\n')).not.toContain(value)
    for (const prompt of w.prompts) expect(prompt.text).not.toContain(value)
  }
  expect(shown).not.toMatch(/\b(?:flow_[0-9a-f]{32}|review_[0-9a-f]{64}|dint_[0-9a-f]{32}|session_[0-9a-f]{32})\b/)
  expect(w.outside.join('\n')).not.toContain(ROOT)
  for (const e of w.calls) {
    const prefix = [executable, ...(state ? ['--state', state] : []), 'onboarding']
    expect(e.init?.timeoutMs, e.kind).toBe(e.kind === COMMIT_COMPLETE ? 95000 : 5000)
    const inspection = ({ 'project.inspect': e.expectedProjectFlow, 'join.inspect': e.expectedFlow,
      'adapter.inspect': e.expectedAdapterFlow } as Record<string, string | undefined>)[e.kind]
    if (inspection) expect(e.argv).toEqual([...prefix, e.kind.split('.')[0], 'inspect', inspection])
    else if (e.kind === 'snapshot') expect(e.argv).toEqual(prefix)
    else expect(e.argv).toEqual([...prefix, ...e.kind.split('.'), '--stdin'])
    for (const secret of [ROOT, NATIVE, TOKEN, SOCKET, ...w.codes]) expect(e.argv).not.toContain(secret)
    expect(e.kind).not.toMatch(/identit|create-identity|resume|selection|admi|\.sign$/)
    if (e.kind.startsWith('join.commit.')) {
      expect(e.payload).toEqual({ flow_id: e.expectedFlow, context: e.expectedContext, join_review_id: e.expectedJoinReview,
        ...([COMMIT_APPROVE, COMMIT_COMPLETE].includes(e.kind) ? { commit_review_id: e.expectedCommitReview } : {}),
        ...(e.kind === COMMIT_COMPLETE ? { decision: 'complete_requester_commit' } : {}) })
      expect(JSON.parse(e.init.stdin)).toEqual(e.payload)
      for (const value of [e.expectedFlow, e.expectedJoinReview, e.expectedOwnerReview, e.expectedCommitReview].filter(Boolean))
        expect(e.argv).not.toContain(value)
    }
  }
  if (!runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.map(tool => tool.name)).toEqual(['delivery_acknowledge'])
  }
}
async function terms(ui: Pane, w: World) {
  const review = w.commitValue.review, shown = await visible(ui)
  for (const term of [quote(ROOT), quote(review.network.name), quote(review.member), review.network.id, review.network.context_id,
    review.network.genesis_root_public_key, review.person_public_key, review.host_public_key, review.device_public_key,
    review.owner_offer_id, review.selection_id, review.administrator_offer_id, review.owner_finalization_id,
    review.root_state_id, review.person_lease_id, review.host_lease_id, review.binding_lease_id, review.device_lease_id,
    review.not_after, review.expires_at, stamp(w.requestExpiry), 'ed25519']) expect(shown).toContain(term)
  for (const meaning of [/original consent|owner consent/i, /profile[^\n]{0,35}7|7[^\n]{0,35}profile/i,
    /policy[^\n]{0,50}1|1[^\n]{0,50}policy/i, /(?:host )?binding[^\n]{0,50}2|2[^\n]{0,50}binding/i,
    /device[^\n]{0,100}4|4[^\n]{0,100}device/i, /administrator[^\n]{0,70}8|8[^\n]{0,70}administrator/i,
    /owned[^\n]{0,80}(?:host|device)|(?:host|device)[^\n]{0,80}owned/i,
    /(?:no|not|never)[^\n]{0,80}original|original[^\n]{0,80}(?:no|not|never)/i,
    /signature/i, /publication/i, /local application/i, /agent access/i, /files/i, /conversation/i, /capabilit/i,
    /leav|navigat/i, /retract|already[^\n]{0,40}dispatch/i]) expect(shown).toMatch(meaning)
  privacy(w, shown)
}
async function consentRecorded(ui: Pane) {
  expect(await visible(ui)).toContain('Requester consent: recorded')
  expect(await button(ui, 'Approve requester commit')).toBeUndefined()
}
async function applicationRecorded(ui: Pane, w: World, runtime = false, configuration: Record<string, string> = {}) {
  const shown = await visible(ui)
  expect(shown).toContain('Local application: recorded')
  for (const reference of [id64('dm', 65), id64('da', 66), id64('dpk', 67)]) expect(shown).toContain(reference)
  expect(shown).not.toMatch(/(?:this pane|this frontend|this conversation) (?:approved|completed|applied)/i)
  expect(shown).toMatch(/not verified|not confirmed|unverified/i)
  await noMutations(ui); privacy(w, shown, runtime, configuration.executable ?? 'peerspan', configuration.state)
}
const configuredCommit: TestOptions & { options: Record<string, string> } = {
  // Native303 supports runtime options despite their declaration omission.
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private requester state/$(literal)' },
}

test('entry original approval owner Check progress Refresh and fresh reentry never prepare requester consent', async ($, on) => {
  const w = fixture(on); w.requestState = 'pending'
  const ui = await ownerPublished($, w, { state: 'review' })
  await reviewOwner(ui); await press(ui, 'Approve owner powers')
  expect(commitCalls(w)).toHaveLength(0)
  w.requestState = 'needs_commit'; w.ownerValue.next_action = 'follow_join_progress'
  await press(ui, 'Check owner consent'); expect(await button(ui, 'Review requester commit')).toBeDefined()
  expect(commitCalls(w)).toHaveLength(0)
  await press(ui, 'Leave owner review'); await press(ui, 'Check join progress'); await press(ui, 'Refresh')
  await w.clock.advance(1000); expect(commitCalls(w)).toHaveLength(0)
  await back(ui); await joinEntry(w, ui); await reviewOwner(ui)
  expect(commitCalls(w)).toHaveLength(0); privacy(w, await visible(ui))
})

test('entry requires exact approved original F while expired or cancelled null history never prepares', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w), normal = w.run
  const variants: [string, (value: any) => void][] = [
    ['owner missing', v => { v.owner = null }], ['owner unapproved', v => { v.owner.state = 'review'; v.owner.next_action = 'approve_owner_intent' }],
    ['F absent', v => { v.request.owner_finalization_id = '-'; v.request.completed.pop(); v.request.state = 'needs_owner_finalization' }],
    ['selection', v => { v.request.selection_approved = false }], ['requester', v => { v.request.role = 'approver' }],
    ['renew', v => { v.request.mode = 'renew' }], ['migration', v => { v.request.migration_proposal_id = id64('ds', 999) }],
  ]
  for (const [label, change] of variants) {
    await leaveIfPresent(ui)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === 'join.owner.lookup' || kind === 'join.owner.prepare') change(value)
      return value }
    await reviewOwner(ui); expect(await button(ui, 'Review requester commit'), label).toBeUndefined()
  }
  w.run = normal; await leaveIfPresent(ui); await w.clock.advance(w.requestExpiry - w.clock.now() + 1000)
  for (const state of ['expired', 'cancelled']) {
    w.requestState = state; await reviewOwner(ui)
    expect(await button(ui, 'Review requester commit'), state).toBeDefined(); await reviewCommit(ui, w)
    await noMutations(ui, state); expect(commitCalls(w, 'prepare')).toHaveLength(0)
    await leaveCommit(ui)
  }
  expect(mutations(w)).toHaveLength(0); privacy(w, await visible(ui))
})

test('explicit null lookup precedes one preparation and displays exact quoted powers parents provider and effects', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w)
  expect(commitCalls(w)).toHaveLength(0); await reviewCommit(ui, w)
  expect(commitCalls(w).map(e => e.kind)).toEqual([COMMIT_LOOKUP, COMMIT_PREPARE])
  expect(await button(ui, 'Approve requester commit')).toBeDefined(); expect(await button(ui, 'Complete requester commit')).toBeUndefined()
  await terms(ui, w); const retained = clone(w.commitValue), prepared = commitCalls(w, 'prepare').length
  await checkConsent(ui, w)
  expect(w.commitValue).toEqual(retained); expect(commitCalls(w, 'prepare')).toHaveLength(prepared)
  expect(mutations(w)).toHaveLength(0); await terms(ui, w)
})

test('existing review approved and terminal histories recover lookup-only and null Check cannot prepare', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w)
  for (const state of ['review', 'approved', 'cancelled', 'invalidated', 'expired']) {
    w.requestState = state === 'cancelled' ? 'cancelled' : state === 'invalidated' ? 'blocked' : state === 'expired' ? 'expired' : 'needs_commit'
    w.commitValue = await commitRecord(w, { state })
    if (state === 'expired') await w.clock.advance(Date.parse(w.commitValue.review.expires_at) - w.clock.now() + 1000)
    await reviewCommit(ui, w); expect(commitCalls(w, 'prepare')).toHaveLength(0)
    if (state === 'approved') await consentRecorded(ui)
    if (!['review', 'approved'].includes(state)) await noMutations(ui, state)
    const ownerReads = ownerCalls(w, 'lookup').length, reads = commitCalls(w, 'lookup').length
    await checkConsent(ui, w)
    expect(ownerCalls(w, 'lookup')).toHaveLength(ownerReads + 1); expect(commitCalls(w, 'lookup')).toHaveLength(reads + 1)
    expect(commitCalls(w, 'prepare')).toHaveLength(0); await leaveCommit(ui); await reviewOwner(ui)
  }
  w.commitValue = null; await reviewCommit(ui, w); await checkConsent(ui, w)
  expect(commitCalls(w, 'prepare')).toHaveLength(0); expect(mutations(w)).toHaveLength(0)
  await noMutations(ui); privacy(w, await visible(ui))
})

test('double Approve freshly rechecks exact bindings and sends one configured5s private stdin action without Complete', configuredCommit, async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w); await reviewCommit(ui, w)
  const normal = w.run, delayed = delaySignal(w, 1000), captured = clone(w.commitValue), at = w.trace.length
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'join.owner.lookup') await delayed.wait(); return value }
  const control = await key(ui, 'Approve requester commit'), pending = ui.press({ key: control }); void pending.catch(() => undefined)
  await delayed.started; const second = ui.press({ key: control }).catch(() => undefined)
  expect(commitCalls(w, 'approve')).toHaveLength(0)
  await w.clock.advance(1000); await Promise.all([pending, second])
  expect(commitCalls(w, 'approve')).toHaveLength(1); expect(commitCalls(w, 'complete')).toHaveLength(0)
  expect(commitCalls(w, 'approve')[0].payload.commit_review_id).toBe(captured.review_id)
  const trace = w.trace.slice(at), sent = trace.findIndex(e => e.kind === COMMIT_APPROVE)
  for (const kind of ['project.inspect', 'join.inspect', 'snapshot', 'join.owner.lookup', COMMIT_LOOKUP, 'root', 'native'])
    expect(trace.slice(0, sent).some(e => e.kind === kind), kind).toBe(true)
  await consentRecorded(ui); expect(await button(ui, 'Complete requester commit')).toBeDefined()
  privacy(w, await visible(ui), false, configuredCommit.options.executable, configuredCommit.options.state)
})

test('double Complete sends one configured95s exact decision and requires verified local application without readiness', configuredCommit, async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w, { commitState: 'approved' }); await reviewCommit(ui, w)
  const normal = w.run, delayed = delaySignal(w, 1000), retained = clone(w.commitValue), at = w.trace.length
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === COMMIT_LOOKUP) await delayed.wait(); return value }
  const control = await key(ui, 'Complete requester commit'), pending = ui.press({ key: control }); void pending.catch(() => undefined)
  await delayed.started; const second = ui.press({ key: control }).catch(() => undefined)
  expect(commitCalls(w, 'complete')).toHaveLength(0)
  await w.clock.advance(1000); await Promise.all([pending, second])
  expect(commitCalls(w, 'complete')).toHaveLength(1); expect(commitCalls(w, 'approve')).toHaveLength(0)
  expect(commitCalls(w, 'complete')[0].payload).toEqual({ flow_id: w.joining.flow_id, context: context(w.parent),
    join_review_id: w.joining.review_id, commit_review_id: retained.review_id, decision: 'complete_requester_commit' })
  const trace = w.trace.slice(at), sent = trace.findIndex(e => e.kind === COMMIT_COMPLETE)
  for (const kind of ['project.inspect', 'join.inspect', 'snapshot', 'join.owner.lookup', COMMIT_LOOKUP, 'root', 'native'])
    expect(trace.slice(0, sent).some(e => e.kind === kind), kind).toBe(true)
  await applicationRecorded(ui, w, false, configuredCommit.options)
})

test('already globally approved or locally applied preflight recovers read-only with zero mutation calls', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w); await reviewCommit(ui, w)
  w.commitValue = { ...w.commitValue, state: 'approved', next_action: 'follow_join_progress' }
  await press(ui, 'Approve requester commit'); expect(mutations(w)).toHaveLength(0); await consentRecorded(ui)
  w.requestState = 'linked'; await press(ui, 'Complete requester commit')
  expect(mutations(w)).toHaveLength(0); await applicationRecorded(ui, w)
  expect(commitCalls(w, 'prepare')).toHaveLength(1)
})

test('changed immutable consent original F request provider or selected terms stop preflight without mutation', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['intent', v => { v.commit.review.intent_id = id('dint', 999) }], ['root', v => { v.commit.review.root_state_id = id64('ds', 999) }],
    ['F', v => { v.request.owner_finalization_id = id64('dpk', 999) }], ['offer', v => { v.request.owner_offer_id = id64('dpk', 999) }],
    ['selection', v => { v.request.selection_id = id64('dpk', 999) }], ['administrator', v => { v.request.administrator_offer_id = id64('dpk', 999) }],
    ['host', v => { v.request.host_public_key = GENESIS_KEY }], ['device', v => { v.request.device_public_key = GENESIS_KEY }],
    ['powers', v => { v.commit.review.scopes = 15 }], ['end', v => { v.commit.review.not_after = stamp(NOW + 86_400_000) }],
  ]
  for (const [label, change] of variants) {
    w.run = normal; await reviewCommit(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === COMMIT_LOOKUP) { change(value); value.commit.review_id = await digest('peerspan-requester-commit-review-v1', value.commit.review) }
      return value }
    await press(ui, 'Approve requester commit'); expect(mutations(w), label).toHaveLength(0)
    await noMutations(ui, label); await leaveCommit(ui); w.run = normal; await reviewOwner(ui)
  }
  w.commitValue = { ...w.commitValue, state: 'approved', next_action: 'follow_join_progress' }
  for (const [field, prefix] of [['manifest_id', 'dm'], ['activation_id', 'da'], ['outcome_id', 'dpk']]) {
    w.run = normal; await reviewCommit(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === COMMIT_LOOKUP) value.request[field] = id64(prefix, 999)
      return value }
    await press(ui, 'Complete requester commit'); expect(mutations(w), field).toHaveLength(0)
    await noMutations(ui, field); await leaveCommit(ui); w.run = normal; await reviewOwner(ui)
  }
  privacy(w, await visible(ui))
})

test('authoritative parent host flow root native and terminal are reread after preparation IO before display', async ($, on) => {
  const w = fixture(on); let ui = await commitEligible($, w); const normal = w.run
  const saved = { parent: clone(w.parent), joining: clone(w.joining), owner: clone(w.ownerValue) }
  for (const [index, mode] of ['parent', 'host', 'flow', 'root', 'native', 'terminal'].entries()) {
    if (index) {
      w.parent = clone(saved.parent); w.joining = clone(saved.joining); w.ownerValue = clone(saved.owner); w.commitValue = null
      w.host = HOST; w.root = ROOT; w.native = NATIVE; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
      ui = await enter($, w); await joinEntry(w, ui); await reviewOwner(ui)
    }
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === COMMIT_PREPARE) {
        if (mode === 'parent') w.parent.state = 'invalidated'
        if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
        if (mode === 'flow') w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: 99 })
        if (mode === 'root') w.root = '/different-committing-root'
        if (mode === 'native') w.native = 'different-native-conversation'
        if (mode === 'terminal') { w.surface = null; w.surfaces = [] }
      }
      return value }
    await reviewCommit(ui, w); await noMutations(ui, mode); expect(mutations(w)).toHaveLength(0)
    const close = await button(ui, 'Close'); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  privacy(w)
})

test('closed wrapper LINK_VIEW dates prefix and request binding corpus refuses actionable terms', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w), normal = w.run
  w.commitValue = await commitRecord(w)
  const variants: [string, (v: any) => void][] = [
    ['extra wrapper', v => { v.extra = true }], ['missing wrapper', v => { delete v.context }], ['version', v => { v.version = 2 }],
    ['host', v => { v.host_id = 'host_' + '9'.repeat(64) }], ['flow', v => { v.flow_id = id('flow', 999) }],
    ['join', v => { v.join_review_id = id64('review', 999) }], ['request', v => { v.request.request_id = id64('link', 999) }],
    ['context', v => { v.context.native_session_id = 'different-native' }], ['null request', v => { v.request = null }],
    ['extra request', v => { v.request.private = RAW }], ['fresh manifest', v => { v.request.manifest_id = id64('dm', 99) }],
    ['prefix', v => { v.request.completed.pop() }], ['future', v => { v.observed_at = stamp(w.clock.now() + 31_000) }],
    ['fractional UTC', v => { v.observed_at = new Date(w.clock.now()).toISOString() }],
    ['approved manifest', v => { v.request.manifest_id = id64('dm', 999) }],
    ['approved activation', v => { v.request.activation_id = id64('da', 999) }],
    ['approved outcome', v => { v.request.outcome_id = id64('dpk', 999) }],
  ]
  for (const [label, change] of variants) {
    w.commitValue = { ...w.commitValue, state: label.startsWith('approved') ? 'approved' : 'review',
      next_action: label.startsWith('approved') ? 'follow_join_progress' : 'approve_requester_commit' }
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === COMMIT_LOOKUP) change(value); return value }
    await reviewCommit(ui, w); await noMutations(ui, label); expect(mutations(w)).toHaveLength(0)
    await leaveCommit(ui); w.run = normal; await reviewOwner(ui)
  }
  privacy(w, await visible(ui))
})

test('review digest fixed powers provider root parents UTC and creation bounds refuse semantic substitutions', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w), normal = w.run
  w.commitValue = await commitRecord(w)
  const variants: [string, (v: any) => void][] = [
    ['kind', v => { v.commit.review.kind = 'approve_other' }], ['extra', v => { v.commit.review.extra = true }],
    ['digest', v => { v.commit.review_id = id64('review', 999) }], ['effects', v => { v.commit.review.effects.share_files = true }],
    ['effect type', v => { v.commit.review.effects.authorize_local_application = 1 }], ['scopes', v => { v.commit.review.scopes = 15 }],
    ['binding', v => { v.commit.review.binding_scopes = 4 }], ['end', v => { v.commit.review.not_after = stamp(NOW + 86_400_000) }],
    ['provider', v => { v.commit.review.provider.kind = 'original' }], ['format', v => { v.commit.review.provider.signature_format = 'sshsig' }],
    ['provider key', v => { v.commit.review.provider.device_public_key = GENESIS_KEY }],
    ['distinct parents', v => { v.commit.review.binding_lease_id = v.commit.review.root_state_id }],
    ['parent type', v => { v.commit.review.root_state_id = id64('drs', 101) }],
    ['creation', v => { v.commit.review.created_at = stamp(w.requestCreated - 1000)
      v.commit.review.expires_at = stamp(Math.min(w.requestCreated - 1000 + 900_000, w.requestExpiry, Date.parse(v.commit.review.not_after))) }],
    ['future creation', v => { v.commit.review.created_at = stamp(w.clock.now() + 1000)
      v.commit.review.expires_at = stamp(Math.min(w.clock.now() + 1000 + 900_000, w.requestExpiry, Date.parse(v.commit.review.not_after))) }],
    ['review end', v => { v.commit.review.expires_at = stamp(Date.parse(v.commit.review.expires_at) + 1000) }],
    ['key', v => { v.commit.review.person_public_key = 'not-a-canonical-key' }],
  ]
  for (const [label, change] of variants) {
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === COMMIT_LOOKUP) { change(value)
        if (label !== 'digest') value.commit.review_id = await digest('peerspan-requester-commit-review-v1', value.commit.review) }
      return value }
    await reviewCommit(ui, w); await noMutations(ui, label); expect(mutations(w)).toHaveLength(0)
    await leaveCommit(ui); w.run = normal; await reviewOwner(ui)
  }
  privacy(w, await visible(ui))
})

test('all seven short private token forms including decorated OSC content never enter requester terms or public output', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w), normal = w.run
  w.commitValue = await commitRecord(w)
  const prefixes = ['psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.', 'peerspan-person-invite-v1.', 'token_', 'instance_']
  for (const [index, prefix] of prefixes.entries()) for (const decorated of [false, true]) {
    const secret = 'SHORTCOMMIT' + index
    const bad = decorated ? '\x1b]0;' + prefix.slice(0, 2) + '\u202e\x1b[0m' + prefix.slice(2) + secret + '\x07visible' : prefix + secret
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === COMMIT_LOOKUP) {
        value.commit.review[index % 2 ? 'member' : 'network'] = index % 2 ? bad : { ...value.commit.review.network, name: bad }
        value.commit.review_id = await digest('peerspan-requester-commit-review-v1', value.commit.review)
      }
      return value }
    await reviewCommit(ui, w); await noMutations(ui, prefix)
    expect(await visible(ui)).not.toContain(prefix); expect(await visible(ui)).not.toContain(secret)
    expect(w.outside.join('\n')).not.toContain(prefix); expect(w.outside.join('\n')).not.toContain(secret)
    await leaveCommit(ui); w.run = normal; await reviewOwner(ui)
  }
  expect(mutations(w)).toHaveLength(0); privacy(w, await visible(ui))
})

test('malformed or changed approval replies stay unknown and Check recovers only global consent without completion', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['missing', v => { delete v.commit }], ['null', v => { v.commit = null }], ['extra', v => { v.extra = true }],
    ['unapproved', v => { v.commit.state = 'review'; v.commit.next_action = 'approve_requester_commit' }],
    ['changed digest', v => { v.commit.review_id = id64('review', 999) }], ['wrong request', v => { v.request.request_id = id64('link', 999) }],
    ['F', v => { v.request.owner_finalization_id = id64('dpk', 999) }], ['request consent', v => { v.request.commit_approved = false }],
    ['end', v => { v.commit.review.not_after = stamp(NOW + 86_400_000) }], ['private', v => { v.commit.review.member = 'token_SHORTREPLY' }],
  ]
  for (const [label, change] of variants) {
    w.run = normal; w.requestState = 'needs_commit'; w.commitValue = await commitRecord(w)
    await reviewCommit(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === COMMIT_APPROVE) change(value); return value }
    const before = commitCalls(w, 'approve').length
    await press(ui, 'Approve requester commit'); await unknownCommit(ui, w, label)
    expect(await visible(ui)).not.toContain('SHORTREPLY'); expect(commitCalls(w, 'approve')).toHaveLength(before + 1)
    w.run = normal; const at = commitCalls(w).length
    await checkConsent(ui, w); await consentRecorded(ui)
    expect(commitCalls(w).slice(at).map(e => e.kind)).toEqual([COMMIT_LOOKUP]); expect(commitCalls(w, 'complete')).toHaveLength(0)
    await leaveCommit(ui); await reviewOwner(ui)
  }
  privacy(w, await visible(ui))
})

test('bare null extra mismatched or overclaiming completion markers cannot confirm application and Check invents no marker', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w, { commitState: 'approved' }), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['bare', v => { delete v.completion }], ['null', v => { v.completion = null }], ['extra', v => { v.completion.extra = true }],
    ['state', v => { v.completion.state = 'approved' }], ['review', v => { v.completion.review_id = id64('review', 999) }],
    ['manifest', v => { v.completion.manifest_id = id64('dm', 999) }], ['activation', v => { v.completion.activation_id = id64('da', 999) }],
    ['outcome', v => { v.completion.outcome_id = id64('dpk', 999) }], ['delivery', v => { v.completion.participant_delivery = 'verified' }],
    ['agent', v => { v.completion.agent_access = true }], ['readiness', v => { v.completion.connection_readiness = 'ready' }],
    ['prefix', v => { v.request.completed.pop() }], ['private', v => { v.completion.outcome_id = 'token_SHORTMARKER' }],
  ]
  for (const [label, change] of variants) {
    w.run = normal; w.requestState = 'needs_commit'; w.commitValue = await commitRecord(w, { state: 'approved' })
    await reviewCommit(ui, w)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === COMMIT_COMPLETE) change(value); return value }
    const before = commitCalls(w, 'complete').length
    await press(ui, 'Complete requester commit'); await unknownCommit(ui, w, label)
    expect(await visible(ui)).not.toContain('SHORTMARKER'); expect(commitCalls(w, 'complete')).toHaveLength(before + 1)
    w.run = normal; const at = commitCalls(w).length
    await checkConsent(ui, w); await applicationRecorded(ui, w)
    expect(commitCalls(w).slice(at).map(e => e.kind)).toEqual([COMMIT_LOOKUP])
    expect(await visible(ui)).not.toMatch(/completion (?:reply|marker)[^\n]{0,40}confirmed/i)
    await leaveCommit(ui); w.requestState = 'needs_commit'; await reviewOwner(ui)
  }
  expect(commitCalls(w, 'approve')).toHaveLength(0); privacy(w, await visible(ui))
})

test('denied nonzero timed-out raw and null mutations show fixed unknown without automatic retry or raw echo', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w), normal = w.run
  for (const op of ['approve', 'complete']) for (const mode of ['deny', 'timeout', 'raw', 'null']) {
    w.run = normal; w.requestState = 'needs_commit'; w.commitValue = await commitRecord(w, { state: op === 'approve' ? 'review' : 'approved' })
    await reviewCommit(ui, w)
    w.run = async (kind, payload, e) => {
      if (kind === 'join.commit.' + op) {
        if (mode === 'deny') return { fixtureDeny: true }
        if (mode === 'timeout') return { fixtureExit: true }
        if (mode === 'raw') return { fixtureRaw: RAW + CODE }
        return null
      }
      return normal(kind, payload, e) }
    const before = mutations(w).length
    await press(ui, op === 'approve' ? 'Approve requester commit' : 'Complete requester commit'); await unknownCommit(ui, w, op + mode)
    await w.clock.advance(1000); expect(mutations(w)).toHaveLength(before + 1)
    w.run = normal; const at = w.calls.length
    await checkConsent(ui, w)
    expect(w.calls.slice(at).filter(e => e.kind.startsWith('join.commit.')).map(e => e.kind)).toEqual([COMMIT_LOOKUP])
    expect(mutations(w)).toHaveLength(before + 1)
    await leaveCommit(ui); await reviewOwner(ui)
  }
  privacy(w, await visible(ui))
})

test('human review expiry removes Approve at the exact boundary without reading renewing or mutating', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w); await reviewCommit(ui, w)
  const end = Date.parse(w.commitValue.review.expires_at), before = w.calls.length
  await w.clock.advance(end - w.clock.now() - 1)
  expect(await button(ui, 'Approve requester commit')).toBeDefined()
  await w.clock.advance(1); await noMutations(ui)
  expect(w.calls).toHaveLength(before); expect(await button(ui, 'Check requester consent')).toBeDefined()
  privacy(w, await visible(ui))
})

test('approved signed six-stage work keeps Complete after review expiry then loses it at signed request deadline', async ($, on) => {
  const w = fixture(on), ui = await commitEligible($, w, { commitState: 'approved', requestState: 'finalizing' })
  await reviewCommit(ui, w); const end = Date.parse(w.commitValue.review.expires_at), before = w.calls.length
  expect(await button(ui, 'Complete requester commit')).toBeDefined()
  await w.clock.advance(end - w.clock.now() + 1)
  expect(await button(ui, 'Complete requester commit')).toBeDefined(); await consentRecorded(ui)
  expect(w.calls).toHaveLength(before)
  await w.clock.advance(w.requestExpiry - w.clock.now()); await noMutations(ui)
  expect(w.calls).toHaveLength(before); privacy(w, await visible(ui))
})

test('actual registered preflight deadline crossing blocks dispatch while post-dispatch expiry permits valid historical evidence', async ($, on) => {
  const w = fixture(on); let ui: Pane | undefined; const normal = w.run
  for (const op of ['approve', 'complete']) for (const phase of ['preflight', 'dispatched']) {
    w.run = normal; w.commitValue = null
    ui = await commitEligible($, w, { commitState: op === 'approve' ? 'review' : 'approved', deadline: w.clock.now() + 1000 })
    await reviewCommit(ui, w)
    const delayed = delaySignal(w, 2000), kind = phase === 'preflight' ? COMMIT_LOOKUP : 'join.commit.' + op
    w.run = async (operation, payload, e) => { const value = await normal(operation, payload, e); if (operation === kind) await delayed.wait(); return value }
    const before = mutations(w).length, pending = press(ui, op === 'approve' ? 'Approve requester commit' : 'Complete requester commit')
    void pending.catch(() => undefined); await delayed.started
    await w.clock.advance(2000); await pending
    expect(mutations(w)).toHaveLength(before + (phase === 'dispatched' ? 1 : 0))
    if (phase === 'preflight') await noMutations(ui)
    else if (op === 'approve') { await consentRecorded(ui); expect(await button(ui, 'Complete requester commit')).toBeUndefined() }
    else await applicationRecorded(ui, w)
    const close = await button(ui, 'Close'); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  privacy(w)
})

test('Leave pending operations and native navigation changes invalidate late results and old timers without retracting consent', async ($, on) => {
  const w = fixture(on); let ui = await commitEligible($, w, { commitState: 'approved', deadline: NOW + 2000 }); const normal = w.run
  await reviewCommit(ui, w)
  const oldRead = delaySignal(w, 1000)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === COMMIT_LOOKUP) await oldRead.wait(); return value }
  const oldAction = press(ui, 'Complete requester commit'); void oldAction.catch(() => undefined); await oldRead.started
  await press(ui, 'Leave requester review'); await noMutations(ui)
  w.run = normal; w.requestState = 'needs_commit'; w.requestCreated = NOW - 30_000; w.requestExpiry = NOW + 3_570_000
  await back(ui)
  w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested', n: 91 })
  w.ownerValue = await ownerRecord(w, { state: 'approved', n: 91 }); w.commitValue = await commitRecord(w, { state: 'approved', n: 91 })
  await joinEntry(w, ui); await reviewOwner(ui); await reviewCommit(ui, w)
  const current = clone(w.commitValue)
  await w.clock.advance(1000); await oldAction
  expect(mutations(w)).toHaveLength(0); expect(w.commitValue).toEqual(current)
  expect(await button(ui, 'Complete requester commit')).toBeDefined(); expect(await visible(ui)).not.toContain('Local application: recorded')
  const calls = w.calls.length; await w.clock.advance(1001)
  expect(await button(ui, 'Complete requester commit')).toBeDefined(); expect(w.calls).toHaveLength(calls)
  await press(ui, 'Close'); await ui.unmount()
  const saved = { parent: clone(w.parent), joining: clone(w.joining), owner: clone(w.ownerValue) }
  const modes = ['leave', 'root', 'native', 'host'].map(mode => ({ mode, phase: 'preflight' }))
    .concat(['leave', 'back', 'close', 'refresh', 'root', 'native', 'host', 'parent', 'surface', 'end']
      .map(mode => ({ mode, phase: 'dispatched' })))
  for (const { mode, phase } of modes) {
    w.parent = clone(saved.parent); w.joining = clone(saved.joining); w.ownerValue = clone(saved.owner)
    w.host = HOST; w.root = ROOT; w.native = NATIVE; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal; w.requestState = 'needs_commit'
    w.commitValue = await commitRecord(w, { state: 'approved', n: 91 }); ui = await enter($, w); await joinEntry(w, ui); await reviewOwner(ui)
    await reviewCommit(ui, w); const retained = clone(w.commitValue), delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e)
      if (kind === (phase === 'preflight' ? COMMIT_LOOKUP : COMMIT_COMPLETE)) await delayed.wait(); return value }
    const pending = press(ui, 'Complete requester commit'); void pending.catch(() => undefined); await delayed.started
    if (mode === 'leave') await press(ui, 'Leave requester review')
    if (mode === 'back') await back(ui)
    if (mode === 'close') await press(ui, 'Close')
    if (mode === 'refresh') await press(ui, 'Refresh')
    if (mode === 'root') { w.root = '/departed-requester-root'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'departed-requester-conversation'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'parent') w.parent.state = 'invalidated'
    if (mode === 'surface') { w.surface = null; w.surfaces = [] }
    if (mode === 'end') await $.session.end({ reason: 'clear', sessionId: NATIVE, resume: { id: NATIVE } })
    await w.clock.advance(1000); await pending; await noMutations(ui, mode)
    expect(await visible(ui), mode).not.toContain('Local application: recorded'); expect(w.commitValue).toEqual(retained)
    const close = await button(ui, 'Close'); if (close) await ui.press({ key: close.key! }); await ui.unmount()
  }
  expect(commitCalls(w, 'complete')).toHaveLength(10); privacy(w)
})

test('requester navigation preserves established message task lease and invitation state without new tools prompts or storage', async ($, on) => {
  const w = fixture(on), ui = await connected($, w)
  await enable($, w, ui); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  w.invitation = await invitationFlow(w.parent, network(9), { state: 'issued' }); const issued = clone(w.invitation)
  w.networks = []; w.joining = await joinFlow(w.parent, await previewResponse(w), KEY, { state: 'requested' })
  w.requestState = 'needs_commit'; w.ownerValue = await ownerRecord(w, { state: 'approved' })
  await press(ui, /^Back to project$/); await joinEntry(w, ui); await reviewOwner(ui)
  const tools = w.tools.map(tool => tool.name), prompts = w.prompts.length, ready = readyCalls(w).length
  await reviewCommit(ui, w); await press(ui, 'Approve requester commit'); await press(ui, 'Complete requester commit')
  await checkConsent(ui, w); await applicationRecorded(ui, w, true); await press(ui, 'Leave requester review')
  const messages = claims(w).length, tasks = requests(w, '/adapter/v1/tasks/next').length, leases = requests(w, '/adapter/v1/connect').length
  await w.clock.advance(5000)
  expect(claims(w).length > messages).toBe(true); expect(requests(w, '/adapter/v1/tasks/next').length > tasks).toBe(true)
  expect(requests(w, '/adapter/v1/connect').length).toBe(leases + 1)
  expect(w.prompts).toHaveLength(prompts); expect(readyCalls(w)).toHaveLength(ready); expect(w.tools.map(tool => tool.name)).toEqual(tools)
  expect(w.invitation).toEqual(issued); expect(commitCalls(w, 'approve')).toHaveLength(1); expect(commitCalls(w, 'complete')).toHaveLength(1)
  privacy(w, await visible(ui), true)
})
