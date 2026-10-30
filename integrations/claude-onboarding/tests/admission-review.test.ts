/**
 * Independent section23 native admission-review cases, pinnedClaude2.1.303.
 * Public native runtime effects only; no production imports, auth, inference,
 * filesystem/clipboard actions or protocol-signature possession claims.
 * Original252 files/assertions/stimuli/delays/default timeouts stay unchanged.
 * Host incoming/consent suites separately prove cryptography and persistence.
 * The kit dispatches current drawings: obsolete rendered callback closures,
 * actual reload/terminal/installed/model and microscopic final-dispatch races
 * remain explicit source/manual acceptance; no invented handler handles.
 * All delayed effects signal actual dispatch AND registered virtual sleep
 * before any navigation/time stimulus. TestOptions.options is runtime-supported
 * on303 despite its omitted declaration, as prior independent fixtures proved.
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


const id64 = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(64, '0')
const stages = ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered', 'owner_finalized', 'commit_persisted', 'locally_applied']
const admissionEffects = { approve_administrator_intent: true, authorize_network_root_signature: true,
  authorize_host_packet_signature: true, publish_administrator_offer_after_signatures: true,
  grant_membership: false, grant_agent_access: false, authorize_original_finalization: false, commit_request: false,
  share_files: false, share_conversation: false, capability_calls: false }
const inspectionEffects = { verify_request_signature: true, verify_original_owner_signature: true,
  verify_requester_selection: true, prepare_administrator_intent: false, approve_administrator_intent: false,
  sign_admission: false, grant_membership: false, grant_agent_access: false, commit_request: false,
  share_files: false, share_conversation: false, capability_calls: false }
function network(): any {
  return { id: id64('net', 1), name: 'Network "é東京"', mode: 'decentralized', context_id: id64('ctx', 1),
    genesis_root_public_key: GENESIS_KEY, root_state_id: id64('ds', 2), root_public_key: GENESIS_KEY, root_epoch: 0,
    member: 'local owner', host_public_key: INVITER_KEY, person_public_key: KEY, provider: null,
    provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'usable', not_after: stamp(NOW + 86_400_000), required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: stamp(NOW - 1000) }
}
function request(n = 1, state = 'needs_administrator', options: any = {}): any {
  const states = ['pending', 'needs_selection', 'needs_administrator', 'needs_owner_finalization', 'needs_commit', 'finalizing', 'linked']
  const level = Math.max(0, states.indexOf(state)), net = network()
  const created = options.created ?? NOW - 60_000
  return { request_id: id64('link', n), role: 'approver', mode: 'new', state, network_id: net.id, context_id: net.context_id,
    migration_proposal_id: '-', person_public_key: KEY, host_public_key: GENESIS_KEY, device_public_key: RELAY_KEY,
    created_at: stamp(created), expires_at: stamp(options.expires ?? created + 3_600_000), request_packet_id: id64('dpk', n * 10),
    owner_offer_id: level >= 1 ? id64('dpk', n * 10 + 1) : '-', selection_id: level >= 2 ? id64('dpk', n * 10 + 2) : '-',
    administrator_offer_id: level >= 3 ? id64('dpk', n * 10 + 3) : '-', owner_finalization_id: level >= 4 ? id64('dpk', n * 10 + 4) : '-',
    manifest_id: level >= 4 ? id64('dm', n * 10 + 5) : '-', activation_id: level >= 5 ? id64('da', n * 10 + 6) : '-',
    outcome_id: level >= 6 ? id64('dpk', n * 10 + 7) : '-', selection_approved: false, commit_approved: false,
    completed: stages.slice(0, level + 1), attention: [], next: [], ...options.fields }
}
const observed = (w: World) => stamp(Math.floor(w.clock.now() / 1000) * 1000)
const findRequest = (w: World, rid: string) => w.requests.find(value => value.request_id === rid)!
const descriptor = () => { const n = network(); return { id: n.id, name: n.name, context_id: n.context_id, genesis_root_public_key: n.genesis_root_public_key } }
async function inspection(w: World, rid: string) {
  const r = findRequest(w, rid)
  const review = { version: 1, kind: 'inspect_new_original_admission', host_id: w.host, context: context(w.parent),
    agent: clone(w.parent.review.agent), network: descriptor(), root_state_id: network().root_state_id,
    request_id: r.request_id, request_packet_id: r.request_packet_id, owner_offer_id: r.owner_offer_id, selection_id: r.selection_id,
    member: 'Incoming "é東京" member', person_public_key: r.person_public_key, host_public_key: r.host_public_key,
    device_public_key: r.device_public_key, scopes: 7, not_after: stamp(Date.parse(r.created_at) + 7 * 86_400_000),
    created_at: r.created_at, expires_at: r.expires_at, effects: clone(inspectionEffects) }
  return { version: 1, host_id: w.host, context: context(w.parent), observed_at: observed(w), request: clone(r),
    review_id: await digest('peerspan-admission-inspection-v1', review), review, next_action: 'review_administrator_consent' }
}
async function admissionRecord(w: World, rid: string, options: any = {}) {
  const source = (await inspection(w, rid)).review, created = options.created ?? NOW - 1000
  const review = { version: 1, kind: 'approve_new_original_admission', host_id: w.host, context: context(w.parent),
    agent: clone(w.parent.review.agent), network: clone(source.network), request_id: rid, request_packet_id: source.request_packet_id,
    owner_offer_id: source.owner_offer_id, selection_id: source.selection_id, intent_id: id('dint', options.n ?? 90),
    root_state_id: source.root_state_id, root_public_key: network().root_public_key,
    person_lease_id: id64('ds', 91), host_lease_id: id64('ds', 92), member: source.member,
    person_public_key: source.person_public_key, host_public_key: source.host_public_key, device_public_key: source.device_public_key,
    scopes: 7, not_after: source.not_after, request_created_at: source.created_at, request_expires_at: source.expires_at,
    created_at: stamp(created), expires_at: stamp(Math.min(Date.parse(source.expires_at), created + 900_000)), effects: clone(admissionEffects) }
  const state = options.state ?? 'review'
  return { review_id: await digest('peerspan-onboarding-original-admission-review-v1', review), review, state,
    next_action: state === 'review' ? 'approve_administrator_intent' : state === 'approved' ? 'follow_link_progress' : 'inspect_link_progress' }
}
async function admissionResponse(w: World, rid: string) {
  const value = clone(w.admissions[rid] ?? null)
  if (value?.state === 'review' && Date.parse(value.review.expires_at) <= w.clock.now()) {
    value.state = 'expired'; value.next_action = 'inspect_link_progress'
  }
  return { version: 1, host_id: w.host, context: context(w.parent), observed_at: observed(w), request: clone(findRequest(w, rid)), admission: value }
}
async function progressResponse(w: World, rid: string) {
  const old = findRequest(w, rid), n = Number.parseInt(rid.slice(-8), 16)
  const updated = request(n, w.progressState, { created: Date.parse(old.created_at), expires: Date.parse(old.expires_at),
    fields: { network_id: old.network_id, context_id: old.context_id, person_public_key: old.person_public_key,
      host_public_key: old.host_public_key, device_public_key: old.device_public_key, request_packet_id: old.request_packet_id } })
  w.requests = w.requests.map(r => r.request_id === rid ? updated : r)
  return { version: 1, host_id: w.host, context: context(w.parent), observed_at: observed(w), request: clone(updated),
    next_action: w.progressState === 'pending' ? 'wait_for_original_owner' : w.progressState === 'needs_selection'
      ? 'wait_for_requester_selection' : 'review_administrator_consent' }
}

function fixture(on: On) {
  const clock = mock.clock(on, { now: NOW })
  const w = { clock, started: false, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, child: null as any, sequence: 20, requests: [request()], networks: [network()],
    admissions: {} as Record<string, any>, progressState: 'needs_administrator', calls: [] as any[], trace: [] as any[],
    httpCalls: [] as any[], outside: [] as string[], tools: [] as any[], forbidden: [] as string[], prompts: [] as any[],
    materials: [] as any[], closes: 0, run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined }
  w.run = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: observed(w), host_id: w.host,
      networks: clone(w.networks), agents: [], requests: clone(w.requests), attention: [] }
    if (kind === 'admission.lookup') return admissionResponse(w, payload.request_id)
    if (kind === 'admission.inspect') return inspection(w, payload.request_id)
    if (kind === 'admission.prepare') {
      w.admissions[payload.request_id] ??= await admissionRecord(w, payload.request_id)
      return admissionResponse(w, payload.request_id)
    }
    if (kind === 'admission.approve') {
      w.admissions[payload.request_id] = { ...w.admissions[payload.request_id], state: 'approved', next_action: 'follow_link_progress' }
      return admissionResponse(w, payload.request_id)
    }
    if (kind === 'admission.progress') return progressResponse(w, payload.request_id)
    if (kind === 'project.lookup') return { version: 1, host_id: w.host, context: payload, flow: w.parent,
      agents: w.parent ? [{ ...w.parent.review.agent, created_at: stamp(NOW - 1000) }] : [] }
    if (kind === 'project.inspect') return w.parent
    if (kind === 'adapter.lookup') return { version: 1, host_id: w.host, context: payload, flow: w.child }
    if (kind === 'adapter.prepare') { w.child = await adapterFlow(w.parent, { n: ++w.sequence }); return w.child }
    if (kind === 'adapter.inspect') return w.child
    if (kind === 'adapter.decide') {
      w.child = await adapterFlow(w.parent, { n: w.sequence, state: payload.decision === 'approve' ? 'authorized' : 'declined' }); return w.child
    }
    if (kind === 'adapter.transport') { const value = await transport(w.child); w.materials.push(clone(value)); return value }
    throw Error('Unexpected independent fixture operation: ' + kind)
  }
  on('session.start', ($, e) => { w.started = true; return { cwd: e.cwd } })
  on('session.end', ($, e) => { w.started = false; return { sessionId: e.sessionId } })
  on('classic.CwdChanged', () => ({}))
  on('session.root', () => { w.trace.push({ kind: 'root', value: w.root }); return { value: w.root } })
  on('session.id', () => { w.trace.push({ kind: 'native', value: w.native }); return { value: w.native } })
  on('session.cwd', () => ({ value: '/different-shell-cwd' }))
  on('session.surface', () => ({ value: w.surface }))
  on('session.surfaces', () => ({ value: w.surfaces }))
  on('command.register', () => ({ value: undefined }))
  on('tool.register', ($, e) => { w.tools.push(e); return { value: undefined } })
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unregistered fixture tool' }))
  on('process.run', async ($, e) => {
    const tail = e.argv.slice(e.argv.indexOf('onboarding') + 1)
    const kind = tail.length ? tail[0] + '.' + tail[1] : 'snapshot'
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined, sent = payload === undefined ? undefined : clone(payload)
    w.calls.push({ ...e, kind, payload: sent, expectedContext: w.parent ? clone(context(w.parent)) : undefined,
      expectedParent: w.parent?.flow_id, expectedAdapter: w.child?.flow_id,
      expectedRequest: sent?.request_id, expectedReview: w.admissions[sent?.request_id]?.review_id })
    w.trace.push({ kind, payload: sent })
    const value = await w.run(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    if (value?.fixtureExit) return { value: { exitCode: 124, stdout: '', stderr: RAW } }
    if (value?.fixtureRaw) return { value: { exitCode: 0, stdout: value.fixtureRaw, stderr: RAW } }
    return { value: { exitCode: 0, stdout: JSON.stringify(value), stderr: '' } }
  })
  on('http.fetch', ($, e) => {
    w.httpCalls.push(clone(e))
    const path = e.url.replace('http://peerspan', '')
    let value: any = null
    if (path === '/adapter/v1/connect' || path === '/adapter/v1/ready') {
      value = connection(w.child, clock.now(), { ready: true, verified: path.endsWith('/ready') || w.child.connection?.channel === 'verified' })
      w.child = { ...w.child, connection: value }
    } else expect(['/adapter/v1/next', '/adapter/v1/tasks/next', '/adapter/v1/tasks/cancels/next']).toContain(path)
    return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify(value) } }
  })
  on('ui.open', () => ({ value: { isPlaced: w.surface === 'terminal' } }))
  on('ui.close', () => { w.closes++; return { value: undefined } })
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  on('ui.toast', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.log', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.status', ($, e) => { w.outside.push(String(e.text ?? '')); return { value: undefined } })
  on('ui.notice', ($, e) => { w.outside.push(JSON.stringify(e)); return { value: undefined } })
  on('prompt.submit', ($, e) => { w.prompts.push(clone(e)); return { text: e.text, origin: e.origin } })
  on('store.set', () => { w.forbidden.push('store.set'); return { deny: 'no persistence' } })
  on('fs.read', () => { w.forbidden.push('fs.read'); return { deny: 'no file reads' } })
  on('fs.write', () => { w.forbidden.push('fs.write'); return { deny: 'no files' } })
  on('process.spawn', async function* () { w.forbidden.push('process.spawn'); throw Error('no spawn') })
  on('model.complete', () => { w.forbidden.push('model.complete'); return { deny: 'no inference' } })
  on('session.send', () => { w.forbidden.push('session.send'); return { isDelivered: false } })
  return w
}
type World = ReturnType<typeof fixture>
type Pane = Mounted<'terminal', 'Pane'>
const calls = (w: World, operation?: string) => w.calls.filter(c => c.kind === (operation ? 'admission.' + operation : c.kind) && c.kind.startsWith('admission.'))
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
async function setup($: Engine, w: World, options: any = {}) {
  w.parent = options.parent ?? await parentFlow({ agent: { id: id('agent', 1), name: 'Agent "東京"', owner: 'Owner \\é', capabilities: ['capability "metadata"'] } })
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w)
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  return ui
}
async function begin(w: World, ui: Pane) { await press(ui, 'Review incoming connections'); await w.clock.settle() }
async function choices(w: World, ui: Pane) {
  return (await ui.findAll({ type: 'Button' })).filter(button => w.requests.some(r => button.text.includes(r.network_id) && button.text.includes(r.host_public_key)))
}
async function choose(w: World, ui: Pane, n = 0) {
  const found = (await choices(w, ui))[n]; expect(found, 'explicit full-identity incoming choice').toBeDefined()
  await ui.press({ key: found!.key! }); await w.clock.settle()
}
async function selected($: Engine, w: World, options: any = {}) {
  if (options.requests) w.requests = options.requests
  const ui = await setup($, w)
  if (options.state) w.admissions[w.requests[0].request_id] = await admissionRecord(w, w.requests[0].request_id, options)
  await begin(w, ui); await choose(w, ui); return ui
}
async function review(ui: Pane) { await press(ui, 'Review administrator consent') }
async function leave(ui: Pane) { const found = await ui.find({ type: 'Button', text: /^Leave incoming review$/ }); if (found) await ui.press({ key: found.key! }) }
async function back(ui: Pane) { const found = await ui.find({ type: 'Button', text: /^Back\b/ }); expect(found).toBeDefined(); await ui.press({ key: found!.key! }) }
async function noApprove(ui: Pane, label = '') { expect(await ui.find({ type: 'Button', text: /^Approve administrator consent$/ }), label).toBeUndefined() }
async function noRecord(ui: Pane, label = '') { expect(await text(ui), label).not.toContain('Administrator consent: recorded') }
function delaySignal(w: World, ms: number) {
  let signal!: () => void
  const started = new Promise<void>(resolve => { signal = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(ms); signal(); return pending } }
}
function safe(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  const internal = [TOKEN, SOCKET, NATIVE, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path', CODE, CODE2,
    w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id, ...w.requests.map(r => r.request_id),
    ...Object.values(w.admissions).flatMap(v => v ? [v.review_id, v.review.intent_id] : [])].filter(Boolean)
  for (const value of internal) {
    expect(shown).not.toContain(value); expect(w.outside.join('\n')).not.toContain(value)
  }
  expect(shown).not.toMatch(/\b(?:flow_[0-9a-f]{32}|review_[0-9a-f]{64}|session_[0-9a-f]{32}|dint_[0-9a-f]{32}|link_[0-9a-f]{64}|dpk_[0-9a-f]{64})\b/)
  expect(w.outside.join('\n')).not.toContain(ROOT)
  const prefix = [executable, ...(state ? ['--state', state] : []), 'onboarding']
  for (const command of w.calls) {
    expect(command.init?.timeoutMs).toBe(5000)
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, CODE, CODE2]) expect(command.argv).not.toContain(value)
    const inspection = command.kind === 'project.inspect' ? command.expectedParent : command.kind === 'adapter.inspect' ? command.expectedAdapter : undefined
    if (inspection) expect(command.argv).toEqual([...prefix, command.kind.split('.')[0], 'inspect', inspection])
    else if (command.kind === 'snapshot') expect(command.argv).toEqual(prefix)
    else expect(command.argv).toEqual([...prefix, ...command.kind.split('.'), '--stdin'])
    expect(['snapshot', 'project.lookup', 'project.inspect', 'adapter.lookup', 'adapter.prepare', 'adapter.inspect', 'adapter.decide', 'adapter.transport',
      'admission.lookup', 'admission.inspect', 'admission.prepare', 'admission.approve', 'admission.progress']).toContain(command.kind)
  }
  for (const command of calls(w)) {
    expect(command.payload).toEqual({ context: command.expectedContext, request_id: command.expectedRequest,
      ...(command.kind === 'admission.approve' ? { admission_review_id: command.expectedReview } : {}) })
    expect(typeof command.init.stdin).toBe('string'); expect(JSON.parse(command.init.stdin)).toEqual(command.payload)
    for (const value of [command.expectedRequest, command.expectedReview].filter(Boolean)) expect(command.argv).not.toContain(value)
  }
  if (!runtime) {
    expect(w.httpCalls).toEqual([]); expect(w.prompts).toEqual([])
    expect(w.tools.length > 0).toBe(true)
    expect(w.tools.every(tool => tool.name === 'delivery_acknowledge')).toBe(true)
  }
}

async function dispose(ui: Pane) {
  const close = await ui.find({ type: 'Button', text: /^Close$/ })
  if (close) await ui.press({ key: close.key! })
  await ui.unmount()
}
async function reopen($: Engine, w: World) {
  const ui = await setup($, w); await begin(w, ui); await choose(w, ui); return ui
}
async function absent(ui: Pane, names: string[], label = '') {
  for (const name of names) expect(await ui.find({ type: 'Button', text: new RegExp('^' + name + '$') }), label + ': ' + name).toBeUndefined()
}
const actions = ['Fetch incoming proofs', 'Review administrator consent', 'Approve administrator consent']

test('admission entry remains inert on initial headless Refresh and model paths', async ($, on) => {
  const w = fixture(on)
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: false })
  await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 100 } })
  expect(calls(w)).toHaveLength(0)
  await $.session.end({ sessionId: NATIVE })
  const ui = await setup($, w)
  expect(await ui.find({ type: 'Button', text: /^Review incoming connections$/ })).toBeDefined()
  await press(ui, 'Refresh'); await w.clock.settle()
  await $.tool.call({ tool: 'mcp__peerspan__delivery_acknowledge', probe_id: '0'.repeat(32) })
  await w.clock.advance(1000)
  expect(calls(w)).toHaveLength(0); expect(w.requests).toHaveLength(1)
  safe(w, await text(ui))
})

test('only attached entry accepts a bounded unique inventory and sorts valid unsorted request IDs', async ($, on) => {
  const w = fixture(on)
  let ui = await setup($, w, { parent: await parentFlow({ state: 'review' }) })
  expect(await ui.find({ type: 'Button', text: /^Review incoming connections$/ })).toBeUndefined()
  await dispose(ui)
  w.requests = [request(3, 'pending'), request(1, 'pending'), request(2, 'pending')]
  ui = await setup($, w); await begin(w, ui)
  expect(await choices(w, ui)).toHaveLength(3); expect(calls(w)).toHaveLength(0)
  await choose(w, ui)
  expect(calls(w, 'lookup')[0].payload.request_id).toBe(id64('link', 1)); await dispose(ui)
  for (const variant of ['duplicate', 'overflow']) {
    w.requests = variant === 'duplicate' ? [request(), request()] : Array.from({ length: 4097 }, (_, index) => request(index + 1, 'pending'))
    ui = await setup($, w); const before = calls(w).length; await begin(w, ui)
    expect(await choices(w, ui), variant).toHaveLength(0); expect(calls(w).length, variant).toBe(before)
    await noApprove(ui, variant); await dispose(ui)
  }
  safe(w)
})

test('empty requester renewal migration and incomplete claims never become incoming choices', async ($, on) => {
  const w = fixture(on)
  for (const rows of [[], [request(1, 'pending', { fields: { role: 'requester' } }),
    request(2, 'pending', { fields: { mode: 'renew' } }),
    request(3, 'pending', { fields: { migration_proposal_id: id64('dmp', 3) } }),
    request(4, 'pending', { fields: { network_id: '-', context_id: '-', person_public_key: '-' } })]]) {
    w.requests = rows; const ui = await setup($, w); await begin(w, ui)
    expect(await choices(w, ui)).toHaveLength(0); expect(calls(w)).toHaveLength(0)
    await absent(ui, actions); await dispose(ui)
  }
  safe(w)
})

test('duplicate public identities remain twelve explicit ordinal choices over ten-item pages', async ($, on) => {
  const w = fixture(on); w.requests = Array.from({ length: 12 }, (_, index) => request(12 - index, 'pending'))
  const ui = await setup($, w); await begin(w, ui)
  const first = await choices(w, ui); expect(first).toHaveLength(10); expect(calls(w)).toHaveLength(0)
  for (const choice of first) for (const value of [network().id, KEY, GENESIS_KEY, stamp(NOW - 60_000)]) expect(choice.text).toContain(value)
  expect(new Set(first.map(choice => choice.text)).size).toBe(10)
  await press(ui, /^(?:More|Next)\b.*(?:incoming|connections|requests)/i)
  expect(await choices(w, ui)).toHaveLength(2); expect(calls(w)).toHaveLength(0)
  await press(ui, /^Previous\b.*(?:incoming|connections|requests)/i)
  await choose(w, ui, 1)
  expect(calls(w, 'lookup')).toHaveLength(1); expect(calls(w, 'lookup')[0].payload.request_id).toBe(id64('link', 2))
  expect(await ui.find({ type: 'Input' })).toBeUndefined(); safe(w, await text(ui))
})

test('selection looks up first and terminal null or retained histories never fetch or prepare', async ($, on) => {
  const w = fixture(on)
  for (const state of ['review', 'approved', 'expired', 'cancelled', 'invalidated', 'null']) {
    w.requests = [request(1, state === 'null' ? 'cancelled' : 'needs_administrator')]
    w.admissions = {}
    // Build retained terms only after setup chooses the current exact parent.
    const ui = await setup($, w)
    if (state !== 'null') w.admissions[w.requests[0].request_id] = await admissionRecord(w, w.requests[0].request_id, { state })
    const before = calls(w).length; await begin(w, ui); await choose(w, ui)
    expect(calls(w).slice(before).map(call => call.kind), state).toEqual(['admission.lookup'])
    if (state !== 'review') await noApprove(ui, state)
    if (state === 'approved') expect(await text(ui)).toContain('Administrator consent: recorded')
    if (state === 'null') await absent(ui, ['Fetch incoming proofs', 'Review administrator consent'])
    const at = calls(w).length; await press(ui, 'Check administrator consent')
    expect(calls(w).slice(at).map(call => call.kind)).toEqual(['admission.lookup'])
    await dispose(ui)
  }
  safe(w)
})

test('one explicit Fetch maps owner waiting selection waiting and verified selected prefix without polling', async ($, on) => {
  const w = fixture(on)
  for (const state of ['pending', 'needs_selection', 'needs_administrator']) {
    w.requests = [request(1, 'pending')]; w.admissions = {}; w.progressState = state
    const ui = await selected($, w), before = calls(w).length
    await press(ui, 'Fetch incoming proofs')
    expect(calls(w).slice(before).map(call => call.kind)).toEqual(['admission.lookup', 'admission.progress'])
    const shown = await text(ui)
    if (state === 'pending') expect(shown).toMatch(/(?:wait|missing|not yet)[\s\S]*(?:original|owner)|(?:original|owner)[\s\S]*(?:wait|missing|not yet)/i)
    if (state === 'needs_selection') expect(shown).toMatch(/(?:wait|missing|not yet)[\s\S]*selection|selection[\s\S]*(?:wait|missing|not yet)/i)
    if (state === 'needs_administrator') expect(await ui.find({ type: 'Button', text: /^Review administrator consent$/ })).toBeDefined()
    await noApprove(ui); const count = calls(w).length; await w.clock.advance(3000)
    expect(calls(w).length).toBe(count); expect(calls(w, 'prepare')).toHaveLength(0)
    safe(w, shown); await dispose(ui)
  }
})

test('fresh lookup discovers a competing retained intent before Fetch and suppresses carrier action', async ($, on) => {
  const w = fixture(on); w.requests = [request(1, 'pending')]
  const ui = await selected($, w)
  w.requests = [request()]; w.admissions[w.requests[0].request_id] = await admissionRecord(w, w.requests[0].request_id)
  await press(ui, 'Fetch incoming proofs')
  expect(calls(w, 'lookup')).toHaveLength(2); expect(calls(w, 'progress')).toHaveLength(0)
  expect(calls(w, 'inspect')).toHaveLength(0); expect(calls(w, 'prepare')).toHaveLength(0)
  expect(await ui.find({ type: 'Button', text: /^Approve administrator consent$/ })).toBeDefined()
  safe(w, await text(ui))
})

test('successful Fetch never prepares and Check Refresh or reentry cannot turn it into consent', async ($, on) => {
  const w = fixture(on); w.requests = [request(1, 'pending')]
  let ui = await selected($, w); await press(ui, 'Fetch incoming proofs')
  await w.clock.advance(5000); await press(ui, 'Check administrator consent')
  expect(calls(w, 'prepare')).toHaveLength(0); expect(calls(w, 'approve')).toHaveLength(0)
  await press(ui, 'Refresh'); await dispose(ui)
  ui = await setup($, w); expect(calls(w, 'prepare')).toHaveLength(0)
  await begin(w, ui); await choose(w, ui); await noApprove(ui)
  expect(calls(w, 'inspect')).toHaveLength(0); expect(calls(w, 'progress')).toHaveLength(1)
  safe(w, await text(ui))
})

test('explicit Review repeats lookup then authentic inspection before one exactly matching prepare', async ($, on) => {
  const w = fixture(on), ui = await selected($, w), before = calls(w).length
  await review(ui)
  expect(calls(w).slice(before).map(call => call.kind)).toEqual(['admission.lookup', 'admission.inspect', 'admission.prepare'])
  expect(calls(w, 'approve')).toHaveLength(0)
  expect(await ui.find({ type: 'Button', text: /^Approve administrator consent$/ })).toBeDefined()
  await dispose(ui)
  const normal = w.run
  for (const field of ['member', 'root_state_id', 'not_after']) {
    w.admissions = {}; w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'admission.prepare') {
        const r = value.admission.review
        r[field] = field === 'member' ? 'Different member' : field === 'root_state_id' ? id64('ds', 88) : stamp(Date.parse(r.not_after) - 1000)
        value.admission.review_id = await digest('peerspan-onboarding-original-admission-review-v1', r)
      }
      return value
    }
    const next = await reopen($, w); await review(next); await noApprove(next, field); await noRecord(next, field); await dispose(next)
  }
  safe(w)
})

test('an existing review appearing at explicit Review is reused without inspect or replacement preparation', async ($, on) => {
  const w = fixture(on), ui = await selected($, w)
  w.admissions[w.requests[0].request_id] = await admissionRecord(w, w.requests[0].request_id)
  await review(ui)
  expect(calls(w).map(call => call.kind)).toEqual(['admission.lookup', 'admission.lookup'])
  expect(await ui.find({ type: 'Button', text: /^Approve administrator consent$/ })).toBeDefined()
  await press(ui, 'Check administrator consent')
  expect(calls(w, 'inspect')).toHaveLength(0); expect(calls(w, 'prepare')).toHaveLength(0)
  safe(w, await text(ui))
})

test('exact administrator terms render reversibly with every finite power effect and public dependency', async ($, on) => {
  const w = fixture(on), ui = await selected($, w, { state: 'review' }), retained = w.admissions[w.requests[0].request_id]
  const r = retained.review, shown = await text(ui)
  for (const value of [ROOT, w.parent.review.agent.name, w.parent.review.agent.owner, ...w.parent.review.agent.capabilities,
    r.network.name, r.member]) expect(shown, value).toContain(quote(value))
  for (const value of [r.network.id, r.network.context_id, r.network.genesis_root_public_key, r.root_state_id, r.root_public_key,
    r.person_lease_id, r.host_lease_id, r.person_public_key, r.host_public_key, r.device_public_key, r.not_after,
    r.request_created_at, r.request_expires_at, r.created_at, r.expires_at]) expect(shown, value).toContain(value)
  // Plain-language meanings are stable; punctuation, labels and raw enum spellings are not a UI contract.
  for (const meaning of [/current.*conversation/i, /policy/i, /host.*bind|bind.*host/i, /own.*device|device.*own/i,
    /root.*sign|sign.*root/i, /host.*sign|sign.*host/i, /publish|publication/i, /administrator.*(?:intent|consent)/i,
    /membership/i, /agent.*access/i, /finalization/i, /commit/i, /files/i, /conversation/i, /capability/i]) expect(shown).toMatch(meaning)
  expect(r.scopes).toBe(7); expect(findRequest(w, r.request_id).selection_approved).toBe(false)
  await noRecord(ui); expect(calls(w, 'approve')).toHaveLength(0); safe(w, shown)
})

const configuredAdmission: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private admission state/$(literal)' },
}
test('double explicit approval performs fresh exact lookup and one configured five-second private stdin call', configuredAdmission, async ($, on) => {
  const w = fixture(on), ui = await selected($, w, { state: 'review' }), retained = clone(w.admissions[w.requests[0].request_id])
  const normal = w.run, delayed = delaySignal(w, 1000), at = w.trace.length
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'admission.lookup') await delayed.wait(); return value }
  const button = await key(ui, 'Approve administrator consent'), pending = ui.press({ key: button }); void pending.catch(() => undefined)
  await delayed.started; const second = ui.press({ key: button }).catch(() => undefined)
  expect(calls(w, 'approve')).toHaveLength(0); await noRecord(ui)
  await w.clock.advance(1000); await Promise.all([pending, second])
  expect(calls(w, 'approve')).toHaveLength(1)
  expect(calls(w, 'approve')[0].payload).toEqual({ context: context(w.parent), request_id: w.requests[0].request_id, admission_review_id: retained.review_id })
  expect(await text(ui)).toContain('Administrator consent: recorded'); await noApprove(ui)
  const trace = w.trace.slice(at), sent = trace.findIndex(event => event.kind === 'admission.approve')
  for (const kind of ['project.inspect', 'snapshot', 'admission.lookup', 'root', 'native']) expect(trace.slice(0, sent).some(event => event.kind === kind), kind).toBe(true)
  expect(calls(w).filter(call => call.kind !== 'admission.lookup').map(call => call.kind)).toEqual(['admission.approve'])
  safe(w, await text(ui), false, configuredAdmission.options.executable, configuredAdmission.options.state)
})

test('changed review root tuple parent native conversation host and terminal cannot authorize approval', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['review', 'root-key', 'tuple', 'parent', 'root', 'native', 'host', 'terminal', 'post-lookup-parent', 'post-lookup-host']) {
    w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
    w.requests = [request()]; w.admissions = {}
    const ui = await selected($, w, { state: 'review' }), button = await key(ui, 'Approve administrator consent'), before = calls(w, 'approve').length
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'admission.lookup') {
        if (mode === 'review') { value.admission.review.member = 'Changed reviewed member'; value.admission.review_id = await digest('peerspan-onboarding-original-admission-review-v1', value.admission.review) }
        if (mode === 'root-key') { value.admission.review.root_public_key = RELAY_KEY; value.admission.review_id = await digest('peerspan-onboarding-original-admission-review-v1', value.admission.review) }
        if (mode === 'tuple') value.request.device_public_key = HELPER_KEY
        if (mode === 'post-lookup-parent') { w.parent.state = 'invalidated'; w.parent.attachment = null }
        if (mode === 'post-lookup-host') w.host = 'host_' + '9'.repeat(64)
      }
      return value
    }
    if (mode === 'parent') { w.parent.state = 'invalidated'; w.parent.attachment = null }
    if (mode === 'root') w.root = '/changed-private-admission-root'
    if (mode === 'native') w.native = 'changed-private-admission-conversation'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'terminal') { w.surface = null; w.surfaces = [] }
    await ui.press({ key: button }).catch(() => undefined); await w.clock.settle()
    expect(calls(w, 'approve').length, mode).toBe(before); await noRecord(ui, mode); await dispose(ui)
  }
  safe(w)
})

test('review and null request deadlines plus raw creation and future observation bounds remove write authority', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['review-deadline', 'null-deadline', 'fetched-deadline', 'before-creation', 'future-observation']) {
    w.admissions = {}; w.run = normal
    const now = w.clock.now(), near = ['review-deadline', 'null-deadline', 'fetched-deadline'].includes(mode)
    w.requests = [request(1, mode === 'null-deadline' || mode === 'fetched-deadline' ? 'pending' : 'needs_administrator',
      { created: near ? now - 3_599_000 : now - 60_000, expires: near ? now + 1000 : now + 3_540_000 })]
    const ui = await selected($, w)
    if (mode === 'fetched-deadline') await press(ui, 'Fetch incoming proofs')
    if (mode === 'review-deadline') { await review(ui); expect(await ui.find({ type: 'Button', text: /^Approve administrator consent$/ })).toBeDefined() }
    if (near) {
      await w.clock.advance(1000); await absent(ui, actions, mode)
      expect(await ui.find({ type: 'Button', text: /^Check administrator consent$/ }), mode).toBeDefined()
    } else {
      // A valid displayed review is followed by a changed observation only at the explicit approval recheck.
      await review(ui)
      w.run = async (kind, payload, e) => {
        const value = await normal(kind, payload, e)
        if (kind === 'admission.lookup') value.observed_at = mode === 'before-creation'
          ? stamp(Date.parse(value.admission.review.created_at) - 1000) : stamp(Math.floor(w.clock.now() / 1000) * 1000 + 31_000)
        return value
      }
      await press(ui, 'Approve administrator consent'); await noRecord(ui, mode)
    }
    expect(calls(w, 'approve'), mode).toHaveLength(0); await dispose(ui)
  }
  safe(w)
})

test('approved global history stays readable after request and review expiry without fresh write or attribution', async ($, on) => {
  const w = fixture(on)
  w.requests = [request(1, 'linked', { created: NOW - 7_200_000, expires: NOW - 3_600_000 })]
  const ui = await selected($, w, { state: 'approved', created: NOW - 7_199_000 })
  expect(await text(ui)).toContain('Administrator consent: recorded'); await noApprove(ui)
  await absent(ui, ['Fetch incoming proofs', 'Review administrator consent'])
  await press(ui, 'Check administrator consent'); expect(await text(ui)).toContain('Administrator consent: recorded')
  expect(calls(w).map(call => call.kind)).toEqual(['admission.lookup', 'admission.lookup'])
  expect(await text(ui)).not.toMatch(/(?:this interface|this project|Peerspan pane)\s+(?:approved|signed)/i)
  safe(w, await text(ui))
})

test('malformed extra private and decorated response terms never expose secrets or approval controls', async ($, on) => {
  const w = fixture(on), normal = w.run
  const prefixes = ['psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.', 'peerspan-person-invite-v1.', 'token_', 'instance_']
  const variants = ['outer-extra', 'review-extra', 'request-extra', 'digest', 'effect', 'lifetime', 'stages', 'state-action',
    ...prefixes.map((_, i) => 'private-' + i), ...prefixes.map((_, i) => 'decorated-' + i)]
  for (const mode of variants) {
    w.admissions = {}; w.requests = [request()]; w.run = normal
    const ui = await setup($, w); w.admissions[w.requests[0].request_id] = await admissionRecord(w, w.requests[0].request_id)
    const secret = 'SHORTSECRET' + variants.indexOf(mode)
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind !== 'admission.lookup') return value
      if (mode === 'outer-extra') value.extra = true
      if (mode === 'review-extra') value.admission.review.provider = 'root'
      if (mode === 'request-extra') value.request.extra = true
      if (mode === 'effect') value.admission.review.effects.grant_membership = true
      if (mode === 'lifetime') value.admission.review.not_after = stamp(Date.parse(value.request.created_at) + 8 * 86_400_000)
      if (mode === 'stages') value.request.completed = ['owner_selected', 'request_created']
      if (mode === 'state-action') value.admission.next_action = 'follow_link_progress'
      if (mode.startsWith('private-') || mode.startsWith('decorated-')) {
        const prefix = prefixes[Number(mode.split('-')[1])], decorated = mode.startsWith('decorated-')
        const text = decorated ? '\x1b]0;' + prefix.slice(0, 2) + '\u202e\x1b[31m' + prefix.slice(2) + secret + '\x07visible' : prefix + secret
        if (variants.indexOf(mode) % 3 === 0) value.admission.review.member = text
        else if (variants.indexOf(mode) % 3 === 1) value.admission.review.agent.owner = text
        else value.admission.review.agent.capabilities = [text]
      }
      value.admission.review_id = mode === 'digest' ? id64('review', 99) : await digest('peerspan-onboarding-original-admission-review-v1', value.admission.review)
      return value
    }
    await begin(w, ui); await choose(w, ui); await noApprove(ui, mode); await noRecord(ui, mode)
    const shown = await text(ui); expect(shown, mode).not.toContain(secret); expect(w.outside.join('\n'), mode).not.toContain(secret)
    for (const prefix of prefixes) expect(shown, mode).not.toContain(prefix)
    expect(calls(w, 'approve')).toHaveLength(0); await dispose(ui)
  }
  safe(w)
})

test('failed reads and lost prepare or approval results require explicit lookup-only recovery', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['lookup-denied', 'lookup-raw', 'prepare-lost', 'approve-lost', 'approve-mismatch', 'progress-lost']) {
    w.admissions = {}; w.requests = [request(1, mode === 'progress-lost' ? 'pending' : 'needs_administrator')]; w.run = normal
    const ui = await setup($, w)
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (mode === 'lookup-denied' && kind === 'admission.lookup') return { fixtureDeny: true }
      if (mode === 'lookup-raw' && kind === 'admission.lookup') return { fixtureRaw: RAW }
      if (mode === 'prepare-lost' && kind === 'admission.prepare') return { fixtureExit: true }
      if (mode === 'approve-lost' && kind === 'admission.approve') return { fixtureExit: true }
      if (mode === 'approve-mismatch' && kind === 'admission.approve') value.admission.review_id = id64('review', 99)
      if (mode === 'progress-lost' && kind === 'admission.progress') return { fixtureExit: true }
      return value
    }
    await begin(w, ui); await choose(w, ui)
    if (mode.startsWith('prepare') || mode.startsWith('approve')) await review(ui)
    if (mode.startsWith('approve')) await press(ui, 'Approve administrator consent')
    if (mode.startsWith('progress')) await press(ui, 'Fetch incoming proofs')
    await noApprove(ui, mode); await noRecord(ui, mode)
    const at = calls(w).length; await w.clock.advance(1000); expect(calls(w).length, mode).toBe(at)
    w.run = normal; await press(ui, 'Check administrator consent')
    expect(calls(w).slice(at).map(call => call.kind), mode).toEqual(['admission.lookup'])
    if (mode.startsWith('approve')) expect(await text(ui)).toContain('Administrator consent: recorded')
    if (mode.startsWith('lookup') || mode.startsWith('progress')) expect(w.admissions[w.requests[0].request_id] ?? null).toBe(null)
    safe(w, await text(ui)); await dispose(ui)
  }
})

test('dispatched reads writes and fetches lose local authority on navigation context host or terminal loss', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const [operation, mode] of [['lookup', 'Leave'], ['prepare', 'Back'], ['approve', 'Close'], ['progress', 'Refresh'],
    ['prepare', 'root'], ['prepare', 'native'], ['prepare', 'terminal'], ['prepare', 'parent'], ['prepare', 'host'], ['prepare', 'end']]) {
    w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.run = normal
    w.requests = [request(1, operation === 'progress' ? 'pending' : 'needs_administrator')]; w.admissions = {}
    const ui = await selected($, w, operation === 'approve' ? { state: 'review' } : {})
    const approvals = calls(w, 'approve').length
    const delayed = delaySignal(w, 1000)
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'admission.' + operation) await delayed.wait(); return value }
    const pending = press(ui, operation === 'approve' ? 'Approve administrator consent' : operation === 'progress' ? 'Fetch incoming proofs' : 'Review administrator consent')
    void pending.catch(() => undefined); await delayed.started
    if (mode === 'Leave') await press(ui, 'Leave incoming review')
    if (mode === 'Back') await back(ui)
    if (mode === 'Close') await press(ui, 'Close')
    if (mode === 'Refresh') await press(ui, 'Refresh')
    if (mode === 'root') { w.root = '/changed-during-private-admission'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'changed-during-admission'
    if (mode === 'terminal') { w.surface = null; w.surfaces = [] }
    if (mode === 'parent') { w.parent.state = 'invalidated'; w.parent.attachment = null }
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'end') await $.session.end({ sessionId: NATIVE })
    await w.clock.advance(1000); await pending.catch(() => undefined)
    await noApprove(ui, mode); await noRecord(ui, mode)
    if (operation === 'approve') expect(w.admissions[w.requests[0].request_id].state).toBe('approved')
    else expect(calls(w, 'approve').length, mode).toBe(approvals)
    await dispose(ui)
  }
  safe(w)
})

test('old timers and delayed results cannot replace newer explicit selection and reentry restores no authority', async ($, on) => {
  const w = fixture(on), normal = w.run
  w.requests = [request(1, 'pending', { created: NOW - 3_599_000, expires: NOW + 1000 }), request(2)]
  const ui = await setup($, w); await begin(w, ui); await choose(w, ui)
  const delayed = delaySignal(w, 1000)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'admission.progress') await delayed.wait(); return value }
  const pending = press(ui, 'Fetch incoming proofs'); void pending.catch(() => undefined); await delayed.started
  await leave(ui); await begin(w, ui); await choose(w, ui, 1); await review(ui)
  const second = clone(w.admissions[id64('link', 2)])
  await w.clock.advance(1000); await pending
  expect(await ui.find({ type: 'Button', text: /^Approve administrator consent$/ })).toBeDefined()
  expect(w.admissions[id64('link', 2)]).toEqual(second); expect(calls(w, 'approve')).toHaveLength(0)
  await press(ui, 'Close'); await ui.unmount(); w.run = normal
  const fresh = await setup($, w), before = calls(w).length
  await noApprove(fresh); await noRecord(fresh); expect(calls(w).length).toBe(before)
  // No persisted frontend journal exists. Actual module reload and retained old drawing callbacks remain source/manual limits.
  await begin(w, fresh); expect(calls(w).length).toBe(before); await choose(w, fresh, 1)
  expect(calls(w).slice(before).map(call => call.kind)).toEqual(['admission.lookup'])
  expect(w.admissions[id64('link', 2)]).toEqual(second); safe(w, await text(fresh))
})

test('administrator navigation preserves established adapter messages and tasks without new prompts tools or secrets', async ($, on) => {
  const w = fixture(on), ui = await setup($, w)
  w.child = await adapterFlow(w.parent, { n: w.sequence, state: 'authorized' })
  await press(ui, 'Review adapter connection'); await press(ui, 'Connect adapter'); await w.clock.settle()
  await press(ui, 'Enable incoming messages'); await w.clock.settle()
  expect(w.prompts).toHaveLength(1)
  const challenge = w.prompts[0].text.match(/\b[0-9a-f]{32}\b/)!; expect(challenge).not.toBe(null)
  const ready = await $.tool.call({ tool: READY, nonce: challenge[0] }); expect(ready.isError ?? false).toBe(false)
  await w.clock.settle(); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  const tools = w.tools.map(tool => tool.name), prompts = w.prompts.length
  const count = (path: string) => w.httpCalls.filter(call => call.url.endsWith(path)).length
  const readyCount = count('/adapter/v1/ready')
  await press(ui, 'Back to Peerspan'); await press(ui, 'Connect this project')
  await begin(w, ui); await choose(w, ui); await review(ui); await press(ui, 'Approve administrator consent'); await leave(ui)
  await press(ui, 'Back to Peerspan'); await press(ui, 'Close')
  const messages = count('/adapter/v1/next'), tasks = count('/adapter/v1/tasks/next'), leases = count('/adapter/v1/connect')
  await w.clock.advance(5000)
  expect(count('/adapter/v1/next') > messages).toBe(true); expect(count('/adapter/v1/tasks/next') > tasks).toBe(true)
  expect(count('/adapter/v1/connect')).toBe(leases + 1); expect(count('/adapter/v1/ready')).toBe(readyCount)
  expect(w.tools.map(tool => tool.name)).toEqual(tools); expect(w.prompts).toHaveLength(prompts)
  expect(calls(w, 'approve')).toHaveLength(1); expect(w.admissions[w.requests[0].request_id].state).toBe('approved')
  for (const command of w.calls) expect(command.kind).not.toMatch(/resume|sign|identit|join|invitation/)
  for (const call of w.httpCalls) {
    const headers = Object.fromEntries(Object.entries(call.init.headers).map(([key, value]) => [key.toLowerCase(), value]))
    expect(call.init.socketPath).toBe(SOCKET); expect(headers.authorization).toBe('Bearer ' + TOKEN)
    expect(headers['x-peerspan-instance']).toBe(w.materials[0].instance_id)
  }
  safe(w, await text(ui), true)
})
