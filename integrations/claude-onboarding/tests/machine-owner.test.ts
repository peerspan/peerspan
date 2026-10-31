/**
 * Independent GU.impl44 public native conformance, pinned Claude2.1.303.
 * Contract41–44 + independently authored test foundations only. No product
 * imports or real key/agent/process/network/model work. Original393 cases and
 * all old host/helper/native files remain byte-exact, including their timeouts.
 * Mocks prove native dispatch/validation/presentation only; host suites prove
 * signatures, atomic persistence and actual provider resolution. Installed,
 * terminal/reload/two-machine/model acceptance and microscopic final awaits
 * remain source/manual limits. The public kit dispatches current drawings,
 * not retained obsolete closures. Delays signal dispatch+sleep registration.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted, TestOptions } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-10-29T12:00:00Z')
// SHA256 of the decoded canonical local host KEY below (32 zero bytes).
const HOST = 'host_66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925'
const ROOT = '/private project/Native $(literal)'
const NATIVE = 'private-native-adapter-conversation'
const TOKEN = 'token_' + 'b'.repeat(64)
const READY = 'mcp__peerspan__adapter_ready'
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


const OWN_DEVICE = 'BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU='
const id64 = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(64, '0')
const inspectEffects = { verify_request_signature: true, inspect_current_owner_authority: true,
  prepare_owner_intent: false, approve_owner_intent: false, sign_owner_offer: false,
  publish_owner_offer: false, grant_membership: false, grant_machine_powers: false,
  grant_agent_access: false, commit_request: false, share_files: false, share_conversation: false, capability_calls: false }
const consentEffects = (fold: boolean) => ({ approve_owner_intent: true, authorize_owner_offer_signature: true,
  publish_owner_offer_after_signatures: true, authorize_owner_finalization: true,
  authorize_binding_and_device_signatures: true, authorize_host_admission_if_folded: fold,
  grant_membership_now: false, grant_machine_powers_now: false, grant_agent_access: false,
  authorize_requester_selection: false, commit_request: false, share_files: false,
  share_conversation: false, capability_calls: false })
function network(): any {
  return { id: id64('net', 1), name: 'Existing network "é東京"', mode: 'decentralized', context_id: id64('ctx', 1),
    genesis_root_public_key: GENESIS_KEY, root_state_id: id64('ds', 2), root_public_key: GENESIS_KEY, root_epoch: 0,
    member: 'Existing "é" owner', host_public_key: KEY, person_public_key: INVITER_KEY, provider: null,
    provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'usable', not_after: stamp(NOW + 86_400_000), required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: stamp(NOW - 86_400_000) }
}
function request(n = 1, state = 'pending', options: any = {}): any {
  const net = network(), created = options.created ?? NOW - 60_000
  return { request_id: id64('link', n), role: 'approver', mode: 'new', state, network_id: net.id, context_id: net.context_id,
    migration_proposal_id: '-', person_public_key: INVITER_KEY, host_public_key: RELAY_KEY, device_public_key: HELPER_KEY,
    created_at: stamp(created), expires_at: stamp(options.expires ?? created + 3_600_000), request_packet_id: id64('dpk', n * 10),
    owner_offer_id: '-', selection_id: '-', administrator_offer_id: '-', owner_finalization_id: '-',
    manifest_id: '-', activation_id: '-', outcome_id: '-', selection_approved: false, commit_approved: false,
    completed: ['request_created'], attention: [], next: [], ...options.fields }
}
const observed = (w: World) => stamp(Math.floor(w.clock.now() / 1000) * 1000)
const findRequest = (w: World, rid: string) => w.requests.find(value => value.request_id === rid)!
async function inspection(w: World, rid: string) {
  const r = findRequest(w, rid), net = network(), personLease = id64('ds', 11), deviceLease = id64('ds', 14)
  const original = w.providerKind === 'original_person'
  const provider = { kind: w.providerKind, person_public_key: INVITER_KEY, host_public_key: KEY,
    device_public_key: original ? '-' : OWN_DEVICE, lease_id: original ? personLease : deviceLease,
    root_state_id: net.root_state_id, scopes: w.providerScopes, not_after: stamp(w.providerEnd) }
  const review = { version: 1, kind: 'inspect_existing_person_machine', host_id: w.host, context: context(w.parent),
    agent: clone(w.parent.review.agent), network: { id: net.id, name: net.name, context_id: net.context_id,
      genesis_root_public_key: net.genesis_root_public_key }, root_state_id: net.root_state_id,
    request_id: rid, request_packet_id: r.request_packet_id, person_public_key: r.person_public_key,
    host_public_key: r.host_public_key, device_public_key: r.device_public_key, member: 'Existing "é" owner',
    person_lease_id: personLease, local_host: { host_public_key: KEY, member: 'Existing "東京" computer',
      person_public_key: INVITER_KEY, host_lease_id: id64('ds', 12), binding_lease_id: id64('ds', 13),
      device_lease_id: deviceLease, not_after: stamp(w.providerEnd) }, provider,
    provider_id: original ? INVITER_KEY : deviceLease, signature_format: original ? 'sshsig' : 'ed25519', scopes: 7,
    not_after: stamp(Math.min(Date.parse(r.created_at) + 7 * 86_400_000, w.providerEnd)),
    host_admission: w.providerScopes & 8 ? 'owner_may_fold' : 'separate_administrator_required',
    created_at: r.created_at, expires_at: r.expires_at, effects: clone(inspectEffects) }
  return { review_id: await digest('peerspan-machine-owner-inspection-v1', review), review }
}
async function consentRecord(w: World, rid: string, options: any = {}) {
  const source = await inspection(w, rid), r = source.review
  const created = options.created ?? w.receiptCreated ?? Math.floor(w.clock.now() / 1000) * 1000
  const stageDeadline = Date.parse(r.created_at) + 600_000
  const review = { version: 1, kind: 'approve_existing_person_machine', consent_id: id('dint', options.n ?? 90),
    host_id: w.host, context: context(w.parent), agent: clone(w.parent.review.agent), request_id: rid,
    request_packet_id: r.request_packet_id, inspection_review_id: source.review_id, inspection: clone(r),
    intent_id: id('dint', options.n ? options.n + 1 : 91), proposed_owner_offer_id: id64('dpk', 92),
    replaces_consent_id: '-', created_at: stamp(created),
    expires_at: stamp(Math.min(created + 300_000, Date.parse(r.expires_at), stageDeadline, Date.parse(r.not_after))),
    request_stage_deadline: stamp(stageDeadline), effects: consentEffects(r.host_admission === 'owner_may_fold') }
  const state = options.state ?? 'review'
  return { consent_id: review.consent_id, review_id: await digest('peerspan-machine-owner-consent-v1', review), review,
    state, next_action: state === 'review' ? 'approve_machine_owner_intent' : state === 'approved' ? 'follow_machine_link' : 'inspect_machine_link' }
}
async function response(w: World, rid: string, withSigning = false) {
  const c = clone(w.consents[rid] ?? null), r = clone(findRequest(w, rid))
  if (c?.state === 'review' && Date.parse(c.review.expires_at) <= w.clock.now()) {
    c.state = 'expired'; c.next_action = 'inspect_machine_link'
  }
  const count = w.counts[rid] ?? 0, required = c?.review.inspection.host_admission === 'owner_may_fold' ? 3 : 2
  if (c?.state === 'approved' && count === required && r.state === 'pending') {
    r.owner_offer_id = c.review.proposed_owner_offer_id; r.state = 'needs_selection'; r.completed = ['request_created', 'owner_offered']
  }
  const live = r.state === 'pending' && Date.parse(r.expires_at) > w.clock.now()
    && Date.parse(r.created_at) + 600_000 > w.clock.now()
  const current = live && (!c || c.state === 'review') ? await inspection(w, rid) : null
  const value: any = { version: 1, host_id: w.host, context: context(w.parent), observed_at: observed(w),
    request: r, inspection: current, consent: c }
  if (withSigning) {
    const canSign = c?.state === 'approved' && count < required && live
      && context(w.parent).project_flow_id === c.review.context.project_flow_id
      && [c.review.expires_at, c.review.request_stage_deadline, c.review.inspection.not_after].every(t => Date.parse(t) > w.clock.now())
    value.signing = c?.state === 'approved' ? { state: count === required ? 'signed' : count ? 'partial' : 'unsigned',
      intent_id: c.review.intent_id, proposed_owner_offer_id: c.review.proposed_owner_offer_id,
      signature_count: count, required_signatures: required, can_sign: canSign,
      next_action: canSign ? 'sign_machine_owner_offer' : count === required ? 'follow_machine_link' : 'inspect_machine_link',
      owner_offer_publication: 'not_verified', host_admission: 'not_verified', machine_powers: 'not_verified',
      requester_selection: 'not_verified', request_commit: 'not_verified', agent_access: 'not_verified', connection_readiness: 'not_verified' } : null
  }
  return value
}

function fixture(on: On) {
  const clock = mock.clock(on, { now: NOW })
  const w = { clock, started: false, starts: 0, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, child: null as any, sequence: 20, requests: [request()], networks: [network()],
    consents: {} as Record<string, any>, counts: {} as Record<string, number>, providerKind: 'device', providerScopes: 15,
    providerEnd: NOW + 86_400_000, receiptCreated: undefined as number | undefined, calls: [] as any[], trace: [] as any[],
    httpCalls: [] as any[], outside: [] as string[], tools: [] as any[], forbidden: [] as string[], prompts: [] as any[],
    materials: [] as any[], closes: 0, run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined }
  w.run = async (kind, payload) => {
    if (kind === 'snapshot') return { version: 1, observed_at: observed(w), host_id: w.host,
      networks: clone(w.networks), agents: [], requests: clone(w.requests), attention: [] }
    if (kind === 'machine.lookup') return response(w, payload.request_id)
    if (kind === 'machine.prepare') {
      w.consents[payload.request_id] ??= await consentRecord(w, payload.request_id)
      return response(w, payload.request_id)
    }
    if (kind === 'machine.approve') {
      w.consents[payload.request_id] = { ...w.consents[payload.request_id], state: 'approved', next_action: 'follow_machine_link' }
      return response(w, payload.request_id)
    }
    if (kind === 'machine.signing') return response(w, payload.request_id, true)
    if (kind === 'machine.sign') {
      const c = w.consents[payload.request_id]
      w.counts[payload.request_id] = c.review.inspection.host_admission === 'owner_may_fold' ? 3 : 2
      return response(w, payload.request_id, true)
    }
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
  on('session.start', ($, e) => { w.started = true; w.starts++; return { cwd: e.cwd } })
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
      expectedRequest: sent?.request_id, expectedConsent: clone(w.consents[sent?.request_id] ?? null) })
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
const calls = (w: World, op?: string) => w.calls.filter(c => c.kind.startsWith('machine.') && (!op || c.kind === 'machine.' + op))
const writes = (w: World) => calls(w).filter(c => ['machine.prepare', 'machine.approve', 'machine.sign'].includes(c.kind))
async function visible(ui: Pane) { return (await ui.findAll({})).map(e => e.text).join('\n') }
async function key(ui: Pane, label: string | RegExp) {
  const e = await ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
  expect(e, String(label)).toBeDefined(); return e!.key!
}
async function press(ui: Pane, label: string | RegExp) { return ui.press({ key: await key(ui, label) }) }
async function absent(ui: Pane, names = ['Review machine consent', 'Approve machine consent', 'Sign machine owner offer'], why = '') {
  for (const name of names) expect(await ui.find({ type: 'Button', text: new RegExp('^' + name + '$') }), why + ': ' + name).toBeUndefined()
}
async function enter($: Engine, w: World): Promise<Pane> {
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 110 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  return $.ui.mount({ plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 110, rows: 45 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 100,
      placement: 'inline', scroll: { offset: 0, bodyRows: 40 }, view: {} } })
}
async function setup($: Engine, w: World, parent?: any) {
  w.parent = parent ?? await parentFlow({ agent: { id: id('agent', 1), name: 'Agent "東京"', owner: 'Owner "é"', capabilities: [] } })
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w)
  const connect = await ui.find({ type: 'Button', text: /^Connect this project$/ })
  if (connect) await ui.press({ key: connect.key! })
  return ui
}
async function begin(w: World, ui: Pane) { await press(ui, 'Review machine requests'); await w.clock.settle() }
async function choices(w: World, ui: Pane) {
  return (await ui.findAll({ type: 'Button' })).filter(e => w.requests.some(r => e.text.includes(r.network_id) && e.text.includes(r.host_public_key)))
}
async function choose(w: World, ui: Pane, n = 0) {
  const e = (await choices(w, ui))[n]; expect(e, 'explicit machine request choice').toBeDefined()
  await ui.press({ key: e!.key! }); await w.clock.settle()
}
async function selected($: Engine, w: World, state?: string, options: any = {}) {
  const ui = await setup($, w, options.parent)
  if (state) w.consents[w.requests[0].request_id] = await consentRecord(w, w.requests[0].request_id, { ...options, state })
  await begin(w, ui); await choose(w, ui); return ui
}
async function prepared($: Engine, w: World) { const ui = await selected($, w); await press(ui, 'Review machine consent'); return ui }
async function dispose(ui: Pane) {
  const close = await ui.find({ type: 'Button', text: /^Close$/ }); if (close) await ui.press({ key: close.key! })
  await ui.unmount()
}
function delayed(w: World, ms = 1000) {
  let signal!: () => void
  const started = new Promise<void>(resolve => { signal = resolve })
  return { started, wait: () => { const pending = w.clock.sleep(ms); signal(); return pending } }
}
async function publicTerms(ui: Pane, i: any) {
  const shown = await visible(ui)
  for (const value of [i.network.id, i.network.context_id, i.network.genesis_root_public_key, i.root_state_id,
    i.request_id, i.request_packet_id, i.person_public_key, i.host_public_key, i.device_public_key,
    i.person_lease_id, i.local_host.host_lease_id, i.local_host.binding_lease_id, i.local_host.device_lease_id,
    i.provider.person_public_key, i.provider.lease_id, i.provider_id, i.provider.not_after, i.not_after, i.signature_format]) expect(shown).toContain(value)
  for (const label of [i.network.name, i.member, i.local_host.member]) expect(shown).toContain(quote(label))
  if (i.provider.kind === 'device') expect(shown).toContain(i.provider.device_public_key)
  expect(shown).toMatch(/polic/i); expect(shown).toMatch(/bind/i); expect(shown).toMatch(/device/i)
  expect(shown).toMatch(/(?:no|not|exclud)[\s\S]*administrator|administrator[\s\S]*(?:no|not|exclud)/i)
  expect(shown).toMatch(/(?:no|not|without)[\s\S]*(?:key|signer)[\s\S]*(?:availab|probe)|(?:key|signer)[\s\S]*(?:availab|probe)[\s\S]*(?:no|not)/i)
  if (i.host_admission === 'owner_may_fold') expect(shown).toMatch(/fold/i)
  else expect(shown).toMatch(/separate[\s\S]*administrator/i)
}
async function consentTerms(ui: Pane, c: any) {
  await publicTerms(ui, c.review.inspection)
  const shown = await visible(ui)
  for (const value of [c.consent_id, c.review_id, c.review.intent_id, c.review.proposed_owner_offer_id,
    c.review.replaces_consent_id, c.review.created_at, c.review.expires_at, c.review.request_stage_deadline,
    c.review.inspection.expires_at, c.review.inspection.not_after]) expect(shown).toContain(value)
  expect(shown).toMatch(/sign/i); expect(shown).toMatch(/publish|publication/i); expect(shown).toMatch(/finaliz/i)
  expect(shown).toMatch(/requester[\s\S]*selection|selection[\s\S]*requester/i)
  expect(shown).toMatch(/(?:not|no|without)[\s\S]*(?:grant|admission|powers)|(?:grant|admission|powers)[\s\S]*(?:not|no)/i)
}
async function evidence(ui: Pane, count: number, required: number) {
  const shown = await visible(ui)
  expect(shown).toMatch(/consent[\s\S]*(?:recorded|approved)|(?:recorded|approved)[\s\S]*consent/i)
  expect(shown).toMatch(new RegExp('(?:signature[\\s\\S]*' + count + '[\\s\\S]*' + required + '|' + count + '\\s*(?:/|of)\\s*' + required + '[\\s\\S]*signature)', 'i'))
  for (const term of [/publish|publication/i, /host[\s\S]*admission/i, /machine[\s\S]*powers/i,
    /requester[\s\S]*selection/i, /commit/i, /agent[\s\S]*access/i, /readiness/i]) expect(shown).toMatch(term)
  expect(shown).toMatch(/not[ _-]verified/i)
  expect(shown).not.toMatch(/(?:connection|link|machine)[\s:]+ready\b|link[\s:]+complete\b/i)
}
function safe(w: World, shown = '', runtime = false, executable = 'peerspan', state?: string) {
  expect(w.forbidden).toEqual([])
  // Consent/request/intent/offer/digest references are explicitly human terms in44.
  // Project/native/session plumbing, transport credentials and raw errors are not.
  for (const value of [NATIVE, TOKEN, SOCKET, RAW, 'PRIVATE_PROVIDER_ERROR', '/private/provider-path', CODE, CODE2,
    w.parent?.flow_id, w.parent?.review_id, w.parent?.review.session_id].filter(Boolean)) {
    expect(shown).not.toContain(value); expect(w.outside.join('\n')).not.toContain(value)
  }
  expect(w.outside.join('\n')).not.toContain(ROOT)
  if (!runtime) expect(w.prompts).toEqual([])
  const prefix = [executable, ...(state ? ['--state', state] : []), 'onboarding']
  for (const c of w.calls) {
    expect(c.init?.timeoutMs).toBe(c.kind === 'machine.sign' ? 95000 : 5000)
    const inspect = c.kind === 'project.inspect' ? c.expectedParent : c.kind === 'adapter.inspect' ? c.expectedAdapter : undefined
    if (inspect) expect(c.argv).toEqual([...prefix, c.kind.split('.')[0], 'inspect', inspect])
    else expect(c.argv).toEqual(c.kind === 'snapshot' ? prefix : [...prefix, ...c.kind.split('.'), '--stdin'])
    for (const value of [ROOT, NATIVE, TOKEN, SOCKET, CODE, CODE2, c.payload?.request_id, c.payload?.consent_id,
      c.payload?.consent_review_id, c.payload?.inspection_review_id].filter(Boolean)) expect(c.argv).not.toContain(value)
    expect(['snapshot', 'project.lookup', 'project.inspect', 'adapter.lookup', 'adapter.prepare', 'adapter.inspect',
      'adapter.decide', 'adapter.transport', 'machine.lookup', 'machine.prepare', 'machine.approve', 'machine.signing', 'machine.sign']).toContain(c.kind)
  }
  for (const c of calls(w)) {
    const expected: any = { context: c.expectedContext, request_id: c.expectedRequest }
    if (c.kind === 'machine.lookup') { if (c.payload.consent_id !== undefined) expected.consent_id = c.expectedConsent?.consent_id }
    else if (c.kind === 'machine.prepare') expected.inspection_review_id = c.payload.inspection_review_id
    else { expected.consent_id = c.expectedConsent?.consent_id; expected.consent_review_id = c.expectedConsent?.review_id }
    if (c.kind === 'machine.sign') expected.decision = 'sign_machine_owner_offer'
    expect(c.payload).toEqual(expected); expect(JSON.parse(c.init.stdin)).toEqual(expected)
  }
  if (!runtime) { expect(w.httpCalls).toEqual([]); expect(w.tools.map(t => t.name)).toEqual(Array(w.starts).fill('delivery_acknowledge')) }
}

// 1–2. Public selection never guesses the first incoming request/provider.
test('machine-owner entry is attached-only, inert on startup and empty inventory has no mutation authority', async ($, on) => {
  const w = fixture(on)
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: false })
  await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 100 } })
  expect(calls(w)).toHaveLength(0)
  await $.session.end({ sessionId: NATIVE })
  let ui = await setup($, w, await parentFlow({ state: 'review' }))
  expect(await ui.find({ type: 'Button', text: /^Review machine requests$/ })).toBeUndefined(); await dispose(ui)
  w.requests = []; ui = await setup($, w); await begin(w, ui)
  expect(await visible(ui)).toMatch(/no[\s\S]*(?:machine|request)|empty/i)
  expect(await choices(w, ui)).toHaveLength(0); await absent(ui)
  await press(ui, 'Refresh'); await w.clock.advance(1000)
  expect(calls(w)).toHaveLength(0); safe(w, await visible(ui))
})

test('machine inventory sorts twelve choices over ten-item pages and refuses unsupported or duplicate claims', async ($, on) => {
  const w = fixture(on); w.requests = Array.from({ length: 12 }, (_, i) => request(12 - i))
  let ui = await setup($, w); await begin(w, ui)
  expect(await choices(w, ui)).toHaveLength(10); expect(calls(w)).toHaveLength(0); await absent(ui)
  for (const e of await choices(w, ui)) for (const value of [network().id, INVITER_KEY, RELAY_KEY, stamp(NOW - 60_000)]) expect(e.text).toContain(value)
  await press(ui, /^(?:More|Next) machine requests$/); expect(await choices(w, ui)).toHaveLength(2)
  await press(ui, 'Previous machine requests'); await choose(w, ui, 1)
  expect(calls(w).map(c => c.kind)).toEqual(['machine.lookup']); expect(calls(w)[0].payload.request_id).toBe(id64('link', 2))
  await dispose(ui)
  w.requests = [request(1, 'pending', { fields: { role: 'requester' } }), request(2, 'pending', { fields: { mode: 'renew' } }),
    request(3, 'pending', { fields: { person_public_key: '-', context_id: '-' } })]
  ui = await setup($, w); await begin(w, ui); expect(await choices(w, ui)).toHaveLength(0); await dispose(ui)
  w.requests = [request(), request()]; ui = await setup($, w); const before = calls(w).length; await begin(w, ui)
  expect(await choices(w, ui)).toHaveLength(0); expect(calls(w)).toHaveLength(before); expect(writes(w)).toHaveLength(0); safe(w)
})

// 3–4. Person/device and machine labels remain separate public authority facts.
test('selected original-person inspection exposes exact finite public authority without probing an unavailable signer', async ($, on) => {
  const w = fixture(on); w.providerKind = 'original_person'
  const ui = await selected($, w), i = await inspection(w, w.requests[0].request_id)
  await publicTerms(ui, i.review)
  expect(calls(w).map(c => c.kind)).toEqual(['machine.lookup']); expect(writes(w)).toHaveLength(0)
  expect(await ui.find({ type: 'Button', text: /^Review machine consent$/ })).toBeDefined()
  await absent(ui, ['Approve machine consent', 'Sign machine owner offer']); safe(w, await visible(ui))
})

test('device15 fold and device7 separate-administrator inspections retain concrete D/key and the exact cap', async ($, on) => {
  const w = fixture(on)
  for (const scopes of [15, 7]) {
    w.providerScopes = scopes; const ui = await selected($, w)
    const i = await inspection(w, w.requests[0].request_id); await publicTerms(ui, i.review)
    expect(i.review.provider_id).toBe(i.review.local_host.device_lease_id)
    expect(i.review.scopes).toBe(7); expect(i.review.not_after).toBe(stamp(w.providerEnd))
    expect(writes(w)).toHaveLength(0); safe(w, await visible(ui)); await dispose(ui)
  }
})

// 5–6. Preparation and approval are separate exact actions, with fresh reads.
test('Review machine consent prepares only the independently hashed displayed inspection and complete immutable terms', async ($, on) => {
  const w = fixture(on), ui = await selected($, w), source = await inspection(w, w.requests[0].request_id)
  const before = calls(w).length; await press(ui, 'Review machine consent')
  expect(calls(w).slice(before).map(c => c.kind)).toEqual(['machine.lookup', 'machine.prepare'])
  expect(calls(w, 'prepare')[0].payload).toEqual({ context: context(w.parent), request_id: w.requests[0].request_id, inspection_review_id: source.review_id })
  await consentTerms(ui, w.consents[w.requests[0].request_id]); expect(calls(w, 'approve')).toHaveLength(0)
  expect(calls(w, 'sign')).toHaveLength(0); await absent(ui, ['Review machine consent', 'Sign machine owner offer']); safe(w, await visible(ui))
})
const configured: TestOptions & { options: Record<string, string> } = {
  options: { executable: '/fixture bin/peerspan;$(literal)', state: '/private machine state/$(literal)' },
}
test('Approve machine consent is single-flight, fresh-lookup bound and one configured private five-second command', configured, async ($, on) => {
  const w = fixture(on), ui = await prepared($, w), c = clone(w.consents[w.requests[0].request_id])
  await consentTerms(ui, c)
  const normal = w.run, delay = delayed(w), before = calls(w).length
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'machine.lookup') await delay.wait(); return value }
  const button = await key(ui, 'Approve machine consent'), pending = ui.press({ key: button }); void pending.catch(() => undefined)
  await delay.started; await ui.press({ key: button }).catch(() => undefined); expect(calls(w, 'approve')).toHaveLength(0)
  await w.clock.advance(1000); await pending
  expect(calls(w, 'approve')).toHaveLength(1)
  expect(calls(w, 'approve')[0].payload).toEqual({ context: context(w.parent), request_id: w.requests[0].request_id,
    consent_id: c.consent_id, consent_review_id: c.review_id })
  expect(calls(w).slice(before).map(c => c.kind)).toEqual(['machine.lookup', 'machine.approve', 'machine.signing'])
  expect(calls(w, 'sign')).toHaveLength(0); await evidence(ui, 0, 3)
  safe(w, await visible(ui), false, configured.options.executable, configured.options.state)
})

// 7–8. Only the finite initial signature set is actionable; later work is absent.
test('explicit Sign rechecks consent and signing then records only the incomplete two-or-three initial slots', async ($, on) => {
  const w = fixture(on)
  for (const scopes of [7, 15]) {
    w.providerScopes = scopes; w.consents = {}; w.counts = {}; const ui = await selected($, w, 'approved')
    const c = clone(w.consents[w.requests[0].request_id]), required = scopes === 15 ? 3 : 2
    await evidence(ui, 0, required)
    w.counts[w.requests[0].request_id] = required - 1; await press(ui, 'Check machine consent'); await evidence(ui, required - 1, required)
    const before = calls(w).length; await press(ui, 'Sign machine owner offer')
    expect(calls(w).slice(before).map(c => c.kind)).toEqual(['machine.lookup', 'machine.signing', 'machine.sign'])
    expect(calls(w, 'sign').at(-1).payload).toEqual({ context: context(w.parent), request_id: w.requests[0].request_id,
      consent_id: c.consent_id, consent_review_id: c.review_id, decision: 'sign_machine_owner_offer' })
    await evidence(ui, required, required); await absent(ui)
    expect(calls(w, 'sign').at(-1).init.timeoutMs).toBe(95000)
    const after = calls(w).length; await w.clock.advance(2000); expect(calls(w)).toHaveLength(after)
    await press(ui, 'Check machine consent'); await evidence(ui, required, required)
    expect(w.consents[w.requests[0].request_id]).toEqual(c); safe(w, await visible(ui)); await dispose(ui)
  }
  expect(calls(w, 'sign')).toHaveLength(2)
})

test('a now-signed preflight reports global initial evidence without a second signature dispatch or attribution', async ($, on) => {
  const w = fixture(on), ui = await selected($, w, 'approved')
  w.counts[w.requests[0].request_id] = 3
  await press(ui, 'Sign machine owner offer'); await evidence(ui, 3, 3)
  expect(calls(w, 'sign')).toHaveLength(0); await absent(ui)
  expect(await visible(ui)).not.toMatch(/\b(?:this interface|we)\b[\s\S]*(?:signed|published|admitted)/i); safe(w, await visible(ui))
})

// 9–10. Retained consent/signature evidence does not turn history into authority.
test('expired cancelled and invalidated unapproved receipts stay view-only and Check never prepares a replacement', async ($, on) => {
  const w = fixture(on)
  for (const state of ['expired', 'cancelled', 'invalidated']) {
    w.consents = {}; w.requests = [request()]
    if (state === 'expired') w.requests = [request(1, 'pending', { created: NOW - 600_000, expires: NOW + 600_000 })]
    const ui = await selected($, w, state, { created: state === 'expired' ? NOW - 400_000 : NOW - 1000 })
    await absent(ui, undefined, state)
    const c = clone(w.consents[w.requests[0].request_id]), before = calls(w).length
    await press(ui, 'Check machine consent')
    expect(calls(w).slice(before).map(c => c.kind), state).toEqual(['machine.lookup'])
    expect(w.consents[w.requests[0].request_id]).toEqual(c); expect(writes(w)).toHaveLength(0)
    safe(w, await visible(ui)); await dispose(ui)
  }
})

test('signed expired history remains honest and another current project cannot adopt its retained approval', async ($, on) => {
  const w = fixture(on)
  w.requests = [request(1, 'cancelled', { created: NOW - 7_200_000, expires: NOW - 3_600_000 })]
  let ui = await selected($, w, 'approved', { created: NOW - 7_199_000 })
  w.counts[w.requests[0].request_id] = 3; await press(ui, 'Check machine consent')
  await evidence(ui, 3, 3); await absent(ui); expect(writes(w)).toHaveLength(0); await dispose(ui)
  for (const state of ['review', 'approved']) {
    w.requests = [request()]; w.consents = {}; w.counts = {}; ui = await setup($, w)
    w.consents[w.requests[0].request_id] = await consentRecord(w, w.requests[0].request_id, { state })
    const previous = clone(w.consents[w.requests[0].request_id]); await dispose(ui)
    const other = await parentFlow({ n: 2, agent: { id: id('agent', 2), name: 'Different project', owner: 'Other owner', capabilities: [] } })
    ui = await setup($, w, other); const before = calls(w).length; await begin(w, ui); await choose(w, ui)
    await absent(ui, undefined, state); expect(calls(w).slice(before).map(c => c.kind)).toEqual(['machine.lookup'])
    expect(await visible(ui)).toMatch(/histor|another|different|recorded project|unavailable/i)
    expect(w.consents[w.requests[0].request_id]).toEqual(previous)
    expect(writes(w)).toHaveLength(0); safe(w, await visible(ui)); await dispose(ui)
  }
})

// 11–14. Rehashed invalid nested public terms still fail independently of hash checks.
test('closed inspection rejects changed request context or project agent even with an internally recomputed digest', async ($, on) => {
  const w = fixture(on), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['request', v => { v.inspection.review.host_public_key = GENESIS_KEY }],
    ['context', v => { v.inspection.review.context.project_flow_id = id('flow', 99) }],
    ['agent', v => { v.inspection.review.agent.name = 'Changed reviewed agent' }],
  ]
  for (const [label, mutate] of variants) {
    const ui = await setup($, w)
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'machine.lookup') { mutate(value); value.inspection.review_id = await digest('peerspan-machine-owner-inspection-v1', value.inspection.review) }
      return value
    }
    await begin(w, ui); await choose(w, ui); await absent(ui, undefined, label)
    expect(await visible(ui)).toMatch(/unavailable|changed|unknown/i); expect(writes(w)).toHaveLength(0)
    safe(w, await visible(ui)); await dispose(ui); w.run = normal
  }
})

test('provider key root lease finite cap and fold are validated rather than inferred from a matching hash', async ($, on) => {
  const w = fixture(on), normal = w.run
  const variants: [string, (i: any) => void][] = [
    ['foreign device', i => { i.provider.device_public_key = i.device_public_key }],
    ['wrong lease/root', i => { i.provider.lease_id = i.person_lease_id; i.provider.root_state_id = id64('ds', 99) }],
    ['unbounded cap', i => { i.not_after = stamp(w.providerEnd + 1000) }],
    ['false administrator fold', i => { i.provider.scopes = 7 }],
  ]
  for (const [label, mutate] of variants) {
    const ui = await setup($, w)
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'machine.lookup') { mutate(value.inspection.review); value.inspection.review_id = await digest('peerspan-machine-owner-inspection-v1', value.inspection.review) }
      return value
    }
    await begin(w, ui); await choose(w, ui); await absent(ui, undefined, label)
    expect(writes(w)).toHaveLength(0); safe(w, await visible(ui)); await dispose(ui); w.run = normal
  }
})

test('consent rejects wrong frozen digest effects receipt binding and unknown nested fields without approval', async ($, on) => {
  const w = fixture(on), normal = w.run
  const variants: [string, (v: any) => void][] = [
    ['frozen digest', v => { v.consent.review.inspection_review_id = 'review_' + '9'.repeat(64) }],
    ['effects', v => { v.consent.review.effects.commit_request = true }],
    ['receipt binding', v => { v.consent.consent_id = id('dint', 99) }],
    ['unknown local field', v => { v.consent.review.inspection.local_host.signer_available = true }],
  ]
  for (const [label, mutate] of variants) {
    w.consents = {}; const ui = await setup($, w)
    w.consents[w.requests[0].request_id] = await consentRecord(w, w.requests[0].request_id)
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'machine.lookup') { mutate(value); value.consent.review_id = await digest('peerspan-machine-owner-consent-v1', value.consent.review) }
      return value
    }
    await begin(w, ui); await choose(w, ui); await absent(ui, undefined, label)
    expect(writes(w)).toHaveLength(0); safe(w, await visible(ui)); await dispose(ui); w.run = normal
  }
})

test('signing requires exact counts IDs can-sign consistency and seven closed not-verified fields', async ($, on) => {
  const w = fixture(on), normal = w.run
  const variants: [string, (s: any) => void][] = [
    ['count', s => { s.signature_count = 4 }],
    ['intent', s => { s.intent_id = id('dint', 99) }],
    ['signed cannot sign', s => { s.state = 'signed'; s.signature_count = 3 }],
    ['unverified field', s => { s.connection_readiness = 'verified'; s.extra = true }],
  ]
  for (const [label, mutate] of variants) {
    w.consents = {}; const ui = await setup($, w)
    w.consents[w.requests[0].request_id] = await consentRecord(w, w.requests[0].request_id, { state: 'approved' })
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e)); if (kind === 'machine.signing') mutate(value.signing); return value
    }
    await begin(w, ui); await choose(w, ui); await absent(ui, undefined, label)
    expect(calls(w, 'sign')).toHaveLength(0); expect(writes(w)).toHaveLength(0)
    safe(w, await visible(ui)); await dispose(ui); w.run = normal
  }
})

// 15–16. No provider bytes or regressing/future observation become human authority.
test('private-prefixed control oversize and subprocess-error output stays unavailable with no external disclosure', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const fault of ['private', 'control', 'oversize', 'stderr']) {
    const ui = await setup($, w)
    w.run = async (kind, payload, e) => {
      if (kind !== 'machine.lookup') return normal(kind, payload, e)
      if (fault === 'oversize') return { fixtureRaw: ' '.repeat(2 * 1024 * 1024 + 1) + '{}' }
      if (fault === 'stderr') return { fixtureExit: true }
      const value = clone(await normal(kind, payload, e))
      value.inspection.review.member = fault === 'private' ? 'token_DO_NOT_ECHO' : 'unsafe\u0001member'
      value.inspection.review_id = await digest('peerspan-machine-owner-inspection-v1', value.inspection.review)
      return value
    }
    await begin(w, ui); await choose(w, ui); await absent(ui, undefined, fault)
    const shown = await visible(ui); expect(shown).toMatch(/unavailable|unknown|failed/i)
    expect(shown).not.toContain('token_DO_NOT_ECHO'); expect(shown).not.toContain('unsafe\u0001member')
    expect(w.outside.join('\n')).not.toContain('token_DO_NOT_ECHO'); safe(w, shown)
    await dispose(ui); w.run = normal
  }
  expect(writes(w)).toHaveLength(0)
})

test('regressing observation and future or before-creation terms clear actionable consent without mutation', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['regression', 'future', 'creation']) {
    w.consents = {}; const ui = await prepared($, w)
    await w.clock.advance(1000)
    const before = calls(w, 'approve').length
    w.run = async (kind, payload, e) => {
      const value = clone(await normal(kind, payload, e))
      if (kind === 'machine.lookup') value.observed_at = mode === 'regression' ? stamp(NOW - 1000)
        : mode === 'future' ? stamp(Math.floor(w.clock.now() / 1000) * 1000 + 31_000)
          : stamp(Date.parse(value.consent.review.created_at) - 1000)
      return value
    }
    await press(ui, 'Approve machine consent'); await absent(ui, undefined, mode)
    expect(calls(w, 'approve')).toHaveLength(before); safe(w, await visible(ui)); await dispose(ui); w.run = normal
  }
})

// 17–18. Each mutation has original deadline authority before and during awaits.
test('original signed deadline removes displayed actions and an in-flight sign cannot restore fresh authority', async ($, on) => {
  const w = fixture(on)
  let ui: Pane
  for (const bound of ['request', 'receipt', 'stage', 'powers']) {
    const at = w.clock.now()
    const created = bound === 'receipt' ? at - 300_000 : bound === 'stage' ? at - 599_000 : at - 60_000
    w.requests = [request(1, 'pending', { created, expires: bound === 'request' ? at + 1000 : at + 3_600_000 })]
    w.consents = {}; w.providerEnd = bound === 'powers' ? at + 1000 : NOW + 86_400_000
    ui = await selected($, w, 'approved', { created: bound === 'receipt' ? at - 299_000 : at - 1000 })
    expect(await ui.find({ type: 'Button', text: /^Sign machine owner offer$/ }), bound).toBeDefined()
    const before = calls(w).length; await w.clock.advance(1000)
    await absent(ui, undefined, bound); expect(calls(w)).toHaveLength(before); expect(calls(w, 'sign')).toHaveLength(0)
    await dispose(ui)
  }
  w.providerEnd = NOW + 86_400_000
  const now = w.clock.now(); w.requests = [request(1, 'pending', { created: now - 60_000, expires: now + 1000 })]; w.consents = {}
  ui = await selected($, w, 'approved', { created: now - 1000 })
  const normal = w.run, delay = delayed(w)
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'machine.sign') await delay.wait(); return value }
  const pending = press(ui, 'Sign machine owner offer'); void pending.catch(() => undefined); await delay.started
  expect(calls(w, 'sign')).toHaveLength(1); await w.clock.advance(1000); await pending
  await absent(ui); expect(await ui.find({ type: 'Button', text: /^Check machine consent$/ })).toBeDefined()
  const after = calls(w).length; await w.clock.advance(1000); expect(calls(w)).toHaveLength(after)
  expect(calls(w, 'sign')).toHaveLength(1); safe(w, await visible(ui))
})

test('held fresh lookups cross original preparation approval and signing windows without dispatching a mutation', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const op of ['prepare', 'approve', 'sign']) {
    const now = w.clock.now(); w.requests = [request(1, 'pending', { created: now - 60_000, expires: now + 1000 })]
    w.consents = {}; w.counts = {}; const ui = await selected($, w, op === 'prepare' ? undefined : op === 'approve' ? 'review' : 'approved', { created: now - 1000 })
    const delay = delayed(w), before = writes(w).length
    w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); if (kind === 'machine.lookup') await delay.wait(); return value }
    const label = op === 'prepare' ? 'Review machine consent' : op === 'approve' ? 'Approve machine consent' : 'Sign machine owner offer'
    const pending = press(ui, label); void pending.catch(() => undefined); await delay.started
    await w.clock.advance(1000); await pending; await absent(ui, undefined, op)
    expect(writes(w)).toHaveLength(before); safe(w, await visible(ui)); await dispose(ui); w.run = normal
  }
})

// 19–20. Delayed valid replies cannot overwrite changed authority/navigation.
test('dispatched lookup rejects changed root native host parent and terminal before late preparation can publish a review', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['root', 'native', 'host', 'parent', 'terminal']) {
    w.root = ROOT; w.native = NATIVE; w.host = HOST; w.surface = 'terminal'; w.surfaces = ['terminal']; w.consents = {}
    const ui = await selected($, w), delay = delayed(w), before = writes(w).length
    w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e)); if (kind === 'machine.lookup') await delay.wait(); return value }
    const pending = press(ui, 'Review machine consent'); void pending.catch(() => undefined); await delay.started
    if (mode === 'root') { w.root = '/changed-private-project'; await $.classic.CwdChanged({ old_cwd: ROOT, new_cwd: w.root }) }
    if (mode === 'native') w.native = 'different-native-conversation'
    if (mode === 'host') w.host = 'host_' + '9'.repeat(64)
    if (mode === 'parent') { w.parent.state = 'invalidated'; w.parent.attachment = null }
    if (mode === 'terminal') { w.surface = null; w.surfaces = [] }
    await w.clock.advance(1000); await pending.catch(() => undefined); await absent(ui, undefined, mode)
    expect(writes(w)).toHaveLength(before); await dispose(ui); w.run = normal
  }
  safe(w)
})

test('Leave Refresh Close and session-end invalidate late mutation replies and old timers cannot replace a new choice', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const mode of ['Leave', 'Refresh', 'Close', 'end']) {
    w.consents = {}; w.counts = {}; w.requests = [request(), request(2)]
    const ui = await prepared($, w), delay = delayed(w)
    w.run = async (kind, payload, e) => { const value = clone(await normal(kind, payload, e)); if (kind === 'machine.approve') await delay.wait(); return value }
    const pending = press(ui, 'Approve machine consent'); void pending.catch(() => undefined); await delay.started
    if (mode === 'Leave') {
      await press(ui, 'Leave machine review'); await begin(w, ui); await choose(w, ui, 1)
      await press(ui, 'Review machine consent')
    }
    if (mode === 'Refresh') await press(ui, 'Refresh')
    if (mode === 'Close') await press(ui, 'Close')
    if (mode === 'end') await $.session.end({ sessionId: NATIVE })
    await w.clock.advance(1000); await pending.catch(() => undefined)
    if (mode === 'Leave') {
      expect(await ui.find({ type: 'Button', text: /^Approve machine consent$/ })).toBeDefined()
      expect(calls(w, 'approve').at(-1).payload.request_id).toBe(id64('link', 1))
      expect(w.consents[id64('link', 2)].state).toBe('review')
    } else await absent(ui, undefined, mode)
    expect(calls(w, 'sign')).toHaveLength(0); await dispose(ui); w.run = normal
  }
  safe(w)
})

// 21. A lost reply is never permission to repeat a mutation.
test('lost prepare approve and sign recover retained evidence only through explicit pure Check', async ($, on) => {
  const w = fixture(on), normal = w.run
  for (const op of ['prepare', 'approve', 'sign']) {
    w.consents = {}; w.counts = {}
    const ui = await selected($, w, op === 'prepare' ? undefined : op === 'approve' ? 'review' : 'approved')
    let lost = true
    w.run = async (kind, payload, e) => {
      const value = await normal(kind, payload, e)
      if (kind === 'machine.' + op && lost) { lost = false; return { fixtureRaw: RAW } }
      return value
    }
    const label = op === 'prepare' ? 'Review machine consent' : op === 'approve' ? 'Approve machine consent' : 'Sign machine owner offer'
    const before = calls(w, op).length; await press(ui, label)
    expect(calls(w, op)).toHaveLength(before + 1); await absent(ui, undefined, op)
    expect(await visible(ui)).toMatch(/(?:outcome[\s\S]*unknown|unknown[\s\S]*outcome)/i)
    const after = calls(w).length; await w.clock.advance(2000); expect(calls(w)).toHaveLength(after)
    await press(ui, 'Check machine consent')
    expect(calls(w).slice(after).map(c => c.kind)).toEqual(op === 'prepare' ? ['machine.lookup'] : ['machine.lookup', 'machine.signing'])
    expect(calls(w, op)).toHaveLength(before + 1)
    if (op === 'sign') { await evidence(ui, 3, 3); await absent(ui) }
    if (op === 'approve') { await evidence(ui, 0, 3); expect(await ui.find({ type: 'Button', text: /^Sign machine owner offer$/ })).toBeDefined() }
    if (op === 'prepare') expect(await ui.find({ type: 'Button', text: /^Approve machine consent$/ })).toBeDefined()
    safe(w, await visible(ui)); await dispose(ui); w.run = normal
  }
})

// 22. Navigating this pane neither takes over other lanes nor stops a ready lease.
test('machine-owner controls preserve authorized messages tasks and the separate new-computer and administrator lanes', async ($, on) => {
  const w = fixture(on), ui = await setup($, w)
  w.child = await adapterFlow(w.parent, { n: w.sequence, state: 'authorized' })
  await press(ui, 'Review adapter connection'); await press(ui, 'Connect adapter'); await w.clock.settle()
  await press(ui, 'Enable incoming messages'); await w.clock.settle()
  expect(w.prompts).toHaveLength(1)
  const nonce = w.prompts[0].text.match(/\b[0-9a-f]{32}\b/)!; expect(nonce).not.toBe(null)
  const ready = await $.tool.call({ tool: READY, nonce: nonce[0] }); expect(ready.isError ?? false).toBe(false)
  await w.clock.settle(); await press(ui, 'Enable incoming tasks'); await w.clock.settle()
  const toolNames = w.tools.map(t => t.name), prompts = clone(w.prompts)
  const count = (path: string) => w.httpCalls.filter(c => c.url.endsWith(path)).length
  const readyCount = count('/adapter/v1/ready')
  await press(ui, 'Back to project')
  expect(await ui.find({ type: 'Button', text: /^Review incoming connections$/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /^Join a network$/ })).toBeDefined()
  await begin(w, ui); await choose(w, ui); await press(ui, 'Review machine consent'); await press(ui, 'Approve machine consent')
  await press(ui, 'Leave machine review')
  const messages = count('/adapter/v1/next'), tasks = count('/adapter/v1/tasks/next'), leases = count('/adapter/v1/connect')
  await w.clock.advance(5000)
  expect(count('/adapter/v1/next') > messages).toBe(true); expect(count('/adapter/v1/tasks/next') > tasks).toBe(true)
  expect(count('/adapter/v1/connect')).toBe(leases + 1); expect(count('/adapter/v1/ready')).toBe(readyCount)
  expect(w.tools.map(t => t.name)).toEqual(toolNames); expect(w.prompts).toEqual(prompts)
  expect(calls(w, 'sign')).toHaveLength(0); expect(calls(w, 'approve')).toHaveLength(1)
  for (const c of w.httpCalls) {
    const headers = Object.fromEntries(Object.entries(c.init.headers).map(([key, value]) => [key.toLowerCase(), value]))
    expect(c.init.socketPath).toBe(SOCKET); expect(headers.authorization).toBe('Bearer ' + TOKEN)
    expect(headers['x-peerspan-instance']).toBe(w.materials[0].instance_id)
  }
  safe(w, await visible(ui), true)
})
