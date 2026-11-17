/**
 * Independent section-55 native conformance (agent access granted with the
 * invite, P5) on Claude Code 2.1.303. Written from the contract alone: public
 * native effects only, no product imports, authentication or inference. Host
 * responses follow sections 9 and 55. Section 55 names the grant lookup's
 * contents and states but not its field names; the grant records below use the
 * field names a real host returned in the contract-only slim suite
 * (conformance/slim/invitation_grants.py), and a stopped record's reason is a
 * stand-in, since no public route produced one. The contract names labels, not
 * how the setting is drawn, so Let MEMBER reach AGENT is found by its name and
 * read as on/off from its shown text or Select value, as section 54's settings are.
 */
import { expect, mock, test } from 'claude-code/testing'
import type { Engine, Mounted } from 'claude-code/testing'
import type { On } from 'claude-code'

const NOW = Date.parse('2026-11-17T12:00:00Z')
const HOST = 'host_75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a'
const ROOT = '/private project/Native $(literal)'
const NATIVE = 'private-native-invitation-conversation'
const RAW = 'PRIVATE_PROVIDER_ERROR token_DO_NOT_ECHO /private/provider-path'
const CODE = 'psi2-UFJJVkFURV9JTlZJVEVfU0VDUkVU'
const GENESIS_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
const INVITER_KEY = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
const PERSON_KEY = 'BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU='
const MEMBER = 'Dana Teammate'
const AGENT = 'Project helper'
const PERSON = 'person_' + 'e'.repeat(64)
const id = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(32, '0')
const id64 = (kind: string, n: number) => kind + '_' + n.toString(16).padStart(64, '0')
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))
const stamp = (milliseconds: number) => new Date(milliseconds).toISOString().replace('.000Z', 'Z')
const context = (parent: any) => ({ project_flow_id: parent.flow_id, project_review_id: parent.review_id,
  project_root: parent.review.project_root, native_session_id: parent.review.native_session_id, integration: 'claude-code' })
// A human label as the pane may show it: bare or quoted (section 10 quotes raw human strings reversibly).
const named = (value: string) => '"?' + value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '"?'
const AGENT_ACCESS = (agent: any) => ({ policy_scope: 'owner_agent_name', agent_id: agent.id, agent_name: agent.name,
  actions: ['message.append', 'task.submit'], max_message_bytes: 65536, max_artifact_bytes: 0,
  allow_disconnected: false, policy_hours: 24 })
const invitationEffects = { create_contact_invitation: true, receive_join_requests: true, grant_membership: false,
  grant_agent_access: false, approve_machine: false, share_files: false, share_conversation: false, capability_calls: false }
const WORDS = (member: string, agent: string) => new RegExp('When ' + named(member) + ' is admitted, they can send ' +
  'messages and tasks to ' + named(agent) + ' on all your machines \\(up to 64 KiB per message, no files\\), ' +
  'renewed daily until you remove it\\.')

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
async function parentFlow() {
  const review = { version: 1, kind: 'attach_project', flow_id: id('flow', 1), host_id: HOST, project_root: ROOT,
    native_session_id: NATIVE, integration: 'claude-code', create_agent: false,
    agent: { id: id('agent', 1), name: AGENT, owner: 'Local owner', capabilities: [] },
    session_id: id('session', 1), expires_at: stamp(NOW + 900_000),
    effects: { register_agent: false, attach_session: true, issue_adapter_credential: false, grant_network_access: false,
      share_files: false, share_conversation: false, capability_calls: false } }
  return { version: 1, flow_id: review.flow_id, state: 'attached', review_id: await digest('peerspan-project-review-v1', review),
    review, attachment: { agent_id: review.agent.id, session_id: review.session_id }, next_action: 'continue_adapter_setup' }
}
function network(n = 1): any {
  return { id: id64('net', n), name: 'Team network', mode: 'decentralized', context_id: id64('ctx', n),
    genesis_root_public_key: GENESIS_KEY, root_state_id: id64('drs', n), root_public_key: GENESIS_KEY, root_epoch: 0,
    member: 'local owner', host_public_key: INVITER_KEY, person_public_key: PERSON_KEY, provider: null,
    provider_state: { state: 'not_selected', code: '-', error: '-', required_ids: [] },
    authority: { state: 'usable', not_after: stamp(NOW + 86_400_000), required_ids: [], conflict_ids: [] },
    delivery: { pending_proof_ids: [], peer_errors: [] }, created_at: stamp(NOW - 1000) }
}
async function invitationFlow(parent: any, selected: any, options: any = {}) {
  const n = options.n ?? 30, state = options.state ?? 'review'
  const review: any = { version: 1, kind: 'create_contact_invitation', flow_id: id('flow', n), host_id: parent.review.host_id,
    context: context(parent), agent: clone(parent.review.agent),
    network: { id: selected.id, name: selected.name, context_id: selected.context_id, genesis_root_public_key: selected.genesis_root_public_key },
    inviter_host_public_key: selected.host_public_key, member: options.member ?? MEMBER,
    expected_person_public_key: options.pin ?? '-',
    transport: { bootstrap_addresses: ['127.0.0.1:443'], quic_addresses: ['127.0.0.1:444'], relays: [], helpers: [] },
    expires_at: stamp(options.expires ?? NOW + 900_000), invitation_expires_at: stamp(options.invitationExpires ?? NOW + 3_600_000),
    effects: clone(invitationEffects) }
  if (options.access ?? true) {
    review.agent_access = AGENT_ACCESS(parent.review.agent)
    review.effects.grant_agent_access_after_admission = true
  }
  return { version: 1, flow_id: review.flow_id, state, review_id: await digest('peerspan-invitation-review-v1', review), review,
    invitation: state === 'issued' ? { invitation_id: id64('di', n), expires_at: review.invitation_expires_at } : null,
    next_action: state === 'review' ? 'review' : state === 'issued' ? 'share_private_invitation' : 'restart_review' }
}
// One grant record (section 55, Lifetime and owner controls) for the issued invitation.
function grantRecord(flow: any, state: string, now: number) {
  const requested = state !== 'waiting_for_request' && state !== 'cancelled' && !(state === 'expired')
  const bound = ['waiting_for_owner', 'granted', 'stopped'].includes(state)
  const outcome: any = { granted: { at: stamp(now), policy_version: 7, state },
    cancelled: { at: stamp(now), state }, expired: { at: stamp(now), reason: 'invitation_expired', state },
    stopped: { at: stamp(now), reason: 'agent_changed', state } }[state] ?? null
  return { agent: { id: flow.review.agent.id, name: flow.review.agent.name }, created_at: stamp(NOW),
    expires_at: flow.review.invitation_expires_at, flow_id: flow.flow_id, invitation_id: flow.invitation.invitation_id,
    member: flow.review.member, network_id: flow.review.network.id, outcome, person_id: bound ? PERSON : null,
    requests: requested ? [{ at: stamp(NOW + 1000), person_id: PERSON, request_id: id64('link', 5) }] : [], state }
}

function fixture(on: On) {
  const clock = mock.clock(on, { now: NOW })
  const w = { clock, started: false, root: ROOT, native: NATIVE, host: HOST, surface: 'terminal' as string | null,
    surfaces: ['terminal'], parent: null as any, sequence: 20, networks: [] as any[], invitation: null as any,
    grant: 'waiting_for_request', calls: [] as any[], trace: [] as any[], outside: [] as string[], forbidden: [] as string[],
    prompts: [] as any[], run: async (_kind: string, _payload: any, _e: any): Promise<any> => undefined }
  w.run = async (kind, payload, e) => {
    if (kind === 'snapshot') return { version: 1, observed_at: stamp(clock.now()), host_id: w.host,
      networks: w.networks, agents: [], requests: [], attention: [] }
    if (kind === 'invitation.lookup') return { version: 1, host_id: w.host, context: payload.context, flow: w.invitation }
    if (kind === 'invitation.prepare') {
      w.invitation = await invitationFlow(w.parent, w.networks.find(net => net.id === payload.network_id),
        { n: ++w.sequence, member: payload.member.trim(), pin: payload.expected_person_public_key,
          access: payload.agent_access === true, expires: clock.now() + 900_000, invitationExpires: clock.now() + 3_600_000 })
      return w.invitation
    }
    if (kind === 'invitation.inspect') return w.invitation
    if (kind === 'invitation.decide') {
      const approve = payload.decision === 'approve'
      w.invitation = { ...w.invitation, state: approve ? 'issued' : 'declined',
        invitation: approve ? { invitation_id: id64('di', w.sequence), expires_at: w.invitation.review.invitation_expires_at } : null,
        next_action: approve ? 'share_private_invitation' : 'restart_review' }
      return w.invitation
    }
    if (kind === 'invitation.handoff') return { version: 1, flow_id: w.invitation.flow_id, review_id: w.invitation.review_id,
      network_id: w.invitation.review.network.id, context_id: w.invitation.review.network.context_id,
      invitation_id: w.invitation.invitation.invitation_id, invitation: CODE, expires_at: w.invitation.invitation.expires_at }
    if (kind === 'grant.inspect') return grantRecord(w.invitation, w.grant, clock.now())
    if (kind === 'grant.complete') { if (w.grant === 'waiting_for_owner') w.grant = 'granted'; return grantRecord(w.invitation, w.grant, clock.now()) }
    if (kind === 'grant.cancel') { if (!['granted', 'cancelled', 'expired', 'stopped'].includes(w.grant)) w.grant = 'cancelled'; return grantRecord(w.invitation, w.grant, clock.now()) }
    if (kind === 'project.lookup') return { version: 1, host_id: w.host, context: payload, flow: w.parent,
      agents: w.parent ? [{ ...w.parent.review.agent, created_at: stamp(NOW - 1000) }] : [] }
    if (kind === 'project.inspect') return w.parent
    if (kind === 'adapter.lookup') return { version: 1, host_id: w.host, context: payload, flow: null }
    throw Error('Unexpected public process operation')
  }
  on('session.start', ($, e) => { w.started = true; return { cwd: e.cwd } })
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  on('classic.CwdChanged', () => ({}))
  on('session.root', () => { w.trace.push({ kind: 'root', value: w.root }); return { value: w.root } })
  on('session.id', () => { w.trace.push({ kind: 'native', value: w.native }); return { value: w.native } })
  on('session.cwd', () => ({ value: '/different-shell-cwd' }))
  on('session.surface', () => ({ value: w.surface }))
  on('session.surfaces', () => ({ value: w.surfaces }))
  on('command.register', () => ({ value: undefined }))
  on('tool.register', () => ({ value: undefined }))
  on('command.run', () => ({ text: 'unhandled fixture command' }))
  on('tool.call', () => ({ deny: 'unregistered fixture tool' }))
  on('process.run', async ($, e) => {
    const tail = e.argv.slice(e.argv.indexOf('onboarding') + 1)
    const kind = !tail.length ? 'snapshot' : tail[0] === 'invitation' && tail[1] === 'grant' ? 'grant.' + tail[2] : tail[0] + '.' + tail[1]
    const payload = e.init?.stdin ? JSON.parse(e.init.stdin) : undefined
    w.calls.push({ ...e, kind, payload }); w.trace.push({ kind, payload })
    const value = await w.run(kind, payload, e)
    if (value?.fixtureDeny) return { deny: RAW }
    return { value: { exitCode: 0, stdout: JSON.stringify(value), stderr: '' } }
  })
  on('http.fetch', () => { w.forbidden.push('http.fetch'); return { deny: 'no adapter traffic' } })
  on('ui.open', () => ({ value: { isPlaced: w.surface === 'terminal' } }))
  on('ui.close', () => ({ value: undefined }))
  on('ui.panes', () => ({ value: [] }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['native core fallback'] }))
  on('ui.toast', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.log', ($, e) => { w.outside.push(e.text); return { value: undefined } })
  on('ui.status', ($, e) => { w.outside.push(String(e.text ?? '')); return { value: undefined } })
  on('ui.notice', ($, e) => { w.outside.push(JSON.stringify(e)); return { value: undefined } })
  on('prompt.submit', ($, e) => { w.prompts.push(clone(e)); return { text: e.text, origin: e.origin } })
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
async function text(ui: Pane) {
  return (await ui.findAll({})).map(element => element.text).join('\n')
}
async function flat(ui: Pane) { return (await text(ui)).replace(/\s+/g, ' ') }
async function button(ui: Pane, label: string | RegExp) {
  return ui.find({ type: 'Button', text: typeof label === 'string' ? new RegExp('^' + label + '$') : label })
}
async function press(ui: Pane, label: string | RegExp) {
  const found = await button(ui, label); expect(found, String(label)).toBeDefined()
  await ui.press({ key: found!.key! })
}
async function enter($: Engine, w: World): Promise<Pane> {
  const answer = await $.command.run({ command: 'peerspan', args: '', origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 } })
  w.outside.push(answer.text ?? '', ...(answer.context ?? []))
  return $.ui.mount({ plugin: 'peerspan', surface: 'terminal', component: 'Pane', requestId: 'peerspan',
    viewport: { columns: 100, rows: 40 }, props: { title: 'Peerspan', isFocused: true, bodyColumns: 80,
      placement: 'inline', scroll: { offset: 0, bodyRows: 30 }, view: {} } })
}
async function setup($: Engine, w: World, state: string | null = null, options: any = {}) {
  w.networks = [network()]
  w.parent = await parentFlow()
  if (state) w.invitation = await invitationFlow(w.parent, w.networks[0], { ...options, state })
  if (!w.started) await $.session.start({ cwd: '/different-shell-cwd', surface: w.surface as any, isInteractive: true })
  const ui = await enter($, w); await toProject(w, ui); return ui
}
// The attached project's view: Connect this project, or, unless show_each_step is set, Connect this
// conversation from the entry view (section 54; on its own review screen that label is the consent press).
async function toProject(w: World, ui: Pane) {
  const connect = await button(ui, 'Connect this project')
    ?? (await button(ui, 'Invite someone') ? undefined : await button(ui, 'Connect this conversation'))
  if (connect) { await ui.press({ key: connect.key! }); await w.clock.settle() }
}
async function begin(w: World, ui: Pane) {
  await toProject(w, ui); await press(ui, 'Invite someone'); await w.clock.settle()
}
async function draft(w: World, ui: Pane, label = MEMBER) {
  const found = (await ui.findAll({ type: 'Button' })).find(element => element.text.includes(w.networks[0].id))
  expect(found, 'explicit full-ID network choice').toBeDefined()
  await ui.press({ key: found!.key! })
  const field = (await ui.findAll({ type: 'Input' })).find(element => element.props.label === 'Invitee label')
  expect(field, 'Invitee label').toBeDefined()
  await ui.input({ key: field!.key!, text: label, kind: 'change' })
  await w.clock.settle()
}

// The setting: a Select labelled with its name, or another element whose shown text carries it.
const SETTING = new RegExp('^\\s*(?:\\S+\\s+)?Let ' + named(MEMBER) + ' reach ' + named(AGENT) + '\\b')
const ANY_SETTING = /\bLet\b.*\breach\b/
const OFF = /\[ \]|☐|□|⬜|\b(?:off|no|unchecked|not checked|disabled|false)\b/i
const ON = /\[[xX✓✔]\]|☑|✅|✓|✔|■|\b(?:on|yes|checked|enabled|true)\b/i
async function setting(ui: Pane, pattern = SETTING) {
  const select = (await ui.findAll({ type: 'Select' })).find(e => pattern.test(String(e.props.label ?? '')))
  if (select) return select
  return (await ui.findAll({})).find(e => e.type !== 'Text' && pattern.test(e.text))
    ?? (await ui.findAll({})).find(e => pattern.test(e.text))
}
async function isOn(ui: Pane) {
  const found = await setting(ui)
  expect(found, 'Let MEMBER reach AGENT setting').toBeDefined()
  if (found!.type === 'Select') {
    const options = (found!.props.options as any[]) ?? [], value = found!.props.value
    const shown = String(options.find(option => option.value === value)?.label ?? value ?? '')
    return !OFF.test(shown) && ON.test(shown)
  }
  const shown = found!.text.replace(new RegExp('Let ' + named(MEMBER) + ' reach ' + named(AGENT)), '')
    .replace(/\s+/g, ' ').replace(WORDS(MEMBER, AGENT), '')
  return !OFF.test(shown) && ON.test(shown)
}
async function turnOff(w: World, ui: Pane) {
  for (let attempt = 0; attempt < 3 && await isOn(ui); attempt++) {
    const found = (await setting(ui))!
    if (found.type === 'Select') {
      const target = ((found.props.options as any[]) ?? []).find(option => OFF.test(String(option.label ?? option.value)))
      expect(target, 'off option').toBeDefined(); await ui.select({ key: found.key!, value: target.value })
    } else await ui.press({ key: found.key! })
    await w.clock.settle()
  }
  expect(await isOn(ui), 'setting unchecked').toBe(false)
}
const ACCESS = (words: string) => new RegExp('Access for ' + named(MEMBER) + ':\\s*' + words)
const GRANT = new RegExp('^Grant access to ' + named(MEMBER) + '$')
async function grantControls(ui: Pane) {
  return { grant: await button(ui, GRANT), cancel: await button(ui, 'Cancel access') }
}
function safe(w: World, uiText = '', executable = 'peerspan') {
  expect(w.forbidden).toEqual([])
  expect(w.outside.join('\n')).not.toContain(CODE); expect(uiText).not.toContain(CODE)
  expect(w.outside.join('\n') + uiText).not.toContain('PRIVATE_PROVIDER_ERROR')
  for (const prompt of w.prompts) expect(prompt.text).not.toContain(CODE)
  for (const command of w.calls) {
    expect(command.init?.timeoutMs).toBe(5000)
    if (command.kind.startsWith('grant.')) {
      expect(command.argv).toEqual([executable, 'onboarding', 'invitation', 'grant', command.kind.slice(6), w.invitation.invitation.invitation_id])
      expect(['inspect', 'complete', 'cancel']).toContain(command.kind.slice(6))
    }
  }
}
async function approveDraft(w: World, ui: Pane) {
  await press(ui, 'Review invitation'); await w.clock.settle()
  await press(ui, 'Approve invitation'); await w.clock.settle()
}

test('Let MEMBER reach AGENT is on by default in the draft with its words and the prepare carries agent_access true', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); await begin(w, ui); await draft(w, ui)
  expect(await setting(ui), 'the setting in the invitation draft').toBeDefined()
  expect(await isOn(ui), 'on by default').toBe(true)
  expect(await flat(ui)).toMatch(WORDS(MEMBER, AGENT))
  expect(count(w, 'invitation.prepare')).toBe(0)
  await press(ui, 'Review invitation'); await w.clock.settle()
  expect(last(w, 'invitation.prepare').payload).toEqual({ context: context(w.parent), network_id: w.networks[0].id,
    member: MEMBER, expected_person_public_key: '-', agent_access: true })
  expect(count(w, 'grant.inspect') + count(w, 'grant.complete') + count(w, 'grant.cancel')).toBe(0)
  safe(w, await text(ui))
})

test('the review shows the agent access terms before approval and approval records nothing more than the decision', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); await begin(w, ui); await draft(w, ui)
  await press(ui, 'Review invitation'); await w.clock.settle()
  const shown = await flat(ui)
  expect(shown).toContain(AGENT)
  expect(shown).toMatch(/64 KiB|65536|65,536/)
  expect(shown).toMatch(/messages?/i); expect(shown).toMatch(/tasks?/i)
  expect(shown).toMatch(/admi/i)
  expect(await button(ui, 'Approve invitation')).toBeDefined()
  expect(count(w, 'invitation.decide')).toBe(0)
  await press(ui, 'Approve invitation'); await w.clock.settle()
  expect(last(w, 'invitation.decide').payload.decision).toBe('approve')
  expect(count(w, 'grant.complete')).toBe(0); expect(count(w, 'grant.cancel')).toBe(0)
  safe(w, await text(ui))
})

test('unchecking the setting omits agent_access from the prepare', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); await begin(w, ui); await draft(w, ui)
  await turnOff(w, ui)
  await press(ui, 'Review invitation'); await w.clock.settle()
  const payload = last(w, 'invitation.prepare').payload
  expect(payload).toEqual({ context: context(w.parent), network_id: w.networks[0].id, member: MEMBER, expected_person_public_key: '-' })
  expect('agent_access' in payload).toBe(false)
  safe(w, await text(ui))
})

test('show_each_step restores the invitation draft without the setting and the prepare omits agent_access', { options: { show_each_step: 'true' } }, async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); await begin(w, ui); await draft(w, ui)
  expect(await setting(ui, ANY_SETTING)).toBeUndefined()
  expect(await flat(ui)).not.toMatch(/renewed daily until you remove it/)
  await press(ui, 'Review invitation'); await w.clock.settle()
  expect(last(w, 'invitation.prepare').payload).toEqual({ context: context(w.parent), network_id: w.networks[0].id,
    member: MEMBER, expected_person_public_key: '-' })
  safe(w, await text(ui))
})

test('the issued view shows the grant state from the read-only lookup and refreshes itself while open', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); await begin(w, ui); await draft(w, ui); await approveDraft(w, ui)
  expect(count(w, 'grant.inspect')).toBeGreaterThanOrEqual(1)
  expect(await flat(ui)).toMatch(ACCESS('waiting for their request'))
  w.grant = 'waiting_for_admission'
  const before = count(w, 'grant.inspect')
  await w.clock.advance(5000); await w.clock.settle()
  expect(count(w, 'grant.inspect'), 'an automatic check 5 seconds on').toBeGreaterThan(before)
  expect(await flat(ui)).toMatch(ACCESS('(?:…|\\.\\.\\.)?\\s*waiting for admission'))
  w.grant = 'granted'
  await w.clock.advance(5000); await w.clock.settle()
  expect(await flat(ui)).toMatch(ACCESS('(?:…|\\.\\.\\.)?\\s*granted'))
  const settled = count(w, 'grant.inspect')
  await w.clock.advance(20_000); await w.clock.settle()
  expect(count(w, 'grant.inspect'), 'checking stops at a terminal state').toBe(settled)
  expect(count(w, 'grant.complete')).toBe(0); expect(count(w, 'grant.cancel')).toBe(0)
  expect(count(w, 'invitation.prepare')).toBe(1); expect(count(w, 'invitation.decide')).toBe(1)
  safe(w, await text(ui))
})

test('Grant access to MEMBER and Cancel access are offered only while the grant waits for the owner', async ($, on) => {
  const w = fixture(on)
  const ui = await setup($, w, 'issued')
  for (const state of ['waiting_for_request', 'waiting_for_admission', 'waiting_for_owner', 'granted', 'cancelled', 'expired', 'stopped']) {
    w.grant = state
    const back = await button(ui, /^Back\b/)
    if (back) { await ui.press({ key: back.key! }); await w.clock.settle() }
    await begin(w, ui)
    const { grant, cancel } = await grantControls(ui)
    if (state === 'waiting_for_owner') {
      expect(grant, state + ': Grant access to MEMBER').toBeDefined(); expect(cancel, state + ': Cancel access').toBeDefined()
    } else expect(grant, state + ': no Grant access').toBeUndefined()
    if (['granted', 'cancelled', 'expired', 'stopped'].includes(state)) expect(cancel, state + ': no Cancel access on a terminal record').toBeUndefined()
    if (state !== 'granted') expect(await flat(ui), state).not.toMatch(ACCESS('(?:…|\\.\\.\\.)?\\s*granted'))
  }
  expect(count(w, 'grant.complete')).toBe(0); expect(count(w, 'grant.cancel')).toBe(0)
  safe(w, await text(ui))
})

test('one press of Grant access to MEMBER runs grant complete once and shows the granted state', async ($, on) => {
  const w = fixture(on); w.grant = 'waiting_for_owner'
  const ui = await setup($, w, 'issued'); await begin(w, ui)
  const before = count(w, 'grant.inspect')
  await w.clock.advance(15_000); await w.clock.settle()
  expect(count(w, 'grant.inspect'), 'no automatic checking while an action is due here').toBe(before)
  expect(count(w, 'grant.complete')).toBe(0)
  const found = await button(ui, GRANT); expect(found).toBeDefined()
  const first = ui.press({ key: found!.key! }); void first.catch(() => undefined)
  const second = ui.press({ key: found!.key! }).catch(() => undefined)
  await Promise.all([first, second]); await w.clock.settle()
  expect(count(w, 'grant.complete')).toBe(1)
  expect(last(w, 'grant.complete').argv).toEqual(['peerspan', 'onboarding', 'invitation', 'grant', 'complete', w.invitation.invitation.invitation_id])
  expect(await flat(ui)).toMatch(ACCESS('(?:…|\\.\\.\\.)?\\s*granted'))
  const { grant, cancel } = await grantControls(ui)
  expect(grant).toBeUndefined(); expect(cancel).toBeUndefined()
  expect(count(w, 'grant.cancel')).toBe(0); expect(count(w, 'invitation.decide')).toBe(0)
  safe(w, await text(ui))
})

test('a lost complete response is resolved by the read-only lookup without a second complete', async ($, on) => {
  const w = fixture(on); w.grant = 'waiting_for_owner'
  const ui = await setup($, w, 'issued'); await begin(w, ui); const normal = w.run
  w.run = async (kind, payload, e) => { const value = await normal(kind, payload, e); return kind === 'grant.complete' ? { fixtureDeny: true } : value }
  await press(ui, GRANT); await w.clock.settle()
  expect(count(w, 'grant.complete')).toBe(1)
  expect(await flat(ui)).not.toContain(RAW)
  w.run = normal
  await press(ui, 'Refresh'); await w.clock.settle()
  if (!await button(ui, GRANT) && !(await flat(ui)).match(ACCESS(''))) await begin(w, ui)
  expect(await flat(ui)).toMatch(ACCESS('(?:…|\\.\\.\\.)?\\s*granted'))
  expect(count(w, 'grant.complete')).toBe(1)
  safe(w, await text(ui))
})

test('Cancel access runs grant cancel once and leaves no grant controls', async ($, on) => {
  const w = fixture(on); w.grant = 'waiting_for_owner'
  const ui = await setup($, w, 'issued'); await begin(w, ui)
  await press(ui, 'Cancel access'); await w.clock.settle()
  expect(count(w, 'grant.cancel')).toBe(1); expect(count(w, 'grant.complete')).toBe(0)
  expect(last(w, 'grant.cancel').argv).toEqual(['peerspan', 'onboarding', 'invitation', 'grant', 'cancel', w.invitation.invitation.invitation_id])
  const { grant, cancel } = await grantControls(ui)
  expect(grant).toBeUndefined(); expect(cancel).toBeUndefined()
  expect(await flat(ui)).not.toMatch(ACCESS('(?:…|\\.\\.\\.)?\\s*granted'))
  const settled = count(w, 'grant.inspect')
  await w.clock.advance(20_000); await w.clock.settle()
  expect(count(w, 'grant.inspect'), 'no checking after a terminal state').toBe(settled)
  safe(w, await text(ui))
})

test('an invitation issued without the setting shows no access state or grant controls', async ($, on) => {
  const w = fixture(on); const ui = await setup($, w); await begin(w, ui); await draft(w, ui)
  await turnOff(w, ui); await approveDraft(w, ui)
  expect(w.invitation.state).toBe('issued')
  expect(await flat(ui)).not.toMatch(new RegExp('Access for ' + named(MEMBER)))
  const { grant, cancel } = await grantControls(ui)
  expect(grant).toBeUndefined(); expect(cancel).toBeUndefined()
  expect(count(w, 'grant.complete')).toBe(0); expect(count(w, 'grant.cancel')).toBe(0)
  safe(w, await text(ui))
})
