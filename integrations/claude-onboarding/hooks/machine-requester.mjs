// Closed public machine requester evidence. Private keys remain in the daemon.
import { same, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { publicKey, publicLabel, canonical, freeze } from './invitation.mjs';
import { decodePublic } from './access.mjs';
import { requestView } from './join-progress.mjs';
import { pinned } from './machine-request.mjs';
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).sort().join(' ') === keys.split(' ').sort().join(' ');
const id = (v, kind, n = 64) => typeof v === 'string' && new RegExp(`^${kind}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const fail = () => { throw new Error('Unavailable machine requester evidence'); };
const pins = ['request_id', 'network_id', 'context_id', 'person_public_key', 'host_public_key', 'device_public_key',
  'created_at', 'expires_at', 'request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id'];
const inspectionEffects = { verify_existing_owner: true, verify_requester_selection: true, verify_host_admission: true,
  verify_owner_finalization: true, prepare_commit_intent: false, approve_commit_intent: false,
  sign_requester_commit: false, publish_requester_commit: false, apply_network: false, grant_membership: false,
  grant_machine_powers: false, grant_agent_access: false, share_files: false, share_conversation: false, capability_calls: false };
const consentEffects = { approve_commit_intent: true, authorize_binding_host_signature: true,
  authorize_requester_commit_signatures: true, authorize_commit_publication: true, authorize_local_application: true,
  grant_agent_access: false, share_files: false, share_conversation: false, capability_calls: false };
async function digest(domain, r, expected) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain + '\n' + canonical(r))));
  if (expected !== 'review_' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')) fail();
}
function prefix(r) {
  return ['request_created', 'owner_offered', 'owner_selected',
    ...(r.administrator_offer_id === '-' ? [] : ['administrator_offered']), 'owner_finalized'];
}
export function finalized(r) {
  return r?.state === 'needs_commit' && r.selection_approved && !r.commit_approved &&
    same(r.completed, prefix(r)) && ['manifest_id', 'activation_id', 'outcome_id'].every(k => r[k] === '-');
}
function unchanged(a, b) {
  return pins.every(k => a[k] === '-' || a[k] === b[k]) && a.completed.every((s, i) => b.completed[i] === s) &&
    (!a.selection_approved || b.selection_approved) && (!a.commit_approved || b.commit_approved);
}
export function sameConsent(a, b) {
  return !!a?.consent && !!b?.consent && a.consent.consent_id === b.consent.consent_id &&
    a.consent.review_id === b.consent.review_id && same(a.consent.review, b.consent.review) &&
    pins.every(k => a.request[k] === b.request[k]);
}
export function sameInspection(a, b) {
  return !!a && !!b && a.review_id === b.review_id && same(a.review, b.review) &&
    pins.every(k => a.request[k] === b.request[k]);
}
async function base(v, flow, parent, host, previous) {
  if (v.version !== 1 || v.host_id !== host || !id(host, 'host') || !pinned(flow) || flow.state !== 'requested' ||
      v.flow_id !== flow.flow_id || v.join_review_id !== flow.review_id || !same(v.context, context(parent)) ||
      !time(v.observed_at) || previous && (Date.parse(v.observed_at) < Date.parse(previous.observed_at) ||
        !unchanged(previous.request, v.request))) fail();
  await requestView(v.request, flow, host);
  if (Date.parse(v.observed_at) < Date.parse(v.request.created_at)) fail();
}
async function review(r, wanted, request, flow, parent, host) {
  if (!exact(r, 'version kind host_id context agent flow_id join_review_id request_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id owner_root_state_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id owner_provider host_admission reused_binding scopes binding_scopes not_after created_at expires_at request_stage_deadline effects') ||
      r.version !== 1 || r.kind !== 'inspect_existing_person_requester_commit' || r.host_id !== host ||
      !same(r.context, context(parent)) || !same(r.agent, parent.review.agent) || r.flow_id !== flow.flow_id ||
      r.join_review_id !== flow.review_id || !exact(r.network, 'id name context_id genesis_root_public_key') ||
      r.network.id !== request.network_id || r.network.context_id !== request.context_id || !publicLabel(r.network.name) ||
      !same(r.network, flow.review.invitation.network) || r.member !== flow.review.invitation.invitation.member ||
      !publicLabel(r.member) || r.member !== r.member.trim() ||
      !['request_id', 'person_public_key', 'host_public_key', 'device_public_key', 'request_packet_id', 'owner_offer_id',
        'selection_id', 'administrator_offer_id', 'owner_finalization_id', 'created_at', 'expires_at'].every(k => r[k] === request[k]) ||
      !['owner_offer_id', 'selection_id', 'owner_finalization_id'].every(k => id(r[k], 'dpk')) ||
      !['owner_root_state_id', 'root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id'].every(k => id(r[k], 'ds')) ||
      new Set([r.root_state_id, r.person_lease_id, r.host_lease_id, r.binding_lease_id, r.device_lease_id]).size !== 5 ||
      r.scopes !== 7 || r.binding_scopes !== 2 || typeof r.reused_binding !== 'boolean' ||
      !['not_after', 'created_at', 'expires_at', 'request_stage_deadline'].every(k => time(r[k])) ||
      Date.parse(r.request_stage_deadline) < Date.parse(r.created_at) + 600000 ||
      !same(r.effects, inspectionEffects)) fail();
  const p = r.owner_provider;
  if (!exact(p, 'kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after') ||
      !['original_person', 'device'].includes(p.kind) || p.person_public_key !== r.person_public_key ||
      !publicKey(p.host_public_key) || p.host_public_key === r.host_public_key || p.root_state_id !== r.owner_root_state_id ||
      !id(p.lease_id, 'ds') || !Number.isSafeInteger(p.scopes) || p.scopes < 7 || p.scopes > 15 || (p.scopes & 7) !== 7 ||
      !time(p.not_after) || (p.kind === 'device' ? !publicKey(p.device_public_key) || p.device_public_key === r.device_public_key
        : p.device_public_key !== '-') ||
      r.host_admission !== (r.administrator_offer_id === '-' ? 'folded_owner' : 'separate_administrator') ||
      r.host_admission === 'folded_owner' && !(p.scopes & 8) ||
      Date.parse(r.not_after) > Math.min(Date.parse(r.created_at) + 7 * 86400000, Date.parse(p.not_after)) ||
      Date.parse(r.not_after) <= Date.parse(r.created_at)) fail();
  await digest('peerspan-machine-requester-inspection-v1', r, wanted);
}
export async function inspection(raw, flow, parent, host, previous = null) {
  const v = decodePublic(raw, 2 << 20);
  if (!exact(v, 'version host_id context flow_id join_review_id observed_at request review_id review next_action') ||
      v.next_action !== 'review_machine_requester_consent' || !finalized(v.request)) fail();
  await base(v, flow, parent, host, previous);
  await review(v.review, v.review_id, v.request, flow, parent, host);
  if (Date.parse(v.observed_at) >= Math.min(...[v.request.expires_at, v.review.request_stage_deadline, v.review.not_after].map(Date.parse))) fail();
  return freeze(v);
}
export function applied(v) {
  return v?.consent?.state === 'approved' && v.request.state === 'linked' &&
    same(v.request.completed, [...prefix(v.request), 'commit_persisted', 'locally_applied']);
}
export async function snapshot(raw, flow, parent, host, previous = null) {
  const v = decodePublic(raw, 2 << 20);
  if (!exact(v, 'version host_id context flow_id join_review_id observed_at request consent')) fail();
  await base(v, flow, parent, host, previous);
  const c = v.consent, r = c?.review;
  if (c === null) {
    if (v.request.commit_approved || previous?.consent) fail();
    return freeze(v);
  }
  if (!exact(c, 'consent_id review_id review state next_action') || !id(c.consent_id, 'dint', 32) ||
      !exact(r, 'version kind consent_id host_id context agent flow_id join_review_id request_id intent_id inspection_review_id inspection created_at expires_at effects') ||
      r.version !== 1 || r.kind !== 'approve_existing_person_requester_commit' || r.consent_id !== c.consent_id ||
      r.host_id !== host || !same(r.context, context(parent)) || !same(r.agent, parent.review.agent) ||
      r.flow_id !== flow.flow_id || r.join_review_id !== flow.review_id || r.request_id !== v.request.request_id ||
      !id(r.intent_id, 'dint', 32) || r.intent_id === c.consent_id || !time(r.created_at) || !time(r.expires_at) ||
      Date.parse(r.created_at) < Date.parse(v.request.created_at) || Date.parse(v.observed_at) < Date.parse(r.created_at) ||
      Date.parse(r.expires_at) !== Math.min(Date.parse(r.created_at) + 900000, Date.parse(v.request.expires_at),
        Date.parse(r.inspection?.request_stage_deadline), Date.parse(r.inspection?.not_after)) ||
      Date.parse(r.expires_at) <= Date.parse(r.created_at) || !same(r.effects, consentEffects)) fail();
  await review(r.inspection, r.inspection_review_id, v.request, flow, parent, host);
  await digest('peerspan-machine-requester-consent-v1', r, c.review_id);
  const action = c.state === 'approved' ? 'follow_machine_link' : c.state === 'review' ? 'approve_machine_requester_commit'
    : ['expired', 'cancelled', 'invalidated'].includes(c.state) ? 'inspect_machine_link' : null;
  const stages = prefix(v.request), done = v.request.completed;
  if (!action || c.next_action !== action || c.state === 'approved' && !v.request.commit_approved ||
      !['approved', 'invalidated'].includes(c.state) && v.request.commit_approved ||
      !v.request.selection_approved || !same(done, [...stages, 'commit_persisted', 'locally_applied'].slice(0, done.length)) ||
      done.length < stages.length || !v.request.commit_approved && done.length !== stages.length ||
      done.length === stages.length && !['manifest_id', 'activation_id', 'outcome_id'].every(k => v.request[k] === '-') ||
      done.length === stages.length + 1 && v.request.outcome_id !== '-' ||
      v.request.state === 'needs_commit' && done.length !== stages.length ||
      v.request.state === 'finalizing' && done.length !== stages.length + 1 ||
      c.state === 'review' && (v.request.state !== 'needs_commit' || Date.parse(v.observed_at) >= Date.parse(r.expires_at)) ||
      previous?.consent && !sameConsent(previous, v)) fail();
  return freeze(v);
}
export function deadline(v, inspected = null) {
  if (applied(v)) return null;
  const c = v?.consent, i = c?.review.inspection ?? inspected?.review;
  if (!i || c && !['review', 'approved'].includes(c.state)) return null;
  return Math.min(Date.parse(i.expires_at), Date.parse(i.not_after),
    !v.request.completed.includes('commit_persisted') ? Date.parse(i.request_stage_deadline) : Infinity,
    c?.state === 'review' ? Date.parse(c.review.expires_at) : Infinity);
}
export function eligible(v, inspected, now, action) {
  const c = v?.consent, r = c?.review, i = r?.inspection ?? inspected?.review;
  if (!i || !Number.isFinite(now) || (action === 'prepare' ? c !== null || !inspected || !finalized(v.request)
    : action === 'approve' ? c?.state !== 'review' : c?.state !== 'approved' || applied(v) ||
      !['needs_commit', 'finalizing'].includes(v.request.state))) return false;
  const observed = Math.max(Date.parse(v.observed_at), Date.parse(inspected?.observed_at ?? v.observed_at));
  return now >= Date.parse(i.created_at) && now >= Date.parse(r?.created_at ?? i.created_at) && observed <= now + 30000 &&
    Math.max(now, observed) < deadline(v, inspected);
}
export async function result(raw, flow, parent, host, captured) {
  const v = decodePublic(raw, 2 << 20), m = v?.completion;
  if (!exact(v, 'version host_id context flow_id join_review_id observed_at request consent completion') ||
      !exact(m, 'state review_id manifest_id activation_id outcome_id participant_delivery agent_access connection_readiness') ||
      m.state !== 'locally_applied' || m.review_id !== captured.consent.review_id ||
      !['participant_delivery', 'agent_access', 'connection_readiness'].every(k => m[k] === 'not_verified') ||
      !['manifest_id', 'activation_id', 'outcome_id'].every(k => m[k] === v.request?.[k])) fail();
  const { completion, ...rest } = v;
  const checked = await snapshot(JSON.stringify(rest), flow, parent, host, captured);
  if (!applied(checked)) fail();
  return freeze(checked);
}
export function lines(v, inspected, parent, expired = false) {
  const c = v?.consent, r = c?.review, i = r?.inspection ?? inspected?.review;
  return [
    `Machine requester consent: ${c?.state === 'approved' ? 'recorded' : c?.state ?? 'none recorded'}`,
    ...(i ? [
      `Network: ${quoted(i.network.name)} (${i.network.id}); context: ${i.network.context_id}`,
      `Genesis root: ${i.network.genesis_root_public_key}; owner root: ${i.owner_root_state_id}; finalization root: ${i.root_state_id}`,
      `Request: ${i.request_id}; packet: ${i.request_packet_id}`, `Person: ${quoted(i.member)}; ${i.person_public_key}`,
      `Target host public key: ${i.host_public_key}; target device public key: ${i.device_public_key}`,
      `Remote provider: ${i.owner_provider.kind}; person/host/device: ${i.owner_provider.person_public_key} / ${i.owner_provider.host_public_key} / ${i.owner_provider.device_public_key}`,
      `Provider lease: ${i.owner_provider.lease_id}; root: ${i.owner_provider.root_state_id}; scopes: ${i.owner_provider.scopes}; deadline: ${i.owner_provider.not_after}`,
      `Person/host/binding/device leases: ${i.person_lease_id} / ${i.host_lease_id} / ${i.binding_lease_id} / ${i.device_lease_id}`,
      `Owner offer: ${i.owner_offer_id}; requester selection: ${i.selection_id}; owner finalization: ${i.owner_finalization_id}`,
      `Host admission: ${i.host_admission}; administrator packet: ${i.administrator_offer_id}; reused binding: ${i.reused_binding ? 'yes' : 'no'}`,
      'Machine powers: 7; binding scope: 2. Policy editing (1), host binding (2), eligible own-device approval/renewal/revocation (4). Network administrator (8): excluded.',
      `Powers end: ${i.not_after}; request window: ${i.created_at} to ${i.expires_at}; original stage deadline: ${i.request_stage_deadline}`,
      `Project: ${quoted(i.context.project_root)}; agent: ${quoted(i.agent.name)} (${i.agent.id}); owner label: ${quoted(i.agent.owner)}; capabilities: ${i.agent.capabilities.map(quoted).join(', ')}`,
      `Inspection review: ${r?.inspection_review_id ?? inspected.review_id}; inspection effects: ${canonical(i.effects)}`,
    ] : ['Waiting for verified existing-computer approval and finalization evidence. Check reads retained evidence only.']),
    ...(r ? [`Consent: ${c.consent_id}; review: ${c.review_id}; intent: ${r.intent_id}`,
      `Requester review window: ${r.created_at} to ${r.expires_at}; effects: ${canonical(r.effects)}`] : ['Preparation grants nothing.']),
    ...(v ? [`Observed at: ${v.observed_at}`] : []),
    ...(expired ? ['Machine requester action deadline elapsed or native clock is incompatible. Check retained evidence; no automatic retry.'] : []),
    'Original person key stays on the existing computer. Public authority does not probe private signer availability.',
    'Approve authorizes ordinary host/device signatures, commit publication and local application; authorized background work may progress independently.',
    'Complete is a separate bounded action. Leaving does not cancel/revoke consent or retract prior/dispatched signatures, publication or application.',
    ...(applied(v) ? ['Local application: recorded', `Manifest: ${v.request.manifest_id}; activation: ${v.request.activation_id}; outcome: ${v.request.outcome_id}`,
      'Global retained evidence; completing interface is not established. Historical application does not establish current powers.'] : ['Local application: not confirmed. Partial signatures or publication may already exist.']),
    'Participant delivery: not verified. Agent access: not verified. Connection readiness: not verified. Model receipt: not verified.',
    'Files shared: none. Conversation sharing: none. Capability calls: none. Check never prepares, approves, completes or retries.',
  ].join('\n');
}
