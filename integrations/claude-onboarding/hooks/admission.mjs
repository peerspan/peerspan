// Closed public incoming evidence. Native effects remain in register.mjs.
import { same, bytes, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { observation } from './observation.mjs';
import { publicKey, publicLabel, freeze, canonical } from './invitation.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, p, n = 64) => typeof v === 'string' && new RegExp(`^${p}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const states = ['pending', 'needs_selection', 'needs_administrator', 'needs_owner_finalization', 'needs_commit',
  'finalizing', 'linked', 'migration_prepared', 'migration_adopted', 'cancelled', 'expired', 'blocked'];
const stages = ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered', 'owner_finalized', 'commit_persisted', 'locally_applied'];
const pins = ['request_id', 'network_id', 'context_id', 'person_public_key', 'host_public_key', 'device_public_key',
  'request_packet_id', 'created_at', 'expires_at'];
const privatePrefixes = ['psi2-', 'psl2-', 'token_', 'instance_', 'peerspan-invite-v1.',
  'peerspan-person-invite-v1.', 'peerspan-member-invite-v1.'];
function safe(v) {
  if (typeof v === 'string') {
    if (/[\u0000-\u001f\u007f-\u009f]/u.test(v)) return false;
    const plain = v.replace(/[\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/gu, '');
    return !privatePrefixes.some(p => v.includes(p) || plain.includes(p));
  }
  return !v || typeof v !== 'object' || Object.values(v).every(safe);
}
const strings = v => Array.isArray(v) && v.length <= 32 && v.every(s => typeof s === 'string' && bytes(s) > 0 && bytes(s) <= 1024 && safe(s));
export function sameRequest(a, b) { return pins.every(k => a[k] === b[k]); }
function request(r) {
  if (!exact(r, 'request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next') ||
      !id(r.request_id, 'link') || !['requester', 'approver'].includes(r.role) || !['new', 'renew'].includes(r.mode) ||
      !states.includes(r.state) || !(r.network_id === '-' || id(r.network_id, 'net')) ||
      !(r.context_id === '-' || id(r.context_id, 'ctx')) || !(r.migration_proposal_id === '-' || id(r.migration_proposal_id, 'ds')) ||
      !(r.person_public_key === '-' || publicKey(r.person_public_key)) || !publicKey(r.host_public_key) || !publicKey(r.device_public_key) ||
      !time(r.created_at) || !time(r.expires_at) || Date.parse(r.expires_at) <= Date.parse(r.created_at) ||
      !id(r.request_packet_id, 'dpk') || !['owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id', 'outcome_id']
        .every(k => r[k] === '-' || id(r[k], 'dpk')) || !(r.manifest_id === '-' || id(r.manifest_id, 'dm')) ||
      !(r.activation_id === '-' || id(r.activation_id, 'da')) || typeof r.selection_approved !== 'boolean' || typeof r.commit_approved !== 'boolean' ||
      !Array.isArray(r.completed) || r.completed[0] !== 'request_created' || r.completed.length > 7 ||
      !r.completed.every((s, i) => stages.includes(s) && (!i || stages.indexOf(r.completed[i - 1]) < stages.indexOf(s))) ||
      !strings(r.attention) || !strings(r.next) || !safe(r)) throw new Error('Unavailable incoming request');
  for (const [stage, field] of [['owner_offered', 'owner_offer_id'], ['owner_selected', 'selection_id'],
    ['administrator_offered', 'administrator_offer_id'], ['owner_finalized', 'owner_finalization_id']]) {
    if (r.completed.includes(stage) !== (r[field] !== '-')) throw new Error('Changed incoming stages');
  }
  if (r.completed.includes('commit_persisted') && r.manifest_id === '-' ||
      r.completed.includes('locally_applied') !== (r.state === 'linked') ||
      r.state === 'linked' && (!r.completed.includes('commit_persisted') || r.activation_id === '-' || r.outcome_id === '-')) {
    throw new Error('Changed incoming completion');
  }
  return r;
}
const incoming = r => r.role === 'approver' && r.mode === 'new' && r.migration_proposal_id === '-' &&
  id(r.network_id, 'net') && id(r.context_id, 'ctx') && publicKey(r.person_public_key);
export function inventory(raw, host) {
  observation(raw);
  const v = JSON.parse(raw);
  if (!id(host, 'host') || v.host_id !== host || v.requests.length > 4096 ||
      !time(v.observed_at) || !safe(v.requests)) throw new Error('Unavailable incoming inventory');
  v.requests.forEach(request);
  if (new Set(v.requests.map(r => r.request_id)).size !== v.requests.length) throw new Error('Ambiguous incoming inventory');
  return freeze(v.requests.filter(incoming).sort((a, b) => a.request_id.localeCompare(b.request_id)));
}
export function early(r) {
  return incoming(r) && ['pending', 'needs_selection', 'needs_administrator'].includes(r.state) &&
    !r.selection_approved && !r.commit_approved && ['administrator_offer_id', 'owner_finalization_id', 'manifest_id', 'activation_id', 'outcome_id'].every(k => r[k] === '-');
}
function envelope(v, keys, selected, parent, host) {
  if (!exact(v, keys) || v.version !== 1 || !id(host, 'host') || v.host_id !== host ||
      !same(v.context, context(parent)) || !time(v.observed_at) || !safe(v)) throw new Error('Unavailable incoming evidence');
  request(v.request);
  if (!incoming(v.request) || !sameRequest(v.request, selected)) throw new Error('Changed incoming request');
}
export function progress(raw, selected, parent, host) {
  const v = JSON.parse(raw), r = v?.request;
  envelope(v, 'version host_id context observed_at request next_action', selected, parent, host);
  const next = r.owner_offer_id === '-' ? 'wait_for_original_owner' : r.selection_id === '-' ? 'wait_for_requester_selection' : 'review_administrator_consent';
  if (!early(r) || v.next_action !== next || Date.parse(v.observed_at) < Date.parse(r.created_at) ||
      Date.parse(v.observed_at) >= Date.parse(r.expires_at)) throw new Error('Changed incoming progress');
  return freeze(v);
}
const inspectionEffects = { verify_request_signature: true, verify_original_owner_signature: true, verify_requester_selection: true,
  prepare_administrator_intent: false, approve_administrator_intent: false, sign_admission: false, grant_membership: false,
  grant_agent_access: false, commit_request: false, share_files: false, share_conversation: false, capability_calls: false };
const consentEffects = { approve_administrator_intent: true, authorize_network_root_signature: true, authorize_host_packet_signature: true,
  publish_administrator_offer_after_signatures: true, grant_membership: false, grant_agent_access: false,
  authorize_original_finalization: false, commit_request: false, share_files: false, share_conversation: false, capability_calls: false };
function common(r, v, parent, host) {
  const q = v.request;
  return r.version === 1 && r.host_id === host && same(r.context, v.context) && same(r.agent, parent.review.agent) &&
    exact(r.network, 'id name context_id genesis_root_public_key') && r.network.id === q.network_id && r.network.context_id === q.context_id &&
    publicLabel(r.network.name) && publicKey(r.network.genesis_root_public_key) && id(r.root_state_id, 'ds') &&
    r.request_id === q.request_id && r.request_packet_id === q.request_packet_id && r.owner_offer_id === q.owner_offer_id && id(r.owner_offer_id, 'dpk') &&
    r.selection_id === q.selection_id && id(r.selection_id, 'dpk') && publicLabel(r.member) && r.member === r.member.trim() &&
    r.person_public_key === q.person_public_key && r.host_public_key === q.host_public_key && r.device_public_key === q.device_public_key &&
    r.scopes === 7 && time(r.not_after) && Date.parse(r.not_after) === Date.parse(q.created_at) + 7 * 86400000;
}
async function digest(r, prefix, wanted) {
  if (!id(wanted, 'review')) throw new Error('Unavailable admission digest');
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(prefix + '\n' + canonical(r))));
  if (wanted !== 'review_' + Array.from(d, b => b.toString(16).padStart(2, '0')).join('')) throw new Error('Changed admission digest');
}
export async function inspection(raw, selected, parent, host) {
  const v = JSON.parse(raw), r = v?.review;
  envelope(v, 'version host_id context observed_at request review_id review next_action', selected, parent, host);
  if (!exact(r, 'version kind host_id context agent network root_state_id request_id request_packet_id owner_offer_id selection_id member person_public_key host_public_key device_public_key scopes not_after created_at expires_at effects') ||
      r.kind !== 'inspect_new_original_admission' || !common(r, v, parent, host) ||
      r.created_at !== v.request.created_at || r.expires_at !== v.request.expires_at ||
      !same(r.effects, inspectionEffects) || !early(v.request) || v.request.state !== 'needs_administrator' ||
      v.next_action !== 'review_administrator_consent') throw new Error('Changed admission inspection');
  await digest(r, 'peerspan-admission-inspection-v1', v.review_id);
  return freeze(v);
}
export async function consent(raw, selected, parent, host) {
  const v = JSON.parse(raw), a = v?.admission, r = a?.review;
  envelope(v, 'version host_id context observed_at request admission', selected, parent, host);
  if (a === null) return freeze(v);
  if (!exact(a, 'review_id review state next_action') ||
      !exact(r, 'version kind host_id context agent network request_id request_packet_id owner_offer_id selection_id intent_id root_state_id root_public_key person_lease_id host_lease_id member person_public_key host_public_key device_public_key scopes not_after request_created_at request_expires_at created_at expires_at effects') ||
      r.kind !== 'approve_new_original_admission' || !common(r, v, parent, host) || !id(r.intent_id, 'dint', 32) ||
      !publicKey(r.root_public_key) || !id(r.person_lease_id, 'ds') || !id(r.host_lease_id, 'ds') ||
      r.request_created_at !== v.request.created_at || r.request_expires_at !== v.request.expires_at ||
      !time(r.created_at) || !time(r.expires_at) || Date.parse(r.created_at) < Date.parse(r.request_created_at) ||
      Date.parse(r.expires_at) !== Math.min(Date.parse(r.request_expires_at), Date.parse(r.created_at) + 900000) ||
      Date.parse(r.expires_at) <= Date.parse(r.created_at) || !same(r.effects, consentEffects)) throw new Error('Changed administrator review');
  const next = a.state === 'approved' ? 'follow_link_progress' : a.state === 'review' ? 'approve_administrator_intent'
    : ['cancelled', 'expired', 'invalidated'].includes(a.state) ? 'inspect_link_progress' : null;
  if (!next || a.next_action !== next || a.state === 'review' && (!early(v.request) || v.request.state !== 'needs_administrator' ||
      Date.parse(v.observed_at) < Date.parse(r.created_at) || Date.parse(v.observed_at) >= Date.parse(r.expires_at))) throw new Error('Changed administrator state');
  await digest(r, 'peerspan-onboarding-original-admission-review-v1', a.review_id);
  return freeze(v);
}
export function matchesInspection(value, inspected) {
  const r = value.admission?.review, i = inspected.review;
  return r && ['network', 'root_state_id', 'member', 'person_public_key', 'host_public_key', 'device_public_key',
    'request_id', 'request_packet_id', 'owner_offer_id', 'selection_id', 'scopes', 'not_after'].every(k => same(r[k], i[k]));
}
export function choiceLabel(r, index) {
  return `Review incoming connection ${index + 1} — network ${r.network_id} — person ${quoted(r.person_public_key)} — host ${quoted(r.host_public_key)} — created ${r.created_at}`;
}
export function reviewLines(value, selected, parent, expired = false) {
  const a = value?.admission, r = a?.review, q = value?.request ?? selected;
  return ['Incoming connection: retained request snapshot', `Network ID: ${q.network_id}`, `Context ID: ${q.context_id}`,
    `Person public key: ${quoted(q.person_public_key)}`, `Host public key: ${quoted(q.host_public_key)}`, `Device public key: ${quoted(q.device_public_key)}`,
    `Request created: ${q.created_at}`, `Request expires: ${q.expires_at}`, `Observed request state: ${q.state}`,
    ...(r ? [`Administrator consent: ${a.state === 'approved' ? 'recorded' : expired && a.state === 'review' ? 'expired' : a.state}`,
      `Observed at: ${value.observed_at}`, `Project: ${quoted(parent.review.project_root)}`, 'Conversation: current conversation',
      `Agent: ${quoted(r.agent.name)}`, `Owner label: ${quoted(r.agent.owner)}`,
      `Capability metadata: ${r.agent.capabilities.length ? r.agent.capabilities.map(quoted).join(', ') : 'none'}`,
      `Network: ${quoted(r.network.name)}`, `Genesis root public key: ${quoted(r.network.genesis_root_public_key)}`,
      `Current root state: ${r.root_state_id}`, `Current root public key: ${quoted(r.root_public_key)}`,
      `Person lease dependency: ${r.person_lease_id}`, `Host lease dependency: ${r.host_lease_id}`, `Invitee label: ${quoted(r.member)}`,
      'Proposed machine powers: 7. Policy editing (1); host binding (2); eligible own-device approval, renewal and revocation (4).',
      'Network administrator powers (8): not granted', `Proposed powers end: ${r.not_after}`,
      `Administrator review created: ${r.created_at}`, `Administrator review expires: ${r.expires_at}`,
      'Approve the exact ordinary administrator intent; authorize current network-root and host-packet signatures.',
      'Publish the administrator offer after signatures. Approved ordinary background work may sign and publish without another frontend action.',
      'Original owner finalization: not authorized. Requester final commit: not approved.',
      ...(a.state === 'approved' ? ['The ordinary protocol records global consent; this record does not identify which interface approved or signed it.',
        'Later original finalization and requester commit remain separate. Use advanced link progress in this preview.'] : [])] : [
      'Administrator consent: no recorded review. Retained request claims need verification before consent.']),
    'Membership grants: none', 'Agent access grants: none', 'Files shared: none', 'Conversation sharing: none', 'Capability calls: none',
    'Leaving does not decline, cancel or revoke the request or recorded consent, and cannot retract an already dispatched action.',
    'Snapshot only. Current authority, admission, agent access, connection readiness and model receipt: not verified.'].join('\n');
}
