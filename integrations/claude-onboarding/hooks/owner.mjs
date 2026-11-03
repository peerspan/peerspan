// Public owner consent/signature evidence. No keys, signing bytes or effects.
import { same, bytes, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { canonical, publicKey, freeze } from './invitation.mjs';
import { requestView } from './join-progress.mjs';
import { privateValue } from './observation.mjs';
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, prefix, n = 64) => typeof v === 'string' && new RegExp(`^${prefix}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const label = v => typeof v === 'string' && v.trim().length > 0 && bytes(v) <= 128 &&
  !/[\u0000-\u001f\u007f-\u009f]/u.test(v) && !privateValue(v);
const effects = { approve_owner_intent: true, authorize_original_signature: true, authorize_bounded_owner_finalization: true,
  auto_select_single_offer_after_signature: true, publish_owner_offer_after_signature: true, grant_membership: false,
  grant_agent_access: false, approve_network_administrator: false, commit_request: false, share_files: false,
  share_conversation: false, capability_calls: false };
const actions = { review: 'approve_owner_intent', cancelled: 'inspect_join_progress', expired: 'inspect_join_progress', invalidated: 'inspect_join_progress' };
export async function owner(raw, flow, parent, host) {
  const v = JSON.parse(raw), o = v?.owner, r = o?.review;
  if (!exact(v, 'version host_id flow_id join_review_id context observed_at request owner') ||
      v.version !== 1 || !id(host, 'host') || v.host_id !== host || flow.state !== 'requested' ||
      v.flow_id !== flow.flow_id || v.join_review_id !== flow.review_id || !same(v.context, context(parent)) ||
      !time(v.observed_at)) throw new Error('Unavailable owner consent');
  await requestView(v.request, flow, host);
  const request = v.request;
  if (Date.parse(v.observed_at) < Date.parse(request.created_at)) throw new Error('Changed owner observation');
  if (o === null) return freeze(v);
  if (!exact(o, 'review_id review state next_action') || !id(o.review_id, 'review') ||
      !exact(r, 'version kind host_id context flow_id join_review_id request_id intent_id network member person_public_key host_public_key device_public_key proposed_owner_offer_id scopes not_after expires_at effects') ||
      r.version !== 1 || r.kind !== 'approve_new_original_owner' || r.host_id !== host || !same(r.context, v.context) ||
      r.flow_id !== flow.flow_id || r.join_review_id !== flow.review_id || r.request_id !== request.request_id ||
      !id(r.intent_id, 'dint', 32) || !id(r.proposed_owner_offer_id, 'dpk') ||
      !exact(r.network, 'id name context_id genesis_root_public_key') || !same(r.network, flow.review.invitation.network) ||
      !id(r.network.id, 'net') || !id(r.network.context_id, 'ctx') || !label(r.network.name) || !publicKey(r.network.genesis_root_public_key) ||
      !label(r.member) || r.member !== flow.review.invitation.invitation.member ||
      r.person_public_key !== flow.outcome.person_public_key || r.host_public_key !== request.host_public_key ||
      r.device_public_key !== request.device_public_key || r.scopes !== 7 || !same(r.effects, effects) ||
      !time(r.not_after) || Date.parse(r.not_after) !== Date.parse(request.created_at) + 7 * 86400000 || !time(r.expires_at) ||
      Date.parse(r.expires_at) <= Date.parse(request.created_at) || Date.parse(r.expires_at) > Date.parse(request.expires_at) ||
      Date.parse(r.expires_at) > Date.parse(v.observed_at) + 900000 ||
      request.owner_offer_id !== '-' && request.owner_offer_id !== r.proposed_owner_offer_id) throw new Error('Changed owner terms');
  const expected = o.state === 'approved' ? request.owner_offer_id === '-' ? 'provide_original_signature' : 'follow_join_progress' : actions[o.state];
  if (!expected || o.next_action !== expected || o.state === 'review' &&
      (request.state !== 'pending' || request.owner_offer_id !== '-' || request.selection_approved || request.commit_approved ||
       Date.parse(v.observed_at) >= Date.parse(r.expires_at))) throw new Error('Changed owner consent state');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(
    'peerspan-onboarding-original-owner-review-v1\n' + canonical(r))));
  if (o.review_id !== 'review_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')) throw new Error('Changed owner digest');
  return freeze(v);
}
export function sameOriginal(a, b) {
  return same(a.owner?.review, b.owner?.review) && a.owner?.review_id === b.owner?.review_id &&
    ['request_id', 'network_id', 'context_id', 'person_public_key', 'host_public_key', 'device_public_key',
      'created_at', 'expires_at', 'request_packet_id'].every(k => a.request[k] === b.request[k]);
}
export function signatureDeadline(v) {
  return Math.min(Date.parse(v.request.expires_at), Date.parse(v.owner.review.not_after));
}
export function signable(v, now) {
  if (v?.owner?.state !== 'approved' || v.request.state !== 'pending' ||
      v.request.selection_approved || v.request.commit_approved || !same(v.request.completed, ['request_created']) ||
      !['owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id', 'manifest_id',
        'activation_id', 'outcome_id'].every(k => v.request[k] === '-')) return false;
  const deadline = signatureDeadline(v), observed = Date.parse(v.observed_at);
  return Number.isFinite(now) && now < deadline && observed < deadline && observed <= now + 30000;
}
export async function signature(raw, flow, parent, host, captured) {
  const v = JSON.parse(raw);
  if (!exact(v, 'version host_id flow_id join_review_id context observed_at request owner original_signature') ||
      !exact(v.original_signature, 'state') || v.original_signature.state !== 'recorded') throw new Error('Unavailable original signature evidence');
  const { original_signature, ...snapshot } = v;
  const checked = await owner(JSON.stringify(snapshot), flow, parent, host);
  if (checked.owner?.state !== 'approved' || !sameOriginal(captured, checked)) throw new Error('Changed original signature evidence');
  return freeze(v);
}
export function reviewLines(v, parent, expired = false, recorded = false) {
  const o = v.owner;
  if (!o) return 'Owner consent: no recorded owner review. Review owner powers explicitly to prepare one.';
  const r = o.review, state = expired && o.state === 'review' ? 'expired' : o.state;
  return [`Owner consent: ${state === 'approved' ? 'recorded' : state}`, `Observed at: ${v.observed_at}`,
    `Project: ${quoted(parent.review.project_root)}`, 'Conversation: current conversation',
    `Network: ${quoted(r.network.name)}`, `Network ID: ${r.network.id}`, `Context ID: ${r.network.context_id}`,
    `Genesis root public key: ${quoted(r.network.genesis_root_public_key)}`, `Invitee label: ${quoted(r.member)}`,
    `Original person public key: ${quoted(r.person_public_key)}`, `Host public key: ${quoted(r.host_public_key)}`,
    `Device public key: ${quoted(r.device_public_key)}`, 'Proposed machine powers: 7',
    'Policy editing (1); host binding (2); approval, renewal and revocation of eligible own devices (4).',
    'Network administrator (8): not approved', `Proposed powers end: ${r.not_after}`, `Owner review expires: ${r.expires_at}`,
    'Consent authorizes the exact original signature and bounded later self binding/device finalization under independently verified administrator parents.',
    'After original signature: publish the exact owner offer and select a single matching offer through the ordinary protocol.',
    'Membership grants: none', 'Agent access grants: none', 'Network administration: none', 'Requester final commit: none',
    'Files shared: none', 'Conversation sharing: none', 'Capability calls: none',
    `Observed request state: ${v.request.state}`,
    ...(state === 'approved' ? ['The ordinary protocol records approval; this record does not identify which interface approved it.',
      recorded || v.request.owner_offer_id !== '-'
        ? 'Original signature: recorded. This is durable protocol evidence; it does not identify which interface signed it.'
        : 'Original signature: not confirmed by this public snapshot. A partial signature may already be retained.',
      v.request.owner_offer_id !== '-'
        ? 'Owner offer recorded. Check join progress for the next participant.'
        : 'Owner offer: not confirmed. Signature evidence alone does not establish a completed offer.',
      'An explicit signing action uses only the approved original on this computer: its safe normal generated key or exact SSH-agent identity.',
      'This creates, copies and imports no key. It submits one exact original owner-offer signature; later administrator approval, original finalization and requester commit remain separate.',
      'Leaving cannot retract an already-dispatched signature. Check owner consent reads public evidence without signing or retrying.'] : []),
    'Leaving this review does not decline, cancel or revoke the request or any recorded consent.',
    'Snapshot only. Historical approval and a finite review window do not prove current powers.',
    'Current original key availability, admission, agent access, reachability and model receipt: not verified.'].join('\n');
}
