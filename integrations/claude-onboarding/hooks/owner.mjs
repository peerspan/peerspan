// Exact public owner consent only. No signing, key inventory or native effects.
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
export function reviewLines(v, parent, expired = false) {
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
      o.next_action === 'provide_original_signature'
        ? 'Original signature: still required. Advanced linking is the next separate action in this preview.'
        : 'Owner offer recorded. Check join progress for the next participant.'] : []),
    'Leaving this review does not decline, cancel or revoke the request or any recorded consent.',
    'Snapshot only. Historical approval and a finite review window do not prove current powers.',
    'Original possession, admission, agent access, reachability and model receipt: not verified.'].join('\n');
}
