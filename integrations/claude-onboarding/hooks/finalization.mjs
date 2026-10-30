// Public original-finalization projections. Keys and signing stay in the CLI.
import { same, quoted } from './project.mjs';
import { context } from './adapter.mjs';
import { canonical, publicKey, freeze } from './invitation.mjs';
import { requestView } from './join-progress.mjs';
import { owner, sameOriginal, signatureDeadline } from './owner.mjs';
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, prefix) => typeof v === 'string' && new RegExp(`^${prefix}_[0-9a-f]{64}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const effects = { verify_original_owner: true, verify_requester_selection: true, verify_administrator_admission: true,
  verify_owner_finalization_bounds: true, prepare_finalization: false, sign_original: false, publish_finalization: false,
  commit_request: false, grant_membership: false, grant_agent_access: false, share_files: false,
  share_conversation: false, capability_calls: false };
export function samePrefix(a, b) {
  return sameOriginal(a, b) && ['owner_offer_id', 'selection_id', 'administrator_offer_id'].every(k => a.request[k] === b.request[k]);
}
export function recorded(v) {
  return v?.owner?.state === 'approved' && id(v.request.owner_finalization_id, 'dpk') && v.request.selection_approved &&
    ['owner_offer_id', 'selection_id', 'administrator_offer_id'].every(k => id(v.request[k], 'dpk')) &&
    v.request.completed.includes('owner_finalized') &&
    ['needs_commit', 'finalizing', 'linked', 'expired', 'cancelled', 'blocked'].includes(v.request.state);
}
export function eligible(v, now) {
  if (v?.owner?.state !== 'approved' || v.request.state !== 'needs_owner_finalization' ||
      !v.request.selection_approved || v.request.commit_approved ||
      !same(v.request.completed, ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered']) ||
      !['owner_offer_id', 'selection_id', 'administrator_offer_id'].every(k => id(v.request[k], 'dpk')) ||
      !['owner_finalization_id', 'manifest_id', 'activation_id', 'outcome_id'].every(k => v.request[k] === '-')) return false;
  const observed = Date.parse(v.observed_at), deadline = signatureDeadline(v);
  return Number.isFinite(now) && now >= Date.parse(v.request.created_at) && Math.max(now, observed) < deadline && observed <= now + 30000;
}
export async function inspection(raw, flow, parent, host, original) {
  const v = JSON.parse(raw), r = v?.review;
  if (!exact(v, 'version host_id flow_id join_review_id owner_review_id context observed_at request review_id review next_action') ||
      v.version !== 1 || v.host_id !== host || v.flow_id !== flow.flow_id || v.join_review_id !== flow.review_id ||
      v.owner_review_id !== original.owner?.review_id || !same(v.context, context(parent)) || !time(v.observed_at) ||
      Date.parse(v.observed_at) < Date.parse(original.observed_at) || !id(v.review_id, 'review') ||
      v.next_action !== 'review_original_finalization' || original.owner?.state !== 'approved') throw new Error('Unavailable original finalization');
  await requestView(v.request, flow, host);
  if (!Object.keys(original.request).filter(k => !['attention', 'next'].includes(k)).every(k => same(v.request[k], original.request[k])) ||
      !eligible({ ...original, observed_at: v.observed_at, request: v.request }, Date.parse(v.observed_at))) throw new Error('Changed finalization request');
  if (!exact(r, 'version kind host_id context flow_id join_review_id owner_review_id request_id intent_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id root_state_id person_lease_id host_lease_id administrator scopes binding_scopes not_after created_at expires_at effects') ||
      r.version !== 1 || r.kind !== 'inspect_new_original_finalization' || r.scopes !== 7 || r.binding_scopes !== 2 ||
      !same(r.effects, effects) || !['host_id', 'context', 'flow_id', 'join_review_id', 'owner_review_id'].every(k => same(r[k], v[k])) ||
      !['intent_id', 'network', 'member', 'person_public_key', 'host_public_key', 'device_public_key', 'not_after']
        .every(k => same(r[k], original.owner.review[k])) ||
      !['request_id', 'request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'created_at', 'expires_at']
        .every(k => r[k] === original.request[k]) ||
      !['root_state_id', 'person_lease_id', 'host_lease_id'].every(k => id(r[k], 'ds')) ||
      new Set([r.root_state_id, r.person_lease_id, r.host_lease_id]).size !== 3 ||
      !exact(r.administrator, 'signer_public_key host_public_key signature_format issuer_id') ||
      !publicKey(r.administrator.signer_public_key) || !publicKey(r.administrator.host_public_key) ||
      !['ed25519', 'sshsig'].includes(r.administrator.signature_format) || !id(r.administrator.issuer_id, 'ds') ||
      !['not_after', 'created_at', 'expires_at'].every(k => time(r[k]))) throw new Error('Changed finalization terms');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(
    'peerspan-original-finalization-inspection-v1\n' + canonical(r))));
  if (v.review_id !== 'review_' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')) throw new Error('Changed finalization digest');
  return freeze(v);
}
export async function result(raw, flow, parent, host, capturedOwner, capturedInspection) {
  const v = JSON.parse(raw), marker = v?.original_finalization;
  if (!exact(v, 'version host_id flow_id join_review_id context observed_at request owner original_finalization') ||
      !exact(marker, 'state review_id packet_id') || marker.state !== 'recorded' ||
      marker.review_id !== capturedInspection.review_id || !id(marker.packet_id, 'dpk')) throw new Error('Unavailable finalization evidence');
  const { original_finalization, ...snapshot } = v;
  const checked = await owner(JSON.stringify(snapshot), flow, parent, host);
  if (!recorded(checked) || !samePrefix(capturedOwner, checked) ||
      checked.request.owner_finalization_id !== marker.packet_id ||
      Date.parse(checked.observed_at) < Date.parse(capturedInspection.observed_at)) throw new Error('Changed finalization evidence');
  return checked;
}
export function reviewLines(v, parent) {
  const r = v.review;
  return ['Original finalization: review', `Observed at: ${v.observed_at}`, `Project: ${quoted(parent.review.project_root)}`,
    'Conversation: current conversation', `Network: ${quoted(r.network.name)}`, `Network ID: ${r.network.id}`,
    `Context ID: ${r.network.context_id}`, `Genesis root public key: ${quoted(r.network.genesis_root_public_key)}`,
    `Invitee label: ${quoted(r.member)}`, `Original person public key: ${quoted(r.person_public_key)}`,
    `Host public key: ${quoted(r.host_public_key)}`, `Device public key: ${quoted(r.device_public_key)}`,
    'Original consent: recorded for this exact person, machine and fixed powers.', `Original offer: ${r.owner_offer_id}`, `Requester selection: ${r.selection_id}`,
    `Administrator offer: ${r.administrator_offer_id}`, `Current root: ${r.root_state_id}`, `Person lease: ${r.person_lease_id}`,
    `Host lease: ${r.host_lease_id}`, `Administrator signer public key: ${quoted(r.administrator.signer_public_key)}`,
    `Administrator host public key: ${quoted(r.administrator.host_public_key)}`, `Administrator signature format: ${r.administrator.signature_format}`,
    `Administrator issuer: ${r.administrator.issuer_id}`, 'Machine powers: 7; binding scope: 2',
    'Policy editing (1); host binding (2); approval, renewal and revocation of eligible own devices (4). Network administrator (8): not approved.',
    `Powers end: ${r.not_after}`, `Request expires: ${r.expires_at}`,
    'Sign uses only this approved original on this computer: its safe existing generated key or exact SSH-agent identity.',
    'This creates, copies and imports no key. At most two ordered batches and three original signatures record binding, device and finalization evidence.',
    'Requester final commit: separate. Current adopted powers, agent access and connection readiness: not verified.',
    'Files shared: none. Conversation sharing: none. Capability calls: none. Reachability and model receipt: not verified.',
    'Leaving cannot retract already dispatched signatures or submissions. Check reads public evidence without signing or retrying.'].join('\n');
}
