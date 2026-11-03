// Closed public projections only. Native effects stay in register.mjs.
import { same, quoted, validContext, bytes } from './project.mjs';
import { context } from './adapter.mjs';
import { publicKey, publicLabel, canonical, freeze } from './invitation.mjs';
import { decodePublic } from './access.mjs';
import { inventory, sameRequest } from './admission.mjs';

const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).sort().join(' ') === keys.split(' ').sort().join(' ');
const id = (v, kind, n = 64) => typeof v === 'string' && new RegExp(`^${kind}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v;
const fail = () => { throw new Error('Unavailable machine review'); };
const inspectEffects = { verify_request_signature: true, inspect_current_owner_authority: true,
  prepare_owner_intent: false, approve_owner_intent: false, sign_owner_offer: false, publish_owner_offer: false,
  grant_membership: false, grant_machine_powers: false, grant_agent_access: false, commit_request: false,
  share_files: false, share_conversation: false, capability_calls: false };
const consentEffects = fold => ({ approve_owner_intent: true, authorize_owner_offer_signature: true,
  publish_owner_offer_after_signatures: true, authorize_owner_finalization: true, authorize_binding_and_device_signatures: true,
  authorize_host_admission_if_folded: fold, grant_membership_now: false, grant_machine_powers_now: false,
  grant_agent_access: false, authorize_requester_selection: false, commit_request: false, share_files: false,
  share_conversation: false, capability_calls: false });
const notVerified = ['owner_offer_publication', 'host_admission', 'machine_powers', 'requester_selection',
  'request_commit', 'agent_access', 'connection_readiness'];
async function digest(domain, r, wanted) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain + '\n' + canonical(r))));
  if (wanted !== 'review_' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')) fail();
}
async function hostFor(key) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', out = [];
  let bits = 0, value = 0;
  for (const c of key.replace(/=+$/, '')) {
    value = value << 6 | alphabet.indexOf(c); bits += 6;
    if (bits >= 8) { bits -= 8; out.push(value >>> bits & 255); }
  }
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(out)));
  return 'host_' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
function validAgent(a) {
  return exact(a, 'id name owner capabilities') && id(a.id, 'agent', 32) && publicLabel(a.name) &&
    publicLabel(a.owner) && Array.isArray(a.capabilities) && a.capabilities.length <= 100 &&
    a.capabilities.every(c => typeof c === 'string' && c.trim().length > 0 && bytes(c) <= 256);
}
function validParent(c) {
  return exact(c, 'project_flow_id project_review_id project_root native_session_id integration') &&
    id(c.project_flow_id, 'flow', 32) && id(c.project_review_id, 'review') && validContext({ project_root: c.project_root, native_session_id: c.native_session_id, integration: c.integration });
}
export function pending(r) {
  return r.state === 'pending' && !r.selection_approved && !r.commit_approved &&
    same(r.completed, ['request_created']) && ['owner_offer_id', 'selection_id', 'administrator_offer_id',
      'owner_finalization_id', 'manifest_id', 'activation_id', 'outcome_id'].every(k => r[k] === '-');
}
async function inspection(r, wanted, request, host, expectedContext, agent) {
  if (!exact(r, 'version kind host_id context agent network root_state_id request_id request_packet_id person_public_key host_public_key device_public_key member person_lease_id local_host provider provider_id signature_format scopes not_after host_admission created_at expires_at effects') ||
      r.version !== 1 || r.kind !== 'inspect_existing_person_machine' || r.host_id !== host ||
      !same(r.context, expectedContext) || !same(r.agent, agent) || !validParent(r.context) || !validAgent(r.agent) ||
      !exact(r.network, 'id name context_id genesis_root_public_key') || r.network.id !== request.network_id ||
      r.network.context_id !== request.context_id || !publicLabel(r.network.name) || !publicKey(r.network.genesis_root_public_key) ||
      !id(r.root_state_id, 'ds') || !id(r.person_lease_id, 'ds') || !publicLabel(r.member) || r.member !== r.member.trim() ||
      !['request_id', 'request_packet_id', 'person_public_key', 'host_public_key', 'device_public_key', 'created_at', 'expires_at']
        .every(k => r[k] === request[k]) || r.scopes !== 7 || !time(r.not_after) || !same(r.effects, inspectEffects)) fail();
  const l = r.local_host, p = r.provider;
  if (!exact(l, 'host_public_key member person_public_key host_lease_id binding_lease_id device_lease_id not_after') ||
      !publicKey(l.host_public_key) || !publicLabel(l.member) || l.person_public_key !== r.person_public_key ||
      !id(l.host_lease_id, 'ds') || !id(l.binding_lease_id, 'ds') || !(l.device_lease_id === '-' || id(l.device_lease_id, 'ds')) ||
      !time(l.not_after) || l.host_public_key === r.host_public_key || await hostFor(l.host_public_key) !== host ||
      !exact(p, 'kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after') ||
      !['original_person', 'device'].includes(p.kind) || p.person_public_key !== r.person_public_key ||
      p.host_public_key !== l.host_public_key || p.root_state_id !== r.root_state_id || !id(p.lease_id, 'ds') ||
      !Number.isSafeInteger(p.scopes) || p.scopes < 7 || p.scopes > 15 || (p.scopes & 7) !== 7 || !time(p.not_after) ||
      (p.kind === 'device' ? !publicKey(p.device_public_key) || p.device_public_key === r.device_public_key ||
        p.lease_id !== l.device_lease_id || r.provider_id !== p.lease_id || r.signature_format !== 'ed25519'
        : p.device_public_key !== '-' || p.lease_id !== r.person_lease_id || r.provider_id !== r.person_public_key || r.signature_format !== 'sshsig') ||
      r.host_admission !== (p.scopes & 8 ? 'owner_may_fold' : 'separate_administrator_required') ||
      Date.parse(r.not_after) !== Math.min(Date.parse(r.created_at) + 7 * 86400000, Date.parse(p.not_after))) fail();
  await digest('peerspan-machine-owner-inspection-v1', r, wanted);
}
export function own(value, parent) {
  return !!value?.consent && same(value.consent.review.context, context(parent)) && same(value.consent.review.agent, parent.review.agent);
}
export function sameConsent(a, b) {
  return !!a?.consent && !!b?.consent && a.consent.consent_id === b.consent.consent_id &&
    a.consent.review_id === b.consent.review_id && same(a.consent.review, b.consent.review);
}
export function deadline(v) {
  const r = v?.consent?.review;
  return r ? Math.min(...[r.expires_at, r.request_stage_deadline, r.inspection.expires_at, r.inspection.not_after].map(Date.parse))
    : v?.inspection ? Math.min(Date.parse(v.inspection.review.expires_at), Date.parse(v.inspection.review.not_after)) : null;
}
export function live(v, now) {
  const end = deadline(v), start = v?.consent?.review.created_at ?? v?.inspection?.review.created_at;
  return Number.isFinite(now) && end !== null && pending(v.request) && now >= Date.parse(start) &&
    Date.parse(v.observed_at) >= Date.parse(start) && Date.parse(v.observed_at) <= now + 30000 &&
    Math.max(now, Date.parse(v.observed_at)) < end;
}
export async function snapshot(raw, selected, parent, host, previous = null, withSigning = false) {
  const v = decodePublic(raw, 2 << 20);
  if (!exact(v, 'version host_id context observed_at request inspection consent' + (withSigning ? ' signing' : '')) ||
      v.version !== 1 || v.host_id !== host || !same(v.context, context(parent)) || !time(v.observed_at) ||
      previous && Date.parse(v.observed_at) < Date.parse(previous.observed_at)) fail();
  const requests = inventory(JSON.stringify({ version: 1, host_id: host, observed_at: v.observed_at,
    networks: [], agents: [], requests: [v.request], attention: [] }), host);
  if (requests.length !== 1 || !sameRequest(v.request, selected)) fail();
  if (v.inspection !== null) {
    if (!exact(v.inspection, 'review_id review') || !pending(v.request)) fail();
    await inspection(v.inspection.review, v.inspection.review_id, v.request, host, context(parent), parent.review.agent);
    if (Date.parse(v.observed_at) < Date.parse(v.request.created_at) ||
        Date.parse(v.observed_at) >= Math.min(Date.parse(v.request.expires_at), Date.parse(v.inspection.review.not_after))) fail();
  }
  const c = v.consent, r = c?.review;
  if (c !== null) {
    if (!exact(c, 'consent_id review_id review state next_action') || !id(c.consent_id, 'dint', 32) ||
        !exact(r, 'version kind consent_id host_id context agent request_id request_packet_id inspection_review_id inspection intent_id proposed_owner_offer_id replaces_consent_id created_at expires_at request_stage_deadline effects') ||
        r.version !== 1 || r.kind !== 'approve_existing_person_machine' || r.consent_id !== c.consent_id || r.host_id !== host ||
        !validParent(r.context) || !validAgent(r.agent) || r.request_id !== selected.request_id ||
        r.request_packet_id !== selected.request_packet_id || !id(r.intent_id, 'dint', 32) || !id(r.proposed_owner_offer_id, 'dpk') ||
        !(r.replaces_consent_id === '-' || id(r.replaces_consent_id, 'dint', 32)) || r.replaces_consent_id === c.consent_id ||
        ![r.created_at, r.expires_at, r.request_stage_deadline].every(time) ||
        Date.parse(r.created_at) < Date.parse(selected.created_at) || Date.parse(r.expires_at) <= Date.parse(r.created_at) ||
        Date.parse(r.expires_at) > Math.min(Date.parse(r.created_at) + 300000, Date.parse(r.request_stage_deadline),
          Date.parse(selected.expires_at), Date.parse(r.inspection?.not_after)) ||
        !['review', 'approved', 'cancelled', 'expired', 'invalidated'].includes(c.state) ||
        c.next_action !== (c.state === 'review' ? 'approve_machine_owner_intent' : c.state === 'approved' ? 'follow_machine_link' : 'inspect_machine_link')) fail();
    await inspection(r.inspection, r.inspection_review_id, v.request, host, r.context, r.agent);
    if (!same(r.effects, consentEffects(r.inspection.host_admission === 'owner_may_fold'))) fail();
    await digest('peerspan-machine-owner-consent-v1', r, c.review_id);
    if (c.state === 'review' && own(v, parent) && (v.inspection === null || !same(v.inspection.review, r.inspection) ||
        v.inspection.review_id !== r.inspection_review_id || !live(v, Date.parse(v.observed_at)))) fail();
    if (previous?.consent && !sameConsent(v, previous)) fail();
  } else if (previous?.consent) fail();
  if (withSigning) {
    const s = v.signing;
    if (s !== null) {
      if (!c || c.state !== 'approved' || !own(v, parent) || !exact(s, 'state intent_id proposed_owner_offer_id signature_count required_signatures can_sign next_action ' + notVerified.join(' ')) ||
          s.intent_id !== r.intent_id || s.proposed_owner_offer_id !== r.proposed_owner_offer_id ||
          ![2, 3].includes(s.required_signatures) || s.required_signatures !== (r.inspection.host_admission === 'owner_may_fold' ? 3 : 2) ||
          !Number.isSafeInteger(s.signature_count) || s.signature_count < 0 || s.signature_count > s.required_signatures ||
          s.state !== (s.signature_count === 0 ? 'unsigned' : s.signature_count === s.required_signatures ? 'signed' : 'partial') ||
          typeof s.can_sign !== 'boolean' || s.state === 'signed' && s.can_sign ||
          s.can_sign && !live(v, Date.parse(v.observed_at)) ||
          s.next_action !== (s.state === 'signed' ? 'follow_machine_link' : s.can_sign ? 'sign_machine_owner_offer' : 'inspect_machine_link') ||
          notVerified.some(k => s[k] !== 'not_verified') || previous?.signing && s.signature_count < previous.signing.signature_count) fail();
    } else if (c?.state === 'approved' || previous?.signing) fail();
  }
  return freeze(v);
}
export function lines(v, selected, parent, expired = false) {
  const c = v?.consent, r = c?.review, i = r?.inspection ?? v?.inspection?.review;
  return [
    `Machine request: ${selected.request_id}`, `Review host: ${parent.review.host_id}`,
    'Inventory claims require host verification; public authority does not probe private signer availability.',
    ...(i ? [
      `Network: ${quoted(i.network.name)} (${i.network.id})`, `Context: ${i.network.context_id}`, `Root: ${i.root_state_id}`,
      `Genesis root public key: ${i.network.genesis_root_public_key}`, `Request packet: ${i.request_packet_id}`,
      `Person: ${quoted(i.member)} (${i.person_public_key})`, `Target host public key: ${i.host_public_key}`,
      `Target device public key: ${i.device_public_key}`, `Provider: ${i.provider.kind}; ${i.provider_id}; ${i.signature_format}`,
      `Provider person/host/device: ${i.provider.person_public_key} / ${i.provider.host_public_key} / ${i.provider.device_public_key}`,
      `Provider lease: ${i.provider.lease_id}; scopes: ${i.provider.scopes}; deadline: ${i.provider.not_after}`,
      `Local member: ${quoted(i.local_host.member)}; host: ${i.local_host.host_public_key}`,
      `Local person/host/binding/device leases: ${i.person_lease_id} / ${i.local_host.host_lease_id} / ${i.local_host.binding_lease_id} / ${i.local_host.device_lease_id}`,
      `Local membership deadline: ${i.local_host.not_after}`,
      'Proposed powers: 7 (1 policy editing, 2 host binding, 4 own-device approval/renewal/revocation). No administrator 8.',
      `Powers deadline: ${i.not_after}`, `Host admission: ${i.host_admission}`,
      `Request window: ${i.created_at} to ${i.expires_at}`,
      `Reviewed project: ${quoted(i.context.project_root)}; ${i.context.integration}`,
      `Reviewed agent: ${quoted(i.agent.name)} (${i.agent.id}); owner: ${quoted(i.agent.owner)}; capabilities: ${i.agent.capabilities.map(quoted).join(', ')}`,
      `Inspection effects: ${canonical(i.effects)}`,
    ] : ['Machine owner authority: unavailable. No consent inferred.']),
    ...(r ? [
      `Machine consent: ${c.state}; ${c.consent_id}; ${c.review_id}`, `Inspection review: ${r.inspection_review_id}`,
      `Owner intent: ${r.intent_id}; proposed offer: ${r.proposed_owner_offer_id}; replaces: ${r.replaces_consent_id}`,
      `Recorded project: ${quoted(r.context.project_root)}; ${r.context.integration}`,
      `Recorded agent: ${quoted(r.agent.name)} (${r.agent.id}); owner: ${quoted(r.agent.owner)}; capabilities: ${r.agent.capabilities.map(quoted).join(', ')}`,
      `Receipt window: ${r.created_at} to ${r.expires_at}; original stage deadline: ${r.request_stage_deadline}`,
      `Consent effects: ${canonical(r.effects)}`,
      own(v, parent) ? 'Exact recorded project consent. Signing attribution: not established.'
        : 'Historical consent belongs to another recorded project. View only; no approval or signing here.',
    ] : ['Machine consent: none. Preparation grants nothing.']),
    ...(v?.signing ? [`Initial owner signatures recorded: ${v.signing.signature_count}/${v.signing.required_signatures} (${v.signing.state}). Historical signature evidence only.`] : []),
    ...(expired ? ['Original machine action deadline elapsed. Check recorded evidence; no automatic retry.'] : []),
    'Approval authorizes ordinary signing/publication and bounded binding/device/finalization after requester selection; background work may proceed independently.',
    'Owner offer publication: not verified. Host admission: not verified. Machine powers: not verified.',
    'Requester selection: not verified. Request commit: not verified. Agent access: not verified. Connection readiness: not verified.',
    'No original key copying. Machine link completion requires later participant steps.',
  ].join('\n');
}
