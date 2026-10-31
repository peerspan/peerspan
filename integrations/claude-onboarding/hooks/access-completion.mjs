// Exact retained public evidence. Keys and policy verification stay in the host.
import { same, bytes, quoted } from './project.mjs';
import { freeze, canonical } from './invitation.mjs';
import { consent, deadline } from './access.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const proof = v => typeof v === 'string' && /^dp_[0-9a-f]{64}$/.test(v);
const states = ['unsigned', 'signed', 'locally_applied'];
export function sameConsent(a, b) {
  return a?.access?.state === 'approved' && b?.access?.state === 'approved' &&
    a.access.access_id === b.access.access_id && a.access.review_id === b.access.review_id && same(a.access.review, b.access.review);
}
export function eligible(v, now) {
  return v?.access?.state === 'approved' && Number.isFinite(now) && now >= Date.parse(v.access.review.created_at) &&
    Date.parse(v.observed_at) <= now + 30000 && Math.max(now, Date.parse(v.observed_at)) < deadline(v);
}
async function snapshot(raw, field, parent, host, network, selected, captured) {
  if (typeof raw !== 'string' || bytes(raw) > 1 << 20) throw new Error('Unavailable completion output');
  const v = JSON.parse(raw);
  if (!exact(v, 'version host_id context observed_at access ' + field)) throw new Error('Unavailable completion wrapper');
  const base = { version: v.version, host_id: v.host_id, context: v.context, observed_at: v.observed_at, access: v.access };
  const checked = await consent(JSON.stringify(base), parent, host, network, selected);
  if (!sameConsent(captured, checked) || Date.parse(checked.observed_at) < Date.parse(captured.observed_at)) throw new Error('Changed completion consent');
  return v;
}
export async function application(raw, parent, host, network, selected, captured, previous = null) {
  const v = await snapshot(raw, 'application', parent, host, network, selected, captured), a = v.application, r = v.access.review;
  if (!exact(a, 'state action_id intent_id statement_id proof_id peer_delivery connection_readiness') ||
      !states.includes(a.state) || a.action_id !== r.action_id || a.intent_id !== r.intent_id || a.statement_id !== r.statement.id ||
      (a.state === 'unsigned' ? a.proof_id !== '-' : !proof(a.proof_id)) ||
      a.peer_delivery !== 'not_verified' || a.connection_readiness !== 'not_verified') throw new Error('Unavailable application evidence');
  if (previous && (!sameConsent(previous, v) || states.indexOf(a.state) < states.indexOf(previous.application.state) ||
      previous.application.proof_id !== '-' && a.proof_id !== previous.application.proof_id ||
      Date.parse(v.observed_at) < Date.parse(previous.observed_at))) throw new Error('Regressed application evidence');
  return freeze(v);
}
export async function signed(raw, parent, host, network, selected, captured) {
  const v = await snapshot(raw, 'signing', parent, host, network, selected, captured), s = v.signing, r = v.access.review;
  if (!exact(s, 'state action_id intent_id statement_id signature_count required_signatures policy_application peer_delivery connection_readiness') ||
      s.state !== 'signed' || s.action_id !== r.action_id || s.intent_id !== r.intent_id || s.statement_id !== r.statement.id ||
      s.signature_count !== 1 || s.required_signatures !== 1 || s.policy_application !== 'not_verified' ||
      s.peer_delivery !== 'not_verified' || s.connection_readiness !== 'not_verified') throw new Error('Unavailable signature evidence');
  return freeze(v);
}
export function lines(v, parent) {
  const r = v.access.review, a = v.application;
  return ['Agent-access consent: recorded', `Observed at: ${v.observed_at}`,
    `Project: ${quoted(parent.review.project_root)}`, 'Conversation: current conversation',
    `Network: ${quoted(r.inspection.network.name)} (${r.inspection.network.id})`,
    `Context ID: ${r.inspection.network.context_id}`, `Current root at approval: ${r.inspection.root_state_id}`,
    `Selected person: ${quoted(r.inspection.participant.member)} ${quoted(r.inspection.participant.person_public_key)}`,
    `Agent: ${quoted(r.grant.agent_name)} (${r.grant.agent_id})`,
    'Policy scope: this exact agent name across the owner’s machines.',
    `Approved grant: ${quoted(canonical(r.grant))}`, `Provider: ${quoted(canonical(r.provider))}`,
    `Signed baseline body: ${r.inspection.policy ? quoted(canonical(r.inspection.policy.body)) : 'none retained'}`,
    `Enforced content at approval: ${r.inspection.policy ? quoted(canonical(r.inspection.policy.enforced_content)) : 'none retained'}`,
    `Exact approved policy: ${quoted(canonical(r.statement.payload))}`,
    `Review expires: ${r.expires_at}; policy ends: ${r.statement.payload.not_after}`,
    `Policy signature: ${a.state === 'unsigned' ? 'not recorded' : 'recorded'}`,
    `Local application: ${a.state === 'locally_applied' ? 'recorded' : 'not recorded'}`,
    `Policy statement: ${a.statement_id}`, ...(a.proof_id === '-' ? [] : [`Policy proof: ${a.proof_id}`]),
    'These are global retained facts; they do not identify which interface performed the work.',
    'Current permission, peer delivery, connection readiness and actual model receipt: not verified.',
    'Finish signs this exact approved policy with its selected provider and applies it locally; ordinary delivery may follow.',
    'Check application only reads evidence. Leaving does not revoke consent or retract prior or dispatched work.'].join('\n');
}
