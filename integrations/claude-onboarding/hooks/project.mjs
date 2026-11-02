// Private project data stays in the native UI; this module has no native effects.
import { safeName, privateValue } from './observation.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, kind, n = 32) => typeof v === 'string' && new RegExp(`^${kind}_[0-9a-f]{${n}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(v) && Number.isFinite(Date.parse(v));
export const same = (a, b) => canonical(a) === canonical(b);
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (object(v)) return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
export function bytes(v) {
  let n = 0;
  for (const ch of v) {
    const code = ch.codePointAt(0);
    if (code >= 0xd800 && code <= 0xdfff) return Infinity;
    n += code < 128 ? 1 : code < 2048 ? 2 : code < 65536 ? 3 : 4;
  }
  return n;
}
const text = (v, n) => typeof v === 'string' && v.trim().length > 0 && bytes(v) <= n;
function agent(v, full = false) {
  return exact(v, 'id name owner capabilities' + (full ? ' created_at' : '')) && id(v.id, 'agent') &&
    text(v.name, 128) && text(v.owner, 128) && Array.isArray(v.capabilities) && (full || v.capabilities.length <= 100) &&
    v.capabilities.every(c => text(c, 256)) && (!full || time(v.created_at));
}
export function validContext(v) {
  return exact(v, 'project_root native_session_id integration') && v.integration === 'claude-code' &&
    typeof v.project_root === 'string' && v.project_root.startsWith('/') && bytes(v.project_root) <= 4096 &&
    !/[\u0000-\u001f\u007f-\u009f]/u.test(v.project_root) && !v.project_root.includes('//') &&
    (v.project_root === '/' || !v.project_root.endsWith('/')) && !v.project_root.split('/').some(p => p === '.' || p === '..') &&
    text(v.native_session_id, 256) && !/[\s\u0000-\u001f\u007f-\u009f]/u.test(v.native_session_id);
}
function frozen(v) {
  if (object(v) || Array.isArray(v)) { Object.values(v).forEach(frozen); Object.freeze(v); }
  return v;
}
export function flow(v, context, host) {
  if (!exact(v, 'version flow_id state review_id review attachment next_action') || v.version !== 1 ||
      !id(v.flow_id, 'flow') || !id(v.review_id, 'review', 64)) throw new Error('Unavailable project review');
  const r = v.review;
  if (!exact(r, 'version kind flow_id host_id project_root native_session_id integration create_agent agent session_id expires_at effects') ||
      r.version !== 1 || r.kind !== 'attach_project' || r.flow_id !== v.flow_id || r.host_id !== host ||
      !id(host, 'host', 64) || !same({ project_root: r.project_root, native_session_id: r.native_session_id, integration: r.integration }, context) ||
      !agent(r.agent) || typeof r.create_agent !== 'boolean' || !id(r.session_id, 'session') || !time(r.expires_at) ||
      !same(r.effects, { register_agent: r.create_agent, attach_session: true, issue_adapter_credential: false,
        grant_network_access: false, share_files: false, share_conversation: false, capability_calls: false }) ||
      (r.create_agent && r.agent.capabilities.length !== 0)) throw new Error('Unavailable project review');
  const actions = { review: 'review', attached: 'continue_adapter_setup', declined: 'restart_review', expired: 'restart_review', invalidated: 'restart_review' };
  if (!Object.hasOwn(actions, v.state) || v.next_action !== actions[v.state] ||
      (v.attachment !== null && !same(v.attachment, { agent_id: r.agent.id, session_id: r.session_id })) ||
      (v.state === 'attached' && v.attachment === null) ||
      (['review', 'declined', 'expired'].includes(v.state) && v.attachment !== null)) throw new Error('Unavailable project review');
  if ([r.project_root, r.native_session_id, r.agent.name, r.agent.owner, ...r.agent.capabilities].some(privateValue)) {
    throw new Error('Unavailable private project review');
  }
  return frozen(v);
}
export function lookup(raw, context, host) {
  const v = JSON.parse(raw);
  if (!exact(v, 'version host_id context flow agents') || v.version !== 1 || v.host_id !== host || !id(v.host_id, 'host', 64) ||
      !validContext(v.context) || !same(v.context, context) || !Array.isArray(v.agents) ||
      !v.agents.every(a => agent(a, true)) || new Set(v.agents.map(a => a.id)).size !== v.agents.length) {
    throw new Error('Unavailable project lookup');
  }
  if (v.flow !== null) flow(v.flow, context, host);
  return frozen(v);
}
export function defaultName(root) {
  const name = root.split('/').at(-1).trim();
  return name && bytes(name) <= 128 && name !== '*' ? name : 'project-agent';
}
export function quoted(value) {
  return JSON.stringify(value).replace(/[\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/gu,
    c => '\\u' + c.codePointAt(0).toString(16).padStart(4, '0'));
}
export const choiceLabel = a => `Review agent ${quoted(safeName(a.name))} — owner ${quoted(safeName(a.owner))}`;
export function reviewLines(v) {
  const r = v.review;
  return [
    `Project: ${quoted(r.project_root)}`, 'Conversation: current conversation',
    `Agent: ${quoted(r.agent.name)}`, `Owner label: ${quoted(r.agent.owner)}`,
    `Agent record: ${r.create_agent ? 'new' : 'existing'}`,
    `Capability metadata: ${r.agent.capabilities.length ? r.agent.capabilities.map(quoted).join(', ') : 'none'}`,
    `Review expires: ${r.expires_at}`, 'Record this local session attachment',
    ...(r.create_agent ? ['Register a local agent'] : []),
    'Adapter credentials: none', 'Network access: none', 'File sharing: none',
    'Conversation sharing: none', 'Capability calls: none',
  ].join('\n');
}
