// Pure validation/presentation. Transport secrets never enter review text.
import { same, bytes, quoted } from './project.mjs';
import { privateValue } from './observation.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === keys.split(' ').sort().join(',');
const id = (v, kind, size = 32) => typeof v === 'string' && new RegExp(`^${kind}_[0-9a-f]{${size}}$`).test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(v) && Number.isFinite(Date.parse(v));
function freeze(v) {
  if (object(v) || Array.isArray(v)) { Object.values(v).forEach(freeze); Object.freeze(v); }
  return v;
}
export function context(parent) {
  return { project_flow_id: parent.flow_id, project_review_id: parent.review_id,
    project_root: parent.review.project_root, native_session_id: parent.review.native_session_id, integration: parent.review.integration };
}
export function connection(v, flow) {
  if (!exact(v, 'adapter_id session_id state recoverable lease_expires_at last_seen_at channel channel_verified_at protocol_version') ||
      v.adapter_id !== flow.review.adapter_id || v.session_id !== flow.review.session_id || typeof v.recoverable !== 'boolean' ||
      !['registered', 'ready', 'offline', 'detached', 'revoked', 'expired'].includes(v.state) ||
      !['lease_expires_at', 'last_seen_at', 'channel_verified_at'].every(k => v[k] === null || time(v[k])) ||
      !(v.protocol_version === null || (typeof v.protocol_version === 'string' && /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(v.protocol_version) && !privateValue(v.protocol_version))) ||
      (v.state === 'ready' ? !['unverified', 'verified'].includes(v.channel) || !time(v.lease_expires_at) ||
        (v.channel === 'verified' ? !time(v.channel_verified_at) : v.channel_verified_at !== null) : v.channel !== null)) {
    throw new Error('Unavailable adapter connection');
  }
  return freeze(v);
}
export function flow(v, parent, host) {
  if (!exact(v, 'version flow_id state review_id review authorization connection next_action') || v.version !== 1 ||
      !id(v.flow_id, 'flow') || !id(v.review_id, 'review', 64) || parent.state !== 'attached') throw new Error('Unavailable adapter review');
  const r = v.review;
  const c = context(parent);
  if (!exact(r, 'version kind flow_id host_id project_flow_id project_review_id project_root native_session_id integration agent session_id adapter_id expires_at credential_expires_at renewable effects') ||
      r.version !== 1 || r.kind !== 'authorize_adapter' || r.flow_id !== v.flow_id || r.host_id !== host ||
      !same(Object.fromEntries(Object.keys(c).map(k => [k, r[k]])), c) ||
      !same(r.agent, parent.review.agent) || r.session_id !== parent.review.session_id || !id(r.adapter_id, 'adapter') ||
      !time(r.expires_at) || !time(r.credential_expires_at) || r.renewable !== false ||
      Date.parse(r.credential_expires_at) - Date.parse(r.expires_at) !== 85_500_000 ||
      !same(r.effects, { issue_adapter_credential: true, receive_authorized_work: true, reply_to_authorized_work: true,
        handle_authorized_tasks: true, task_artifacts: true, register_agent: false, attach_session: false,
        grant_network_access: false, directory_access: false, outbound_routes: false, capability_calls: false,
        share_files: false, share_conversation: false })) throw new Error('Unavailable adapter review');
  const actions = { review: 'review', authorized: 'connect_adapter', declined: 'restart_review', expired: 'restart_review', invalidated: 'restart_review' };
  if (!Object.hasOwn(actions, v.state) || v.next_action !== actions[v.state] ||
      (v.authorization === null ? v.connection !== null || v.state === 'authorized' :
        !same(v.authorization, { adapter_id: r.adapter_id, session_id: r.session_id, agent_id: r.agent.id,
          expires_at: r.credential_expires_at, renewable: false }) || ['review', 'declined'].includes(v.state))) {
    throw new Error('Unavailable adapter outcome');
  }
  if ([r.project_root, r.native_session_id, r.agent.name, r.agent.owner, ...r.agent.capabilities].some(privateValue)) {
    throw new Error('Unavailable private adapter review');
  }
  if (v.connection !== null) connection(v.connection, v);
  return freeze(v);
}
export function lookup(raw, parent, host) {
  const v = JSON.parse(raw);
  if (!exact(v, 'version host_id context flow') || v.version !== 1 || v.host_id !== host || !same(v.context, context(parent))) {
    throw new Error('Unavailable adapter lookup');
  }
  if (v.flow !== null) flow(v.flow, parent, host);
  return freeze(v);
}
export function transport(raw, captured) {
  const v = JSON.parse(raw);
  if (!exact(v, 'version adapter_id session_id token instance_id adapter_socket') || v.version !== 1 ||
      v.adapter_id !== captured.review.adapter_id || v.session_id !== captured.review.session_id ||
      !id(v.token, 'token', 64) || !id(v.instance_id, 'instance', 64) || typeof v.adapter_socket !== 'string' ||
      !v.adapter_socket.startsWith('/') || !v.adapter_socket.endsWith('/adapter.sock') || bytes(v.adapter_socket) > 103 ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(v.adapter_socket) || v.adapter_socket.includes('//') ||
      v.adapter_socket.split('/').some(p => p === '.' || p === '..')) throw new Error('Unavailable private adapter transport');
  return freeze(v);
}
export function reviewLines(v) {
  const r = v.review;
  return [`Project: ${quoted(r.project_root)}`, 'Conversation: current conversation',
    `Agent: ${quoted(r.agent.name)}`, `Owner label: ${quoted(r.agent.owner)}`,
    `Capability metadata: ${r.agent.capabilities.length ? r.agent.capabilities.map(quoted).join(', ') : 'none'}`,
    `Review expires: ${r.expires_at}`, `Credential expires: ${r.credential_expires_at}`, 'Credential renewal: none',
    'Issue one credential for this existing local session',
    'Receive and reply to work already authorized for this agent',
    'Handle already authorized tasks and their task artifacts',
    'Existing authorized work may resume when delivery is connected',
    'New agents or sessions: none', 'Membership and access grants: none',
    'Directory access: none', 'Outbound destinations: none', 'Capability calls: none',
    'Automatic project file or conversation sharing: none',
    'Local harness permissions still govern actions and task-result files'].join('\n');
}
