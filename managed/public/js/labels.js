// Words for the states, codes and kinds the API reports.

export const OPEN_STATES = ['submitting', 'queued', 'running'];

const RUN_STATES = {
  submitting: ['Submitting', 'warn'],
  queued: ['Queued', 'warn'],
  running: ['Running', 'info'],
  succeeded: ['Succeeded', 'ok'],
  failed: ['Failed', 'danger'],
  rejected: ['Rejected', 'danger'],
  expired: ['Expired', 'danger'],
  cancelled: ['Cancelled', ''],
  abandoned: ['Released', '']
};

/** `[label, tone]` for a run state; unknown states are shown as they are. */
export const runState = state => RUN_STATES[state] ?? [String(state), ''];

/** `[label, tone]` for a workflow, from the workflow and its newest run. */
export function workflowStatus(workflow, runs) {
  const open = runs.find(run => run.workflowId === workflow.id && OPEN_STATES.includes(run.state));
  if (open) {
    if (open.error) return ['Status uncertain', 'warn'];
    if (open.cancelRequestedAt) return ['Cancelling', 'warn'];
    return runState(open.state);
  }
  if (!workflow.enabled) return workflow.pausedBy === 'failures' ? ['Paused after failures', 'danger'] : ['Paused', ''];
  if (workflow.blockedReason === 'Waiting for next scheduled run' || !workflow.blockedReason) return ['Scheduled', 'ok'];
  if (workflow.blockedReason === 'Daily dispatch limit reached') return ['Daily limit reached', ''];
  return ['Waiting for worker', 'warn'];
}

export function schedule(workflow) {
  const minutes = workflow.intervalMinutes;
  const every = minutes % 1440 === 0 ? `${minutes / 1440} day${minutes === 1440 ? '' : 's'}`
    : minutes % 60 === 0 ? `${minutes / 60} hour${minutes === 60 ? '' : 's'}`
      : `${minutes} minute${minutes === 1 ? '' : 's'}`;
  return `Every ${every}`;
}

// The upstream status attention kinds, in the host's own words where they matter here.
const HINTS = {
  policy_expired: 'The access policy on this host has expired, so peers cannot send it new work.',
  credential_expiring: 'A session credential on this host expires soon.',
  tasks_failed: 'Outbound tasks from this host failed, were rejected or expired in the last 24 hours.',
  artifact_quota: 'Artifact storage on this host is almost full.',
  service_not_installed: 'The host daemon is not installed as a user service, so it will not restart on its own.',
  linger_disabled: 'User lingering is off, so the host service stops when you log out.',
  person_agent_unreachable: 'A policy signer for this network is unreachable.',
  person_device_signer_unavailable: 'The device signer for this person is unavailable.',
  network_authority_expired: 'Network authority has expired and needs repair.',
  network_proof_required: 'The network needs a fresh proof of authority.',
  network_state_conflict: 'The network state is in conflict and changes are frozen.',
  network_clock_rollback: 'The local clock went backwards past a retained guard.',
  network_migration_pending: 'A legacy network is kept as read-only history.',
  network_root_unreachable: 'The network root has been unreachable; grants will lapse unless it renews them.',
  link_request_waiting: 'A machine link request is waiting for a decision.',
  agent_name_conflict: 'Two agents of the same person share a name in one network.',
  channel_unverified: 'An attached session has not confirmed that it receives Peerspan channel events, so nothing is delivered to it.',
  capability_failing: 'A shared capability on this host is failing.',
  capability_name_conflict: 'Two shared capabilities use the same name.',
  policy_edit_unsettled: 'A policy edit has not settled yet.',
  policy_edit_dropped: 'A policy edit was dropped.',
  call_approval_pending: 'A capability call is waiting for approval.',
  conversation_invites: 'There are pending conversation invitations.',
  peer_delivery_failing: 'Deliveries to a peer host have been failing for a while.'
};

export const hintText = kind => HINTS[kind] ?? `The worker host reports: ${kind.replaceAll('_', ' ')}.`;

const READINESS_CODES = {
  worker_state_invalid: 'worker state file missing or invalid',
  identity_changed: 'identity changed',
  peerspan_unavailable: 'Peerspan executable unavailable',
  peerspan_incompatible: 'Peerspan executable too old',
  daemon_not_running: 'host daemon not running',
  status_invalid: 'host status unreadable',
  sender_unavailable: 'sender host not answering',
  sender_is_worker: 'sender and worker are the same host',
  agent_missing: 'agent no longer registered',
  session_not_ready: 'no ready session',
  channel_unverified: 'channel not verified'
};

/** One sentence for an activity entry; `names` resolves IDs to current names. */
export function activityText(entry, names) {
  const workflow = names.workflow(entry.workflowId);
  const connection = names.connection(entry.connectionId);
  switch (entry.kind) {
    case 'workflow.created': return `created ${workflow}`;
    case 'workflow.edited': return `edited ${workflow}` + (entry.data?.fields?.length ? ` (${entry.data.fields.join(', ')})` : '');
    case 'workflow.paused': return `paused ${workflow}`;
    case 'workflow.resumed': return `resumed ${workflow}`;
    case 'workflow.run_requested': return `asked ${workflow} to run now`;
    case 'workflow.archived': return `archived ${workflow}`;
    case 'workflow.restored': return `restored ${workflow}`;
    case 'workflow.auto_paused': return `paused ${workflow} after ${entry.data?.failureStreak ?? 3} consecutive failures`;
    case 'run.dispatched': return `dispatched a run of ${workflow}`;
    case 'run.finished': return `a run of ${workflow} ${runState(entry.data?.state)[0].toLowerCase()}`;
    case 'run.problem': return `lost track of a run of ${workflow}; keeping its task identity`;
    case 'run.recovered': return `regained contact with a run of ${workflow}`;
    case 'run.cancel_requested': return `asked to cancel a run of ${workflow}`;
    case 'run.abandoned': return `released a run of ${workflow}`;
    case 'connection.added': return `connected ${connection}`;
    case 'connection.removed': return `disconnected ${connection}`;
    case 'observation.added': return 'started following an external program';
    case 'observation.removed': return 'stopped following an external program';
    case 'worker.ready': return `${connection} became ready`;
    case 'worker.unready': {
      const why = READINESS_CODES[entry.data?.code];
      return `${connection} is not ready` + (why ? ` (${why})` : '');
    }
    default: return entry.kind;
  }
}
