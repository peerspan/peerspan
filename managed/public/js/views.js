// Console views. Each takes the app context and returns the nodes of one page.
import { absoluteTime, commandLine, copyable, duration, h, icon, secondsBetween, shortId, timeAgo } from './dom.js';
import { OPEN_STATES, activityText, hintText, runState, schedule, workflowStatus } from './labels.js';

const CLI = 'node managed/cli.mjs';

const badge = ([label, tone], live = false) => h('span.badge', { class: [tone, live && 'live'].filter(Boolean).join(' ') }, label);
const isOpen = run => OPEN_STATES.includes(run.state);
const percent = rate => (rate === null ? '—' : `${Math.round(rate * 100)}%`);
const plural = (count, word, many = word + 's') => `${count} ${count === 1 ? word : many}`;

function section(title, body, { note, more } = {}) {
  return h('section.section', null,
    h('div.section-head', null,
      h('h2', null, title),
      note && h('span.section-note', null, note),
      more && h('a.more', { href: more.href }, more.label)),
    body);
}

function empty(title, text, extra) {
  return h('div.panel.empty', null, h('strong', null, title), text && h('p', null, text), extra);
}

function button(label, { iconName, onclick, key, kind = '', disabled = false, title } = {}) {
  return h('button.button', { class: kind, type: 'button', onclick, disabled, title, 'data-key': key },
    iconName && icon(iconName), label);
}

// ----- shared pieces --------------------------------------------------------------------

function attentionList(ctx) {
  const { attention } = ctx.data;
  if (!attention.length) {
    return h('p.all-clear', null, icon('check'), 'Nothing needs your attention.');
  }
  const target = item => {
    if (item.subject.type === 'workflow') return `#/workflows/${item.subject.id}`;
    if (item.subject.type === 'run') return `#/runs/${item.subject.id}`;
    if (item.subject.type === 'connection') return '#/workers';
    return null;
  };
  return h('ul.attention', null, attention.map(item => {
    const href = target(item);
    return h('li.attention-item', { class: item.severity },
      icon(item.severity === 'info' ? 'info' : 'alert'),
      h('div.attention-body', null,
        h('strong', null, item.subject.type === 'controller' ? 'Controller' : item.subject.name), ' ',
        h('span', null, item.message), ' ',
        item.since && h('span', null, '· ', timeAgo(item.since))),
      href && h('a.button.small', { href }, 'View'));
  }));
}

function runStrip(workflow) {
  const recent = [...workflow.recent].reverse();
  if (!recent.length) return h('div.strip', null, h('span.strip-label', null, 'No runs yet'));
  return h('div.strip', { 'aria-label': 'Latest runs, oldest first' },
    recent.map(run => h('a', {
      class: run.state,
      href: `#/runs/${run.id}`,
      title: `${runState(run.state)[0]} · ${absoluteTime(run.createdAt)}`,
      'aria-label': `${runState(run.state)[0]} run from ${absoluteTime(run.createdAt)}`
    })),
    h('span.strip-label', null, `last ${plural(recent.length, 'run')}`));
}

function nextLine(workflow, openRun) {
  if (openRun) return ['Assignment in progress since ', timeAgo(openRun.createdAt)];
  if (!workflow.enabled) return [workflow.blockedReason || 'Paused'];
  if (!workflow.blockedReason || workflow.blockedReason === 'Waiting for next scheduled run') {
    return Date.parse(workflow.nextRunAt) <= Date.now() ? ['Due now'] : ['Next run ', timeAgo(workflow.nextRunAt)];
  }
  return [workflow.blockedReason];
}

function workflowActions(ctx, workflow, openRun) {
  const act = action => () => ctx.actions.workflow(workflow.id, action);
  return [
    workflow.enabled
      ? button('Pause', { iconName: 'pause', kind: 'small', onclick: act('pause'), key: `wf:${workflow.id}:toggle` })
      : button('Resume', { iconName: 'play', kind: 'small', onclick: act('resume'), key: `wf:${workflow.id}:toggle` }),
    button('Run now', {
      iconName: 'zap',
      kind: 'small',
      onclick: act('run'),
      key: `wf:${workflow.id}:run`,
      disabled: !workflow.enabled || Boolean(openRun),
      title: !workflow.enabled ? 'Resume the workflow first' : openRun ? 'A run is already in progress' : 'Make the next run due now'
    })
  ];
}

function workflowCard(ctx, workflow) {
  const { runs, connections } = ctx.data;
  const openRun = runs.find(run => run.workflowId === workflow.id && isOpen(run));
  const worker = connections.find(connection => connection.id === workflow.connectionId);
  const status = workflowStatus(workflow, runs);
  return h('article.panel.card', null,
    h('div.card-main', null,
      h('div.card-top', null,
        h('a.card-title', { href: `#/workflows/${workflow.id}` }, workflow.name),
        badge(status, Boolean(openRun) && openRun.state === 'running')),
      h('p.card-meta', null,
        `${worker ? worker.name : 'No worker'} · ${schedule(workflow)} · up to ${plural(workflow.maxRunsPerDay, 'run')} a day`),
      runStrip(workflow),
      openRun?.progress && h('p.card-line', null, h('span', null, 'Now:'), h('span.progress', null, openRun.progress))),
    h('div.card-foot', null,
      h('span.next', null, nextLine(workflow, openRun)),
      h('div.card-actions', null, workflowActions(ctx, workflow, openRun))));
}

function observedCard(source) {
  const tone = !source.available ? 'danger' : source.error ? 'warn' : source.enabled ? 'info' : '';
  const facts = [];
  if (source.available) {
    facts.push(`Batch ${source.cycle || '—'}`);
    if (source.lastBatch?.key) facts.push(`last complete ${source.lastBatch.key}${source.lastBatch.status ? ` (${source.lastBatch.status})` : ''}`);
  }
  return h('article.panel.card.observed', null,
    h('div.card-main', null,
      h('div.card-top', null,
        h('span.card-title', null, source.name),
        badge([source.phase, tone])),
      h('p.card-meta', null, 'External program · read only'),
      source.task?.lane && h('p.card-line', null, h('span.progress', { title: source.task.lane }, source.task.lane)),
      facts.length > 0 && h('p.card-meta', null, facts.join(' · '))),
    h('div.card-foot', null,
      h('span.next', null, source.error ?? ['Heartbeat ', timeAgo(source.lastTickAt), ' · run by its own controller'])));
}

/** One run in a list. Inside a workflow's own history the workflow name is left out. */
function runRow(run, { named = true } = {}) {
  const seconds = secondsBetween(run.createdAt, run.finishedAt);
  const summary = run.error ?? run.progress ?? run.reason ?? run.output?.split('\n', 1)[0]
    ?? (isOpen(run) ? 'No result yet' : 'No output reported');
  return h('a.row', { href: `#/runs/${run.id}` },
    h('span.row-state', null, badge(runState(run.state), run.state === 'running')),
    h('div.row-main', null,
      named ? [h('div.row-title', null, run.workflowName), h('div.row-sub', null, summary)] : h('div.row-title.plain', null, summary)),
    h('div.row-side', null, timeAgo(run.createdAt), seconds !== null && ` · ${duration(seconds)}`));
}

function nameResolver(ctx) {
  const workflows = new Map([...ctx.data.workflows, ...ctx.data.archived].map(item => [item.id, item.name]));
  const connections = new Map(ctx.data.connections.map(item => [item.id, item.name]));
  return {
    workflow: id => (workflows.has(id) ? `“${workflows.get(id)}”` : 'a workflow'),
    connection: id => (connections.has(id) ? connections.get(id) : 'a worker')
  };
}

function activityRow(ctx, entry, names) {
  const what = [activityText(entry, names)];
  if (entry.runId) what.push(' ', h('a', { href: `#/runs/${entry.runId}` }, 'view run'));
  return h('div.activity-row', null,
    h('span.who', { class: entry.actor }, entry.actor === 'operator' ? 'You' : 'Controller'),
    h('span.what', null, what),
    timeAgo(entry.at));
}

function connectHelp() {
  return h('div.panel.pad', null,
    h('p', null, 'Workers are registered from a terminal on this machine, never from the browser. Name the agent as ',
      h('code', null, 'peerspan agents'), ' shows it, or pass its agent ID:'),
    h('div.dialog-body', null,
      commandLine(`${CLI} connect --name "Repository maintainer" --agent AGENT`),
      h('p.help', null, 'Add ', h('code', null, '--host-state DIR'), ' when the worker host does not use the default Peerspan state, and ',
        h('code', null, '--sender-state DIR'), ' when tasks are submitted from a host other than the default. Sender and worker must be two Peerspan hosts: a host cannot send tasks to itself. Check the setup with ',
        h('code', null, `${CLI} doctor`), '.')));
}

// ----- pages ------------------------------------------------------------------------------

export function overview(ctx) {
  const { workflows, connections, observed, runs, activity } = ctx.data;
  const names = nameResolver(ctx);
  const enabled = workflows.filter(workflow => workflow.enabled).length;
  const ready = connections.filter(connection => connection.readiness.ready).length;
  const sum = key => workflows.reduce((total, workflow) => total + workflow.stats[key], 0);
  const judged = sum('succeeded') + sum('failed');

  const tiles = h('div.tiles', null,
    tile('Workflows', enabled, 'active', `${workflows.length - enabled} paused`),
    tile('Workers ready', ready, `of ${connections.length}`, connections.length ? 'Live channel checks' : 'None connected yet'),
    tile('Runs, last 7 days', sum('runs'), null, judged ? `${percent(sum('succeeded') / judged)} succeeded` : 'No finished runs yet'),
    tile('Unattended runs', sum('unattendedRuns'), null, `${plural(sum('interventions'), 'operator action')} in 7 days`));

  const workflowList = workflows.length
    ? h('div.cards', null, workflows.map(workflow => workflowCard(ctx, workflow)))
    : connections.length
      ? empty('Create your first recurring assignment',
        'Pick a worker, describe a bounded assignment, and set how often it may run.',
        h('p.empty-action', null, button('New workflow', { iconName: 'plus', kind: 'primary', onclick: ctx.actions.newWorkflow })))
      : empty('Connect a worker to begin', 'A worker is an agent session that is already attached to Peerspan on this machine.',
        h('p.empty-action', null, h('a.button.primary', { href: '#/workers' }, 'How to connect a worker')));

  return [
    pageHead('Overview', 'Keep recurring work moving, and see what needs you.',
      button('New workflow', { iconName: 'plus', kind: 'primary', onclick: ctx.actions.newWorkflow, disabled: !connections.length,
        title: connections.length ? null : 'Connect a worker first' })),
    attentionList(ctx),
    h('div.section', null, tiles),
    section('Workflows', workflowList, { more: workflows.length ? { href: '#/workflows', label: 'All workflows' } : null }),
    observed.length > 0 && section('Followed programs', h('div.cards', null, observed.map(observedCard)),
      { note: 'Read only. Each keeps its own controller and history.' }),
    h('div.section.two-col', null,
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Latest runs'), h('a.more', { href: '#/runs' }, 'Run history')),
        runs.length ? h('div.panel.rows', null, runs.slice(0, 8).map(run => runRow(run)))
          : empty('No runs yet', 'Runs dispatched from this console appear here with their actual results.')),
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Activity'), h('a.more', { href: '#/activity' }, 'Full log')),
        activity.length ? h('div.panel.rows', null, activity.slice(0, 8).map(entry => activityRow(ctx, entry, names)))
          : empty('Nothing has happened yet', 'Operator actions and controller events are recorded here.')))
  ];
}

function tile(label, value, unit, detail) {
  return h('div.panel.tile', null,
    h('div.label', null, label),
    h('div.value', null, String(value), unit && [' ', h('small', null, unit)]),
    h('div.detail', null, detail));
}

function pageHead(title, sub, actions, crumbs) {
  return h('header.page-head', null,
    h('div', null, crumbs && h('p.crumbs', null, crumbs), h('h1', null, title), sub && h('p.sub', null, sub)),
    actions && h('div.head-actions', null, actions));
}

export function workflowsPage(ctx) {
  const { workflows, archived, connections } = ctx.data;
  return [
    pageHead('Workflows', 'Recurring assignments this console dispatches and follows.',
      button('New workflow', { iconName: 'plus', kind: 'primary', onclick: ctx.actions.newWorkflow, disabled: !connections.length })),
    workflows.length ? h('div.cards', null, workflows.map(workflow => workflowCard(ctx, workflow)))
      : empty('No workflows yet', connections.length ? 'Create one to start dispatching recurring work.' : 'Connect a worker first, then create a workflow.'),
    archived.length > 0 && section('Archived', h('div.panel.rows', null, archived.map(item =>
      h('div.row', null,
        h('div.row-main', null,
          h('a.row-title', { href: `#/workflows/${item.id}` }, item.name),
          h('div.row-sub', null, 'Archived ', timeAgo(item.archivedAt))),
        button('Restore', { kind: 'small', onclick: () => ctx.actions.workflow(item.id, 'restore'), key: `wf:${item.id}:restore` })))),
    { note: 'Archived workflows never dispatch. Their runs stay in the history.' })
  ];
}

function historyPanel(ctx, { named = true } = {}) {
  const { history } = ctx;
  if (!history.loaded) return h('div.panel.empty', null, 'Loading runs…');
  if (!history.runs.length) return empty('No runs yet', 'Runs appear here as soon as the workflow dispatches.');
  return h('div.panel', null,
    h('div.rows', null, history.runs.map(run => runRow(run, { named }))),
    history.nextBefore && h('div.pager', null, button('Load older runs', { onclick: ctx.actions.moreRuns, key: 'runs:more' })));
}

export function workflowPage(ctx, id) {
  const { workflows, archived, runs, connections } = ctx.data;
  const crumbs = [h('a', { href: '#/workflows' }, 'Workflows'), ' / '];
  const archivedItem = archived.find(item => item.id === id);
  if (archivedItem) {
    return [
      pageHead(archivedItem.name, ['Archived ', timeAgo(archivedItem.archivedAt), '. It never dispatches; its runs are kept.'],
        button('Restore', { onclick: () => ctx.actions.workflow(id, 'restore'), key: `wf:${id}:restore` }), crumbs),
      section('Run history', historyPanel(ctx, { named: false }))
    ];
  }
  const workflow = workflows.find(item => item.id === id);
  if (!workflow) return [pageHead('Workflow not found', 'It may belong to another state directory.', null, crumbs)];

  const openRun = runs.find(run => run.workflowId === id && isOpen(run));
  const worker = connections.find(connection => connection.id === workflow.connectionId);
  const { stats } = workflow;
  const status = workflowStatus(workflow, runs);
  return [
    pageHead([workflow.name, ' ', badge(status, openRun?.state === 'running')], null, [
      ...workflowActions(ctx, workflow, openRun),
      button('Edit', { iconName: 'edit', kind: 'small', onclick: () => ctx.actions.editWorkflow(workflow), key: `wf:${id}:edit` }),
      button('Archive', { iconName: 'archive', kind: 'small', onclick: () => ctx.actions.archiveWorkflow(workflow), key: `wf:${id}:archive`,
        disabled: Boolean(openRun), title: openRun ? 'Wait for the run in progress, cancel it or release it first' : null })
    ], crumbs),
    workflow.pausedBy === 'failures' && h('div.callout.danger', null, icon('alert'),
      'Paused after three consecutive failed runs. Review the latest results below, then resume.'),
    h('div.section.stats', null,
      tile('Success rate, 7 days', percent(stats.successRate), null, `${stats.succeeded} succeeded · ${stats.failed} failed`),
      tile('Runs, 7 days', stats.runs, null, `Limit ${workflow.maxRunsPerDay} a day`),
      tile('Average duration', duration(stats.averageSeconds), null, 'Succeeded runs, 7 days'),
      tile('Operator actions', stats.interventions, null, 'In the last 7 days'),
      tile('Unattended runs', stats.unattendedRuns, null, 'Since you last stepped in')),
    h('div.section.two-col', null,
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Run history')),
        historyPanel(ctx, { named: false })),
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Assignment')),
        h('div.panel.pad', null, h('p.prose', null, workflow.instructions)),
        h('div.section-head.section', null, h('h2', null, 'Schedule')),
        h('div.panel.pad', null, h('dl.facts', null,
          fact('Worker', worker ? h('a', { href: '#/workers' }, worker.name) : 'Not connected'),
          fact('Repeats', schedule(workflow) + ', counted from the end of the previous run'),
          fact('Daily limit', `${plural(workflow.maxRunsPerDay, 'dispatch', 'dispatches')} per UTC day`),
          fact('Acceptance window', `${plural(workflow.acceptanceMinutes, 'minute')} for the worker to accept`),
          fact('Next run', nextLine(workflow, openRun)),
          fact('Failure streak', `${workflow.failureStreak} of 3`),
          fact('Created', timeAgo(workflow.createdAt)),
          fact('Changed', timeAgo(workflow.updatedAt))))))
  ];
}

const fact = (term, value) => [h('dt', null, term), h('dd', null, value)];

export function runsPage(ctx) {
  const { workflows, archived } = ctx.data;
  const select = h('select', { 'aria-label': 'Filter by workflow', onchange: event => ctx.actions.filterRuns(event.target.value || null), 'data-key': 'runs:filter' },
    h('option', { value: '' }, 'All workflows'),
    [...workflows, ...archived].map(item =>
      h('option', { value: item.id, selected: ctx.history.workflowId === item.id }, item.name)));
  return [
    pageHead('Run history', 'Every assignment this console dispatched, with the result the worker reported.'),
    h('div.filters', null, select),
    historyPanel(ctx)
  ];
}

export function runPage(ctx, id) {
  const crumbs = [h('a', { href: '#/runs' }, 'Run history'), ' / '];
  const detail = ctx.runDetail;
  if (detail.id !== id || (!detail.run && !detail.error)) return [pageHead('Run', 'Loading…', null, crumbs)];
  if (detail.error) return [pageHead('Run not found', detail.error, null, crumbs)];
  const { run, events } = detail;
  const open = isOpen(run);
  const seconds = secondsBetween(run.startedAt ?? run.createdAt, run.finishedAt);
  return [
    pageHead(['Run of ', run.workflowName, ' ', badge(runState(run.state), run.state === 'running')], null, open && [
      button('Cancel run', { iconName: 'stop', kind: 'small', onclick: () => ctx.actions.cancelRun(run), key: 'run:cancel',
        disabled: Boolean(run.cancelRequestedAt), title: run.cancelRequestedAt ? 'Cancellation was already requested' : 'Ask the worker to stop' }),
      button('Release…', { kind: 'small danger', onclick: () => ctx.actions.abandonRun(run), key: 'run:abandon',
        title: 'Give up on a run that can no longer be resolved' })
    ], crumbs),
    run.error && h('div.callout', null, icon('alert'), `${run.error}. The controller keeps checking under the same task ID.`),
    open && run.cancelRequestedAt && h('div.callout.info', null, icon('info'),
      h('span', null, 'Cancellation requested ', timeAgo(run.cancelRequestedAt), '. The run ends when the worker confirms it stopped, or finishes anyway.')),
    run.state === 'abandoned' && h('div.callout', null, icon('info'),
      'Released by the operator. The worker was not told to stop, and its result, if any, was not collected.'),
    run.reason && h('div.callout.danger', null, icon('alert'), run.reason),
    h('div.section.two-col', null,
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Result'),
          run.outputTruncated && h('span.section-note', null, 'Truncated at 262,144 characters')),
        run.output ? h('pre.output', { tabindex: '0' }, run.output)
          : h('div.panel.empty', null, open ? ['No result yet.', run.progress && [' Latest update: ', run.progress]] : 'This run reported no output.'),
        run.state === 'succeeded' && h('p.help', null, 'A succeeded run is the worker\'s own report. Nothing here has checked its output.'),
        h('div.section-head.section', null, h('h2', null, 'Instructions sent')),
        h('div.panel.pad', null, h('p.prose', null, run.instructions))),
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Details')),
        h('div.panel.pad', null, h('dl.facts', null,
          fact('Workflow', h('a', { href: `#/workflows/${run.workflowId}` }, run.workflowName)),
          fact('Task ID', copyable(run.taskId, shortId(run.taskId))),
          fact('Dispatched', timeAgo(run.createdAt)),
          fact('Accepted', timeAgo(run.startedAt, open ? 'Not yet' : '—')),
          fact('Finished', timeAgo(run.finishedAt, open ? 'In progress' : '—')),
          fact('Duration', open ? (run.startedAt ? duration(secondsBetween(run.startedAt, new Date().toISOString())) + ' so far' : 'Not started') : duration(seconds)))),
        h('div.section-head.section', null, h('h2', null, 'Timeline')),
        events.length
          ? h('div.panel.pad', null, h('ol.timeline', null, events.map(event =>
            h('li', { class: event.kind },
              h('div', null, h('div.kind', null, event.kind.replaceAll('_', ' ')), event.message && h('div.message', null, event.message)),
              timeAgo(event.at, '')))))
          : h('div.panel.empty', null, 'No task events have been retained yet.')))
  ];
}

function workerPanel(ctx, connection) {
  const { readiness } = connection;
  const tone = readiness.ready ? 'ok' : readiness.code === 'checking' ? '' : 'warn';
  const label = readiness.ready ? 'Ready' : readiness.code === 'checking' ? 'Checking' : 'Not ready';
  const assigned = ctx.data.workflows.filter(workflow => workflow.connectionId === connection.id);
  return h('article.panel.worker', null,
    h('div.worker-top', null,
      h('div', null,
        h('div.worker-name', null, connection.name),
        h('p.card-meta', null, readiness.reason, readiness.since && [' · since ', timeAgo(readiness.since)])),
      badge([label, tone])),
    h('dl.facts', null,
      fact('Agent', copyable(connection.agentId, shortId(connection.agentId))),
      fact('Host', copyable(connection.hostId, shortId(connection.hostId))),
      fact('Follows', connection.mode === 'agent' ? 'Whichever session of this agent is attached and verified' : 'The session named by its worker state file'),
      fact('Workflows', assigned.length
        ? assigned.map((workflow, index) => [index > 0 && ', ', h('a', { href: `#/workflows/${workflow.id}` }, workflow.name)])
        : 'None'),
      fact('Last checked', timeAgo(readiness.checkedAt, 'Not yet'))),
    readiness.hints.length > 0 && h('div.hints', null,
      h('p.card-meta', null, 'The worker host reports:'),
      readiness.hints.map(hint => h('div.hint-item', null, hintText(hint.kind), hint.command && commandLine(hint.command)))),
    h('details', null,
      h('summary.card-meta', null, 'Remove this worker'),
      h('p.help', null, 'Archive or move its workflows first, then run:'),
      commandLine(`${CLI} disconnect --id ${connection.id}`)));
}

export function workersPage(ctx) {
  const { connections } = ctx.data;
  return [
    pageHead('Workers', 'Agent sessions this console may assign work to. Readiness is checked on every pass.'),
    connections.length ? h('div.cards', null, connections.map(connection => workerPanel(ctx, connection)))
      : empty('No workers connected', 'Connect an agent that is already attached to Peerspan on this machine.'),
    section('Connect a worker', connectHelp()),
    h('p.help.section', null, 'Model usage is billed by your provider. Daily limits here count dispatches, not dollars.')
  ];
}

export function activityPage(ctx) {
  const names = nameResolver(ctx);
  const { log } = ctx;
  return [
    pageHead('Activity', 'What you did and what the controller did, newest first. The newest 5,000 entries are kept.'),
    !log.loaded ? h('div.panel.empty', null, 'Loading activity…')
      : log.entries.length
        ? h('div.panel', null,
          h('div.rows', null, log.entries.map(entry => activityRow(ctx, entry, names))),
          log.nextBefore && h('div.pager', null, button('Load older activity', { onclick: ctx.actions.moreActivity, key: 'activity:more' })))
        : empty('Nothing has happened yet', 'Operator actions and controller events are recorded here.')
  ];
}
