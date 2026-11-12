// Console views. Each takes the app context and returns the nodes of one page.
import { absoluteTime, commandLine, copyable, duration, h, icon, secondsBetween, shortId, timeAgo } from './dom.js';
import { diffLines, foldUnchanged } from './diff.js';
import {
  OPEN_STATES, activityText, checkText, fallbackText, hintText, reviewState, reworkText, runState, runtimeText, schedule,
  waitsForOperator, workflowStatus
} from './labels.js';

const CLI = 'node managed/cli.mjs';
// Readiness codes that only an agent without a launch profile reaches (contract sections 3 and 3.1).
const SESSION_CODES = ['ready', 'ready_service_inactive', 'session_not_ready', 'channel_unverified'];

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

function runStrip(workflow, runs) {
  // The snapshot's own runs say who a pending result waits for; older `recent` entries do not.
  const recent = [...workflow.recent].reverse().map(entry => runs.find(run => run.id === entry.id) ?? entry);
  if (!recent.length) return h('div.strip', null, h('span.strip-label', null, 'No runs yet'));
  const label = run => [runState(run.state)[0], reviewState(run)?.[0]].filter(Boolean).join(', ');
  return h('div.strip', { 'aria-label': 'Latest runs, oldest first' },
    recent.map(run => h('a', {
      class: [run.state, run.review && 'review-' + run.review].filter(Boolean).join(' '),
      href: `#/runs/${run.id}`,
      title: `${label(run)} · ${absoluteTime(run.createdAt)}`,
      'aria-label': `${label(run)} run from ${absoluteTime(run.createdAt)}`
    })),
    h('span.strip-label', null, `last ${plural(recent.length, 'run')}`));
}

// The scheduler's explanation while a workflow is simply not due yet (contract sections 14 and 14.1).
const waiting = reason => !reason || reason === 'Waiting for next scheduled run' || reason.startsWith('Waiting for an accepted result');

function nextLine(workflow, openRun) {
  if (openRun) return ['Assignment in progress since ', timeAgo(openRun.createdAt)];
  if (!workflow.enabled) {
    return [workflow.blockedReason || 'Paused', workflow.reworkPending ? '; a rework is due on resume'
      : workflow.handoffPending ? '; a new input is waiting for resume' : ''];
  }
  if (workflow.reworkPending && waiting(workflow.blockedReason)) return ['Rework due now'];
  // A workflow that runs after another has no next run time: a new accepted result makes it due.
  if (workflow.after) {
    if (workflow.handoffPending && waiting(workflow.blockedReason)) return ['Due now, on a new input'];
    return [workflow.blockedReason || 'Waiting for an accepted result of the workflow it runs after'];
  }
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
      title: !workflow.enabled ? 'Resume the workflow first' : openRun ? 'A run is already in progress'
        : workflow.after ? 'Run on the latest accepted result of the workflow it runs after' : 'Make the next run due now'
    })
  ];
}

/** The name of the workflow that `workflow` runs after, archived ones included. */
function upstreamName(ctx, workflow) {
  if (!workflow.after) return null;
  const upstream = [...ctx.data.workflows, ...ctx.data.archived].find(item => item.id === workflow.after.workflowId);
  return upstream ? upstream.name : 'a workflow that no longer exists';
}

function workflowCard(ctx, workflow) {
  const { runs, connections } = ctx.data;
  const openRun = runs.find(run => run.workflowId === workflow.id && isOpen(run));
  const worker = connections.find(connection => connection.id === workflow.connectionId);
  const reviewer = connections.find(connection => connection.id === workflow.reviewerId);
  const status = workflowStatus(workflow, runs);
  const checkedBy = workflow.review === 'agent' ? ` · checked by ${reviewer ? reviewer.name : 'a disconnected reviewer'}`
    : workflow.review === 'operator' ? ' · checked by you' : '';
  return h('article.panel.card', null,
    h('div.card-main', null,
      h('div.card-top', null,
        h('a.card-title', { href: `#/workflows/${workflow.id}` }, workflow.name),
        badge(status, Boolean(openRun) && openRun.state === 'running')),
      h('p.card-meta', null,
        `${worker ? worker.name : 'No worker'} · ${schedule(workflow, { upstream: upstreamName(ctx, workflow) })} · up to ${plural(workflow.maxRunsPerDay, 'run')} a day${checkedBy}`),
      runStrip(workflow, runs),
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
  const review = reviewState(run);
  const title = run.attempt > 1 ? `${run.workflowName} · attempt ${run.attempt}` : run.workflowName;
  return h('a.row', { href: `#/runs/${run.id}` },
    h('span.row-state', null, badge(review && run.review !== 'accepted' ? review : runState(run.state), run.state === 'running')),
    h('div.row-main', null,
      named ? [h('div.row-title', null, title), h('div.row-sub', null, summary)]
        : h('div.row-title.plain', null, run.attempt > 1 ? `Attempt ${run.attempt}: ${summary}` : summary)),
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
    h('p', null, 'Workers are registered from a terminal on this machine, never from the browser. Sender and worker must be two Peerspan hosts: a host cannot send tasks to itself.'),
    h('div.dialog-body', null,
      h('h3', null, 'An agent whose host runs on this machine'),
      commandLine(`${CLI} connect --name "Repository maintainer" --agent AGENT`),
      h('p.help', null, 'Name the agent as ', h('code', null, 'peerspan agents'), ' shows it, or pass its agent ID. Add ',
        h('code', null, '--host-state DIR'), ' when the worker host does not use the default Peerspan state, and ',
        h('code', null, '--sender-state DIR'), ' when tasks are submitted from a host other than the default.'),
      h('p.help', null, 'A runtime agent, one with a launch profile (', h('code', null, 'peerspan agent runtime set'),
        '), needs no attached session: it is ready while its host\'s runtime is on and answering and it has a credential, ',
        'and each of its tasks runs in its own microVM on a fork of its branch.'),
      h('h3', null, 'An agent on another machine'),
      commandLine(`${CLI} connect --name "Research agent" --remote PERSON/AGENT`),
      h('p.help', null, 'Pass the address or agent ID that ', h('code', null, 'peerspan agents'),
        ' lists for the sender host. Readiness then comes from the sender\'s directory: whether the agent is connected, ',
        'whether its host answered, and whether its owner lets you submit tasks. Add ', h('code', null, '--network ID'),
        ' when the sender is in several networks.'),
      h('p.help', null, 'Check the setup with ', h('code', null, `${CLI} doctor`), '.')));
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
    tile('Workers ready', ready, `of ${connections.length}`, connections.length ? 'Live readiness checks' : 'None connected yet'),
    tile('Runs, last 7 days', sum('runs'), null, judged ? `${percent(sum('succeeded') / judged)} succeeded` : 'No finished runs yet'),
    tile('Unattended runs', sum('unattendedRuns'), null, `${plural(sum('interventions'), 'operator action')} in 7 days`));

  const workflowList = workflows.length
    ? h('div.cards', null, workflows.map(workflow => workflowCard(ctx, workflow)))
    : connections.length
      ? empty('Create your first recurring assignment',
        'Pick a worker, describe a bounded assignment, and set how often it may run.',
        h('p.empty-action', null, button('New workflow', { iconName: 'plus', kind: 'primary', onclick: ctx.actions.newWorkflow })))
      : empty('Connect a worker to begin', 'A worker is an agent already attached to Peerspan, on this machine or on one your sender host can reach.',
        h('p.empty-action', null, h('a.button.primary', { href: '#/workers' }, 'How to connect a worker')));
  // Oldest first: the result that has waited longest is reviewed first. Results a reviewer
  // agent is still checking are not the operator's to decide yet.
  const waiting = runs.filter(waitsForOperator).reverse();

  return [
    pageHead('Overview', 'Keep recurring work moving, and see what needs you.',
      button('New workflow', { iconName: 'plus', kind: 'primary', onclick: ctx.actions.newWorkflow, disabled: !connections.length,
        title: connections.length ? null : 'Connect a worker first' })),
    attentionList(ctx),
    h('div.section', null, tiles),
    waiting.length > 0 && section('Waiting for your review', h('div.panel.rows', null, waiting.slice(0, 8).map(run => runRow(run))),
      { note: waiting.length > 8 ? `The oldest 8 of ${waiting.length} recent results` : 'Results count as successes once accepted.' }),
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
  const reviewer = connections.find(connection => connection.id === workflow.reviewerId);
  const { stats } = workflow;
  const status = workflowStatus(workflow, runs);
  const checked = workflow.resultChecks.length > 0;
  // The workflows that run after this one, on its accepted results (contract section 14.1).
  const downstream = workflows.filter(item => item.after?.workflowId === workflow.id);
  const results = {
    none: checked ? 'Counted as the worker reports them once they pass their checks' : 'Counted as the worker reports them',
    operator: checked ? 'Each success that passes its checks waits for your verdict before it counts'
      : 'Each success waits for your verdict before it counts',
    agent: [checked ? 'Each success that passes its checks is checked by ' : 'Each success is checked by ',
      reviewer ? h('a', { href: '#/workers' }, reviewer.name) : 'a disconnected reviewer',
      ' before it counts; when it gives no verdict, you decide']
  }[workflow.review];
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
      (workflow.review !== 'none' || stats.awaitingReview > 0)
        ? tile('Awaiting review', stats.awaitingReview, null,
          stats.awaitingReview ? 'Not counted until a verdict' : 'All results reviewed')
        : tile('Operator actions', stats.interventions, null, 'In the last 7 days'),
      tile('Unattended runs', stats.unattendedRuns, null, 'Since you last stepped in')),
    h('div.section.two-col', null,
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Run history')),
        historyPanel(ctx, { named: false })),
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Assignment')),
        h('div.panel.pad', null, h('p.prose', null, workflow.instructions)),
        workflow.reviewCriteria && [
          h('div.section-head.section', null, h('h2', null, 'Review criteria')),
          h('div.panel.pad', null, h('p.prose', null, workflow.reviewCriteria))],
        workflow.resultChecks.length > 0 && [
          h('div.section-head.section', null, h('h2', null, 'Checks before review'),
            h('span.section-note', null, 'A result that fails one is rejected')),
          h('ul.panel.pad.check-results', null, workflow.resultChecks.map(check => h('li', null, icon('check'), h('span', null, checkText(check)))))],
        h('div.section-head.section', null, h('h2', null, 'Schedule')),
        h('div.panel.pad', null, h('dl.facts', null,
          fact('Worker', worker ? h('a', { href: '#/workers' }, worker.name) : 'Not connected'),
          fact('Repeats', workflow.after
            ? ['After each accepted result of ', h('a', { href: `#/workflows/${workflow.after.workflowId}` }, upstreamName(ctx, workflow)),
              ', which becomes its input']
            : workflow.schedule
              ? `${schedule(workflow, { zone: false })}, ${workflow.schedule.timeZone} time; a slot missed while busy or paused runs once`
              : schedule(workflow) + ', counted from the end of the previous run'),
          downstream.length > 0 && fact('Hands off to', downstream.map((item, index) =>
            [index ? ', ' : '', h('a', { href: `#/workflows/${item.id}` }, item.name)])),
          fact('Results', results),
          (workflow.review !== 'none' || workflow.resultChecks.length > 0) && fact('Rejected results', reworkText(workflow.reworkLimit)),
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
  const rework = ctx.data.runs.find(other => other.reworkOf === run.id);
  return [
    pageHead(['Run of ', run.workflowName, run.attempt > 1 ? ` · attempt ${run.attempt}` : '', ' ',
      badge(runState(run.state), run.state === 'running'),
      reviewState(run) && [' ', badge(reviewState(run))]], null, open && [
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
    run.reworkOf && h('div.callout.info', null, icon('info'), h('span', null,
      'A rework: the worker received the review and the result of ', h('a', { href: `#/runs/${run.reworkOf}` }, 'the rejected run'),
      ' with the assignment.')),
    run.handoffFrom && !run.reworkOf && h('div.callout.info', null, icon('info'), h('span', null,
      'Its input was ', h('a', { href: `#/runs/${run.handoffFrom}` }, 'an accepted result'),
      ' of the workflow it runs after, sent with the assignment.')),
    h('div.section.two-col', null,
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Result'),
          run.outputTruncated && h('span.section-note', null, 'Truncated at 262,144 characters')),
        run.output ? h('pre.output', { tabindex: '0', 'data-key': `result:${run.id}` }, run.output)
          : h('div.panel.empty', null, open ? ['No result yet.', run.progress && [' Latest update: ', run.progress]] : 'This run reported no output.'),
        comparePanel(run, detail.previous),
        checksPanel(run),
        reviewPanel(ctx, run, rework),
        reviewTaskPanel(ctx, run, detail.reviewEvents),
        h('div.section-head.section', null, h('h2', null, 'Instructions sent'),
          run.attempt > 1 ? h('span.section-note', null, 'The assignment, the review and the previous result')
            : run.handoffFrom && h('span.section-note', null, 'The assignment and its input')),
        h('div.panel.pad', null, h('p.prose', null, run.instructions))),
      h('div', null,
        h('div.section-head', null, h('h2', null, 'Details')),
        h('div.panel.pad', null, h('dl.facts', null,
          fact('Workflow', h('a', { href: `#/workflows/${run.workflowId}` }, run.workflowName)),
          run.attempt > 1 && fact('Attempt', [`${run.attempt}, reworking `, h('a', { href: `#/runs/${run.reworkOf}` }, 'the rejected run')]),
          run.handoffFrom && fact('Input from', h('a', { href: `#/runs/${run.handoffFrom}` }, 'an accepted upstream result')),
          rework && fact('Sent back', ['Reworked in ', h('a', { href: `#/runs/${rework.id}` }, `attempt ${rework.attempt}`)]),
          run.branch && fact('Branch', branchText(run.branch)),
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

// The latest comparison, so that live refreshes do not compute it again.
let compared = { key: null, ops: null };

/** What changed in this result since the workflow's previous one, line by line. */
function comparePanel(run, previous) {
  if (previous?.unavailable) return h('p.help.compare', null, `Not compared with the previous result: ${previous.unavailable}.`);
  if (!previous || typeof run.output !== 'string') return null;
  const key = run.id + '/' + previous.id;
  if (compared.key !== key) compared = { key, ops: diffLines(previous.output, run.output) };
  const { ops } = compared;
  const earlier = [h('a', { href: `#/runs/${previous.id}` }, previous.skipped ? 'an earlier result'
    : previous.attempt > 1 ? `attempt ${previous.attempt}` : 'the previous result'),
    ' from ', timeAgo(previous.createdAt)];
  if (ops === null) return h('p.help.compare', null, 'Compared with ', earlier, ': too long or too different to compare line by line.');
  const added = ops.filter(([op]) => op === '+').length;
  const removed = ops.filter(([op]) => op === '-').length;
  if (!added && !removed) return h('p.help.compare', null, 'Unchanged since ', earlier, '.');
  const line = ([op, text]) => (op === '…'
    ? h('span.diff-fold', null, `… ${text} unchanged line${text === 1 ? '' : 's'}`)
    : h('span', { class: { '+': 'diff-add', '-': 'diff-del', '=': 'diff-same' }[op] }, `${op === '=' ? ' ' : op} ${text}`));
  return h('details.compare', { 'data-key': `compare:${key}` },
    h('summary', null, `Changes since the previous result: ${added} line${added === 1 ? '' : 's'} added, ${removed} removed`),
    h('p.help', null, 'Compared with ', earlier, '.'),
    h('pre.output.diff', { tabindex: '0', 'data-key': `compare:${key}:text` }, foldUnchanged(ops).map(line)));
}

const BRANCH_OUTCOMES = {
  committed: branch => [h('code', null, branch.name), ' at commit ', copyable(branch.commit, shortId(branch.commit))],
  unchanged: branch => [h('code', null, branch.name), ', unchanged from ', h('code', null, branch.from)],
  not_committed: branch => [h('code', null, branch.name), ', not committed: ', branch.error],
  none: () => ['None: the run never started']
};

/** The peerfs branch a runtime agent reported working on (contract section 10.1). */
const branchText = branch => (BRANCH_OUTCOMES[branch.outcome] ?? BRANCH_OUTCOMES.none)(branch);

/** Each result check the run was checked with, and how it went (contract section 15.3). */
function checksPanel(run) {
  if (!run.checks) return null;
  const failed = run.checks.filter(item => !item.passed).length;
  return [
    h('div.section-head.section', null, h('h2', null, 'Checks'),
      h('span.section-note', null, failed ? `${failed} of ${run.checks.length} failed` : `All ${run.checks.length} passed`)),
    h('ul.panel.pad.check-results', null, run.checks.map(item => h('li', { class: item.passed ? 'passed' : 'failed' },
      icon(item.passed ? 'check' : 'alert'),
      h('div', null, h('span', null, checkText(item.check)), item.message && h('div.help', null, item.message)))))
  ];
}

/** The verdict on a result, who gave it, and what happens next; or the form to give one. */
function reviewPanel(ctx, run, rework) {
  if (run.state !== 'succeeded') return null;
  if (run.review === null) {
    return h('p.help', null, 'A succeeded run is the worker\'s own report. This workflow does not ask for its results to be reviewed',
      run.checks ? ', and it passed its checks.' : '.');
  }
  const reviewer = run.reviewTask && ctx.data.connections.find(connection => connection.id === run.reviewTask.connectionId);
  const reviewerName = reviewer ? reviewer.name : 'The reviewer agent';
  if (run.review !== 'pending') {
    const accepted = run.review === 'accepted';
    const who = run.reviewedBy === 'checks' ? 'This result failed its checks'
      : run.reviewedBy === 'agent' ? `${reviewerName} ${accepted ? 'accepted' : 'rejected'} this result`
        : `You ${accepted ? 'accepted' : 'rejected'} this result`;
    return h('div.callout', { class: accepted ? 'ok' : 'danger' }, icon(accepted ? 'check' : 'alert'),
      h('div', null,
        h('strong', null, who), ' ', timeAgo(run.reviewedAt), '.',
        run.reviewedBy === 'checks' && h('p.review-note', null, 'It was rejected before any review, and counts as a failure.'),
        run.reviewNote && run.reviewedBy !== 'checks' && h('p.review-note', null, run.reviewNote),
        rework && h('p.review-note', null, run.reviewedBy === 'checks' ? 'Sent back to the worker with the failed checks: '
          : 'Sent back to the worker with this review: ', h('a', { href: `#/runs/${rework.id}` }, `attempt ${rework.attempt}`), '.')));
  }
  const operatorTurn = waitsForOperator(run);
  const next = [...ctx.data.runs].reverse().find(other => waitsForOperator(other) && other.id !== run.id);
  // Keyed by run, so that a draft note survives refreshes but never follows the operator to the next result.
  const note = h('textarea', { id: 'review-note', maxlength: '2000', rows: '2', placeholder: 'Optional note: what was right or wrong',
    'data-key': `review:note:${run.id}` });
  const decide = verdict => () => ctx.actions.reviewRun(run, verdict, note.value, next);
  let status = null;
  if (run.reviewTask && run.reviewFallback) {
    status = h('div.callout', null, icon('alert'),
      h('span', null, `${reviewerName} gave no verdict: ${fallbackText(run.reviewFallback)}. Your verdict decides.`));
  } else if (run.reviewTask && run.reviewTask.taskId) {
    status = h('div.callout.info', null, icon('info'),
      h('span', null, `${reviewerName} is checking this result. You can still decide now; its answer is then kept but changes nothing.`));
  } else if (run.reviewTask) {
    status = h('div.callout.info', null, icon('info'),
      h('span', null, `Waiting for ${reviewer ? reviewer.name : 'the reviewer agent'}`,
        reviewer && !reviewer.readiness.ready ? `: ${reviewer.readiness.reason}` : ' to be free',
        '. You can decide now instead.'));
  }
  return h('div.panel.pad.review', null,
    h('h3', null, operatorTurn ? 'Does this result count?' : 'Decide instead of the reviewer?'),
    status,
    h('p.help', null, 'It is the worker\'s own report. It counts as a success once accepted; a rejection counts as a failure. ',
      'A verdict is final and does not change the schedule.'),
    h('label.sr-only', { for: 'review-note' }, 'Note'),
    note,
    h('div.review-actions', null,
      button('Accept', { iconName: 'check', kind: operatorTurn ? 'primary' : '', onclick: decide('accepted'), key: 'review:accept' }),
      button('Reject', { iconName: 'close', kind: 'danger', onclick: decide('rejected'), key: 'review:reject' }),
      next && h('span.help', null, 'Then opens the next result waiting for you.')));
}

/** The reviewer agent's task for this result: its state, answer and timeline (contract section 15.1). */
function reviewTaskPanel(ctx, run, events = []) {
  const task = run.reviewTask;
  if (!task?.taskId) return null;
  const reviewer = ctx.data.connections.find(connection => connection.id === task.connectionId);
  const open = OPEN_STATES.includes(task.state);
  return [
    h('div.section-head.section', null, h('h2', null, 'Review task'),
      h('span.section-note', null, reviewer ? reviewer.name : 'Disconnected reviewer')),
    h('div.panel.pad.review-task', null,
      h('div.review-task-top', null,
        badge(runState(task.state), task.state === 'running'),
        h('span.card-meta', null, 'Task ', copyable(task.taskId, shortId(task.taskId)), ' · sent ', timeAgo(task.createdAt),
          task.finishedAt && [' · ended ', timeAgo(task.finishedAt)])),
      task.error && h('p.help', null, `${task.error}. The controller keeps checking under the same task ID.`),
      task.reason && h('p.help', null, task.reason),
      open && h('div.review-actions', null,
        button('Cancel review task', { iconName: 'stop', kind: 'small', onclick: () => ctx.actions.cancelReview(run),
          key: 'review:cancel', disabled: Boolean(task.cancelRequestedAt),
          title: task.cancelRequestedAt ? 'Cancellation was already requested' : 'Ask the reviewer to stop' }),
        button('Release…', { kind: 'small danger', onclick: () => ctx.actions.abandonReview(run), key: 'review:abandon',
          title: 'Give up on a review task that can no longer be resolved' })),
      task.output && h('details', { 'data-key': `review-answer:${run.id}` },
        h('summary', null, 'The reviewer\'s full answer'), h('pre.output', { 'data-key': `review-answer-text:${run.id}` }, task.output)),
      task.input && h('details', { 'data-key': `review-input:${run.id}` },
        h('summary', null, 'What the reviewer was asked'), h('pre.output', { 'data-key': `review-input-text:${run.id}` }, task.input)),
      events.length > 0 && h('details', { 'data-key': `review-timeline:${run.id}` }, h('summary', null, 'Timeline'),
        h('ol.timeline', null, events.map(event =>
          h('li', { class: event.kind },
            h('div', null, h('div.kind', null, event.kind.replaceAll('_', ' ')), event.message && h('div.message', null, event.message)),
            timeAgo(event.at, ''))))))
  ];
}

/** How many tasks a worker agent holds, against how many it may hold (contract section 4). */
function workingOn({ activeTasks, capacity }) {
  if (activeTasks > capacity) return `${activeTasks} tasks, more than its capacity of ${capacity} now; no new task until fewer`;
  if (capacity > 1) return `${activeTasks} of ${capacity} tasks at once`;
  return activeTasks ? 'One task' : 'Nothing now';
}

function workerPanel(ctx, connection) {
  const { readiness } = connection;
  const tone = readiness.ready ? 'ok' : readiness.code === 'checking' ? '' : 'warn';
  const label = readiness.ready ? 'Ready' : readiness.code === 'checking' ? 'Checking' : 'Not ready';
  const assigned = ctx.data.workflows.filter(workflow => workflow.connectionId === connection.id);
  const reviewing = ctx.data.workflows.filter(workflow => workflow.reviewerId === connection.id);
  const links = workflows => workflows.map((workflow, index) =>
    [index > 0 && ', ', h('a', { href: `#/workflows/${workflow.id}` }, workflow.name)]);
  const remote = connection.mode === 'remote';
  return h('article.panel.worker', null,
    h('div.worker-top', null,
      h('div', null,
        h('div.worker-name', null, connection.name),
        h('p.card-meta', null, readiness.reason, readiness.since && [' · since ', timeAgo(readiness.since)])),
      badge([label, tone])),
    h('dl.facts', null,
      fact('Agent', copyable(connection.agentId, shortId(connection.agentId))),
      fact('Host', copyable(connection.hostId, shortId(connection.hostId))),
      fact('Where', remote ? 'Another machine, seen through the sender host\'s directory' : 'A Peerspan host on this machine'),
      fact('Follows', remote ? 'Whether the directory shows the agent connected, its host reachable and task submission allowed'
        : readiness.runtime ? 'Its launch profile and the host\'s runtime: each task runs in its own microVM on a fork'
          : connection.mode === 'agent'
            ? 'Whichever session of this agent is attached and verified'
              // Until a check reaches the launch profiles, the agent may be either kind.
              + (SESSION_CODES.includes(readiness.code) ? '' : ', or, for a runtime agent, its launch profile and the host\'s runtime')
            : 'The session named by its worker state file'),
      readiness.runtime && fact('Runtime', runtimeText(readiness.runtime) || 'Launch profile without details'),
      fact('Workflows', assigned.length ? links(assigned) : 'None'),
      reviewing.length > 0 && fact('Reviews for', links(reviewing)),
      fact('Working on', workingOn(connection)),
      fact('Last checked', timeAgo(readiness.checkedAt, 'Not yet')),
      remote && fact('Directory as of', timeAgo(readiness.directoryAt, 'Unknown'))),
    readiness.hints.length > 0 && h('div.hints', null,
      h('p.card-meta', null, remote ? 'The sender host reports:' : 'The worker host reports:'),
      readiness.hints.map(hint => h('div.hint-item', null, hintText(hint.kind), hint.command && commandLine(hint.command)))),
    h('details', { 'data-key': `remove-worker:${connection.id}` },
      h('summary.card-meta', null, 'Remove this worker'),
      h('p.help', null, 'Archive its workflows or give them another worker and reviewer first, then run:'),
      commandLine(`${CLI} disconnect --id ${connection.id}`)));
}

export function workersPage(ctx) {
  const { connections } = ctx.data;
  return [
    pageHead('Workers', 'Agents this console may assign work to. Readiness is checked on every pass.'),
    connections.length ? h('div.cards', null, connections.map(connection => workerPanel(ctx, connection)))
      : empty('No workers connected', 'Connect an agent that is already attached to Peerspan, here or on another machine.'),
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
