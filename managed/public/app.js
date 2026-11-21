// Peerspan Managed console: sign-in, routing, live updates and operator actions.
import { h, icon, tickTimes } from './js/dom.js';
import { abandonDialog, confirmDialog, recipeDialog, workflowDialog } from './js/dialogs.js';
import { recipeTemplate } from './js/recipes.js';
import * as views from './js/views.js';

const POLL_MS = 15_000;
const PAGE = 50;
const $ = id => document.getElementById(id);

const app = {
  data: null,
  signature: '',
  revision: null,
  route: { name: 'overview', id: null },
  history: { workflowId: null, runs: [], nextBefore: null, loaded: false },
  log: { entries: [], nextBefore: null, loaded: false },
  runDetail: { id: null, run: null, events: [], error: null },
  stream: null,
  poll: null
};

// ----- requests ---------------------------------------------------------------------

async function request(path, { method = 'GET', body } = {}) {
  const response = await fetch(path, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  let data = null;
  try {
    data = await response.json();
  } catch {
    // Not JSON; the status decides.
  }
  if (response.status === 401) {
    showLogin();
    throw new Error(data?.error || 'Sign in to continue');
  }
  if (!response.ok) throw new Error(data?.error || `Request failed (${response.status})`);
  return data;
}

const post = (path, body = {}) => request(path, { method: 'POST', body });

function toast(message, kind = '') {
  const note = h('div.toast', { class: kind }, message);
  $('toasts').append(note);
  setTimeout(() => note.remove(), kind === 'error' ? 7000 : 3500);
}

/** Runs an operator action, then refreshes; a failure is shown, never thrown. */
async function perform(action, done) {
  try {
    await action();
    if (done) toast(done);
    await refresh();
  } catch (error) {
    toast(error.message, 'error');
  }
}

// ----- routing and page data --------------------------------------------------------------

function parseRoute() {
  const [name = 'overview', id = null] = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  return { name, id };
}

async function loadHistory({ more = false } = {}) {
  const { history } = app;
  const query = new URLSearchParams({ limit: String(more ? PAGE : Math.min(200, Math.max(PAGE, history.runs.length))) });
  if (history.workflowId) query.set('workflowId', history.workflowId);
  if (more && history.nextBefore) query.set('before', history.nextBefore);
  const page = await request('/api/runs?' + query);
  history.runs = more ? [...history.runs, ...page.runs] : page.runs;
  history.nextBefore = page.nextBefore;
  history.loaded = true;
}

async function loadLog({ more = false } = {}) {
  const { log } = app;
  const query = new URLSearchParams({ limit: String(more ? PAGE : Math.min(200, Math.max(PAGE, log.entries.length))) });
  if (more && log.nextBefore) query.set('before', String(log.nextBefore));
  const page = await request('/api/activity?' + query);
  log.entries = more ? [...log.entries, ...page.activity] : page.activity;
  log.nextBefore = page.nextBefore;
  log.loaded = true;
}

async function loadRun(id) {
  // A load for a run page the operator has already left must not replace the page now shown.
  const stillShown = () => app.route.name === 'runs' && app.route.id === id;
  try {
    const detail = await request('/api/runs/' + id);
    const previous = app.runDetail.id === id && app.runDetail.previous !== undefined
      ? app.runDetail.previous : await previousResult(detail.run);
    if (!stillShown()) return;
    app.runDetail = { id, run: detail.run, events: detail.events, reviewEvents: detail.reviewEvents ?? [], previous, error: null };
  } catch (error) {
    if (!stillShown()) return;
    app.runDetail = { id, run: null, events: [], reviewEvents: [], previous: null, error: error.message };
  }
}

// At most this many earlier runs are fetched to find one whose whole result can be compared.
const COMPARE_LOOKBACK = 5;

/**
 * The workflow's previous run with a whole result, for comparing results:
 * `{id, createdAt, attempt, output}`; `{unavailable}` with the reason when this
 * result cannot be compared; null when there is nothing earlier to compare
 * with; or undefined while the run has no final result yet. A found answer is
 * kept per run page, so live refreshes do not fetch it again.
 */
async function previousResult(run) {
  if (run.state !== 'succeeded' && run.state !== 'failed') return undefined;
  if (typeof run.output !== 'string') return null;
  if (run.outputTruncated) return { unavailable: 'this result was truncated' };
  try {
    const page = await request(`/api/runs?workflowId=${encodeURIComponent(run.workflowId)}&limit=200`);
    const index = page.runs.findIndex(item => item.id === run.id);
    const earlier = index < 0 ? [] : page.runs.slice(index + 1)
      .filter(item => (item.state === 'succeeded' || item.state === 'failed') && item.output !== null)
      .slice(0, COMPARE_LOOKBACK);
    // A truncated earlier result is skipped for the one before it.
    for (const [position, item] of earlier.entries()) {
      const { run: full } = await request('/api/runs/' + item.id);
      if (typeof full.output === 'string' && !full.outputTruncated) {
        return { id: full.id, createdAt: full.createdAt, attempt: full.attempt, output: full.output, skipped: position > 0 };
      }
    }
    return null;
  } catch {
    // The comparison is a convenience; the page works without it.
    return null;
  }
}

/** Loads what the current page shows beyond the snapshot. */
async function loadPageData() {
  const { name, id } = app.route;
  try {
    if (name === 'runs' && id) await loadRun(id);
    else if (name === 'runs') await loadHistory();
    else if (name === 'workflows' && id) await loadHistory();
    else if (name === 'activity') await loadLog();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function navigate() {
  const previous = app.route;
  app.route = parseRoute();
  const { name, id } = app.route;
  if (name === 'workflows' && id) {
    if (app.history.workflowId !== id) app.history = { workflowId: id, runs: [], nextBefore: null, loaded: false };
  } else if (name === 'runs' && !id) {
    // Coming from a workflow page, the history page starts unfiltered.
    if (previous.name === 'workflows') app.history = { workflowId: null, runs: [], nextBefore: null, loaded: false };
  } else if (name === 'runs' && id && app.runDetail.id !== id) {
    app.runDetail = { id, run: null, events: [], error: null };
  }
  render();
  await loadPageData();
  render();
  $('view').focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

// ----- rendering -------------------------------------------------------------------------

const NAV = [
  ['overview', '#/', 'Overview', 'overview'],
  ['workflows', '#/workflows', 'Workflows', 'workflows'],
  ['runs', '#/runs', 'Run history', 'runs'],
  ['workers', '#/workers', 'Workers', 'workers'],
  ['activity', '#/activity', 'Activity', 'activity']
];

function renderNav() {
  const { workflows, connections, attention } = app.data;
  const unready = connections.filter(connection => !connection.readiness.ready && connection.readiness.code !== 'checking').length;
  const urgent = attention.filter(item => item.severity === 'action').length;
  const counts = {
    overview: urgent ? [urgent, true] : null,
    workflows: workflows.length ? [workflows.length, false] : null,
    workers: unready ? [unready, true] : connections.length ? [connections.length, false] : null
  };
  $('nav').replaceChildren(...NAV.map(([name, href, label, iconName]) => {
    const count = counts[name];
    return h('a', { href, 'aria-current': app.route.name === name ? 'page' : null },
      icon(iconName), label,
      count && h('span.count', { class: count[1] ? 'alert' : '' }, String(count[0])));
  }));
}

function page() {
  const { name, id } = app.route;
  const context = { data: app.data, history: app.history, log: app.log, runDetail: app.runDetail, actions };
  if (name === 'workflows') return id ? views.workflowPage(context, id) : views.workflowsPage(context);
  if (name === 'runs') return id ? views.runPage(context, id) : views.runsPage(context);
  if (name === 'workers') return views.workersPage(context);
  if (name === 'activity') return views.activityPage(context);
  return views.overview(context);
}

function render() {
  if (!app.data) return;
  renderNav();
  const view = $('view');
  // Keep keyboard focus, and anything typed into a text field, across a refresh.
  const active = document.activeElement;
  const focused = active?.dataset?.key;
  const selection = focused && 'selectionStart' in active ? [active.selectionStart, active.selectionEnd] : null;
  const drafts = [...view.querySelectorAll('textarea[data-key], input[type="text"][data-key]')]
    .filter(field => field.value).map(field => [field.dataset.key, field.value]);
  // Opened sections and scrolled text stay as the operator left them.
  const opened = [...view.querySelectorAll('details[data-key]')].map(section => [section.dataset.key, section.open]);
  const scrolled = [...view.querySelectorAll('[data-key]')].filter(element => element.scrollTop > 0)
    .map(element => [element.dataset.key, element.scrollTop]);
  view.replaceChildren(...page().flat().filter(Boolean));
  const keyed = key => view.querySelector(`[data-key="${CSS.escape(key)}"]`);
  for (const [key, value] of drafts) {
    const field = keyed(key);
    if (field && !field.value) field.value = value;
  }
  for (const [key, open] of opened) {
    const section = keyed(key);
    if (section) section.open = open;
  }
  for (const [key, top] of scrolled) {
    const element = keyed(key);
    if (element) element.scrollTop = top;
  }
  if (focused) {
    const field = view.querySelector(`[data-key="${CSS.escape(focused)}"]`);
    field?.focus({ preventScroll: true });
    if (field && selection && 'setSelectionRange' in field) field.setSelectionRange(...selection);
  }
}

function setLive(on) {
  $('live').className = 'live ' + (on ? 'on' : 'off');
  $('live-text').textContent = on ? 'Live' : 'Reconnecting';
}

/** Where alerts go (contract section 8.1): set on this machine with the alerts command, never here. */
function showAlerts(alerts) {
  const note = $('alerts-note');
  note.textContent = !alerts?.configured ? 'Alerts off'
    : alerts.failing ? `Alerts to ${alerts.host} are failing` : `Alerts go to ${alerts.host}`;
  note.className = 'alerts-note' + (alerts?.failing ? ' failing' : '');
  note.title = alerts?.configured ? 'Attention items are announced to this webhook'
    : 'Announce attention items to a webhook: node managed/cli.mjs alerts --url URL';
}

/** What a snapshot shows, without the fields that change on every pass. */
function signatureOf(data) {
  return JSON.stringify(data, (key, value) => (key === 'checkedAt' || key === 'lastTickAt' ? undefined : value));
}

// Each refresh and each sign-out takes the next number; a response is applied only when no
// later refresh has been applied and no sign-out happened since it was requested.
let requested = 0;
let applied = 0;

async function refresh() {
  const number = ++requested;
  let data;
  try {
    data = await request('/api/snapshot');
  } catch {
    if (number > applied && !$('console').hidden) setLive(false);
    return;
  }
  if (number < applied || number <= signedOutAt) return;
  applied = number;
  app.data = data;
  notifyAttention(data.attention);
  showAlerts(data.meta.alerts);
  $('login').hidden = true;
  $('console').hidden = false;
  setLive(true);
  const revisionChanged = data.meta.revision !== app.revision;
  app.revision = data.meta.revision;
  if (revisionChanged) await loadPageData();
  const signature = signatureOf(data);
  if (signature !== app.signature || revisionChanged) {
    app.signature = signature;
    render();
  }
}

// ----- live updates ------------------------------------------------------------------------

function startLive() {
  stopLive();
  // The stream says when stored state changed; observed programs have no such signal, so keep a slow poll.
  app.stream = new EventSource('/api/events');
  app.stream.addEventListener('change', event => {
    if (JSON.parse(event.data).revision !== app.revision) refresh();
  });
  app.stream.addEventListener('error', () => setLive(false));
  app.stream.addEventListener('open', () => setLive(true));
  app.poll = setInterval(refresh, POLL_MS);
}

function stopLive() {
  app.stream?.close();
  app.stream = null;
  clearInterval(app.poll);
}

let signedOutAt = 0;

function showLogin() {
  signedOutAt = requested;
  stopLive();
  $('dialog').close();
  $('console').hidden = true;
  $('view').replaceChildren();
  $('login').hidden = false;
  $('token').focus();
}

// ----- operator actions ---------------------------------------------------------------------

const actions = {
  workflow(id, action) {
    const done = { pause: 'Paused. The run in progress, if any, continues.', resume: 'Resumed.', run: 'The next run is due now.', restore: 'Restored, paused.',
      approve: 'Approved. The run goes out when its worker is ready.', skip: 'Skipped. The workflow waits for its next run.' }[action];
    return perform(() => post(`/api/workflows/${id}/${action}`), done);
  },

  async newWorkflow() {
    const recipe = await recipeDialog();
    if (recipe === undefined) return;
    const created = await workflowDialog({
      template: recipe ? recipeTemplate(recipe) : null,
      connections: app.data.connections,
      workflows: app.data.workflows,
      archived: app.data.archived,
      submit: fields => post('/api/workflows', fields)
    });
    if (created) await refresh();
  },

  async editWorkflow(workflow) {
    const saved = await workflowDialog({
      workflow,
      connections: app.data.connections,
      workflows: app.data.workflows,
      archived: app.data.archived,
      submit(fields) {
        const patch = Object.fromEntries(Object.entries(fields)
          .filter(([key, value]) => JSON.stringify(workflow[key]) !== JSON.stringify(value)));
        return Object.keys(patch).length ? request(`/api/workflows/${workflow.id}`, { method: 'PATCH', body: patch }) : null;
      }
    });
    if (saved) await refresh();
  },

  async archiveWorkflow(workflow) {
    const confirmed = await confirmDialog({
      title: `Archive “${workflow.name}”?`,
      body: [h('p', null, 'It stops dispatching and leaves the workflow list. Its runs stay in the history, and you can restore it at any time.')],
      confirmLabel: 'Archive workflow'
    });
    if (!confirmed) return;
    await perform(() => post(`/api/workflows/${workflow.id}/archive`), 'Archived.');
    location.hash = '#/workflows';
  },

  async cancelRun(run) {
    const confirmed = await confirmDialog({
      title: 'Cancel this run?',
      body: [h('p', null, 'The worker is asked to stop. The run ends when the worker confirms it stopped; it may also finish anyway. ',
        'A cancelled run does not count against the failure limit.')],
      confirmLabel: 'Cancel run',
      danger: true
    });
    if (confirmed) await perform(() => post(`/api/runs/${run.id}/cancel`), 'Cancellation requested.');
  },

  async abandonRun(run) {
    if (await abandonDialog(run)) {
      await perform(() => post(`/api/runs/${run.id}/abandon`, { confirm: run.taskId }), 'Run released.');
    }
  },

  async cancelReview(run) {
    const confirmed = await confirmDialog({
      title: 'Cancel this review task?',
      body: [h('p', null, 'The reviewer agent is asked to stop. When the review task ends without a verdict, ',
        'the result waits for yours.')],
      confirmLabel: 'Cancel review task',
      danger: true
    });
    if (confirmed) await perform(() => post(`/api/runs/${run.id}/review/cancel`), 'Cancellation requested.');
  },

  async abandonReview(run) {
    const task = { taskId: run.reviewTask.taskId };
    if (await abandonDialog(task, { what: 'review task', who: 'reviewer' })) {
      await perform(() => post(`/api/runs/${run.id}/review/abandon`, { confirm: task.taskId }),
        'Review task released. The result waits for your verdict.');
    }
  },

  /** Records a final verdict, then opens `next`, the next result waiting for review, if there is one. */
  async reviewRun(run, verdict, note, next) {
    const body = note.trim() ? { verdict, note } : { verdict };
    try {
      await post(`/api/runs/${run.id}/review`, body);
    } catch (error) {
      toast(error.message, 'error');
      return;
    }
    toast(verdict === 'accepted' ? 'Accepted. It counts as a success.' : 'Rejected. It counts as a failure.');
    if (next) location.hash = `#/runs/${next.id}`;
    else await refresh();
  },

  async moreRuns() {
    await loadHistory({ more: true }).catch(error => toast(error.message, 'error'));
    render();
  },

  async filterRuns(workflowId) {
    app.history = { workflowId, runs: [], nextBefore: null, loaded: false };
    render();
    await loadHistory().catch(error => toast(error.message, 'error'));
    render();
  },

  async moreActivity() {
    await loadLog({ more: true }).catch(error => toast(error.message, 'error'));
    render();
  }
};

// ----- theme, sign-in and start -----------------------------------------------------------

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $('theme').textContent = theme === 'dark' ? 'Light theme' : 'Dark theme';
}

function storedTheme() {
  try {
    return localStorage.getItem('theme');
  } catch {
    return null;
  }
}

applyTheme(storedTheme() ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

$('theme').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try {
    localStorage.setItem('theme', next);
  } catch {
    // The choice then lasts for this page only.
  }
});

$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('login-error').textContent = '';
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: $('token').value.trim() })
    });
    if (!response.ok) throw new Error((await response.json()).error || 'Sign-in failed');
    $('token').value = '';
    await start();
  } catch (error) {
    $('login-error').textContent = error.message;
  }
});

$('logout').addEventListener('click', async () => {
  try {
    await post('/api/logout');
  } finally {
    app.data = null;
    app.signature = '';
    showLogin();
  }
});

// ----- notifications ------------------------------------------------------------------------

// The action items of the last snapshot this page received, and since when others have been absent;
// null until the first snapshot.
let seenAttention = null;

function storedNotify() {
  try {
    return localStorage.getItem('notify') === 'on';
  } catch {
    return false;
  }
}

const notificationsGranted = () => 'Notification' in window && Notification.permission === 'granted';

const BLOCKED = 'Notifications are blocked for this console in the browser\'s site settings';

/** The toggle keeps one label; `aria-pressed` and a check mark say whether it is on. */
function showNotifyButton() {
  const button = $('notify');
  // Browsers without notifications get no button.
  button.hidden = !('Notification' in window);
  if (button.hidden) return;
  const blocked = Notification.permission === 'denied';
  const on = !blocked && storedNotify() && notificationsGranted();
  button.disabled = blocked;
  button.setAttribute('aria-pressed', on ? 'true' : 'false');
  button.title = blocked ? BLOCKED : on ? 'Stop notifying this browser'
    : 'Notify this browser when something new needs you, while this page is open';
}

// An item that disappears for less than this, as while a restarted controller checks its
// workers again, is not new when it returns.
const NOTIFY_GRACE_MS = 120_000;
const NOTIFY_AT_ONCE = 3;

/**
 * Notifies this browser, while the page is open but not in view, of each new
 * attention item that needs the operator to act. Nothing leaves this machine:
 * the browser shows the notification itself.
 */
function notifyAttention(attention) {
  const now = Date.now();
  const items = new Map(attention.filter(item => item.severity === 'action')
    .map(item => [`${item.kind}:${item.subject.type}:${item.subject.id}`, item]));
  if (seenAttention === null) {
    // The first snapshot this page receives is what already needed the operator: nothing is new.
    seenAttention = { present: new Set(items.keys()), absentSince: new Map() };
    return;
  }
  const { present, absentSince } = seenAttention;
  // New: not in the previous snapshot received, and either never seen or seen absent for the grace
  // period. Time between snapshots, such as while the computer slept, never makes an item new.
  const fresh = [...items].filter(([key]) => !present.has(key)
    && (!absentSince.has(key) || now - absentSince.get(key) >= NOTIFY_GRACE_MS));
  for (const key of present) if (!items.has(key) && !absentSince.has(key)) absentSince.set(key, now);
  for (const key of items.keys()) absentSince.delete(key);
  // Long gone items are forgotten; if one returns it is new, as after the grace period.
  for (const [key, at] of absentSince) if (now - at >= NOTIFY_GRACE_MS) absentSince.delete(key);
  seenAttention = { present: new Set(items.keys()), absentSince };
  if (!fresh.length || !storedNotify() || !notificationsGranted() || (!document.hidden && document.hasFocus())) return;
  const show = (title, body, tag) => {
    try {
      const note = new Notification(title, { body, tag });
      note.onclick = () => {
        window.focus();
        note.close();
      };
    } catch {
      // Some browsers only notify through a service worker; the console still shows the items.
    }
  };
  for (const [key, item] of fresh.slice(0, NOTIFY_AT_ONCE)) {
    show(item.subject.type === 'controller' ? 'Peerspan Managed' : item.subject.name, item.message, key);
  }
  const more = fresh.length - NOTIFY_AT_ONCE;
  if (more > 0) show('Peerspan Managed', `${more} more item${more === 1 ? ' needs' : 's need'} you; open the console to see them.`, 'more');
}

$('notify').addEventListener('click', async () => {
  const on = storedNotify() && notificationsGranted();
  let next = !on;
  if (next && Notification.permission !== 'granted') next = (await Notification.requestPermission()) === 'granted';
  try {
    localStorage.setItem('notify', next ? 'on' : 'off');
  } catch {
    // The choice then lasts for this page only.
  }
  showNotifyButton();
  if (next) toast('This browser will be notified when something new needs you, while this page is open.');
  else if (!on && Notification.permission === 'denied') {
    toast(BLOCKED + '.', 'error');
    // The disabled button cannot keep keyboard focus; the page takes it.
    $('view').focus({ preventScroll: true });
  }
});

showNotifyButton();

window.addEventListener('hashchange', navigate);
window.addEventListener('pagehide', stopLive);
setInterval(tickTimes, 5000);

async function start() {
  app.route = parseRoute();
  await refresh();
  if (!app.data) return;
  startLive();
  await navigate();
}

start();
