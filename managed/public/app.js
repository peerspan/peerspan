// Peerspan Managed console: sign-in, routing, live updates and operator actions.
import { h, icon, tickTimes } from './js/dom.js';
import { abandonDialog, confirmDialog, workflowDialog } from './js/dialogs.js';
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
  try {
    const detail = await request('/api/runs/' + id);
    app.runDetail = { id, run: detail.run, events: detail.events, error: null };
  } catch (error) {
    app.runDetail = { id, run: null, events: [], error: error.message };
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
  // Keep keyboard focus on the same control across a refresh.
  const focused = document.activeElement?.dataset?.key;
  view.replaceChildren(...page().flat().filter(Boolean));
  if (focused) view.querySelector(`[data-key="${CSS.escape(focused)}"]`)?.focus({ preventScroll: true });
}

function setLive(on) {
  $('live').className = 'live ' + (on ? 'on' : 'off');
  $('live-text').textContent = on ? 'Live' : 'Reconnecting';
}

/** What a snapshot shows, without the fields that change on every pass. */
function signatureOf(data) {
  return JSON.stringify(data, (key, value) => (key === 'checkedAt' || key === 'lastTickAt' ? undefined : value));
}

async function refresh() {
  let data;
  try {
    data = await request('/api/snapshot');
  } catch {
    if (!$('console').hidden) setLive(false);
    return;
  }
  app.data = data;
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

function showLogin() {
  stopLive();
  $('dialog').close();
  $('console').hidden = true;
  $('login').hidden = false;
  $('token').focus();
}

// ----- operator actions ---------------------------------------------------------------------

const actions = {
  workflow(id, action) {
    const done = { pause: 'Paused. The run in progress, if any, continues.', resume: 'Resumed.', run: 'The next run is due now.', restore: 'Restored, paused.' }[action];
    return perform(() => post(`/api/workflows/${id}/${action}`), done);
  },

  async newWorkflow() {
    const created = await workflowDialog({
      connections: app.data.connections,
      submit: fields => post('/api/workflows', fields)
    });
    if (created) await refresh();
  },

  async editWorkflow(workflow) {
    const saved = await workflowDialog({
      workflow,
      connections: app.data.connections,
      submit(fields) {
        const patch = Object.fromEntries(Object.entries(fields).filter(([key, value]) => workflow[key] !== value));
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
