// Modal dialogs: one <dialog> element whose content is rebuilt for each use.
import { h, icon, shortId } from './dom.js';
import { DAYS, schedule } from './labels.js';
import { RECIPES } from './recipes.js';

const REVIEW_MODES = [['none', 'As reported'], ['operator', 'I check them'], ['agent', 'An agent checks them']];
const REWORK_CHOICES = ['Count it as a failure', 'Send it back once with the review', 'Send it back up to twice',
  'Send it back up to three times'];

// Result checks (contract section 15.3): the label of each kind and the value it takes.
const CHECK_KINDS = [
  ['contains', 'Must contain', 'text'],
  ['excludes', 'Must not contain', 'text'],
  ['minLength', 'At least this many characters', 'chars'],
  ['maxLength', 'At most this many characters', 'chars'],
  ['jsonKeys', 'Is a JSON object with the keys', 'keys'],
  ['branch', 'Ends with a committed branch line', null]
];
const MAX_CHECKS = 8;

/**
 * The result checks editor. `read()` returns the checks, or throws a message for
 * the form; `onChange` hears when checks are added or removed.
 */
function checksPart(workflow, onChange) {
  const list = h('ol.checks-edit');
  const add = h('button.button.small', { type: 'button' }, icon('plus'), 'Add a check');
  // `saved` is a check the workflow already has, or null for a new row.
  const row = (saved = null) => {
    const check = saved ?? { kind: 'contains', text: '' };
    const kind = h('select', { 'aria-label': 'Check' },
      CHECK_KINDS.map(([value, label]) => h('option', { value, selected: value === check.kind }, label)));
    const value = h('input', { 'aria-label': 'Check value', autocomplete: 'off', spellcheck: 'false' });
    // Attributes that do not apply to a kind are removed, never set to an empty or negative value.
    const attribute = (name, text) => (text === null ? value.removeAttribute(name) : value.setAttribute(name, text));
    const sync = () => {
      const field = CHECK_KINDS.find(([name]) => name === kind.value)[2];
      value.hidden = field === null;
      value.type = field === 'chars' ? 'number' : 'text';
      attribute('min', field === 'chars' ? '1' : null);
      attribute('max', field === 'chars' ? '262144' : null);
      // No maxlength: browsers count UTF-16 units, the contract code points; the controller checks the length.
      attribute('placeholder', field === 'text' ? 'Exact text, such as ## Summary' : field === 'keys' ? 'summary, links, count' : null);
    };
    value.value = check.text ?? (check.chars !== undefined ? String(check.chars) : check.keys?.join(', ') ?? '');
    kind.addEventListener('change', () => { value.value = ''; sync(); });
    sync();
    // A text input drops line breaks and keys are split at commas, so a stored check the operator
    // leaves alone is kept exactly as it is, never rebuilt from what the form shows.
    const shown = { kind: check.kind, value: value.value };
    const item = h('li', null, kind, value,
      h('button.button.quiet.icon-button', { type: 'button', 'aria-label': 'Remove this check',
        onclick: () => { item.remove(); refresh(); } }, icon('close')));
    if (saved) stored.set(item, () => (kind.value === shown.kind && value.value === shown.value ? saved : null));
    return item;
  };
  const stored = new WeakMap();
  const refresh = () => {
    add.disabled = list.children.length >= MAX_CHECKS;
    onChange(list.children.length);
  };
  add.addEventListener('click', () => {
    list.append(row());
    refresh();
    list.lastElementChild.querySelector('input:not([hidden])')?.focus();
  });
  for (const check of workflow?.resultChecks ?? []) list.append(row(check));
  add.disabled = list.children.length >= MAX_CHECKS;
  const read = () => [...list.children].map(item => {
    const unchanged = stored.get(item)?.();
    if (unchanged) return unchanged;
    const kind = item.querySelector('select').value;
    const value = item.querySelector('input').value;
    const field = CHECK_KINDS.find(([name]) => name === kind)[2];
    if (field === null) return { kind };
    if (field === 'text') {
      if (!value.trim()) throw new Error('Give each text check the text to look for.');
      return { kind, text: value };
    }
    if (field === 'chars') {
      const chars = Number(value);
      if (!Number.isInteger(chars) || chars < 1 || chars > 262_144) throw new Error('A length check counts 1 to 262,144 characters.');
      return { kind, chars };
    }
    const keys = [...new Set(value.split(',').map(key => key.trim()).filter(Boolean))];
    if (!keys.length || keys.length > 16) throw new Error('List 1 to 16 JSON keys, separated by commas.');
    return { kind, keys };
  });
  const node = h('div.when-part', null,
    h('span.label', null, 'Checks before review'),
    list, add,
    h('p.help', null, 'The controller checks each result itself, with no model call, before anyone reviews it. ',
      'A result that fails a check is rejected at once, and the failed checks are its review.'));
  return { node, read, count: () => list.children.length, refresh };
}

/** The "Results" part of the workflow form: who checks results, the criteria, and what a rejection does. */
function resultsPart(workflow, connections, workerSelect) {
  const mode = workflow?.review ?? 'none';
  const modes = h('div.segmented', { role: 'radiogroup', 'aria-label': 'Who checks results' },
    REVIEW_MODES.map(([value, label]) => h('label', null,
      h('input', { type: 'radio', name: 'review', value, checked: value === mode }), h('span', null, label))));
  const sameAgent = (a, b) => a && b && a.hostId === b.hostId && a.agentId === b.agentId;
  const worker = () => connections.find(connection => connection.id === workerSelect.value);
  const firstOther = connections.find(connection => !sameAgent(connection, worker()));
  const chosen = workflow?.reviewerId ?? firstOther?.id ?? '';
  const reviewer = h('select', { id: 'wf-reviewer', name: 'reviewerId' },
    workflow?.reviewerId && !connections.some(connection => connection.id === workflow.reviewerId)
      && h('option', { value: workflow.reviewerId, selected: true }, 'Disconnected reviewer (choose another)'),
    connections.map(connection => h('option', { value: connection.id, selected: connection.id === chosen },
      connection.name + (connection.readiness.ready ? '' : ' (not ready)'))));
  // The worker cannot review its own results: its agent is not offered as the reviewer.
  const syncReviewer = () => {
    for (const option of reviewer.options) {
      option.disabled = sameAgent(connections.find(connection => connection.id === option.value), worker());
    }
    if (reviewer.selectedOptions[0]?.disabled) reviewer.value = [...reviewer.options].find(option => !option.disabled)?.value ?? '';
  };
  workerSelect.addEventListener('change', syncReviewer);
  syncReviewer();
  const agentPart = h('div.when-part', null,
    h('label', { for: 'wf-reviewer' }, 'Reviewer agent'),
    reviewer,
    h('p.help', null, 'Another agent than the worker. It is sent the assignment, your criteria and the result, and answers ',
      'ACCEPT or REJECT with its reasons. When it gives no verdict, the result waits for you.'));
  const criteriaPart = h('div.when-part', null,
    h('label', { for: 'wf-criteria' }, 'Review criteria'),
    h('textarea', { id: 'wf-criteria', name: 'reviewCriteria', maxlength: '2000', rows: '3',
      placeholder: 'What a good result must do, such as: names every changed file and cites at least two sources.' },
    workflow?.reviewCriteria ?? ''));
  const reworkPart = h('div.when-part', null,
    h('label', { for: 'wf-rework' }, 'When a result is rejected'),
    h('select', { id: 'wf-rework', name: 'reworkLimit' },
      REWORK_CHOICES.map((label, limit) => h('option', { value: String(limit), selected: limit === (workflow?.reworkLimit ?? 0) }, label))),
    h('p.help', null, 'A rejected result counts as a failure. Sending it back runs the assignment again at once with the ',
      'review and the previous result; each rework counts toward the daily limit.'));
  // A rejection by checks can be sent back too, whoever reviews the results.
  const show = () => {
    const current = modes.querySelector('input:checked').value;
    agentPart.hidden = current !== 'agent';
    criteriaPart.hidden = current === 'none';
    reworkPart.hidden = current === 'none' && checks.count() === 0;
  };
  const checks = checksPart(workflow, () => show());
  modes.addEventListener('change', show);
  show();
  const node = h('div.when', null, h('span.label', null, 'Results'), modes, agentPart, criteriaPart, checks.node, reworkPart);
  return { node, readChecks: checks.read, reworkShown: () => !reworkPart.hidden };
}

const element = () => document.getElementById('dialog');

/**
 * Shows a dialog. `build(close)` returns its body nodes; the promise resolves
 * with whatever `close(value)` is given, or undefined when it is dismissed.
 */
function show(title, build) {
  const dialog = element();
  return new Promise(resolve => {
    let result;
    const close = value => {
      result = value;
      dialog.close();
    };
    dialog.replaceChildren(
      h('div.dialog-head', null,
        h('h2', { id: 'dialog-title' }, title),
        h('button.button.quiet.icon-button', { type: 'button', 'aria-label': 'Close', onclick: () => close(undefined) }, icon('close'))),
      ...build(close));
    dialog.addEventListener('close', () => resolve(result), { once: true });
    dialog.showModal();
  });
}

export function confirmDialog({ title, body, confirmLabel, danger = false }) {
  return show(title, close => [
    h('div.dialog-body', null, body),
    h('div.dialog-actions', null,
      h('button.button', { type: 'button', autofocus: true, onclick: () => close(false) }, 'Keep as it is'),
      h('button.button', { class: danger ? 'danger solid' : 'primary', type: 'button', onclick: () => close(true) }, confirmLabel))
  ]).then(Boolean);
}

/**
 * Releasing a run or a review task does not stop remote work; the operator must
 * acknowledge that first. `what` and `who` name the task and the agent doing it.
 */
export function abandonDialog(run, { what = 'run', who = 'worker' } = {}) {
  return show(`Release this ${what}?`, close => {
    const acknowledge = h('input', { type: 'checkbox', id: 'abandon-ack' });
    const confirm = h('button.button.danger.solid', { type: 'button', disabled: true, onclick: () => close(true) }, `Release ${what}`);
    acknowledge.addEventListener('change', () => { confirm.disabled = !acknowledge.checked; });
    return [
      h('div.dialog-body', null,
        h('p', null, `Release a ${what} only when it can no longer be resolved, for example because its ${who}'s host no longer exists.`),
        h('div.callout.danger', null, icon('alert'),
          h('span', null, `Releasing does not stop the ${who}. If it is still working on task `, h('code', null, shortId(run.taskId)),
            `, that work continues, its result is not collected, and new work may reach the same agent while it is busy.`)),
        h('p', null, `To stop a ${who} that can still be reached, cancel the ${what} instead.`),
        h('label.check', { for: 'abandon-ack' }, acknowledge, `I understand that the ${who} may still be running this task.`)),
      h('div.dialog-actions', null,
        h('button.button', { type: 'button', autofocus: true, onclick: () => close(false) }, `Keep the ${what}`),
        confirm)
    ];
  }).then(Boolean);
}

/**
 * Where a new workflow starts: a blank form or a recipe. Resolves the recipe,
 * null for a blank form, or undefined when the dialog is dismissed.
 */
export function recipeDialog() {
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return show('New workflow', close => [
    h('div.dialog-body', null,
      h('p', null, 'Start from a blank form, or from a recipe to adapt. Nothing is created until you have read and saved the form.'),
      h('div.recipes', null,
        h('button.recipe', { type: 'button', onclick: () => close(null), autofocus: true },
          h('strong', null, 'Blank workflow'), h('span', null, 'Write your own assignment.')),
        RECIPES.map(recipe => h('button.recipe', { type: 'button', onclick: () => close(recipe), 'data-recipe': recipe.id },
          h('strong', null, recipe.name),
          h('span', null, recipe.summary),
          h('span.recipe-meta', null, schedule({ schedule: { ...recipe.schedule, timeZone: zone } }, { zone: false }),
            recipe.review === 'operator' ? ' · you check results' : ''))))),
    h('div.dialog-actions', null,
      h('button.button', { type: 'button', onclick: () => close(undefined) }, 'Cancel'))
  ]);
}

const UNITS = [['minutes', 1], ['hours', 60], ['days', 1440]];
const WEEKDAYS = DAYS.slice(0, 5).map(([value]) => value);

function splitInterval(minutes) {
  const [unit, size] = [...UNITS].reverse().find(([, factor]) => minutes % factor === 0);
  return { amount: minutes / size, unit };
}

/** The time zones the browser knows, with this browser's own zone and UTC always present. */
function timeZones(selected) {
  let zones = [];
  try {
    zones = Intl.supportedValuesOf('timeZone');
  } catch {
    // Older browsers: the selected and local zones are still offered.
  }
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return [...new Set([selected, local, 'UTC', ...zones].filter(Boolean))].sort((a, b) =>
    (a === 'UTC' ? -1 : b === 'UTC' ? 1 : a.localeCompare(b)));
}

/** "9:00, 17:30 13:05" as sorted distinct HH:MM times, or null when one of them is not a time of day. */
function parseTimes(text) {
  const parts = text.split(/[\s,;]+/).filter(Boolean);
  const times = [];
  for (const part of parts) {
    const match = /^(\d{1,2}):(\d{2})$/.exec(part);
    if (!match || Number(match[1]) > 23 || Number(match[2]) > 59) return null;
    times.push(match[1].padStart(2, '0') + ':' + match[2]);
  }
  return [...new Set(times)].sort();
}

/**
 * Create (no `workflow`, optionally from a recipe's `template`) or edit a workflow. `submit(fields)` performs the
 * request; its error message is shown in the form and the dialog stays open.
 */
export function workflowDialog({ workflow = null, template = null, connections, workflows = [], archived = [], submit }) {
  const editing = workflow !== null;
  // The form starts from the workflow being edited, or from a recipe.
  const initial = workflow ?? template;
  const interval = splitInterval(initial?.intervalMinutes ?? 60);
  const planned = initial?.schedule ?? null;
  const upstreamId = initial?.after?.workflowId ?? null;
  // A workflow may run after any other one whose own chain of upstreams never leads back to it,
  // archived workflows included, as the controller checks it (section 14.1).
  const everyWorkflow = [...workflows, ...archived];
  const leadsBack = candidate => {
    const seen = new Set();
    for (let at = candidate; at && !seen.has(at.id); at = everyWorkflow.find(item => item.id === at.after?.workflowId)) {
      if (editing && at.id === workflow.id) return true;
      seen.add(at.id);
    }
    return false;
  };
  return show(editing ? 'Edit workflow' : 'New workflow', close => {
    const error = h('p.form-error', { role: 'alert' });
    const save = h('button.button.primary', { type: 'submit' }, editing ? 'Save changes' : 'Create workflow');
    const intervalPart = h('div.when-part', null,
      h('label', { for: 'wf-interval' }, 'Repeat every'),
      h('div.interval', null,
        h('input', { id: 'wf-interval', name: 'amount', type: 'number', min: '1', max: '10080', value: String(interval.amount) }),
        h('select', { name: 'unit', 'aria-label': 'Interval unit' },
          UNITS.map(([unit]) => h('option', { value: unit, selected: unit === interval.unit }, unit)))),
      h('p.help', null, 'Counted from the end of the previous run.'));
    const days = planned?.days ?? WEEKDAYS;
    const schedulePart = h('div.when-part', null,
      h('fieldset.days', null,
        h('legend', null, 'Days'),
        DAYS.map(([value, label]) => h('label.day', null,
          h('input', { type: 'checkbox', name: 'day', value, checked: days.includes(value) }), h('span', null, label)))),
      h('div.field-row.two', null,
        h('div', null,
          h('label', { for: 'wf-times' }, 'Times'),
          h('input', { id: 'wf-times', name: 'times', value: (planned?.times ?? ['09:00']).join(', '), placeholder: '09:00, 17:30',
            autocomplete: 'off', spellcheck: 'false' })),
        h('div', null,
          h('label', { for: 'wf-zone' }, 'Time zone'),
          h('select', { id: 'wf-zone', name: 'timeZone' },
            timeZones(planned?.timeZone).map(zone => h('option', { value: zone, selected: zone === (planned?.timeZone ?? Intl.DateTimeFormat().resolvedOptions().timeZone) }, zone))))),
      h('p.help', null, 'Local times, 24-hour. A slot that passes while a run is in progress or the workflow is paused runs once, as soon as it can.'));
    // Handoffs (contract section 14.1): the workflows this one may run after.
    const candidates = workflows.filter(item => !editing || item.id !== workflow.id);
    // The current upstream stays selectable when it was archived since, so that other fields can be saved.
    const archivedUpstream = upstreamId && !candidates.some(item => item.id === upstreamId)
      ? archived.find(item => item.id === upstreamId) ?? { id: upstreamId, name: 'A workflow that no longer exists' } : null;
    const upstreamSelect = h('select', { id: 'wf-after', name: 'afterId' },
      archivedUpstream && h('option', { value: upstreamId, selected: true }, `${archivedUpstream.name} (archived)`),
      candidates.map(item => h('option', { value: item.id, selected: item.id === upstreamId, disabled: leadsBack(item) },
        item.name + (leadsBack(item) ? ' (it runs after this one)' : ''))));
    const afterPart = h('div.when-part', null,
      h('label', { for: 'wf-after' }, 'Run after'),
      candidates.length || archivedUpstream ? upstreamSelect : h('p.help', null, 'Create the workflow it should run after first.'),
      h('p.help', null, 'Each result of that workflow that counts as a success, by passing its checks and review, ',
        'becomes this workflow\'s next input. When several arrive before it runs, the latest is used.'));
    const mode = upstreamId ? 'after' : planned ? 'schedule' : 'interval';
    const modes = h('div.segmented', { role: 'radiogroup', 'aria-label': 'When it runs' },
      h('label', null, h('input', { type: 'radio', name: 'when', value: 'interval', checked: mode === 'interval' }), h('span', null, 'After an interval')),
      h('label', null, h('input', { type: 'radio', name: 'when', value: 'schedule', checked: mode === 'schedule' }), h('span', null, 'On days and times')),
      h('label', null, h('input', { type: 'radio', name: 'when', value: 'after', checked: mode === 'after' }), h('span', null, 'After another workflow')));
    const showMode = () => {
      const chosen = modes.querySelector('input:checked').value;
      intervalPart.hidden = chosen !== 'interval';
      schedulePart.hidden = chosen !== 'schedule';
      afterPart.hidden = chosen !== 'after';
    };
    modes.addEventListener('change', showMode);
    showMode();
    const workerSelect = h('select', { id: 'wf-connection', name: 'connectionId', required: true },
      // A workflow whose worker was disconnected keeps it until another one is chosen.
      editing && !connections.some(connection => connection.id === workflow.connectionId)
        && h('option', { value: workflow.connectionId, selected: true }, 'Disconnected worker (choose another)'),
      connections.map(connection => h('option', { value: connection.id, selected: connection.id === workflow?.connectionId },
        connection.name + (connection.readiness.ready ? '' : ' (not ready)'))));
    const results = resultsPart(initial, connections, workerSelect);
    const form = h('form', null,
      h('label', { for: 'wf-name' }, 'Name'),
      h('input', { id: 'wf-name', name: 'name', maxlength: '100', required: true, autofocus: true, value: initial?.name ?? '', placeholder: 'Weekly repository maintenance' }),
      h('label', { for: 'wf-connection' }, 'Worker'),
      workerSelect,
      h('p.help', null, 'The worker uses its own workspace and model configuration.'),
      h('label', { for: 'wf-instructions' }, 'Assignment'),
      h('textarea', { id: 'wf-instructions', name: 'instructions', maxlength: '12000', required: true, rows: '6',
        placeholder: 'Describe a bounded assignment, the result you expect, and the checks it must pass.' }, initial?.instructions ?? ''),
      h('div.when', null, h('span.label', null, 'When it runs'), modes, intervalPart, schedulePart, afterPart),
      // Approval before each run (contract section 14.2).
      h('div.when', null, h('span.label', null, 'Before each run'),
        h('div.segmented', { role: 'radiogroup', 'aria-label': 'Before each run' },
          h('label', null, h('input', { type: 'radio', name: 'approval', value: 'none', checked: (initial?.approval ?? 'none') === 'none' }),
            h('span', null, 'Run without asking')),
          h('label', null, h('input', { type: 'radio', name: 'approval', value: 'operator', checked: initial?.approval === 'operator' }),
            h('span', null, 'Wait for my approval'))),
        h('p.help', null, 'With approval, each run waits until you approve it; skipping passes on that run. ',
          'Nothing is sent before you decide, and alerts tell you when a run waits.')),
      h('div.field-row.two', null,
        h('div', null,
          h('label', { for: 'wf-cap' }, 'Daily run limit'),
          h('input', { id: 'wf-cap', name: 'maxRunsPerDay', type: 'number', min: '1', max: '1000', required: true, value: String(initial?.maxRunsPerDay ?? 12) })),
        h('div', null,
          h('label', { for: 'wf-acceptance' }, 'Acceptance window (min)'),
          h('input', { id: 'wf-acceptance', name: 'acceptanceMinutes', type: 'number', min: '1', max: '1440', required: true, value: String(initial?.acceptanceMinutes ?? 60) }))),
      h('p.help', null, 'The daily limit counts dispatches per UTC day, not model cost. ',
        'A run the worker has not accepted within the window expires.'),
      results.node,
      !editing && h('label.check', { for: 'wf-enabled' },
        h('input', { id: 'wf-enabled', name: 'enabled', type: 'checkbox' }), 'Start dispatching as soon as it is created'),
      !editing && h('p.help', null, 'Otherwise it is created paused. Three consecutive failed runs pause a workflow automatically.'),
      editing && h('p.help', null, 'Changes apply from the next dispatch. A run that is already in progress keeps the instructions it was sent.'),
      error,
      h('div.dialog-actions', null,
        h('button.button', { type: 'button', onclick: () => close(false) }, 'Cancel'),
        save));

    form.addEventListener('submit', async event => {
      event.preventDefault();
      const data = new FormData(form);
      const values = Object.fromEntries(data);
      const fields = {
        name: values.name,
        connectionId: values.connectionId,
        instructions: values.instructions,
        maxRunsPerDay: Number(values.maxRunsPerDay),
        acceptanceMinutes: Number(values.acceptanceMinutes),
        review: values.review,
        reviewerId: values.review === 'agent' ? values.reviewerId || null : null,
        // Hidden while results are counted as reported; the stored values are kept then.
        reviewCriteria: values.review === 'none' ? workflow?.reviewCriteria ?? null : values.reviewCriteria.trim() || null,
        reworkLimit: results.reworkShown() ? Number(values.reworkLimit) : workflow?.reworkLimit ?? 0,
        approval: values.approval
      };
      error.textContent = '';
      try {
        fields.resultChecks = results.readChecks();
      } catch (problem) {
        return void (error.textContent = problem.message);
      }
      if (fields.review === 'agent' && !fields.reviewerId) return void (error.textContent = 'Choose another agent as the reviewer.');
      if (values.when === 'after') {
        if (!values.afterId) return void (error.textContent = 'Choose the workflow it runs after.');
        fields.after = { workflowId: values.afterId };
      } else if (values.when === 'schedule') {
        const times = parseTimes(values.times);
        const chosen = data.getAll('day');
        if (!chosen.length) return void (error.textContent = 'Choose at least one day.');
        if (!times?.length || times.length > 24) return void (error.textContent = 'Enter 1 to 24 times of day, such as 09:00, 17:30.');
        fields.schedule = { timeZone: values.timeZone, days: chosen, times };
      } else {
        const amount = Number(values.amount);
        if (!Number.isInteger(amount) || amount < 1) return void (error.textContent = 'Enter how often it repeats.');
        fields.intervalMinutes = amount * UNITS.find(([unit]) => unit === values.unit)[1];
      }
      if (!editing) fields.enabled = form.elements.enabled.checked;
      save.disabled = true;
      try {
        await submit(fields);
        close(true);
      } catch (failure) {
        error.textContent = failure.message;
        save.disabled = false;
      }
    });
    return [form];
  }).then(Boolean);
}
