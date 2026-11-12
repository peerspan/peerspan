// Modal dialogs: one <dialog> element whose content is rebuilt for each use.
import { h, icon, shortId } from './dom.js';
import { DAYS } from './labels.js';

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

/** Releasing a run does not stop remote work; the operator must acknowledge that first. */
export function abandonDialog(run) {
  return show('Release this run?', close => {
    const acknowledge = h('input', { type: 'checkbox', id: 'abandon-ack' });
    const confirm = h('button.button.danger.solid', { type: 'button', disabled: true, onclick: () => close(true) }, 'Release run');
    acknowledge.addEventListener('change', () => { confirm.disabled = !acknowledge.checked; });
    return [
      h('div.dialog-body', null,
        h('p', null, 'Release a run only when it can no longer be resolved, for example because its worker host no longer exists.'),
        h('div.callout.danger', null, icon('alert'),
          h('span', null, 'Releasing does not stop the worker. If it is still working on task ', h('code', null, shortId(run.taskId)),
            ', that work continues, its result is not collected, and the next run may reach the same agent while it is busy.')),
        h('p', null, 'To stop a worker that can still be reached, cancel the run instead.'),
        h('label.check', { for: 'abandon-ack' }, acknowledge, 'I understand that the worker may still be running this task.')),
      h('div.dialog-actions', null,
        h('button.button', { type: 'button', autofocus: true, onclick: () => close(false) }, 'Keep the run'),
        confirm)
    ];
  }).then(Boolean);
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
 * Create (no `workflow`) or edit a workflow. `submit(fields)` performs the
 * request; its error message is shown in the form and the dialog stays open.
 */
export function workflowDialog({ workflow = null, connections, submit }) {
  const editing = workflow !== null;
  const interval = splitInterval(workflow?.intervalMinutes ?? 60);
  const planned = workflow?.schedule ?? null;
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
    const modes = h('div.segmented', { role: 'radiogroup', 'aria-label': 'When it runs' },
      h('label', null, h('input', { type: 'radio', name: 'when', value: 'interval', checked: !planned }), h('span', null, 'After an interval')),
      h('label', null, h('input', { type: 'radio', name: 'when', value: 'schedule', checked: Boolean(planned) }), h('span', null, 'On days and times')));
    const showMode = () => {
      const scheduled = modes.querySelector('input:checked').value === 'schedule';
      intervalPart.hidden = scheduled;
      schedulePart.hidden = !scheduled;
    };
    modes.addEventListener('change', showMode);
    showMode();
    const form = h('form', null,
      h('label', { for: 'wf-name' }, 'Name'),
      h('input', { id: 'wf-name', name: 'name', maxlength: '100', required: true, autofocus: true, value: workflow?.name ?? '', placeholder: 'Weekly repository maintenance' }),
      h('label', { for: 'wf-connection' }, 'Worker'),
      h('select', { id: 'wf-connection', name: 'connectionId', required: true },
        // A workflow whose worker was disconnected keeps it until another one is chosen.
        editing && !connections.some(connection => connection.id === workflow.connectionId)
          && h('option', { value: workflow.connectionId, selected: true }, 'Disconnected worker (choose another)'),
        connections.map(connection => h('option', { value: connection.id, selected: connection.id === workflow?.connectionId },
          connection.name + (connection.readiness.ready ? '' : ' (not ready)')))),
      h('p.help', null, 'The worker uses its own workspace and model configuration.'),
      h('label', { for: 'wf-instructions' }, 'Assignment'),
      h('textarea', { id: 'wf-instructions', name: 'instructions', maxlength: '12000', required: true, rows: '6',
        placeholder: 'Describe a bounded assignment, the result you expect, and the checks it must pass.' }, workflow?.instructions ?? ''),
      h('div.when', null, h('span.label', null, 'When it runs'), modes, intervalPart, schedulePart),
      h('div.field-row.two', null,
        h('div', null,
          h('label', { for: 'wf-cap' }, 'Daily run limit'),
          h('input', { id: 'wf-cap', name: 'maxRunsPerDay', type: 'number', min: '1', max: '1000', required: true, value: String(workflow?.maxRunsPerDay ?? 12) })),
        h('div', null,
          h('label', { for: 'wf-acceptance' }, 'Acceptance window (min)'),
          h('input', { id: 'wf-acceptance', name: 'acceptanceMinutes', type: 'number', min: '1', max: '1440', required: true, value: String(workflow?.acceptanceMinutes ?? 60) }))),
      h('p.help', null, 'The daily limit counts dispatches per UTC day, not model cost. ',
        'A run the worker has not accepted within the window expires.'),
      h('label.check', { for: 'wf-review' },
        h('input', { id: 'wf-review', name: 'review', type: 'checkbox', checked: workflow?.review === 'operator' }),
        h('span', null, 'Hold each result for my review', h('span.help.block', null,
          'A succeeded run counts as a success only once you accept it. Reviews never hold back the schedule.'))),
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
        review: form.elements.review.checked ? 'operator' : 'none'
      };
      error.textContent = '';
      if (values.when === 'schedule') {
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
