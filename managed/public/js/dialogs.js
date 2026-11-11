// Modal dialogs: one <dialog> element whose content is rebuilt for each use.
import { h, icon, shortId } from './dom.js';

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

function splitInterval(minutes) {
  const [unit, size] = [...UNITS].reverse().find(([, factor]) => minutes % factor === 0);
  return { amount: minutes / size, unit };
}

/**
 * Create (no `workflow`) or edit a workflow. `submit(fields)` performs the
 * request; its error message is shown in the form and the dialog stays open.
 */
export function workflowDialog({ workflow = null, connections, submit }) {
  const editing = workflow !== null;
  const interval = splitInterval(workflow?.intervalMinutes ?? 60);
  return show(editing ? 'Edit workflow' : 'New workflow', close => {
    const error = h('p.form-error', { role: 'alert' });
    const save = h('button.button.primary', { type: 'submit' }, editing ? 'Save changes' : 'Create workflow');
    const form = h('form', null,
      h('label', { for: 'wf-name' }, 'Name'),
      h('input', { id: 'wf-name', name: 'name', maxlength: '100', required: true, autofocus: true, value: workflow?.name ?? '', placeholder: 'Weekly repository maintenance' }),
      h('label', { for: 'wf-connection' }, 'Worker'),
      h('select', { id: 'wf-connection', name: 'connectionId', required: true },
        connections.map(connection => h('option', { value: connection.id, selected: connection.id === workflow?.connectionId },
          connection.name + (connection.readiness.ready ? '' : ' (not ready)')))),
      h('p.help', null, 'The worker uses its own workspace and model configuration.'),
      h('label', { for: 'wf-instructions' }, 'Assignment'),
      h('textarea', { id: 'wf-instructions', name: 'instructions', maxlength: '12000', required: true, rows: '6',
        placeholder: 'Describe a bounded assignment, the result you expect, and the checks it must pass.' }, workflow?.instructions ?? ''),
      h('div.field-row', null,
        h('div', null,
          h('label', { for: 'wf-interval' }, 'Repeat every'),
          h('div.interval', null,
            h('input', { id: 'wf-interval', name: 'amount', type: 'number', min: '1', max: '10080', required: true, value: String(interval.amount) }),
            h('select', { name: 'unit', 'aria-label': 'Interval unit' },
              UNITS.map(([unit]) => h('option', { value: unit, selected: unit === interval.unit }, unit))))),
        h('div', null,
          h('label', { for: 'wf-cap' }, 'Daily run limit'),
          h('input', { id: 'wf-cap', name: 'maxRunsPerDay', type: 'number', min: '1', max: '1000', required: true, value: String(workflow?.maxRunsPerDay ?? 12) })),
        h('div', null,
          h('label', { for: 'wf-acceptance' }, 'Acceptance window (min)'),
          h('input', { id: 'wf-acceptance', name: 'acceptanceMinutes', type: 'number', min: '1', max: '1440', required: true, value: String(workflow?.acceptanceMinutes ?? 60) }))),
      h('p.help', null, 'The interval counts from the end of the previous run. The daily limit counts dispatches, not model cost. ',
        'A run the worker has not accepted within the window expires.'),
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
      const values = Object.fromEntries(new FormData(form));
      const factor = UNITS.find(([unit]) => unit === values.unit)[1];
      const fields = {
        name: values.name,
        connectionId: values.connectionId,
        instructions: values.instructions,
        intervalMinutes: Number(values.amount) * factor,
        maxRunsPerDay: Number(values.maxRunsPerDay),
        acceptanceMinutes: Number(values.acceptanceMinutes)
      };
      if (!editing) fields.enabled = form.elements.enabled.checked;
      save.disabled = true;
      error.textContent = '';
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
