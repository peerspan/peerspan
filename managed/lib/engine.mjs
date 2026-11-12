// The scheduler. It owns timing and every Peerspan call; all state decisions
// are atomic store operations (model.mjs), so an operator request never waits
// for a subprocess and no interleaving can break the exclusion rules.
import { nowMs, stamp } from './clock.mjs';
import { capacityOf, checkReadiness } from './readiness.mjs';
import { OUTPUT_LIMIT } from './model.mjs';

const OPEN = new Set(['submitting', 'queued', 'running']);
const FINAL = new Set(['succeeded', 'failed', 'rejected', 'expired', 'cancelled']);
// At most this many readiness checks, reconciliations and submissions at once, across passes.
const BACKGROUND_LIMIT = 8;
// A pass waits this long for the work it started, then dispatches with what it knows (MGD-15).
const PASS_WAIT_MS = 2000;
const POKE_DELAY_MS = 20;
// A long task's older progress may be skipped, never its newest events. Progress
// messages can be 64 KiB each, so the window keeps a fetch well inside the 4 MiB
// output limit of one Peerspan call.
const EVENT_FETCH_WINDOW = 50;
const MESSAGE_LIMIT = 2000;

// A remote connection's directory is refreshed on its first check and at most this often after (MGD-7).
const DIRECTORY_REFRESH_MS = 60_000;

const PROBLEM = 'Delivery or status uncertain; retaining this task identity';
const CONTROLLER_PROBLEM = 'Controller check failed; inspect local service logs';

/** Resolves when `promise` settles or `ms` pass, whichever is first; never rejects. */
async function waitAtMost(promise, ms) {
  let timer;
  await Promise.race([promise.catch(() => {}), new Promise(resolve => { timer = setTimeout(resolve, ms); })]);
  clearTimeout(timer);
}

/** The task state a local record implies, or null while delivery is unresolved. */
function stateOf(record) {
  if (typeof record?.status?.state === 'string') return record.status.state;
  if (record?.submit_state === 'rejected') return 'rejected';
  if (record?.submit_state === 'accepted') return 'queued';
  return null;
}

const text = (value, limit) => (typeof value === 'string' && value.length ? value.slice(0, limit) : null);
// Remote text is shown to the operator: drop control characters, keep line breaks.
const printable = value => (value === null ? null : value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, ''));
const singleLine = value => (value === null ? null : value.replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ').trim() || null);

function time(value) {
  const ms = typeof value === 'string' ? Date.parse(value) : NaN;
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/** Upstream events newer than `after`, ascending, in the retained shape plus `output`. */
function normalizeEvents(events, after) {
  if (!Array.isArray(events)) throw new Error('Peerspan returned invalid task events');
  return events
    .filter(event => event && Number.isInteger(event.sequence) && event.sequence > after && typeof event.kind === 'string')
    .map(event => ({
      sequence: event.sequence,
      kind: event.kind.slice(0, 32),
      state: text(event.state, 32),
      message: printable(text(event.message, MESSAGE_LIMIT)),
      at: time(event.created_at),
      output: event.output
    }))
    .sort((a, b) => a.sequence - b.sequence);
}

export class Engine {
  constructor(store, peerspan, { tickMs = 10_000 } = {}) {
    this.store = store;
    this.peerspan = peerspan;
    this.tickMs = tickMs;
    this.readiness = new Map();
    // When each remote connection's last check that refreshed the sender's directory began.
    this.refreshedAt = new Map();
    // When each connection's latest check ended, and when dispatch last decided, on the monotonic
    // clock: dispatch uses only verdicts from checks that ended since its previous decision (MGD-15).
    this.checkEndedAt = new Map();
    this.dispatchedAt = -Infinity;
    this.listeners = new Set();
    this.bootId = Date.now().toString(36);
    this.changes = 0;
    this.lastTickAt = null;
    this.error = null;
    this.errorSince = null;
    this.running = false;
    this.passing = null;
    this.again = false;
    this.timer = null;
    this.dataVersion = null;
    // Tasks with a Peerspan call in flight; no second call for one task starts meanwhile.
    this.inFlight = new Set();
    this.prompt = null;
    this.promptAgain = false;
    // Background work by key (`connection:ID`, `task:ID`): at most one of each runs at a time.
    this.work = new Map();
    this.workSlots = 0;
    this.workQueue = [];
    // Keys whose latest work failed; the controller problem stays visible until each succeeds.
    this.failedWork = new Set();
    // A pass never waits longer than one interval, so that passes keep their pace (contract section 1).
    this.passWaitMs = Math.min(PASS_WAIT_MS, this.tickMs);
  }

  // ----- change notification ------------------------------------------------------

  /** Opaque value that changes whenever stored state or a readiness changes. */
  get revision() {
    return `${this.bootId}-${this.changes}`;
  }

  touch() {
    this.changes += 1;
    for (const listener of this.listeners) listener();
  }

  /** Subscribes to revision changes; returns the unsubscribe function. */
  onChange(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  // ----- lifecycle ------------------------------------------------------------------

  start() {
    this.running = true;
    this.schedule(0);
  }

  /** Stops scheduling and waits for the work in flight, whose subprocesses the caller aborts. */
  async stop() {
    this.running = false;
    clearTimeout(this.timer);
    await Promise.all([this.passing, this.prompt, ...this.work.values()]);
  }

  /**
   * Starts `job` under `key` unless work with that key is still running, and
   * returns the new work's completion, or null when the key was already running:
   * a pass waits only for work it started itself. At most BACKGROUND_LIMIT jobs
   * hold a slot at once, and a job that outlasts the pass wait gives its slot
   * back, so slow calls never queue fast ones behind them (MGD-15). A failure is
   * logged and reported by every pass until that key's work succeeds; it is never
   * thrown.
   */
  startWork(key, job) {
    if (this.work.has(key)) return null;
    const promise = (async () => {
      await this.acquireSlot();
      let held = true;
      const release = () => {
        if (!held) return;
        held = false;
        this.releaseSlot();
      };
      const timer = setTimeout(release, this.passWaitMs);
      try {
        if (this.running) await job();
        this.failedWork.delete(key);
      } catch (error) {
        if (this.running && !error.aborted) {
          console.error('Scheduler work failed: ' + error.message);
          this.failedWork.add(key);
        }
      } finally {
        clearTimeout(timer);
        release();
        this.work.delete(key);
      }
    })();
    this.work.set(key, promise);
    return promise;
  }

  acquireSlot() {
    if (this.workSlots < BACKGROUND_LIMIT) {
      this.workSlots += 1;
      return Promise.resolve();
    }
    return new Promise(resolve => this.workQueue.push(resolve));
  }

  /** Hands a slot to the next waiting job, or frees it. */
  releaseSlot() {
    const next = this.workQueue.shift();
    if (next) next();
    else this.workSlots -= 1;
  }

  /** Starts each keyed job and waits, at most one pass wait, for the ones this call started. */
  async runWork(jobs) {
    const started = jobs.map(([key, job]) => this.startWork(key, job)).filter(Boolean);
    if (started.length) await waitAtMost(Promise.all(started), this.passWaitMs);
  }

  schedule(delay) {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.passing = this.pass();
    }, delay);
  }

  /**
   * Acts on an operator request at once (contract section 4). With no pass in
   * flight a full pass starts. During a pass, which may be waiting for slow
   * Peerspan calls, prompt work runs beside it: cancellations not yet sent, and
   * dispatch with the readiness already known. A full pass follows either way.
   */
  poke() {
    if (!this.running) return;
    if (!this.passing) {
      this.schedule(POKE_DELAY_MS);
      return;
    }
    this.again = true;
    if (this.prompt) {
      this.promptAgain = true;
      return;
    }
    this.prompt = (async () => {
      try {
        do {
          this.promptAgain = false;
          await this.promptWork();
        } while (this.promptAgain && this.running);
      } catch (error) {
        if (this.running && !error.aborted) console.error('Prompt scheduler work failed: ' + error.message);
      } finally {
        this.prompt = null;
      }
    })();
  }

  async promptWork() {
    const tasks = await this.store.openTasks();
    const cancels = tasks.filter(task => task.cancelRequestedAt !== null && task.cancelSentAt === null);
    await this.runWork(cancels.map(task => ['task:' + task.taskId, () => this.reconcile({ ...task, retryAt: null })]));
    await this.dispatch();
  }

  async pass() {
    this.again = false;
    const started = performance.now();
    try {
      await this.tick();
      // Work beside the passes that failed, and has not since succeeded, is a failed check of the controller.
      this.setError(this.failedWork.size ? CONTROLLER_PROBLEM : null);
    } catch (error) {
      if (this.running && !error.aborted) {
        console.error('Scheduler pass failed: ' + error.message);
        this.setError(CONTROLLER_PROBLEM);
      }
    } finally {
      this.passing = null;
      // The next pass starts one interval after this one started, or at once when this one took longer.
      if (this.running) this.schedule(this.again ? 0 : Math.max(0, this.tickMs - (performance.now() - started)));
    }
  }

  setError(message) {
    if (message === this.error) return;
    this.error = message;
    this.errorSince = message ? stamp() : null;
    this.touch();
  }

  // ----- one pass -------------------------------------------------------------------

  async tick() {
    // Local commands in other processes (connect, observe, ...) change the store too.
    const dataVersion = await this.store.dataVersion();
    if (this.dataVersion !== null && dataVersion !== this.dataVersion) this.touch();
    this.dataVersion = dataVersion;

    const [connections, tasks] = await Promise.all([this.store.listConnections(), this.store.openTasks()]);
    // A slow call delays only its own task or connection: the pass waits a bounded time (MGD-15).
    const jobs = [
      ...tasks.map(task => ['task:' + task.taskId, () => this.reconcile(task)]),
      ...connections.map(connection => ['connection:' + connection.id, () => this.refreshReadiness(connection)])
    ];
    // A failure of work whose task or connection is gone no longer needs the operator.
    const keys = new Set(jobs.map(([key]) => key));
    for (const key of this.failedWork) if (!keys.has(key)) this.failedWork.delete(key);
    await this.runWork(jobs);
    for (const id of this.readiness.keys()) {
      if (!connections.some(connection => connection.id === id)) {
        this.readiness.delete(id);
        this.refreshedAt.delete(id);
        this.checkEndedAt.delete(id);
      }
    }

    await this.dispatch();
    this.lastTickAt = stamp();
  }

  /** Reserves runs for every workflow that may dispatch now, then sends them. */
  async dispatch() {
    // Evidence is never older than one check: a worker whose check has not ended since the previous
    // decision, such as one still waiting for a slow call, gets nothing new until one has.
    const since = this.dispatchedAt;
    this.dispatchedAt = performance.now();
    const ready = {};
    for (const [id, state] of this.readiness) {
      const current = (this.checkEndedAt.get(id) ?? -Infinity) > since;
      ready[id] = { ready: state.ready, current, reason: state.reason, capacity: capacityOf(state) };
    }
    const reserved = await this.store.planDispatch(stamp(), ready);
    // Each reserved task is persisted; only now may anything be sent for it.
    await this.runWork(reserved.map(task => ['task:' + task.taskId, () => this.reconcile(task, { fresh: true })]));
  }

  async refreshReadiness(connection) {
    const started = nowMs();
    const checkedAt = new Date(started).toISOString();
    let refresh = false;
    if (connection.mode === 'remote') {
      // Elapsed time or the controller's clock, whichever has advanced 60 seconds first: a held or
      // corrected step back of the clock must not suspend refreshes (contract section 7.1).
      const elapsed = performance.now();
      const last = this.refreshedAt.get(connection.id);
      refresh = last === undefined || elapsed - last.elapsed >= DIRECTORY_REFRESH_MS
        || started - last.clock >= DIRECTORY_REFRESH_MS;
      if (refresh) this.refreshedAt.set(connection.id, { elapsed, clock: started });
    }
    let result;
    try {
      result = await checkReadiness(connection, this.peerspan, { refresh });
    } catch (error) {
      if (error.aborted) throw error;
      // One connection that cannot be evaluated must not fail the pass for the others.
      console.error('Readiness check failed: ' + error.message);
      result = {
        ready: false,
        code: 'status_invalid',
        reason: 'Worker host status could not be read',
        hints: [],
        directoryAt: null,
        runtime: null
      };
    }
    const since = await this.store.recordReadiness(connection.id, result.ready, result.code, checkedAt);
    const previous = this.readiness.get(connection.id);
    this.readiness.set(connection.id, { ...result, checkedAt, since });
    this.checkEndedAt.set(connection.id, performance.now());
    const same = previous && previous.code === result.code && previous.reason === result.reason
      && previous.directoryAt === result.directoryAt && JSON.stringify(previous.hints) === JSON.stringify(result.hints)
      && JSON.stringify(previous.runtime) === JSON.stringify(result.runtime);
    if (!same) this.touch();
  }

  /** The readiness to show for a stored connection row. */
  readinessOf(connection) {
    return this.readiness.get(connection.id) ?? {
      ready: false,
      code: 'checking',
      reason: 'Checking connection',
      checkedAt: null,
      since: connection.readySince,
      hints: [],
      directoryAt: null,
      runtime: null
    };
  }

  // ----- reconciliation ----------------------------------------------------------------

  /**
   * Brings one open task up to date with the sender daemon's record of it, under
   * the task's persisted identity. A failure keeps the task and schedules a retry.
   * `fresh` marks a task reserved in this very pass.
   */
  async reconcile(task, { fresh = false } = {}) {
    if (task.retryAt && Date.parse(task.retryAt) > nowMs()) return;
    if (this.inFlight.has(task.taskId)) return;
    this.inFlight.add(task.taskId);
    try {
      // A released run is never inspected again, however long this task waited for its turn.
      if (!fresh && !(await this.store.isOpen(task.taskId))) return;
      const record = fresh ? await this.firstSubmission(task) : await this.remoteRecord(task);
      if (record) await this.absorb(task, record);
    } catch (error) {
      if (error.aborted || !this.running) return;
      const retryAt = new Date(nowMs() + Math.max(1000, this.tickMs)).toISOString();
      await this.store.taskProblem(task.taskId, PROBLEM, retryAt, stamp());
    } finally {
      this.inFlight.delete(task.taskId);
    }
  }

  /**
   * The first attempt for a task whose ID was created in this pass: no earlier
   * submission can exist, so nothing needs inspecting first. Every later
   * attempt, in this process or after a restart, goes through `remoteRecord`.
   */
  async firstSubmission(task) {
    if (!(await this.store.maySubmit(task.taskId))) return null;
    return this.peerspan.submit(task);
  }

  /** Inspects first; submits or cancels only when the stored state and the inspection permit it. */
  async remoteRecord(task) {
    let record;
    try {
      record = await this.peerspan.inspect(task);
    } catch (error) {
      // Only a genuine not-found for a never-accepted task may lead to a submission.
      if (!error.notFound || task.state !== 'submitting') throw error;
      if (task.cancelRequestedAt !== null) {
        // The sender daemon never held the task, so there is nothing to cancel remotely.
        await this.store.applyTask(task.taskId,
          { state: 'cancelled', reason: 'Cancelled before the task was sent' }, stamp());
        return null;
      }
      // The operator may have released or cancelled the run since this pass began.
      if (!(await this.store.maySubmit(task.taskId))) return null;
      return this.peerspan.submit(task);
    }
    const cancelPending = task.cancelRequestedAt !== null && task.cancelSentAt === null;
    if (cancelPending && !FINAL.has(stateOf(record))) {
      if (!(await this.store.isOpen(task.taskId))) return null;
      record = await this.peerspan.cancel(task);
      await this.store.markCancelSent(task.taskId, stamp());
    }
    return record;
  }

  /**
   * Events after the stored ones, up to the record's `last_event`. The status
   * record and the events are two reads, so the events may already hold a newer
   * final event; that one belongs to a later record and is taken with it.
   */
  async newEvents(task, remoteLast, final) {
    const after = Math.max(task.lastEvent, remoteLast - EVENT_FETCH_WINDOW);
    let events;
    try {
      events = await this.peerspan.events(task, after);
    } catch (error) {
      // A final event is needed; when the window is too large to fetch, fetching
      // after last_event - 1 is permitted (contract section 6).
      if (error.aborted || !final || after >= remoteLast - 1) throw error;
      events = await this.peerspan.events(task, remoteLast - 1);
    }
    return normalizeEvents(events, task.lastEvent).filter(event => event.sequence <= remoteLast);
  }

  /** Stores what a record and its new events say; a result is final only with its final event. */
  async absorb(task, record) {
    const state = stateOf(record);
    if (!OPEN.has(state) && !FINAL.has(state)) throw new Error('Remote task state is unresolved');
    const final = FINAL.has(state);
    const producesOutput = state === 'succeeded' || state === 'failed';
    const remoteLast = record.status?.last_event;

    let events = [];
    if (Number.isInteger(remoteLast) && remoteLast > task.lastEvent) {
      try {
        events = await this.newEvents(task, remoteLast, final);
      } catch (error) {
        // The timeline is best effort while the task runs; a final result waits for its event.
        if (error.aborted || final) throw error;
      }
      // Status can run ahead of the stored events: a final state waits until its event is retained.
      if (final && !events.some(event => event.sequence === remoteLast)) {
        throw new Error('Waiting for the final task event');
      }
    }

    const update = { state };
    const last = events.find(event => event.sequence === remoteLast);
    if (producesOutput) {
      // Status can run ahead of the locally stored events: wait for the output itself. Upstream
      // outputs are never empty, but an empty string is still an output, not a missing one.
      const hasOutput = last && last.kind === state && last.state === state && typeof last.output === 'string';
      if (!hasOutput) throw new Error('Waiting for final task output');
      update.output = last.output.slice(0, OUTPUT_LIMIT);
      update.outputTruncated = last.output.length > OUTPUT_LIMIT;
    }
    if (FINAL.has(state) && state !== 'succeeded') {
      update.reason = singleLine(text(record.error, MESSAGE_LIMIT) ?? last?.message ?? null);
    }
    const accepted = events.find(event => event.kind === 'accepted');
    if (accepted?.at) update.startedAt = accepted.at;
    update.events = events.map(({ output, ...event }) => event);
    await this.store.applyTask(task.taskId, update, stamp());
  }
}
