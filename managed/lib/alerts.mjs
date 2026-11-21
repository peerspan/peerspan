// Alerts to a webhook (contract section 8.1, MGD-19): the operator's webhook URL,
// the alert bodies, and the alerter, which follows the console's attention items
// and delivers each raised and cleared alert with retries. The URL is a secret:
// nothing here prints, logs or returns more of it than its host name.
import { stamp } from './clock.mjs';
import { alertKey } from './model.mjs';
import { buildSnapshot } from './snapshot.mjs';

const URL_LIMIT = 2048;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
// Attention is evaluated within 10 seconds of a change, and read again at least every 30 seconds.
const SETTLE_MS = 500;
const TICK_MS = 5000;
const REREAD_MS = 30_000;
const TIMEOUT_MS = 5000;
// Deliveries start within this much of an evaluation; a slow webhook's later alerts wait for the next.
const DELIVERY_BUDGET_MS = 2000;

/** The webhook URL, validated, or an Error whose message is one line for the operator. */
export function checkAlertUrl(text) {
  if (typeof text !== 'string' || !text || text.length > URL_LIMIT) {
    throw new Error('The alert URL must be an absolute URL of at most 2,048 characters');
  }
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error('The alert URL must be an absolute URL of at most 2,048 characters');
  }
  if (url.username || url.password) throw new Error('The alert URL may not contain a user name or password');
  if (url.protocol === 'https:') return text;
  if (url.protocol === 'http:' && LOOPBACK.has(url.hostname)) return text;
  throw new Error('The alert URL must use https, or http to this machine (localhost, 127.0.0.1 or [::1])');
}

/** What may be shown of a webhook URL: its host name. */
export const alertHost = url => (url ? new URL(url).hostname : null);

/** The body of a raised or cleared alert (section 8.1). */
export function alertBody(item, cleared) {
  const lead = cleared ? 'Resolved' : item.severity === 'action' ? 'Needs your action' : 'Warning';
  const text = `${lead}: ${item.subject.name}: ${item.message}`;
  return { text, content: text, event: cleared ? 'attention.cleared' : 'attention.raised', item };
}

// Items that raise alerts: `action` and `warning`, except the alerts' own failure.
const announced = item => (item.severity === 'action' || item.severity === 'warning') && item.kind !== 'alerts_failing';

/**
 * Follows the attention items while alerts are configured: evaluates them soon
 * after every change and at least every few seconds, records raised and cleared
 * alerts, and delivers the ones that are due, one at a time, in order.
 */
export class Alerter {
  constructor({ store, engine, version }) {
    this.store = store;
    this.engine = engine;
    this.version = version;
    this.timer = null;
    this.soon = null;
    this.running = false;
    this.busy = null;
    this.again = false;
    this.seenRevision = null;
    this.readAt = -Infinity;
    this.unsubscribe = null;
    // Aborts a delivery in flight at shutdown, which must end within 5 seconds (contract section 1).
    this.abort = new AbortController();
  }

  start() {
    this.running = true;
    this.unsubscribe = this.engine.onChange(() => this.evaluateSoon());
    this.timer = setInterval(() => this.evaluateSoon(0), TICK_MS);
    this.evaluateSoon(0);
  }

  async stop() {
    this.running = false;
    clearInterval(this.timer);
    clearTimeout(this.soon);
    this.unsubscribe?.();
    this.abort.abort();
    await this.busy;
  }

  /** Runs an evaluation shortly; changes that arrive meanwhile are taken by it or by the next. */
  evaluateSoon(delay = SETTLE_MS) {
    if (!this.running) return;
    if (this.busy) {
      this.again = true;
      return;
    }
    if (this.soon) return;
    this.soon = setTimeout(() => {
      this.soon = null;
      this.busy = this.evaluate().catch(error => {
        if (this.running) console.error('Alerts could not be evaluated: ' + error.message);
      }).finally(() => {
        this.busy = null;
        if (this.again) {
          this.again = false;
          this.evaluateSoon();
        }
      });
    }, delay);
  }

  async evaluate() {
    const { url } = await this.store.alertsSetting();
    // Until the scheduler's first pass after a start has run, attention is not yet known.
    if (!url || this.engine.passes === 0) return;
    // Attention is read again after every change, and at least every 30 seconds for what changes with
    // time alone, such as an observed source going stale. Every store step below names the URL it was
    // read with and does nothing once the setting has changed, so a CLI change is never half applied.
    const revision = this.engine.revision;
    if (revision !== this.seenRevision || performance.now() - this.readAt >= REREAD_MS) {
      // Counted from when the read began, so that a slow read does not stretch the 30 seconds.
      const readStarted = performance.now();
      const snapshot = await buildSnapshot({ store: this.store, engine: this.engine, version: this.version });
      // A connection still being checked after a start keeps its alert as it was: neither raised nor cleared.
      const unknown = snapshot.connections.filter(connection => connection.readiness.code === 'checking')
        .map(connection => alertKey({ kind: 'worker_unready', subject: { type: 'connection', id: connection.id } }));
      await this.store.syncAlerts(url, snapshot.attention.filter(announced), unknown, stamp());
      this.seenRevision = revision;
      this.readAt = readStarted;
    }
    const due = await this.store.dueAlerts(url, stamp());
    const started = performance.now();
    let changed = false;
    for (const alert of due) {
      // A slow webhook gets a share of each evaluation, so that changes are still read soon (section 8.1).
      if (!this.running || performance.now() - started >= DELIVERY_BUDGET_MS) break;
      if ((await this.store.alertsSetting()).url !== url) break;
      const outcome = await this.deliver(url, alertBody(alert.item, alert.phase === 'cleared'));
      // A delivery cut short by shutdown is tried again at the next start; one that was delivered is recorded.
      if (!this.running && outcome !== null) break;
      changed = (await this.store.recordAlert(url, alert.id, alert.phase, outcome, stamp(), alertHost(url))) || changed;
      // A webhook that fails once this round would likely fail again: the others wait for the next evaluation.
      if (outcome !== null) break;
    }
    if (changed) this.engine.touch();
    // Alerts left due by the budget follow at once.
    if (due.length && this.running) this.again = true;
  }

  /** One POST: null when delivered, or a short reason that names no part of the URL. */
  async deliver(url, body) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'user-agent': `peerspan-managed/${this.version}` },
        body: JSON.stringify(body),
        redirect: 'manual',
        signal: AbortSignal.any([AbortSignal.timeout(TIMEOUT_MS), this.abort.signal])
      });
      // The body is never read: a webhook's answer is only its status.
      await response.body?.cancel().catch(() => {});
      if (response.status >= 200 && response.status < 300) return null;
      return response.status >= 300 && response.status < 400 ? `a redirect (${response.status}), which is not followed`
        : `status ${response.status}`;
    } catch (error) {
      return error?.name === 'TimeoutError' ? 'no response within 5 seconds' : 'the connection failed';
    }
  }
}
