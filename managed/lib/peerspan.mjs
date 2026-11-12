// The only way the controller reaches Peerspan: the owner CLI, invoked with
// argument arrays (never a shell) and the global --json flag on every call.
import { execFile } from 'node:child_process';

const COMMAND_TIMEOUT_MS = 15_000;
const RUNTIME_SHOW_TIMEOUT_MS = 5_000;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

export class PeerspanError extends Error {
  constructor(message, fields = {}) {
    super(message);
    Object.assign(this, fields);
  }
}

function parse(stdout) {
  try {
    return JSON.parse(stdout);
  } catch {
    throw new PeerspanError('Peerspan returned invalid JSON');
  }
}

export class Peerspan {
  /** `signal` aborts every command still running, for shutdown. */
  constructor({ binary = process.env.PEERSPAN_BIN || 'peerspan', timeoutMs = COMMAND_TIMEOUT_MS, signal } = {}) {
    this.binary = binary;
    this.timeoutMs = timeoutMs;
    this.signal = signal;
  }

  /**
   * Runs one command and resolves `{code, stdout, stderr}` for any exit status.
   * Rejects only when the process could not run to an exit of its own.
   */
  exec(stateDir, args, { timeoutMs = this.timeoutMs } = {}) {
    const argv = [...(stateDir ? ['--state', stateDir] : []), '--json', ...args];
    const options = {
      encoding: 'utf8',
      timeout: timeoutMs,
      maxBuffer: MAX_OUTPUT_BYTES,
      windowsHide: true,
      signal: this.signal
    };
    return new Promise((resolve, reject) => {
      execFile(this.binary, argv, options, (error, stdout, stderr) => {
        if (!error) {
          resolve({ code: 0, stdout, stderr });
        } else if (typeof error.code === 'number') {
          resolve({ code: error.code, stdout, stderr });
        } else {
          const unavailable = error.code === 'ENOENT' || error.code === 'EACCES';
          reject(new PeerspanError(unavailable ? 'Peerspan executable is unavailable' : 'Peerspan command failed', {
            unavailable,
            aborted: error.name === 'AbortError'
          }));
        }
      });
    });
  }

  /** Runs a command that must exit 0 and print JSON. */
  async json(stateDir, args) {
    const result = await this.exec(stateDir, args);
    if (result.code !== 0) {
      throw new PeerspanError('Peerspan command failed', {
        exitCode: result.code,
        // The upstream CLI's report of a task its daemon has never held.
        notFound: result.code === 1 && /^error: host daemon: not found\s*$/.test(result.stderr)
      });
    }
    return parse(result.stdout);
  }

  /**
   * Reads a host's status. Resolves `{kind: 'ok', value}` or `{kind}` with the
   * readiness code that explains why it could not be read (contract section 3).
   */
  async status(hostDir) {
    let result;
    try {
      result = await this.exec(hostDir, ['status']);
    } catch (error) {
      if (error.aborted) throw error;
      return { kind: error.unavailable ? 'peerspan_unavailable' : 'status_invalid' };
    }
    if (result.code === 2) {
      const tooOld = result.stderr.includes("unexpected argument '--json'");
      return { kind: tooOld ? 'peerspan_incompatible' : 'daemon_not_running' };
    }
    // Exit 1 only says that something needs attention, which may be historical.
    if (result.code !== 0 && result.code !== 1) return { kind: 'status_invalid' };
    let value;
    try {
      value = parse(result.stdout);
    } catch {
      return { kind: 'status_invalid' };
    }
    const valid = value && typeof value.host_id === 'string' && typeof value.service?.active === 'boolean'
      && Array.isArray(value.attention) && Array.isArray(value.agents);
    return valid ? { kind: 'ok', value } : { kind: 'status_invalid' };
  }

  /**
   * Reads the sender host's directory of reachable agents (contract section 7.1).
   * Resolves `{kind: 'ok', value}` or `{kind}` with the readiness code that
   * explains why it could not be read. `network` may be null only at registration.
   */
  async agents(stateDir, { network = null, refresh = false } = {}) {
    let result;
    try {
      result = await this.exec(stateDir,
        ['agents', ...(network ? ['--network', network] : []), ...(refresh ? ['--refresh'] : [])]);
    } catch (error) {
      if (error.aborted) throw error;
      return { kind: error.unavailable ? 'peerspan_unavailable' : 'directory_unavailable' };
    }
    if (result.code === 2 && result.stderr.includes("unexpected argument '--json'")) {
      return { kind: 'peerspan_incompatible' };
    }
    if (result.code !== 0) return { kind: 'directory_unavailable', stderr: result.stderr };
    let value;
    try {
      value = parse(result.stdout);
    } catch {
      return { kind: 'directory_unavailable' };
    }
    const valid = value && typeof value.network_id === 'string' && Array.isArray(value.reachable)
      && Array.isArray(value.mine) && Array.isArray(value.hosts);
    return valid ? { kind: 'ok', value } : { kind: 'directory_unavailable' };
  }

  /**
   * The host's launch profiles (contract section 3.1). Resolves `{kind: 'ok',
   * value}` with the array, `{kind: 'none'}` for an executable older than
   * runtime agents, or `{kind: 'invalid'}` when they cannot be read.
   */
  async launchProfiles(hostDir) {
    let result;
    try {
      result = await this.exec(hostDir, ['agent', 'runtime', 'show']);
    } catch (error) {
      if (error.aborted) throw error;
      return { kind: 'invalid' };
    }
    if (result.code === 2 && result.stderr.includes('unrecognized subcommand')) return { kind: 'none' };
    if (result.code !== 0) return { kind: 'invalid' };
    try {
      const value = parse(result.stdout);
      return Array.isArray(value) ? { kind: 'ok', value } : { kind: 'invalid' };
    } catch {
      return { kind: 'invalid' };
    }
  }

  /**
   * The host's runtime switch and report (`runtime show`), or null when they
   * cannot be read in time. Upstream waits up to 35 seconds for a runtime that
   * does not answer; a check never waits that long (contract section 3.1).
   */
  async runtimeSwitch(hostDir) {
    let result;
    try {
      result = await this.exec(hostDir, ['runtime', 'show'], { timeoutMs: Math.min(this.timeoutMs, RUNTIME_SHOW_TIMEOUT_MS) });
    } catch (error) {
      if (error.aborted) throw error;
      return null;
    }
    if (result.code !== 0) return null;
    try {
      const value = parse(result.stdout);
      return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
    } catch {
      return null;
    }
  }

  adapterConnection(hostDir, adapterId) {
    return this.json(hostDir, ['adapter', 'connection', adapterId]);
  }

  // The input is one `--input=TEXT` argument: the upstream parser refuses a
  // separate value that begins with a hyphen.
  submit(task) {
    return this.json(task.senderState, ['task', 'submit', '--peer', task.peer, '--agent', task.agent,
      '--task', task.taskId, '--input=' + task.input, '--deadline', task.deadline]);
  }

  inspect(task) {
    return this.json(task.senderState, ['task', 'inspect', '--peer', task.peer, task.taskId]);
  }

  events(task, after) {
    return this.json(task.senderState, ['task', 'events', '--peer', task.peer, task.taskId, '--after', String(after)]);
  }

  cancel(task) {
    return this.json(task.senderState, ['task', 'cancel', '--peer', task.peer, task.taskId]);
  }
}
