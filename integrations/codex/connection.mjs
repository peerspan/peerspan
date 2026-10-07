import { EventEmitter } from 'node:events';
import WebSocket from 'ws';
export class RPCError extends Error {
  constructor(code) {
    super(`Codex rejected the request (RPC ${code}).`);
    this.code = code;
  }
}
// Connect to the owner's existing local backend. Closing this client never
// starts, restarts, stops or replaces Codex or its selected conversation.
export class Connection extends EventEmitter {
  constructor(socket, { timeoutMs = 10000 } = {}) {
    super();
    this.pending = new Map();
    this.counter = 0;
    this.timeoutMs = timeoutMs;
    this.ws = new WebSocket('ws+unix://' + socket + ':/', {
      maxPayload: 4 * 1048576,
      handshakeTimeout: timeoutMs
    });
    this.opened = new Promise((resolve, reject) => {
      this.ws.once('open', resolve);
      this.ws.once('error', () =>
        reject(new Error('Could not connect to the existing Codex backend.'))
      );
    });
    this.opened.catch(() => {});
    this.ws.on('message', (data) => {
      if (this.failure) return;
      let message;
      try {
        message = JSON.parse(data.toString('utf8'));
      } catch {
        this.fail(new Error('Invalid Codex protocol frame.'));
        return;
      }
      if (message.method) this.emit(message.id === undefined ? 'notification' : 'request', message);
      else {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        if (message.error) {
          const error = new RPCError(message.error.code);
          error.method = pending.method;
          pending.reject(error);
        } else pending.resolve(message.result);
      }
    });
    this.ws.on('error', () => this.fail(new Error('Existing Codex backend connection failed.')));
    this.ws.on('close', () => this.fail(new Error('Existing Codex backend connection closed.')));
  }
  write(value) {
    if (this.failure || this.ws.readyState !== WebSocket.OPEN)
      throw this.failure ?? new Error('Codex connection is not open.');
    this.ws.send(JSON.stringify(value));
  }
  async initialize() {
    await this.opened;
    await this.request('initialize', {
      clientInfo: { name: 'capsule', title: 'Capsule', version: '0.1.0' },
      capabilities: { experimentalApi: true }
    });
    this.write({ method: 'initialized' });
  }
  request(method, params) {
    if (this.failure) return Promise.reject(this.failure);
    const id = ++this.counter;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => this.fail(new Error('Codex response timed out; request outcome is uncertain.')),
        this.timeoutMs
      );
      this.pending.set(id, { resolve, reject, timer, method });
      try {
        this.write({ id, method, params });
      } catch (error) {
        this.fail(error);
      }
    });
  }
  fail(error) {
    if (this.failure) return;
    this.failure = error;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    this.emit('failure', error);
    this.ws.terminate();
  }
  close() {
    this.fail(new Error('Capsule disconnected from Codex.'));
  }
}
export async function inspectExisting(socket, threadId) {
  const rpc = new Connection(socket, { timeoutMs: 5000 });
  try {
    await rpc.initialize();
    const { thread } = await rpc.request('thread/read', { threadId, includeTurns: false });
    if (thread?.id !== threadId || !['idle', 'active'].includes(thread.status?.type))
      throw new Error('Select an already-running Codex thread in this backend.');
    return { id: thread.id, cwd: thread.cwd, status: thread.status.type };
  } finally {
    rpc.close();
  }
}
