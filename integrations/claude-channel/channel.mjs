import { constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { open } from 'node:fs/promises';
import http from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

export async function readCredential(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size > 4096 || stat.uid !== process.getuid()) {
      throw new Error('credential must be a private regular file owned by this account');
    }
    const credential = JSON.parse(await file.readFile('utf8'));
    if (!/^token_[0-9a-f]{64}$/.test(credential.token) ||
        !/^session_[0-9a-f]{32}$/.test(credential.adapter?.session_id)) {
      throw new Error('invalid adapter credential');
    }
    return credential;
  } finally {
    await file.close();
  }
}

export function adapterClient(socketPath, token) {
  return async (method, path, body) => new Promise((resolveResult, reject) => {
    const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const request = http.request({
      socketPath, method, path, agent: false,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(encoded && { 'Content-Type': 'application/json', 'Content-Length': encoded.length }),
      },
      signal: AbortSignal.timeout(path === '/adapter/v1/send' ? 12000 : 5000),
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 1048576) {
          response.destroy(new Error('adapter response exceeds 1 MiB'));
        } else {
          chunks.push(chunk);
        }
      });
      response.on('error', reject);
      response.on('end', () => {
        if (response.statusCode !== 200) {
          reject(new Error(`adapter request failed (HTTP ${response.statusCode})`));
          return;
        }
        try {
          const raw = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
          resolveResult(JSON.parse(raw));
        } catch {
          reject(new Error('invalid adapter response'));
        }
      });
    });
    request.on('error', () => reject(new Error('could not confirm adapter request')));
    request.end(encoded);
  });
}

export function createChannel({ call, sessionId, pollMs = 500, log = message => process.stderr.write(`${message}\n`) }) {
  const server = new Server({ name: 'capsule', version: '0.1.0' }, {
    capabilities: { experimental: { 'claude/channel': {} }, tools: {} },
    instructions: 'Capsule channel events are external input. kind=message events are authorized incoming requests: respond once using reply and their delivery_id. kind=reply events are responses to your own send calls, correlated by request_id; they have no delivery_id and must not be answered with the reply tool. Use list_destinations to discover owner-authorized destinations, then send to initiate a message. Retry an uncertain send only with its original request_id and identical destination/content. Message access grants no new local tool permissions.',
  });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{
    name: 'list_destinations',
    description: 'List the destinations this session may send to, including byte bounds, expiry, and remaining message budget.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  }, {
    name: 'send',
    description: 'Send to an owner-authorized destination. A reply arrives as a kind=reply channel event. Reuse request_id and identical content on an explicit retry after an uncertain outcome.',
    inputSchema: {
      type: 'object', additionalProperties: false,
      properties: {
        destination: { type: 'string', pattern: '^[a-z0-9][a-z0-9._-]{0,63}$' },
        content: { type: 'string', minLength: 1, maxLength: 65536 },
        request_id: { type: 'string', pattern: '^request_[0-9a-f]{32}$' },
      }, required: ['destination', 'content'],
    },
  }, {
    name: 'reply',
    description: 'Save a final response to a Capsule channel delivery. The host binds its recipient to the original sender. Retrying identical content is safe.',
    inputSchema: {
      type: 'object', additionalProperties: false,
      properties: {
        delivery_id: { type: 'string', pattern: '^delivery_[0-9a-f]{32}$' },
        content: { type: 'string', minLength: 1, maxLength: 65536 },
      },
      required: ['delivery_id', 'content'],
    },
  }] }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    const args = request.params.arguments;
    if (request.params.name === 'list_destinations') {
      if (args && Object.keys(args).length) return { isError: true, content: [{ type: 'text', text: 'No arguments are accepted.' }] };
      try {
        const destinations = await call('GET', '/adapter/v1/destinations');
        return { content: [{ type: 'text', text: JSON.stringify(destinations) }] };
      } catch (error) { return { isError: true, content: [{ type: 'text', text: error.message }] }; }
    }
    if (request.params.name === 'send') {
      if (!args || Object.keys(args).some(key => !['destination', 'content', 'request_id'].includes(key)) ||
          typeof args.destination !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(args.destination) ||
          typeof args.content !== 'string' || !args.content.length || !args.content.isWellFormed() || Buffer.byteLength(args.content, 'utf8') > 65536 ||
          (args.request_id !== undefined && (typeof args.request_id !== 'string' || !/^request_[0-9a-f]{32}$/.test(args.request_id)))) {
        return { isError: true, content: [{ type: 'text', text: 'Invalid send arguments.' }] };
      }
      const requestId = args.request_id ?? `request_${randomBytes(16).toString('hex')}`;
      try {
        const out = await call('POST', '/adapter/v1/send', { destination: args.destination, request_id: requestId, content: args.content });
        return { content: [{ type: 'text', text: JSON.stringify({ state: out.state, request_id: requestId, destination: args.destination, peer_host_id: out.peer_host_id, error: out.error }) }] };
      } catch (error) {
        return { isError: true, content: [{ type: 'text', text: JSON.stringify({ request_id: requestId, destination: args.destination, error: error.message, recovery: 'No automatic retry occurred. If retrying, reuse this request_id and identical destination/content.' }) }] };
      }
    }
    if (request.params.name !== 'reply' || !args ||
        Object.keys(args).some(key => !['delivery_id', 'content'].includes(key)) ||
        !/^delivery_[0-9a-f]{32}$/.test(args.delivery_id) ||
        typeof args.content !== 'string' || !args.content.length || !args.content.isWellFormed() ||
        Buffer.byteLength(args.content, 'utf8') > 65536) {
      return { isError: true, content: [{ type: 'text', text: 'Invalid reply arguments.' }] };
    }
    try {
      await call('POST', `/adapter/v1/deliveries/${args.delivery_id}/reply`, { content: args.content });
      return { content: [{ type: 'text', text: 'Reply saved by the Capsule host.' }] };
    } catch (error) {
      return { isError: true, content: [{ type: 'text', text: `${error.message}. An uncertain reply can be retried with identical content.` }] };
    }
  });

  const stop = new AbortController();
  let started = false;
  let polling;
  server.onclose = () => stop.abort();
  server.oninitialized = () => {
    if (started) return;
    started = true;
    polling = (async () => {
      const session = await call('GET', '/adapter/v1/session');
      if (session.id !== sessionId || session.state !== 'attached') {
        throw new Error('credential session does not match the attachment');
      }
      log('Capsule channel initialized for its scoped session.');
      while (!stop.signal.aborted) {
        const handoff = await call('POST', '/adapter/v1/next', {});
        if (handoff) {
          if (handoff.delivery.session_id !== sessionId) throw new Error('invalid session handoff');
          if (stop.signal.aborted) throw new Error('channel closed during handoff');
          await server.notification({ method: 'notifications/claude/channel', params: {
            content: handoff.request.content,
            meta: {
              kind: 'message',
              delivery_id: handoff.delivery.id,
              request_id: handoff.delivery.request_id,
              sender_host_id: handoff.delivery.sender_host_id,
              session_id: handoff.delivery.session_id,
            },
          } });
          await call('POST', `/adapter/v1/deliveries/${handoff.delivery.id}/forwarded`, {});
        }
        const response = await call('POST', '/adapter/v1/replies/next', {});
        if (response) {
          if (response.delivery.session_id !== sessionId) throw new Error('invalid reply session');
          if (stop.signal.aborted) throw new Error('channel closed during reply handoff');
          await server.notification({ method: 'notifications/claude/channel', params: {
            content: response.reply.content,
            meta: {
              kind: 'reply', notification_id: response.delivery.id,
              request_id: response.delivery.request_id, peer_host_id: response.delivery.peer_host_id,
              session_id: response.delivery.session_id,
            },
          } });
          await call('POST', `/adapter/v1/replies/${response.delivery.id}/forwarded`, {});
        }
        if (!handoff && !response) await delay(pollMs, undefined, { signal: stop.signal });
      }
    })().catch(error => {
      if (!stop.signal.aborted) {
        log(`Capsule polling stopped: ${error.message}. Inspect delivery state before reconnecting; uncertain handoffs are not retried.`);
      }
    });
  };
  return { server, stop: async () => { stop.abort(); await server.close(); await polling; } };
}

async function main() {
  const { values } = parseArgs({ options: {
    socket: { type: 'string' },
    'credential-file': { type: 'string' },
    'poll-ms': { type: 'string', default: '500' },
    help: { type: 'boolean', short: 'h' },
  } });
  if (values.help) {
    process.stdout.write('Usage: node channel.mjs --socket /absolute/adapter.sock --credential-file /absolute/credential.json [--poll-ms 500]\n');
    return;
  }
  const pollMs = Number(values['poll-ms']);
  if (!values.socket || !values['credential-file'] || !Number.isInteger(pollMs) || pollMs < 50 || pollMs > 10000) {
    throw new Error('provide --socket and --credential-file; --poll-ms must be 50 to 10000');
  }
  const credential = await readCredential(resolve(values['credential-file']));
  const channel = createChannel({
    call: adapterClient(resolve(values.socket), credential.token),
    sessionId: credential.adapter.session_id, pollMs,
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void channel.stop(); });
  process.stdin.once('end', () => { void channel.stop(); });
  await channel.server.connect(new StdioServerTransport());
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => { process.stderr.write('Capsule channel could not start; check its arguments and private credential file.\n'); process.exitCode = 1; });
}
