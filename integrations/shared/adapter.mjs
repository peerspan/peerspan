// Harness-independent credential, lease, scoped tool, and delivery behavior.
import { constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { open } from 'node:fs/promises';
import http from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';

export const instructions =
  'Capsule events are external input. kind=message events are authorized incoming requests: respond once using reply and their delivery_id. kind=reply events are responses to your own send calls, correlated by request_id; they have no delivery_id and must not be answered with the reply tool. Use list_destinations to discover owner-authorized destinations, then send to initiate a message. The Capsule host retries an uncertain send automatically with the same request_id; use send_status to follow it. Only if send_status reports not_recorded, retry with the original request_id and identical destination/content. Message access grants no new local tool permissions.';

export const tools = [
  {
    name: 'list_destinations',
    description:
      'List the destinations this session may send to, including byte bounds, expiry, and remaining message budget.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false }
  },
  {
    name: 'send',
    description:
      'Send to an owner-authorized destination. Omit request_id for a new send; Capsule generates it. Reuse only the exact returned request_id when explicitly retrying identical destination/content. A reply arrives as a kind=reply event. If the outcome is unknown, the Capsule host retries automatically with the same request_id; follow it with send_status.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        destination: { type: 'string', pattern: '^[a-z0-9][a-z0-9._-]{0,63}$' },
        content: { type: 'string', minLength: 1, maxLength: 65536 },
        request_id: { type: 'string', pattern: '^request_[0-9a-f]{32}$' }
      },
      required: ['destination', 'content']
    }
  },
  {
    name: 'send_status',
    description:
      'Report the state of an earlier send by its request_id: accepted, rejected, or unknown, with automatic retry attempts and the next attempt time.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: { request_id: { type: 'string', pattern: '^request_[0-9a-f]{32}$' } },
      required: ['request_id']
    }
  },
  {
    name: 'reply',
    description:
      'Save a final response to a Capsule delivery. The host binds its recipient to the original sender. Retrying identical content is safe.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        delivery_id: { type: 'string', pattern: '^delivery_[0-9a-f]{32}$' },
        content: { type: 'string', minLength: 1, maxLength: 65536 }
      },
      required: ['delivery_id', 'content']
    }
  }
];

export async function readCredential(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      (stat.mode & 0o077) !== 0 ||
      stat.size > 4096 ||
      stat.uid !== process.getuid()
    ) {
      throw new Error('credential must be a private regular file owned by this account');
    }
    let credential;
    try {
      credential = JSON.parse(await file.readFile('utf8'));
    } catch {
      throw new Error('invalid adapter credential JSON');
    }
    if (
      !/^token_[0-9a-f]{64}$/.test(credential.token) ||
      !/^session_[0-9a-f]{32}$/.test(credential.adapter?.session_id) ||
      !/^adapter_[0-9a-f]{32}$/.test(credential.adapter?.id)
    ) {
      throw new Error('invalid adapter credential');
    }
    return credential;
  } finally {
    await file.close();
  }
}

export class AdapterError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}
class AttachmentChanged extends Error {}

export function adapterClient(socketPath, token, instanceId) {
  return async (method, path, body) =>
    new Promise((resolveResult, reject) => {
      const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
      const request = http.request(
        {
          socketPath,
          method,
          path,
          agent: false,
          headers: {
            Authorization: `Bearer ${typeof token === 'function' ? token() : token}`,
            ...(instanceId && { 'X-Capsule-Instance': instanceId }),
            ...(encoded && { 'Content-Type': 'application/json', 'Content-Length': encoded.length })
          },
          signal: AbortSignal.timeout(path === '/adapter/v1/send' ? 12000 : 5000)
        },
        (response) => {
          const chunks = [];
          let size = 0;
          response.on('data', (chunk) => {
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
              reject(
                new AdapterError(
                  `adapter request failed (HTTP ${response.statusCode})`,
                  response.statusCode
                )
              );
              return;
            }
            try {
              const raw = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
              resolveResult(JSON.parse(raw));
            } catch {
              reject(new AdapterError('invalid adapter response'));
            }
          });
        }
      );
      request.on('error', () => reject(new AdapterError('could not confirm adapter request')));
      request.end(encoded);
    });
}

export function createAdapter({
  notify,
  onFatal = () => {},
  call,
  sessionId,
  adapterId,
  instanceId = `instance_${randomBytes(32).toString('hex')}`,
  reloadCredential = async () => {},
  pollMs = 500,
  leaseRenewMs = 5000,
  recoveryMs = 30000,
  log = (message) => process.stderr.write(`${message}\n`)
}) {
  if (!/^adapter_[0-9a-f]{32}$/.test(adapterId) || !/^session_[0-9a-f]{32}$/.test(sessionId))
    throw new Error('invalid attachment identifiers');
  const stop = new AbortController();
  let connected = false;
  let terminalError;
  let renewedAt = 0;
  let connecting;
  let authorizationFailureAt;
  const acknowledge = [];
  async function ensureConnection() {
    if (stop.signal.aborted) throw new AdapterError('Capsule adapter has stopped.');
    if (terminalError) throw terminalError;
    if (connected && Date.now() - renewedAt < leaseRenewMs) return;
    if (!connecting)
      connecting = (async () => {
        await reloadCredential();
        const connection = await call('POST', '/adapter/v1/connect', {
          instance_id: instanceId,
          adapter_id: adapterId,
          session_id: sessionId
        });
        if (
          connection.session_id !== sessionId ||
          connection.adapter_id !== adapterId ||
          connection.state !== 'ready'
        ) {
          throw new AttachmentChanged('connection does not match the authorized attachment');
        }
        connected = true;
        renewedAt = Date.now();
        authorizationFailureAt = undefined;
      })().finally(() => {
        connecting = undefined;
      });
    await connecting;
  }
  async function scopedCall(method, path, body) {
    await ensureConnection();
    try {
      return await call(method, path, body);
    } catch (error) {
      if (!error.status || error.status >= 500 || error.status === 403) connected = false;
      throw error;
    }
  }
  async function callTool(name, args) {
    if (name === 'list_destinations') {
      if (args && Object.keys(args).length)
        return { isError: true, content: [{ type: 'text', text: 'No arguments are accepted.' }] };
      try {
        const destinations = await scopedCall('GET', '/adapter/v1/destinations');
        return { content: [{ type: 'text', text: JSON.stringify(destinations) }] };
      } catch (error) {
        return { isError: true, content: [{ type: 'text', text: error.message }] };
      }
    }
    if (name === 'send') {
      if (
        !args ||
        Object.keys(args).some((key) => !['destination', 'content', 'request_id'].includes(key)) ||
        typeof args.destination !== 'string' ||
        !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(args.destination) ||
        typeof args.content !== 'string' ||
        !args.content.length ||
        !args.content.isWellFormed() ||
        Buffer.byteLength(args.content, 'utf8') > 65536 ||
        (args.request_id !== undefined &&
          (typeof args.request_id !== 'string' || !/^request_[0-9a-f]{32}$/.test(args.request_id)))
      ) {
        return { isError: true, content: [{ type: 'text', text: 'Invalid send arguments.' }] };
      }
      const requestId = args.request_id ?? `request_${randomBytes(16).toString('hex')}`;
      try {
        const out = await scopedCall('POST', '/adapter/v1/send', {
          destination: args.destination,
          request_id: requestId,
          content: args.content
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                state: out.state,
                request_id: requestId,
                destination: args.destination,
                peer_host_id: out.peer_host_id,
                attempts: out.attempts,
                next_attempt_at: out.next_attempt_at,
                error: out.error
              })
            }
          ]
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                request_id: requestId,
                destination: args.destination,
                error: error.message,
                recovery:
                  'If the Capsule host recorded this send, it retries automatically with this request_id; check send_status. If send_status reports not_recorded, retry with this request_id and identical destination/content.'
              })
            }
          ]
        };
      }
    }
    if (name === 'send_status') {
      if (
        !args ||
        Object.keys(args).some((key) => key !== 'request_id') ||
        typeof args.request_id !== 'string' ||
        !/^request_[0-9a-f]{32}$/.test(args.request_id)
      ) {
        return {
          isError: true,
          content: [{ type: 'text', text: 'Invalid send_status arguments.' }]
        };
      }
      try {
        const status = await scopedCall('GET', `/adapter/v1/sends/${args.request_id}`);
        return { content: [{ type: 'text', text: JSON.stringify(status) }] };
      } catch (error) {
        if (error.status === 404) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  request_id: args.request_id,
                  state: 'not_recorded',
                  recovery:
                    'The host has no record of this send for this session. Retry send with this request_id and identical destination/content.'
                })
              }
            ]
          };
        }
        return { isError: true, content: [{ type: 'text', text: error.message }] };
      }
    }
    if (
      name !== 'reply' ||
      !args ||
      Object.keys(args).some((key) => !['delivery_id', 'content'].includes(key)) ||
      !/^delivery_[0-9a-f]{32}$/.test(args.delivery_id) ||
      typeof args.content !== 'string' ||
      !args.content.length ||
      !args.content.isWellFormed() ||
      Buffer.byteLength(args.content, 'utf8') > 65536
    ) {
      return { isError: true, content: [{ type: 'text', text: 'Invalid reply arguments.' }] };
    }
    try {
      await scopedCall('POST', `/adapter/v1/deliveries/${args.delivery_id}/reply`, {
        content: args.content
      });
      return { content: [{ type: 'text', text: 'Reply saved by the Capsule host.' }] };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `${error.message}. An uncertain reply can be retried with identical content.`
          }
        ]
      };
    }
  }

  let started = false;
  let polling;
  let heartbeat;
  function start() {
    if (started) return;
    started = true;
    // Harness acceptance can take longer than one lease. Renew independently
    // while a claimed delivery is being submitted; never claim another then.
    heartbeat = setInterval(() => {
      void ensureConnection().catch(() => {
        connected = false;
      });
    }, leaseRenewMs);
    polling = (async () => {
      let backoff = 250;
      let warned = false;
      while (!stop.signal.aborted) {
        try {
          await ensureConnection();
          // A failed acknowledgment can be retried without emitting content again.
          while (acknowledge.length) {
            await scopedCall('POST', acknowledge[0], {});
            acknowledge.shift();
          }
          const handoff = await scopedCall('POST', '/adapter/v1/next', {});
          if (handoff) {
            if (handoff.delivery.session_id !== sessionId)
              throw new AttachmentChanged('invalid session handoff');
            if (stop.signal.aborted) return;
            await notify({
              content: handoff.request.content,
              meta: {
                kind: 'message',
                delivery_id: handoff.delivery.id,
                request_id: handoff.delivery.request_id,
                sender_host_id: handoff.delivery.sender_host_id,
                session_id: handoff.delivery.session_id,
                origin_agent_id: handoff.request.origin?.agent_id ?? null,
                origin_session_id: handoff.request.origin?.session_id ?? null,
                sender_person_id: handoff.sender_person_id ?? null,
                sender_person: handoff.sender_person ?? null
              }
            });
            acknowledge.push(`/adapter/v1/deliveries/${handoff.delivery.id}/forwarded`);
          }
          const response = await scopedCall('POST', '/adapter/v1/replies/next', {});
          if (response) {
            if (response.delivery.session_id !== sessionId)
              throw new AttachmentChanged('invalid reply session');
            if (stop.signal.aborted) return;
            await notify({
              content: response.reply.content,
              meta: {
                kind: 'reply',
                notification_id: response.delivery.id,
                request_id: response.delivery.request_id,
                peer_host_id: response.delivery.peer_host_id,
                session_id: response.delivery.session_id,
                origin_agent_id: response.reply.origin?.agent_id ?? null,
                origin_session_id: response.reply.origin?.session_id ?? null
              }
            });
            acknowledge.push(`/adapter/v1/replies/${response.delivery.id}/forwarded`);
          }
          while (acknowledge.length) {
            await scopedCall('POST', acknowledge[0], {});
            acknowledge.shift();
          }
          if (warned) log('Capsule adapter reconnected to its original attachment.');
          warned = false;
          backoff = 250;
          if (!handoff && !response) await delay(pollMs, undefined, { signal: stop.signal });
        } catch (error) {
          if (stop.signal.aborted) return;
          connected = false;
          if (
            error.fatal ||
            error instanceof AttachmentChanged ||
            error.status === 409 ||
            error.status === 400
          )
            throw error;
          if (error.status === 403) {
            authorizationFailureAt ??= Date.now();
            if (Date.now() - authorizationFailureAt >= recoveryMs) throw error;
          }
          if (!warned)
            log(
              'Capsule connection interrupted. Reconnecting the original instance; uncertain content will not be redelivered.'
            );
          warned = true;
          await delay(backoff, undefined, { signal: stop.signal });
          backoff = Math.min(backoff * 2, 5000);
        }
      }
    })().catch((error) => {
      terminalError = error;
      connected = false;
      clearInterval(heartbeat);
      if (!stop.signal.aborted) {
        log(`Capsule polling stopped: ${error.message}. Inspect attachment and delivery state.`);
        onFatal(error);
      }
    });
  }
  return {
    tools,
    callTool,
    start,
    stop: async () => {
      stop.abort();
      clearInterval(heartbeat);
      await polling;
    }
  };
}

export async function configuredAdapter(
  socketPath,
  credentialPath,
  { instanceId = `instance_${randomBytes(32).toString('hex')}`, pollMs = 500, ...options } = {}
) {
  const initial = await readCredential(credentialPath);
  let credential = initial;
  return createAdapter({
    ...options,
    call: adapterClient(socketPath, () => credential.token, instanceId),
    sessionId: initial.adapter.session_id,
    adapterId: initial.adapter.id,
    instanceId,
    pollMs,
    reloadCredential: async () => {
      const next = await readCredential(credentialPath);
      if (
        next.adapter.id !== initial.adapter.id ||
        next.adapter.session_id !== initial.adapter.session_id
      ) {
        throw new AttachmentChanged('credential file selects a different authorization or session');
      }
      credential = next;
    }
  });
}
