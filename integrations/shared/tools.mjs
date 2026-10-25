import { createHash, randomBytes } from 'node:crypto';
import http from 'node:http';
import { createConnection } from 'node:net';
import { dirname, join } from 'node:path';
import { chmod, lstat, mkdir, unlink } from 'node:fs/promises';
import { lostCallRecovery } from './adapter.mjs';
const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino;
const socketDirectory = () => `/tmp/peerspan-tools-${process.getuid()}`;
// The daemon's protocol_version pattern.
const protocolPattern = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/;

// macOS has a 104-byte sun_path, including its terminating NUL. Profiles
// containing a full host ID commonly exceed it. Use a stable private path
// so both the native client and crash recovery select the same gateway.
export function toolSocketPath(path) {
  if (Buffer.byteLength(path) <= 103) return path;
  const digest = createHash('sha256').update(path).digest('hex').slice(0, 32);
  return join(socketDirectory(), digest + '.sock');
}

async function reclaimSocket(socket) {
  if (dirname(socket) === socketDirectory()) {
    await mkdir(socketDirectory(), { mode: 0o700 }).catch((error) => {
      if (error.code !== 'EEXIST') throw error;
    });
  }
  const parent = await lstat(dirname(socket));
  if (!parent.isDirectory() || parent.uid !== process.getuid() || parent.mode & 0o077)
    throw new Error('Peerspan tool sockets must be in a private owned directory.');
  let stat;
  try {
    stat = await lstat(socket);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  if (!stat.isSocket() || stat.uid !== process.getuid() || stat.mode & 0o077)
    throw new Error('Unexpected Peerspan tool socket.');
  // Only an explicit refusal proves a leftover socket has no listener.
  // Timeouts and other errors retain it, as does a successful connection.
  const live = await new Promise((resolve, reject) => {
    const probe = createConnection({ path: socket });
    probe.setTimeout(1000, () => {
      probe.destroy();
      reject(new Error('Could not confirm that the previous Peerspan bridge stopped.'));
    });
    probe.once('connect', () => { probe.destroy(); resolve(true); });
    probe.once('error', (error) => {
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOENT') resolve(false);
      else reject(error);
    });
  });
  if (live) throw new Error('A Peerspan tool socket is already serving a bridge.');
  try {
    if (!sameFile(stat, await lstat(socket)))
      throw new Error('The Peerspan tool socket changed during recovery.');
    await unlink(socket);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

export async function toolGateway(socket, callerSession, adapter, emit = () => {}) {
  await reclaimSocket(socket);
  // The protocol revision the harness's MCP server negotiated, as sent with
  // the latest accepted tool call that carried one.
  let protocolVersion;
  const server = http.createServer(async (request, response) => {
    const reply = (status, value) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(value));
    };
    if (request.method !== 'POST' || request.url !== '/tool') {
      reply(404, {});
      return;
    }
    try {
      let size = 0;
      const chunks = [];
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 1048576) throw new Error('Tool request too large.');
        chunks.push(chunk);
      }
      const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (value.caller_session !== callerSession) {
        reply(403, {});
        return;
      }
      // Recorded before the call, so the adapter reports it before this
      // call's daemon request (peerspan_ready included).
      if (typeof value.protocol_version === 'string' && protocolPattern.test(value.protocol_version))
        protocolVersion = value.protocol_version;
      const result = await adapter.callTool(value.name, value.arguments);
      reply(200, result);
      emit({
        type: 'tool_result',
        tool: value.name,
        success: !result.isError,
        content: result.content
      });
    } catch {
      reply(400, {});
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 15000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socket, resolve);
  });
  let owned;
  try {
    await chmod(socket, 0o600);
    owned = await lstat(socket);
  } catch (error) {
    await new Promise((resolve) => server.close(resolve));
    throw error;
  }
  return {
    socket,
    protocolVersion: () => protocolVersion,
    ownsSocket: async () => {
      if (!server.listening) return false;
      try { return sameFile(owned, await lstat(socket)); }
      catch (error) { if (error.code === 'ENOENT') return false; throw error; }
    },
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      })
  };
}
// protocolVersion, when given, is the protocol revision the caller's MCP
// server negotiated with the harness; the gateway reports it to the daemon.
export async function proxyTool(socket, callerSession, name, args, protocolVersion) {
  // Allocate at the harness side of this extra hop so a lost gateway response
  // still leaves the caller with the exact ID the Peerspan host may have saved.
  // call_capability likewise allocates its call_id here.
  const objectArgs = args && typeof args === 'object' && !Array.isArray(args);
  const requestId =
    name === 'send'
      ? (args?.request_id ?? `request_${randomBytes(16).toString('hex')}`)
      : undefined;
  const callId =
    name === 'call_capability'
      ? (args?.call_id ?? `call_${randomBytes(16).toString('hex')}`)
      : undefined;
  const input =
    name === 'send' && objectArgs
      ? { ...args, request_id: requestId }
      : name === 'call_capability' && objectArgs
        ? { ...args, call_id: callId }
        : args;
  // The host may hold call_capability for up to 50 s; list_capabilities may
  // return up to 16 MiB.
  const timeout = name === 'call_capability' ? 60000 : 40000;
  const limit = name === 'list_capabilities' ? 67108864 : 1048576;
  try {
    return await new Promise((resolve, reject) => {
      const encoded = Buffer.from(
        JSON.stringify({
          caller_session: callerSession,
          name,
          arguments: input,
          ...(typeof protocolVersion === 'string' && { protocol_version: protocolVersion })
        })
      );
      const request = http.request(
        {
          socketPath: socket,
          path: '/tool',
          method: 'POST',
          agent: false,
          headers: { 'Content-Type': 'application/json', 'Content-Length': encoded.length },
          signal: AbortSignal.timeout(timeout)
        },
        (response) => {
          const chunks = [];
          let size = 0;
          response.on('data', (chunk) => {
            size += chunk.length;
            if (size > limit) response.destroy();
            else chunks.push(chunk);
          });
          response.on('error', () => reject(new Error('Peerspan tool response unavailable.')));
          response.on('end', () => {
            if (response.statusCode !== 200) {
              reject(
                new Error('This harness session is not authorized for this Peerspan attachment.')
              );
              return;
            }
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
              reject(new Error('Invalid Peerspan tool response.'));
            }
          });
        }
      );
      request.on('error', () =>
        reject(
          new Error(
            'Peerspan bridge unavailable; an uncertain send must be checked with send_status.'
          )
        )
      );
      request.end(encoded);
    });
  } catch (error) {
    if (name === 'call_capability')
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              call_id: callId,
              address: args?.address,
              error: error.message,
              recovery: lostCallRecovery
            })
          }
        ]
      };
    if (name !== 'send') throw error;
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            request_id: requestId,
            ...(args?.to === undefined ? { destination: args?.destination } : { to: args.to }),
            error: error.message,
            recovery:
              'The host may have saved this send and retries it automatically. Check send_status with this request_id; only if not_recorded, retry the identical destination/content with this same ID.'
          })
        }
      ]
    };
  }
}
