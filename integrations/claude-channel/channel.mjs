import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  InitializeRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

export { readCredential, AdapterError, adapterClient } from '../shared/adapter.mjs';
import { createAdapter, configuredAdapter, instructions } from '../shared/adapter.mjs';

// Claude Code accepts only string meta values and drops the connection on any
// other, so null fields are omitted and booleans, numbers, and lists are sent
// as JSON text.
export function channelParams(params) {
  const meta = {};
  for (const [key, value] of Object.entries(params.meta ?? {})) {
    if (value === null || value === undefined) continue;
    meta[key] = typeof value === 'string' ? value : JSON.stringify(value);
  }
  return { ...params, meta };
}

// channelServer builds the MCP server; negotiated records the protocol
// revision it agreed with Claude Code, which the adapter reports on connect.
function channelServer(adapter, negotiated) {
  const server = new Server(
    { name: 'capsule', version: '0.1.0' },
    {
      capabilities: { experimental: { 'claude/channel': {} }, tools: {} },
      instructions
    }
  );
  server.setRequestHandler(InitializeRequestSchema, async (request) => {
    const result = await server._oninitialize(request);
    negotiated.version = result.protocolVersion;
    return result;
  });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: adapter.tools }));
  server.setRequestHandler(CallToolRequestSchema, (request) =>
    adapter.callTool(request.params.name, request.params.arguments)
  );
  server.onclose = () => {
    void adapter.stop();
  };
  server.oninitialized = () => adapter.start();
  return {
    server,
    stop: async () => {
      await server.close();
      await adapter.stop();
    }
  };
}
const reattach = 'capsule attach claude';
export function createChannel(options) {
  let channel;
  const negotiated = {};
  const adapter = createAdapter({
    reattach,
    ...options,
    protocolVersion: () => negotiated.version,
    notify: (params) =>
      channel.server.notification({
        method: 'notifications/claude/channel',
        params: channelParams(params)
      })
  });
  channel = channelServer(adapter, negotiated);
  return channel;
}
export async function configuredChannel(socketPath, credentialPath, options = {}) {
  let channel;
  const negotiated = {};
  const adapter = await configuredAdapter(socketPath, credentialPath, {
    reattach,
    ...options,
    protocolVersion: () => negotiated.version,
    notify: (params) =>
      channel.server.notification({
        method: 'notifications/claude/channel',
        params: channelParams(params)
      })
  });
  channel = channelServer(adapter, negotiated);
  return channel;
}

async function main() {
  const { values } = parseArgs({
    options: {
      socket: { type: 'string' },
      'credential-file': { type: 'string' },
      'poll-ms': { type: 'string', default: '500' },
      help: { type: 'boolean', short: 'h' }
    }
  });
  if (values.help) {
    process.stdout.write(
      'Usage: node channel.mjs --socket /absolute/adapter.sock --credential-file /absolute/credential.json [--poll-ms 500]\n'
    );
    return;
  }
  const pollMs = Number(values['poll-ms']);
  if (
    !values.socket ||
    !values['credential-file'] ||
    !Number.isInteger(pollMs) ||
    pollMs < 50 ||
    pollMs > 10000
  ) {
    throw new Error('provide --socket and --credential-file; --poll-ms must be 50 to 10000');
  }
  const channel = await configuredChannel(
    resolve(values.socket),
    resolve(values['credential-file']),
    {
      pollMs,
      // A fatal stop has already sent its disconnected event and written its
      // reason; exiting lets Claude Code show the server as failed.
      onFatal: () => process.exit(1)
    }
  );
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.once(signal, () => {
      void channel.stop();
    });
  process.stdin.once('end', () => {
    void channel.stop();
  });
  await channel.server.connect(new StdioServerTransport());
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => {
    process.stderr.write(
      'Capsule channel could not start; check its arguments and private credential file.\n'
    );
    process.exitCode = 1;
  });
}
