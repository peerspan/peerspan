import { parseArgs } from 'node:util';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { proxyTool } from '../shared/tools.mjs';
import { tools, instructions } from '../shared/adapter.mjs';
const { values } = parseArgs({
  options: { socket: { type: 'string' }, thread: { type: 'string' } }
});
if (!values.socket?.startsWith('/') || !values.thread)
  throw new Error('Provide a Capsule tool socket and the selected Codex thread.');
// This MCP consumer never reads credentials, owns a lease, or claims a message.
const server = new Server(
  { name: 'capsule', version: '0.1.0' },
  { capabilities: { tools: {} }, instructions }
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: tools }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params._meta?.threadId !== values.thread)
    return {
      isError: true,
      content: [
        { type: 'text', text: 'This Codex thread is not selected for this Capsule attachment.' }
      ]
    };
  try {
    return await proxyTool(
      values.socket,
      values.thread,
      request.params.name,
      request.params.arguments
    );
  } catch (error) {
    return { isError: true, content: [{ type: 'text', text: error.message }] };
  }
});
process.stdin.once('end', () => {
  void server.close();
});
await server.connect(new StdioServerTransport());
