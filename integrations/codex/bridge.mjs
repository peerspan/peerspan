import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { privateJSON } from '../shared/provider.mjs';
import { configuredAdapter } from '../shared/adapter.mjs';
import { presentEvent } from '../shared/presentation.mjs';
import { Connection } from './connection.mjs';
import { ExistingThread } from './thread.mjs';
import { toolGateway } from '../shared/tools.mjs';
import { installEntry, removeEntry } from './configuration.mjs';
export async function run(config, { emit = () => {} } = {}) {
  const rpc = new Connection(config.codex_socket);
  let adapter,
    gateway,
    thread,
    closing = false,
    entryInstalled = false;
  let startupFinished;
  const startup = new Promise((resolve) => {
    startupFinished = resolve;
  });
  let finish;
  const done = new Promise((resolve) => {
    finish = resolve;
  });
  const close = async (error) => {
    if (closing) return;
    closing = true;
    if (error) emit({ type: 'error', detail: error.message });
    await startup;
    thread?.stop();
    // Remove only our unique MCP entry. If the backend failed, the dead private
    // gateway remains inaccessible; neither Codex nor its thread is restarted.
    if (entryInstalled && !rpc.failure) {
      try {
        await removeEntry(rpc, config.server_name, config.mcp_entry);
      } catch {
        emit({
          type: 'configuration_cleanup_unconfirmed',
          detail:
            'Capsule could not confirm cleanup of its MCP entry; inspect it before removing it.'
        });
      }
    }
    const stopped = adapter?.stop();
    rpc.close();
    await gateway?.close();
    await stopped;
    finish(error ? 1 : 0);
  };
  const onSignal = () => {
    void close();
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  rpc.on('failure', (error) => {
    if (!closing) void close(error);
  });
  try {
    await rpc.initialize();
    thread = new ExistingThread(rpc, config.thread_id, {
      emit,
      onFatal: (error) => {
        void close(error);
      }
    });
    const selected = await thread.attach();
    if (closing) throw new Error('Attachment stopped during setup.');
    adapter = await configuredAdapter(config.socket, config.credential, {
      notify: async (event) => {
        try {
          const presentation = presentEvent(event);
          const id = await thread.submit(
            presentation.text + '\n\nMCP server: ' + config.server_name +
              '\n' + presentation.metadata
          );
          emit({
            type: 'input_accepted',
            kind: event.meta.kind,
            request_id: event.meta.request_id,
            queued_id: id
          });
        } catch (error) {
          error.fatal = true;
          throw error;
        }
      },
      onFatal: (error) => {
        void close(error);
      }
    });
    if (closing) throw new Error('Attachment stopped during setup.');
    gateway = await toolGateway(config.tool_socket, config.thread_id, adapter, emit);
    if (closing) throw new Error('Attachment stopped during setup.');
    await installEntry(rpc, config.server_name, config.mcp_entry);
    entryInstalled = true;
    await rpc.request('config/mcpServer/reload', {});
    if (!closing) {
      thread.start();
      adapter.start();
      emit({
        type: 'ready',
        thread_id: config.thread_id,
        model: selected.model,
        approval_policy: selected.approvalPolicy,
        sandbox: selected.sandbox
      });
    }
  } catch (error) {
    void close(error);
  } finally {
    startupFinished();
  }
  const code = await done;
  process.removeListener('SIGINT', onSignal);
  process.removeListener('SIGTERM', onSignal);
  return code;
}
async function main() {
  const { values } = parseArgs({
    options: { config: { type: 'string' }, json: { type: 'boolean' } }
  });
  if (!values.config) throw new Error('Provide the private --config file.');
  const config = await privateJSON(resolve(values.config));
  if (config.version !== 1 || !config.thread_id || !config.codex_socket?.startsWith('/'))
    throw new Error('Invalid existing-session configuration.');
  const emit = (event) => {
    if (values.json) process.stdout.write(JSON.stringify(event) + '\n');
    else if (event.type === 'ready')
      process.stdout.write(
        'Capsule attached to existing Codex thread ' +
          event.thread_id +
          '. Stop this bridge with Ctrl-C; Codex continues running.\n'
      );
    else if (event.type === 'error' || event.type === 'configuration_cleanup_unconfirmed')
      process.stderr.write(event.detail + '\n');
  };
  process.exitCode = await run(config, { emit });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main().catch(() => {
    process.stderr.write('Capsule could not attach to the selected Codex session.\n');
    process.exitCode = 1;
  });
