import { tool } from '@opencode-ai/plugin';
import { tools } from '../shared/adapter.mjs';
import { readBinding } from './binding.mjs';
import { proxyTool } from '../shared/tools.mjs';
export async function Capsule(_input, { bindings } = {}) {
  if (typeof bindings !== 'string' || !bindings.startsWith('/'))
    throw new Error('Capsule requires a private absolute bindings directory.');
  const schema = tool.schema;
  const string = (property) => {
    let result = schema.string();
    if (property.pattern) result = result.regex(new RegExp(property.pattern));
    if (property.minLength) result = result.min(property.minLength);
    if (property.maxLength) result = result.max(property.maxLength);
    return result;
  };
  return {
    tool: Object.fromEntries(
      tools.map((definition) => {
        const required = definition.inputSchema.required ?? [];
        const args = Object.fromEntries(
          Object.entries(definition.inputSchema.properties).map(([name, property]) => [
            name,
            required.includes(name) ? string(property) : string(property).optional()
          ])
        );
        const name = 'capsule_' + definition.name;
        return [
          name,
          tool({
            description: definition.description,
            args,
            async execute(args, context) {
              // sessionID comes from OpenCode's tool runtime, never model arguments.
              const binding = await readBinding(bindings, context.sessionID);
              await context.ask({ permission: name, patterns: ['*'], always: ['*'], metadata: {} });
              const result = await proxyTool(
                binding.socket,
                context.sessionID,
                definition.name,
                args
              );
              const output = result.content.map((item) => item.text).join('\n');
              if (result.isError) throw new Error(output);
              return output;
            }
          })
        ];
      })
    )
  };
}
