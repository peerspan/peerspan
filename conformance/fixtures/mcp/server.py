"""A fixture MCP stdio server for conformance/tools.py (written from docs/tools-contract.md).

Speaks newline-delimited JSON-RPC 2.0 over stdio, as MCP's stdio transport does: `initialize`,
`notifications/initialized`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, and
`notifications/cancelled`. Uses only Python's standard library; run it with `python3 -I` so that nothing is
imported from the working directory (the agent's workspace).

Every start, request, execution, cancellation, and exit is appended to the JSON-lines file given by `--log`
(or the `FIXTURE_LOG` variable). Tool executions record their arguments, never environment values.

Options (each also accepted as NAME=VALUE, such as `log=PATH`):
  --log PATH       the execution log (required unless FIXTURE_LOG is set)
  --control PATH    a JSON object read at start and at every request; keys below
  --label NAME      adds a read-only tool `from_NAME`, so a snapshot shows which definition ran; repeatable
  --page-size N     paginate tools/list and resources/list with `nextCursor`, N entries per page
  --generate N      adds N generated read-only tools `gen_0000` ... (for pagination)

Control keys (all optional):
  exit_on_start     exit with status 3 before reading anything (a start failure)
  init_delay        seconds to wait before answering `initialize`
  list_delay        seconds to wait before answering `tools/list`
  list_error        answer `tools/list` with a JSON-RPC error
  huge_snapshot     give every tool a 128 KiB description, so that the snapshot exceeds 1 MiB
  extra_tools       [{"name": ..., "read_only": true|false}] added to the tool list

Tools (`readOnlyHint` true unless noted):
  echo {text}                 returns text
  info {}                     labels, pid, and working directory
  env_names {}                the names (never the values) of the environment variables it was given
  env_matches {name, sha256}  whether that variable is present and its value's SHA-256 is sha256
  sleep {seconds, text?}      sleeps, then returns; a cancellation ends it without a response
  fail {message?, code?}      a JSON-RPC error
  tool_error {message?}       a CallToolResult with isError true
  big {bytes}                 a text result of that many characters
  crash {delay?}              exits the process mid-call, after `delay` seconds
  write_note {text}           readOnlyHint false: a write tool
  purge {}                    no annotations at all: not read-only
"""
import hashlib
import json
import os
import signal
import sys
import threading
import time

PROTOCOLS = ('2025-06-18', '2025-03-26', '2024-11-05')
RESOURCES = [
    {'uri': 'fixture://docs/readme', 'name': 'readme', 'description': 'The fixture readme', 'mimeType': 'text/plain'},
    {'uri': 'fixture://docs/guide', 'name': 'guide', 'description': 'The fixture guide', 'mimeType': 'text/markdown'},
    {'uri': 'file:///srv/docs/a.txt', 'name': 'a.txt', 'description': 'A document', 'mimeType': 'text/plain'},
    {'uri': 'file:///srv/private/b.txt', 'name': 'b.txt', 'description': 'A private document',
     'mimeType': 'text/plain'},
]


def parse(argv):
    options = {'log': os.environ.get('FIXTURE_LOG'), 'control': None, 'labels': [], 'page_size': 0, 'generate': 0}
    # Each option is also accepted as NAME=VALUE (log=PATH, label=NAME, ...), so that a profile's `--arg`
    # values never have to start with a hyphen.
    expanded = []
    for item in argv:
        name, equals, value = item.partition('=')
        if equals and not item.startswith('-') and name in ('log', 'control', 'label', 'page-size', 'generate'):
            expanded += ['--' + name, value]
        else:
            expanded.append(item)
    argv = expanded
    i = 0
    while i < len(argv):
        flag = argv[i]
        value = argv[i + 1] if i + 1 < len(argv) else None
        if flag == '--log':
            options['log'] = value
        elif flag == '--control':
            options['control'] = value
        elif flag == '--label':
            options['labels'].append(value)
        elif flag == '--page-size':
            options['page_size'] = int(value)
        elif flag == '--generate':
            options['generate'] = int(value)
        else:
            sys.stderr.write(f'fixture: unknown argument {flag!r}\n')
            i += 1
            continue
        i += 2
    return options


OPTIONS = parse(sys.argv[1:])
LOCK = threading.Lock()
WRITE = threading.Lock()
ACTIVE = {}          # JSON-RPC id -> threading.Event set on cancellation
RUNNING = [0]        # executions in progress


def log(event, **fields):
    if not OPTIONS['log']:
        return
    record = {'event': event, 'pid': os.getpid(), 'time': time.time(), **fields}
    with LOCK:
        with open(OPTIONS['log'], 'a') as f:
            f.write(json.dumps(record) + '\n')


def control():
    path = OPTIONS['control']
    if not path:
        return {}
    try:
        with open(path) as f:
            value = json.load(f)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def send(message):
    data = json.dumps(message, separators=(',', ':')) + '\n'
    with WRITE:
        sys.stdout.write(data)
        sys.stdout.flush()


def result(request_id, value):
    send({'jsonrpc': '2.0', 'id': request_id, 'result': value})


def error(request_id, code, message, data=None):
    body = {'code': code, 'message': message}
    if data is not None:
        body['data'] = data
    send({'jsonrpc': '2.0', 'id': request_id, 'error': body})


def tool(name, description, properties=None, read_only=True, annotate=True):
    entry = {'name': name, 'description': description,
             'inputSchema': {'type': 'object', 'properties': properties or {}, 'additionalProperties': True}}
    if annotate:
        entry['annotations'] = {'readOnlyHint': read_only}
    return entry


def tools():
    c = control()
    padding = ' ' + 'x' * 131072 if c.get('huge_snapshot') else ''
    entries = [
        tool('echo', 'Returns its text' + padding, {'text': {'type': 'string'}}),
        tool('info', 'Labels, pid, and working directory' + padding),
        tool('env_names', 'Names of the environment variables given' + padding),
        tool('env_matches', 'Whether a variable has the value with this SHA-256' + padding,
             {'name': {'type': 'string'}, 'sha256': {'type': 'string'}}),
        tool('sleep', 'Sleeps for seconds' + padding, {'seconds': {'type': 'number'}, 'text': {'type': 'string'}}),
        tool('fail', 'Answers with a JSON-RPC error' + padding, {'message': {'type': 'string'}}),
        tool('tool_error', 'Returns isError' + padding, {'message': {'type': 'string'}}),
        tool('big', 'Returns a result of the given size' + padding, {'bytes': {'type': 'integer'}}),
        tool('crash', 'Exits mid-call' + padding, {'delay': {'type': 'number'}}),
        tool('write_note', 'Writes a note' + padding, {'text': {'type': 'string'}}, read_only=False),
        tool('purge', 'Deletes every note; no annotations' + padding, annotate=False),
    ]
    entries += [tool(f'from_{label}', f'Present when started with --label {label}' + padding)
                for label in OPTIONS['labels']]
    entries += [tool(f'gen_{n:04d}', f'Generated tool {n}' + padding) for n in range(OPTIONS['generate'])]
    for extra in c.get('extra_tools') or []:
        entries.append(tool(extra['name'], 'Added by the control file' + padding, read_only=bool(extra.get('read_only'))))
    return entries


def page(items, cursor, key):
    size = OPTIONS['page_size']
    start = int(cursor) if cursor else 0
    if not size:
        return {key: items[start:]}
    chunk = items[start:start + size]
    value = {key: chunk}
    if start + size < len(items):
        value['nextCursor'] = str(start + size)
    return value


def text_result(text, is_error=False):
    value = {'content': [{'type': 'text', 'text': text}]}
    if is_error:
        value['isError'] = True
    return value


def execute(request_id, name, arguments, cancelled):
    """One tools/call, on its own thread."""
    with LOCK:
        RUNNING[0] += 1
        concurrent = RUNNING[0]
    log('call', id=request_id, name=name, arguments=arguments, concurrent=concurrent)
    respond = True
    try:
        if name == 'echo':
            reply = text_result(str(arguments.get('text', '')))
        elif name == 'info':
            reply = text_result(json.dumps({'labels': OPTIONS['labels'], 'pid': os.getpid(), 'cwd': os.getcwd()}))
        elif name == 'env_names':
            reply = text_result(json.dumps(sorted(os.environ)))
        elif name == 'env_matches':
            value = os.environ.get(str(arguments.get('name', '')))
            matches = value is not None and hashlib.sha256(value.encode()).hexdigest() == arguments.get('sha256')
            reply = text_result(json.dumps({'present': value is not None, 'matches': matches}))
        elif name == 'sleep':
            finished = not cancelled.wait(float(arguments.get('seconds', 1)))
            if not finished:
                respond = False
                reply = None
            else:
                reply = text_result('slept ' + str(arguments.get('text', '')))
        elif name == 'fail':
            log('done', id=request_id, name=name, outcome='jsonrpc_error')
            error(request_id, int(arguments.get('code', -32000)), str(arguments.get('message', 'fixture failure')))
            return
        elif name == 'tool_error':
            reply = text_result(str(arguments.get('message', 'the tool failed')), is_error=True)
        elif name == 'big':
            reply = text_result('b' * int(arguments.get('bytes', 0)))
        elif name == 'crash':
            time.sleep(float(arguments.get('delay', 0)))
            log('exit', reason='crash')
            os._exit(7)
        elif name == 'write_note':
            reply = text_result('noted ' + str(arguments.get('text', '')))
        elif name == 'purge':
            reply = text_result('purged')
        elif name.startswith('from_') or name.startswith('gen_') or name in {t['name'] for t in tools()}:
            reply = text_result(name)
        else:
            log('done', id=request_id, name=name, outcome='unknown_tool')
            error(request_id, -32602, f'Unknown tool: {name}')
            return
        if respond:
            log('done', id=request_id, name=name, outcome='result')
            result(request_id, reply)
        else:
            log('done', id=request_id, name=name, outcome='cancelled')
    finally:
        with LOCK:
            RUNNING[0] -= 1
            ACTIVE.pop(request_id, None)


def read_resource(request_id, uri):
    log('read', id=request_id, uri=uri)
    for entry in RESOURCES:
        if entry['uri'] == uri:
            result(request_id, {'contents': [{'uri': uri, 'mimeType': entry['mimeType'],
                                              'text': f'contents of {uri}'}]})
            return
    error(request_id, -32002, 'Resource not found', {'uri': uri})


def handle(message):
    method = message.get('method')
    request_id = message.get('id')
    params = message.get('params') or {}
    if method is None:
        return  # a response to something we never sent
    if request_id is None:
        if method == 'notifications/cancelled':
            target = params.get('requestId')
            log('cancelled', request_id=target, reason=params.get('reason'))
            event = ACTIVE.get(target)
            if event:
                event.set()
        return
    if method == 'initialize':
        delay = control().get('init_delay')
        if delay:
            time.sleep(float(delay))
        requested = params.get('protocolVersion')
        log('initialize', protocol=requested, client=params.get('clientInfo'))
        result(request_id, {'protocolVersion': requested if requested in PROTOCOLS else PROTOCOLS[0],
                            'capabilities': {'tools': {'listChanged': False},
                                             'resources': {'subscribe': False, 'listChanged': False}},
                            'serverInfo': {'name': 'peerspan-conformance-fixture', 'version': '1'}})
    elif method == 'ping':
        result(request_id, {})
    elif method == 'tools/list':
        c = control()
        if c.get('list_delay'):
            time.sleep(float(c['list_delay']))
        log('list', kind='tools', cursor=params.get('cursor'))
        if c.get('list_error'):
            error(request_id, -32603, 'tools/list failed (fixture)')
            return
        result(request_id, page(tools(), params.get('cursor'), 'tools'))
    elif method == 'resources/list':
        log('list', kind='resources', cursor=params.get('cursor'))
        result(request_id, page(RESOURCES, params.get('cursor'), 'resources'))
    elif method == 'tools/call':
        event = threading.Event()
        with LOCK:
            ACTIVE[request_id] = event
        threading.Thread(target=execute, args=(request_id, str(params.get('name')), params.get('arguments') or {},
                                               event), daemon=True).start()
    elif method == 'resources/read':
        threading.Thread(target=read_resource, args=(request_id, str(params.get('uri'))), daemon=True).start()
    else:
        error(request_id, -32601, f'Method not found: {method}')


def stop(signum, frame):
    log('exit', reason=f'signal {signum}')
    os._exit(0)


def main():
    if control().get('exit_on_start'):
        log('start_failed', argv=sys.argv[1:])
        sys.exit(3)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log('start', argv=sys.argv[1:], cwd=os.getcwd())
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            error(None, -32700, 'Parse error')
            continue
        if isinstance(message, list):
            for item in message:
                handle(item)
        elif isinstance(message, dict):
            handle(message)
    log('exit', reason='stdin closed')


if __name__ == '__main__':
    main()
