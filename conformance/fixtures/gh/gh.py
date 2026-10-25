"""A fake GitHub CLI (`gh`) for the capabilities conformance suite (slice 3: the built-in `gh` source).

conformance/capability_bounds.py installs it as an executable named `gh` whose first lines are a shebang naming
this suite's Python and `ROOT = '...'`, followed by this file. Peerspan runs it with an environment it chooses
(the contract fixes it), so every setting comes from files under ROOT, never from the environment:

- ROOT/control.json: how to answer (below); re-read at every run.
- ROOT/log.jsonl: one `start` entry per run (argv, the whole environment with the token variables replaced by their
  SHA-256, working directory and whether it is empty and its mode, GH_CONFIG_DIR's emptiness and mode, standard
  input read to end of file, or null when it stayed open for 3 seconds, pid), then `end` (exit code), `signal`, or
  `child` entries.

control.json:
- version: the version `gh --version` reports (default 2.102.0); version_text replaces its whole output.
- accounts: [{login, state, active, token, token_source}] for `gh auth status --json hosts` (host github.com) and
  `gh auth token --hostname github.com --user LOGIN`; other_hosts: {HOST: [entries]} added as given.
- auth_status_exit / auth_token_exit: exit codes to use instead.
- users: {TOKEN: {login, scopes}}: `gh api --include --hostname github.com user` answers with that login and, when
  scopes is not null, an X-Oauth-Scopes header; a token not listed answers HTTP 401 and exits 1.
- repos: {REPO: BEHAVIOUR} and ops: {"issue list": BEHAVIOUR, ...}: how an operation answers, chosen by the
  --repo value (or the positional repository of `repo view`), else by the command, else the default. BEHAVIOUR
  keys: exit, stdout (exact text), stderr, stdout_b64 and stderr_b64 (exact bytes), sleep (seconds before
  answering), ignore_term (ignore SIGTERM while sleeping), child (start a child process in the same process group
  that ignores SIGTERM), big (write this many bytes of `x` to stdout first, then sleep), garbage (unparseable
  stdout), url (the URL a write prints). users entries may also have sleep, garbage, or exit.
Defaults: lists print a JSON array of one object holding every requested --json field; views an object; `pr diff`
a fixed diff (or file names with --name-only); writes the URL of a new issue (42) or comment.
"""
import hashlib
import json
import os
import signal
import stat
import sys
import time

CONTROL = os.path.join(ROOT, 'control.json')  # noqa: F821 (ROOT is prepended by the installer)
LOG = os.path.join(ROOT, 'log.jsonl')  # noqa: F821

DIFF = ('diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n--- a/README.md\n+++ b/README.md\n'
        '@@ -1 +1 @@\n-old line\n+new line\n')
FILES = ['README.md', 'src/main.go']


def control():
    try:
        with open(CONTROL) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def log(entry):
    entry['pid'] = os.getpid()
    entry['time'] = time.time()
    with open(LOG, 'a') as f:
        f.write(json.dumps(entry) + '\n')


def describe(path):
    if not path:
        return None
    try:
        st = os.stat(path)
        return {'path': path, 'mode': stat.S_IMODE(st.st_mode), 'entries': sorted(os.listdir(path))}
    except OSError as error:
        return {'path': path, 'error': str(error)}


def hidden_env():
    env = {}
    for name, value in os.environ.items():
        if name in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
            value = 'sha256:' + hashlib.sha256(value.encode()).hexdigest()
        env[name] = value
    return env


def finish(code, out='', err=''):
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if err:
        sys.stderr.write(err)
        sys.stderr.flush()
    log({'event': 'end', 'exit': code})
    sys.exit(code)


def flag(argv, name):
    """The value of --name=VALUE (also accepting `--name VALUE`, recorded either way by argv)."""
    values = flags(argv, name)
    return values[-1] if values else None


def flags(argv, name):
    out = []
    for i, a in enumerate(argv):
        if a.startswith(f'--{name}='):
            out.append(a.split('=', 1)[1])
        elif a == f'--{name}' and i + 1 < len(argv):
            out.append(argv[i + 1])
    return out


def sample(field, n=1, repo='acme/api'):
    if field in ('number',):
        return n
    if field in ('title', 'name', 'body', 'description'):
        return f'{field} {n}'
    if field in ('state',):
        return 'OPEN'
    if field in ('author',):
        return {'login': 'octo'}
    if field in ('labels', 'assignees', 'files', 'comments', 'reviews'):
        return []
    if field in ('url', 'link', 'homepageUrl'):
        return f'https://github.com/{repo}/issues/{n}'
    if field in ('isDraft', 'isArchived'):
        return False
    if field in ('additions', 'deletions', 'changedFiles', 'stargazerCount', 'forkCount'):
        return 3
    if field in ('nameWithOwner',):
        return repo
    return f'{field}-value'


def read_stdin():
    """Standard input, read until end of file; None when it is still open after 3 seconds without end of file
    (Peerspan closes it at once for operations without a body) or when there is none."""
    import select
    try:
        fd = sys.stdin.fileno()
    except (AttributeError, ValueError, OSError):
        return None
    data, deadline = b'', time.time() + 3
    while True:
        left = deadline - time.time()
        if left <= 0:
            return None
        try:
            ready, _, _ = select.select([fd], [], [], left)
        except (OSError, ValueError):
            return None
        if not ready:
            return None
        chunk = os.read(fd, 65536)
        if not chunk:
            return data.decode('utf-8', errors='replace')
        data += chunk


def main():
    argv = sys.argv[1:]
    c = control()
    body = read_stdin()
    entry = {'event': 'start', 'argv': argv, 'env': hidden_env(), 'cwd': describe(os.getcwd()),
             'config_dir': describe(os.environ.get('GH_CONFIG_DIR')), 'stdin': body}
    log(entry)

    if argv == ['--version']:
        version = c.get('version', '2.102.0')
        finish(0, c.get('version_text') or f'gh version {version} (2026-09-30)\n'
               f'https://github.com/cli/cli/releases/tag/v{version}\n')

    accounts = c.get('accounts') or []
    if argv[:2] == ['auth', 'status']:
        if c.get('auth_status_exit'):
            finish(c['auth_status_exit'], err='auth status failed\n')
        hosts = {}
        entries = []
        if os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN'):
            # As gh does: a token in the environment is reported as an extra account.
            entries.append({'state': 'success', 'active': True, 'host': 'github.com', 'login': 'env-user',
                            'tokenSource': 'GH_TOKEN' if os.environ.get('GH_TOKEN') else 'GITHUB_TOKEN',
                            'gitProtocol': 'https'})
        for a in accounts:
            entries.append({'state': a.get('state', 'success'), 'active': bool(a.get('active')),
                            'host': 'github.com', 'login': a['login'],
                            'tokenSource': a.get('token_source', 'keyring'), 'gitProtocol': 'https'})
        if entries:
            hosts['github.com'] = entries
        hosts.update(c.get('other_hosts') or {})
        finish(0, json.dumps({'hosts': hosts}) + '\n')

    if argv[:2] == ['auth', 'token']:
        if c.get('auth_token_exit'):
            finish(c['auth_token_exit'], err='no token\n')
        user = flag(argv, 'user')
        for a in accounts:
            if a['login'] == user and a.get('token'):
                finish(0, a['token'] + '\n')
        finish(1, err=f'no oauth token found for github.com account {user}\n')

    if argv[:1] == ['api']:
        token = os.environ.get('GH_TOKEN', '')
        user = (c.get('users') or {}).get(token)
        if user is not None and user.get('sleep'):
            time.sleep(user['sleep'])
        if user is not None and user.get('garbage'):
            finish(0, 'HTTP/2.0 200 OK\nContent-Type: text/html\n\n<html>not json</html>')
        if user is not None and user.get('exit'):
            finish(user['exit'], err='gh: failure\n')
        if user is None:
            finish(1, 'HTTP/2.0 401 Unauthorized\nContent-Type: application/json; charset=utf-8\n\n'
                   '{"message":"Bad credentials","status":"401"}', 'gh: Bad credentials (HTTP 401)\n')
        headers = 'HTTP/2.0 200 OK\nContent-Type: application/json; charset=utf-8\n'
        if user.get('scopes') is not None:
            headers += f'X-Oauth-Scopes: {user["scopes"]}\n'
        finish(0, headers + '\n' + json.dumps({'login': user['login'], 'id': 1}))

    command = ' '.join(argv[:2])
    repo = flag(argv, 'repo')
    if command == 'repo view' and len(argv) > 2:
        repo = argv[2]
    behaviour = dict((c.get('ops') or {}).get(command) or {})
    behaviour.update((c.get('repos') or {}).get(repo or '') or {})

    if behaviour.get('ignore_term'):
        signal.signal(signal.SIGTERM, lambda *a: log({'event': 'signal', 'signal': 'SIGTERM', 'ignored': True}))
    else:
        def terminated(*a):
            log({'event': 'signal', 'signal': 'SIGTERM'})
            sys.exit(143)
        signal.signal(signal.SIGTERM, terminated)

    if behaviour.get('child'):
        import subprocess
        child = subprocess.Popen([sys.executable, '-c', 'import signal, time\n'
                                  'signal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(600)'])
        log({'event': 'child', 'child_pid': child.pid})
    if behaviour.get('big'):
        chunk = b'x' * 65536
        left = behaviour['big']
        try:
            while left > 0:
                n = min(left, len(chunk))
                sys.stdout.buffer.write(chunk[:n])
                left -= n
            sys.stdout.flush()
        except BrokenPipeError:
            log({'event': 'broken_pipe'})
            os._exit(141)
    if behaviour.get('sleep'):
        deadline = time.time() + behaviour['sleep']
        while time.time() < deadline:
            time.sleep(0.1)
    if behaviour.get('stdout_b64') is not None:
        import base64
        sys.stdout.buffer.write(base64.b64decode(behaviour['stdout_b64']))
        sys.stdout.flush()
        if behaviour.get('stderr_b64'):
            sys.stderr.buffer.write(base64.b64decode(behaviour['stderr_b64']))
            sys.stderr.flush()
        finish(behaviour.get('exit', 0))
    if 'exit' in behaviour or 'stdout' in behaviour or 'stderr' in behaviour:
        finish(behaviour.get('exit', 0), behaviour.get('stdout', ''), behaviour.get('stderr', ''))
    if behaviour.get('garbage'):
        finish(0, 'this is not JSON {\n')

    fields = (flag(argv, 'json') or '').split(',') if flag(argv, 'json') else []
    repo = repo or 'acme/api'
    if command in ('issue list', 'pr list', 'pr checks'):
        finish(0, json.dumps([{f: sample(f, 1, repo) for f in fields}]) + '\n')
    if command in ('issue view', 'pr view', 'repo view'):
        n = int(argv[2]) if command != 'repo view' and len(argv) > 2 and argv[2].isdigit() else 1
        finish(0, json.dumps({f: sample(f, n, repo) for f in fields}) + '\n')
    if command == 'pr diff':
        if '--name-only' in argv:
            finish(0, '\n'.join(FILES) + '\n')
        finish(0, DIFF)
    if command == 'issue create':
        finish(0, behaviour.get('url') or f'https://github.com/{repo}/issues/42\n')
    if command in ('issue comment', 'pr comment'):
        n = argv[2] if len(argv) > 2 else '1'
        kind = 'pull' if command.startswith('pr') else 'issues'
        finish(0, behaviour.get('url') or f'https://github.com/{repo}/{kind}/{n}#issuecomment-123456\n')
    finish(1, err=f'unknown command "{command}" for "gh"\n')


main()
