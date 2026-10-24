#!/usr/bin/env python3
"""Live acceptance for agent capability tools (milestone 10 slice 2) with real harnesses and models.

Written from docs/capabilities-contract.md ("Agent tools (slice 2)", Verification, the live acceptance paragraph),
separately from deterministic conformance (capabilities.py and capability_agents.py). It records its results in
docs/results/capabilities-live.json (or --output).

Two persons on one machine, each with their own daemon and state, joined through a coordinator this run starts on
loopback (`--coord`):
- Bob (a temporary HOME): his Claude Code configuration (`~/.claude.json`, user scope) has a GitHub MCP server
  named `github` (by default `npx -y @modelcontextprotocol/server-github`, overridable with --github-command and
  --github-arg), whose token is the reference `${GITHUB_PERSONAL_ACCESS_TOKEN}`, captured at `attach` from the
  environment variable named by --token-env (default GITHUB_TOKEN). `attach claude --no-start` discovers it; Bob
  creates `github-issues` from it with `list_issues` selected and shares it with `person:alice`.
  Attach checks that Claude Code is signed in even with --no-start, so Bob's HOME links the operator's Claude
  login (`~/.claude/.credentials.json`, where Claude Code keeps it on Linux); Bob never starts Claude Code.
- Alice (the operator's real HOME, so each harness uses its existing login; a private XDG_CONFIG_HOME for
  Peerspan, with the operator's `opencode` configuration directory linked into it): for each of Claude Code, Codex,
  and OpenCode in turn, `attach HARNESS --calls -- ARGS` launches the harness non-interactively in a project of its
  own, asked in plain words to list the open issues of the test repository (--repo, or PEERSPAN_LIVE_REPO) through
  Bob's capability. Attach also discovers Alice's own harness MCP servers and snapshots them, as it always does.

For each harness the run checks that:
- the model called `list_capabilities` and `call_capability` with `bob/github-issues` and `list_issues`, and its
  answer names issues of the repository (their numbers or titles, from the GitHub API with the same token);
- both hosts recorded the call, with Alice's agent as `origin`;
- after Bob runs `unshare github-issues --with person:alice`, a second run is refused with the `not_found` text,
  nothing more is executed on Bob's host (no further received call), and the model's answer says it can no longer
  reach the capability (a keyword check, recorded with the answer for review).
Before each harness's run Bob shares again. The report records each harness's version, the negotiated MCP revision
(the adapter connection's `protocol_version` on Alice's host), and the model's tool calls and answers, as parsed from
the harness's JSON output; nothing about model behavior is inferred from notification acknowledgements.

The harness arguments after `--` default to print/exec modes with JSON output (see DEFAULT_ARGS); `{prompt}` in
them is replaced by the prompt. Override them per harness with --claude-args, --codex-args, or --opencode-args (a
JSON array). Tool calls are recognized in the output by name (any name ending in list_capabilities or
call_capability) with their arguments.

Needs Python 3, Node 22, the Go or Rust host binaries, the Go coordinator, the harnesses on PATH and logged in, a
GitHub token that can read the repository, and network access for the GitHub MCP server. It is never run by the
deterministic suites.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from coordination import Coordinator, wait_for
from host_service import stop_all
from launch_directory import DirectoryHost

REPO = Path(__file__).resolve().parents[1]
NOT_FOUND = ('No capability at this address is available to this session now. It may have been unshared, or its host '
             'may not have answered (see unanswered). Check list_capabilities.')
HARNESSES = {'claude': 'claude', 'codex': 'codex', 'opencode': 'opencode'}
DEFAULT_ARGS = {
    # Claude Code: print mode with the stream of tool calls; only the four tools allowed, built-in tools off.
    'claude': ['-p', '{prompt}', '--output-format', 'stream-json', '--verbose', '--setting-sources', '', '--tools', '',
               '--allowedTools', ','.join('mcp__peerspan__' + t for t in ('list_capabilities', 'call_capability',
                                                                          'call_status', 'call_cancel')),
               '--permission-mode', 'dontAsk'],
    'codex': ['exec', '--json', '--skip-git-repo-check', '{prompt}'],
    'opencode': ['run', '--format', 'json', '{prompt}'],
}
FIRST_PROMPT = ('Please list the open issues of the GitHub repository {repo}. Bob has shared a capability for this '
                'with me through Peerspan; use it. Answer with each issue\'s number and title.')
SECOND_PROMPT = ('Please list the open issues of the GitHub repository {repo} again, through Bob\'s Peerspan '
                 'capability. If you cannot reach it, say so plainly.')
UNREACHABLE = re.compile(r'no longer|not available|unavailable|cannot|can\'t|can not|unable|not_found|not found|'
                         r'unshared|no capability|isn\'t available|is not available|lost access|no access', re.I)


class Person(DirectoryHost):
    """A daemon and CLI of one implementation. With real_home, HOME is the operator's (harness logins); Peerspan's
    configuration stays private in XDG_CONFIG_HOME either way."""

    def __init__(self, binary, root, real_home=False):
        super().__init__(binary, binary, root / 'state', root / 'user')
        self.real_home = real_home
        if real_home:
            source = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'opencode'
            if source.exists():
                (self.config / 'opencode').symlink_to(source)

    def private_env(self):
        env = {'XDG_CONFIG_HOME': str(self.config)}
        if not self.real_home:
            env['HOME'] = str(self.home)
        return env


def tool_calls(text):
    """Every tool call in a harness's JSON output: (name, arguments) for names ending in list_capabilities or
    call_capability, found anywhere in the JSON objects of its lines."""
    found = []

    def walk(value):
        if isinstance(value, dict):
            name = value.get('name') or value.get('tool')
            if isinstance(name, str) and re.search(r'(list_capabilities|call_capability|call_status)$', name):
                arguments = value.get('input') or value.get('arguments') or (value.get('state') or {}).get('input')
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except ValueError:
                        pass
                found.append({'name': name, 'arguments': arguments})
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    for line in text.splitlines():
        try:
            walk(json.loads(line))
        except ValueError:
            continue
    return found


def answer_text(text):
    """The model's final answer as best found in the JSON output: Claude Code's result, Codex agent messages, or
    OpenCode text parts; otherwise the raw output's last 2,000 characters."""
    answers = []
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get('type') == 'result' and isinstance(event.get('result'), str):
            answers.append(event['result'])
        item = event.get('item') if isinstance(event.get('item'), dict) else None
        if item and item.get('type') in ('agent_message', 'assistant_message') and isinstance(item.get('text'), str):
            answers.append(item['text'])
        part = event.get('part') if isinstance(event.get('part'), dict) else None
        if part and part.get('type') == 'text' and isinstance(part.get('text'), str):
            answers.append(part['text'])
    return '\n'.join(answers) if answers else text[-2000:]


def open_issues(repo, token):
    request = urllib.request.Request(f'https://api.github.com/repos/{repo}/issues?state=open&per_page=100',
                                     headers={'Authorization': f'Bearer {token}',
                                              'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        issues = json.loads(response.read())
    return [{'number': i['number'], 'title': i['title']} for i in issues if 'pull_request' not in i]


def version_of(command):
    try:
        return subprocess.run([command, '--version'], capture_output=True, text=True, timeout=30).stdout.strip()
    except OSError as error:
        return f'unavailable: {error}'


class Run:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.coord = Coordinator(args.coord, root / 'coord')
        self.token = os.environ.get(args.token_env)
        if not self.token:
            raise SystemExit(f'set {args.token_env} to a GitHub token that can read {args.repo}')

    def received(self):
        return self.bob.cli('calls', 'received', '--limit', '1000')

    def harness_run(self, harness, prompt, first):
        """Run the harness once through Alice's attach (first) or session start; (exit code, output, seconds)."""
        workspace = self.root / 'projects' / harness
        workspace.mkdir(parents=True, exist_ok=True)
        override = getattr(self.args, f'{harness}_args')
        extra = [a.replace('{prompt}', prompt) for a in (json.loads(override) if override else DEFAULT_ARGS[harness])]
        if first:
            argv = ['attach', HARNESSES[harness], '--calls', '--directory', str(workspace), '--integrations',
                    str(self.args.integrations), '--runner', str(self.args.node), '--', *extra]
        else:
            argv = ['session', 'start', '--', *extra]
        started = time.monotonic()
        result = subprocess.run([self.alice.cli_binary, '--state', str(self.alice.state), *argv], cwd=str(workspace),
                                env=self.alice.environment(), capture_output=True, text=True,
                                timeout=self.args.timeout, stdin=subprocess.DEVNULL)
        return result.returncode, result.stdout + '\n' + result.stderr, time.monotonic() - started

    def origin_session(self, origin):
        """Alice's session and adapter credential for a call's origin: the session must belong to the origin's agent
        on Alice's host. (session object, adapter record or None)."""
        if not isinstance(origin, dict):
            return None, None
        status, session = self.alice.call('GET', f"/v1/sessions/{origin.get('session_id')}")
        if status != 200 or session.get('agent_id') != origin.get('agent_id'):
            return None, None
        status, adapters = self.alice.call('GET', '/v1/adapters')
        adapters = adapters.get('adapters', []) if isinstance(adapters, dict) else adapters or []
        adapter = next((a for a in adapters if a.get('session_id') == origin.get('session_id')), None)
        return session, adapter

    def one(self, harness):
        repo = self.args.repo
        report = {'harness': harness, 'version': version_of(HARNESSES[harness])}
        self.bob.cli('share', 'github-issues', '--with', 'person:alice', '--yes', '--network', self.net)
        self.alice.run('network', 'sync', self.net)
        before = len(self.received())
        code, output, seconds = self.harness_run(harness, FIRST_PROMPT.format(repo=repo), first=True)
        calls = tool_calls(output)
        answer = answer_text(output)
        report['first'] = {'exit': code, 'seconds': round(seconds), 'tool_calls': calls, 'answer': answer}
        listed = any(c['name'].endswith('list_capabilities') for c in calls)
        called = [c for c in calls if c['name'].endswith('call_capability') and isinstance(c['arguments'], dict)
                  and c['arguments'].get('address') == 'bob/github-issues'
                  and c['arguments'].get('operation') == 'list_issues']
        named = [i for i in self.issues if f"#{i['number']}" in answer or i['title'] in answer]
        received = self.received()[before:]
        origins = [r['request'].get('origin') for r in received]
        sessions = [self.origin_session(o) for o in origins]
        adapter = next((a for _, a in sessions if a), None)
        outbound = self.alice.cli('calls', 'list', '--limit', '1000')
        recorded = [o['call'] for o in outbound if (o['call'].get('request') or {}).get('call_id') in
                    {r['request']['call_id'] for r in received}]
        report['checks'] = {
            'model_called_list_capabilities': listed,
            'model_called_call_capability_with_address_and_operation': bool(called),
            'answer_names_issues': bool(named) if self.issues else None,
            'bob_recorded_the_call': bool(received),
            'alice_recorded_the_call': bool(recorded),
            'origin_is_alices_agent': bool(received) and all(session for session, _ in sessions),
        }
        report['received'] = [{'call_id': r['request']['call_id'], 'operation': r['request']['operation'],
                               'origin': r['request'].get('origin'), 'state': (r.get('status') or {}).get('state')}
                              for r in received]
        report['alice_session'] = sessions[0][0] if sessions else None
        if adapter:
            status, connection = self.alice.call('GET', f"/v1/adapters/{adapter['id']}/connection")
            report['negotiated_protocol'] = (connection or {}).get('protocol_version') if status == 200 else None

        # Unshared: the next call is refused with the not_found text, and nothing more runs on Bob's host.
        self.bob.cli('unshare', 'github-issues', '--with', 'person:alice', '--network', self.net)
        self.alice.run('network', 'sync', self.net)
        before = len(self.received())
        code, output, seconds = self.harness_run(harness, SECOND_PROMPT.format(repo=repo), first=False)
        calls = tool_calls(output)
        answer = answer_text(output)
        refused = NOT_FOUND in output
        report['after_unshare'] = {'exit': code, 'seconds': round(seconds), 'tool_calls': calls, 'answer': answer}
        report['checks'].update({
            'after_unshare_refused_with_not_found_text': refused,
            'after_unshare_nothing_executed_on_bob': len(self.received()) == before,
            'after_unshare_answer_says_unreachable': bool(UNREACHABLE.search(answer)),
        })
        report['checks']['harness_exited_0'] = report['first']['exit'] == 0
        report['checks']['after_unshare_harness_exited_0'] = code == 0
        report['passed'] = all(v is not False for v in report['checks'].values())
        print(json.dumps({'harness': harness, 'checks': report['checks']}), flush=True)
        return report

    def run(self):
        args, root = self.args, self.root
        coord_key = self.coord.start()['public_key']
        self.bob = Person(args.bob_binary, root / 'bob')
        self.alice = Person(args.alice_binary, root / 'alice', real_home=True)
        for person in (self.bob, self.alice):
            person.start()
        try:
            created = self.bob.cli('network', 'create', 'live', '--as', 'bob', '--untrusted', '--coordinator',
                                   self.coord.address, '--coordinator-key', coord_key)
            self.net = created['id']
            token = self.bob.cli('invite', 'alice', '--network', self.net)['token']
            self.alice.cli('join', token, '--untrusted')
            wait_for(lambda: len(self.bob.cli('network', 'members', self.net)) == 2, timeout=60,
                     message='both members')

            # Bob's GitHub server in his Claude Code user configuration, discovered at attach.
            server = {'command': args.github_command,
                      'args': args.github_arg or ['-y', '@modelcontextprotocol/server-github'],
                      'env': {'GITHUB_PERSONAL_ACCESS_TOKEN': '${GITHUB_PERSONAL_ACCESS_TOKEN}'}}
            (self.bob.home / '.claude.json').write_text(json.dumps({'mcpServers': {'github': server}}))
            # Attach's readiness checks need a signed-in Claude Code, also with --no-start.
            login = Path.home() / '.claude' / '.credentials.json'
            if login.exists():
                (self.bob.home / '.claude').mkdir(exist_ok=True)
                (self.bob.home / '.claude' / '.credentials.json').symlink_to(login)
            workspace = root / 'projects' / 'bob'
            workspace.mkdir(parents=True)
            result = self.bob.run('attach', 'claude', '--name', 'bob-claude', '--directory', str(workspace),
                                  '--integrations', str(args.integrations), '--runner', str(args.node), '--no-start',
                                  env={'GITHUB_PERSONAL_ACCESS_TOKEN': self.token}, timeout=300)
            if result.returncode != 0:
                raise SystemExit(f'Bob\'s attach failed: {result.stderr[-800:]}')
            sources = json.loads(result.stdout).get('sources')
            self.bob.cli('capability', 'create', 'github-issues', '--from', 'bob-claude/github', '--operations',
                         'list_issues')
            self.issues = open_issues(args.repo, self.token)
            reports = [self.one(h) for h in args.harness]
            return {'timestamp': datetime.now(timezone.utc).isoformat(), 'repository': args.repo,
                    'mode': 'real harnesses and models; Bob and Alice on one machine; local daemons '
                            f'({Path(args.bob_binary).name} for Bob, {Path(args.alice_binary).name} for Alice)',
                    'open_issues': self.issues, 'bob_sources': sources, 'harnesses': reports,
                    'passed': all(r['passed'] for r in reports),
                    'limits': ['One machine; cross-host connectivity is not established by this run.',
                               'Tool calls and answers come from each harness\'s JSON output; the unreachable '
                               'answer is a keyword check recorded with the answer for review.']}
        finally:
            stop_all((self.bob, self.alice))
            self.coord.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--bob-binary', type=Path, required=True, help='peerspan-host for Bob (Go or Rust)')
    parser.add_argument('--alice-binary', type=Path, required=True, help='peerspan-host for Alice (Go or Rust)')
    parser.add_argument('--coord', type=Path, required=True, help='peerspan-coord')
    parser.add_argument('--node', type=Path, default=shutil.which('node'), help='Node 22 or newer')
    parser.add_argument('--integrations', type=Path, default=REPO / 'integrations')
    parser.add_argument('--repo', default=os.environ.get('PEERSPAN_LIVE_REPO'),
                        help='the test repository, OWNER/NAME (or PEERSPAN_LIVE_REPO)')
    parser.add_argument('--token-env', default='GITHUB_TOKEN',
                        help='the environment variable holding the GitHub token (never written anywhere)')
    parser.add_argument('--github-command', default='npx')
    parser.add_argument('--github-arg', action='append', help='an argument of the GitHub MCP server; repeatable')
    parser.add_argument('--harness', action='append', choices=sorted(HARNESSES),
                        help='repeatable; default claude, codex, and opencode in turn')
    for name in HARNESSES:
        parser.add_argument(f'--{name}-args', help=f'the {name} arguments after --, as a JSON array; '
                                                   '{prompt} is replaced')
    parser.add_argument('--timeout', type=int, default=600, help='seconds for each harness run')
    parser.add_argument('--output', type=Path, default=REPO / 'docs' / 'results' / 'capabilities-live.json')
    parser.add_argument('--keep', action='store_true', help='keep the temporary directory')
    args = parser.parse_args()
    if not args.repo or not re.fullmatch(r'[\w.-]+/[\w.-]+', args.repo):
        parser.error('--repo OWNER/NAME (or PEERSPAN_LIVE_REPO) is required')
    if not args.node:
        parser.error('--node is required (no node on PATH)')
    args.harness = args.harness or ['claude', 'codex', 'opencode']
    for key in ('bob_binary', 'alice_binary', 'coord', 'node', 'integrations', 'output'):
        setattr(args, key, Path(getattr(args, key)).resolve())
    root = Path(tempfile.mkdtemp(prefix='peerspan-capabilities-live-'))
    try:
        result = Run(args, root).run()
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'output': str(args.output)}))
    sys.exit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
