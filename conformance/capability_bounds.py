#!/usr/bin/env python3
"""Resource bounds and the built-in `gh` source (capabilities slice 3, item D), run by conformance/capabilities.py.

Written from docs/capabilities-contract.md, "Resource bounds and the `gh` source (slice 3)" and its Verification
list, with docs/capabilities-slice3-bounds-sources-proposal.md for intent, independently of the Go and Rust hosts.
GitHub is never contacted: a fake `gh` (fixtures/gh/gh.py) is installed as an executable named `gh` in a directory
put first on the CLI's PATH and absent from the daemon's. It finds its control file and log by a path written into
it, records every run (arguments, environment, working directory, standard input), and answers with canned output.

Each CLI/daemon pairing gets its own topology:
- pat: p1 serves (agent `srv` with the fixture MCP server `srv/fx` started with --bounded 1, and the built-in
  source `builtin/gh` for the account `bob`, discovered from the fake `gh`) and opens its sources to p2; p2 is
  trusted; with --baseline18, o1 runs a version 18 host and serves `oldcap` (compatibility).
- quinn: q1, the caller by policy.
- p3: a host in no network, for discovery cases (its own fake `gh`), the `name` reason, and reach variants.
Network: team.

Sections, per pairing (contract Verification bullets in brackets):
- gh discovery [Discovery];
- token capture [Token capture];
- reach [Reach];
- gh operations [Operations];
- gh execution [Execution];
- bounds [Bounds on gh and on an MCP source], and the recheck after remove and recreate;
- display [Display], except list_capabilities (capability_agents.py, with --node);
- calls through gh capabilities [Calls through capabilities on gh], except call_capability (capability_agents.py);
- status [Status];
- compatibility [Compatibility] with --baseline18.
Once per run (from capabilities.py): migration from version 20 (and, with --baseline18, from 18) to version 21 [Migration].

Where the contract is silent, the suite takes the reading most faithful to the proposal; such spots are marked
"Q:" and soft results are NOTE lines.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
import traceback

from support import Coordinator, wait_for
from host_service import stop_all
from launch_onboarding import Failure, need, parse_time
from peer_messaging import fixture_context, timestamp, wire
from persons import Agent, person_id, ssh_key
from policy import edit_start, sign_edit

import capabilities as caps
from capabilities import (CapHost, Fixture, PYTHON, SHARE_PROMPT, SERVER_KEYS, ATTACH_SERVER_KEYS, CAN_CHANGE,
                          FINAL, LAPSED, cap_rule, db_rows, squash)
from capability_agents import canonical

HERE = Path(__file__).resolve().parent
FAKE_GH = HERE / 'fixtures' / 'gh' / 'gh.py'

# --- the contract's exact texts and shapes ----------------------------------------------------------------------

HINT = ('GitHub CLI (gh) not found on PATH; install gh 2.81.0 or later and run peerspan sources refresh to use it as '
        'a source.')
GH_PROMPT = ('Limit which repositories? Enter OWNER/REPO, several separated by spaces, or leave empty for no limit: ')
MCP_PROMPT = ('Limit by argument values? Enter KEY=VALUE[,KEY=VALUE] combinations separated by spaces, or leave empty '
              'for no limit: ')
UNENFORCEABLE = ('Operation {op} has no string argument {key}, so Peerspan cannot check this bound for it. Leave the '
                 'operation out, or narrow the credential instead (--env-file).')
GH_BOUND_INVALID = 'A gh repository bound is OWNER/REPO or OWNER/*.'
NO_TOOL_OPS = 'A bound applies to tool operations, and the capability has none.'
NOT_AUTH = 'gh is not authenticated for github.com. The owner runs gh auth login, then peerspan sources refresh.'
TOO_BIG = 'gh output exceeded 1000000 bytes.'
UNREADABLE = 'gh returned output Peerspan could not read.'
TIMED_OUT = 'gh did not finish within 120 seconds.'
NOT_STARTED = 'gh could not be started.'
EVERY_GH = 'Every gh operation names its repository in repo, so Peerspan checks every call.'
EVERY_ARG = 'Peerspan checks every argument of these operations.'
READ_LINE = "The bound does not apply to read, which is limited to the capability's resources."
LIST_SENTENCE = ("Each entry's bounds lists the argument values its owner allows, as combinations; an empty object "
                 "means no bound, and a call outside them is refused and never runs.")

BUILTIN_SERVER_KEYS = SERVER_KEYS | {'adapter', 'version', 'host', 'account', 'authenticated', 'reach'}
REACH_KEYS = {'account', 'host', 'token_type', 'scopes', 'checked_at', 'error'}
DEFINITION_KEYS = {'name', 'adapter', 'command', 'version', 'host', 'account', 'authenticated', 'env', 'disabled'}
GH_ENV_NAMES = {'PATH', 'HOME', 'GH_TOKEN', 'GH_HOST', 'GH_CONFIG_DIR', 'GH_PROMPT_DISABLED', 'GH_NO_UPDATE_NOTIFIER',
                'GH_NO_EXTENSION_UPDATE_NOTIFIER', 'GH_SPINNER_DISABLED', 'NO_COLOR', 'GH_PAGER', 'GH_TELEMETRY'}
GH_ENV_FIXED = {'GH_HOST': 'github.com', 'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1',
                'GH_NO_EXTENSION_UPDATE_NOTIFIER': '1', 'GH_SPINNER_DISABLED': '1', 'NO_COLOR': '1', 'GH_PAGER': 'cat',
                'GH_TELEMETRY': '0'}
TOKEN_VARS = ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN')

OPERATIONS = ['issue_list', 'issue_view', 'pr_list', 'pr_view', 'pr_diff', 'pr_checks', 'repo_view', 'issue_create',
              'issue_comment', 'pr_comment']
READ_ONLY = set(OPERATIONS[:7])
FIELDS = {
    'issue_list': 'number,title,state,author,labels,assignees,milestone,createdAt,updatedAt,url',
    'issue_view': 'number,title,state,stateReason,body,author,labels,assignees,milestone,createdAt,updatedAt,'
                  'closedAt,url',
    'pr_list': 'number,title,state,isDraft,author,baseRefName,headRefName,labels,createdAt,updatedAt,url',
    'pr_view': 'number,title,state,isDraft,body,author,baseRefName,headRefName,mergeable,reviewDecision,additions,'
               'deletions,changedFiles,files,labels,createdAt,updatedAt,mergedAt,url',
    'pr_checks': 'name,state,bucket,workflow,link,startedAt,completedAt',
    'repo_view': 'nameWithOwner,description,url,visibility,isArchived,defaultBranchRef,homepageUrl,primaryLanguage,'
                 'stargazerCount,forkCount,pushedAt,updatedAt',
}
TOOL_DESCRIPTIONS = {
    'issue_list': 'List issues in a GitHub repository.',
    'issue_view': 'Show one issue of a GitHub repository, with its comments when comments is true.',
    'pr_list': 'List pull requests in a GitHub repository.',
    'pr_view': 'Show one pull request of a GitHub repository, with its comments and reviews when comments is true.',
    'pr_diff': 'Show the diff of a pull request, or with name_only the names of the changed files.',
    'pr_checks': 'Show the status checks of a pull request.',
    'repo_view': 'Show a GitHub repository.',
    'issue_create': 'Create an issue in a GitHub repository.',
    'issue_comment': 'Add a comment to an issue.',
    'pr_comment': 'Add a comment to a pull request.',
}
REPO = {'type': 'string', 'pattern': '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$'}
NUMBER = {'type': 'integer', 'minimum': 1, 'maximum': 2147483647}
LIMIT = {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 30}
ARRAY = {'type': 'array', 'items': {'type': 'string', 'minLength': 1, 'maxLength': 256}, 'maxItems': 10}
STRING = {'type': 'string', 'minLength': 1, 'maxLength': 256}
BOOL = {'type': 'boolean'}
BOOL_FALSE = {'type': 'boolean', 'default': False}
BODY = {'type': 'string', 'maxLength': 65536}


def state_schema(values):
    return {'type': 'string', 'enum': values, 'default': 'open'}


# operation -> [(property, schema, description, required)]
SCHEMAS = {
    'issue_list': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                   ('state', state_schema(['open', 'closed', 'all']), 'Which items to list.', False),
                   ('limit', LIMIT, 'At most this many items.', False),
                   ('label', ARRAY, 'Only items with all of these labels.', False),
                   ('assignee', STRING, 'Only items assigned to this login.', False),
                   ('author', STRING, 'Only items opened by this login.', False),
                   ('milestone', STRING, 'Only issues in this milestone.', False)],
    'issue_view': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                   ('number', NUMBER, 'The issue or pull request number.', True),
                   ('comments', BOOL_FALSE, 'Include comments.', False)],
    'pr_list': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                ('state', state_schema(['open', 'closed', 'merged', 'all']), 'Which items to list.', False),
                ('limit', LIMIT, 'At most this many items.', False),
                ('base', STRING, 'Only pull requests into this base branch.', False),
                ('head', STRING, 'Only pull requests from this head branch.', False),
                ('label', ARRAY, 'Only items with all of these labels.', False),
                ('author', STRING, 'Only items opened by this login.', False),
                ('draft', BOOL, 'Only draft pull requests.', False)],
    'pr_view': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                ('number', NUMBER, 'The issue or pull request number.', True),
                ('comments', BOOL_FALSE, 'Include comments and reviews.', False)],
    'pr_diff': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                ('number', NUMBER, 'The issue or pull request number.', True),
                ('name_only', BOOL_FALSE, 'Return only the names of the changed files.', False)],
    'pr_checks': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                  ('number', NUMBER, 'The issue or pull request number.', True)],
    'repo_view': [('repo', REPO, 'The repository, as OWNER/REPO.', True)],
    'issue_create': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                     ('title', STRING, 'The issue title.', True),
                     ('body', BODY, 'The text, in Markdown.', False),
                     ('label', ARRAY, 'Labels to add.', False),
                     ('assignee', ARRAY, 'Logins to assign.', False)],
    'issue_comment': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                      ('number', NUMBER, 'The issue or pull request number.', True),
                      ('body', BODY, 'The text, in Markdown.', True)],
    'pr_comment': [('repo', REPO, 'The repository, as OWNER/REPO.', True),
                   ('number', NUMBER, 'The issue or pull request number.', True),
                   ('body', BODY, 'The text, in Markdown.', True)],
}


def cid():
    return 'call_' + secrets.token_hex(16)


def expected_argv(op, i):
    """The `gh` arguments for one call (contract: gh operations, Arguments)."""
    r = i['repo']
    if op in ('issue_list', 'pr_list'):
        a = op.split('_')[0:1] + ['list', f'--repo={r}', f'--state={i.get("state", "open")}',
                                  f'--limit={i.get("limit", 30)}']
        if op == 'issue_list':
            a += [f'--label={x}' for x in i.get('label', [])]
            a += [f'--{k}={i[k]}' for k in ('assignee', 'author', 'milestone') if k in i]
        else:
            a += [f'--{k}={i[k]}' for k in ('base', 'head') if k in i]
            a += [f'--label={x}' for x in i.get('label', [])]
            a += [f'--author={i["author"]}'] if 'author' in i else []
            a += ['--draft'] if i.get('draft') else []
        return a + [f'--json={FIELDS[op]}']
    n = str(int(i['number'])) if 'number' in i else None
    if op in ('issue_view', 'pr_view'):
        extra = {'issue_view': ',comments', 'pr_view': ',comments,reviews'}[op]
        a = [op.split('_')[0], 'view', n, f'--repo={r}'] + (['--comments'] if i.get('comments') else [])
        return a + [f'--json={FIELDS[op]}' + (extra if i.get('comments') else '')]
    if op == 'pr_diff':
        return ['pr', 'diff', n, f'--repo={r}', '--color=never'] + (['--name-only'] if i.get('name_only') else [])
    if op == 'pr_checks':
        return ['pr', 'checks', n, f'--repo={r}', f'--json={FIELDS[op]}']
    if op == 'repo_view':
        return ['repo', 'view', r, f'--json={FIELDS[op]}']
    if op == 'issue_create':
        return (['issue', 'create', f'--repo={r}', f'--title={i["title"]}', '--body-file=-'] +
                [f'--label={x}' for x in i.get('label', [])] + [f'--assignee={x}' for x in i.get('assignee', [])])
    return [op.split('_')[0], 'comment', n, f'--repo={r}', '--body-file=-']


def ordered(combination):
    return sorted(combination.items(), key=lambda kv: kv[0].encode())


def allowed(bounds):
    return ' or '.join(' and '.join(f'{k} is {v}' for k, v in ordered(c)) for c in bounds['arguments'])


def names_in_order(bounds):
    out = []
    for c in bounds['arguments']:
        for k, _ in ordered(c):
            if k not in out:
                out.append(k)
    return out


def got(bounds, input):
    parts = []
    for k in names_in_order(bounds):
        if k not in input:
            parts.append(f'no {k}')
        elif not isinstance(input[k], str):
            parts.append(f'a non-string {k}')
        else:
            parts.append(f'{k} {canonical(input[k])}')
    return ' and '.join(parts)


def out_of_bounds(bounds, input):
    return f'This capability is limited to calls where {allowed(bounds)}. The call has {got(bounds, input)}. ' \
           'Nothing was run.'


def reach_sentence(reach, account=None):
    """The reach sentence (contract: The reach sentence), first row that applies."""
    login = (reach or {}).get('account') or account or 'unknown'
    host = 'github.com'
    if reach is None:
        return (f'Peerspan could not check the reach of the gh account {login} on {host} (not checked yet). Assume '
                'everything the account can reach.')
    if reach.get('error'):
        return (f'Peerspan could not check the reach of the gh account {login} on {host} ({reach["error"]}). Assume '
                'everything the account can reach.')
    scopes = reach.get('scopes')
    if scopes is not None and 'repo' in scopes:
        return (f'The gh account {login} on {host} (token scopes: {", ".join(scopes)}) can read and change every '
                f'repository {login} can, public and private.')
    if scopes is not None and 'public_repo' in scopes:
        return (f'The gh account {login} on {host} (token scopes: {", ".join(scopes)}) can read public repositories '
                f'and change public repositories {login} can.')
    if reach.get('token_type') in ('oauth', 'classic') and scopes is not None:
        return (f'The gh account {login} on {host} (token scopes: {", ".join(scopes) or "none"}) can read public '
                'repositories only.')
    return (f'The gh account {login} on {host} uses a token that states no scopes, so Peerspan cannot tell which '
            'repositories it reaches. Assume every repository it was granted.')


def reach_statement(principal, gh, bounds, sentence=None):
    if bounds and bounds.get('arguments'):
        lead = f'{principal} can use these operations only where {allowed(bounds)}; Peerspan refuses other calls.'
        if gh:
            return f'{lead} The credential reaches more than the bound. {sentence}'
        return (f'{lead} Arguments Peerspan does not check can still reach anything the credentials they run with '
                'on this host can reach.')
    lead = f'{principal} can use these operations with the credentials they run with on this host.'
    if gh:
        return f'{lead} {sentence} No resource bound.'
    return f'{lead} Anything those credentials can reach through them, {principal} can too. No resource bound.'


def text_of(result):
    if not isinstance(result, dict):
        return None
    return ''.join(x.get('text', '') for x in result.get('content') or [] if isinstance(x, dict))


def contains(value, text):
    """Whether any string inside a JSON value contains text."""
    if isinstance(value, str):
        return text in value
    if isinstance(value, dict):
        return any(contains(v, text) for v in value.values())
    if isinstance(value, list):
        return any(contains(v, text) for v in value)
    return False


def alive(pid):
    try:
        with open(f'/proc/{pid}/stat') as f:
            return f.read().rsplit(')', 1)[1].split()[0] != 'Z'
    except (OSError, IndexError):
        return False


def sha(text):
    return 'sha256:' + hashlib.sha256(text.encode()).hexdigest()


def b64(data):
    return base64.b64encode(data).decode()


# --- the fake gh ------------------------------------------------------------------------------------------------

class FakeGh:
    """One fake `gh`: ROOT/bin/gh, ROOT/control.json, ROOT/log.jsonl."""

    def __init__(self, root):
        self.root = Path(root)
        self.bin = self.root / 'bin'
        self.bin.mkdir(parents=True)
        self.path = self.bin / 'gh'
        self.path.write_text(f'#!{PYTHON} -I\nROOT = {str(self.root)!r}\n' + FAKE_GH.read_text())
        self.path.chmod(0o755)
        self.control = {}
        self.write()

    def write(self):
        (self.root / 'control.json').write_text(json.dumps(self.control))

    def set(self, **values):
        self.control.update(values)
        self.write()

    def repo(self, repo, **behaviour):
        self.control.setdefault('repos', {})[repo] = behaviour
        self.write()

    def entries(self):
        path = self.root / 'log.jsonl'
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def starts(self, repo=None, since=0):
        out = []
        for e in self.entries()[since:]:
            if e['event'] != 'start':
                continue
            if repo is not None:
                argv = e['argv']
                r = next((a.split('=', 1)[1] for a in argv if a.startswith('--repo=')), None)
                if r is None and argv[:2] == ['repo', 'view'] and len(argv) > 2:
                    r = argv[2]
                if r != repo:
                    continue
            out.append(e)
        return out

    def mark(self):
        return len(self.entries())

    def events_for(self, pid):
        return [e for e in self.entries() if e.get('pid') == pid]


class GhHost(CapHost):
    """A CapHost whose CLI finds a fake gh first on PATH (when `gh_bin` is set)."""
    gh_bin = None

    def environment(self, sock=caps.DEFAULT, env=None):
        e = super().environment(sock, None)
        if self.gh_bin:
            e['PATH'] = str(self.gh_bin) + os.pathsep + e['PATH']
        e.update(env or {})
        return e


# --- the pairing ------------------------------------------------------------------------------------------------

class BoundsPairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, root, only=None, baseline18=None):
        self.label, self.cli_binary, self.daemon, self.root = label, cli_binary, daemon_binary, root
        self.only = only
        self.baseline18 = baseline18
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results, self.notes, self.setup_notes = [], [], []
        self.hosts, self.ids, self.keys, self.agents, self.aid = {}, {}, {}, {}, {}
        self.reviews = {}

    # --- infrastructure ----------------------------------------------------------------------------------------

    def host(self, name, person, daemon=None, cli=None):
        h = GhHost(daemon or self.daemon, cli or self.cli_binary, self.root / name, self.root / f'user-{name}')
        h.sock = self.agents[person].socket if person else None
        self.hosts[name] = h
        return h

    def section(self, name, function):
        if self.only and name not in self.only:
            return None
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=5)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [bounds and gh: {name}] ({time.monotonic() - started:.0f}s): {detail}',
                  flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [bounds and gh: {name}] ({time.monotonic() - started:.0f}s)'
              f'{": " + notes if notes else ""}', flush=True)
        return True

    def soft(self, condition, rule, *detail):
        if not condition:
            self.notes.append(f'{rule}: ' + ' | '.join(repr(d)[:300] for d in detail))
            print(f'NOTE {self.label} (not counted): {rule}', flush=True)

    def coordinator_flags(self):
        return ('--coordinator', self.coord.address, '--coordinator-key', self.coord_key)

    def invite(self, label):
        return self.hosts['p1'].cli('network', 'invite', '--network', self.team, '--member', label,
                                    '--expires-in', '1h')['token']

    def policy(self, host='p1'):
        status, body = self.hosts[host].call('GET', f'/v1/networks/{self.team}/policy?person={self.pat}')
        return caps.policy_of(body) if status == 200 else None

    def version(self, host='p1'):
        p = self.policy(host)
        return p['version'] if p else 0

    def synced(self, *names, timeout=40):
        version = self.version('p1')
        for name in names:
            h = self.hosts[name]

            def caught_up():
                h.run('network', 'sync', self.team)
                return self.version(name) >= version
            wait_for(caught_up, timeout=timeout, message=f'policy version {version} on {name}')

    def sync(self):
        self.synced('p2', 'q1', *(['o1'] if 'o1' in self.hosts else []))

    def rule_for(self, name):
        for r in (self.policy('p1') or {}).get('capability_rules') or []:
            if r['capability'] == name and r['host'] == self.ids['p1']:
                return r
        return None

    def out(self, host, *args, env=None, cwd=None, timeout=150, piped=None):
        """(exit code, parsed stdout or None, stdout, stderr), recording output for the secret scan."""
        code, value, stdout, stderr = self.hosts[host].outcome(*args, env=env, cwd=cwd or str(self.root),
                                                               timeout=timeout, piped=piped)
        self.exposed.append((f'{host} {" ".join(args[:3])}', stdout + stderr))
        return code, value, stdout, stderr

    def create(self, name, source, operations=None, *bounds, resources=None, env_file=None, host='p1',
               expect=0):
        args = ['capability', 'create', name, '--from', source]
        if operations:
            args += ['--operations', ','.join(operations)]
        if resources:
            args += ['--resources', resources]
        if env_file:
            args += ['--env-file', str(env_file)]
        for b in bounds:
            args += ['--bound', b]
        code, value, stdout, stderr = self.out(host, *args)
        if expect is not None:
            need(code == expect, f'capability create {name} {" ".join(args[5:])}', code, stdout[-300:],
                 stderr[-500:])
        return code, value, stderr

    def share(self, name, principal='quinn', per_hour=None, terminal=True):
        """share NAME --with PRINCIPAL, at a terminal answering y (the review is kept in self.reviews)."""
        args = ['share', name, '--with', principal, '--network', self.team]
        if per_hour:
            args += ['--calls-per-hour', str(per_hour)]
        h = self.hosts['p1']
        if terminal:
            code, value, tty, stdout, seen = h.at_terminal(*args, answer='y', prompt=SHARE_PROMPT, timeout=120)
            self.exposed.append((f'share {name}', tty + stdout))
            self.reviews[name] = tty
            need(code == 0 and seen, f'share {name} --with {principal} at a terminal', code, tty[-600:])
        else:
            code, value, stdout, stderr = self.out('p1', *args, '--yes')
            need(code == 0, f'share {name} --with {principal} --yes', code, stderr[-600:])
        return value

    def remove(self, name):
        for attempt in range(3):
            code, value, stdout, stderr = self.out('p1', 'capability', 'remove', name, '--yes')
            # A signing step that fails (here, the local service timing out under load) keeps the record, and
            # repeating the command finishes the removal (capabilities contract, capability remove).
            if code == 0 or 'repeating the command finishes the removal' not in stderr:
                break
            print(f'NOTE {self.label}: repeating capability remove {name} after: {stderr.strip()[-200:]}', flush=True)
        need(code == 0, f'capability remove {name}', code, stderr[-400:])

    def capability(self, name, host='p1'):
        status, body = self.hosts[host].call('GET', f'/v1/capabilities/{name}')
        return body if status == 200 else None

    def claim_policies(self, name, host='p1'):
        """The claim edits the CLI would send with POST /v1/capabilities (as capabilities.py signs them)."""
        start_status, start = edit_start(self.hosts[host], self.team)
        need(start_status == 200, 'setup: the edit route', start_status, start)

        def change(p):
            if not any(r['capability'] == name for r in p['capability_rules']):
                p['capability_rules'].append(cap_rule(self.ids[host], name, []))
        return [sign_edit(start, self.team, self.keys['pat'][2], self.ids[host], self.keys['pat'][0], self.root,
                          change)]

    def post_capability(self, name, source, operations, bounds=None, resources=None, args=None, env_file=None,
                        host='p1', claims=True):
        agent, _, server = source.partition('/')
        body = {'name': name, 'source': {'agent': agent, 'server': server}, 'operations': operations,
                'resources': resources, 'env_file': env_file,
                'policies': self.claim_policies(name, host) if claims else []}
        if args is not None:
            body['args'] = args
        if bounds is not None:
            body['bounds'] = bounds
        return self.hosts[host].call('POST', '/v1/capabilities', body)

    def builtin(self, host='p1'):
        status, view = self.hosts[host].call('GET', '/v1/sources')
        need(status == 200 and isinstance(view, dict) and isinstance(view.get('builtin'), list),
             'GET /v1/sources has builtin: [SERVER]', status, str(view)[:400])
        self.exposed.append((f'{host} GET /v1/sources', json.dumps(view)))
        names = [s['name'] for s in view['builtin']]
        need(names == sorted(names), 'builtin sorted by name', names)
        for s in view['builtin']:
            need(set(s) == BUILTIN_SERVER_KEYS, 'a built-in SERVER has the fields of an agent\'s SERVER plus adapter, '
                 'version, host, account, authenticated, and reach', sorted(set(s) ^ BUILTIN_SERVER_KEYS))
        return {s['name']: s for s in view['builtin']}

    def refresh(self, host, *flags, env=None, expect=0):
        code, value, stdout, stderr = self.out(host, 'sources', 'refresh', *flags, env=env, timeout=180)
        if expect is not None:
            need(code == expect, f'sources refresh {" ".join(flags)} on {host}', code, stderr[-500:])
        return code, value, stdout, stderr

    def tool_values(self, host='p1'):
        return db_rows(self.hosts[host], "SELECT * FROM tool_values WHERE agent_id = 'builtin'")

    # calls through the peer route

    def wire(self, receiver, caller, method, path, body=None):
        """A peer request through the probe as `caller`, retried on the probe's own transient failures under load
        (its deadline, or the caller's database briefly locked while the probe reads its identity); peer calls are
        idempotent by call ID."""
        contexts = self.__dict__.setdefault('contexts', {})
        for attempt in range(10):
            try:
                if caller not in contexts:
                    contexts[caller] = fixture_context(self.hosts[caller])
                return wire(self.hosts[receiver], contexts[caller], method, path, body)
            except (OSError, sqlite3.OperationalError) as error:
                if attempt == 9:
                    raise
                print(f'NOTE {self.label}: retrying a probe request after {error!r}', flush=True)
                time.sleep(2 + attempt)

    def cite(self, caller):
        if caller in ('p2',):
            return {'self': {'person_id': self.pat, 'network_id': self.team}}
        return {'policy': {'person_id': self.pat, 'network_id': self.team, 'version': self.version('p1')}}

    def submit(self, caller, capability, operation, input, call_id=None, deadline=None, receiver='p1'):
        body = {'call_id': call_id or cid(), 'capability': capability, 'operation': operation, 'input': input,
                'deadline': deadline or timestamp(300), **self.cite(caller)}
        started = time.monotonic()
        while True:
            status, record = self.wire(receiver, caller, 'POST', '/peer/v1/calls', body)
            # Under heavy load a host can briefly lose its coordination connection and answer 503 (recoverable);
            # the same call is submitted again, which the receiver deduplicates.
            if not (status == 503 and isinstance(record, dict) and 'coordination' in str(record.get('error'))
                    and time.monotonic() - started < 90):
                break
            print(f'NOTE {self.label}: resubmitting after 503 {record}', flush=True)
            time.sleep(3)
        return body['call_id'], status, record

    def status_of(self, caller, call_id, receiver='p1'):
        return self.wire(receiver, caller, 'GET', f'/peer/v1/calls/{call_id}')

    def final(self, caller, call_id, receiver='p1', timeout=90):
        def done():
            status, record = self.status_of(caller, call_id, receiver)
            return record if status == 200 and record.get('state') in FINAL else None
        return wait_for(done, timeout=timeout, message=f'call {call_id} final')

    def run_call(self, caller, capability, operation, input, timeout=90, rule='the call'):
        call_id, status, record = self.submit(caller, capability, operation, input)
        need(status == 200, f'{rule}: accepted (200)', capability, operation, status, record)
        return self.final(caller, call_id, timeout=timeout)

    def cancel(self, caller, call_id, receiver='p1'):
        return self.wire(receiver, caller, 'POST',
                    f'/peer/v1/calls/{call_id}/cancel', {})

    def listing(self, caller='q1'):
        status, body = self.wire('p1', caller, 'GET',
                            f'/peer/v1/capabilities?network={self.team}')
        need(status == 200 and isinstance(body, list), 'GET /peer/v1/capabilities', status, body)
        return {e['capability']: e for e in body}

    def items(self, host='p1'):
        status, value = self.hosts[host].call('GET', '/v1/status')
        need(status == 200, 'GET /v1/status', status)
        return value

    # --- a pseudo-terminal conversation driven by prompts ------------------------------------------------------

    def dialogue(self, host, args, rules, timeout=120):
        """Run the CLI at a terminal; whenever output has been quiet for a second, answer the first rule whose
        prompt is in the output since the last answer, or send an empty line when output is waiting on an unknown
        question for 6 seconds. Returns (exit code, parsed stdout, terminal text, stdout, prompts answered)."""
        import fcntl
        import termios
        master, slave = os.openpty()

        def preexec():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        h = self.hosts[host]
        process = subprocess.Popen([h.cli_binary, '--state', str(h.state), *args], stdin=slave,
                                   stdout=subprocess.PIPE, stderr=slave, env=h.environment(), preexec_fn=preexec)
        os.close(slave)
        chunks = []
        reader = threading.Thread(target=lambda: chunks.append(process.stdout.read()), daemon=True)
        reader.start()
        seen, mark, last_output, answered = b'', 0, time.monotonic(), []
        started = time.monotonic()
        try:
            while time.monotonic() - started < timeout:
                ready, _, _ = select.select([master], [], [], 0.1)
                if master in ready:
                    try:
                        data = os.read(master, 4096)
                    except OSError:
                        data = b''
                    if data:
                        seen += data
                        last_output = time.monotonic()
                    elif process.poll() is not None:
                        break
                elif process.poll() is not None:
                    break
                quiet = time.monotonic() - last_output
                if len(seen) > mark and quiet >= 1.0:
                    fresh = squash(seen[mark:].decode(errors='replace'))
                    for prompt, answer in rules:
                        if squash(prompt) in fresh:
                            os.write(master, (answer + '\n').encode())
                            answered.append(prompt)
                            mark = len(seen)
                            break
                    else:
                        lines = [l.strip() for l in seen[mark:].decode(errors='replace').splitlines() if l.strip()]
                        asking = bool(lines) and lines[-1][-1:] in ('?', ':', ']')
                        if quiet >= 6 and asking:
                            os.write(master, b'\n')
                            answered.append(None)
                            mark = len(seen)
            process.wait(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
        reader.join(timeout=10)
        stdout = (chunks[0] if chunks else b'').decode(errors='replace')
        try:
            value = json.loads(stdout) if stdout.strip() else None
        except ValueError:
            value = None
        text = seen.decode(errors='replace')
        self.exposed.append((f'{host} {" ".join(args[:2])} terminal', text + stdout))
        return process.returncode, value, text, stdout, answered

    # --- setup -------------------------------------------------------------------------------------------------

    def run(self):
        root = self.root
        self.exposed = []
        (root / 'keys').mkdir()
        for name in ('pat', 'quinn'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.quinn = (person_id(self.keys[n][2]) for n in ('pat', 'quinn'))
        self.fixture = Fixture(root / 'fixture')
        self.gh1 = FakeGh(root / 'gh1')
        self.gh3 = FakeGh(root / 'gh3')
        self.coord_key = self.coord.start()['public_key']
        for name, person in (('p1', 'pat'), ('p2', 'pat'), ('q1', 'quinn')):
            self.host(name, person)
        self.host('p3', None)
        if self.baseline18:
            self.host('o1', 'pat', self.baseline18, self.baseline18)
        self.hosts['p1'].gh_bin = self.gh1.bin
        self.hosts['p3'].gh_bin = self.gh3.bin
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        h, ids = self.hosts, self.ids
        self.team = h['p1'].cli('network', 'create', 'team', '--as', 'pat', '--trusted',
                                *self.coordinator_flags())['id']
        members = [('p2', 'pat', '--trusted'), ('q1', 'quinn', '--untrusted')]
        if 'o1' in h:
            members.append(('o1', 'pat', '--untrusted'))
        for name, label, flag in members:
            h[name].cli('join', self.invite(label), flag)
        expected = {ids['p1']: self.pat, **{ids[n]: {'pat': self.pat, 'quinn': self.quinn}[l] for n, l, _ in members}}

        def bound():
            for n in [n for n, _, _ in members] + ['p1']:
                h[n].run('network', 'sync', self.team)
            seen = {m['host_id']: m['person_id'] for m in h['p1'].cli('network', 'members', self.team)}
            return seen == expected
        wait_for(bound, timeout=90, message='every member of team bound as expected')

        # p1's sources: srv/fx (the fixture with the bounds tools) and builtin/gh (bob, an OAuth token).
        self.token_bob = 'gho_' + secrets.token_hex(18)
        self.token_own = 'ghp_' + secrets.token_hex(18)
        self.gh1.set(version='2.102.0',
                     accounts=[{'login': 'bob', 'active': True, 'state': 'success', 'token': self.token_bob}],
                     users={self.token_bob: {'login': 'bob', 'scopes': 'repo, read:org, workflow'},
                            self.token_own: {'login': 'bob-narrow', 'scopes': 'public_repo'}})
        agent = h['p1'].cli('agent', 'register', '--name', 'srv', '--owner', 'pat')
        self.aid['srv'] = agent['id']
        definition = {'name': 'fx', 'transport': 'stdio', 'command': PYTHON,
                      'args': self.fixture.args('fx') + ['bounded=1'], 'env': {}, 'url': None,
                      'source': 'claude-code:user'}
        status, body = h['p1'].call('PUT', f'/v1/agents/{self.aid["srv"]}/tool-servers',
                                    {'workspace': str(root), 'servers': [definition], 'values': {}})
        need(status == 200, 'setup: PUT tool-servers for srv/fx', status, body)
        self.refresh('p1', '--builtin')
        status, body = h['p1'].call('POST', '/v1/sources/open-to', {'host_id': ids['p2']})
        need(status in (200, 201), 'setup: sources open-to p2', status, body)

        # The own-credential environment file for ghown.
        self.own_env = root / 'own-gh.env'
        self.own_env.write_text(f'GH_TOKEN={self.token_own}\nOTHER_VARIABLE=not-for-gh\n')
        self.own_env.chmod(0o600)

        # Capabilities and shares the sections rely on (failures become setup notes).
        self.B = {
            'ghb': {'arguments': [{'repo': 'acme/api'}, {'repo': 'Beta/*'}]},
            'ghenum': {'arguments': [{'repo': 'acme/api'}, {'repo': 'acme/web'}, {'repo': 'acme/api'}]},
            'ghtight': {'arguments': [{'repo': 'acme/api'}]},
            'mcpb': {'arguments': [{'owner': 'acme', 'repo': 'api'}, {'owner': 'beta', 'repo': 'web'}]},
            'mcpall': {'arguments': [{'owner': 'acme', 'repo': 'api'}]},
        }
        plan = [
            ('ghall', 'builtin/gh', OPERATIONS, [], None, None),
            ('ghb', 'builtin/gh', ['issue_list', 'issue_view', 'issue_comment'], ['repo=acme/api', 'repo=Beta/*'],
             None, None),
            ('ghenum', 'builtin/gh', ['issue_list'], ['repo=acme/api', 'repo=acme/web', 'repo=acme/api'], None, None),
            ('ghtight', 'builtin/gh', ['issue_list'], ['repo=acme/api'], None, None),
            ('mcpb', 'srv/fx', ['list_issues', 'search_issues'], ['owner=acme,repo=api', 'repo=web,owner=beta'],
             'all', None),
            ('mcpall', 'srv/fx', ['get_repo'], ['owner=acme,repo=api'], None, None),
            ('mcpfree', 'srv/fx', ['echo'], [], None, None),
            ('ghown', 'builtin/gh', ['issue_list'], [], None, self.own_env),
        ]
        self.created = {}
        for name, source, operations, bounds, resources, env_file in plan:
            try:
                self.created[name] = self.create(name, source, operations, *bounds, resources=resources,
                                                 env_file=env_file)
            except Exception as error:
                self.setup_notes.append(f'capability {name}: {str(error)[:300]}')
        for name, per_hour in (('ghall', 1000), ('ghb', 1000), ('ghenum', None), ('ghtight', 1), ('mcpb', 1000),
                               ('mcpall', None), ('mcpfree', None), ('ghown', None)):
            if name in self.created:
                try:
                    self.share(name, per_hour=per_hour)
                except Exception as error:
                    self.setup_notes.append(f'share {name}: {str(error)[:300]}')
        if 'o1' in h:
            try:
                self.setup_old()
            except Exception as error:
                self.setup_notes.append(f'o1 (version 18): {str(error)[:300]}')
        self.sync()

        self.section('gh discovery', self.check_discovery)
        self.section('token capture', self.check_tokens)
        self.section('reach', self.check_reach)
        self.section('gh operations', self.check_operations)
        self.section('gh execution', self.check_execution)
        self.section('bounds', self.check_bounds)
        self.section('bounds recheck', self.check_recheck)
        self.section('display', self.check_display)
        self.section('calls through gh capabilities', self.check_gh_calls)
        self.section('status', self.check_status)
        if 'o1' in h:
            self.section('compatibility', self.check_compatibility)
        self.section('secrets', self.check_secrets)
        if self.setup_notes:
            print(f'NOTE {self.label} bounds and gh setup: ' + ' | '.join(self.setup_notes), flush=True)

    def setup_old(self):
        o1 = self.hosts['o1']
        self.synced('o1')
        agent = o1.cli('agent', 'register', '--name', 'srvo', '--owner', 'pat')
        definition = {'name': 'fx', 'transport': 'stdio', 'command': PYTHON, 'args': self.fixture.args('fx-o1'),
                      'env': {}, 'url': None, 'source': 'claude-code:user'}
        status, body = o1.call('PUT', f'/v1/agents/{agent["id"]}/tool-servers',
                               {'workspace': str(self.root), 'servers': [definition], 'values': {}})
        need(status == 200, 'setup: o1 tool servers', status, body)
        code, value, stdout, stderr = o1.outcome('capability', 'create', 'oldcap', '--from', 'srvo/fx',
                                                 '--operations', 'echo')
        need(code == 0, 'setup: oldcap on o1', code, stderr[-300:])
        code, value, stdout, stderr = o1.outcome('share', 'oldcap', '--with', 'quinn', '--yes', '--network',
                                                 self.team)
        need(code == 0, 'setup: share oldcap', code, stderr[-300:])
        h = self.hosts['p1']

        def caught_up():
            h.run('network', 'sync', self.team)
            return self.version('p1') >= self.version('o1')
        wait_for(caught_up, timeout=40, message='p1 stores o1\'s edit')

    def needs(self, *names):
        missing = [n for n in names if n not in self.created]
        need(not missing, 'setup: the capabilities this section uses were created', missing,
             *[n for n in self.setup_notes if any(m in n for m in missing)])

    # --- discovery ---------------------------------------------------------------------------------------------

    def check_discovery(self):
        p3, gh = self.hosts['p3'], self.gh3
        tokens = {'alice': 'gho_' + secrets.token_hex(16), 'dave': 'gho_' + secrets.token_hex(16),
                  'long': 'gho_' + secrets.token_hex(16), 'envtok': 'gho_' + secrets.token_hex(16)}
        self.p3_tokens = tokens
        long_login = 'L' * 70
        gh.set(version='2.81.0', accounts=[
            {'login': 'env-account', 'active': True, 'state': 'success', 'token': tokens['envtok'],
             'token_source': 'GH_TOKEN'},
            {'login': 'bob', 'active': False, 'state': 'success'},                  # auth token fails: missing_env
            {'login': 'Alice.Smith+x', 'active': True, 'state': 'success', 'token': tokens['alice']},
            {'login': 'carol', 'active': False, 'state': 'failure', 'token': 'gho_unused'},
            {'login': 'Dave.O', 'active': False, 'state': 'success', 'token': tokens['dave']},
            {'login': 'dave-o', 'active': False, 'state': 'success', 'token': 'gho_dropped'},   # repeats gh-dave-o
            {'login': long_login, 'active': False, 'state': 'success', 'token': tokens['long']},
            {'login': 'gitenv', 'active': False, 'state': 'success', 'token': 'gho_x', 'token_source': 'GITHUB_TOKEN'},
        ], other_hosts={'ghe.example.com': [{'state': 'success', 'active': True, 'host': 'ghe.example.com',
                                             'login': 'enterprise', 'tokenSource': 'keyring', 'gitProtocol': 'https'}]},
               users={tokens['alice']: {'login': 'Alice.Smith+x', 'scopes': 'repo'}})
        cli_env = {'GH_TOKEN': 'cli-gh-token-' + secrets.token_hex(6), 'GITHUB_TOKEN': 'cli-github-token',
                   'GH_ENTERPRISE_TOKEN': 'cli-ent-token', 'GITHUB_ENTERPRISE_TOKEN': 'cli-gent-token',
                   'BOUNDS_MARKER': 'kept'}
        mark = gh.mark()
        code, value, stdout, stderr = self.refresh('p3', '--builtin', env=cli_env)
        need(isinstance(value, list) and len(value) == 1 and
             {k: value[0].get(k) for k in ('agent_id', 'agent', 'workspace')} ==
             {'agent_id': None, 'agent': 'builtin', 'workspace': None} and
             set(value[0]) == {'agent_id', 'agent', 'workspace', 'sources'} and
             set(value[0]['sources']) == {'servers', 'errors'},
             'sources refresh --builtin prints only the element {agent_id: null, agent: "builtin", workspace: null, '
             'sources: {servers, errors}}', value)
        for entry in value[0]['sources']['servers']:
            need(set(entry) == ATTACH_SERVER_KEYS, 'built-in ENTRY has the shape of attach servers', entry)
        b = self.builtin('p3')
        long_name = 'gh-' + 'l' * 60
        need(set(b) == {'gh', 'gh-bob', 'gh-carol', 'gh-dave-o', long_name},
             'one source per github.com account: gh for the active one, gh-LOGIN lowercased with other characters '
             'replaced by -, cut to 63 characters; a repeated name dropped; GH_TOKEN and GITHUB_TOKEN entries and '
             'other hosts ignored', sorted(b))
        need(b['gh']['account'] == 'Alice.Smith+x' and b['gh-dave-o']['account'] == 'Dave.O' and
             b[long_name]['account'] == long_login, 'account is the login', {k: v['account'] for k, v in b.items()})
        for name, s in b.items():
            need(s['transport'] == 'stdio' and s['command'] == str(gh.path) and s['args'] == [] and s['url'] is None
                 and s['source'] == 'builtin' and s['adapter'] == 'gh' and s['version'] == '2.81.0' and
                 s['host'] == 'github.com', 'a built-in SERVER: transport stdio, command the absolute gh path, args '
                 '[], url null, source builtin, adapter, version, host', name, s)
        expect = {'gh': (True, None, True), 'gh-dave-o': (True, None, True), long_name: (True, None, True),
                  'gh-bob': (False, 'missing_env', True), 'gh-carol': (False, 'not_authenticated', False)}
        for name, (shareable, reason, authenticated) in expect.items():
            s = b[name]
            need(s['shareable'] is shareable and s['reason'] == reason and s['authenticated'] is authenticated,
                 f'{name}: shareable {shareable}, reason {reason}, authenticated {authenticated}', s)
        need(b['gh']['env'] == {'GH_TOKEN': {'source': 'captured'}}, 'a captured token: env GH_TOKEN captured',
             b['gh']['env'])
        for name in ('gh-bob', 'gh-carol'):
            need(b[name]['env'] == {'GH_TOKEN': {'source': 'missing', 'variables': ['GH_TOKEN']}},
                 'a failed auth token, or an account not authenticated: env GH_TOKEN missing', name, b[name]['env'])
        need('GH_TOKEN' in json.dumps(b['gh-bob']['missing_env']), 'missing_env names GH_TOKEN',
             b['gh-bob']['missing_env'])
        need([t['name'] for t in b['gh']['tools']] and {t['name'] for t in b['gh']['tools']} == set(OPERATIONS),
             'a shareable built-in source is snapshotted: its tools are the ten operations', b['gh']['tools'])
        # The discovery commands' environment.
        runs = gh.starts(since=mark)
        cli_runs = [e for e in runs if e['argv'][:1] in (['--version'], ['auth'])]
        argvs = [e['argv'] for e in cli_runs]
        need(['--version'] in argvs and ['auth', 'status', '--json', 'hosts'] in argvs,
             'discovery runs gh --version and gh auth status --json hosts', argvs)
        token_runs = sorted(tuple(a) for a in argvs if a[:2] == ['auth', 'token'])
        wanted = sorted(('auth', 'token', '--hostname', 'github.com', '--user', login)
                        for login in ('bob', 'Alice.Smith+x', 'Dave.O', long_login))
        need(token_runs == wanted, 'gh auth token --hostname github.com --user LOGIN for each authenticated account '
             '(only those; not the dropped repeat, the GH_TOKEN entries, or an unauthenticated one)', token_runs,
             wanted)
        for e in cli_runs:
            env = e['env']
            need(not any(v in env for v in TOKEN_VARS), 'discovery commands run without GH_TOKEN, GITHUB_TOKEN, '
                 'GH_ENTERPRISE_TOKEN, and GITHUB_ENTERPRISE_TOKEN', e['argv'], sorted(env))
            need(env.get('GH_PROMPT_DISABLED') == '1' and env.get('GH_NO_UPDATE_NOTIFIER') == '1',
                 'discovery commands run with GH_PROMPT_DISABLED=1 and GH_NO_UPDATE_NOTIFIER=1', e['argv'])
            need(env.get('BOUNDS_MARKER') == 'kept', 'discovery commands keep the rest of the CLI\'s environment',
                 e['argv'])
        values = {r for r in self.tool_values('p3')}
        need(any(tokens['alice'] in map(str, r) for r in values) and any(tokens['dave'] in map(str, r) for r in values)
             and not any(tokens['envtok'] in map(str, r) for r in values), 'tokens are stored in tool_values with '
             'agent_id builtin; a GH_TOKEN entry\'s is never captured', len(values))
        # Without --builtin: the agents' discovery, then the built-in element.
        code, value, stdout, stderr = self.refresh('p3')
        need(isinstance(value, list) and value and value[-1].get('agent') == 'builtin' and
             value[-1].get('agent_id') is None, 'sources refresh without --agent adds the built-in element', value)
        code, value, stdout, stderr = self.refresh('p3', '--builtin', '--agent', 'x', expect=None)
        need(code == 1, '--builtin with --agent exits 1', code, stderr[-300:])

        # No active account: the first remaining entry is gh.
        gh.set(accounts=[{'login': 'zed', 'active': False, 'state': 'success', 'token': 'gho_' + 'z' * 20},
                         {'login': 'amy', 'active': False, 'state': 'success', 'token': 'gho_' + 'a' * 20}])
        self.refresh('p3', '--builtin')
        b = self.builtin('p3')
        need(set(b) == {'gh', 'gh-amy'} and b['gh']['account'] == 'zed', 'with no active entry, the first remaining '
             'entry is gh', {k: v['account'] for k, v in b.items()})

        # auth status failing, or only GH_TOKEN entries: one definition gh, account null, authenticated false.
        for control, rule in (({'auth_status_exit': 1}, 'a failing gh auth status'),
                              ({'accounts': [{'login': 'e', 'active': True, 'state': 'success', 'token': 'gho_e',
                                              'token_source': 'GH_TOKEN'}]}, 'no remaining entry')):
            gh.set(**{'auth_status_exit': 0, **control})
            self.refresh('p3', '--builtin')
            b = self.builtin('p3')
            need(set(b) == {'gh'} and b['gh']['account'] is None and b['gh']['authenticated'] is False and
                 b['gh']['shareable'] is False and b['gh']['reason'] == 'not_authenticated',
                 f'{rule}: one definition gh, account null, authenticated false (not_authenticated)', b)
        gh.set(auth_status_exit=0, accounts=[{'login': 'Alice.Smith+x', 'active': True, 'state': 'success',
                                              'token': tokens['alice']}])

        # Versions: below 2.81.0, unparseable, and a failing --version run nothing else.
        for control, version, rule in (({'version': '2.80.9'}, '2.80.9', 'a version below 2.81.0'),
                                       ({'version': '2.9.10', 'version_text': None}, '2.9.10',
                                        'a version compared numerically (2.9.10 < 2.81.0)'),
                                       ({'version_text': 'gh version 2.x (unknown)\n'}, None, 'an unparseable version'),
                                       ({'version_text': 'GitHub CLI 2.90.0\n'}, None,
                                        'a first line not starting with gh version')):
            gh.set(version_text=None, version='2.102.0')
            gh.set(**control)
            mark = gh.mark()
            self.refresh('p3', '--builtin')
            b = self.builtin('p3')
            need(set(b) == {'gh'} and b['gh']['version'] == version and b['gh']['account'] is None and
                 b['gh']['authenticated'] is False and b['gh']['shareable'] is False and
                 b['gh']['reason'] == 'version', f'{rule}: one definition gh, version {version}, reason version', b)
            need([e['argv'] for e in gh.starts(since=mark)] == [['--version']],
                 f'{rule}: discovery runs nothing else', [e['argv'] for e in gh.starts(since=mark)])
        gh.set(version_text=None, version='2.102.0')

        # The name reason: an agent named builtin with a tool server gh (precedence over version).
        code, value, stdout, stderr = self.out('p3', 'agent', 'register', '--name', 'builtin', '--owner', 'pat')
        if code == 0:
            agent_id = value['id']
            definition = {'name': 'gh', 'transport': 'stdio', 'command': PYTHON, 'args': self.fixture.args('bgh'),
                          'env': {}, 'url': None, 'source': 'claude-code:user'}
            status, body = p3.call('PUT', f'/v1/agents/{agent_id}/tool-servers',
                                   {'workspace': str(self.root), 'servers': [definition], 'values': {}})
            need(status == 200, 'setup: the agent builtin with a tool server gh', status, body)
            gh.set(version='2.50.0')
            self.refresh('p3', '--builtin')
            b = self.builtin('p3')
            need(b['gh']['shareable'] is False and b['gh']['reason'] == 'name',
                 'reason name for a built-in source named as a tool server of an agent named builtin, before '
                 'version', b['gh'])
            status, body = p3.call('PUT', f'/v1/agents/{agent_id}/tool-servers',
                                   {'workspace': str(self.root), 'servers': [], 'values': {}})
            gh.set(version='2.102.0')
        else:
            self.soft(False, 'Q: agent register --name builtin was refused, so the name reason (an agent named builtin '
                      'that already exists) is not exercised here', stderr[-300:])

        # attach: its builtin output; attach --name builtin refused.
        catalog = self.root / 'integrations'
        bundle = catalog / 'claude-code'
        bundle.mkdir(parents=True)
        shutil.copy2(caps.HARNESS / 'provider.py', bundle / 'provider.py')
        shutil.copy2(caps.HARNESS / 'harness.py', bundle / 'harness.py')
        (bundle / 'integration.json').write_text(json.dumps({
            'version': 1, 'id': 'claude-code', 'command': [PYTHON, './provider.py'],
            'operations': ['prepare', 'check', 'launch']}))
        workspace = self.root / 'projects' / 'w3'
        workspace.mkdir(parents=True)
        (p3.home / '.claude.json').write_text(json.dumps({'mcpServers': {}}))
        agents_before = p3.cli('agent', 'list')
        code, value, stdout, stderr = self.out('p3', 'attach', 'claude', '--name', 'builtin', '--directory',
                                               str(workspace), '--integrations', str(catalog), '--no-start')
        need(code == 1 and 'builtin' in stderr and p3.cli('agent', 'list') == agents_before,
             'attach --name builtin exits 1 before anything changes, saying the name is reserved', code,
             stderr[-300:])
        code, value, stdout, stderr = self.out('p3', 'attach', 'claude', '--name', 'w3', '--directory',
                                               str(workspace), '--integrations', str(catalog), '--no-start')
        need(code == 0 and isinstance(value, dict) and isinstance(value.get('sources'), dict) and
             isinstance(value['sources'].get('builtin'), list), 'attach\'s sources gains builtin: [ENTRY]', code,
             stdout[-400:], stderr[-300:])
        entries = {e['name']: e for e in value['sources']['builtin']}
        need(set(entries) == {'gh'} and set(entries['gh']) == ATTACH_SERVER_KEYS and
             entries['gh']['shareable'] is True and entries['gh']['tools'] == 10 and
             entries['gh']['read_only_tools'] == 7, 'attach runs built-in discovery after its MCP source discovery: '
             'ENTRY as for servers (10 tools, 7 read-only)', entries)

        # gh absent: no definitions, earlier ones removed, and the hint line.
        no_gh = caps.path_without_gh(os.environ.get('PATH', ''))
        code, value, stdout, stderr = self.refresh('p3', '--builtin', env={'PATH': no_gh})
        need(isinstance(value, list) and value[0]['sources']['servers'] == [],
             'with no gh on PATH, discovery sends no gh definitions', value)
        need(self.builtin('p3') == {}, 'earlier built-in sources are removed')
        code, value, stdout, stderr = self.out('p3', 'sources', env={'PATH': no_gh})
        lines = [l for l in stdout.splitlines() if l.strip()]
        need(code == 0 and lines and lines[-1].strip() == HINT, 'sources text ends with the hint line when PATH has no '
             'gh', code, stdout[-400:])
        code, value, stdout, stderr = self.out('p3', 'sources')
        need(HINT not in stdout, 'no hint line when gh is on PATH', stdout[-300:])
        # Restore one source on p3 for later sections.
        self.refresh('p3', '--builtin')
        return 'accounts, names, reasons, versions, environment, refresh, attach, absence'

    # --- tokens ------------------------------------------------------------------------------------------------

    def check_tokens(self):
        p1 = self.hosts['p1']
        rows = self.tool_values('p1')
        need(rows and any(self.token_bob in map(str, r) for r in rows) and
             any('env.GH_TOKEN' in map(str, r) for r in rows), 'the token is stored in tool_values with agent_id '
             'builtin, field env.GH_TOKEN', [tuple(c if c != self.token_bob else 'TOKEN' for c in r) for r in rows])
        b = self.builtin('p1')
        need(self.token_bob not in json.dumps(b), 'the token is not in GET /v1/sources')
        record = db_rows(p1, 'SELECT record FROM builtin_sources')
        need(record and not any(self.token_bob in r[0] for r in record), 'builtin_sources.record holds no token')
        # A failed auth token gives missing_env (also in discovery); here on p1 with the stored token intact.
        # The environment file overrides the stored GH_TOKEN (checked through the reach, which runs with the
        # instance's environment): on p3.
        p3, gh = self.hosts['p3'], self.gh3
        file_token = 'gho_' + secrets.token_hex(17)
        gh.set(users={**gh.control.get('users', {}), file_token: {'login': 'from-env-file', 'scopes': 'repo'}})
        env_file = p3.config / 'peerspan' / 'env'
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_file.write_text(f'# overrides\nGH_TOKEN={file_token}\nUNRELATED=x\n')
        env_file.chmod(0o600)
        try:
            mark = gh.mark()
            self.refresh('p3', '--builtin')
            b = self.builtin('p3')
            need(b['gh']['reach'] and b['gh']['reach']['account'] == 'from-env-file',
                 'the environment file\'s GH_TOKEN overrides the stored one (the reach check ran with it)',
                 b['gh']['reach'])
            api = [e for e in gh.starts(since=mark) if e['argv'][:1] == ['api']]
            need(api and api[-1]['env'].get('GH_TOKEN') == sha(file_token) and 'UNRELATED' not in api[-1]['env'],
                 'the gh process gets GH_TOKEN from the environment file, and nothing else from it',
                 api[-1]['env'] if api else None)
        finally:
            env_file.unlink()
        self.refresh('p3', '--builtin')
        # A capability's env_file overrides it, and only GH_TOKEN reaches gh: ghown on p1.
        self.needs('ghown')
        mark = self.gh1.mark()
        done = self.run_call('p2', 'ghown', 'issue_list', {'repo': 'acme/own'})
        need(done['state'] == 'succeeded', 'a call through ghown succeeds', done)
        runs = self.gh1.starts('acme/own', since=mark)
        need(len(runs) == 1 and runs[0]['env'].get('GH_TOKEN') == sha(self.token_own) and
             'OTHER_VARIABLE' not in runs[0]['env'], 'a capability\'s env_file overrides the stored GH_TOKEN, and only '
             'its GH_TOKEN reaches gh', runs[0]['env'] if runs else None)
        logs = p1.state / 'tool-logs' / 'builtin'
        need((logs / 'gh@ghown.log').exists(), 'a capability\'s own instance logs to STATE/tool-logs/builtin/'
             'NAME@CAPABILITY.log', sorted(os.listdir(logs)) if logs.exists() else None)
        return ''

    # --- reach -------------------------------------------------------------------------------------------------

    def check_reach(self):
        p3, gh = self.hosts['p3'], self.gh3
        kinds = {
            'oauth': ('gho_' + secrets.token_hex(10), {'login': 'u-oauth', 'scopes': 'repo, read:org'}),
            'classic': ('ghp_' + secrets.token_hex(10), {'login': 'u-classic', 'scopes': 'public_repo,  gist'}),
            'fine': ('github_pat_' + secrets.token_hex(10), {'login': 'u-fine', 'scopes': None}),
            'appu': ('ghu_' + secrets.token_hex(10), {'login': 'u-appu', 'scopes': None}),
            'apps': ('ghs_' + secrets.token_hex(10), {'login': 'u-apps', 'scopes': None}),
            'other': ('zzz_' + secrets.token_hex(10), {'login': 'u-other', 'scopes': None}),
            'empty': ('gho_' + secrets.token_hex(11), {'login': 'u-empty', 'scopes': ''}),
            'noscope': ('ghp_' + secrets.token_hex(11), {'login': 'u-noscope', 'scopes': None}),
            'failing': ('gho_' + secrets.token_hex(12), None),
            'slow': ('gho_' + secrets.token_hex(13), {'login': 'u-slow', 'scopes': 'repo', 'sleep': 13}),
            'garbled': ('gho_' + secrets.token_hex(14), {'login': 'u-garbled', 'garbage': True}),
        }
        users = {token: user for token, user in kinds.values() if user is not None}
        gh.set(users=users)
        sources = [{'name': f'gh-{k}', 'adapter': 'gh', 'command': str(gh.path), 'version': '2.102.0',
                    'host': 'github.com', 'account': f'def-{k}', 'authenticated': True,
                    'env': {'GH_TOKEN': {'source': 'captured'}}, 'disabled': False} for k in kinds]
        sources.append({'name': 'gh-nostart', 'adapter': 'gh', 'command': str(self.root / 'no-such-gh'),
                        'version': '2.102.0', 'host': 'github.com', 'account': 'def-nostart', 'authenticated': True,
                        'env': {'GH_TOKEN': {'source': 'captured'}}, 'disabled': False})
        sources.append({'name': 'gh-unchecked', 'adapter': 'gh', 'command': str(gh.path), 'version': '2.102.0',
                        'host': 'github.com', 'account': 'def-unchecked', 'authenticated': False,
                        'env': {'GH_TOKEN': {'source': 'missing', 'variables': ['GH_TOKEN']}}, 'disabled': False})
        values = {f'gh-{k}': {'env.GH_TOKEN': token} for k, (token, _) in kinds.items()}
        values['gh-nostart'] = {'env.GH_TOKEN': 'gho_' + secrets.token_hex(8)}
        status, body = p3.call('PUT', '/v1/builtin-sources', {'sources': sources, 'values': values})
        need(status == 200 and isinstance(body, dict) and set(body) == {'builtin'},
             'PUT /v1/builtin-sources returns {builtin: [SERVER]} once the snapshots finish', status, str(body)[:400])
        b = self.builtin('p3')
        expected = {
            'oauth': ('u-oauth', 'oauth', ['repo', 'read:org'], None),
            'classic': ('u-classic', 'classic', ['public_repo', 'gist'], None),
            'fine': ('u-fine', 'fine_grained', None, None),
            'appu': ('u-appu', 'app', None, None),
            'apps': ('u-apps', 'app', None, None),
            'other': ('u-other', 'unknown', None, None),
            'empty': ('u-empty', 'oauth', [], None),
            'noscope': ('u-noscope', 'classic', None, None),
            'failing': ('def-failing', 'oauth', None, 'gh exited with status 1'),
            'slow': ('def-slow', 'oauth', None, 'gh did not finish within 10 seconds'),
            'garbled': ('def-garbled', 'oauth', None, 'gh returned output Peerspan could not read'),
            'nostart': ('def-nostart', 'oauth', None, 'gh could not be started'),
        }
        code, value, text, stderr = self.out('p3', 'sources')
        lines = [l.strip() for l in text.splitlines()]
        for k, (account, token_type, scopes, error) in expected.items():
            s = b[f'gh-{k}']
            r = s['reach']
            need(isinstance(r, dict) and set(r) == REACH_KEYS, f'gh-{k}: reach is {{account, host, token_type, '
                 'scopes, checked_at, error}', s)
            need(r['account'] == account and r['host'] == 'github.com' and r['token_type'] == token_type and
                 r['scopes'] == scopes and r['error'] == error and parse_time(r['checked_at']),
                 f'gh-{k}: reach {account}, {token_type}, scopes {scopes}, error {error}', r)
            need(s['snapshot_error'] is None and {t['name'] for t in s['tools']} == set(OPERATIONS),
                 f'gh-{k}: a failed reach check does not fail the snapshot', s['snapshot_error'])
            sentence = reach_sentence(r, s['account'])
            need(f'reach: {sentence}' in lines, f'gh-{k}: sources prints "    reach: SENTENCE"', sentence,
                 text[-1500:])
        u = b['gh-unchecked']
        need(u['reach'] is None, 'reach is null before the first snapshot', u)
        need('reach: ' + reach_sentence(None, 'def-unchecked') in lines, 'the null-reach sentence names the '
             'definition\'s account', text[-1200:])
        line = next((l for l in lines if l.startswith('builtin/gh-oauth ')), '')
        need(squash(line) == 'builtin/gh-oauth gh 2.102.0 account def-oauth usable',
             'sources text: "  builtin/NAME  gh VERSION  account LOGIN  usable", LOGIN the definition\'s account',
             line)
        line = next((l for l in lines if l.startswith('builtin/gh-unchecked ')), '')
        need(squash(line) == 'builtin/gh-unchecked gh 2.102.0 account def-unchecked not usable: not_authenticated',
             'sources text: "not usable: REASON"', line)
        need('builtin' in lines, 'sources text lists built-in sources under a line builtin', text[:600])
        # A failed snapshot keeps the previous reach: the server cannot start (tools/list fails) is not reachable
        # here without breaking the adapter, so this is left to the generic snapshot cases.
        # Restore p3's discovered source.
        self.refresh('p3', '--builtin')
        # A capability with its own GH_TOKEN gets its own reach in credential_reach; one without has the source's.
        self.needs('ghown', 'ghall', 'mcpfree')
        own = self.capability('ghown')
        need(own and own['credential_reach'] and own['credential_reach']['account'] == 'bob-narrow' and
             own['credential_reach']['token_type'] == 'classic' and
             own['credential_reach']['scopes'] == ['public_repo'], 'a capability with its own GH_TOKEN gets its own '
             'reach (credential_reach)', own)
        source_reach = self.builtin('p1')['gh']['reach']
        need(source_reach and source_reach['account'] == 'bob' and source_reach['token_type'] == 'oauth' and
             source_reach['scopes'] == ['repo', 'read:org', 'workflow'], 'p1\'s builtin/gh reach', source_reach)
        need(self.capability('ghall')['credential_reach'] == source_reach, 'without its own credential, '
             'credential_reach is the source\'s reach', self.capability('ghall'))
        need(self.capability('mcpfree')['credential_reach'] is None, 'credential_reach is null for another source')
        # The sentence in the review and shares.
        review = squash(self.reviews.get('ghown', ''))
        need(squash(reach_statement('quinn', True, None, reach_sentence(own['credential_reach']))) in review,
             'the review states the gh reach for the capability\'s own credential', review[-900:])
        code, value, stdout, stderr = self.out('p1', 'shares', '--network', self.team)
        need(squash('reach: ' + reach_statement('Recipients', True, None, reach_sentence(source_reach))) in
             squash(stdout), 'shares states the reach sentence', stdout[-1500:])
        return ''

    # --- operations --------------------------------------------------------------------------------------------

    def check_operations(self):
        self.needs('ghall')
        p1, gh = self.hosts['p1'], self.gh1
        tools = {t['name']: t for t in self.builtin('p1')['gh']['tools']}
        names = [t['name'] for t in self.builtin('p1')['gh']['tools']]
        need(set(names) == set(OPERATIONS), 'the ten operations', names)
        self.soft(names == OPERATIONS, 'Q: sources --json lists the operations in tools/list order', names)
        for op in OPERATIONS:
            t = tools[op]
            need(t['read_only'] is (op in READ_ONLY), f'{op}: read_only {op in READ_ONLY}', t)
            need(t['description'] == TOOL_DESCRIPTIONS[op], f'{op}: the description', t['description'])
            schema = t['input_schema']
            props = schema.get('properties') or {}
            need(schema.get('type') == 'object' and schema.get('additionalProperties') is False and
                 set(schema) <= {'type', 'properties', 'required', 'additionalProperties'},
                 f'{op}: {{type: object, properties, required, additionalProperties: false}}', schema)
            need(list(props) == [p for p, _, _, _ in SCHEMAS[op]] or set(props) == {p for p, _, _, _ in SCHEMAS[op]},
                 f'{op}: exactly its properties', sorted(props))
            need(sorted(schema.get('required') or []) == sorted(p for p, _, _, r in SCHEMAS[op] if r),
                 f'{op}: required', schema.get('required'))
            for prop, expected, description, _ in SCHEMAS[op]:
                got_schema = dict(props[prop])
                need(got_schema.pop('description', None) == description, f'{op}.{prop}: description "{description}"',
                     props[prop])
                need(got_schema == expected, f'{op}.{prop}: schema', got_schema, expected)
        # Each operation: arguments, result text, standard input, working directory, environment.
        state = Path(os.path.realpath(p1.state))
        daemon = p1.daemon_env()
        cases = [
            ('issue_list', {'repo': 'acme/il-min'}, '[{"number": 1, "title": "one"}]', '{{"issues":{out}}}'),
            ('issue_list', {'repo': 'acme/il-full', 'state': 'closed', 'limit': 5, 'label': ['bug', 'p 1', '-x'],
                            'assignee': 'al', 'author': '--repo=evil/x', 'milestone': 'v1'}, '[]',
             '{{"issues":{out}}}'),
            ('issue_list', {'repo': 'acme/il-all', 'state': 'all', 'limit': 100}, ' \n [ ]\n', '{{"issues":{out}}}'),
            ('issue_view', {'repo': 'acme/iv-min', 'number': 5}, '{"number": 5,  "title": "\\u00e9 x"}',
             '{{"issue":{out}}}'),
            ('issue_view', {'repo': 'acme/iv-com', 'number': 5.0, 'comments': True}, '{"comments": []}',
             '{{"issue":{out}}}'),
            ('issue_view', {'repo': 'acme/iv-false', 'number': 6, 'comments': False}, '{}', '{{"issue":{out}}}'),
            ('pr_list', {'repo': 'acme/pl-min'}, '[{"number": 2}]', '{{"pull_requests":{out}}}'),
            ('pr_list', {'repo': 'acme/pl-full', 'state': 'merged', 'limit': 1, 'base': 'main', 'head': '-feat',
                         'label': ['a'], 'author': 'me', 'draft': True}, '[]', '{{"pull_requests":{out}}}'),
            ('pr_list', {'repo': 'acme/pl-nodraft', 'draft': False}, '[]', '{{"pull_requests":{out}}}'),
            ('pr_view', {'repo': 'acme/pv-min', 'number': 7}, '{"number": 7}', '{{"pull_request":{out}}}'),
            ('pr_view', {'repo': 'acme/pv-com', 'number': 7, 'comments': True}, '{"reviews": []}',
             '{{"pull_request":{out}}}'),
            ('pr_checks', {'repo': 'acme/pc', 'number': 7}, '[{"name": "ci", "bucket": "pass"}]',
             '{{"checks":{out}}}'),
            ('repo_view', {'repo': 'Acme-Org/repo.name_x'}, '{"nameWithOwner": "Acme-Org/repo.name_x"}',
             '{{"repository":{out}}}'),
        ]
        for op, input, stdout, template in cases:
            gh.repo(input['repo'], stdout=stdout)
        gh.repo('acme/pd', stdout='diff --git a/x b/x\n+"quoted"\t\n')
        gh.repo('acme/pd-names', stdout='README.md\r\n\r\nsrc/main.go\n')
        gh.repo('acme/ic-frag', stdout='Creating issue in acme/ic-frag\n\nhttps://github.com/acme/ic-frag/issues/77'
                                       '#top\n  \n')
        cases += [
            ('pr_diff', {'repo': 'acme/pd', 'number': 9}, None,
             canonical({'diff': 'diff --git a/x b/x\n+"quoted"\t\n'})),
            ('pr_diff', {'repo': 'acme/pd-names', 'number': 9, 'name_only': True}, None,
             canonical({'files': ['README.md', 'src/main.go']})),
            ('issue_create', {'repo': 'acme/ic-min', 'title': '-T'}, None,
             canonical({'number': 42, 'url': 'https://github.com/acme/ic-min/issues/42'})),
            ('issue_create', {'repo': 'acme/ic-full', 'title': 'Title', 'body': 'line one\n"two"\n',
                              'label': ['bug', 'x y'], 'assignee': ['al', 'bo']}, None,
             canonical({'number': 42, 'url': 'https://github.com/acme/ic-full/issues/42'})),
            ('issue_create', {'repo': 'acme/ic-frag', 'title': 'F'}, None,
             canonical({'number': 77, 'url': 'https://github.com/acme/ic-frag/issues/77#top'})),
            ('issue_comment', {'repo': 'acme/cm', 'number': 7, 'body': 'a comment'}, None,
             canonical({'url': 'https://github.com/acme/cm/issues/7#issuecomment-123456'})),
            ('pr_comment', {'repo': 'acme/pcm', 'number': 8, 'body': 'x' * 65536}, None,
             canonical({'url': 'https://github.com/acme/pcm/pull/8#issuecomment-123456'})),
        ]
        for op, input, stdout, template in cases:
            mark = gh.mark()
            done = self.run_call('p2', 'ghall', op, input, rule=f'{op} {input["repo"]}')
            runs = gh.starts(input['repo'], since=mark)
            need(len(runs) == 1, f'{op}: gh runs once', input['repo'], len(runs))
            run = runs[0]
            need(run['argv'] == expected_argv(op, input), f'{op}: the exact arguments', input, run['argv'],
                 expected_argv(op, input))
            text = template.format(out=stdout.strip(' \n\t\r')) if stdout is not None else template
            need(done['state'] == 'succeeded' and text_of(done['result']) == text and
                 not done['result'].get('isError'), f'{op}: the result text', input, done['state'],
                 text_of(done.get('result')), text)
            self.soft(set(done['result']) == {'content'} and done['result']['content'] ==
                      [{'type': 'text', 'text': text}], f'{op}: the result is exactly {{content: [{{type, text}}]}}',
                      done['result'])
            body = input.get('body', '') if op in ('issue_create', 'issue_comment', 'pr_comment') else ''
            need(run['stdin'] == body, f'{op}: standard input is the body for writes, and closed at once (empty) '
                 'otherwise', op, (run['stdin'] or '')[:80] if run['stdin'] is not None else None)
            need(run['cwd'].get('path') and os.path.realpath(run['cwd']['path']) == str(state / 'builtin' / 'gh' /
                                                                                         'work') and
                 run['cwd'].get('mode') == 0o700 and run['cwd'].get('entries') == [],
                 f'{op}: working directory STATE/builtin/gh/work, empty, mode 0700', run['cwd'])
            env = run['env']
            extra = set(env) - GH_ENV_NAMES
            need(not (extra - caps.INTERPRETER_NAMES) and GH_ENV_NAMES <= set(env),
                 f'{op}: exactly the gh environment', sorted(env))
            need({k: env[k] for k in GH_ENV_FIXED} == GH_ENV_FIXED and env['PATH'] == daemon.get('PATH') and
                 env['HOME'] == daemon.get('HOME') and env['GH_TOKEN'] == sha(self.token_bob) and
                 os.path.realpath(env['GH_CONFIG_DIR']) == str(state / 'builtin' / 'gh' / 'config'),
                 f'{op}: the gh environment\'s values (GH_TELEMETRY=0, private GH_CONFIG_DIR, the stored token)',
                 {k: v for k, v in env.items() if k != 'GH_TOKEN'})
            need(run['config_dir'] and run['config_dir'].get('mode') == 0o700,
                 f'{op}: GH_CONFIG_DIR is mode 0700', run['config_dir'])
        # Invalid arguments: a tool error naming the operation, running nothing.
        invalid = [
            ('issue_list', {}, 'arguments absent: repo required'),
            ('issue_list', {'repo': 'acme/api', 'search': 'repo:other/x'}, 'an unknown property'),
            ('repo_view', {'repo': 'acme/api', 'number': 1}, 'an unknown property on repo_view'),
            ('issue_list', {'repo': 5}, 'repo not a string'),
            ('issue_list', {'repo': 'github.com/acme/api'}, 'HOST/ in repo'),
            ('issue_list', {'repo': 'acme/..'}, 'repo ending in /..'),
            ('issue_list', {'repo': 'acme/.'}, 'repo ending in /.'),
            ('issue_list', {'repo': '-acme/api'}, 'repo starting with -'),
            ('issue_list', {'repo': 'acme/api\n'}, 'a control character in repo'),
            ('issue_list', {'repo': 'a' * 40 + '/x'}, 'an owner over 39 characters'),
            ('issue_list', {'repo': 'acme/api', 'state': 'merged'}, 'state outside issue_list\'s enum'),
            ('issue_list', {'repo': 'acme/api', 'limit': 0}, 'limit 0'),
            ('issue_list', {'repo': 'acme/api', 'limit': 101}, 'limit 101'),
            ('issue_list', {'repo': 'acme/api', 'limit': '5'}, 'limit a string'),
            ('issue_list', {'repo': 'acme/api', 'limit': 2.5}, 'limit not whole'),
            ('issue_list', {'repo': 'acme/api', 'label': ['l'] * 11}, '11 labels'),
            ('issue_list', {'repo': 'acme/api', 'label': ['']}, 'an empty label'),
            ('issue_list', {'repo': 'acme/api', 'label': ['x' * 257]}, 'a label over 256 bytes'),
            ('issue_list', {'repo': 'acme/api', 'label': 'bug'}, 'label not an array'),
            ('issue_list', {'repo': 'acme/api', 'author': ''}, 'an empty author'),
            ('issue_list', {'repo': 'acme/api', 'author': 'é' * 129}, 'an author over 256 bytes'),
            ('issue_list', {'repo': 'acme/api', 'author': 'a\x07b'}, 'a control character in author'),
            ('issue_list', {'repo': 'acme/api', 'author': 'a\x7fb'}, 'U+007F in author'),
            ('issue_list', {'repo': 'acme/api', 'milestone': 5}, 'milestone not a string'),
            ('issue_view', {'repo': 'acme/api'}, 'number required'),
            ('issue_view', {'repo': 'acme/api', 'number': '5'}, 'number a string'),
            ('issue_view', {'repo': 'acme/api', 'number': 0}, 'number 0'),
            ('issue_view', {'repo': 'acme/api', 'number': 2147483648}, 'number over 2^31 - 1'),
            ('issue_view', {'repo': 'acme/api', 'number': 1.5}, 'number not whole'),
            ('issue_view', {'repo': 'acme/api', 'number': True}, 'number a boolean'),
            ('pr_view', {'repo': 'acme/api', 'number': 'https://github.com/other/repo/pull/1'}, 'a URL in number'),
            ('pr_diff', {'repo': 'acme/api', 'number': 'main'}, 'a branch in number'),
            ('issue_view', {'repo': 'acme/api', 'number': 1, 'comments': 'yes'}, 'comments not a boolean'),
            ('pr_list', {'repo': 'acme/api', 'draft': 'true'}, 'draft not a boolean'),
            ('pr_list', {'repo': 'acme/api', 'state': 'draft'}, 'state outside pr_list\'s enum'),
            ('issue_create', {'repo': 'acme/api'}, 'title required'),
            ('issue_create', {'repo': 'acme/api', 'title': ''}, 'an empty title'),
            ('issue_create', {'repo': 'acme/api', 'title': 'x' * 257}, 'a title over 256 bytes'),
            ('issue_create', {'repo': 'acme/api', 'title': 'a\nb'}, 'a newline in title'),
            ('issue_create', {'repo': 'acme/api', 'title': 't', 'body': 'x' * 65537}, 'a body over 65,536 bytes'),
            ('issue_create', {'repo': 'acme/api', 'title': 't', 'assignee': 'al'}, 'assignee not an array on create'),
            ('issue_comment', {'repo': 'acme/api', 'number': 1}, 'body required for comments'),
            ('pr_comment', {'repo': 'acme/api', 'number': 1, 'body': 'a\x00b'}, 'U+0000 in body'),
        ]
        mark = gh.mark()
        for op, input, rule in invalid:
            done = self.run_call('p2', 'ghall', op, input, rule=rule)
            text = text_of(done.get('result')) or ''
            need(done['state'] == 'failed' and done['error'] == 'tool_error' and done['result'].get('isError') is True
                 and text.startswith(f'Invalid arguments for {op}: ') and len(text) > len(f'Invalid arguments for '
                                                                                          f'{op}: '),
                 f'invalid arguments ({rule}): isError "Invalid arguments for {op}: DETAIL"', done['state'],
                 done.get('error'), text[:200])
        need(gh.starts(since=mark) == [], 'invalid arguments run nothing', [e['argv'] for e in gh.starts(since=mark)])
        return f'{len(cases)} calls, {len(invalid)} invalid arguments'

    # --- execution ---------------------------------------------------------------------------------------------

    def check_execution(self):
        self.needs('ghall')
        p1, gh = self.hosts['p1'], self.gh1
        # The 120-second timeout, running in the background: SIGTERM ignored, SIGKILL 2 seconds later, the
        # process group with it.
        gh.repo('acme/hang', sleep=400, ignore_term=True, child=True)
        timeout_call = {}

        def hang():
            try:
                call_id, status, record = self.submit('p2', 'ghall', 'issue_view', {'repo': 'acme/hang', 'number': 1})
                timeout_call['status'] = status
                timeout_call['final'] = self.final('p2', call_id, timeout=200)
                timeout_call['at'] = time.time()
            except Exception as error:
                timeout_call['error'] = repr(error)
        worker = threading.Thread(target=hang, daemon=True)
        worker.start()
        try:
            self.execution_cases()
        finally:
            worker.join(timeout=230)
        need('final' in timeout_call, 'the hanging call finished', timeout_call)
        done = timeout_call['final']
        need(done['state'] == 'failed' and done['error'] == 'tool_error' and text_of(done['result']) == TIMED_OUT,
             f'the 120-second timeout: "{TIMED_OUT}"', done)
        run = gh.starts('acme/hang')[0]
        events = gh.events_for(run['pid'])
        term = [e for e in events if e['event'] == 'signal']
        need(term and 117 <= term[0]['time'] - run['time'] <= 126, 'SIGTERM at 120 seconds', events)
        need(not alive(run['pid']), 'a process that ignores SIGTERM is killed (SIGKILL)')
        need(not any(e['event'] == 'end' for e in events), 'it did not exit on its own', events)
        need(timeout_call['at'] - term[0]['time'] >= 1.5, 'SIGKILL 2 seconds after SIGTERM',
             timeout_call['at'] - term[0]['time'])
        child = next((e['child_pid'] for e in events if e['event'] == 'child'), None)
        need(child and not alive(child), 'the process group is killed with it', child)
        # The server's log: one line per call; no arguments, bodies, results, or token.
        log = p1.state / 'tool-logs' / 'builtin' / 'gh.log'
        need(log.exists(), 'the server logs to STATE/tool-logs/builtin/gh.log')
        text = log.read_text(errors='replace')
        for forbidden in ('acme/', 'cancel me', self.token_bob, 'line one', '"quoted"', 'Acme-Org', 'evil/x',
                          'nameWithOwner', 'issuecomment'):
            need(forbidden not in text, 'the server log holds no arguments, bodies, results, or token', forbidden)
        need('issue_list' in text and 'pr_diff' in text, 'the server log names the operations', text[-500:])
        return ''

    def execution_cases(self):
        p1, gh = self.hosts['p1'], self.gh1

        # Exit 1: the gh failed text with the 2,048-byte tail at a UTF-8 boundary, trailing whitespace removed.
        ascii_tail = ''.join(chr(65 + i % 26) for i in range(3000))
        gh.repo('acme/fail', exit=1, stderr=ascii_tail + '\n\n')
        gh.repo('acme/fail-utf8', exit=1, stderr='é' * 1500 + '\n')   # the 2,048-byte tail starts mid-character
        gh.repo('acme/fail-empty', exit=3, stderr='')
        gh.repo('acme/fail-space', exit=1, stderr='  \n\t\n')
        gh.repo('acme/fail-bytes', stderr_b64=b64(b'bad \xff\xfe end\n'), stdout_b64=b64(b''), exit=1)
        # The last 2,048 bytes are taken first (here including the two newlines), then trailing whitespace removed.
        for repo, text in (('acme/fail', 'gh failed: ' + ascii_tail[-2046:]),
                           ('acme/fail-utf8', 'gh failed: ' + 'é' * 1023),
                           ('acme/fail-empty', 'gh failed with exit status 3.'),
                           ('acme/fail-space', 'gh failed with exit status 1.'),
                           ('acme/fail-bytes', 'gh failed: bad �� end')):
            done = self.run_call('p2', 'ghall', 'issue_list', {'repo': repo})
            need(done['state'] == 'failed' and done['error'] == 'tool_error' and done['result'].get('isError') and
                 text_of(done['result']) == text, f'a non-zero exit ({repo}): "{text[:40]}..."', done['state'],
                 (text_of(done.get('result')) or '')[:120], len(text_of(done.get('result')) or ''))
        # Exit 4: a JSON-RPC error -32001, jsonrpc_error, auth_error_at, and item 14.
        gh.repo('acme/noauth', exit=4, stderr='To get started with GitHub CLI, please run:  gh auth login\n')
        done = self.run_call('p2', 'ghall', 'issue_list', {'repo': 'acme/noauth'})
        need(done['state'] == 'failed' and done['error'] == 'jsonrpc_error' and
             done['result'] == {'code': -32001, 'message': NOT_AUTH}, 'exit 4: failed with jsonrpc_error, the -32001 '
             'message', done)
        gh_source = self.builtin('p1')['gh']
        need(gh_source['auth_error_at'], 'exit 4 sets auth_error_at', gh_source)
        items = [i for i in self.items().get('attention', []) if i.get('subject') == 'builtin/gh']
        need(items and items[0].get('kind') == 'capability_failing' and
             items[0].get('command') == 'peerspan sources refresh --builtin', 'item 14 for builtin/gh with the '
             'command peerspan sources refresh --builtin', self.items().get('attention'))
        # pr_checks: exits 1 and 8 with a JSON array are success; exit 1 without one is not.
        for repo, code, stdout, ok in (('acme/checks-fail', 1, '[{"bucket": "fail"}]', True),
                                       ('acme/checks-pending', 8, '[{"bucket": "pending"}]', True),
                                       ('acme/checks-zero', 0, '[]', True),
                                       ('acme/checks-text', 1, 'no checks reported', False),
                                       ('acme/checks-obj', 8, '{"a": 1}', False)):
            gh.repo(repo, exit=code, stdout=stdout, stderr='checks stderr\n')
            done = self.run_call('p2', 'ghall', 'pr_checks', {'repo': repo, 'number': 3})
            if ok:
                need(done['state'] == 'succeeded' and text_of(done['result']) == '{"checks":' + stdout + '}',
                     f'pr_checks exit {code} with a JSON array is success', done)
            else:
                need(done['state'] == 'failed' and done['error'] == 'tool_error', f'pr_checks exit {code} without a '
                     'JSON array is not success', done)
        need(text_of(self.run_call('p2', 'ghall', 'issue_list', {'repo': 'acme/checks-text'}).get('result')) ==
             'gh failed: checks stderr', 'exit 1 other than pr_checks with valid output: gh failed')
        # Output over 1,000,000 bytes: result_too_large and no stored result; the process is killed.
        gh.repo('acme/big', big=1000001, sleep=60)
        mark = gh.mark()
        started = time.monotonic()
        done = self.run_call('p2', 'ghall', 'pr_diff', {'repo': 'acme/big', 'number': 1}, timeout=60)
        need(done['state'] == 'failed' and done['error'] == 'result_too_large' and done.get('result') is None and
             done.get('result_bytes') is None, 'output over 1,000,000 bytes: failed with result_too_large, no stored '
             'result', {k: done.get(k) for k in ('state', 'error', 'result_bytes')}, str(done.get('result'))[:200])
        need(time.monotonic() - started < 50, 'one byte over the limit kills the process (no wait for it to end)')
        pid = gh.starts('acme/big', since=mark)[0]['pid']
        wait_for(lambda: not alive(pid), timeout=10, message='the oversized gh process is gone')
        gh.repo('acme/exact', big=1000000, stdout='')
        done = self.run_call('p2', 'ghall', 'issue_list', {'repo': 'acme/exact'})
        need(done['state'] == 'failed' and done['error'] == 'tool_error' and text_of(done['result']) == UNREADABLE,
             'exactly 1,000,000 bytes is read (and is not a JSON array: unreadable)', done['state'], done.get('error'))
        # pr_diff with invalid UTF-8: one U+FFFD per byte.
        gh.repo('acme/bytes', stdout_b64=b64(b'line \xff\xfe end \xe2\x82\n'))
        done = self.run_call('p2', 'ghall', 'pr_diff', {'repo': 'acme/bytes', 'number': 1})
        need(done['state'] == 'succeeded' and
             text_of(done['result']) == canonical({'diff': 'line �� end ��\n'}),
             'invalid UTF-8 in standard output becomes U+FFFD, one per byte', text_of(done.get('result')))
        # Unreadable output.
        for repo, op, behaviour in (('acme/garbage', 'issue_list', {'garbage': True}),
                                    ('acme/view-array', 'issue_view', {'stdout': '[1, 2]'}),
                                    ('acme/list-object', 'pr_list', {'stdout': '{"a": 1}'}),
                                    ('acme/no-url', 'issue_create', {'stdout': 'created\nhttp://example.com/1\n'})):
            gh.repo(repo, **behaviour)
            input = {'repo': repo}
            input.update({'issue_view': {'number': 1}, 'issue_create': {'title': 't'}}.get(op, {}))
            done = self.run_call('p2', 'ghall', op, input)
            need(done['state'] == 'failed' and done['error'] == 'tool_error' and done['result'].get('isError') and
                 text_of(done['result']) == UNREADABLE, f'unreadable output ({repo}): "{UNREADABLE}"', done['state'],
                 text_of(done.get('result')))
        # Cancellation of a running write: SIGTERM to gh, uncertain, no second run.
        gh.repo('acme/cancel', sleep=60)
        mark = gh.mark()
        call_id, status, record = self.submit('p2', 'ghall', 'issue_comment',
                                              {'repo': 'acme/cancel', 'number': 4, 'body': 'cancel me'})
        need(status == 200, 'the write to cancel is accepted', status, record)
        run = wait_for(lambda: (gh.starts('acme/cancel', since=mark) or [None])[0], timeout=30,
                       message='gh started for the write')
        status, record = self.cancel('p2', call_id)
        need(status == 200, 'cancel', status, record)
        done = self.final('p2', call_id)
        need(done['state'] == 'uncertain' and done['error'] == 'cancel_requested',
             'a cancelled running write is uncertain with cancel_requested', done)
        wait_for(lambda: not alive(run['pid']), timeout=10, message='the cancelled gh process is killed')
        need(any(e['event'] == 'signal' and e['signal'] == 'SIGTERM' for e in gh.events_for(run['pid'])),
             'cancellation sends SIGTERM to gh', gh.events_for(run['pid']))
        time.sleep(8)
        need(len(gh.starts('acme/cancel', since=mark)) == 1, 'a cancelled write is never run a second time')

    # --- bounds ------------------------------------------------------------------------------------------------

    def refused(self, caller, capability, operation, input, bounds, rule):
        mark = self.gh1.mark()
        fx_mark = len(self.fixture.calls('fx'))
        call_id, status, body = self.submit(caller, capability, operation, input)
        need(status == 403 and isinstance(body, dict) and body.get('code') == 'out_of_bounds' and
             body.get('error') == out_of_bounds(bounds, input) and body.get('bounds') == bounds,
             f'{rule}: 403 out_of_bounds with the exact text and bounds', status, body, out_of_bounds(bounds, input))
        need(set(body) == {'code', 'error', 'bounds'}, f'{rule}: the body is {{code, error, bounds}}', body)
        status, record = self.status_of(caller, call_id)
        need(status == 404, f'{rule}: nothing persisted at the receiver', status, record)
        need(self.gh1.starts(since=mark) == [] and len(self.fixture.calls('fx')) == fx_mark,
             f'{rule}: nothing executed')

    def check_bounds(self):
        self.needs('ghb', 'ghtight', 'mcpb', 'mcpall')
        p1, gh = self.hosts['p1'], self.gh1
        B = self.B
        for name, bounds in B.items():
            need(self.capability(name)['bounds'] == bounds, f'{name}: bounds stored as given, in order', name,
                 self.capability(name)['bounds'])
        # gh matcher: case-insensitive, OWNER/*.
        for repo in ('acme/api', 'ACME/Api', 'beta/anything', 'BETA/x.y'):
            done = self.run_call('q1', 'ghb', 'issue_list', {'repo': repo}, rule=f'ghb {repo}')
            need(done['state'] == 'succeeded', f'the gh repo matcher passes {repo}', done)
        for input, rule in (({'repo': 'acme/web'}, 'a different value'),
                            ({'repo': 'betax/y'}, 'another owner sharing a prefix'),
                            ({'repo': 'acme/api-x'}, 'a longer name'),
                            ({}, 'an absent argument'),
                            ({'repo': 5}, 'a non-string argument'),
                            ({'repo': ['acme/api']}, 'an array argument')):
            self.refused('q1', 'ghb', 'issue_list', input, B['ghb'], f'ghb, {rule}')
        self.refused('q1', 'ghb', 'issue_comment', {'repo': 'acme/web', 'number': 1, 'body': 'b"q'}, B['ghb'],
                     'ghb, a write outside the bound')
        self.refused('p2', 'ghb', 'issue_list', {'repo': 'other/x'}, B['ghb'], 'ghb by self')
        # MCP: combinations, not independent values; exact bytes.
        for input in ({'owner': 'acme', 'repo': 'api'}, {'owner': 'beta', 'repo': 'web', 'state': 'open'}):
            done = self.run_call('q1', 'mcpb', 'list_issues', input, rule='mcpb')
            need(done['state'] == 'succeeded', 'a call matching one combination passes', input, done)
        for input, rule in (({'owner': 'acme', 'repo': 'web'}, 'combinations, not independent values'),
                            ({'owner': 'ACME', 'repo': 'api'}, 'exact byte equality for MCP sources'),
                            ({'repo': 'api'}, 'an absent argument'),
                            ({'owner': 'acme', 'repo': 'a"pi\n'}, 'a value needing escapes in GOT')):
            self.refused('q1', 'mcpb', 'list_issues', input, B['mcpb'], f'mcpb, {rule}')
        # read is unaffected.
        done = self.run_call('q1', 'mcpb', 'read', {'uri': 'fixture://docs/readme'}, rule='read on mcpb')
        need(done['state'] == 'succeeded', 'read is not bounded', done)
        # Raw sources are unbounded.
        done = self.run_call('p2', 'builtin/gh', 'issue_list', {'repo': 'anyone/anything'}, rule='builtin/gh')
        need(done['state'] == 'succeeded', 'the raw source builtin/gh has no bounds', done)
        done = self.run_call('p2', 'srv/fx', 'list_issues', {'owner': 'x', 'repo': 'y'}, rule='srv/fx')
        need(done['state'] == 'succeeded', 'the implicit capability AGENT/SERVER has no bounds', done)
        # Refused calls are not counted against max_calls_per_hour (ghtight: 1 an hour).
        for _ in range(3):
            self.refused('q1', 'ghtight', 'issue_list', {'repo': 'acme/web'}, B['ghtight'], 'ghtight')
        done = self.run_call('q1', 'ghtight', 'issue_list', {'repo': 'acme/api'}, rule='ghtight after refusals')
        need(done['state'] == 'succeeded', 'refused calls are not counted: the one call an hour still runs', done)
        call_id, status, body = self.submit('q1', 'ghtight', 'issue_list', {'repo': 'acme/api'})
        need(status == 429, 'the budget then refuses the next', status, body)

        # Create-time checks through the API (claims signed as the CLI would).
        def post(name, source, operations, bounds, resources=None, code='invalid', error=None):
            status, body = self.post_capability(name, source, operations, bounds, resources=resources)
            body = body if isinstance(body, dict) else {}
            need(status == 400 and body.get('code') == code and (error is None or body.get('error') == error) and
                 self.capability(name) is None, f'POST /v1/capabilities {name} bounds {json.dumps(bounds)[:100]}: '
                 f'400 {code}' + (f' "{error}"' if error else ''), status, body)
            return body
        long_value = 'v' * 257
        for bounds, rule in (({'arguments': []}, 'no combination'),
                             ({'arguments': [{'text': str(i)} for i in range(17)]}, '17 combinations'),
                             ({'arguments': [{}]}, 'an empty combination'),
                             ({'arguments': [{'a': '1', 'b': '2', 'c': '3', 'd': '4', 'e': '5'}]}, '5 names'),
                             ({'arguments': [{'1bad': 'x'}]}, 'a name starting with a digit'),
                             ({'arguments': [{'a' * 65: 'x'}]}, 'a name over 64 characters'),
                             ({'arguments': [{'text': ''}]}, 'an empty value'),
                             ({'arguments': [{'text': long_value}]}, 'a value over 256 bytes'),
                             ({'arguments': [{'text': 'a\nb'}]}, 'a control character in a value'),
                             ({'arguments': [{'text': 'a\x7f'}]}, 'U+007F in a value'),
                             ({'arguments': [{'text': 5}]}, 'a non-string value'),
                             ({'arguments': [{'text': 'x'}], 'extra': 1}, 'an unknown key'),
                             ({'args': []}, 'the wrong key'),
                             ('text=x', 'not an object')):
            post('badb', 'srv/fx', ['echo'], bounds)
        for value in ('acme/*/x', '*/api', 'acme/a*', 'github.com/acme/api', 'acme', 'acme/..', '-a/b', 'acme/'):
            post('badgh', 'builtin/gh', ['issue_list'], {'arguments': [{'repo': value}]}, error=GH_BOUND_INVALID)
        post('badres', 'srv/fx', [], {'arguments': [{'text': 'x'}]}, resources='all', error=NO_TOOL_OPS)
        post('badres2', 'srv/fx', None, {'arguments': [{'text': 'x'}]}, resources=['fixture://docs/readme'],
             error=NO_TOOL_OPS)
        b = {'arguments': [{'owner': 'acme', 'repo': 'api'}]}
        post('unenf1', 'srv/fx', ['list_issues', 'no_repo', 'get_count'], b, code='bound_unenforceable',
             error=UNENFORCEABLE.format(op='no_repo', key='repo'))
        post('unenf2', 'srv/fx', ['get_count', 'no_repo'], b, code='bound_unenforceable',
             error=UNENFORCEABLE.format(op='get_count', key='repo'))
        post('unenf3', 'srv/fx', ['echo'], {'arguments': [{'text': 'x'}, {'zeta': 'y', 'alpha': 'z'}]},
             code='bound_unenforceable', error=UNENFORCEABLE.format(op='echo', key='alpha'))
        post('unenf4', 'builtin/gh', ['issue_list', 'issue_view'], {'arguments': [{'repo': 'acme/api', 'state': 'open'}]},
             code='bound_unenforceable', error=UNENFORCEABLE.format(op='issue_view', key='state'))
        post('unenf5', 'builtin/gh', ['issue_view'], {'arguments': [{'number': '1'}]}, code='bound_unenforceable',
             error=UNENFORCEABLE.format(op='issue_view', key='number'))
        # A property need not be required: echo's text is optional.
        status, body = self.post_capability('optb', 'srv/fx', ['echo'], {'arguments': [{'text': 'only'}]})
        need(status == 201 and body.get('bounds') == {'arguments': [{'text': 'only'}]} and
             body.get('warnings') == [], 'a bound on an optional string property is accepted (201, warnings [])',
             status, body)
        # Repeat and conflict with bounds.
        status, body = self.post_capability('optb', 'srv/fx', ['echo'], {'arguments': [{'text': 'only'}]})
        need(status == 200 and body.get('warnings') == [], 'an identical repeat with equal bounds: 200 with warnings '
             '[] (a repeat runs no check)', status, body)
        for bounds, rule in (({'arguments': [{'text': 'other'}]}, 'different bounds'),
                             ({}, 'no bounds'),
                             (None, 'bounds absent')):
            status, body = self.post_capability('optb', 'srv/fx', ['echo'], bounds)
            need(status == 409, f'a different record ({rule}) under the same name: 409', status, body)
        status, body = self.post_capability('ordb', 'srv/fx', ['echo'], {'arguments': [{'text': 'a'}, {'text': 'b'}]})
        need(status == 201, 'ordb created', status, body)
        status, body = self.post_capability('ordb', 'srv/fx', ['echo'], {'arguments': [{'text': 'b'}, {'text': 'a'}]})
        need(status == 409, 'combinations in another order are a different record: 409', status, body)
        status, body = self.post_capability('nob', 'srv/fx', ['echo'], {})
        need(status == 201 and body.get('bounds') == {}, 'bounds {} means no bound', status, body)
        status, body = self.post_capability('nob', 'srv/fx', ['echo'], None)
        need(status == 200, 'absent bounds equal {} (identical repeat)', status, body)
        for name in ('optb', 'ordb', 'nob'):
            self.remove(name)

        # --bound parsing in the CLI.
        version = self.version()
        for flag, rule in (('repo', 'a part without ='), ('=x', 'an empty name'), ('repo=a,repo=b', 'a name twice'),
                           ('repo=acme/api,', 'an empty part')):
            code, value, stderr = self.create('cliref', 'builtin/gh', ['issue_list'], flag, expect=None)
            need(code == 1 and self.capability('cliref') is None and self.version() == version,
                 f'--bound {flag}: {rule} exits 1 before anything is sent', code, stderr[-300:])
        self.create('clib', 'srv/fx', ['flags'], 'text=a=b', 'network=n,input=i')
        need(self.capability('clib')['bounds'] == {'arguments': [{'text': 'a=b'}, {'input': 'i', 'network': 'n'}]},
             '--bound splits each part at its first =, and each flag is a combination', self.capability('clib'))
        code, value, stderr = self.create('clib', 'srv/fx', ['flags'], 'text=a=b', 'network=n,input=i', expect=None)
        need(code == 0, 'an identical CLI repeat succeeds', code, stderr[-300:])
        code, value, stderr = self.create('clib', 'srv/fx', ['flags'], 'text=a=b', expect=None)
        need(code != 0, 'a CLI repeat with different bounds fails (409)', code)
        self.remove('clib')

        # Warnings for repositories the credential cannot see.
        gh.repo('acme/hidden', exit=1, stderr='GraphQL: Could not resolve to a Repository\n')
        gh.repo('acme/slowview', sleep=14)
        mark = gh.mark()
        code, value, stderr = self.create('ghwarn', 'builtin/gh', ['issue_list'], 'repo=acme/api', 'repo=acme/hidden',
                                          'repo=acme/*', 'repo=acme/slowview', 'repo=acme/api')
        warnings = ['acme/hidden is not visible to this credential', 'acme/slowview is not visible to this credential']
        for w in warnings:
            need(f'warning: {w}' in stderr, 'the CLI prints each warning as "warning: TEXT" to stderr', w,
                 stderr[-600:])
        views = [e['argv'] for e in gh.starts(since=mark) if e['argv'][:2] == ['repo', 'view']]
        need(views == [['repo', 'view', r, f'--json={FIELDS["repo_view"]}'] for r in
                       ('acme/api', 'acme/hidden', 'acme/slowview')],
             'repo_view\'s arguments for each distinct exact repo, in order, skipping OWNER/*', views)
        need(all(e['env'].get('GH_TOKEN') == sha(self.token_bob) and e['env'].get('GH_TELEMETRY') == '0'
                 for e in gh.starts(since=mark) if e['argv'][:2] == ['repo', 'view']),
             'the check runs with the gh environment of the capability\'s credential')
        self.remove('ghwarn')
        status, body = self.post_capability('ghwarn2', 'builtin/gh', ['issue_list'],
                                            {'arguments': [{'repo': 'acme/hidden'}, {'repo': 'beta/*'}]})
        need(status == 201 and body.get('warnings') == ['acme/hidden is not visible to this credential'],
             'the POST response carries warnings; none for OWNER/*', status, body)
        self.remove('ghwarn2')
        # Last, so that a failure here does not hide the cases above: null is a non-string value.
        self.refused('q1', 'mcpb', 'list_issues', {'owner': 'acme', 'repo': None}, B['mcpb'],
                     'mcpb, a null argument (non-string)')
        self.refused('q1', 'ghb', 'issue_list', {'repo': None}, B['ghb'], 'ghb, a null repo (non-string)')
        return ''

    def check_recheck(self):
        """A call queued under a capability removed and recreated with a narrower bound is rejected at the recheck;
        one inside the new bound runs."""
        self.needs('ghall')
        gh = self.gh1
        self.create('ghq', 'builtin/gh', ['issue_list'], 'repo=acme/api', 'repo=acme/other')
        self.share('ghq', terminal=False)
        self.sync()
        gh.repo('acme/slow', sleep=45)
        fillers = []
        for n in range(4):
            call_id, status, record = self.submit('p2', 'ghall', 'pr_view', {'repo': 'acme/slow', 'number': n + 1})
            need(status == 200, 'setup: a slow call filling the source instance', status, record)
            fillers.append(call_id)
        wait_for(lambda: len(gh.starts('acme/slow')) >= 4, timeout=60, message='four slow gh runs')
        gh.repo('acme/api', stdout='[]')
        lapsing, status, record = self.submit('q1', 'ghq', 'issue_list', {'repo': 'acme/api'})
        need(status == 200 and record['state'] == 'queued', 'a fifth call waits as queued', status, record)
        kept, status, record = self.submit('q1', 'ghq', 'issue_list', {'repo': 'acme/other'})
        need(status == 200 and record['state'] == 'queued', 'a sixth call waits as queued', status, record)
        mark = gh.mark()
        self.remove('ghq')
        self.create('ghq', 'builtin/gh', ['issue_list'], 'repo=acme/other')
        self.share('ghq', terminal=False)
        done = self.final('q1', lapsing, timeout=90)
        need(done['state'] == 'rejected' and LAPSED in json.dumps(done), f'the queued call outside the narrower '
             f'bound is rejected at the recheck, "{LAPSED}"', done)
        done = self.final('q1', kept, timeout=90)
        # A recheck that falls between the remove and the create finds no capability and rejects this one too
        # (contract, Enforcement), so whether it runs depends on timing; soft.
        self.soft(done['state'] == 'succeeded', 'the queued call inside the new bound runs (when no recheck fell '
                  'between the remove and the create)', done.get('state'), done.get('error'))
        need(not gh.starts('acme/api', since=mark), 'the rejected call never ran')
        for call_id in fillers:
            self.final('p2', call_id, timeout=90)
        return ''

    # --- display -----------------------------------------------------------------------------------------------

    def check_display(self):
        self.needs('ghb', 'ghenum', 'mcpb', 'mcpall', 'mcpfree', 'ghall')
        p1, q1, B = self.hosts['p1'], self.hosts['q1'], self.B
        # capability list and show.
        status, body = p1.call('GET', '/v1/capabilities')
        records = {c['name']: c for c in body['capabilities']}
        for name, bounds in B.items():
            need(records[name]['bounds'] == bounds, f'GET /v1/capabilities shows {name}\'s bounds', records[name])
        need(records['ghall']['bounds'] == {} and records['mcpfree']['bounds'] == {}, 'unbounded: bounds {}')
        code, value, stdout, stderr = self.out('p1', 'capability', 'show', 'ghb')
        need(code == 0 and isinstance(value, dict) and value.get('bounds') == B['ghb'] and 'credential_reach' in value,
             'capability show: bounds and credential_reach', code, stdout[:400])
        code, value, stdout, stderr = self.out('p1', 'capability', 'list')
        line = next((l for l in stdout.splitlines() if re.search(r'\bghb\b', l)), '')
        need(f'bounds: {allowed(B["ghb"])}' in line, 'capability list text adds "  bounds: ALLOWED" to a bounded '
             'capability\'s line', line, stdout[-800:])
        # GET /peer/v1/capabilities: bounds and narrowed schemas.
        entries = self.listing('q1')
        for name, bounds in B.items():
            if name in entries:
                need(entries[name]['bounds'] == bounds, f'{name}: bounds in GET /peer/v1/capabilities',
                     entries[name].get('bounds'))
        need(entries['ghall']['bounds'] == {} and entries['mcpfree']['bounds'] == {},
             'unbounded entries have bounds {}', entries['ghall'].get('bounds'))
        ops = {o['name']: o for o in entries['ghenum']['operations']}
        props = ops['issue_list']['input_schema']['properties']
        need(props['repo'] == {'type': 'string', 'enum': ['acme/api', 'acme/web']}, 'one name in every combination '
             'and no OWNER/*: the property becomes exactly {type: string, enum: [distinct values]}', props['repo'])
        need(props['state'] == dict(state_schema(['open', 'closed', 'all']), description='Which items to list.'),
             'other properties unchanged', props['state'])
        text = f'Limited by the owner: {allowed(B["ghb"])}.'
        for op in ('issue_list', 'issue_view', 'issue_comment'):
            prop = {o['name']: o for o in entries['ghb']['operations']}[op]['input_schema']['properties']['repo']
            need(prop == dict(REPO, description='The repository, as OWNER/REPO. ' + text), 'with OWNER/*, the '
                 'description gains "Limited by the owner: ALLOWED." after one space', op, prop)
        text = f'Limited by the owner: {allowed(B["mcpb"])}.'
        for op in ('list_issues', 'search_issues'):
            schema = {o['name']: o for o in entries['mcpb']['operations']}[op]['input_schema']['properties']
            need(schema['owner'] == {'type': 'string', 'description': text}, 'several names: the description is the '
                 'whole text when the property has none', op, schema['owner'])
            want = 'The repository name ' + text if op == 'list_issues' else text
            need(schema['repo'] == {'type': 'string', 'description': want}, 'several names: appended to an existing '
                 'description', op, schema['repo'])
            other = 'query' if op == 'search_issues' else 'state'
            need(schema[other] == {'type': 'string'}, 'a property not in the bound is unchanged', schema[other])
        read = {o['name']: o for o in entries['mcpb']['operations']}.get('read')
        need(read and read['input_schema']['properties']['uri'].get('enum'), 'read keeps its uri schema', read)
        snapshot = {t['name']: t for t in self.sources_tools('srv')}
        need(snapshot['list_issues']['input_schema']['properties']['owner'] == {'type': 'string'},
             'the stored snapshot is unchanged', snapshot['list_issues'])
        # discover.
        code, value, stdout, stderr = self.out('q1', 'discover', 'pat', '--json', '--network', self.team)
        found = {e['capability']: e for e in (value or {}).get('capabilities', [])}
        need(found.get('ghb', {}).get('bounds') == B['ghb'] and found.get('ghall', {}).get('bounds') == {},
             'discover --json: bounds on each entry', {k: v.get('bounds') for k, v in found.items()},
             (value or {}).get('unanswered'), stderr[-300:])
        code, value, stdout, stderr = self.out('q1', 'discover', 'pat', '--network', self.team)
        lines = stdout.splitlines()
        index = next((i for i, l in enumerate(lines) if re.search(r'\bghb\b', l)), None)
        need(index is not None and any(l.strip() == f'limited to {allowed(B["ghb"])}' and l.startswith('    ')
                                       for l in lines[index + 1:index + 6]),
             'discover text adds "    limited to ALLOWED" under a bounded capability', stdout[-1200:])
        # The review: bounds block and reach statements.
        gh_reach = reach_sentence(self.builtin('p1')['gh']['reach'])
        checks = {
            'ghb': [f'Bounds: {allowed(B["ghb"])}', EVERY_GH, reach_statement('quinn', True, B['ghb'], gh_reach)],
            'mcpb': [f'Bounds: {allowed(B["mcpb"])}',
                     'Not checked by Peerspan: list_issues: labels, state; search_issues: query, sort.', READ_LINE,
                     reach_statement('quinn', False, B['mcpb'])],
            'mcpall': [f'Bounds: {allowed(B["mcpall"])}', EVERY_ARG, reach_statement('quinn', False, B['mcpall'])],
            'ghall': [reach_statement('quinn', True, None, gh_reach)],
            'mcpfree': [reach_statement('quinn', False, None)],
        }
        for name, texts in checks.items():
            review = squash(self.reviews.get(name, ''))
            for t in texts:
                need(squash(t) in review, f'the review of {name}: "{t[:70]}"', review[-1500:])
            if name in ('ghall', 'mcpfree'):
                need('Bounds:' not in review, f'no bounds block for unbounded {name}', review[-600:])
        review = self.reviews.get('ghall', '')
        lines = review.splitlines()
        for op in OPERATIONS:
            line = next((l for l in lines if re.search(rf'\b{op}\b', l)), '')
            need((CAN_CHANGE in line) is (op not in READ_ONLY), f'the review marks {op} by its annotations', line)
        # shares: text and --json.
        code, value, stdout, stderr = self.out('p1', 'shares', '--network', self.team)
        text = squash(stdout)
        need(squash(f'bounds: {allowed(B["ghb"])}') in text and 'bounds: none' in text,
             'shares text: "  bounds: ALLOWED" and "  bounds: none"', stdout[-1500:])
        need(squash('reach: ' + reach_statement('Recipients', False, B['mcpb'])) in text,
             'shares text: "  reach: STATEMENT" with Recipients as PRINCIPAL', stdout[-1500:])
        code, value, stdout, stderr = self.out('p1', 'shares', '--json', '--network', self.team)
        found = {}

        def walk(v):
            if isinstance(v, dict):
                n = v.get('name') or v.get('capability')
                if isinstance(n, str) and 'reach' in v:
                    found[n] = v
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
        walk(value)
        need(found.get('ghb', {}).get('bounds') == B['ghb'] and
             found['ghb'].get('reach') == reach_statement('Recipients', True, B['ghb'], gh_reach) and
             found.get('mcpfree', {}).get('reach') == reach_statement('Recipients', False, None) and
             found['mcpfree'].get('bounds') == {}, 'shares --json: each capability with bounds and reach',
             {k: (v.get('bounds'), v.get('reach')) for k, v in found.items()})
        # The guided share's prompts at a terminal.
        code, value, tty, stdout, answered = self.dialogue('p1', ['share', '--with', 'quinn', '--network', self.team,
                                                                  '--from', 'builtin/gh', '--operations', 'issue_list',
                                                                  '--name', 'gguided'],
                                                           [(GH_PROMPT, 'acme/api Acme/*'), (SHARE_PROMPT, 'y')])
        need(GH_PROMPT in answered and code == 0, f'the guided share asks for a gh source: "{GH_PROMPT}"', code,
             answered, tty[-800:])
        need((self.capability('gguided') or {}).get('bounds') == {'arguments': [{'repo': 'acme/api'},
                                                                                {'repo': 'Acme/*'}]},
             'each word becomes the combination {repo: WORD}', self.capability('gguided'))
        code, value, tty, stdout, answered = self.dialogue('p1', ['share', '--with', 'quinn', '--network', self.team,
                                                                  '--from', 'srv/fx', '--operations', 'list_issues',
                                                                  '--name', 'mguided'],
                                                           [(MCP_PROMPT, 'owner=acme,repo=api repo=web'),
                                                            (SHARE_PROMPT, 'y')])
        need(MCP_PROMPT in answered and code == 0, f'the guided share asks for an MCP source: "{MCP_PROMPT}"', code,
             answered, tty[-800:])
        need((self.capability('mguided') or {}).get('bounds') == {'arguments': [{'owner': 'acme', 'repo': 'api'},
                                                                                {'repo': 'web'}]},
             'each word is read as a --bound value', self.capability('mguided'))
        code, value, tty, stdout, answered = self.dialogue('p1', ['share', '--with', 'quinn', '--network', self.team,
                                                                  '--from', 'builtin/gh', '--operations', 'issue_list',
                                                                  '--name', 'eguided'],
                                                           [(GH_PROMPT, ''), (SHARE_PROMPT, 'y')])
        need(code == 0 and (self.capability('eguided') or {}).get('bounds') == {}, 'an empty answer is no bound', code,
             self.capability('eguided'), tty[-600:])
        code, value, tty, stdout, answered = self.dialogue('p1', ['share', '--with', 'quinn', '--network', self.team,
                                                                  '--from', 'builtin/gh', '--operations', 'issue_list',
                                                                  '--name', 'fguided', '--bound', 'repo=acme/api'],
                                                           [(GH_PROMPT, 'acme/web'), (SHARE_PROMPT, 'y')])
        need(code == 0 and GH_PROMPT not in answered and
             (self.capability('fguided') or {}).get('bounds') == {'arguments': [{'repo': 'acme/api'}]},
             'with --bound, the guided share does not ask', code, answered, self.capability('fguided'))
        # A guided share creating a capability with its own credential states a null reach.
        code, value, tty, stdout, answered = self.dialogue('p1', ['share', '--with', 'quinn', '--network', self.team,
                                                                  '--from', 'builtin/gh', '--operations', 'issue_list',
                                                                  '--name', 'oguided', '--env-file',
                                                                  str(self.own_env), '--bound', 'repo=acme/api'],
                                                           [(SHARE_PROMPT, 'y')])
        need(code == 0 and squash(reach_statement('quinn', True, {'arguments': [{'repo': 'acme/api'}]},
                                                  reach_sentence(None, 'bob'))) in squash(tty),
             'a guided share creating a capability with its own credential uses a null reach in the review', code,
             squash(tty)[-900:])
        code, value, stdout, stderr = self.out('p1', 'share', '--with', 'quinn', '--network', self.team, '--from',
                                               'builtin/gh', '--operations', 'issue_list', '--name', 'nguided',
                                               '--bound', 'repo=acme/api', '--yes')
        need(code == 0 and (self.capability('nguided') or {}).get('bounds') == {'arguments': [{'repo': 'acme/api'}]},
             'without a terminal, --bound sets the bound of a guided share', code, stderr[-400:])
        for name in ('gguided', 'mguided', 'eguided', 'fguided', 'oguided', 'nguided'):
            if self.capability(name):
                self.remove(name)
        return ''

    def sources_tools(self, agent):
        status, view = self.hosts['p1'].call('GET', '/v1/sources')
        for a in view['agents']:
            if a['agent']['name'] == agent:
                return a['servers'][0]['tools']
        raise Failure(f'agent {agent} not in GET /v1/sources')

    # --- calls through gh capabilities -------------------------------------------------------------------------

    def check_gh_calls(self):
        self.needs('ghb', 'ghall')
        q1, p2 = self.hosts['q1'], self.hosts['p2']
        self.gh1.repo('acme/api', stdout='[{"number": 11}]')
        code, value, stdout, stderr = self.out('q1', 'call', 'pat/ghb', 'issue_list', '--repo', 'acme/api',
                                               '--network', self.team, '--wait', '30s')
        need(code == 0 and caps.dig(value, 'status', 'state') == 'succeeded' and
             text_of(value.get('result')) == '{"issues":[{"number": 11}]}', 'a call by policy from the CLI (call '
             'PERSON/CAPABILITY OP --repo R)', code, stdout[-600:], stderr[-300:])
        code, value, stdout, stderr = self.out('q1', 'call', 'pat/ghb', 'issue_list', '--repo', 'acme/infra',
                                               '--network', self.team, '--wait', '30s')
        text = out_of_bounds(self.B['ghb'], {'repo': 'acme/infra'})
        need(code == 1 and caps.dig(value, 'submit_state') == 'rejected' and (contains(value, text) or text in stderr),
             'out_of_bounds is a final rejected submission for call, with its text', code, stdout[-600:],
             stderr[-300:])
        code, value, stdout, stderr = self.out('p2', 'call', 'pat/ghall', 'repo_view', '--repo', 'acme/selfview',
                                               '--network', self.team, '--wait', '30s')
        need(code == 0 and caps.dig(value, 'status', 'state') == 'succeeded', 'a call by self from the CLI', code,
             stdout[-600:], stderr[-300:])
        code, value, stdout, stderr = self.out('p2', 'call', 'pat/builtin/gh', 'issue_list', '--repo', 'any/where',
                                               '--network', self.team, '--wait', '30s')
        need(code == 0 and caps.dig(value, 'status', 'state') == 'succeeded', 'a raw builtin/gh source call from a '
             'trusted host it is open to (PERSON/builtin/gh)', code, stdout[-600:], stderr[-300:])
        code, value, stdout, stderr = self.out('p2', 'call', f'{self.ids["p1"]}/builtin/gh', 'issue_list', '--repo',
                                               'any/where', '--network', self.team, '--wait', '30s')
        need(code == 0 and caps.dig(value, 'status', 'state') == 'succeeded', 'HOST_ID/builtin/gh', code,
             stdout[-600:], stderr[-300:])
        # The source listed to p2 as kind source.
        entries = self.listing('p2')
        need(entries.get('builtin/gh', {}).get('kind') == 'source' and entries['builtin/gh'].get('bounds') == {},
             'builtin/gh is listed to the person\'s trusted machine as kind source with bounds {}',
             entries.get('builtin/gh'))
        entries = self.listing('q1')
        need('builtin/gh' not in entries, 'the raw source never reaches another person', sorted(entries))
        # SOURCE resolution: bare gh resolves to the one built-in source; --arg refused for a built-in source.
        code, value, stderr = self.create('bare', 'gh', ['issue_list'], expect=None)
        need(code == 0 and (self.capability('bare') or {}).get('source') == {'agent': 'builtin', 'server': 'gh'},
             'a bare NAME resolves when exactly one source has it; the record keeps {agent: builtin, server}', code,
             stderr[-300:], self.capability('bare'))
        if self.capability('bare'):
            self.remove('bare')
        status, body = self.post_capability('witharg', 'builtin/gh', ['issue_list'], args=['x'])
        need(status == 400 and self.capability('witharg') is None, '--arg (args) is refused for a built-in source '
             'with 400', status, body)
        return ''

    # --- status ------------------------------------------------------------------------------------------------

    def check_status(self):
        counts = self.items().get('capabilities') or {}
        need(counts.get('sources') == 2, 'capabilities.sources counts built-in sources (srv/fx and builtin/gh)',
             counts)
        counts = self.items('p3').get('capabilities') or {}
        need(counts.get('sources') == len(self.builtin('p3')), 'p3: the built-in sources counted', counts)
        acts = self.hosts['p1'].cli('activity', '--after', '0', '--limit', '1000')
        kinds = {(a.get('kind'), a.get('subject_id')) for a in acts}
        need(('sources.discovered', 'builtin') in kinds, 'sources.discovered with subject builtin',
             sorted(k for k in kinds if k[0].startswith('sources')))
        return ''

    # --- compatibility -----------------------------------------------------------------------------------------

    def check_compatibility(self):
        need(not [n for n in self.setup_notes if n.startswith('o1')], 'setup: o1', self.setup_notes)
        self.synced('q1')
        code, value, stdout, stderr = self.out('q1', 'discover', 'pat', '--json', '--network', self.team)
        entries = [e for e in (value or {}).get('capabilities', []) if e['capability'] == 'oldcap']
        need(entries and entries[0]['host_id'] == self.ids['o1'] and entries[0]['bounds'] == {},
             'a version 18 receiver\'s capability is listed with bounds {} by discover', entries, stdout[-600:])
        status, body = self.submit('q1', 'oldcap', 'echo', {'text': 'old'}, receiver='o1')[1:]
        need(status == 200, 'a version 18 receiver still serves its capability', status, body)
        return ''

    # --- secrets -----------------------------------------------------------------------------------------------

    def check_secrets(self):
        """The captured tokens appear only in tool_values: never in outputs, logs, activity, or other tables."""
        tokens = [self.token_bob, self.token_own, *getattr(self, 'p3_tokens', {}).values()]
        leaks = []
        for where, text in self.exposed:
            for t in tokens:
                if t in text:
                    leaks.append(where)
        for name in ('p1', 'p3'):
            h = self.hosts[name]
            for path in h.state.rglob('*'):
                if path.is_file() and not path.name.startswith('host.db') and path.stat().st_size < 50_000_000:
                    data = path.read_bytes()
                    leaks += [str(path) for t in tokens if t.encode() in data and path.name != self.own_env.name]
            connection = sqlite3.connect(h.state / 'host.db')
            try:
                for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
                    if table == 'tool_values':
                        continue
                    for row in connection.execute(f'SELECT * FROM {table}'):
                        text = json.dumps(row, default=str)
                        leaks += [f'{name}:{table}' for t in tokens if t in text]
            finally:
                connection.close()
            if getattr(h, 'logs', None):
                h.logs.flush()
                h.logs.seek(0)
                logs = h.logs.read().decode(errors='replace')
                h.logs.seek(0, 2)
                leaks += [f'{name} daemon log' for t in tokens if t in logs]
            acts = json.dumps(h.cli('activity', '--after', '0', '--limit', '1000'))
            leaks += [f'{name} activity' for t in tokens if t in acts]
        need(not leaks, 'a token appears only in tool_values (definitions, listings, output, logs, activity)',
             sorted(set(leaks)))
        return ''

    def close(self):
        try:
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()


def run_pairing(coord_binary, cli_binary, daemon_binary, label, only=None, baseline18=None):
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-bounds-') as temporary:
        pairing = BoundsPairing(label, cli_binary, daemon_binary, coord_binary, Path(temporary), only, baseline18)
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [bounds and gh: setup]: {detail}', flush=True)
            if pairing.setup_notes:
                print(f'NOTE {label} bounds and gh setup: ' + ' | '.join(pairing.setup_notes), flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        for note in pairing.notes:
            print(f'NOTE {label} bounds and gh (not counted): {note}', flush=True)
        print(f'---- {label} bounds and gh: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} '
              f'sections passed in {time.monotonic() - started:.0f}s', flush=True)
        return [(f'bounds and gh: {name}', ok, detail) for name, ok, detail in pairing.results]


# --- migration to version 21 ---------------------------------------------------------------------------------

def check_migration(original, replacement, label, baseline=None):
    """Version 20 (or the version 18 baseline) to 21 (builtin_sources created; capabilities read bounds {}), and on to the
    current version; the next version refused.

    With `baseline` (a version 18 peerspan-host), the version 18 state is made by it; otherwise by `original`, taken
    back to version 20 by dropping builtin_sources."""
    from host_service import Host, SCHEMA_VERSION
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-bounds-migration-') as directory:
        host = Host(baseline or original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            host.stop()
            if baseline:
                need(db_rows(host, 'PRAGMA user_version')[0][0] == 18, 'the baseline is version 18')
            else:
                need(db_rows(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION, f'Database version '
                     f'{SCHEMA_VERSION}', label)
                connection = sqlite3.connect(host.state / 'host.db')
                try:
                    # Version 22 (remote MCP servers and OAuth) tables too, when the binaries have them.
                    from host_service import DEC_TABLES, OAUTH_TABLES
                    for table in (*DEC_TABLES, *OAUTH_TABLES):
                        connection.execute(f'DROP TABLE IF EXISTS {table}')
                    connection.execute('DROP TABLE builtin_sources')
                    connection.execute('PRAGMA user_version = 20')
                    connection.commit()
                finally:
                    connection.close()
            host.binary = str(replacement)
            need(host.start()['id'] == identity['id'], 'the identity survives migration')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION >= 21, 'migrated to version 21 (and on to '
                 'the current version)')
            columns = [r[1] for r in db_rows(host, 'PRAGMA table_info(builtin_sources)')]
            need(columns == ['name', 'record'], 'builtin_sources (name TEXT PRIMARY KEY, record TEXT NOT NULL)', columns)
            if baseline:
                from host_service import APPROVAL_TABLES, LINKING_TABLES
                tables = {r[0] for r in db_rows(host, "SELECT name FROM sqlite_master WHERE type = 'table'")}
                need(set(LINKING_TABLES) | set(APPROVAL_TABLES) <= tables, 'a version 18 database migrating to 21 '
                     'gains the version 19 and 20 tables on the way', sorted(set(LINKING_TABLES) |
                                                                            set(APPROVAL_TABLES) - tables))
            need(host.cli('agent', 'inspect', agent['id']) == agent, 'existing state preserved')
            status, view = host.call('GET', '/v1/sources')
            need(status == 200 and view.get('builtin') == [], 'no built-in sources after migration', status, view)
            host.stop()
            connection = sqlite3.connect(host.state / 'host.db')
            connection.execute(f'PRAGMA user_version = {SCHEMA_VERSION + 1}')
            connection.commit()
            connection.close()
            for binary in {str(original), str(replacement)}:
                result = subprocess.run([binary, '--state', str(host.state), 'run'], capture_output=True, timeout=10)
                need(result.returncode != 0, 'current binaries reject the next version', binary)
        finally:
            stop_all((host,))
    return label
