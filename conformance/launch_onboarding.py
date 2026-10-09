#!/usr/bin/env python3
"""Exercise team onboarding (milestone 7 slice 3) across CLI/daemon pairings.

Written from docs/launch-contract.md ("Slice 3: team onboarding") and the
contracts it builds on, independently of both implementations. Runs every
Go/Rust CLI and daemon pairing (all hosts of a pairing run that pairing's
daemon and are driven by its CLI), with one Go coordinator per pairing and real
ssh-agents. Each pairing reports these sections separately:

- root help: the new command set, and the moved commands still listed in
  `help advanced` (that they still run is checked where they are used);
- create: `network create NAME` with `--as` and its login-name default, the
  positional and `--name` forms, `--member` as an alias, and both name forms
  together refused;
- person keys: a key generated with no agent or an empty agent (files, modes,
  comment, `key.source` `new`), reused as `generated` even after an agent key
  appears, `agent` and `option` sources, two agent keys refused (no network,
  membership, or key file), refused commands creating no key, `--no-person`
  generating nothing, a second machine with a different key reporting the
  taken label then bound after copying the key, and renewal by a daemon with
  only the generated key (no item 10). Each host has its own HOME and
  XDG_CONFIG_HOME;
- invite and join: `invite` output and its `join` line run verbatim, a second
  machine of the same person bound without a new admission, and the moved
  `network invite`/`network join`;
- self access: messages, tasks, delegation, and artifacts between hosts of one
  person with no policy; with the coordinator stopped; blocks not applying;
  refusal for another person's host; the `self` citation by the owner CLI and
  adapter routes (and `authorization` on route records); ended by unbinding;
- allow: each principal form, SIZE parsing and bounds, default and flag
  settings, set semantics within a scope, other scopes untouched, flag
  dependencies, and `access allow` replacing several rules;
- deny: with and without `--agent`, `removed` counts, the zero-removal note
  with no new version, and group access still working; `access deny` still runs;
- `*` rules: a message and a task to any agent, named rules overriding `*` in
  both directions, `deny --agent '*'`, and `agent register` refusing `*`;
- block/unblock: by label, person ID, and host ID.

Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen) and capsule-peer-probe. Exits
non-zero listing every failed section.
"""
import argparse
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import socket
import sqlite3
import subprocess
import tempfile
import time
import traceback

from agent_adapter import adapter_call, credential
from artifacts import adapter_upload
from coordination import Coordinator, wait_for
from host_service import stop_all
from peer_messaging import fixture_context, request_id, set_probe, timestamp, wire
from persons import Agent, person_id, ssh_key
from policy import PolicyHost, crafted
from tasks import HANDOFF_KEYS, act, claim, task_id
from delegation import link_hash, sign, submit_raw

ROOT_COMMANDS = [
    'status', 'install', 'run',
    'network create', 'join', 'invite',
    'allow', 'deny', 'block', 'unblock',
    'network list', 'network members',
    'access show',
    'session setup', 'session start', 'session doctor',
    'message send', 'task submit',
]
MOVED_COMMANDS = ['network join', 'network invite', 'access allow', 'access deny']
INVITE_KEYS = {'network_id', 'member', 'invite_expires_at', 'token', 'join'}
ALLOW_KEYS = {'policy', 'principal', 'agent', 'actions', 'max_artifact_bytes'}
DEFAULT_ACTIONS = ('message.append', 'task.submit')
GIB = 1073741824
DAY = 86400
# The login name is the effective user ID's user name; USER and LOGNAME are set
# to something else so that the source matters.
LOGIN = pwd.getpwuid(os.geteuid()).pw_name
DEFAULT = object()


class Failure(AssertionError):
    pass


def need(condition, rule, *detail):
    """Assert one contract rule, naming it in the failure."""
    if not condition:
        raise Failure(f'{rule}: ' + ' | '.join(repr(d)[:600] for d in detail))


def parse_time(value):
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)', value)
    assert match, value
    fraction = (match.group(2) or '.0')[:7]
    zone = '+00:00' if match.group(3) == 'Z' else match.group(3)
    return datetime.fromisoformat(match.group(1) + fraction + zone)


def near(value, seconds, tolerance=120):
    offset = (parse_time(value) - datetime.now(timezone.utc)).total_seconds()
    return abs(offset - seconds) <= tolerance


class OnboardHost(PolicyHost):
    """A daemon of one implementation, driven by a CLI of either, choosing the CLI's ssh-agent per call."""

    def __init__(self, daemon_binary, cli_binary, state, home):
        super().__init__(daemon_binary, state, interval=1)
        self.cli_binary = str(cli_binary)
        self.sock = None  # the CLI's default ssh-agent socket
        # Each host has its own HOME and XDG_CONFIG_HOME, so no real configuration is touched.
        self.home, self.config = home / 'home', home / 'config'
        self.home.mkdir(parents=True)
        self.config.mkdir()

    def private_env(self):
        return {'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.config)}

    def daemon_env(self):
        env = super().daemon_env()
        env.update(self.private_env())
        return env

    @property
    def key_file(self):
        return self.config / 'capsule' / 'person_ed25519'

    def run(self, *args, sock=DEFAULT, env=None, argv=None):
        e = dict(os.environ)
        e.pop('SSH_AUTH_SOCK', None)
        chosen = self.sock if sock is DEFAULT else sock
        if chosen:
            e['SSH_AUTH_SOCK'] = chosen
        e['USER'] = e['LOGNAME'] = 'not-the-login-name'
        e.update(self.private_env())
        e.update(env or {})
        command = argv or [self.cli_binary, '--state', str(self.state), *args]
        return subprocess.run(command, capture_output=True, text=True, timeout=30, env=e)

    def cli(self, *args, success=True, sock=DEFAULT):
        result = self.run(*args, sock=sock)
        assert (result.returncode == 0) == success, (self.cli_binary, args, result.returncode, result.stdout[-800:],
                                                     result.stderr[-800:])
        return json.loads(result.stdout) if success else result.stderr


def version_of(value):
    """`allow`/`deny` print `policy`, the signed policy object."""
    need(isinstance(value, dict) and 'signature' in value, 'policy is the signed policy object', value)
    return value.get('version')


def rule_key(rule):
    return (tuple(sorted(rule['principals'])), tuple(rule['actions']), rule['max_message_bytes'],
            rule.get('max_artifact_bytes', 0), rule['allow_disconnected'])


def scope(policy, agent):
    """The rules of one agent scope, as a multiset of settings and principal sets."""
    return Counter(rule_key(r) for r in policy['rules'] if r['agent'] == agent)


def setting(principals, actions=DEFAULT_ACTIONS, files=0):
    return (tuple(sorted(principals)), tuple(actions), 65536, files, False)


class Pairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, root):
        self.label, self.cli_binary, self.daemon, self.root = label, cli_binary, daemon_binary, root
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results = []
        self.hosts = {}
        self.agents = {}
        self.keys = {}

    # --- infrastructure -----------------------------------------------------------------------------------

    def host(self, name, state=None):
        h = OnboardHost(self.daemon, self.cli_binary, state or (self.root / name), self.root / f'user-{name}')
        self.hosts[name] = h
        return h

    def section(self, name, function):
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:  # report and continue with the next section
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=4)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}',
              flush=True)
        return True

    def coordinator_flags(self):
        return ('--coordinator', self.coord.address, '--coordinator-key', self.coord_key)

    def policy(self, host=None, person=None):
        host = host or self.p1
        status, body = host.call('GET', f'/v1/networks/{self.net}/policy?person={person or self.pat}')
        return body if status == 200 else None

    def version(self, host=None, person=None):
        p = self.policy(host, person)
        return p['version'] if p else 0

    def synced(self, version, *hosts, person=None):
        for h in hosts:
            wait_for(lambda: self.version(h, person) >= version, timeout=30,
                     message=f'policy version {version} on {h.state.name}')

    def send(self, sender, peer, agent, content='hello'):
        out = sender.cli('message', 'send', '--peer', peer, '--agent', agent['id'], '--content', content)
        if out['state'] == 'unknown':
            rid = out['request']['request_id']

            def settled():
                o = sender.cli('message', 'retry', '--peer', peer, rid)
                return o if o['state'] != 'unknown' else None
            out = wait_for(settled, timeout=30, message='message outcome')
        return out

    def task(self, sender, peer, agent, *extra, text='work'):
        out = sender.cli('task', 'submit', '--peer', peer, '--agent', agent['id'], '--input', text, *extra)
        if out['submit_state'] == 'unknown':
            tid = out['request']['task_id']

            def settled():
                o = sender.cli('task', 'inspect', '--peer', peer, tid)
                return o if o['submit_state'] != 'unknown' else None
            out = wait_for(settled, timeout=40, message='task outcome')
        return out

    def expect(self, sender, peer, agent, state, rule, content='hello'):
        out = self.send(sender, peer, agent, content)
        need(out['state'] == state, rule, f'{sender.state.name} -> {agent["name"]} expected {state}', out)
        return out

    def allow(self, *args, host=None):
        before = self.version()
        out = (host or self.p1).cli('allow', *args, '--network', self.net)
        need(set(out) == ALLOW_KEYS, 'allow prints {policy, principal, agent, actions, max_artifact_bytes}', out)
        now = self.policy()
        need(now['version'] == before + 1, 'allow signs version + 1', before, now['version'])
        need(version_of(out['policy']) == now['version'], 'allow prints the signed policy', out['policy'])
        return out, now

    def refused_allow(self, *args, rule):
        before = self.version()
        result = self.p1.run('allow', *args, '--network', self.net)
        need(result.returncode != 0, rule, args, result.stdout)
        need(self.version() == before, f'{rule} (no new version)', args)

    def deny(self, *args):
        before = self.version()
        out = self.p1.cli('deny', *args, '--network', self.net)
        if out.get('removed') == 0:
            need(set(out) == {'policy', 'removed', 'note'}, 'deny with removed 0 prints {policy, removed} and note', out)
            need(isinstance(out['note'], str) and out['note'].strip(), 'deny: the zero-removal note', out)
            need(self.version() == before, 'deny with removed 0 signs no new version', before, self.version())
        else:
            need(set(out) == {'policy', 'removed'}, 'deny prints {policy, removed}', out)
            need(self.version() == before + 1, 'deny signs the next version', before, self.version())
            need(version_of(out['policy']) == before + 1, 'deny prints the signed policy', out['policy'])
        return out, self.policy()

    # --- sections ------------------------------------------------------------------------------------------

    def check_help(self):
        def help_of(*args):
            r = subprocess.run([self.cli_binary, *args], capture_output=True, text=True, timeout=10)
            need(r.returncode == 0, 'help exits 0', args, r.stderr)
            return r.stdout

        def commands(text):
            lines = text.splitlines()
            need('Commands:' in lines, 'help has a Commands: header (slice 1)', text)
            paths = []
            for line in lines[lines.index('Commands:') + 1:]:
                if not line.strip():
                    break
                paths.append(re.split(r' {2,}', line.strip())[0])
            return paths
        root = commands(help_of('--help'))
        need(root == ROOT_COMMANDS, 'Root help now lists, in order: status, install, run, network create, join, '
             'invite, allow, deny, block, unblock, network list, network members, access show, session setup/start/'
             'doctor, message send, task submit', root)
        advanced = commands(help_of('help', 'advanced'))
        missing = [c for c in ROOT_COMMANDS + MOVED_COMMANDS + ['access block', 'access unblock'] if c not in advanced]
        need(not missing, 'network join, network invite, access allow, and access deny move to help advanced, '
             'unchanged', missing)
        for path in MOVED_COMMANDS + ['join', 'invite', 'allow', 'deny', 'block', 'unblock']:
            need('--' in help_of(*path.split(), '--help'), 'each command keeps its own --help', path)

    def check_create(self):
        f = self.hosts['forms']
        a = f.cli('network', 'create', 'alpha', '--as', 'sol-a', *self.coordinator_flags())
        need(a['name'] == 'alpha' and a['member'] == 'sol-a', 'network create NAME positional; --as is the member label', a)
        b = f.cli('network', 'create', '--name', 'beta', '--member', 'sol-b', *self.coordinator_flags())
        need(b['name'] == 'beta' and b['member'] == 'sol-b', '--name still works; --member remains an alias for --as', b)
        c = f.cli('network', 'create', 'gamma', *self.coordinator_flags())
        need(c['name'] == 'gamma' and c['member'] == LOGIN, '--as defaults to the login name', c, LOGIN)
        for created, label in ((a, 'sol-a'), (b, 'sol-b'), (c, LOGIN)):
            need(created.get('person') and created['person']['admitted'] and created['person']['bound'],
                 'network create admits and binds the creator (a person key is found)', created)
            persons = f.cli('network', 'persons', created['id'])
            need([p['member'] for p in persons] == [label] and persons[0]['person_id'] == self.sol,
                 '--as is the person label', persons, label)
        result = f.run('network', 'create', 'delta', '--name', 'delta', *self.coordinator_flags())
        need(result.returncode != 0, 'network create: giving both NAME and --name is an error', result.stdout)
        names = sorted(n['name'] for n in f.cli('network', 'list'))
        need(names == ['alpha', 'beta', 'gamma'], 'a refused create leaves no network', names)

    def fingerprint(self, name):
        out = subprocess.run(['ssh-keygen', '-lf', str(self.keys[name][0]) + '.pub'], capture_output=True, text=True,
                             check=True, timeout=10).stdout.split()
        return out[1]

    def two_keys_refused(self, host, args, what):
        """Several agent identities and no generated key: refused before any request, leaving no key file."""
        result = host.run(*args, sock=self.agents['two'].socket)
        need(result.returncode != 0, f'Person keys: {what} with two agent keys and no generated key fails', result.stdout)
        for hint in ('--person-key', 'two-a', 'two-b', self.fingerprint('two-a'), self.fingerprint('two-b')):
            need(hint in result.stderr, f'Person keys: the error lists the keys\' comments and fingerprints and says to '
                 f'pass --person-key ({what})', hint, result.stderr)
        need(not host.key_file.exists() and not host.key_file.with_suffix('.pub').exists(),
             f'Person keys: a refused command creates no key ({what})', host.key_file)

    def registrations(self):
        try:
            with sqlite3.connect(self.coord.state / 'coord.db') as db:
                return db.execute('SELECT COUNT(*) FROM registrations').fetchone()[0]
        except sqlite3.Error:
            return None

    def key_of(self, out, source, rule, path=DEFAULT):
        """The response's person.key, with the expected source and path."""
        person = out.get('person') or {}
        key = person.get('key')
        need(isinstance(key, dict) and set(key) == {'source', 'public_key', 'path'},
             'Command output: person gains key {source, public_key, path}', person)
        need(key['source'] == source, f'{rule}: key.source {source}', key)
        if path is not DEFAULT:
            got = key['path'] and str(Path(key['path']).resolve())
            want = path and str(Path(path).resolve())
            need(got == want, f'{rule}: key.path is the file, or null for an agent key', key, path)
        return key

    def generated(self, host, out, label, rule):
        """A newly generated key: files, modes, comment, output, and next."""
        key = self.key_of(out, 'new', rule, host.key_file)
        private, public = host.key_file, host.key_file.with_name('person_ed25519.pub')
        need(private.exists() and public.exists(), 'The generated key: person_ed25519 and person_ed25519.pub', private)
        modes = (private.stat().st_mode & 0o777, public.stat().st_mode & 0o777, private.parent.stat().st_mode & 0o777)
        need(modes == (0o600, 0o644, 0o700), 'The generated key: modes 0600 and 0644 in a 0700 directory',
             [oct(m) for m in modes])
        fields = public.read_text().split(maxsplit=2)
        need(fields[0] == 'ssh-ed25519', 'The generated key is ssh-ed25519', fields)
        if label is not None:
            # suite-questions.md Q11: HOSTNAME as the system host name.
            need(len(fields) == 3 and fields[2].strip() == f'capsule {label}@{socket.gethostname()}',
                 'The generated key: comment capsule LABEL@HOSTNAME', fields)
        derived = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', str(private)], capture_output=True, text=True,
                                 timeout=10)
        need(derived.returncode == 0 and derived.stdout.split()[:2] == fields[:2],
             'The generated key is an unencrypted OpenSSH private key matching its public key', derived.stderr)
        raw = base64.b64encode(base64.b64decode(fields[1])[-32:]).decode()
        # suite-questions.md Q10: public_key as canonical Base64 or an ssh-ed25519 line.
        need(key['public_key'] == raw, 'key.public_key uses the person_public_key encoding', key, fields)
        need(out['person'].get('person_id') == person_id(raw), 'the person is the generated key', out['person'])
        need(out['person'].get('next'), 'with source new, next says to back up and copy the key', out['person'])
        return raw

    def check_person_keys_create(self):
        x, g1 = self.hosts['x'], self.hosts['g1']
        flags = self.coordinator_flags()
        # Generation with no agent; reuse on the next command, also once an agent key appears.
        out = g1.cli('network', 'create', 'gen1', '--as', 'gena', *flags, sock=None)
        need(out['person']['admitted'] and out['person']['bound'], 'create with a generated key admits and binds', out)
        raw = self.generated(g1, out, 'gena', 'Person keys: generation with no agent')
        before = g1.key_file.read_bytes()
        again = g1.cli('network', 'create', 'gen1b', '--as', 'gena', *flags, sock=None)
        key = self.key_of(again, 'generated', 'Person keys: the next command reuses the generated key', g1.key_file)
        need(key['public_key'] == raw, 'reuse: the same key', key, raw)
        later = g1.cli('network', 'create', 'gen1c', '--as', 'gena', *flags, sock=self.agents['zed'].socket)
        key = self.key_of(later, 'generated', 'Person keys: an existing generated key wins over an agent key',
                          g1.key_file)
        need(key['public_key'] == raw and later['person']['person_id'] == person_id(raw),
             'Person keys: identity unchanged after an agent key appears', later['person'])
        need(g1.key_file.read_bytes() == before, 'The generated key is never overwritten', g1.key_file)

        # The single agent key, and --person-key.
        f = self.hosts['forms']
        out = f.cli('network', 'create', 'agentkey', '--as', 'sol', *flags)
        self.key_of(out, 'agent', 'Person keys: the only ssh-ed25519 identity in ssh-agent', None)
        need(not f.key_file.exists(), 'Person keys: an agent key generates nothing', f.key_file)
        out = x.cli('network', 'create', 'optionkey', '--as', 'sol', '--person-key', str(self.keys['sol'][0]), *flags,
                    sock=self.agents['two'].socket)
        self.key_of(out, 'option', 'Person keys: --person-key', self.keys['sol'][0])
        need(out['person']['person_id'] == self.sol, '--person-key selects that person', out['person'])

        # Two agent keys and no generated key: refused, leaving no network and no key.
        before = self.registrations()
        known = {n['id'] for n in x.cli('network', 'list')}
        self.two_keys_refused(x, ('network', 'create', 'refused', '--as', 'xavier', *flags), 'network create')
        need({n['id'] for n in x.cli('network', 'list')} == known, 'Person keys: a refused create leaves no network')
        need(self.registrations() == before, 'Person keys: refused before any request (no registration)',
             before, self.registrations())
        # Refused for other reasons: no key either, even where one would be generated.
        result = x.run('network', 'create', 'both', '--name', 'both', *flags, sock=None)
        need(result.returncode != 0 and not x.key_file.exists(), 'Person keys: a refused command creates no key',
             result.stdout, x.key_file)
        result = x.run('join', 'capsule-member-invite-v1.bm90LWEtdG9rZW4', sock=None)
        need(result.returncode != 0 and not x.key_file.exists(), 'Person keys: a refused join creates no key',
             result.stdout, x.key_file)
        # --no-person: host-only, generating nothing.
        solo = x.cli('network', 'create', 'solo', '--as', 'xavier', '--no-person', *flags, sock=None)
        need(solo['name'] == 'solo' and not x.key_file.exists(), '--no-person generates nothing', solo)
        x.cli('network', 'sync', solo['id'])
        need(x.cli('network', 'persons', solo['id']) == [], '--no-person keeps host-only create: no person', solo)
        [me] = x.cli('network', 'members', solo['id'])
        need(me['person_id'] is None, '--no-person keeps host-only create: the host is not bound', me)

    def check_person_keys_join(self):
        x, g2, g4 = self.hosts['x'], self.hosts['g2'], self.hosts['g4']
        # Two agent keys: join and network join refused, leaving no membership and no key.
        token = self.p1.cli('network', 'invite', '--network', self.net, '--member', 'xavier')['token']
        self.two_keys_refused(x, ('join', token), 'join')
        self.two_keys_refused(x, ('network', 'join', '--token', token), 'network join')
        need(self.net not in {n['id'] for n in x.cli('network', 'list')}, 'Person keys: a refused join leaves no '
             'membership')
        self.p1.cli('network', 'sync', self.net)
        need(self.ids['x'] not in {m['host_id'] for m in self.p1.cli('network', 'members', self.net)},
             'Person keys: a refused join leaves no membership at the coordinator')
        joined = x.cli('join', token, '--no-person', sock=None)
        need(joined['id'] == self.net and not x.key_file.exists(),
             '--no-person joins host-only and generates nothing (the refused token was unused)', joined)
        x.cli('network', 'sync', self.net)
        mine = next(m for m in x.cli('network', 'members', self.net) if m['host_id'] == self.ids['x'])
        need(mine['person_id'] is None, '--no-person keeps host-only join', mine)

        # Generation with an empty agent, through join.
        token = self.p1.cli('network', 'invite', '--network', self.net, '--member', 'gen2')['token']
        joined = g2.cli('join', token, sock=self.agents['empty'].socket)
        raw = self.generated(g2, joined, None, 'Person keys: generation with an empty agent (join)')
        need(joined['person']['admitted'] and joined['person']['bound'], 'join with a generated key binds', joined)
        self.gen2, self.gen2_raw = person_id(raw), raw

        # A second machine with a different key: the label is taken; bound after copying the key.
        token = self.p1.cli('network', 'invite', '--network', self.net, '--member', 'gen2')['token']
        joined = g4.cli('join', token, sock=None)
        self.key_of(joined, 'new', 'Second machines: a machine without the key generates a different one')
        person = joined['person']
        need(joined['id'] == self.net and not person['bound'] and not person['admitted'] and person['skipped']
             and person['next'], 'Second machines: the person part reports the member label as taken, and the host '
             'joins without a person', joined)
        g4.key_file.write_bytes(g2.key_file.read_bytes())
        g4.key_file.with_name('person_ed25519.pub').write_bytes(g2.key_file.with_name('person_ed25519.pub').read_bytes())
        # Every person-signing command finds the generated key (steps 1 to 3), with no agent and no --person-key.
        bound = g4.cli('network', 'bind', '--network', self.net, sock=None)
        need(bound['person_id'] == self.gen2, 'Second machines: bound after copying the key', bound)
        out = g2.cli('allow', 'network', '--agent', 'gen-agent', '--network', self.net, sock=None)
        need(out['policy']['person_public_key'] == self.gen2_raw and out['policy']['version'] == 1,
             'Person keys: allow signs with the generated key (steps 1 to 3)', out)

    def check_renewal(self):
        """Policy renewal by a daemon with only the generated key, and no item 10."""
        g2 = self.hosts['g2']
        g2.stop()
        g2.start()  # reads the generated key at start; no agent
        now = datetime.now(timezone.utc)
        base = {'network_id': self.net, 'person_public_key': self.gen2_raw,
                'rules': [{'agent': 'renewed', 'principals': ['network'], 'actions': ['message.append'],
                           'max_message_bytes': 100, 'allow_disconnected': False}]}
        ending = crafted(base, 2, now - timedelta(hours=23), now + timedelta(hours=1), g2.key_file, self.root)
        status, body = g2.call('POST', f'/v1/networks/{self.net}/policy', {'policy': ending})
        need(status == 201, 'renewal setup: a crafted policy near its end', status, body)

        def renewed():
            s, p = g2.call('GET', f'/v1/networks/{self.net}/policy?person={self.gen2}')
            return p if s == 200 and p['version'] >= 3 else None
        try:
            policy = wait_for(renewed, timeout=20, message='renewal with the generated key')
        except AssertionError:
            raise Failure('Renewal with a generated key: the daemon renews with the file when it holds the bound '
                          'person\'s key and no agent does')
        need(policy['rules'] == ending['rules'], 'a renewal keeps the rules', policy)
        status, value = g2.call('GET', '/v1/status')
        kinds = [i['kind'] for i in value.get('attention', [])]
        need(status == 200 and 'person_agent_unreachable' not in kinds,
             'Status item 10 is not raised when the key file holds the bound person\'s key', kinds)

    def member_invite(self, label, failures):
        """`invite LABEL`, falling back to `network invite` so later sections can run."""
        try:
            out = self.p1.cli('invite', label)
            return out['token'], out
        except Exception as error:
            failures.append(f'invite {label}: {error}')
            return self.p1.cli('network', 'invite', '--network', self.net, '--member', label)['token'], None

    def joined(self, host, token, failures, *extra, sock=DEFAULT, argv=None, env=None):
        try:
            if argv:
                result = host.run(argv=argv, env=env, sock=sock)
                assert result.returncode == 0, (argv, result.stdout, result.stderr)
                return json.loads(result.stdout)
            return host.cli('join', token, *extra, sock=sock)
        except Exception as error:
            failures.append(f'join on {host.state.name}: {error}')
            return host.cli('network', 'join', '--token', token, *extra, sock=sock)

    def check_invite_and_join(self):
        """Joins every host; soft failures fall back to the advanced commands, and are reported at the end."""
        failures = []
        token, out = self.member_invite('quinn', failures)
        if out:
            try:
                need(set(out) == INVITE_KEYS, 'invite prints {network_id, member, invite_expires_at, token, join}', out)
                need(out['network_id'] == self.net and out['member'] == 'quinn', 'invite issues a member invite', out)
                need(out['token'].startswith('capsule-member-invite-v1.'), 'invite issues a member invite', out)
                need(near(out['invite_expires_at'], 7 * DAY), 'invite defaults to 7 days', out)
                need(out['join'] == f'capsule join {out["token"]}', 'join is the string `capsule join TOKEN`', out)
                timed = self.p1.cli('invite', 'later', '--expires-in', '2h')
                need(near(timed['invite_expires_at'], 7200, 60), 'invite --expires-in', timed)
            except Failure as error:
                failures.append(str(error))
        q = self.hosts['quinn']
        if out:
            # The join line, run verbatim: `capsule` on PATH, and quinn's state at the default location.
            argv = shlex.split(out['join'])
            env = {'PATH': f"{self.root / 'links'}:{os.environ.get('PATH', '')}",
                   'XDG_STATE_HOME': str(self.root / 'xdg-quinn')}
            joined = self.joined(q, token, failures, sock=self.agents['quinn'].socket, argv=argv, env=env)
        else:
            joined = self.joined(q, token, failures, sock=self.agents['quinn'].socket)
        try:
            need(joined['id'] == self.net and joined['person']['bound'] and joined['person']['admitted'],
                 'join TOKEN: same as network join --token, with the person admitted and bound', joined)
        except Failure as error:
            failures.append(str(error))

        # --person-key, without an agent.
        token, _ = self.member_invite('rhea', failures)
        joined = self.joined(self.hosts['rhea'], token, failures, '--person-key', str(self.keys['rhea'][0]), sock=None)
        try:
            need(joined['person']['bound'] and joined['person']['person_id'] == self.rhea,
                 'join uses --person-key if given', joined)
            self.key_of(joined, 'option', 'Person keys: --person-key (join)', self.keys['rhea'][0])
        except Failure as error:
            failures.append(str(error))

        # A second machine of pat: bound without a new admission.
        token, _ = self.member_invite('pat', failures)
        joined = self.joined(self.p2, token, failures, sock=self.agents['pat'].socket)
        try:
            person = joined['person']
            need(person['person_id'] == self.pat and person['admitted'] and person['bound'] and person['skipped'] is None,
                 'join: a person already admitted with this key is bound without a new admission', joined)
            self.key_of(joined, 'agent', 'Person keys: the single agent key (join)', None)
        except Failure as error:
            failures.append(str(error))

        # The moved commands still run.
        try:
            token = self.p1.cli('network', 'invite', '--member', 'pat')['token']
            joined = self.p3.cli('network', 'join', '--token', token, sock=self.agents['pat'].socket)
            need(joined['person']['bound'], 'moved commands still run: network invite and network join', joined)
        except Exception as error:
            failures.append(f'moved network invite/join: {error}')
            raise

        # Everyone sees the expected bindings.
        expected = {self.ids['p1']: self.pat, self.ids['p2']: self.pat, self.ids['p3']: self.pat,
                    self.ids['quinn']: self.quinn, self.ids['rhea']: self.rhea}

        def bindings():
            for name in ('p1', 'p2', 'p3', 'quinn', 'rhea'):
                self.hosts[name].cli('network', 'sync', self.net)
            seen = {m['host_id']: m['person_id'] for m in self.p1.cli('network', 'members', self.net)}
            return seen if seen == expected else None
        try:
            wait_for(bindings, timeout=20, message='bindings of every joined host')
        except AssertionError:
            failures.append('every join binds as expected: ' +
                            repr({m['host_id']: m['person_id'] for m in self.p1.cli('network', 'members', self.net)}))
        persons = {p['person_id']: p for p in self.p1.cli('network', 'persons', self.net)}
        if set(persons) != {self.pat, self.quinn, self.rhea}:
            failures.append(f'only the joined persons are admitted: {sorted(persons)}')
        elif sorted(persons[self.pat]['hosts']) != sorted([self.ids['p1'], self.ids['p2'], self.ids['p3']]):
            failures.append(f'second machine bound to the same person: {persons[self.pat]}')
        need(not failures, 'Invite and join', *failures)

    def check_self_access(self):
        p1, p2, p3, q = self.p1, self.p2, self.p3, self.hosts['quinn']
        P1, P2, P3 = self.ids['p1'], self.ids['p2'], self.ids['p3']
        rule = 'Self access'
        need(self.policy() is None, f'{rule}: pat has no policy for these cases', self.policy())
        cite = {'person_id': self.pat}

        # Messages, both ways, citing self.
        out = self.expect(p1, P2, self.agent['helper'], 'accepted', f'{rule}: a message between hosts of one person')
        request = out['request']
        need(request.get('self') == cite and request.get('grant_id') is None and request.get('policy') is None,
             'What senders cite: owner sends cite self {person_id}', request)
        received = p2.cli('message', 'list')[-1]['request']
        need(received.get('self') == cite and 'grant_id' not in received and 'policy' not in received,
             'Wire: exactly one of grant_id, policy, or self', received)
        self.expect(p2, P1, self.agent['reviewer'], 'accepted', f'{rule}: the other direction')

        # The wire form, from a host of pat and from quinn's host.
        def body(**auth):
            return {'request_id': request_id(), 'target_agent_id': self.agent['reviewer']['id'], 'deadline': timestamp(),
                    'content': 'wire', **auth}
        status, _ = wire(p1, fixture_context(p3), 'POST', '/peer/v1/messages', body(self=cite))
        need(status == 200, 'Wire: self {person_id} from a sibling host is authorized', status)
        status, _ = wire(p1, fixture_context(p3), 'POST', '/peer/v1/messages',
                         body(self=cite, policy={'person_id': self.pat, 'version': 1}))
        need(status == 400, 'Wire: exactly one of grant_id, policy, or self', status)
        for claimed in (self.quinn, self.pat):
            status, _ = wire(p1, fixture_context(q), 'POST', '/peer/v1/messages', body(self={'person_id': claimed}))
            need(status == 403, 'Wire: 403 when either host is not bound to that person (another person\'s host)',
                 claimed, status)
            task_body = {'task_id': task_id(), 'target_agent_id': self.agent['reviewer']['id'], 'deadline': timestamp(),
                         'input': 'wire', 'self': {'person_id': claimed}}
            status, _ = wire(p1, fixture_context(q), 'POST', '/peer/v1/tasks', task_body)
            need(status == 403, 'Wire: a task from another person\'s host citing self is refused', claimed, status)

        # A task with an input artifact and a delegation chain, forwarded to the third host.
        data = b'self access input ' * 64
        path = self.root / 'input.txt'
        path.write_bytes(data)
        t0 = self.task(p1, P2, self.agent['helper'], '--from-agent', self.agent['origin']['id'],
                       '--delegation-depth', '1', '--artifact', str(path))
        need(t0['submit_state'] == 'accepted', f'{rule}: a task with an artifact (bound 1 GiB) and a chain', t0)
        need(t0['request'].get('self') == cite and t0['request'].get('grant_id') is None,
             'What senders cite: owner task submissions cite self', t0['request'])
        tid = t0['request']['task_id']
        token = self.tokens['helper']
        handoff = wait_for(lambda: claim(p2, token), timeout=30, message='self task handoff after its input is stored')
        need(handoff['task']['task_id'] == tid and set(handoff) == HANDOFF_KEYS, f'{rule}: handoff', handoff)
        need(handoff['task'].get('self') == cite, 'the handoff task is the request as received', handoff['task'])
        need(len(handoff['task'].get('artifacts') or []) == 1, f'{rule}: input artifacts', handoff['task'])
        need(handoff['delegable'] is True, 'Self access scope: delegable true', handoff)
        act(p2, token, tid, 'accept')
        status, t1 = p2.call('POST', '/v1/tasks', {'peer_host_id': P3, 'target_agent_id': self.agent['extra']['id'],
                                                   'input': 'part', 'parent': {'sender_host_id': P1, 'task_id': tid}})
        need(status == 200, f'{rule}: a delegation forwarded between hosts of one person', status, t1)
        if t1['submit_state'] == 'unknown':
            t1 = wait_for(lambda: (lambda o: o if o['submit_state'] != 'unknown' else None)(
                p2.cli('task', 'inspect', '--peer', P3, t1['request']['task_id'])), timeout=40, message='forward')
        need(t1['submit_state'] == 'accepted' and len(t1['delegation']) == 2,
             'Rechecks: wherever a policy can authorize a chain\'s originator, self access can too', t1)
        need(t1['request'].get('self') == cite, 'What senders cite: delegations without --grant cite self',
             t1['request'])
        child = wait_for(lambda: claim(p3, self.tokens['extra']), timeout=20, message='forwarded handoff')
        need(child['task']['task_id'] == t1['request']['task_id'], f'{rule}: forwarded handoff', child)
        act(p3, self.tokens['extra'], child['task']['task_id'], 'accept')
        act(p3, self.tokens['extra'], child['task']['task_id'], 'complete', {'status': 'succeeded', 'output': 'part done'})
        entry = adapter_upload(p2, token, 'result.txt', b'self access result')
        act(p2, token, tid, 'complete', {'status': 'succeeded', 'output': 'done', 'artifacts': [entry]})

        def finished():
            o = p1.cli('task', 'inspect', '--peer', P2, tid)
            results = [a for a in o['artifacts'] if a['direction'] == 'result']
            done = o['status'] and o['status']['state'] == 'succeeded' and results and results[0]['state'] == 'stored'
            return o if done else None
        wait_for(finished, timeout=90, message='self task succeeded with its result fetched')

        # Blocks do not apply.
        made = [p2.cli('access', 'block', '--host', P1), p2.cli('access', 'block', '--person', self.pat)]
        self.expect(p1, P2, self.agent['helper'], 'accepted', 'Self access: blocks do not apply (message)')
        blocked_task = self.task(p1, P2, self.agent['helper'], text='blocked task')
        need(blocked_task['submit_state'] == 'accepted', 'Self access: blocks do not apply (task)', blocked_task)
        for entry in made:
            p2.cli('access', 'unblock', f"--{entry['kind']}", entry['subject'])

        # Adapter routes record and use the citation.
        secret = self.secrets['origin']
        adapter = secret['adapter']['id']

        def route(name, peer, agent, *extra):
            return p1.cli('adapter', 'route', 'add', '--adapter', adapter, '--name', name, '--peer', peer,
                          '--agent', agent['id'], '--expires-in', '10m', *extra)
        r = route('to-helper', P2, self.agent['helper'])
        need(r.get('authorization') == 'self', 'A route created this way records authorization "self"', r)
        rid = request_id()
        status, sent = adapter_call(p1, secret['token'], 'POST', '/adapter/v1/send',
                                    {'destination': 'to-helper', 'request_id': rid, 'content': 'via route'})
        need(status == 200, 'adapter send through a self route', status, sent)

        def route_sent():
            s, v = adapter_call(p1, secret['token'], 'GET', f'/adapter/v1/sends/{rid}')
            return v if s == 200 and v['state'] != 'unknown' else None
        settled = wait_for(route_sent, timeout=30, message='route send outcome')
        need(settled['state'] == 'accepted', 'Self access: a message through a self route', settled)
        outbound = p1.cli('message', 'inspect', '--peer', P2, rid)
        need(outbound['request'].get('self') == cite, 'What senders cite: adapter routes cite self', outbound['request'])
        r = route('task-helper', P2, self.agent['helper'], '--action', 'task.submit')
        need(r.get('authorization') == 'self', 'a task.submit route to a sibling records authorization "self"', r)
        status, record = adapter_call(p1, secret['token'], 'POST', '/adapter/v1/delegations',
                                      {'destination': 'task-helper', 'task_id': task_id(), 'input': 'via route'})
        need(status == 200 and record['request'].get('self') == cite, 'a task through a self route cites self',
             status, record)
        g = p2.cli('grant', 'create', '--peer', P1, '--agent', self.agent['helper']['id'], '--expires-in', '1h',
                   '--allow-disconnected')
        r = route('by-grant', P2, self.agent['helper'], '--grant', g['id'])
        need(r.get('authorization') == 'grant', 'Route records always show authorization: grant', r)
        # Another person's host: the target owner's policy, as before.
        q.cli('access', 'allow', '--network', self.net, '--agent', 'qagent', '--principal', 'network',
              '--allow-disconnected', sock=self.agents['quinn'].socket)
        self.synced(1, p1, person=self.quinn)
        r = route('to-quinn', self.ids['quinn'], self.agent['qagent'])
        need(r.get('authorization') == 'policy', 'Route records always show authorization: policy', r)
        out = self.expect(p1, self.ids['quinn'], self.agent['qagent'], 'accepted', 'owner send to another person')
        need(out['request'].get('policy', {}).get('person_id') == self.quinn and out['request'].get('self') is None,
             'What senders cite: otherwise the target owner\'s policy, as before', out['request'])

        # The coordinator stopped: self access is allow_disconnected.
        self.coord.stop()
        try:
            def stale(host):
                status, networks = host.call('GET', '/v1/networks')
                n = next(n for n in networks if n['id'] == self.net)
                last = n['last_sync_at']
                return last and (datetime.now(timezone.utc) - parse_time(last)).total_seconds() > 4
            for h in (p1, p2):
                wait_for(lambda: stale(h), timeout=20, message='syncs older than three coordination intervals')
            self.expect(p1, P2, self.agent['helper'], 'accepted', 'Self access works while the coordinator is stopped')
            offline = self.task(p1, P2, self.agent['helper'], text='offline')
            need(offline['submit_state'] == 'accepted', 'Self access: a task while the coordinator is stopped', offline)
        finally:
            self.coord.start()
        for h in (p1, p2, p3):
            wait_for(lambda: h.cli('network', 'sync', self.net)['last_sync_error'] is None, timeout=20,
                     message='sync after the coordinator restarts')

        # In a chain of two or more links, self names the originator's person and is checked for the originator.
        def chained(originator_host, originator, cite_person):
            deadline = timestamp(1200)
            first = sign(originator_host, self.net, 0, 'none', originator, self.ids['quinn'], task_id(),
                         self.agent['origin']['id'], ['network'], timestamp(1800), 1)
            second = sign(q, self.net, 1, link_hash(first), self.ids['quinn'], P2, task_id(),
                          self.agent['origin']['id'], ['network'], deadline, 0)
            request = {'task_id': second['task_id'], 'target_agent_id': self.agent['helper']['id'],
                       'deadline': deadline, 'input': 'chained', 'origin': {'agent_id': self.agent['qagent']['id']},
                       'self': {'person_id': cite_person}}
            return submit_raw(q, p2, request, [first, second])[0]
        status = chained(p1, P1, self.pat)
        need(status == 200, 'Wire: in a chain, self.person_id is the originator host\'s bound person', status)
        status = chained(p1, P1, self.quinn)
        need(status == 403, 'Wire: in a chain, self naming the sender\'s person is refused', status)
        status = chained(self.hosts['rhea'], self.ids['rhea'], self.pat)
        need(status == 403, 'Wire: in a chain, the self check applies to the originator host', status)
        # Drain the accepted chained task from helper's queue.
        leftover = claim(p2, token)
        if leftover:
            act(p2, token, leftover['task']['task_id'], 'reject', {'reason': 'chained check'})

        # Ended by unbinding the third host.
        p1.cli('network', 'unbind', '--network', self.net, '--host', P3, sock=self.agents['pat'].socket)
        status, _ = wire(p1, fixture_context(p3), 'POST', '/peer/v1/messages', body(self=cite))
        need(status == 403, 'Self access is ended by unbinding a host (at the unbinding host)', status)
        result = p1.run('message', 'send', '--peer', P3, '--agent', self.agent['extra']['id'], '--content', 'gone')
        need(result.returncode != 0 or json.loads(result.stdout)['state'] == 'rejected',
             'after unbinding, a send to the unbound host no longer cites self', result.stdout)

        def refused_at_p3():
            b = {'request_id': request_id(), 'target_agent_id': self.agent['extra']['id'], 'deadline': timestamp(),
                 'content': 'after unbind', 'self': cite}
            p3.cli('network', 'sync', self.net)
            return wire(p3, fixture_context(p1), 'POST', '/peer/v1/messages', b)[0] == 403
        wait_for(refused_at_p3, timeout=20, message='self access refused at the unbound host')

    def check_allow(self):
        p1 = self.p1
        self.p1.cli('network', 'group', 'set', '--network', self.net, '--group', 'backend', '--person', 'rhea')
        q, r = 'person:' + self.quinn, 'person:' + self.rhea
        # Each principal form.
        forms = [('everyone', 'f-everyone', 'network'), ('network', 'f-network', 'network'),
                 ('group:backend', 'f-group', 'group:backend'), ('person:quinn', 'f-person-label', q),
                 (f'person:{self.quinn}', 'f-person-id', q), ('quinn', 'f-bare-label', q),
                 (self.rhea, 'f-bare-id', r),
                 (f"agent:{self.ids['quinn']}/{self.agent['qagent']['id']}", 'f-agent',
                  f"agent:{self.ids['quinn']}/{self.agent['qagent']['id']}")]
        for given, agent, stored in forms:
            out, policy = self.allow(given, '--agent', agent)
            need(scope(policy, agent) == Counter([setting([stored])]), f'Principals: {given} means {stored}',
                 policy['rules'])
            need(out['agent'] == agent and out['principal'] == stored, 'allow prints the resolved principal and agent', out)
        self.refused_allow('nobody', '--agent', 'f-x', rule='Principals: a label matching no current person is an error')
        self.refused_allow('person:nobody', '--agent', 'f-x', rule='Principals: a label matching no person is an error')

        # Default and flag-set settings; 7 days.
        out, policy = self.allow('network', '--agent', 'd-default')
        need(out['actions'] == list(DEFAULT_ACTIONS) and out['max_artifact_bytes'] == 0,
             'allow settings: message.append then task.submit; max_artifact_bytes 0', out)
        [rule] = [x for x in policy['rules'] if x['agent'] == 'd-default']
        need(rule['actions'] == list(DEFAULT_ACTIONS) and rule['max_message_bytes'] == 65536
             and rule.get('max_artifact_bytes', 0) == 0 and rule['allow_disconnected'] is False,
             'allow settings: max_message_bytes 65,536, max_artifact_bytes 0, allow_disconnected false', rule)
        span = (parse_time(policy['valid_until']) - parse_time(policy['issued_at'])).total_seconds()
        need(span == 7 * DAY, 'allow signs version + 1, valid for 7 days', policy['issued_at'], policy['valid_until'])
        out, policy = self.allow('network', '--agent', 'd-no-tasks', '--no-tasks')
        need(out['actions'] == ['message.append'] and scope(policy, 'd-no-tasks') == Counter(
            [setting(['network'], ['message.append'])]), 'allow --no-tasks: message.append only', policy['rules'])
        out, policy = self.allow('network', '--agent', 'd-delegate', '--delegate', '--files', '1K')
        expected = ['message.append', 'task.submit', 'task.delegate']
        need(out['actions'] == expected and out['max_artifact_bytes'] == 1024 and scope(policy, 'd-delegate') == Counter(
            [setting(['network'], expected, 1024)]), 'allow --delegate adds task.delegate; --files sets the bound',
             out, policy['rules'])
        self.refused_allow('network', '--agent', 'd-bad', '--delegate', '--no-tasks',
                           rule='--delegate requires tasks')
        self.refused_allow('network', '--agent', 'd-bad', '--files', '1K', '--no-tasks', rule='--files requires tasks')

        # SIZE parsing and bounds.
        for given, size in (('1', 1), ('512', 512), ('1K', 1024), ('3M', 3 * 1048576), ('1G', GIB), (str(GIB), GIB)):
            out, policy = self.allow('network', '--agent', 'size', '--files', given)
            need(out['max_artifact_bytes'] == size and scope(policy, 'size') == Counter(
                [setting(['network'], DEFAULT_ACTIONS, size)]), f'SIZE {given} is {size} bytes (powers of 1024)',
                 out, policy['rules'])
        for given in ('0', str(GIB + 1), '2G', '1048577K', '1T', 'abc', '-1', ''):
            self.refused_allow('network', '--agent', 'size', '--files', given,
                               rule=f'SIZE must be from 1 to 1,073,741,824 bytes with suffix K, M, or G ({given!r})')

        # Set semantics in one scope, leaving other scopes alone.
        self.allow('quinn', '--agent', 'sem')
        _, policy = self.allow('rhea', '--agent', 'sem')
        need(scope(policy, 'sem') == Counter([setting([q, r])]),
             'allow adds the principal to the first rule of that scope with identical settings', policy['rules'])
        _, policy = self.allow('quinn', '--agent', 'sem', '--no-tasks')
        need(scope(policy, 'sem') == Counter([setting([r]), setting([q], ['message.append'])]),
             'allow removes the principal from every rule of the scope, then appends a new rule', policy['rules'])
        _, policy = self.allow('quinn', '--agent', 'other')
        need(scope(policy, 'sem') == Counter([setting([r]), setting([q], ['message.append'])])
             and scope(policy, 'other') == Counter([setting([q])]), 'allow leaves other scopes alone', policy['rules'])
        _, policy = self.allow('rhea', '--agent', 'sem', '--no-tasks')
        need(scope(policy, 'sem') == Counter([setting([q, r], ['message.append'])]),
             'allow moves a principal into an identical rule and drops rules left without principals', policy['rules'])
        _, policy = self.allow('quinn', '--agent', 'sem')
        moved = Counter([setting([r], ['message.append']), setting([q])])
        need(scope(policy, 'sem') == moved and scope(policy, 'other') == Counter([setting([q])]),
             'allow moves a principal between rules of a scope', policy['rules'])
        before = policy['rules']
        _, policy = self.allow('quinn', '--agent', 'sem')
        need(scope(policy, 'sem') == moved and Counter(map(rule_key, policy['rules'])) == Counter(map(rule_key, before)),
             'allowing a principal that already has these settings still signs a new version, unchanged', policy)

        # access allow and access deny still run; several rules become one.
        v = self.version()
        replaced = p1.cli('access', 'allow', '--network', self.net, '--agent', 'sem', '--principal', 'network')
        need(replaced['version'] == v + 1 and scope(replaced, 'sem') == Counter([setting(['network'], ['message.append'])
                                                                                   ]),
             'access allow --agent N replaces several rules with one rule (moved commands still run)',
             replaced['rules'])
        denied = p1.cli('access', 'deny', '--network', self.net, '--agent', 'other')
        need(denied['version'] == v + 2 and not scope(denied, 'other'),
             'access deny behaves as before for an agent with one rule (moved commands still run)', denied['rules'])

    def check_deny(self):
        q, r = 'person:' + self.quinn, 'person:' + self.rhea
        self.allow('quinn', '--agent', 'dn1')
        self.allow('rhea', '--agent', 'dn1', '--no-tasks')
        _, policy = self.allow('quinn', '--agent', 'dn2')
        out, policy = self.deny('quinn', '--agent', 'dn1')
        need(out['removed'] == 1 and scope(policy, 'dn1') == Counter([setting([r], ['message.append'])])
             and scope(policy, 'dn2') == Counter([setting([q])]),
             'deny --agent removes the principal from every rule naming that agent', out, policy['rules'])
        holding = sum(1 for x in policy['rules'] if q in x['principals'])
        need(holding >= 2, 'deny setup: quinn in several rules', policy['rules'])
        emptied = sum(1 for x in policy['rules'] if x['principals'] == [q])
        count = len(policy['rules'])
        out, policy = self.deny('quinn')
        need(out['removed'] == holding, 'deny without --agent removes the principal from every rule; removed counts '
             'the rules', out, holding)
        need(not any(q in x['principals'] for x in policy['rules']) and len(policy['rules']) == count - emptied,
             'deny drops empty rules', policy['rules'])
        out, _ = self.deny('quinn')
        need(out['removed'] == 0, 'deny with nothing to remove: removed 0', out)
        out, _ = self.deny('rhea', '--agent', 'nosuch')
        need(out['removed'] == 0, 'deny for an agent without rules: removed 0', out)

        # Access through a group still works after deny.
        reviewer = self.agent['reviewer']
        self.allow('group:backend', '--agent', 'reviewer', '--no-tasks')
        _, policy = self.allow('rhea', '--agent', 'reviewer')
        rh = self.hosts['rhea']
        self.synced(policy['version'], rh)
        out, policy = self.deny('rhea', '--agent', 'reviewer')
        need(out['removed'] == 1 and scope(policy, 'reviewer') == Counter([setting(['group:backend'], ['message.append'])]),
             'deny removes the direct rule only', out, policy['rules'])
        self.expect(rh, self.ids['p1'], reviewer, 'accepted', 'deny: access through a group still works afterwards')
        out, _ = self.deny('rhea', '--agent', 'reviewer')
        need(out['removed'] == 0, 'deny: removing again finds nothing (group access unaffected)', out)
        self.expect(rh, self.ids['p1'], reviewer, 'accepted', 'deny with removed 0 leaves group access')

    def check_star(self):
        P1, P2 = self.ids['p1'], self.ids['p2']
        qh, rh = self.hosts['quinn'], self.hosts['rhea']
        status, body = self.p1.call('POST', '/v1/agents', {'name': '*', 'owner': 'pat'})
        need(status == 400, '* is reserved: agent register refuses it with 400', status, body)
        need(self.p1.run('agent', 'register', '--name', '*', '--owner', 'pat').returncode != 0,
             '* is reserved: agent register refuses it', '*')
        out, policy = self.allow('quinn')
        need(out['agent'] == '*' and scope(policy, '*') == Counter([setting(['person:' + self.quinn])]),
             'allow scope defaults to *', out, policy['rules'])
        self.synced(policy['version'], self.p2, qh, rh)
        self.expect(qh, P1, self.agent['wide'], 'accepted', 'a * rule authorizes a message to any agent of the owner')
        self.expect(qh, P2, self.agent['other'], 'accepted', 'a * rule covers agents on any of the owner\'s hosts')
        t = self.task(qh, P1, self.agent['wide'], text='by star')
        need(t['submit_state'] == 'accepted', 'a * rule authorizes a task to any agent', t)
        t = self.task(qh, P2, self.agent['other'], text='by star elsewhere')
        need(t['submit_state'] == 'accepted', 'a * rule authorizes a task on another host of the owner', t)
        self.expect(rh, P1, self.agent['wide'], 'rejected', 'a * rule without rhea refuses rhea')

        _, policy = self.allow('rhea', '--agent', 'narrow')
        self.synced(policy['version'], qh, rh)
        self.expect(qh, P1, self.agent['narrow'], 'rejected',
                    'a receiver applies the rules naming N if there are any (named rule narrows *)')
        self.expect(rh, P1, self.agent['narrow'], 'accepted', 'a named rule widens * for its agent')
        self.expect(qh, P1, self.agent['wide'], 'accepted', 'other agents still use the * rules')

        _, policy = self.allow('quinn', '--agent', 'keepq')
        out, policy = self.deny('quinn', '--agent', '*')
        need(out['removed'] == 1 and not scope(policy, '*') and scope(policy, 'keepq') == Counter(
            [setting(['person:' + self.quinn])]), 'deny --agent * names only the * rules', out, policy['rules'])
        self.expect(qh, P1, self.agent['wide'], 'rejected', 'without * rules, an agent without named rules is closed')

    def check_block(self):
        P1 = self.ids['p1']
        qh = self.hosts['quinn']
        _, policy = self.allow('quinn', '--agent', 'wide')
        self.synced(policy['version'], qh)
        self.expect(qh, P1, self.agent['wide'], 'accepted', 'block setup: quinn allowed at wide')
        for target, kind, subject in (('quinn', 'person', self.quinn), (self.quinn, 'person', self.quinn),
                                      (self.ids['quinn'], 'host', self.ids['quinn'])):
            made = self.p1.cli('block', target)
            need(made.get('kind') == kind and made.get('subject') == subject,
                 'block TARGET: a host ID, or else a person ID or label, as access block', target, made)
            need(self.p1.cli('block', target) == made, 'blocking again returns the existing entry', made)
            need(self.p1.cli('access', 'blocks') == [made], 'access blocks lists it', self.p1.cli('access', 'blocks'))
            self.expect(qh, P1, self.agent['wide'], 'rejected', f'block {target} refuses the sender')
            removed = self.p1.cli('unblock', target)
            need(removed == made, 'unblock returns the removed entry', removed, made)
            need(self.p1.run('unblock', target).returncode != 0, 'unblocking again is 404', target)
            self.expect(qh, P1, self.agent['wide'], 'accepted', f'unblock {target} restores access')
        need(self.p1.cli('access', 'blocks') == [], 'no blocks remain', self.p1.cli('access', 'blocks'))

    # --- the pairing ---------------------------------------------------------------------------------------

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        (root / 'links').mkdir()
        (root / 'links' / 'capsule').symlink_to(self.cli_binary)
        for name in ('pat', 'quinn', 'rhea', 'sol', 'zed', 'two-a', 'two-b'):
            self.keys[name] = ssh_key(root / 'keys', name)
        for name, keys in (('pat', ['pat']), ('quinn', ['quinn']), ('rhea', ['rhea']), ('sol', ['sol']),
                           ('zed', ['zed']), ('two', ['two-a', 'two-b'])):
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            for key in keys:
                self.agents[name].add(self.keys[key][0])
        (root / 'agent-empty').mkdir()
        self.agents['empty'] = Agent(root / 'agent-empty')
        self.pat, self.quinn, self.rhea, self.sol = (person_id(self.keys[n][2]) for n in ('pat', 'quinn', 'rhea', 'sol'))

        self.section('root help', self.check_help)
        self.coord_key = self.coord.start()['public_key']
        for name in ('p1', 'p2', 'p3', 'rhea', 'x', 'forms', 'g1', 'g2', 'g4'):
            self.host(name)
        self.host('quinn', root / 'xdg-quinn' / 'capsule' / 'host')
        self.p1, self.p2, self.p3 = self.hosts['p1'], self.hosts['p2'], self.hosts['p3']
        for name, sock in (('p1', 'pat'), ('p2', 'pat'), ('p3', 'pat'), ('quinn', 'quinn'), ('rhea', 'rhea'),
                           ('forms', 'sol')):
            self.hosts[name].sock = self.agents[sock].socket
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}

        self.section('create', self.check_create)
        self.section('person keys: create', self.check_person_keys_create)

        # The team network, created with the slice-2 flags so later sections do not depend on the new forms.
        created = self.p1.cli('network', 'create', '--name', 'team', '--member', 'pat', *self.coordinator_flags())
        self.net = created['id']
        assert created['person']['bound'], created
        joins = self.section('invite and join', self.check_invite_and_join)
        if self.section('person keys: join', self.check_person_keys_join):
            self.section('person keys: renewal', self.check_renewal)
        else:
            self.results.append(('person keys: renewal', False, 'skipped: person keys: join failed'))
            print(f'SKIP {self.label} [person keys: renewal]: person keys: join failed', flush=True)
        if not joins:
            members = {m['host_id']: m['person_id'] for m in self.p1.cli('network', 'members', self.net)}
            if any(members.get(self.ids[n]) is None for n in ('p2', 'p3', 'quinn', 'rhea')):
                raise AssertionError(f'cannot continue without the joined hosts: {members}')

        self.agent = {}
        for host, names in (('p1', ('origin', 'reviewer', 'wide', 'narrow')), ('p2', ('helper', 'other')),
                            ('p3', ('extra',)), ('quinn', ('qagent',)), ('rhea', ('ragent',))):
            for name in names:
                self.agent[name] = self.hosts[host].cli('agent', 'register', '--name', name, '--owner', host)
        self.sessions, self.tokens, self.secrets = {}, {}, {}
        for host, name in (('p1', 'origin'), ('p2', 'helper'), ('p3', 'extra')):
            h = self.hosts[host]
            self.sessions[name] = h.cli('session', 'attach', '--agent', self.agent[name]['id'], '--integration', 'test')
            self.secrets[name] = credential(h, self.sessions[name])
            self.tokens[name] = self.secrets[name]['token']

        self.section('self access', self.check_self_access)
        if self.section('allow', self.check_allow):
            self.section('deny', self.check_deny)
            self.section('* rules', self.check_star)
            self.section('block/unblock', self.check_block)
        else:
            for name in ('deny', '* rules', 'block/unblock'):
                self.results.append((name, False, 'skipped: allow failed'))
                print(f'SKIP {self.label} [{name}]: allow failed', flush=True)

    def close(self):
        try:
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()


def run_pairing(coord_binary, cli_binary, daemon_binary, label):
    with tempfile.TemporaryDirectory(prefix='capsule-onboarding-') as temporary:
        pairing = Pairing(label, cli_binary, daemon_binary, coord_binary, Path(temporary))
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [setup]: {detail}', flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        print(f'---- {label}: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} sections passed '
              f'in {time.monotonic() - started:.0f}s', flush=True)
        return pairing.results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, help='required unless every --pairing is Go/Go')
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    parser.add_argument('--pairing', action='append', help='CLI/DAEMON, such as Go/Rust; repeatable; default all four')
    args = parser.parse_args()
    set_probe(args.probe.resolve())
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve() if args.rust else None}
    pairings = args.pairing or [f'{c}/{d}' for c in binaries for d in binaries]
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        if cli not in binaries or daemon not in binaries:
            parser.error(f'unknown pairing {pairing}')
        if binaries[cli] is None or binaries[daemon] is None:
            parser.error(f'pairing {pairing} needs --rust')
    failures = []
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        label = f'{cli} CLI, {daemon} daemon'
        for name, ok, detail in run_pairing(args.coord.resolve(), binaries[cli], binaries[daemon], label):
            if not ok:
                failures.append(f'{label} [{name}]: {detail.strip().splitlines()[-1] if detail.strip() else ""}')
    print('==== summary', flush=True)
    for line in failures:
        print('FAIL ' + line[:1200], flush=True)
    if failures:
        raise SystemExit(f'{len(failures)} section(s) failed')
    print('PASS all sections', flush=True)


if __name__ == '__main__':
    main()
