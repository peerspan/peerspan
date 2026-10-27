"""Coordinator-free network fixture shared by the product suites.

Product suites used to start a Go `peerspan-coord`, run `network create
--coordinator`, and join hosts with coordinator tokens. Coordinator networks
are refused now (DEC-OWN2), so this module builds the same topologies through
the public CLI only, as docs/decentralized-spec.md sections 6 and 8 describe
and as conformance/decentralized_native_introduction.py (the CI reference)
drives the current hosts:

- `network create NAME --as MEMBER --person-key-file KEY` on the creator's
  host (spec 6). That host holds the raw root seed, so it is also the
  administrator for every later join (`link admit --signer network_root`,
  spec 8.2 "Separate admin").
- A new person joins with `network invite` on a member host, then `network
  join --invite-file` on the new machine with that person's own original key,
  which also signs the possession-only owner offer (spec 8.1, 8.2 stage 2).
- Another machine of an existing person runs `link --network ID
  --expect-person KEY`; the person approves on a host where their original
  key file lives (spec 8.1 last paragraph).
- A host with no person joins with `network join --no-person`.

Each requester gives explicit consent with `link select --approve` and `link
commit --approve` (spec 8.4); the helper never answers a prompt it did not
review: it passes the exact IDs it just read back from `link status`.

Original person keys are OpenSSH ed25519 key files in the fixture directory
(spec 3: they never enter a daemon). No helper server or coordinator runs;
hosts reach each other over their loopback peer and first-contact listeners.

Only public CLI, owner-local /v2 routes and documented help are used; nothing
here reads go/, rust/ or integrations/.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import pty
import signal
import subprocess
import time

STEP_TIMEOUT = 60  # One CLI step may include the runtime's bounded 30 s publication attempt.


class SetupFailure(AssertionError):
    """The coordinator-free fixture itself could not be built (not a product assertion)."""


def ssh_person_key(directory: Path, name: str):
    """A fresh unencrypted ssh-ed25519 original person key: (path, 'ssh-ed25519 AAAA..', raw Base64)."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', str(path)],
                   check=True, capture_output=True, timeout=10)
    line = (directory / (name + '.pub')).read_text().split()
    raw = base64.b64decode(line[1])[-32:]
    return path, ' '.join(line[:2]), base64.b64encode(raw).decode()


def person_id(raw_b64):
    return 'person_' + hashlib.sha256(base64.b64decode(raw_b64)).hexdigest()


def utc(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')


def run_cli(host, *args, input=b'', tty=False, timeout=STEP_TIMEOUT, env=None):
    """Run one CLI command for `host` (a host_service.Host); returns (exit, stdout, stderr)."""
    if env is not None:
        environment = env
    elif hasattr(host, 'environment'):      # launch_directory.DirectoryHost and its subclasses
        environment = host.environment()
    elif hasattr(host, 'private_env'):      # launch_onboarding.OnboardHost
        environment = dict(os.environ)
        environment.pop('SSH_AUTH_SOCK', None)
        if getattr(host, 'sock', None):
            environment['SSH_AUTH_SOCK'] = host.sock
        environment.update(host.private_env())
    else:
        environment = host.isolated(dict(os.environ))
        if not getattr(host, 'keep_agent', False):
            environment.pop('SSH_AUTH_SOCK', None)
    argv = [str(getattr(host, 'cli_binary', None) or host.binary), '--state', str(host.state), *args]
    master = slave = None
    if tty:
        master, slave = pty.openpty()
    process = subprocess.Popen(argv, stdin=slave if tty else subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, start_new_session=True)
    if slave is not None:
        os.close(slave)
    try:
        if tty:
            os.write(master, input)
            stdout, stderr = process.communicate(timeout=timeout)
        else:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=5)
        raise SetupFailure(f'{args[:2]} timed out after {timeout}s: {stderr.decode(errors="replace")[-800:]}')
    finally:
        if master is not None:
            os.close(master)
    return process.returncode, stdout, stderr


def cli_json(host, *args, input=b'', tty=False, expect=None, timeout=STEP_TIMEOUT):
    code, out, err = run_cli(host, *args, input=input, tty=tty, timeout=timeout)
    if expect is not None and (code == 0) != expect:
        raise SetupFailure(f'{" ".join(args[:3])}: exit {code}: {err.decode(errors="replace")[-1500:]} {out[-500:]!r}')
    try:
        return json.loads(out)
    except ValueError:
        raise SetupFailure(f'{" ".join(args[:3])}: exit {code}, no JSON: {err.decode(errors="replace")[-1500:]}')


def api(host, method, path, body=None, timeout=45):
    """One owner-local request with a reader bound above the runtime's 30 s publication attempt."""
    from host_service import UnixHTTPConnection
    connection = UnixHTTPConnection(host.state / 'admin.sock', timeout=timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        connection.request(method, path, payload, {'Content-Type': 'application/json'})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class Person:
    def __init__(self, label, key):
        self.label = label
        self.key, self.public, self.raw = key

    @property
    def id(self):
        return person_id(self.raw)


class DecNetwork:
    """One coordinator-free network built through the public CLI.

    `hosts` maps every member host to the Person bound to it (None for a
    host-only member). The creator's host holds the root seed and is the
    administrator for every admission.
    """

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.keys = self.directory / 'person-keys'
        self.keys.mkdir(parents=True, exist_ok=True)
        self.people = {}
        self.hosts = {}
        self.root_host = None
        self.id = self.context = None
        self.log = []

    def key_args(self, label):
        """Daemon arguments for a host whose person's original key file lives on it.

        Today's hosts keep the creator's provider as the original key (see
        bug N1), so the creator's daemon signs its owner link stages with it.
        """
        return ('--person-key-file', str(self.person(label).key))

    def install_key(self, host, label):
        """Make `label`'s original key this host's configured owner key (spec 6 step 3: "the explicit
        file, the configured owner key, ..."): $XDG_CONFIG_HOME/peerspan/person_ed25519, which the CLI
        and the daemon's --person-key-file default both use while it exists."""
        config = Path(getattr(host, 'config', None) or host.config_home)
        target = config / 'peerspan' / 'person_ed25519'
        target.parent.mkdir(parents=True, exist_ok=True)
        person = self.person(label)
        target.write_bytes(person.key.read_bytes())
        target.chmod(0o600)
        target.with_suffix('.pub').write_bytes(person.key.with_suffix('.pub').read_bytes())
        return target

    def bound(self, host):
        """The person this host's selected provider acts for (spec 11 "Selected provider")."""
        status, value = api(host, 'GET', f'/v2/networks/{self.id}/provider')
        return value.get('person_public_key') if status == 200 else None

    def person(self, label):
        """The fixture's original key for `label`, created once."""
        if label not in self.people:
            safe = ''.join(c if c.isalnum() else '_' for c in label)
            self.people[label] = Person(label, ssh_person_key(self.keys, 'person-' + safe))
        return self.people[label]

    # Spec 6.
    def create(self, host, label, name='team'):
        person = self.person(label)
        value = cli_json(host, 'network', 'create', name, '--as', label, '--person-key-file', str(person.key), expect=True)
        self.id = value['id']
        status, view = api(host, 'GET', '/v2/networks/' + self.id)
        if status != 200 or view.get('mode') != 'decentralized':
            raise SetupFailure(f'network create did not give a coordinator-free view: {status} {view}')
        self.context = view['context_id']
        self.root_host = host
        self.hosts[host] = person
        self.log.append(('create', label))
        return value

    def status(self, host, request_id):
        return cli_json(host, 'link', 'status', request_id)

    def _wait(self, host, request_id, predicate, what, seconds=90, resume=True):
        deadline = time.monotonic() + seconds
        view = None
        while time.monotonic() < deadline:
            if resume:
                status, view = api(host, 'POST', f'/v2/link/requests/{request_id}/resume', {})
                if status not in (200, 202, 409, 503):
                    raise SetupFailure(f'resume {what}: {status} {view}')
            status, current = api(host, 'GET', '/v2/link/requests/' + request_id)
            if status == 200:
                view = current
                if predicate(view):
                    return view
            time.sleep(1)
        raise SetupFailure(f'timed out waiting for {what}: {view}')

    def _admit_finalize_commit(self, requester, owner_host, request_id, code, person, admin_signer_args):
        view = self._wait(requester, request_id, lambda v: v['owner_offer_id'] != '-', 'owner offer at requester')
        keys = ['--expect-host-key', view['host_public_key'], '--expect-device-key', view['device_public_key']]
        if not view['selection_approved']:
            cli_json(requester, 'link', 'select', request_id, '--network', self.id, '--context', self.context,
                     '--expect-person', person.raw, *keys, '--owner-offer', view['owner_offer_id'], '--approve')
        view = self._wait(requester, request_id, lambda v: v['selection_id'] != '-' and v['selection_approved'], 'selection')
        if view['administrator_offer_id'] == '-':
            cli_json(self.root_host, 'link', 'admit', '--network', self.id, '--person', person.raw, *admin_signer_args,
                     *keys, '--owner-offer', view['owner_offer_id'], '--selection', view['selection_id'],
                     '--code-stdin', '--approve', input=(code + '\n').encode())
        view = self._wait(requester, request_id, lambda v: v['administrator_offer_id'] != '-', 'administrator offer at requester')
        fixed = ['--network', self.id, '--context', self.context, '--expect-person', person.raw, *keys,
                 '--owner-offer', view['owner_offer_id'], '--selection', view['selection_id'],
                 '--administrator-offer', view['administrator_offer_id']]
        if view['owner_finalization_id'] == '-':
            cli_json(owner_host, 'link', 'finalize', request_id, *fixed, '--person-key', str(person.key), '--approve')
        view = self._wait(requester, request_id, lambda v: v['owner_finalization_id'] != '-', 'owner finalization at requester')
        if view['state'] != 'linked':
            cli_json(requester, 'link', 'commit', request_id, *fixed, '--owner-finalization', view['owner_finalization_id'],
                     '--approve')
        view = self._wait(requester, request_id, lambda v: v['state'] == 'linked', 'requester applied')
        for other in {owner_host, self.root_host} - {requester}:
            self._wait(other, request_id, lambda v: v['state'] == 'linked', 'participant applied')
        return view

    # Spec 8.1: a new person, invited by a member host, joins with their own original key.
    def join(self, inviter, joiner, label):
        person = self.person(label)
        invitation = cli_json(inviter, 'network', 'invite', '--network', self.id, '--member', label, expect=True)
        private = self.directory / f'invite-{len(self.log)}.private'
        private.write_text(invitation['invitation'] + '\n')
        private.chmod(0o600)
        request = cli_json(joiner, 'network', 'join', '--invite-file', str(private), '--person-key', str(person.key))
        request_id, code = request['request_id'], request['display_code']
        # Possession-only owner offer by the new person's own key on the new machine (spec 8.2 stage 2).
        cli_json(joiner, 'link', 'approve', '--network', self.id, '--person', person.raw,
                 '--expect-host-key', request['host_public_key'], '--expect-device-key', request['device_public_key'],
                 '--person-key', str(person.key), '--not-after', utc(6 * 86400), '--code-stdin', '--approve',
                 input=(code + '\n').encode())
        view = self._admit_finalize_commit(joiner, joiner, request_id, code, person, ['--signer', 'network_root'])
        self.hosts[joiner] = person
        self.log.append(('join', label, request_id))
        return view

    # Spec 8.1 last paragraph: another machine of an existing person.
    def link(self, owner_host, new_host, label, scopes=15):
        person = self.people[label]
        request = cli_json(new_host, 'link', '--network', self.id, '--expect-person', person.raw)
        request_id, code = request['request_id'], request['display_code']
        cli_json(owner_host, 'link', 'approve', '--network', self.id, '--person', person.raw,
                 '--expect-host-key', request['host_public_key'], '--expect-device-key', request['device_public_key'],
                 '--person-key', str(person.key), '--scopes', str(scopes), '--not-after', utc(6 * 86400),
                 '--code-stdin', '--approve', input=(code + '\n').encode())
        view = self._admit_finalize_commit(new_host, owner_host, request_id, code, person, ['--signer', 'network_root'])
        self.hosts[new_host] = person
        self.log.append(('link', label, request_id))
        return view

    def sync(self, hosts=None, rounds=2):
        """Bounded sync on every member (spec 10) so third hosts learn new activations."""
        for _ in range(rounds):
            for host in hosts or list(self.hosts):
                run_cli(host, 'network', 'sync', self.id)

    def member_host_ids(self, host):
        """Host IDs of the current verified members `host` knows (GET /v2/networks/{id}/members).

        The v2 member view names hosts by public key; a host ID is `host_` plus the
        lowercase hex SHA-256 of the raw host public key (the /v1/host identity).
        """
        status, value = api(host, 'GET', f'/v2/networks/{self.id}/members')
        if status != 200:
            return set()
        return {host_id(m['host_public_key']) for m in value['members']}

    def wait_members(self, hosts, count, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            seen = {h: len(self.member_host_ids(h)) for h in hosts}
            if all(n == count for n in seen.values()):
                return
            if time.monotonic() > deadline:
                raise SetupFailure(f'members never reached {count}: {list(seen.values())}')
            self.sync(hosts, rounds=1)
            time.sleep(1)


def host_id(public_b64):
    return 'host_' + hashlib.sha256(base64.b64decode(public_b64)).hexdigest()
