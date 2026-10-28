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

STEP_TIMEOUT = 180  # Fixture bound only. A step may include the runtime's bounded 30 s publication attempt;
SLOW_STEP = 40      # a step slower than this is printed as a NOTE (Rust stalls: bug B5) but does not fail setup.


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
    started = time.monotonic()
    for attempt in range(3):
        code, out, err = run_cli(host, *args, input=input, tty=tty, timeout=timeout)
        if b'local host daemon request timed out' not in err or attempt == 2:
            break
        # The Rust CLI gave up on its own daemon request (bug B5). Link stages and actions are retried with the
        # same bytes (spec 8.7), so the fixture repeats the command; the NOTE keeps the evidence.
        print(f'NOTE dec_network: `{" ".join(args[:2])}` hit the CLI\'s daemon request deadline; repeating', flush=True)
    if time.monotonic() - started > SLOW_STEP:
        print(f'NOTE dec_network: `{" ".join(args[:2])}` took {time.monotonic() - started:.0f} s', flush=True)
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

    def __init__(self, directory: Path, people=None):
        """`people` shares the original keys of another DecNetwork, for a second network of the same people."""
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.keys = self.directory / 'person-keys'
        self.keys.mkdir(parents=True, exist_ok=True)
        self.people = people if people is not None else {}
        self.hosts = {}
        self.root_host = None
        self.id = self.context = None
        self.log = []
        self.slow_resumes = []

    def key_args(self, label):
        """Daemon arguments for a host whose person's original key file lives on it.

        Today's hosts keep the creator's provider as the original key (see
        bug N1), so the creator's daemon signs its owner link stages with it.
        """
        return ('--person-key-file', str(self.person(label).key))

    def install_key(self, host, label):
        """Make `label`'s original key this host's configured owner key, $XDG_CONFIG_HOME/peerspan/person_ed25519
        ("the configured owner key", spec 6 step 3), which the CLI and the daemon's --person-key-file default
        both use while it exists. create() and the joins do this for every member host: with the key only in
        ssh-agent neither CLI signs (bug B6), and the coordinator-era flow generated the key at this path."""
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
    def create(self, host, label, name='team', flags=()):
        person = self.person(label)
        self.install_key(host, label)
        value = cli_json(host, 'network', 'create', name, '--as', label, '--person-key-file', str(person.key), *flags,
                         expect=True)
        self.created = value
        self.id = value['id']
        self.networks = getattr(self, 'networks', {})
        self.networks[name] = value['id']
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
                started = time.monotonic()
                try:
                    status, view = api(host, 'POST', f'/v2/link/requests/{request_id}/resume', {})
                except TimeoutError:
                    # decentralized-spec.md 9.5 bounds a resume's publication at 30 s; record a slower
                    # answer (reported with the results) and keep polling the request instead.
                    self.slow_resumes.append((what, round(time.monotonic() - started, 1)))
                    print(f'NOTE dec_network: POST /v2/link/requests/{{id}}/resume ({what}) gave no answer within '
                          f'{round(time.monotonic() - started)} s (spec 9.5: 30 s)', flush=True)
                    status, view = 0, None
                if status not in (0, 200, 202, 409, 503):
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
        admitted = []
        for attempt in range(3):
            if view['administrator_offer_id'] != '-':
                break
            # Spec 8.7: a retry resends the exact same bytes, so repeating the admission is safe.
            admitted.append(cli_json(self.root_host, 'link', 'admit', '--network', self.id, '--person', person.raw,
                                     *admin_signer_args, *keys, '--owner-offer', view['owner_offer_id'],
                                     '--selection', view['selection_id'], '--code-stdin', '--approve',
                                     input=(code + '\n').encode()))
            try:
                view = self._wait(requester, request_id, lambda v: v['administrator_offer_id'] != '-',
                                  'administrator offer at requester', seconds=60)
            except SetupFailure:
                if attempt == 2:
                    raise SetupFailure(f'administrator offer never reached the requester; admit said: '
                                       f'{[{k: a.get(k) for k in ("state", "completed", "next", "attention")} for a in admitted]}')
                print(f'NOTE dec_network: administrator offer not at the requester 60 s after admit; admitting again',
                      flush=True)
        fixed = ['--network', self.id, '--context', self.context, '--expect-person', person.raw, *keys,
                 '--owner-offer', view['owner_offer_id'], '--selection', view['selection_id'],
                 '--administrator-offer', view['administrator_offer_id']]
        if view['owner_finalization_id'] == '-':
            if owner_host is not requester:
                # The owner's host must hold the selection and the administrator offer before it finalizes
                # (otherwise it answers proof_required); resume on both sides (spec 9.5) until it does.
                def owner_has_offer():
                    api(requester, 'POST', f'/v2/link/requests/{request_id}/resume', {})
                    return self._wait(owner_host, request_id, lambda v: v['administrator_offer_id'] != '-',
                                      'administrator offer at the owner', seconds=20)
                for _ in range(3):
                    try:
                        owner_has_offer()
                        break
                    except (SetupFailure, TimeoutError):
                        pass
            try:
                cli_json(owner_host, 'link', 'finalize', request_id, *fixed, '--person-key', str(person.key), '--approve')
            except SetupFailure as error:
                # The owner's stage-2 approval also approves its own stage-5 signatures (spec 8.2 "Preapproval"),
                # so the owner's host may already have finalized; a second finalization is then a conflict.
                # Whether it did is decided by the requester's view below.
                if 'conflict' not in str(error):
                    raise
                print(f'NOTE dec_network: link finalize answered a conflict ({str(error)[-80:]}); '
                      f'waiting for the preapproved finalization', flush=True)
        view = self._wait(requester, request_id, lambda v: v['owner_finalization_id'] != '-', 'owner finalization at requester')
        if view['state'] != 'linked':
            cli_json(requester, 'link', 'commit', request_id, *fixed, '--owner-finalization', view['owner_finalization_id'],
                     '--approve')
        view = self._wait(requester, request_id, lambda v: v['state'] == 'linked', 'requester applied')
        for other in {owner_host, self.root_host} - {requester}:
            self._wait(other, request_id, lambda v: v['state'] == 'linked', 'participant applied')
        return view

    # Spec 8.1: a person, invited by a member host, joins with their own original key on the new machine.
    def join(self, inviter, joiner, label, flags=(), person=None):
        """`label` is the member label; `person` names the fixture key when it differs (as `ops/sam` for sam).

        A person who already has a member host in this network adds this machine with `link` instead
        (spec 8.1, last paragraph: "Linking another machine of an existing person uses `peerspan link` on
        the new machine instead of `join`"), approved on that person's first member host."""
        owner = next((h for h, p in self.hosts.items() if p is self.person(person or label)), None)
        if owner is not None and not flags:
            return self.link(owner, joiner, person or label)
        key = self.person(person or label).key
        invitation = cli_json(inviter, 'network', 'invite', '--network', self.id, '--member', label, expect=True)
        private = self.directory / f'invite-{len(self.log)}-{os.getpid()}-{time.monotonic_ns()}.private'
        private.write_text(invitation['invitation'] + '\n')
        private.chmod(0o600)
        request = cli_json(joiner, 'network', 'join', '--invite-file', str(private), '--person-key', str(key), *flags)
        self.join_outputs = getattr(self, 'join_outputs', {})
        self.join_outputs[joiner] = request
        if 'request_id' not in request:
            raise SetupFailure(f'network join did not create a request: {request}')
        return self.complete_join(joiner, request, label, person or label)

    def complete_join(self, joiner, request, label, person):
        """Finish a join request `request` (the `network join` output) of `person`'s original key on `joiner`."""
        self.install_key(joiner, person)
        person = self.person(person)
        request_id, code = request['request_id'], request['display_code']
        # Possession-only owner offer by the person's own key on the new machine (spec 8.2 stage 2); scopes
        # stay at the new-person default 7 (spec 8.3).
        if request.get('owner_offer_id', '-') == '-':
            cli_json(joiner, 'link', 'approve', '--network', self.id, '--person', person.raw,
                     '--expect-host-key', request['host_public_key'], '--expect-device-key', request['device_public_key'],
                     '--person-key', str(person.key), '--not-after', utc(6 * 86400), '--code-stdin', '--approve',
                     input=(code + '\n').encode())
        view = self._admit_finalize_commit(joiner, joiner, request_id, code, person, ['--signer', 'network_root'])
        self.hosts[joiner] = person
        self.log.append(('join', label, request_id))
        return view

    def adopt(self, host, label, network_id):
        """Track a network `host` created itself with `label`'s key (`network create` run by the suite)."""
        self.id = network_id
        self.context = api(host, 'GET', '/v2/networks/' + network_id)[1]['context_id']
        self.root_host = host
        self.hosts[host] = self.person(label)

    # Spec 8.1 last paragraph: another machine of an existing person.
    def link(self, owner_host, new_host, label, scopes=None):
        """Spec 8.1 last paragraph and 8.3: `link` on the new machine, `link approve` on a machine of the person,
        admission by the root host. The owner offer is signed by the original key (`--signer` names it): a
        joined person's device has scopes 7, without 4, so it cannot approve a device (spec 5, 8.2 stage 2).
        Scopes take the default, 15 capped by the owner's path (spec 8.3); naming 15 above that cap is refused.
        The deadline is 3 days, inside every parent (a joined owner's own grants end 6 days after its join)."""
        person = self.people[label]
        self.install_key(new_host, label)
        request = cli_json(new_host, 'link', '--network', self.id, '--expect-person', person.raw)
        request_id, code = request['request_id'], request['display_code']
        cli_json(owner_host, 'link', 'approve', '--network', self.id, '--person', person.raw,
                 '--expect-host-key', request['host_public_key'], '--expect-device-key', request['device_public_key'],
                 '--person-key', str(person.key), '--signer', person.raw,
                 *(('--scopes', str(scopes)) if scopes else ()), '--not-after', utc(3 * 86400), '--code-stdin', '--approve', input=(code + '\n').encode())
        view = self._admit_finalize_commit(new_host, owner_host, request_id, code, person, ['--signer', 'network_root'])
        self.hosts[new_host] = person
        self.log.append(('link', label, request_id))
        return view

    def sync(self, hosts=None, rounds=2, check=False):
        """`network sync` on each host (spec 10: bounded at 30 s, so the reader allows 60 s, unlike
        host_service.Host.cli's 10 s). With `check`, a nonzero exit fails, as `Host.cli` did."""
        for _ in range(rounds):
            for host in hosts or list(self.hosts):
                code, out, err = run_cli(host, 'network', 'sync', self.id)
                if check and code != 0:
                    raise SetupFailure(f'network sync: exit {code}: {err.decode(errors="replace")[-500:]}')

    def member_persons(self, host):
        """{host_id: person_id} of the current verified members `host` knows (the old `network members` map)."""
        status, value = api(host, 'GET', f'/v2/networks/{self.id}/members')
        if status != 200:
            return {}
        return {host_id(m['host_public_key']): person_id(m['person_public_key']) if m['person_public_key'] != '-' else None
                for m in value['members']}

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


# --- policies on coordinator-free networks ------------------------------------------------------------------
#
# A coordinator-free network keeps each person's policy as a DEC `policy` statement whose payload carries the
# unchanged `peerspan-policy-v2` body (decentralized-wire-formats.md section 5). The owner-local read is
# `GET /v2/networks/{id}/policy/{person}` -> {statement_id, statement_base64} (wire formats 16.2); the
# coordinator-era `GET /v1/networks/{id}/policy` does not serve these networks (it answers 426).

def _b64json(value):
    return json.loads(base64.b64decode(value))


def policy_statement(host, network_id, person_raw):
    """(statement_id, envelope, payload, body) of `person_raw`'s current policy on `host`, or None (404)."""
    import urllib.parse
    status, value = api(host, 'GET', f'/v2/networks/{network_id}/policy/' + urllib.parse.quote(person_raw, safe=''))
    if status != 200:
        return None
    envelope = _b64json(value['statement_base64'])
    payload = _b64json(envelope['payload_base64'])
    return value['statement_id'], envelope, payload, _b64json(payload['body_base64'])


def policy_body(host, network_id, person_raw):
    """The current `peerspan-policy-v2` body (the fields the /v1 policy view used to return), or None."""
    current = policy_statement(host, network_id, person_raw)
    return current[3] if current else None


def sshsig(key, message):
    """Canonical Base64 of the binary SSHSIG (namespace peerspan-person-v1) of `message` by an original key file."""
    result = subprocess.run(['ssh-keygen', '-q', '-Y', 'sign', '-n', 'peerspan-person-v1', '-f', str(key)],
                            input=message, capture_output=True, timeout=20)
    if result.returncode != 0:
        raise SetupFailure('ssh-keygen -Y sign failed: ' + result.stderr.decode(errors='replace')[-300:])
    armored = result.stdout.decode().strip().splitlines()
    return ''.join(line for line in armored if not line.startswith('-----'))


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _fmt(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


def _policy_payload(host, network_id, person, body, predecessors):
    """The unsigned DEC policy payload around `body` (wire formats section 5), issued by the original key now."""
    now = _now()
    persons = api(host, 'GET', f'/v2/networks/{network_id}/persons')
    rows = [p for p in persons[1].get('persons', [])] if persons[0] == 200 else []
    rows = [p for p in rows if p['person_public_key'] == person.raw]
    if len(rows) != 1:
        raise SetupFailure(f'no current person lease for the policy: {persons}')
    until = min(now + timedelta(seconds=86400),
                datetime.strptime(rows[0]['not_after'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc))
    body['issued_at'], body['valid_until'] = _fmt(now), _fmt(until)
    view = api(host, 'GET', f'/v2/networks/{network_id}')[1]
    payload = {'root_state_id': view['root_state_id'], 'operation_id': '-', 'sequence': body['version'],
               'predecessors': sorted(predecessors), 'resolves': [],
               'issuer': {'kind': 'person', 'person_public_key': person.raw},
               'parents': [{'role': 'issuer_person', 'id': rows[0]['person_lease_id']}],
               'issued_at': _fmt(now), 'not_before': _fmt(now), 'not_after': _fmt(until),
               'body_base64': base64.b64encode(json.dumps(body, separators=(',', ':')).encode()).decode()}
    return base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode()


def _sign_action(host, route, ready, person):
    """Sign every ready original-key slot of a prepared action (spec 11 "Slots") until none is left."""
    for _ in range(4):
        slots = ready.get('signing_requests') or []
        if not slots:
            return ready
        signatures = [{'slot_id': s['slot_id'], 'role': s['role'],
                       'signature': sshsig(person.key, base64.b64decode(s['message_base64']))} for s in slots]
        status, ready = api(host, 'POST', f'{route}/{ready["action_id"]}/signed',
                            {'intent_id': slots[0]['intent_id'], 'signatures': signatures})
        if status != 200:
            raise SetupFailure(f'{route} signatures: {status} {ready}')
    raise SetupFailure(f'{route} left unsigned slots: {ready}')


def next_edit_seq(host, network_id, person):
    """This host's next local edit number (decentralized-spec.md 12.1 "Edit records": "names this host's next local
    edit number, chosen when the plan is made and checked for uniqueness when it is applied").

    Today's hosts still hand it out through the reservation route of the old policy-edit contract; where that route
    is gone (DEC-S16), it is one more than the highest number in this owner's edit list
    (GET /v2/networks/{id}/policy-edits)."""
    status, reserved = api(host, 'POST', f'/v2/networks/{network_id}/policy-edits', {'provider_id': person.raw})
    if status == 200 and isinstance(reserved, dict) and 'seq' in reserved:
        return reserved['seq']
    status, listed = api(host, 'GET', f'/v2/networks/{network_id}/policy-edits')
    if status != 200:
        raise SetupFailure(f'policy edits: {status} {listed}')
    return max([e['seq'] for e in listed.get('edits', [])] or [0]) + 1


def policy_action(host, network_id, person, change):
    """Sign and apply the next version of `person`'s policy with `change(body)` applied, as an edit by `host`,
    through the ordinary action route (wire formats 16.4, kind `policy`), signed by the original key. This replaces
    the coordinator-era crafted `POST /v1/networks/{id}/policy`. Returns the action result.

    It is an edit, with a new `edits` number for this host (dispute D2): decentralized-spec.md 12.1 has a host's
    content-changing policy name this host's next local edit number, unique when applied, so copying the host's
    already settled entry (the coordinator-era "not an edit" form) is refused. Other hosts' entries are kept."""
    host_id = api(host, 'GET', '/v1/host')[1]['id']
    seq = next_edit_seq(host, network_id, person)
    current = policy_statement(host, network_id, person.raw)
    # The version is the retained maximum plus one and the predecessors are every known head of the stream
    # (GET .../access-versions; runtime contract: "Versions use the retained maximum, not an active-only view").
    status, versions = api(host, 'GET', f'/v2/networks/{network_id}/access-versions')
    row = next((r for r in versions.get('policies', []) if r['person_public_key'] == person.raw), None) \
        if status == 200 else None
    if current:
        statement_id, _, _, body = current
        predecessors = list(row['head_ids']) if row else [statement_id]
        if row:
            body['version'] = row['version']
    else:
        body = {'format': 2, 'network_id': network_id, 'person_public_key': person.raw, 'version': 0,
                'issued_at': '-', 'valid_until': '-', 'rules': [], 'capability_rules': [], 'trusted_hosts': [],
                'edits': []}
        predecessors = []
    change(body)
    body['version'] += 1
    body['edits'] = sorted([e for e in body['edits'] if e['host'] != host_id] + [{'host': host_id, 'seq': seq}],
                           key=lambda e: e['host'])
    payload = _policy_payload(host, network_id, person, body, predecessors)
    route = f'/v2/networks/{network_id}/actions'
    status, ready = api(host, 'POST', route, {'kind': 'policy', 'provider_id': person.raw, 'signature_format': 'sshsig',
                                             'payload_base64': payload, 'approve': True})
    if status != 200:
        raise SetupFailure(f'policy action: {status} {ready}; access-versions row: {row}')
    return _sign_action(host, route, ready, person)


def claim_catalog(host, host_id, network_id, person, capability, change):
    """The signed claim for POST /v1/capabilities `catalogs`, prepared as the CLI does on a coordinator-free network.

    decentralized-runtime-contract.md "Prepare a capability claim without applying a policy" and
    linking-host-checks.md "Atomic capability claims": the CLI reserves this host's next edit
    (POST /v2/networks/{id}/policy-edits), applies its change to the reserved starting policy, wraps
    the unsigned policy-v2 body in a DEC policy payload with version + 1 and this host's `edits` entry,
    prepares it with POST /v2/networks/{id}/policy-claims, signs the original-key slots, and sends the
    resulting exact catalog as `{network_id, catalog}`. `change(body)` edits the body in place.
    `person` is a dec_network.Person.
    """
    reserved = api(host, 'POST', f'/v2/networks/{network_id}/policy-edits', {'provider_id': person.raw})
    if reserved[0] != 200:
        raise SetupFailure(f'policy edit reservation: {reserved}')
    reserved = reserved[1]
    if isinstance(reserved['policy'], dict):  # '-' when the person has no policy yet
        body = _b64json(reserved['policy']['body_base64'])
        predecessors = [reserved['policy']['statement_id']]
    else:
        body = {'format': 2, 'network_id': network_id, 'person_public_key': person.raw, 'version': 0,
                'issued_at': '-', 'valid_until': '-', 'rules': [], 'capability_rules': [], 'trusted_hosts': [],
                'edits': []}
        predecessors = []
    change(body)
    body['version'] = reserved['version'] + 1
    body['edits'] = sorted([e for e in body['edits'] if e['host'] != host_id] + [{'host': host_id, 'seq': reserved['seq']}],
                           key=lambda e: e['host'])
    payload = _policy_payload(host, network_id, person, body, predecessors)
    route = f'/v2/networks/{network_id}/policy-claims'
    status, ready = api(host, 'POST', route, {'capability': capability, 'provider_id': person.raw,
                                             'signature_format': 'sshsig', 'payload_base64': payload, 'approve': True})
    if status != 200:
        raise SetupFailure(f'policy-claims preparation: {status} {ready}')
    ready = _sign_action(host, route, ready, person)
    return {'network_id': network_id, 'catalog': ready['catalog']}


def trust(host, network_id):
    """`trust --network ID` for this host, after a bounded sync so its edit starts from the person's newest policy.

    The suites' joins used `--trusted` (refused on coordinator-free networks: bug B4). Two hosts of one person
    signing trust back to back otherwise race: the second host's edit starts from a policy it has not yet
    learned and both CLIs exit 1 with `policy changed after reservation` instead of reloading (bug B7)."""
    run_cli(host, 'network', 'sync', network_id)
    # The configured owner key is named explicitly: this is fixture setup, and the Rust CLI with a Go daemon
    # refuses to sign without --person-key-file-style naming (bug B8; the suites' own commands still show it).
    config = Path(getattr(host, 'config', None) or host.config_home)
    key = config / 'peerspan' / 'person_ed25519'
    code, out, err = run_cli(host, 'trust', '--network', network_id, *(('--person-key', str(key)) if key.exists() else ()))
    if code != 0:
        raise SetupFailure(f'trust: exit {code}: {err.decode(errors="replace")[-400:]}')
    return json.loads(out)
