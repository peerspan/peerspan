#!/usr/bin/env python3
"""Exercise coordinator moves and repair (milestone 8 slice 3) with Go coordinators and Go and Rust hosts.

Written from docs/hosted-coordinator-contract.md ("Slice 3: moves and repair", whose Verification
subsection names this suite) alone, with context from slices 1 and 2 of that contract, the hosted
coordinator proposal, and the coordination contract (administrators, SSHSIG statements, maps, groups,
policies, persons, revocations), independently of the coordinator and host implementations. Hosts are
driven through their CLIs and local APIs, the peer route through capsule-peer-probe, and coordinators
through their CLI and raw TLS clients holding member and non-member keys.

Section, run once:

- move test vector: the suite's statement encoding self-checked against the coordination contract's raw
  and SSHSIG vectors, the contract's move test vector reproduced, and an extra vector (genesis root of the
  coordination contract, root raw signature and administrator SSHSIG) computed and printed.

Sections per combination of MOVER/OTHER/JOINER implementations (alice and adam run the mover's
implementation, bob and dave the other member's, carol and erin the joiner's). adam runs `network move`
with the other implementation's CLI against its daemon, so both Go-CLI/Rust-daemon and Rust-CLI/Go-daemon
pairings move networks. Each uses five Go coordinators: C1 (where the network is created), C2, C3, C4, and
C5 (import refusals only). `GET /v1/networks/{id}/move` is checked for `{move, next_sequence}` before any
move, after the administrator move, and after the signer's removal.

- setup: pat creates the network on alice (root holder and administrator); quinn (adam), rhea (bob), and
  dan (dave) join; quinn is delegated as administrator; a group, a policy, a revoked raw host, and raw
  watcher and victim members; carol's invite is issued now, before any move; the peer move route answers
  404 before any move; `network move` is listed in `help advanced`;
- root move (alice, sequence 1, C1 to C2): `network move` refused with exit 1 and nothing changed for an
  unreachable coordinator and for a wrong coordinator key; then the printed object; the move statement
  (strict fields, `signer: root`, raw signature over the contract's lines, equal to the suite's own
  signature with the root seed); C1 accepting and serving `move`; C2's map holding the imported members,
  revocation, persons, administrators, group, policy, and move; every member switching; `network members`,
  connected-only messages, a policy-cited message, a policy update reaching another host through C2, and
  a change notification reaching a host whose interval sync is far off;
- join with an old invite (carol): the invite names C1; the join through C1 ends pinned to C2 with carol's
  membership in C2's map, and carol messages bob;
- precedence: C2 signs a successor to an unreachable key and address, which every host records as pending
  (`source: successor`, `move_sequence: null`); dave stops; quinn moves the network from adam (sequence 2,
  SSHSIG, verified with ssh-keygen and equal to ssh-keygen's own signature) to C3, C2 accepting; running
  hosts switch to C3 (the pending move replaced the pending successor); with C3 stopped, dave restarts,
  learns the move from C2's map and records it as pending (`source: move`, `move_sequence: 2`), which C2's
  successor chain never replaces over several syncs; dave switches once C3 starts; then a successor of C3
  (an address change) is followed by every host;
- sequence refusals: crafted moves posted to the current coordinator: equal and lower sequences 409; a bad
  signature, an invalid address, and a non-administrator signer 400; a non-member caller 403; the peer
  route refusing an invalid move with 400 and a non-member host with 403, and answering 200 to a valid lower
  move while keeping the held one; the local POST route refusing an unsigned move without the root seed
  (403) and a signed move naming another coordinator than the request (400);
- move with the previous coordinator stopped (quinn from adam, sequence 3, back to C1): `previous_coordinator:
  unreachable`; running members learn it from the push; dave, stopped during the move, learns it by peer
  lookup after its syncs fail and switches;
- repair after a restore: a backup of C1, then a member joining (erin, with its person), a group, a policy
  version, and a revocation; with alice and adam (the root and administrators' hosts) stopped, C1 is
  restored from the backup; all of it reappears in C1's map, and erin syncs again;
- import refusals (C5): a non-member caller 403 for an unknown and an existing network, registering nothing;
  a member importing a map with a forged member, person, group version, and move gets 201 with those
  skipped and absent from the map; the map as held then 200, adding what was missing; a repeat adding
  nothing;
- removed administrator: after `remove-admin quinn`, hosts stay switched to quinn's move; `network move` by
  quinn is refused with nothing imported; a quinn-signed move is refused by the coordinator and the peer
  route with 400; next_sequence is 4;
- exchanged move: a move signed by this suite with the root seed (sequence 4, to C4) delivered on the peer
  route to a mover-implementation and an other-implementation host (200, then served by GET); they switch
  to C4 after its 403 by importing; C1 lacks it (only the mover submits) and stores it when the suite posts
  it, so every other host follows; messages at C4.

Default combinations (MOVER/OTHER/JOINER): Go/Rust/Rust, Rust/Go/Go, Go/Go/Rust, Rust/Rust/Go. Each
implementation plays mover, other member, and joiner at least twice; mover and other member differ in two
and match in two, and the joiner differs from the mover in all four, so every exchanged statement crosses
implementations both ways. `--all` runs all eight; `--combo` picks some.

Needs openssl and OpenSSH (ssh-agent, ssh-add, ssh-keygen). HOME and XDG_CONFIG_HOME are redirected per host
under a temporary directory; the real ~/.config/capsule and systemd are never touched. Open questions are
marked `Q<n>` and listed in the suite-questions file given to the owner. Exits non-zero listing every failed
section.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))

from coord_ops import OpsHost, coord_command, tls_request  # noqa: E402
from coord_successor import Coordinator  # noqa: E402
from coordination import decode_token  # noqa: E402
from host_service import stop_all  # noqa: E402
from launch_push import seed_of  # noqa: E402
from launch_service import Key, token_membership  # noqa: E402
from peer_messaging import available_port, request_id, set_probe, timestamp, wire  # noqa: E402
from persons import Agent, person_id, ssh_key, ssh_sign, ssh_verify  # noqa: E402

INTERVAL = 2
SLACK = 30.0
NOTIFY_INTERVAL = 600
NAMESPACE = b'capsule-person-v1'
MOVE_FIELDS = {'network_id', 'sequence', 'address', 'public_key', 'moved_at', 'signer', 'signature'}
PENDING_FIELDS = {'address', 'public_key', 'sequence', 'source', 'move_sequence'}
OUTPUT_FIELDS = {'network_id', 'sequence', 'coordinator', 'imported', 'previous_coordinator', 'pushed', 'members'}


class Failure(AssertionError):
    pass


def need(condition, rule, *detail):
    if not condition:
        raise Failure(f'hosted coordinator contract, slice 3: {rule}'
                      + (': ' + ' | '.join(repr(d)[:900] for d in detail) if detail else ''))


def eventually(predicate, timeout, rule, describe=None):
    """Poll predicate (exceptions count as false) until it holds; returns the seconds it took."""
    started = time.monotonic()
    last = None
    while True:
        try:
            if predicate():
                return time.monotonic() - started
        except Exception as error:  # a host restarting, a coordinator not yet up
            last = error
        if time.monotonic() - started > timeout:
            detail = None
            try:
                detail = describe() if describe else None
            except Exception as error:
                detail = repr(error)
            need(False, f'{rule} (within {timeout:.0f}s)', detail, repr(last) if last else 'timed out')
        time.sleep(0.25)


def rfc3339_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_time(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


# --- statements ---------------------------------------------------------------------------------------------

def move_lines(m):
    return ['capsule-coordinator-move-v1', m['network_id'], str(m['sequence']), m['address'], m['public_key'],
            m['moved_at']]


def sign_bytes(key, data):
    """key's raw Ed25519 signature over data, through OpenSSL."""
    message = key.directory / f'{secrets.token_hex(6)}.bin'
    message.write_bytes(data)
    signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(key.pem), '-rawin', '-in',
                                str(message)], check=True, capture_output=True, timeout=10).stdout
    message.unlink()
    assert len(signature) == 64
    return signature


def _string(value):
    return struct.pack('>I', len(value)) + value


def sshsig(key, lines):
    """The SSHSIG blob (namespace capsule-person-v1, sha512) by key over the lines, built from the format."""
    message = '\n'.join(lines).encode()
    signed = b'SSHSIG' + _string(NAMESPACE) + _string(b'') + _string(b'sha512') + \
        _string(hashlib.sha512(message).digest())
    signature = sign_bytes(key, signed)
    public = _string(b'ssh-ed25519') + _string(key.public)
    blob = b'SSHSIG' + struct.pack('>I', 1) + _string(public) + _string(NAMESPACE) + _string(b'') + \
        _string(b'sha512') + _string(_string(b'ssh-ed25519') + _string(signature))
    return base64.b64encode(blob).decode()


def root_move(root, network_id, sequence, address, public_key, moved_at=None):
    m = {'network_id': network_id, 'sequence': sequence, 'address': address, 'public_key': public_key,
         'moved_at': moved_at or rfc3339_now(), 'signer': 'root'}
    m['signature'] = base64.b64encode(sign_bytes(root, '\n'.join(move_lines(m)).encode())).decode()
    return m


def admin_move(ssh_private, person_b64, network_id, sequence, address, public_key, directory):
    m = {'network_id': network_id, 'sequence': sequence, 'address': address, 'public_key': public_key,
         'moved_at': rfc3339_now(), 'signer': person_b64}
    m['signature'] = ssh_sign(move_lines(m), ssh_private, directory)
    return m


def raw_verify(public_b64, lines, signature_b64, directory):
    key_der = directory / f'{secrets.token_hex(6)}.pub.der'
    pem, msg, sig = key_der.with_suffix('.pem'), key_der.with_suffix('.msg'), key_der.with_suffix('.sig')
    key_der.write_bytes(bytes.fromhex('302a300506032b6570032100') + base64.b64decode(public_b64))
    subprocess.run(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', str(key_der), '-out', str(pem)],
                   check=True, capture_output=True, timeout=10)
    msg.write_bytes('\n'.join(lines).encode())
    sig.write_bytes(base64.b64decode(signature_b64))
    result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(pem), '-rawin', '-in',
                             str(msg), '-sigfile', str(sig)], capture_output=True, timeout=10)
    for p in (key_der, pem, msg, sig):
        p.unlink()
    return result.returncode == 0


VECTOR = {
    'root_seed': 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
    'root_public': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
    'network_id': 'net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e',
    'person_seed': 'BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=',
    'person_public': 'bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=',
    'host_public': '7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=',
    'new_public': 'ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=',
    'address': 'coord.example.com:7400',
    'moved_at': '2026-10-10T00:00:00Z',
}


def check_vector(keys):
    root = Key(keys, base64.b64decode(VECTOR['root_seed']))
    person = Key(keys, base64.b64decode(VECTOR['person_seed']))
    need(root.b64 == VECTOR['root_public'] and person.b64 == VECTOR['person_public'], 'vector seeds derive their keys')
    need('net_' + hashlib.sha256(root.public).hexdigest() == VECTOR['network_id'], 'the vector network ID')
    # Self-checks of this suite's encodings against the coordination contract's vectors.
    revoke = ['capsule-revoke-host-v1', VECTOR['network_id'], VECTOR['host_public'], '2026-10-07T00:00:00Z']
    need(base64.b64encode(sign_bytes(root, '\n'.join(revoke).encode())).decode() ==
         '651E7LldaU/s+qQra4F9e6uJ5sDvFfYI0Nc+x4WdmfciBtVME9wp+fNq034EGTB2utFOLkPxhOg3k8gujAI7Ag==',
         'self-check: the host revocation vector (raw root signature)')
    bind = ['capsule-host-bind-v1', VECTOR['network_id'], VECTOR['person_public'], VECTOR['host_public'],
            '2026-10-08T00:00:00Z']
    need(sshsig(person, bind) ==
         'U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABADAULCAWp02fy0fuxtv6fhaI8PHqxyBPr6SzVcTupgU0xsTYIMciLKFSVOaqYIOshUcKvNhgbAmBsiz6Cbe7UBw==',
         'self-check: the host binding SSHSIG vector')
    m = root_move(root, VECTOR['network_id'], 1, VECTOR['address'], VECTOR['new_public'], VECTOR['moved_at'])
    need(raw_verify(root.b64, move_lines(m), m['signature'], keys), 'the computed root move verifies')
    lines = move_lines(m)
    admin_sig = sshsig(person, lines)
    # Cross-check the SSHSIG with OpenSSH itself.
    ssh_public = 'ssh-ed25519 ' + base64.b64encode(_string(b'ssh-ed25519') + _string(person.public)).decode()
    ssh_verify(lines, admin_sig, ssh_public, keys)
    VECTOR['computed'] = {'lines': lines, 'root_signature': m['signature'], 'administrator_signature': admin_sig}
    # The contract's move test vector (slice 3, The move statement).
    contract_root = Key(keys, base64.b64decode('BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ='))
    contract_net = 'net_' + hashlib.sha256(contract_root.public).hexdigest()
    need(contract_net == 'net_c5b940ed3f65c391965de8295fc5d25f474fa57b48d36eb10ad363b8539c1b79',
         'the contract move vector: the root seed derives the network', contract_net)
    cm = root_move(contract_root, contract_net, 1, 'coord.example.com:7400',
                   'bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=', '2026-10-10T00:00:00Z')
    need(cm['signature'] == 'IBmzYpyWsCU4IE5B4HhL9CMjdn2WlWUYWuJNjxWaoZ03ynlz2pCGzJ5i8Nj1LvEXm1936XDTB3o23GnvHN14CQ==',
         'the contract move test vector: the root\'s raw signature over the move lines', cm['signature'])
    VECTOR['computed']['contract_vector'] = 'reproduced'
    return (f'contract vector reproduced; extra vector (genesis root AQEB...): root {m["signature"]}; '
            f'administrator (SSHSIG, person {VECTOR["person_public"]}) {admin_sig}')


# --- hosts and coordinators ---------------------------------------------------------------------------------

class MoveHost(OpsHost):
    """A daemon with a direct peer address (127.0.0.1:port, advertised), syncing every INTERVAL seconds."""

    def __init__(self, binary, state, home):
        super().__init__(binary, state, home)
        self.interval = INTERVAL
        self._args()

    def _args(self):
        self.daemon_args = ('--peer-listen', self.address, '--coordination-interval', str(self.interval))

    def restart(self, interval=None):
        self.stop()
        if interval is not None:
            self.interval = interval
        self._args()
        return self.start()

    @property
    def running(self):
        return self.process is not None and self.process.poll() is None


class Combo:
    def __init__(self, suite, mover, other, joiner):
        self.suite = suite
        self.label = f'{mover}/{other}/{joiner}'
        b = suite.binaries
        self.impl = {'alice': mover, 'adam': mover, 'bob': other, 'dave': other, 'carol': joiner, 'erin': joiner}
        self.root = suite.root / f'combo-{mover}-{other}-{joiner}'
        self.root.mkdir()
        self.keys = suite.keys
        self.hosts, self.ids, self.agents_reg, self.grants = {}, {}, {}, {}
        for name, implementation in self.impl.items():
            h = MoveHost(b[implementation], self.root / name, self.root / f'user-{name}')
            self.hosts[name] = h
            suite.all_hosts.append(h)
        # adam runs `network move` with the other implementation's CLI against its daemon (CLI/daemon pairing).
        self.move_cli = {'adam': b['Rust' if mover == 'Go' else 'Go']}
        self.persons = {}
        self.ssh = {}
        for host, person in (('alice', 'pat'), ('adam', 'quinn'), ('bob', 'rhea'), ('dave', 'dan'), ('carol', 'cara'),
                             ('erin', 'eve')):
            directory = self.root / f'agent-{person}'
            directory.mkdir()
            self.ssh[person] = ssh_key(directory, person)
            agent = Agent(directory)
            agent.add(self.ssh[person][0])
            suite.ssh_agents.append(agent)
            self.hosts[host].sock = agent.socket
            self.persons[host] = person
        self.pid = {p: person_id(k[2]) for p, k in self.ssh.items()}
        self.c = {}
        self.bound = 2 * INTERVAL + suite.args.slack

    # helpers

    def coordinator(self, name, port=None):
        c = self.suite.coordinator(f'{self.label.replace("/", "-")}-{name}', self.root / f'coord-{name}')
        identity = c.serve(port or available_port())
        self.c[name] = c
        return c, identity['public_key']

    def start(self, name, interval=None):
        h = self.hosts[name]
        identity = h.restart(interval) if interval is not None else h.start()
        self.ids[name] = identity['id']
        return identity

    def record(self, name):
        status, body = self.hosts[name].call('GET', '/v1/networks')
        assert status == 200, (status, body)
        return {n['id']: n for n in body}.get(self.net)

    def pinned(self, name, address, key, error_null=True):
        r = self.record(name)
        return (r is not None and r.get('coordinator_address') == address and r.get('coordinator_public_key') == key
                and r.get('coordinator_pending') is None and (not error_null or r.get('last_sync_error') is None))

    def await_pin(self, names, coord, key, rule, timeout=None, address=None):
        address = address or coord.address
        since = time.monotonic()
        took = {}
        for name in names:
            eventually(lambda: self.pinned(name, address, key), (timeout or self.bound) - (time.monotonic() - since),
                       f'{rule}: {name} ({self.impl[name]}) pins {address} with coordinator_pending null and no sync '
                       'error', lambda: self.record(name))
            took[name] = round(time.monotonic() - since, 1)
        return took

    def members(self, name):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{self.net}/members')
        assert status == 200, (status, body)
        return {m['host_id'] for m in body}

    def persons_of(self, name):
        return {p['person_id']: p for p in self.hosts[name].cli('network', 'persons', self.net)}

    def groups_of(self, name):
        return {g['name']: g for g in self.hosts[name].cli('network', 'groups', self.net)}

    def map_at(self, coord, key=None):
        """The map a coordinator serves, through a sync by the raw watcher member (or another key)."""
        status, body = tls_request(coord.port, key or self.watcher, 'POST', f'/coord/v1/networks/{self.net}/sync',
                                   {'address': '', 'candidates': []})
        return status, body

    def coord_map(self, coord):
        status, body = self.map_at(coord)
        assert status == 200, (status, body)
        return body

    def peer_get(self, target, caller):
        return wire(self.hosts[target], {'seed_hex': seed_of(self.hosts[caller]).hex()}, 'GET',
                    f'/peer/v1/networks/{self.net}/move')

    def peer_post(self, target, seed, move):
        return wire(self.hosts[target], {'seed_hex': seed.hex()}, 'POST', f'/peer/v1/networks/{self.net}/move',
                    {'move': move})

    def post_move(self, coord, key, move):
        return tls_request(coord.port, key, 'POST', f'/coord/v1/networks/{self.net}/moves', {'move': move})

    def root_key(self):
        with sqlite3.connect(self.hosts['alice'].state / 'host.db') as db:
            seed = db.execute('SELECT root_seed FROM networks WHERE id = ?', (self.net,)).fetchone()[0]
        return Key(self.keys, bytes(seed))

    def agent(self, name):
        if name not in self.agents_reg:
            self.agents_reg[name] = self.hosts[name].cli('agent', 'register', '--name', 'mv', '--owner',
                                                         self.persons[name])
        return self.agents_reg[name]

    def send(self, sender, receiver, timeout=120, policy_agent=None):
        """A connected-only message (or a policy-cited one to policy_agent), retried until accepted."""
        s = self.hosts[sender]
        rid = request_id()
        if policy_agent is None:
            key = (receiver, sender)
            if key not in self.grants:
                self.grants[key] = self.hosts[receiver].grant({'id': self.ids[sender]}, self.agent(receiver),
                                                              allow=False)
            extra, agent = ['--grant', self.grants[key]['id']], self.agent(receiver)
        else:
            extra, agent = [], policy_agent
        out = s.cli('message', 'send', '--peer', self.ids[receiver], *extra, '--agent', agent['id'], '--deadline',
                    timestamp(), '--content', f'move {sender}->{receiver} {secrets.token_hex(4)}', '--request', rid)
        deadline = time.monotonic() + timeout
        while out['state'] != 'accepted' and time.monotonic() < deadline:
            time.sleep(1)
            out = s.cli('message', 'retry', '--peer', self.ids[receiver], rid)
        need(out['state'] == 'accepted', f'a {"policy-cited" if policy_agent else "connected-only"} message '
             f'{sender}→{receiver} is accepted', out)

    def move(self, name, coord, key, success=True):
        args = ('network', 'move', '--coordinator', coord if isinstance(coord, str) else coord.address,
                '--coordinator-key', key, '--network', self.net)
        h = self.hosts[name]
        argv = [self.move_cli.get(name, h.cli_binary), '--state', str(h.state), *args]
        result = h.run(argv=argv)
        if not success:
            return result
        need(result.returncode == 0, f'network move on {name} ({self.cli_pair(name)}) succeeds', result.returncode,
             result.stdout[-600:], result.stderr[-600:])
        return json.loads(result.stdout)

    def cli_pair(self, name):
        cli = self.move_cli.get(name, self.hosts[name].cli_binary)
        names = {v: k for k, v in self.suite.binaries.items()}
        return f'{names[cli]} CLI, {self.impl[name]} daemon'

    def local_move(self, name):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{self.net}/move')
        need(status == 200 and isinstance(body, dict) and set(body) == {'move', 'next_sequence'},
             'GET /v1/networks/{id}/move returns {move, next_sequence}', status, body)
        return body

    def check_output(self, out, sequence, coord, key, previous, pushed, rule):
        need(isinstance(out, dict) and set(out) == OUTPUT_FIELDS, f'{rule}: network move prints {{network_id, '
             'sequence, coordinator, imported, previous_coordinator, pushed, members}', out)
        need(out['network_id'] == self.net and out['sequence'] == sequence,
             f'{rule}: the move has sequence one more than the current one ({sequence})', out)
        need(out['coordinator'] == {'address': coord.address, 'public_key': key}, f'{rule}: coordinator is the new '
             '{address, public_key}', out)
        imported = out['imported']
        need(isinstance(imported, dict) and set(imported) == {'added', 'skipped'} and imported['added'] > 0
             and imported['skipped'] == 0, f'{rule}: imported {{added, skipped}}, nothing skipped (Q2)', imported)
        need(out['previous_coordinator'] == previous, f'{rule}: previous_coordinator is {previous}', out)
        others = len(self.members(self._mover)) - 1
        need(out['pushed'] == pushed and out['members'] == others,
             f'{rule}: pushed counts the {pushed} hosts that accepted the push; members counts the {others} other '
             'current member hosts', out)

    def check_move(self, m, sequence, coord, key, signer):
        need(isinstance(m, dict) and set(m) == MOVE_FIELDS, 'a move is a strict object with network_id, sequence, '
             'address, public_key, moved_at, signer, and signature', m)
        need(m['network_id'] == self.net and m['sequence'] == sequence and isinstance(m['sequence'], int)
             and m['address'] == coord.address and m['public_key'] == key, 'the move names the network, its '
             'sequence, and the new address and key', m)
        need(m['signer'] == signer, 'signer is root or the administrator\'s person_public_key', m, signer)

    def wait_members(self, names, ids, timeout=90):
        for name in names:
            eventually(lambda: ids <= self.members(name), timeout, f'{name} sees every member',
                       lambda: sorted(self.members(name)))

    def raw_member(self, coord, label):
        token = self.hosts['alice'].cli('network', 'invite', '--network', self.net, '--member', label,
                                        '--expires-at', timestamp(3600), '--host-only')['token']
        key = Key(self.keys)
        status, out = tls_request(coord.port, key, 'POST', f'/coord/v1/networks/{self.net}/members',
                                  {'membership': token_membership(token, key, self.keys), 'address': '',
                                   'candidates': []})
        need(status == 201, f'a raw member joins ({label})', status, out)
        return key

    # phases

    def setup(self):
        self.joined = {}
        c1, self.k1 = self.coordinator('c1')
        for name in self.hosts:
            self.start(name)
        a = self.hosts['alice']
        created = a.cli('network', 'create', 'moves', '--as', 'pat', '--coordinator', c1.address,
                        '--coordinator-key', self.k1)
        self.net = created['id']
        need(created.get('person') and created['person']['admitted'], 'the creator person is admitted', created)
        self.joined['alice'] = True
        for name in ('adam', 'bob', 'dave'):
            token = a.cli('invite', self.persons[name], '--network', self.net)['token']
            out = self.hosts[name].cli('join', token)
            need(out.get('id') == self.net, f'{name} joins', out)
            self.joined[name] = True
        # carol's invite is issued before any move and names C1.
        self.carol_token = a.cli('invite', 'cara', '--network', self.net)['token']
        a.cli('network', 'delegate-admin', '--network', self.net, '--person', 'quinn')
        self.watcher = self.raw_member(c1, 'watcher')
        self.victim = self.raw_member(c1, 'victim')
        gone = self.raw_member(c1, 'gone')
        eventually(lambda: gone.host_id in self.members('alice'), 60, 'alice sees the raw members')
        a.cli('network', 'revoke', '--network', self.net, '--host', gone.host_id)
        self.gone = gone
        a.cli('network', 'group', 'set', '--network', self.net, '--group', 'team', '--person', 'pat', '--person',
              'rhea')
        self.work = self.hosts['bob'].cli('agent', 'register', '--name', 'work', '--owner', 'rhea')
        p1 = self.hosts['bob'].cli('access', 'allow', '--network', self.net, '--agent', 'work', '--principal',
                                   'person:pat')
        self.policy_version = p1['version']
        everyone = {self.ids[n] for n in ('alice', 'adam', 'bob', 'dave')} | {self.watcher.host_id,
                                                                              self.victim.host_id}
        self.wait_members(('alice', 'adam', 'bob', 'dave'), everyone)

        def alice_holds_policy():
            status, value = a.call('GET', f'/v1/networks/{self.net}/policy?person={self.pid["rhea"]}')
            return status == 200 and value.get('version') == p1['version']
        eventually(alice_holds_policy, 60, 'alice holds rhea\'s policy (so the mover\'s import can carry it)')
        eventually(lambda: self.persons_of('adam')[self.pid['quinn']]['administrator'], 60,
                   'adam sees quinn as an administrator')
        for name in ('alice', 'bob'):
            r = self.record(name)
            need('coordinator_pending' in r and r['coordinator_pending'] is None, 'coordinator_pending is null when '
                 'nothing is pending', r)
        status, body = self.peer_get('alice', 'bob')
        need(status == 404, 'GET /peer/v1/networks/{network}/move is 404 without a move', status, body)
        status, body = self.peer_get('bob', 'alice')
        need(status == 404, 'GET .../move is 404 without a move (other implementation)', status, body)
        m = self.coord_map(c1)
        need('move' in m and m['move'] is None, 'the map gains move, null without one', sorted(m))
        for name in ('alice', 'bob'):
            local = self.local_move(name)
            need(local == {'move': None, 'next_sequence': 1}, f'{name}: without a move, move is null and '
                 'next_sequence 1', local)
        return f'alice/adam {self.impl["alice"]}, bob/dave {self.impl["bob"]}, carol/erin {self.impl["carol"]}'

    def help(self):
        for name in ('alice', 'bob', 'carol'):
            h = self.hosts[name]
            result = subprocess.run([h.cli_binary, 'help', 'advanced'], capture_output=True, text=True, timeout=10)
            need(result.returncode == 0 and any(line.strip().startswith('network move') for line in
                                                result.stdout.splitlines()),
                 f'network move is listed in help advanced ({self.impl[name]})', result.stdout[-600:])
        return 'listed'

    def root_move(self):
        c1 = self.c['c1']
        c2, self.k2 = self.coordinator('c2')
        a = self.hosts['alice']
        before = self.record('alice')
        # Refusals: an unreachable coordinator, and one presenting a key other than --coordinator-key.
        dead = f'127.0.0.1:{available_port()}'
        result = self.move('alice', dead, self.k2, success=False)
        need(result.returncode == 1, 'network move without a reachable new coordinator exits 1', result.returncode,
             result.stdout[-400:], result.stderr[-400:])
        result = self.move('alice', c2, Key(self.keys).b64, success=False)
        need(result.returncode == 1, 'network move to a coordinator presenting another key exits 1 with nothing changed',
             result.returncode, result.stdout[-400:], result.stderr[-400:])
        after = self.record('alice')
        need(all(after.get(k) == before.get(k) for k in ('coordinator_address', 'coordinator_public_key',
                                                         'coordinator_pending')),
             'a failed import changes nothing', before, after)
        status, _ = self.peer_get('alice', 'bob')
        need(status == 404, 'a failed move stores no move', status)
        need(self.coord_map(c1)['move'] is None, 'a failed move submits nothing to the current coordinator')
        status, body = self.map_at(c2)
        need(status == 403, 'a refused move imports nothing into the new coordinator (unknown network: 403)', status,
             body)

        self._mover = 'alice'
        out = self.move('alice', c2, self.k2)
        self.check_output(out, 1, c2, self.k2, 'accepted', 3, 'root move')
        need(self.pinned('alice', c2.address, self.k2), 'the mover syncs the new coordinator and switches its own pin',
             self.record('alice'))
        status, body = self.peer_get('alice', 'bob')
        need(status == 200 and isinstance(body, dict) and set(body) == {'move'}, 'GET .../move returns {move}',
             status, body)
        m1 = body['move']
        self.check_move(m1, 1, c2, self.k2, 'root')
        root = self.root_key()
        need(raw_verify(root.b64, move_lines(m1), m1['signature'], self.keys),
             'a root move carries a raw signature by the root over capsule-coordinator-move-v1, network_id, '
             'sequence, address, public_key, moved_at', m1)
        mine = root_move(root, self.net, 1, m1['address'], m1['public_key'], m1['moved_at'])
        need(mine['signature'] == m1['signature'], 'the suite\'s own encoding of the move lines reproduces the '
             'implementation\'s signature (Ed25519 is deterministic)', mine, m1)
        self.m1 = m1
        # The previous coordinator accepted it and keeps serving with move.
        old = self.coord_map(c1)
        need(old.get('move') == m1, 'the previous coordinator accepts the move and serves it on sync', old.get('move'))
        new = self.coord_map(c2)
        need(new.get('move') == m1, 'the new coordinator\'s map carries the imported move', new.get('move'))
        hosts = {self.ids[n] for n in ('alice', 'adam', 'bob', 'dave')} | {self.watcher.host_id, self.victim.host_id}
        need(hosts <= {e['host_id'] for e in new['members']} and self.gone.host_id not in
             {e['host_id'] for e in new['members']}, 'import carries the members, excluding the revoked host',
             [e['host_id'] for e in new['members']])
        need(any(r.get('kind') == 'host' and r.get('statement', {}).get('host_public_key') == self.gone.b64
                 for r in new.get('revocations', [])), 'import carries the revocation', new.get('revocations'))
        need({self.pid[p] for p in ('pat', 'quinn', 'rhea', 'dan')} <= {p['person_id'] for p in new['persons']},
             'import carries the persons', new.get('persons'))
        need({self.ssh['pat'][2], self.ssh['quinn'][2]} <= {d.get('person_public_key') for d in new['admins']},
             'import carries the administrator delegations', new.get('admins'))
        need(any(g.get('name') == 'team' for g in new['groups']), 'import carries the group', new.get('groups'))
        need(any(p.get('person_public_key') == self.ssh['rhea'][2] and p.get('version') == self.policy_version
                 for p in new['policies']), 'import carries the policy', new.get('policies'))
        took = self.await_pin(('adam', 'bob', 'dave'), c2, self.k2, 'root move: every member switches')
        listed = self.hosts['bob'].cli('network', 'members', self.net)
        need(hosts <= {m['host_id'] for m in listed}, 'network members lists every member at the new coordinator',
             listed)
        self.send('alice', 'bob')
        self.send('bob', 'alice')
        self.send('dave', 'adam')
        # Policies: a policy-cited message, then a new version reaching alice only through C2.
        self.send('alice', 'bob', policy_agent=self.work)
        p2 = self.hosts['bob'].cli('access', 'allow', '--network', self.net, '--agent', 'work', '--principal',
                                   'person:quinn')
        self.policy_version = p2['version']

        def policy_seen():
            status, value = a.call('GET', f'/v1/networks/{self.net}/policy?person={self.pid["rhea"]}')
            return status == 200 and value.get('version') == p2['version']
        eventually(policy_seen, self.bound, 'a policy update reaches another host through the new coordinator')
        self.send('adam', 'bob', policy_agent=self.work)
        # Change notifications: dave's interval sync is far off, so only a changed frame explains a prompt update.
        self.start('dave', NOTIFY_INTERVAL)
        eventually(lambda: self.pinned('dave', c2.address, self.k2), 30, 'dave keeps the new pin on restart')
        time.sleep(3)
        g = a.cli('network', 'group', 'set', '--network', self.net, '--group', 'team', '--person', 'pat', '--person',
                  'rhea', '--person', 'dan')
        notified = eventually(lambda: self.groups_of('dave')['team']['version'] == g['version'], 15,
                              'change notifications work at the new coordinator: dave learns a group change '
                              'without an interval sync', lambda: self.groups_of('dave'))
        self.start('dave', INTERVAL)
        return f'switch times {took}; notified in {notified:.1f}s'

    def old_invite(self):
        c1, c2 = self.c['c1'], self.c['c2']
        _, fields = decode_token(self.carol_token)
        need(fields['coordinator_address'] == c1.address and fields['coordinator_public_key'] == self.k1,
             'an invite issued before the move names the previous coordinator', fields)
        out = self.hosts['carol'].cli('join', self.carol_token)
        need(out.get('id') == self.net, 'a join with an invite issued before the move succeeds at the previous '
             'coordinator', out)
        self.joined['carol'] = True
        took = self.await_pin(('carol',), c2, self.k2, 'old invite: the joiner ends at the new coordinator')
        new = self.coord_map(c2)
        entry = next((e for e in new['members'] if e['host_id'] == self.ids['carol']), None)
        own = next(m for m in self.hosts['carol'].cli('network', 'members', self.net)
                   if m['host_id'] == self.ids['carol'])
        need(entry is not None and entry.get('membership') == own.get('membership'),
             'the joiner\'s membership is at the new coordinator', entry, own)
        eventually(lambda: self.ids['carol'] in self.members('bob'), self.bound, 'other members see the joiner')
        self.send('carol', 'bob')
        self.send('bob', 'carol')
        return f'carol switched in {took["carol"]}s'

    def precedence(self):
        c2 = self.c['c2']
        dead = f'127.0.0.1:{available_port()}'
        c2.stop()
        s = c2.append(dead, new_key=True)
        # Identity 0 keeps serving at its address; nothing listens at the successor's.
        c2.serve(available_port(), {0: self.c2_port})
        want = {'address': dead, 'public_key': s['public_key'], 'sequence': 1, 'source': 'successor',
                'move_sequence': None}
        running = ('alice', 'adam', 'bob', 'carol', 'dave')

        def successor_pending(name):
            r = self.record(name)
            return r['coordinator_pending'] == want and r['coordinator_public_key'] == self.k2
        for name in running:
            eventually(lambda: successor_pending(name), self.bound, f'{name} records the successor as pending with '
                       'source successor and move_sequence null', lambda: self.record(name))
        self.hosts['dave'].stop()
        c3, self.k3 = self.coordinator('c3')
        self._mover = 'adam'
        out = self.move('adam', c3, self.k3)
        self.check_output(out, 2, c3, self.k3, 'accepted', 3, 'administrator move')
        need(self.pinned('adam', c3.address, self.k3), 'the administrator\'s host switches its own pin',
             self.record('adam'))
        status, body = self.peer_get('adam', 'bob')
        need(status == 200, 'GET .../move on the mover', status, body)
        m2 = body['move']
        self.check_move(m2, 2, c3, self.k3, self.ssh['quinn'][2])
        ssh_verify(move_lines(m2), m2['signature'], self.ssh['quinn'][1], self.keys)
        mine = ssh_sign(move_lines(m2), self.ssh['quinn'][0], self.keys)
        need(mine == m2['signature'], 'an administrator move is an SSHSIG over the move lines, equal to '
             'ssh-keygen -Y sign by the same key (deterministic)', mine, m2['signature'])
        self.m2 = m2
        old = self.coord_map(Port(self.c2_port))
        need(old.get('move') == m2, 'the previous coordinator accepted the administrator\'s move', old.get('move'))
        took = self.await_pin(('alice', 'bob', 'carol'), c3, self.k3, 'precedence: a pending move replaces a pending '
                              'successor')
        self.send('bob', 'adam')
        # dave missed the push; with C3 stopped it learns the move from C2's map and keeps it pending.
        c3.stop()
        self.start('dave')
        want_move = {'address': c3.address, 'public_key': self.k3, 'source': 'move', 'move_sequence': 2}

        def move_pending():
            p = self.record('dave')['coordinator_pending']
            return isinstance(p, dict) and set(p) == PENDING_FIELDS and \
                all(p[k] == v for k, v in want_move.items()) and p['sequence'] == p['move_sequence']
        eventually(move_pending, self.bound, 'a stopped host learns the move from the previous coordinator\'s map and '
                   'records it as pending with source move and move_sequence', lambda: self.record('dave'))
        r = self.record('dave')
        need(r['coordinator_address'] == self.c2_address and r['coordinator_public_key'] == self.k2,
             'the pin stays until the moved-to coordinator answers', r)
        for _ in range(4):
            time.sleep(INTERVAL)
            r = self.record('dave')
            need(move_pending() and r['coordinator_address'] == self.c2_address,
                 'a successor never replaces a pending move (C2 serves its successor chain on every sync)', r)
        c3.serve(c3.port)
        took.update(self.await_pin(('dave',), c3, self.k3, 'the pending move is followed once its coordinator '
                                   'answers'))
        # A successor of the moved-to coordinator is followed afterwards.
        c2.stop()
        c3.stop()
        p3 = c3.port
        p3b = available_port()
        s3 = c3.append(f'127.0.0.1:{p3b}')
        need(s3['public_key'] == self.k3, 'an address change keeps the key', s3)
        c3.serve(p3b, {0: p3})
        took.update(self.await_pin(running, c3, self.k3, 'a successor of the moved-to coordinator is followed'))
        self.send('dave', 'carol')
        return f'switch times {took}'

    def refusals(self):
        c3 = self.c['c3']
        root = self.root_key()
        stranger_ssh = ssh_key(self.keys, f'stranger-{secrets.token_hex(3)}')
        target = Key(self.keys).b64
        address = f'127.0.0.1:{available_port()}'
        cases = (
            ('an equal sequence', root_move(root, self.net, 2, address, target), 409),
            ('a lower sequence', root_move(root, self.net, 1, address, target), 409),
        )
        for what, m, code in cases:
            status, body = self.post_move(c3, self.watcher, m)
            need(status == code, f'POST .../moves with {what} is refused with {code}', status, body)
        bad = root_move(root, self.net, 3, address, target)
        raw = base64.b64decode(bad['signature'])
        bad['signature'] = base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode()
        invalid = (
            ('a bad signature', bad),
            ('an invalid address', root_move(root, self.net, 3, 'not an address', target)),
            ('a signer that is not an administrator', admin_move(stranger_ssh[0], stranger_ssh[2], self.net, 3,
                                                                 address, target, self.keys)),
            ('a root signer field with an administrator\'s signature',
             dict(admin_move(self.ssh['quinn'][0], self.ssh['quinn'][2], self.net, 3, address, target, self.keys),
                  signer='root')),
        )
        for what, m in invalid:
            status, body = self.post_move(c3, self.watcher, m)
            need(status == 400, f'POST .../moves with {what} is refused with 400', status, body)
            status, body = self.peer_post('bob', seed_of(self.hosts['alice']), m)
            need(status == 400, f'the peer route refuses a move with {what} with 400', status, body)
        stranger = Key(self.keys)
        status, body = self.post_move(c3, stranger, root_move(root, self.net, 3, address, target))
        need(status == 403, 'POST .../moves from a non-member is refused with 403', status, body)
        need(self.coord_map(c3).get('move') == self.m2, 'refused moves leave the stored move')
        # The peer route: a host known as a manual peer but not a member of the network is refused.
        self.hosts['alice'].cli('peer', 'add', '--id', stranger.host_id, '--public-key', stranger.b64, '--address',
                                '127.0.0.1:9')
        status, body = wire(self.hosts['alice'], {'seed_hex': stranger.seed.hex()}, 'GET',
                            f'/peer/v1/networks/{self.net}/move')
        need(status == 403, 'GET .../move from a host that is not a member is refused with 403', status, body)
        status, body = wire(self.hosts['alice'], {'seed_hex': stranger.seed.hex()}, 'POST',
                            f'/peer/v1/networks/{self.net}/move', {'move': self.m2})
        need(status == 403, 'POST .../move from a host that is not a member is refused with 403', status, body)
        # A valid move that is not higher: 200, and the held move is kept.
        for receiver, caller in (('bob', 'alice'), ('alice', 'bob')):
            status, body = self.peer_post(receiver, seed_of(self.hosts[caller]), self.m1)
            need(status == 200, f'POST .../move with a valid lower move returns 200 ({self.impl[receiver]})', status,
                 body)
        for name in ('alice', 'bob'):
            status, body = self.peer_get(name, 'carol')
            need(status == 200 and body.get('move') == self.m2, f'{name} keeps and serves its latest valid move', status,
                 body)
            local = self.local_move(name)
            need(local['move'] == self.m2 and local['next_sequence'] == 3, f'{name}: GET /v1/networks/{{id}}/move '
                 'gives the latest valid move and next_sequence one more than the applied and held sequences', local)
        # The local POST route: a host without the root seed refuses an unsigned move; a signed move naming another
        # coordinator than the request is refused with 400.
        other = f'127.0.0.1:{available_port()}'
        status, body = self.hosts['bob'].call('POST', f'/v1/networks/{self.net}/move',
                                              {'coordinator_address': other, 'coordinator_public_key': target,
                                               'move': None})
        need(status == 403, 'POST /v1/networks/{id}/move with move null on a host without the root seed: 403',
             status, body)
        signed = admin_move(self.ssh['quinn'][0], self.ssh['quinn'][2], self.net, 3, address, target, self.keys)
        status, body = self.hosts['adam'].call('POST', f'/v1/networks/{self.net}/move',
                                               {'coordinator_address': other, 'coordinator_public_key': target,
                                                'move': signed})
        need(status == 400, 'POST /v1/networks/{id}/move refuses a signed move naming another address than the '
             'request with 400', status, body)
        need(self.pinned('adam', c3.address, self.k3, error_null=False), 'a refused local move changes nothing',
             self.record('adam'))
        return f'{len(cases) + len(invalid) + 1} coordinator refusals'

    def stopped_previous(self):
        c1, c3 = self.c['c1'], self.c['c3']
        self.hosts['dave'].stop()
        c3.stop()
        self._mover = 'adam'
        out = self.move('adam', c1, self.k1)
        self.check_output(out, 3, c1, self.k1, 'unreachable', 3, 'move with the previous coordinator stopped')
        need(self.pinned('adam', c1.address, self.k1), 'the mover switches', self.record('adam'))
        took = self.await_pin(('alice', 'bob', 'carol'), c1, self.k1, 'members learn the move from the mover\'s push')
        status, body = self.peer_get('bob', 'alice')
        need(status == 200 and body['move']['sequence'] == 3, 'a pushed move is stored and served', status, body)
        self.m3 = body['move']
        # dave missed the push; its pinned coordinator is down: peer lookup after three failed intervals.
        self.start('dave')
        took.update(self.await_pin(('dave',), c1, self.k1, 'a member learns the move by peer lookup after its syncs '
                                   'fail', timeout=6 * INTERVAL + self.bound))
        self.send('dave', 'alice')
        self.send('carol', 'adam')
        return f'switch times {took}'

    def repair(self):
        c1 = self.c['c1']
        backup = self.root / 'c1-backup.db'
        result = coord_command(c1.binary, c1.state, 'backup', str(backup))
        need(result.returncode == 0, 'backup of the running coordinator', result.returncode, result.stderr[-400:])
        a, b = self.hosts['alice'], self.hosts['bob']
        token = a.cli('invite', 'eve', '--network', self.net)['token']
        out = self.hosts['erin'].cli('join', token)
        need(out.get('id') == self.net and out.get('person') and out['person']['admitted'], 'erin joins with a '
             'person', out)
        self.joined['erin'] = True
        for name in ('alice', 'bob'):
            eventually(lambda: self.pid['eve'] in self.persons_of(name), self.bound, f'{name} sees the new person')
        g = a.cli('network', 'group', 'set', '--network', self.net, '--group', 'late', '--person', 'eve')
        p = b.cli('access', 'allow', '--network', self.net, '--agent', 'work', '--principal', 'person:eve')
        self.policy_version = p['version']
        a.cli('network', 'revoke', '--network', self.net, '--host', self.victim.host_id)
        eve = self.pid['eve']

        def complete(m):
            return (self.ids['erin'] in {e['host_id'] for e in m['members']}
                    and self.victim.host_id not in {e['host_id'] for e in m['members']}
                    and eve in {x['person_id'] for x in m['persons']}
                    and any(x.get('name') == 'late' and x.get('version') == g['version'] for x in m['groups'])
                    and any(x.get('person_public_key') == self.ssh['rhea'][2] and x.get('version') == p['version']
                            for x in m['policies'])
                    and any(r.get('kind') == 'host' and r.get('statement', {}).get('host_public_key') ==
                            self.victim.b64 for r in m.get('revocations', [])))
        eventually(lambda: complete(self.coord_map(c1)), 60, 'the changes reach the coordinator before the restore')
        everyone = {self.ids[n] for n in ('alice', 'adam', 'bob', 'carol', 'dave', 'erin')}
        self.wait_members(('bob', 'carol', 'dave', 'erin'), everyone)
        for name in ('bob', 'carol', 'dave', 'erin'):
            eventually(lambda: 'late' in self.groups_of(name) and self.victim.host_id not in self.members(name),
                       60, f'{name} holds the group and the revocation')
        self.hosts['alice'].stop()
        self.hosts['adam'].stop()
        c1.stop()
        result = coord_command(c1.binary, c1.state, 'restore', '--replace', str(backup))
        need(result.returncode == 0, 'restore --replace from the older backup', result.returncode,
             result.stderr[-400:])
        stale = None
        c1.serve(c1.port)
        restored = datetime.now(timezone.utc)
        status, stale = self.map_at(c1)
        took = eventually(lambda: complete(self.coord_map(c1)), 90,
                          'repair: members, persons, a group, a policy, and a revocation made after the backup '
                          'reappear at the coordinator without administrator action', lambda: self.coord_map(c1))

        def erin_synced():
            r = self.record('erin')
            return r['last_sync_error'] is None and r['last_sync_at'] and parse_time(r['last_sync_at']) > restored
        eventually(erin_synced, self.bound, 'a member that joined after the backup syncs again',
                   lambda: self.record('erin'))
        for name in ('alice', 'adam'):
            self.start(name)
        self.await_pin(('alice', 'adam'), c1, self.k1, 'the administrators\' hosts sync again')
        # Hosts may apply the restored map before it is repaired; they see every member again once it is.
        self.wait_members(('alice', 'adam', 'bob', 'carol', 'dave', 'erin'), everyone)
        self.send('erin', 'bob')
        lacked = 'unknown' if status != 200 else ('lacked erin' if self.ids['erin'] not in
                                                   {e['host_id'] for e in stale['members']} else 'already repaired')
        return f'restored map at first sync: {lacked}; repaired in {took:.1f}s'

    def imports(self):
        c1 = self.c['c1']
        c5, _ = self.coordinator('c5')
        m = self.coord_map(c1)
        # Q5: the map as served, without its top-level identity fields (sent beside it) and successors.
        held = {k: v for k, v in m.items() if k not in ('network_id', 'name', 'root_public_key', 'successors')}
        body = {'name': m['name'], 'root_public_key': m['root_public_key'], 'map': held}
        stranger = Key(self.keys)
        path = '/coord/v1/networks/import'
        status, out = tls_request(c5.port, stranger, 'POST', path, body)
        need(status == 403, 'import by a caller that is not a member of the result is refused with 403 (unknown '
             'network)', status, out)
        # Forged entries: a member, a person, a group version, and a move.
        forged = json.loads(json.dumps(held))
        fake_host = Key(self.keys)
        entry = next(e for e in forged['members'] if e.get('membership'))
        fm = dict(entry, host_id=fake_host.host_id)
        fm['membership'] = dict(entry['membership'], host_public_key=fake_host.b64)
        forged['members'].append(fm)
        fake_person = ssh_key(self.keys, f'forged-{secrets.token_hex(3)}')
        pe = next(x for x in forged['persons'] if x.get('admission'))
        fp = dict(pe, person_id=person_id(fake_person[2]), person_public_key=fake_person[2], member='forged')
        fp['admission'] = dict(pe['admission'], person_public_key=fake_person[2], member='forged')
        forged['persons'].append(fp)
        gi = next(i for i, x in enumerate(forged['groups']) if x.get('name') == 'team')
        group = dict(forged['groups'][gi], version=forged['groups'][gi]['version'] + 10)
        lines = ['capsule-group-v1', group['network_id'], group['name'], str(group['version']), group['defined_at'],
                 *group['members']]
        group['signature'] = ssh_sign(lines, fake_person[0], self.keys)
        forged['groups'][gi] = group
        mv = dict(forged['move'], sequence=forged['move']['sequence'] + 5)
        forged['move'] = mv
        status, out = tls_request(c5.port, self.watcher, 'POST', path, dict(body, map=forged))
        need(status == 201 and isinstance(out, dict) and {'added', 'skipped', 'map'} <= set(out),
             'import of an unknown network by a member registers it: 201 {added, skipped, map} (so the refused '
             'import registered nothing)', status, out)
        need(out['skipped'] >= 4 and out['added'] > 0, 'entries that fail verification are skipped, not fatal (Q2)',
             out['added'], out['skipped'])
        r = out['map']
        need(fake_host.host_id not in {e['host_id'] for e in r['members']}, 'a forged member is skipped')
        need(person_id(fake_person[2]) not in {x['person_id'] for x in r['persons']}, 'a forged person is skipped')
        need(all(x['version'] != group['version'] for x in r['groups'] if x['name'] == 'team'),
             'a forged group version is skipped', r['groups'])
        need(r.get('move') != mv, 'a forged move is skipped', r.get('move'))
        need({e['host_id'] for e in m['members']} <= {e['host_id'] for e in r['members']},
             'the valid members are imported alongside skipped entries')
        # The same network again, as held: 200, adding what it lacked (the valid group version and move).
        status, out = tls_request(c5.port, self.watcher, 'POST', path, body)
        need(status == 200 and out.get('added', 0) > 0 and out['map'].get('move') == m['move']
             and any(x['name'] == 'team' and x['version'] == held['groups'][gi]['version'] for x in out['map']['groups']),
             'an import of an existing network returns 200 and adds what the coordinator lacks', status,
             out and {k: out.get(k) for k in ('added', 'skipped')})
        status, out = tls_request(c5.port, self.watcher, 'POST', path, body)
        need(status == 200 and out.get('added') == 0, 'a repeated import adds nothing it already has (Q2)', status,
             out and {k: out.get(k) for k in ('added', 'skipped')})
        status, out = tls_request(c5.port, stranger, 'POST', path, body)
        need(status == 403, 'import by a non-member is refused with 403 (existing network)', status, out)
        c5.stop()
        return 'non-member 403 twice; 4 forged entries skipped; repeat 200'

    def removed_admin(self):
        c1 = self.c['c1']
        c4, self.k4 = self.coordinator('c4')
        self.hosts['alice'].cli('network', 'remove-admin', '--network', self.net, '--person', 'quinn')
        for name in ('adam', 'bob', 'carol'):
            eventually(lambda: not self.persons_of(name)[self.pid['quinn']]['administrator'], self.bound,
                       f'{name} sees quinn removed as administrator')
        result = self.move('adam', c4, self.k4, success=False)
        need(result.returncode != 0, 'network move by a removed administrator is refused (the daemon answers 403; the CLI exits nonzero)', result.returncode,
             result.stdout[-400:])
        status, body = self.map_at(c4)
        need(status == 403, 'a refused move imports nothing', status, body)
        m = admin_move(self.ssh['quinn'][0], self.ssh['quinn'][2], self.net, 4, c4.address, self.k4, self.keys)
        status, body = self.post_move(c1, self.watcher, m)
        need(status == 400, 'the coordinator refuses a move by a removed administrator with 400', status, body)
        status, body = self.peer_post('bob', seed_of(self.hosts['alice']), m)
        need(status == 400, 'the peer route refuses a move by a removed administrator with 400', status, body)
        status, body = self.peer_post('alice', seed_of(self.hosts['bob']), m)
        need(status == 400, 'the peer route refuses a move by a removed administrator with 400 (mover '
             'implementation)', status, body)
        for name in ('alice', 'bob'):
            local = self.local_move(name)
            need(local['next_sequence'] == 4, f'{name}: next_sequence is one more than the higher of the applied '
                 'sequence and the latest held move, also after its signer was removed', local)
        names = [n for n in self.hosts]
        for _ in range(3):
            time.sleep(INTERVAL)
            for name in names:
                need(self.pinned(name, c1.address, self.k1, error_null=False), f'{name} stays switched after the '
                     'signer of its move stops being an administrator', self.record(name))
        return 'refused by the CLI, the coordinator, and both peer routes; every host stays switched'

    def exchanged(self):
        c1, c4 = self.c['c1'], self.c['c4']
        root = self.root_key()
        m4 = root_move(root, self.net, 4, c4.address, self.k4)
        for target, caller in (('bob', 'alice'), ('alice', 'bob')):
            status, body = self.peer_post(target, seed_of(self.hosts[caller]), m4)
            need(status == 200, f'POST .../move delivers a suite-signed move to {target} ({self.impl[target]}): 200',
                 status, body)
            status, body = self.peer_get(target, 'carol')
            need(status == 200 and body.get('move') == m4, f'{target} serves the delivered move', status, body)
        took = self.await_pin(('alice', 'bob'), c4, self.k4, 'a host whose new coordinator answers 403 imports and '
                              'switches')
        status, body = self.post_move(c1, self.watcher, m4)
        need(status == 200, 'only the mover submits a move: the previous coordinator lacks it and stores it (200)',
             status, body)
        took.update(self.await_pin(('adam', 'carol', 'dave', 'erin'), c4, self.k4,
                                   'every member follows the move served by the previous coordinator'))
        m = self.coord_map(c4)
        need({self.ids[n] for n in self.hosts} <= {e['host_id'] for e in m['members']} and m.get('move') == m4,
             'the new coordinator holds every member and the move', m)
        self.send('carol', 'bob')
        self.send('erin', 'alice')
        self.send('dave', 'adam')
        return f'switch times {took}'

    def run(self):
        s = self.suite
        tag = self.label
        if not s.section(f'{tag} setup', self.setup):
            return self.close()
        s.section(f'{tag} help advanced', self.help)
        for name, phase in (('root move', self.root_move), ('join with an invite issued before the move',
                                                             self.old_invite),
                            ('precedence over successors', self.precedence_wrapper),
                            ('sequence and signer refusals', self.refusals),
                            ('move with the previous coordinator stopped', self.stopped_previous),
                            ('repair after a restore from an older backup', self.repair),
                            ('import refusals', self.imports),
                            ('removed administrator', self.removed_admin),
                            ('exchanged move', self.exchanged)):
            if not s.section(f'{tag} {name}', phase):
                break
        self.close()

    def precedence_wrapper(self):
        c2 = self.c['c2']
        self.c2_port = c2.port
        self.c2_address = c2.address
        return self.precedence()

    def close(self):
        try:
            stop_all(tuple(self.hosts.values()))
        except Exception as error:
            self.suite.results.append((f'{self.label} shutdown', False, repr(error)))
            print(f'FAIL [{self.label} shutdown]: {error!r}', flush=True)
        for c in self.c.values():
            try:
                c.stop()
            except Exception:
                pass


class Port:
    def __init__(self, port):
        self.port = port


# --- the suite -----------------------------------------------------------------------------------------------

class Suite:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.binaries = {'Go': str(args.go), 'Rust': str(args.rust)}
        self.logs = root / 'logs'
        self.logs.mkdir()
        self.keys = root / 'keys'
        self.keys.mkdir()
        self.results = []
        self.coordinators = []
        self.all_hosts = []
        self.ssh_agents = []

    def section(self, name, function):
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=8)
            self.results.append((name, False, detail))
            print(f'FAIL [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}', flush=True)
        return True

    def coordinator(self, name, state):
        c = Coordinator(self.args.coord, state, self.logs, name)
        self.coordinators.append(c)
        return c

    def run(self):
        self.section('move test vector', lambda: check_vector(self.keys))
        if self.args.all:
            combos = [(m, o, j) for m in ('Go', 'Rust') for o in ('Go', 'Rust') for j in ('Go', 'Rust')]
        elif self.args.combo:
            combos = [tuple(c.split('/')) for c in self.args.combo]
        else:
            combos = [('Go', 'Rust', 'Rust'), ('Rust', 'Go', 'Go'), ('Go', 'Go', 'Rust'), ('Rust', 'Rust', 'Go')]
        for combo in combos:
            Combo(self, *combo).run()

    def close(self):
        try:
            stop_all(tuple(self.all_hosts))
        finally:
            for c in self.coordinators:
                try:
                    c.stop()
                except Exception:
                    if c.process is not None:
                        c.process.kill()
            for agent in self.ssh_agents:
                try:
                    agent.stop()
                except Exception:
                    pass

    def save_logs(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        for path in self.logs.iterdir():
            shutil.copy2(path, directory / path.name)
        for h in self.all_hosts:
            try:
                h.logs.seek(0)
                (directory / f'{h.state.parent.name}-{h.state.name}.log').write_bytes(h.logs.read())
            except (OSError, ValueError):
                pass


def main():
    global INTERVAL
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--coord', type=Path, required=True, help='capsule-coord')
    parser.add_argument('--go', type=Path, required=True, help='Go capsule-host')
    parser.add_argument('--rust', type=Path, required=True, help='Rust capsule-host')
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe (for the peer move route)')
    choices = [f'{m}/{o}/{j}' for m in ('Go', 'Rust') for o in ('Go', 'Rust') for j in ('Go', 'Rust')]
    parser.add_argument('--combo', action='append', choices=choices,
                        help='MOVER/OTHER/JOINER to run (repeatable); default four combinations, see above')
    parser.add_argument('--all', action='store_true', help='run all eight combinations')
    parser.add_argument('--interval', type=int, default=INTERVAL, help="hosts' --coordination-interval (seconds)")
    parser.add_argument('--slack', type=float, default=SLACK, help='seconds added to two sync intervals for waits')
    parser.add_argument('--logs', type=Path, help='save coordinator and host logs here when a section fails')
    args = parser.parse_args()
    INTERVAL = args.interval
    args.coord, args.go, args.rust = (p.resolve(strict=True) for p in (args.coord, args.go, args.rust))
    set_probe(args.probe.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix='capsule-coord-move-') as temporary:
        suite = Suite(args, Path(temporary))
        try:
            suite.run()
        except Exception:
            detail = traceback.format_exc(limit=8)
            suite.results.append(('suite', False, detail))
            print(f'FAIL [suite]: {detail}', flush=True)
        finally:
            if args.logs and not all(ok for _, ok, _ in suite.results):
                suite.save_logs(args.logs)
            try:
                suite.close()
            except Exception as error:
                suite.results.append(('shutdown', False, repr(error)))
                print(f'FAIL [shutdown]: {error!r}', flush=True)
    if 'computed' in VECTOR:
        print('==== move test vector (for the contract)', flush=True)
        print(json.dumps(VECTOR['computed'], indent=2), flush=True)
    failures = [(name, detail) for name, ok, detail in suite.results if not ok]
    print('==== summary', flush=True)
    for name, detail in failures:
        last = detail.strip().splitlines()[-1] if detail.strip() else ''
        print(f'FAIL [{name}]: {last[:1200]}', flush=True)
    if failures:
        raise SystemExit(f'{len(failures)} section(s) failed')
    print('PASS all sections', flush=True)


if __name__ == '__main__':
    main()
