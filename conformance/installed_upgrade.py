#!/usr/bin/env python3
"""Genuine old-binary upgrade/complete-backup restore, final acceptance section1.

The author reads public contracts and independent fixtures only. All product
state is created by real supplied binaries through public CLI/owner APIs.
SQLite access is read-only. No compilation or runtime execution by the author.
Private fixtures, complete backups, observations and logs survive every attempt.
"""
import argparse
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time

from onboarding_bundle import safe_members, sha256_file, verify_checksum


GUIDED = frozenset({'onboarding_project_flows', 'onboarding_adapter_flows',
                    'onboarding_invitation_flows', 'onboarding_join_flows'})
CONVERSATIONS = frozenset({'conversations', 'conversation_messages', 'conversation_targets',
                          'conversation_invites', 'conversation_roster_outbound',
                          'conversation_notifications', 'conversation_reads', 'conversation_events'})
# Signed/retained history tables from the public storage contracts. Clock and
# transport scheduling are observed privately, but are not immutable history.
HISTORY = frozenset({'agents', 'sessions', 'activity', 'events', 'networks', 'policies', 'policy_edits',
                    'dec_contexts', 'dec_objects', 'dec_admissions', 'dec_restrictions',
                    'dec_activations', 'dec_heads', 'dec_highwater', 'dec_signers',
                    'dec_intents', 'dec_pending', 'dec_frames', 'dec_operations',
                    'dec_migrations', 'link_signers', 'link_highwater', 'link_features',
                    'link_objects', 'link_operations', 'link_frames', 'link_pending',
                    'link_device_keys'}) | CONVERSATIONS | GUIDED
BASE = '/v1/onboarding/project-flows'
PROCESSES = set()


class CheckFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def private_json(path, value):
    with open(path, 'w', encoding='utf-8', opener=lambda name, flags: os.open(name, flags, 0o600)) as target:
        json.dump(value, target, sort_keys=True, indent=2)
        target.write('\n')


class Budget:
    def __init__(self):
        self.began = time.monotonic()
        self.end = self.began + 120

    def remaining(self, maximum=10):
        remaining = self.end - time.monotonic()
        require(remaining > 0, 'complete upgrade suite exceeded 120 seconds')
        return min(maximum, remaining)


def alarm(_signum, _frame):
    for process in tuple(PROCESSES):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
    raise CheckFailure('complete upgrade suite exceeded 120 seconds')


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Host:
    def __init__(self, root, binary, budget):
        self.root, self.binary, self.budget = root, binary, budget
        self.state, self.config = root / 'state', root / 'config'
        root.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        self.config.mkdir(mode=0o700)
        # HOME is inherited unchanged. Do not borrow an SSH identity or helper.
        self.env = {key: value for key, value in os.environ.items()
                    if key not in {'SSH_AUTH_SOCK', 'PEERSPAN_TEST_CLOCK_OFFSET_FILE',
                                   'PEERSPAN_INTEGRATIONS_DIR'}}
        self.env.update(XDG_CONFIG_HOME=str(self.config), XDG_STATE_HOME=str(root / 'xdg state'),
                        XDG_RUNTIME_DIR=str(root / 'xdg runtime'))
        self.process, self.counter = None, 0

    def api(self, method, path, body=None, expected=200):
        self.counter += 1
        connection = UnixHTTP(self.state / 'admin.sock', self.budget.remaining())
        try:
            data = None if body is None else json.dumps(body).encode()
            connection.request(method, path, body=data,
                               headers={} if data is None else {'Content-Type': 'application/json'})
            response = connection.getresponse()
            payload = response.read()
            private_json(self.root / f'api-{self.counter:03d}.json',
                         {'method': method, 'path': path, 'status': response.status,
                          'body': payload.decode(errors='replace')})
            require(response.status == expected, 'public owner API returned unexpected status')
            return json.loads(payload)
        finally:
            connection.close()

    def cli(self, *args):
        self.counter += 1
        result = subprocess.run([str(self.binary), '--state', str(self.state), *args],
                                env=self.env, cwd=self.root, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=self.budget.remaining())
        private_json(self.root / f'cli-{self.counter:03d}.json',
                     {'args': args, 'code': result.returncode,
                      'stdout': result.stdout.decode(errors='replace'),
                      'stderr': result.stderr.decode(errors='replace')})
        require(result.returncode == 0, 'public CLI fixture operation failed')
        return json.loads(result.stdout)

    def launch(self):
        require(self.process is None, 'fixture daemon is already running')
        self.counter += 1
        with (self.root / f'daemon-{self.counter:03d}.log').open('ab') as log:
            self.process = subprocess.Popen([str(self.binary), '--state', str(self.state), 'run'],
                env=self.env, cwd=self.root, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True)
        PROCESSES.add(self.process)

    def start(self):
        self.launch()
        end = time.monotonic() + self.budget.remaining(8)
        while time.monotonic() < end:
            require(self.process.poll() is None, 'fixture daemon exited before owner API readiness')
            try:
                self.api('GET', '/v1/host')
                return
            except (OSError, http.client.HTTPException):
                time.sleep(min(0.05, self.budget.remaining()))
        raise CheckFailure('fixture daemon owner API did not become ready within 8 seconds')

    def stop(self):
        if self.process is None:
            return
        process, self.process = self.process, None
        try:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=self.budget.remaining(5))
                except (subprocess.TimeoutExpired, CheckFailure):
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=1)
                    raise CheckFailure('fixture daemon did not stop within 5 seconds') from None
            require(process.returncode == 0, 'fixture daemon stopped with a failure')
        finally:
            PROCESSES.discard(process)

    def refuse(self):
        before = databases(self.state)
        self.launch()
        process = self.process
        try:
            try:
                code = process.wait(timeout=self.budget.remaining(5))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
                raise CheckFailure('old binary did not refuse schema28 within 5 seconds') from None
            require(code != 0, 'old binary opened the upgraded schema28')
        finally:
            self.process = None
            PROCESSES.discard(process)
        require(databases(self.state) == before,
                'old-binary refusal mutated database bytes, modes, schema or records')


def tree(root):
    """Complete directory/file inventory with modes and hashes, never file data."""
    value = {}
    for path in [root, *sorted(root.rglob('*'))]:
        mode = path.lstat().st_mode
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode),
                'stopped state/config contains a link, socket or special file')
        value[path.relative_to(root).as_posix()] = {
            'mode': stat.S_IMODE(mode), 'kind': 'directory' if stat.S_ISDIR(mode) else 'file',
            'sha256': sha256_file(path) if stat.S_ISREG(mode) else None}
    return value


def database(state):
    matches = []
    for path in sorted(state.rglob('*.db')):
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                matches.append(path)
    require(len(matches) == 1, 'fixture does not have exactly one public host database')
    return matches[0]


def logical(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)) as db:
        db.execute('BEGIN')
        value = {'version': db.execute('PRAGMA user_version').fetchone()[0],
                 'schema': tuple(db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name')),
                 'tables': {}}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            quoted = '"' + name.replace('"', '""') + '"'
            value['tables'][name] = tuple(sorted(db.execute(f'SELECT * FROM {quoted}'), key=repr))
        return value


def databases(state):
    # Compare the physical database and SQLite sidecars, as well as every
    # logical record/schema. Read only after a daemon has exited.
    files = {str(path.relative_to(state)): (stat.S_IMODE(path.stat().st_mode), sha256_file(path))
             for path in state.rglob('*') if path.is_file()
             and (path.suffix == '.db' or path.name.endswith(('.db-wal', '.db-shm', '.db-journal')))}
    records = {str(path.relative_to(state)): logical(path) for path in state.rglob('*.db')}
    return files, records


def observations(host, network, agent, session, conversation=None):
    result = {name: host.api('GET', path) for name, path in {
        'identity': '/v1/host', 'networks': '/v2/networks',
        'network': f'/v2/networks/{network}', 'members': f'/v2/networks/{network}/members',
        'persons': f'/v2/networks/{network}/persons', 'provider': f'/v2/networks/{network}/provider',
        'catalog': f'/v2/networks/{network}/catalog',
        'access': f'/v2/networks/{network}/access-versions',
        'agent': f'/v1/agents/{agent}', 'agents': '/v1/agents',
        'session': f'/v1/sessions/{session}', 'sessions': '/v1/sessions',
        'activity': '/v1/activity?after=0&limit=1000'}.items()}
    if conversation:
        result['conversation'] = host.api('GET', f'/v1/conversations/{conversation}')
        result['messages'] = host.api('GET', f'/v1/conversations/{conversation}/messages?limit=100')
    return result


def proposal(host, label):
    return {'project_root': str(host.root / 'project' / label),
            'native_session_id': 'upgrade-' + label, 'integration': 'claude-code',
            'agent': {'kind': 'new', 'name': 'review-' + label, 'owner': 'fixture owner'}}


def review(host, label):
    request = proposal(host, label)
    value = host.api('POST', BASE, request, expected=201)
    require(value['state'] == 'review' and value['attachment'] is None
            and value['review_id'] and value['review']['expires_at'], 'new exact project review was not retained')
    require(all(value['review'][key] == request[key]
                for key in ('project_root', 'native_session_id', 'integration')),
            'new review changed its project/native-session/integration bindings')
    require(host.api('GET', BASE + '/' + value['flow_id']) == value,
            'new project review lookup changed its terms')
    return value


def preserve_history(before, after, *, fresh_flow=None):
    require(set(before['schema']) <= set(after['schema']), 'upgrade changed existing database definitions')
    for name in HISTORY & before['tables'].keys():
        rows = after['tables'].get(name)
        if name == 'onboarding_project_flows' and fresh_flow:
            require(rows is not None and len(rows) == len(before['tables'][name]) + 1
                    and set(before['tables'][name]) <= set(rows), 'upgrade lost pending project review history')
        else:
            require(rows == before['tables'][name], 'upgrade/restore changed original authority or history rows')


def one_history(work, label, old_binary, expected_version, installed, budget):
    host = Host(work / label, old_binary, budget)
    restored = None
    try:
        host.start()
        created = host.cli('network', 'create', 'upgrade-' + label, '--as', 'owner')
        require(created.get('mode') == 'decentralized', 'old binary did not create genuine DEC authority')
        network = created['id']
        agent = host.api('POST', '/v1/agents', {'name': 'retained-agent', 'owner': 'fixture owner'}, expected=201)
        session = host.api('POST', '/v1/sessions', {'agent_id': agent['id'], 'integration': 'metadata'}, expected=201)
        host.api('POST', '/v1/sessions/' + session['id'] + '/detach', {})
        conversation = None
        if label == 'main24':
            created_conversation = host.api('POST', '/v1/conversations',
                {'participants': [host.api('GET', '/v1/host')['id'] + '/' + agent['name']],
                 'title': 'retained upgrade history', 'content': 'retained conversation message'}, expected=201)
            conversation = created_conversation['conversation']['conversation_id']
            require(created_conversation['message'] is not None, 'main24 did not retain a genuine conversation message')
        pending = review(host, 'pending') if label == 'feature27' else None
        baseline_public = observations(host, network, agent['id'], session['id'], conversation)
        require(baseline_public['members']['members'] and baseline_public['persons']['persons']
                and baseline_public['catalog']['catalog']['objects'] and baseline_public['activity'],
                'old binary fixture lacks genuine membership/signed authority/history')
        host.stop()
        original = logical(database(host.state))
        tables = original['tables'].keys()
        require(original['version'] == expected_version, 'supplied old binary did not create its genuine schema version')
        require((CONVERSATIONS <= tables and not GUIDED & tables) if label == 'main24'
                else (GUIDED <= tables and not CONVERSATIONS & tables) if label == 'feature27'
                else not (CONVERSATIONS | GUIDED) & tables, 'old binary did not create the required genuine history')
        key = host.config / 'peerspan/person_ed25519'
        require(key.is_file() and stat.S_IMODE(key.stat().st_mode) == 0o600,
                'genuine generated person key is missing or not private')
        backup = host.root / 'complete preupgrade backup'
        backup.mkdir(mode=0o700)
        for name, source in (('state', host.state), ('config', host.config)):
            inventory = tree(source)
            shutil.copytree(source, backup / name, copy_function=shutil.copy2)
            require(tree(backup / name) == inventory, 'complete backup did not preserve every file mode/hash')
        manifests = {name: tree(backup / name) for name in ('state', 'config')}
        private_json(backup / 'manifest.json', manifests)
        private_json(host.root / 'original public observations.json', baseline_public)

        host.binary = installed
        host.start()
        require(observations(host, network, agent['id'], session['id'], conversation) == baseline_public,
                'installed upgrade changed public identity/network/agent/session/history')
        if pending:
            require(host.api('GET', BASE + '/' + pending['flow_id']) == pending,
                    'feature27 pending review ID, expiry or immutable terms changed')
        fresh = review(host, 'fresh')
        require(not pending or fresh['flow_id'] != pending['flow_id'], 'fresh review reused the retained pending flow')
        host.stop()
        upgraded = logical(database(host.state))
        require(upgraded['version'] == 28 and (CONVERSATIONS | GUIDED) <= upgraded['tables'].keys(),
                'installed upgrade did not create schema28 with both complete table histories')
        preserve_history(original, upgraded, fresh_flow=fresh)
        require(tree(host.config) == manifests['config'], 'upgrade changed original person-key configuration')
        host.binary = old_binary
        host.refuse()

        # A new empty directory receives the entire private backup. This is the
        # same logical host restored, never another person's key on a peer host.
        restored = Host(work / (label + ' restored'), old_binary, budget)
        for name in ('state', 'config'):
            destination = getattr(restored, name)
            destination.rmdir()
            shutil.copytree(backup / name, destination, copy_function=shutil.copy2)
            require(tree(destination) == manifests[name], 'complete restore changed a file mode/hash')
        require(logical(database(restored.state)) == original, 'restored database is not the complete original')
        restored.start()
        require(observations(restored, network, agent['id'], session['id'], conversation) == baseline_public,
                'old binary did not recover exact original public identity/authority/history')
        if pending:
            require(restored.api('GET', BASE + '/' + pending['flow_id']) == pending,
                    'old binary did not recover original pending project review')
        restored.stop()
        restored_records = logical(database(restored.state))
        require(restored_records['version'] == expected_version, 'old binary changed restored schema version')
        preserve_history(original, restored_records)
        require(tree(restored.config) == manifests['config'], 'old binary changed restored original key/config')
        return {'original_schema': expected_version, 'upgraded_schema': 28,
                'backup_mode_hash_match': True, 'public_history_retained': True,
                'pending_review_retained': pending is not None, 'new_review': True,
                'old_binary_refused_without_db_mutation': True, 'complete_restore_reopened': True,
                'backup_manifest_sha256': sha256_file(backup / 'manifest.json')}
    finally:
        host.stop()
        if restored:
            restored.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old23', type=Path, required=True)
    parser.add_argument('--main24', type=Path, required=True)
    parser.add_argument('--feature27', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--work', type=Path, help='new private directory retaining all evidence (default: private temporary directory)')
    args = parser.parse_args()
    os.umask(0o077)
    work = args.work.resolve() if args.work else Path(tempfile.mkdtemp(prefix='peerspan installed upgrade '))
    if args.work:
        work.mkdir(mode=0o700)
    report = {'suite': 'installed_upgrade', 'contract': 'guided-final-acceptance section1',
              'source_sha256': sha256_file(Path(__file__)), 'histories': {}, 'passed': False}
    stage = 'input_artifacts'
    budget = Budget()
    previous = signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, 120)
    try:
        require(hasattr(tarfile, 'data_filter'), 'safe installed archive extraction needs Python3.12+ or its data_filter backport')
        archive = args.archive.resolve()
        report['archive_sha256'] = verify_checksum(archive)
        binaries = {name: getattr(args, name).resolve() for name in ('old23', 'main24', 'feature27')}
        require(all(path.is_file() and os.access(path, os.X_OK) for path in binaries.values()),
                'all three genuine old binaries must be supplied as executable files')
        report['old_binary_sha256'] = {name: sha256_file(path) for name, path in binaries.items()}
        extracted = work / 'archive'
        extracted.mkdir(mode=0o700)
        with tarfile.open(archive, 'r:gz') as bundle:
            members, name = safe_members(bundle)
            bundle.extractall(extracted, members=members, filter='data')
        prefix = work / 'relocated installed prefix with spaces'
        (extracted / name).rename(prefix)
        release = json.loads((prefix / 'RELEASE.json').read_text())
        require(release.get('implementation') == 'rust' and release.get('os') == 'linux',
                'archive is not the final Linux Rust installed layout')
        installed = prefix / 'bin/peerspan-host'
        require(installed.is_file() and not installed.is_symlink() and os.access(installed, os.X_OK),
                'final installed archive lacks its real host executable')
        report['installed_binary_sha256'] = sha256_file(installed)
        for label, version in (('old23', 23), ('main24', 24), ('feature27', 27)):
            stage = label
            report['histories'][label] = one_history(work, label, binaries[label], version, installed, budget)
        report['passed'] = True
    except Exception as error:
        report['failure_stage'] = stage
        report['failure'] = str(error) if isinstance(error, CheckFailure) else type(error).__name__
    finally:
        for process in tuple(PROCESSES):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
        logs = {path.relative_to(work).as_posix(): sha256_file(path) for path in work.rglob('*')
                if path.is_file() and (path.suffix == '.log' or path.name.startswith(('api-', 'cli-')))}
        private_json(work / 'log hashes.json', logs)
        report['log_manifest_sha256'] = sha256_file(work / 'log hashes.json')
        report['elapsed_seconds'] = round(time.monotonic() - budget.began, 3)
        private_json(work / 'receipt.json', report)
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
