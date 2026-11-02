#!/usr/bin/env python3
"""Serial public native test-file scheduling, final acceptance contract7e459e3.

No product inspection/imports: runtime resources are only enumerated, copied
and hashed. Every original test executes once, unchanged, through Claude's
public plugin-directory argument. No unsupported runner knobs or case timeout
changes. Raw CLI output/configuration remains private; only closed receipts
leave the fixture. The independent author performs source/static checks only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import time


EXPECTED_FILES = frozenset('tests/' + name + '.test.ts' for name in (
    'access-completion', 'access-review', 'adapter-review', 'admission-review',
    'invitation-preview', 'invitation-review', 'join-progress', 'join-review',
    'machine-owner', 'machine-request', 'machine-requester', 'native-entry',
    'native-message', 'native-task', 'new-identity', 'owner-finalization',
    'owner-review', 'owner-signing', 'peer-reachability', 'project-review',
    'readiness', 'requester-commit'))
EXPECTED_CASES = 440
GATE_SECONDS = 600
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


class Refused(Exception):
    """Contains only a fixed receipt category, never input/CLI diagnostics."""


def need(condition, category):
    if not condition:
        raise Refused(category)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def test_file(name):
    return name.endswith(('.test.ts', '.test.tsx'))


def tree(root):
    """Hash opaque regular files; refuse every linked/special source object."""
    need(stat.S_ISDIR(root.lstat().st_mode), 'source_or_mirror_not_directory')
    files = {}
    for directory, names, entries in os.walk(root, followlinks=False):
        for name in names:
            need(stat.S_ISDIR((Path(directory) / name).lstat().st_mode), 'linked_or_special_directory')
        for name in entries:
            path = Path(directory) / name
            need(stat.S_ISREG(path.lstat().st_mode), 'linked_or_special_file')
            relative = path.relative_to(root).as_posix()
            need(re.fullmatch(r'[A-Za-z0-9_.\-/]+', relative) is not None, 'unsupported_resource_name')
            files[relative] = digest(path)
    return files


def private_directory(path):
    path.mkdir(mode=0o700)
    return path


def environment(configuration):
    # Do not read/copy authentication variables or change the user's HOME.
    result = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG', 'USER', 'LOGNAME', 'SHELL')
              if key in os.environ}
    result.update(CLAUDE_CONFIG_DIR=str(configuration), DISABLE_UPDATES='1',
                  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1')
    need(result.get('HOME') == os.environ.get('HOME'), 'home_override')
    return result


def execute(argv, *, cwd, env, log, deadline):
    """Exactly one subprocess invocation; captured output is never echoed."""
    remaining = deadline - time.monotonic()
    need(remaining > 0, 'whole_gate_deadline')
    began = time.monotonic()
    with log.open('xb') as output:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
    return process.returncode, timed_out, round((time.monotonic() - began) * 1000)


def summary(log):
    """Read only public CLI summary counts, never publish raw CLI text."""
    need(log.stat().st_size <= 4 * 1024 * 1024, 'summary_output_oversized')
    text = ANSI.sub('', log.read_text(errors='replace'))
    found = re.findall(r'^\s*Ran (\d+) tests? across (\d+) files?\.', text, re.MULTILINE)
    need(len(found) == 1, 'summary_missing_or_ambiguous')
    cases, files = map(int, found[0])
    counts = {}
    for label in ('pass', 'fail', 'skip', 'todo'):
        matches = re.findall(r'^\s*(\d+) ' + label + r'\s*$', text, re.MULTILINE)
        need(len(matches) == 1 if label in ('pass', 'fail') else len(matches) <= 1,
             'summary_missing_or_ambiguous')
        counts[label] = int(matches[0]) if matches else 0
    need(files == 1 and cases > 0 and sum(counts.values()) == cases, 'summary_discovery_mismatch')
    return dict(cases=cases, discovered_files=files, passed=counts['pass'],
                failed=counts['fail'], skipped=counts['skip'], todo=counts['todo'])


def candidate_files(repo, plugin, deadline):
    relative = plugin.relative_to(repo).as_posix()
    result = subprocess.run(['git', 'ls-files', '-z', '--', relative], cwd=repo,
                            capture_output=True, timeout=min(5, max(.001, deadline - time.monotonic())))
    need(result.returncode == 0, 'candidate_inventory_unavailable')
    tracked = set()
    for item in result.stdout.decode('utf-8').split('\0'):
        if item:
            tracked.add(Path(item).relative_to(relative).as_posix())
    snapshot = tree(plugin)
    need(tracked and set(snapshot) == tracked, 'unknown_or_missing_candidate_resource')
    tests = {name for name in snapshot if test_file(name)}
    need(tests == EXPECTED_FILES and len(tests) == 22, 'candidate_test_discovery_mismatch')
    need('.claude-plugin/plugin.json' in snapshot and 'hooks/hooks.json' in snapshot,
         'required_plugin_resources_missing')
    return relative, snapshot


def copy_mirror(source, mirror, snapshot, selected):
    private_directory(mirror)
    wanted = {name: value for name, value in snapshot.items()
              if not test_file(name) or name == selected}
    for name in sorted(wanted):
        target = mirror / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(source / name, target, follow_symlinks=False)
    need(tree(mirror) == wanted, 'mirror_hash_or_inventory_mismatch')
    need({name for name in wanted if test_file(name)} == {selected},
         'mirror_test_discovery_mismatch')
    return wanted


def run(cli, plugin, work, receipt_path):
    began = time.monotonic()
    deadline = began + GATE_SECONDS - 2  # Reserve process cleanup/receipt writing.
    repo = Path(__file__).resolve().parents[1]
    receipt = dict(version=1, outcome='input_refused', expected_files=22, expected_cases=EXPECTED_CASES,
                   gate_seconds=GATE_SECONDS, files=[], sources={}, elapsed_ms=0)
    try:
        need(not work.exists(), 'work_directory_not_fresh')
        need(not receipt_path.exists(), 'receipt_already_exists')
        need(not work.is_relative_to(plugin) and not plugin.is_relative_to(work), 'overlapping_input_and_work')
        private_directory(work)
        logs = private_directory(work / 'private logs')
        configs = private_directory(work / 'private configurations')
        mirrors = private_directory(work / 'private mirrors')
        prefix, source = candidate_files(repo, plugin, deadline)
        receipt['sources'] = {prefix + '/' + name: value for name, value in sorted(source.items())}
        canonical = json.dumps(receipt['sources'], sort_keys=True, separators=(',', ':')).encode()
        receipt['source_manifest_sha256'] = hashlib.sha256(canonical).hexdigest()
        config = private_directory(configs / 'version')
        version_log = logs / 'version.log'
        code, expired, _ = execute([str(cli), '--version'], cwd=repo, env=environment(config),
                                   log=version_log, deadline=min(deadline, time.monotonic() + 30))
        need(code == 0 and not expired and re.fullmatch(r'2\.1\.303(?:\s+\(Claude Code\))?\s*',
             version_log.read_text()) is not None, 'pinned_native_version_unavailable')
        receipt['claude_version'] = '2.1.303'
        exhausted = False
        for index, selected in enumerate(sorted(EXPECTED_FILES), 1):
            result = dict(file=prefix + '/' + selected, outcome='not_run', exit_code=None, cases=None,
                          passed=None, failed=None, skipped=None, todo=None, elapsed_ms=0)
            receipt['files'].append(result)
            if exhausted or time.monotonic() >= deadline:
                exhausted = True
                result['outcome'] = 'whole_gate_deadline'
                continue
            try:
                need(tree(plugin) == source, 'candidate_source_changed')
                mirror = mirrors / str(index)
                expected = copy_mirror(plugin, mirror, source, selected)
                configuration = private_directory(configs / str(index))
                log = logs / (str(index) + '.log')
                code, expired, elapsed = execute([str(cli), 'plugin', 'test', str(mirror)], cwd=repo,
                    env=environment(configuration), log=log, deadline=deadline)
                result.update(exit_code=code, elapsed_ms=elapsed, log_sha256=digest(log))
                if expired:
                    exhausted = True
                    result['outcome'] = 'whole_gate_deadline'
                    continue
                need(tree(mirror) == expected, 'mirror_changed')
                need(tree(plugin) == source, 'candidate_source_changed')
                counts = summary(log)
                result.update(counts)
                result['outcome'] = 'passed' if code == 0 and counts['failed'] == 0 and counts['skipped'] == 0 and counts['todo'] == 0 else 'failed'
            except Refused as error:
                result['outcome'] = str(error)
                # Source changes cannot be frozen back or ignored for later files.
                if str(error) == 'candidate_source_changed':
                    break
            except (OSError, ValueError, subprocess.SubprocessError):
                result['outcome'] = 'local_operation_unavailable'
        need(tree(plugin) == source, 'candidate_source_changed')
        complete = [item for item in receipt['files'] if item['cases'] is not None]
        receipt['counts'] = {field: sum(item[field] for item in complete)
                             for field in ('cases', 'passed', 'failed', 'skipped', 'todo')}
        passed = len(receipt['files']) == len(complete) == 22 and receipt['counts']['cases'] == EXPECTED_CASES
        passed = passed and all(item['outcome'] == 'passed' and item['exit_code'] == 0 for item in receipt['files'])
        receipt['outcome'] = 'passed' if passed and time.monotonic() < deadline else 'failed'
    except Refused as error:
        receipt['outcome'] = str(error)
    except (OSError, ValueError, subprocess.SubprocessError):
        receipt['outcome'] = 'local_input_unavailable'
    receipt['elapsed_ms'] = round((time.monotonic() - began) * 1000)
    try:
        with receipt_path.open('x') as output:
            json.dump(receipt, output, sort_keys=True, indent=2)
            output.write('\n')
    except OSError:
        receipt['outcome'] = 'receipt_write_unavailable'
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['outcome'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--claude', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    # Do not resolve away a symlinked plugin root before the inventory check.
    raise SystemExit(run(args.claude.absolute(), args.plugin.absolute(), args.work_dir.absolute(),
                         args.receipt.absolute()))


if __name__ == '__main__':
    main()
