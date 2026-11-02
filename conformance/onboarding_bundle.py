#!/usr/bin/env python3
"""Verify a real relocated archive and explicitly install its local native plugin.

Guided section50; independent public contracts/CLI only. No host/model turn,
authority, conversation attachment or private native cache parsing. Root runs
this committed artifact consumer; the author performs static/fake audits only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import subprocess
import tarfile
import tempfile
import time


MODULES = ('access-completion', 'access', 'adapter', 'admission', 'finalization', 'invitation',
           'join-progress', 'join', 'machine-owner', 'machine-request', 'machine-requester', 'messages',
           'observation', 'owner', 'project', 'reachability', 'readiness', 'recipient', 'register',
           'requester-commit', 'tasks')
PLUGIN_FILES = frozenset({'.claude-plugin/plugin.json', 'README.md', 'hooks/hooks.json',
                         *(f'hooks/{name}.mjs' for name in MODULES)})
PLUGIN_RELATIVE = Path('share/peerspan/integrations/claude-onboarding')
PLUGIN_ID = 'peerspan@peerspan-bundled'


class CheckFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_checksum(path):
    checksum = Path(str(path) + '.sha256').read_text()
    digest = sha256_file(path)
    require(checksum == f'{digest}  {path.name}\n', 'archive/checksum pair does not match')
    return digest


def safe_members(archive):
    members = archive.getmembers()
    require(bool(members), 'archive is empty')
    roots, names = set(), set()
    for member in members:
        path = PurePosixPath(member.name)
        require(bool(path.parts) and not path.is_absolute() and '..' not in path.parts
                and '\\' not in member.name and not any(ord(char) < 32 or ord(char) == 127 for char in member.name),
                'archive contains an unsafe member name')
        require(str(path) not in names, 'archive contains a duplicate member')
        names.add(str(path)); roots.add(path.parts[0])
        require(member.isdir() or member.isfile() or member.issym() or member.islnk(), 'archive contains a special file')
        if member.issym() or member.islnk():
            target = PurePosixPath(member.linkname)
            require(not target.is_absolute() and bool(target.parts), 'archive contains an unsafe link')
            linked = target if member.islnk() else path.parent / target
            normalized = PurePosixPath(posixpath.normpath(str(linked)))
            require(bool(normalized.parts) and normalized.parts[0] == path.parts[0], 'archive link escapes its named root')
    require(len(roots) == 1, 'archive must have one named root')
    return members, next(iter(roots))


def validate_marketplace(value):
    require(type(value) is dict and value.get('name') == 'peerspan-bundled'
            and value.get('owner') == {'name': 'Peerspan'}
            and type(value.get('description')) is str and bool(value['description'].strip())
            and value.get('plugins') == [{'name': 'peerspan', 'source': './integrations/claude-onboarding'}],
            'bundled marketplace does not have exact local source/owner/name/description')


def validate_layout(prefix):
    metadata = json.loads((prefix / 'RELEASE.json').read_text())
    require(type(metadata) is dict and metadata.get('implementation') == 'rust' and metadata.get('os') == 'linux'
            and type(metadata.get('version')) is str and bool(metadata['version']), 'invalid host release metadata')
    marketplace = prefix / 'share/peerspan'
    plugin = prefix / PLUGIN_RELATIVE
    for directory in (marketplace, marketplace / '.claude-plugin', plugin, plugin / '.claude-plugin', plugin / 'hooks'):
        require(stat.S_ISDIR(directory.lstat().st_mode), 'required bundled directory is linked or unavailable')
    files, directories = set(), set()
    for path in plugin.rglob('*'):
        relative = path.relative_to(plugin).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            directories.add(relative)
        else:
            require(stat.S_ISREG(mode), 'bundled plugin contains a link or special file')
            files.add(relative)
    require(files == PLUGIN_FILES and directories == {'.claude-plugin', 'hooks'}, 'bundled plugin inventory is not exact')
    manifest = json.loads((plugin / '.claude-plugin/plugin.json').read_text())
    require(type(manifest) is dict and manifest.get('name') == 'peerspan' and manifest.get('version') == metadata['version'],
            'plugin version/name does not match this release')
    marketplace_file = marketplace / '.claude-plugin/marketplace.json'
    require(stat.S_ISREG(marketplace_file.lstat().st_mode), 'marketplace manifest is not a regular file')
    validate_marketplace(json.loads(marketplace_file.read_text()))
    binary, short = prefix / 'bin/peerspan-host', prefix / 'bin/peerspan'
    require(stat.S_ISREG(binary.lstat().st_mode) and os.access(binary, os.X_OK), 'installed host binary is unavailable')
    require(short.is_symlink() and os.readlink(short) == 'peerspan-host' and os.access(short, os.X_OK), 'short executable is not the relocatable host link')
    hashes = {relative: sha256_file(plugin / relative) for relative in PLUGIN_FILES}
    hashes['marketplace'] = sha256_file(marketplace_file)
    hashes['release'] = sha256_file(prefix / 'RELEASE.json')
    return metadata, marketplace, plugin, short, hashes


def native(cli, args, *, operation, environment, cwd, deadline, as_json=False):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'native installation exceeded the whole-check deadline')
    try:
        result = subprocess.run([str(cli), *args], env=environment, cwd=cwd,
            capture_output=True, text=True, timeout=min(30, remaining))
    except subprocess.TimeoutExpired:
        raise CheckFailure('native ' + operation + ' timed out') from None
    require(result.returncode == 0, 'native ' + operation + ' refused (nonzero exit)')
    if not as_json:
        return result.stdout
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise CheckFailure('native ' + operation + ' did not return public JSON') from None


def check_bundle(archive_path, cli):
    require(hasattr(tarfile, 'data_filter'), 'safe extraction requires Python3.12+ or a data_filter backport')
    deadline = time.monotonic() + 120
    archive_hash = verify_checksum(archive_path)
    with tempfile.TemporaryDirectory(prefix='peerspan native bundle ') as temporary:
        work = Path(temporary); work.chmod(0o700)
        with tarfile.open(archive_path, 'r:gz') as archive:
            members, original_name = safe_members(archive)
            archive.extractall(work, members=members, filter='data')
        prefix = work / 'relocated Peerspan prefix with spaces'
        (work / original_name).rename(prefix)
        metadata, marketplace, plugin, executable, snapshot = validate_layout(prefix)
        config, cwd = work / 'private Claude configuration', work / 'empty native workspace'
        config.mkdir(mode=0o700); cwd.mkdir(mode=0o700)
        environment = dict(os.environ)
        environment.update(CLAUDE_CONFIG_DIR=str(config), DISABLE_UPDATES='1',
                           CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1')
        require(environment.get('HOME') == os.environ.get('HOME'), 'native check must not override HOME')
        call = dict(environment=environment, cwd=cwd, deadline=deadline)
        version = native(cli, ['--version'], operation='version', **call)
        require(re.fullmatch(r'2\.1\.303(?:\s+\(Claude Code\))?\s*', version.strip()) is not None,
                'native runtime must be exactly2.1.303')
        native(cli, ['plugin', 'validate', str(plugin), '--strict'], operation='plugin validation', **call)
        native(cli, ['plugin', 'validate', str(marketplace), '--strict'], operation='marketplace validation', **call)
        installed = native(cli, ['plugin', 'install', 'peerspan', '--marketplace', str(marketplace),
            '--scope', 'user', '--config', 'executable=' + str(executable), '--json'], operation='installation', as_json=True, **call)
        require(type(installed) is dict and installed.get('command') == 'install' and installed.get('outcome') == 'ok'
                and installed.get('pluginId') == PLUGIN_ID and installed.get('scope') == 'user'
                and installed.get('configApplied') is True, 'native install did not record exact user plugin configuration')
        listing = native(cli, ['plugin', 'list', '--json'], operation='listing', as_json=True, **call)
        require(type(listing) is list, 'native plugin listing must be an array')
        matching = [entry for entry in listing if type(entry) is dict and entry.get('id') == PLUGIN_ID]
        require(len(matching) == 1 and matching[0].get('enabled') is True and matching[0].get('scope') == 'user'
                and matching[0].get('version') == metadata['version']
                and matching[0].get('folderVersion') == metadata['version'], 'expected bundled version is not enabled in public listing')
        configured = native(cli, ['plugin', 'configure', PLUGIN_ID, '--json'], operation='configuration lookup', as_json=True, **call)
        require(type(configured) is dict and configured.get('pluginId') == PLUGIN_ID and type(configured.get('inputs')) is dict
                and configured['inputs'].get('executable') == str(executable)
                and configured['inputs'].get('state') in (None, ''), 'public executable configuration does not match the relocated binary')
        require(validate_layout(prefix)[4] == snapshot, 'native validation/installation changed the archive plugin source')
        require(time.monotonic() <= deadline, 'native installation exceeded120 seconds')
        print('PASS bundled native onboarding: exact inventory/version, relocated local marketplace, strict2.1.303 validation, user installation, enabled version and executable pin')
        print('archive_sha256=' + archive_hash)
        print('LIMIT installation does not verify UI loading/reload, adapter delivery, model receipt, authority or remote readiness')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--claude', type=Path, required=True)
    args = parser.parse_args()
    try:
        check_bundle(args.archive.resolve(), args.claude.resolve())
    except CheckFailure as error:
        print('FAIL onboarding bundle: ' + str(error))
        raise SystemExit(1) from None
    except (OSError, ValueError, tarfile.TarError):
        print('FAIL onboarding bundle: local archive/native input unavailable')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
