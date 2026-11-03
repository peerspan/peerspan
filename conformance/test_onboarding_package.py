"""Independent section50 packaging CLI checks: fake build/npm, real Node/archive.

Only isolated fixture copies change. Actual packaging/copy/checksum/publication
logic executes; this suite never imports its implementation. Existing release
race tests and every earlier host/native file remain unchanged.
"""
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from onboarding_bundle import PLUGIN_FILES, PLUGIN_RELATIVE, safe_members, validate_marketplace, verify_checksum


REPO = Path(__file__).resolve().parents[1]
VERSION = '0.0.0-onboarding-test'
SHIM = r'''import json
import os
from pathlib import Path
import shutil
import sys

command = Path(sys.argv[0]).name
args = sys.argv[1:]
if command == 'cargo':
    output = Path(os.environ['CARGO_TARGET_DIR']) / args[args.index('--target') + 1] / 'release/peerspan-host'
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(os.environ['PEERSPAN_TEST_ELF'], output)
elif command == 'npm':
    prefix = Path(args[args.index('--prefix') + 1])
    dependencies = {'claude-channel':'@modelcontextprotocol/sdk', 'codex':'ws', 'opencode':'@opencode-ai/plugin'}
    if prefix.name not in dependencies:
        sys.exit('unexpected npm fixture target')
    dependency = dependencies[prefix.name]
    manifest = prefix / 'node_modules' / dependency / 'package.json'
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({'name':dependency,'version':'0.0.0-fixture','type':'module'}))
    with Path(os.environ['PEERSPAN_TEST_NPM_LOG']).open('a') as log:
        log.write(prefix.name + '\n')
else:
    sys.exit('unexpected fixture command')
'''


@unittest.skipUnless(sys.platform.startswith('linux'), 'native Linux packaging')
class OnboardingPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='peerspan onboarding package ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        architecture = {'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(os.uname().machine)
        if architecture is None or not shutil.which('flock'):
            self.skipTest('requires supported Linux architecture and flock')
        self.node = shutil.which('node')
        self.assertTrue(self.node, 'requires real Node22+')
        node = subprocess.run([self.node, '--version'], capture_output=True, text=True, timeout=5)
        self.assertTrue(node.returncode == 0 and node.stdout.strip().startswith('v')
                        and int(node.stdout.strip().split('.')[0][1:]) >= 22, 'requires real Node22+')
        self.repo = self.root / 'isolated repository'
        (self.repo / 'scripts').mkdir(parents=True)
        shutil.copy2(REPO / 'scripts/package-release.sh', self.repo / 'scripts')
        (self.repo / 'docs').mkdir()
        shutil.copy2(REPO / 'docs/quick-start.md', self.repo / 'docs')
        shutil.copytree(REPO / 'integrations', self.repo / 'integrations', symlinks=True,
                        ignore=shutil.ignore_patterns('node_modules','__pycache__','.git'))
        self.plugin = self.repo / 'integrations/claude-onboarding'
        self.source_manifest = json.loads((self.plugin / '.claude-plugin/plugin.json').read_text())
        self.output, self.commands = self.root / 'output', self.root / 'commands'
        self.output.mkdir(); self.commands.mkdir()
        self.archive = self.output / f'peerspan-{VERSION}-linux-{architecture}-rust.tar.gz'
        self.npm_log = self.root / 'npm-calls'
        self.environment = dict(os.environ)
        for obsolete in ('PEERSPAN_PACKAGE_OVERWRITE','PEERSPAN_COORDINATOR','PEERSPAN_COORDINATOR_KEY'):
            self.environment.pop(obsolete, None)
        self.environment.update(PATH=str(self.commands) + os.pathsep + os.environ.get('PATH',''),
            CARGO_TARGET_DIR=str(self.root / 'compiler output'), PEERSPAN_TEST_ELF=shutil.which('true'),
            PEERSPAN_TEST_NPM_LOG=str(self.npm_log))
        for command in ('cargo','npm'):
            shim = self.commands / command
            shim.write_text(f'#!{sys.executable}\n' + SHIM); shim.chmod(0o755)
        self.assertFalse((self.commands / 'node').exists(), 'Node must not be stubbed')
        self.assertEqual(self.environment.get('HOME'), os.environ.get('HOME'), 'packaging fixture must not override HOME')

    def package(self):
        return subprocess.run([str(self.repo / 'scripts/package-release.sh'), 'rust', VERSION, str(self.output)],
            cwd=self.repo, env=self.environment, capture_output=True, text=True, timeout=30)

    def no_pair(self):
        self.assertFalse(any(path.name.endswith(('.tar.gz','.sha256')) for path in self.output.iterdir()),
                         'refused source published a new archive/checksum')

    def test_exact_inventory_version_bytes_and_unlisted_omission(self):
        planted = ('PRIVATE_STATE.db', '.env', 'tests/unlisted.test.ts', 'node_modules/unlisted/package.json',
                   'hooks/unlisted.mjs', '.claude-plugin/unlisted.json')
        for relative in planted:
            path = self.plugin / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('PRIVATE_UNLISTED_PACKAGE_MARKER')
        result = self.package()
        self.assertEqual(result.returncode, 0, 'isolated packaging CLI failed')
        verify_checksum(self.archive)
        self.assertTrue(self.npm_log.exists(), 'fake npm boundary was not exercised')
        self.assertNotIn('claude-onboarding', self.npm_log.read_text().splitlines(), 'native plugin introduced an npm build dependency')
        with tarfile.open(self.archive, 'r:gz') as archive:
            members, root = safe_members(archive)
            def read(relative):
                info = archive.getmember(root + '/' + relative)
                self.assertTrue(info.isfile(), 'required archive source is not a regular file')
                with archive.extractfile(info) as source:
                    return source.read()
            metadata = json.loads(read('RELEASE.json'))
            self.assertEqual(metadata['version'], VERSION)
            self.assertEqual(metadata['implementation'], 'rust')
            plugin_root = PurePosixPath(root) / PLUGIN_RELATIVE.as_posix()
            files, directories = set(), set()
            for member in members:
                path = PurePosixPath(member.name)
                if not path.is_relative_to(plugin_root) or path == plugin_root:
                    continue
                relative = path.relative_to(plugin_root).as_posix()
                if member.isdir():
                    directories.add(relative)
                else:
                    self.assertTrue(member.isfile(), 'packaged native source is linked or special')
                    files.add(relative)
            self.assertEqual(files, PLUGIN_FILES, 'native package inventory is not exact')
            self.assertEqual(directories, {'.claude-plugin','hooks'}, 'native package contains unlisted directories')
            manifest = json.loads(read(PLUGIN_RELATIVE.as_posix() + '/.claude-plugin/plugin.json'))
            self.assertEqual(manifest, {**self.source_manifest, 'version': VERSION}, 'packaged manifest changed fields besides version')
            for relative in PLUGIN_FILES - {'.claude-plugin/plugin.json'}:
                self.assertTrue(read(PLUGIN_RELATIVE.as_posix() + '/' + relative) == (self.plugin / relative).read_bytes(),
                                'native module/hooks/README source bytes changed')
            validate_marketplace(json.loads(read('share/peerspan/.claude-plugin/marketplace.json')))
        self.assertEqual(json.loads((self.plugin / '.claude-plugin/plugin.json').read_text()), self.source_manifest,
                         'packaging rewrote the source manifest')

    def test_missing_runtime_module_refuses_without_pair(self):
        (self.plugin / 'hooks/tasks.mjs').unlink()
        self.assertNotEqual(self.package().returncode, 0, 'missing required module was accepted')
        self.no_pair()

    def test_linked_runtime_file_refuses_without_pair(self):
        source = self.plugin / 'hooks/owner.mjs'; target = self.root / 'external module.mjs'
        source.rename(target); source.symlink_to(target)
        self.assertNotEqual(self.package().returncode, 0, 'linked required module was accepted')
        self.no_pair()

    def test_linked_hooks_directory_refuses_without_pair(self):
        source = self.plugin / 'hooks'; target = self.root / 'external hooks'
        source.rename(target); source.symlink_to(target, target_is_directory=True)
        self.assertNotEqual(self.package().returncode, 0, 'linked hooks directory was accepted')
        self.no_pair()

    def test_linked_plugin_root_refuses_without_pair(self):
        target = self.root / 'external plugin'; self.plugin.rename(target)
        self.plugin.symlink_to(target, target_is_directory=True)
        self.assertNotEqual(self.package().returncode, 0, 'linked plugin root was accepted')
        self.no_pair()


if __name__ == '__main__':
    unittest.main()
