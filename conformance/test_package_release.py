"""Exercise release publication races without compiling or downloading packages."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[1]

SHIM = r'''import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

command = Path(sys.argv[0]).name
args = sys.argv[1:]
archive = Path(os.environ["PEERSPAN_TEST_ARCHIVE"])
checksum = Path(str(archive) + ".sha256")
control = Path(os.environ["PEERSPAN_TEST_CONTROL"])
if command == "node":
    print("22" if args[0] == "-p" else "v22.0.0")
elif command == "go":
    output = Path(args[args.index("-o") + 1])
    shutil.copy2(os.environ["PEERSPAN_TEST_ELF"], output)
elif command == "npm":
    prefix = Path(args[args.index("--prefix") + 1])
    dependency = {
        "claude-channel": "@modelcontextprotocol/sdk",
        "codex": "ws",
        "opencode": "@opencode-ai/plugin",
    }[prefix.name]
    manifest = prefix / "node_modules" / dependency / "package.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("{}")
    if not (control / "ready").exists():
        collision = os.environ.get("PEERSPAN_TEST_COLLISION")
        if collision == "archive":
            archive.write_bytes(b"another publisher's archive")
        elif collision == "checksum":
            checksum.write_bytes(b"another publisher's checksum")
        elif collision == "both":
            archive.write_bytes(b"another publisher's archive")
            checksum.write_bytes(b"another publisher's checksum")
        elif collision == "symlink":
            archive.symlink_to("missing-archive")
        (control / "ready").touch()
        if os.environ.get("PEERSPAN_TEST_HOLD") == "1":
            deadline = time.monotonic() + 15
            while not (control / "release").exists():
                if time.monotonic() >= deadline:
                    sys.exit("fixture release timed out")
                time.sleep(0.02)
elif command == "ln":
    result = subprocess.run([os.environ["PEERSPAN_TEST_LN"], *args])
    if result.returncode == 0 and args[-1] == str(archive):
        checksum.write_bytes(b"checksum created during publication")
    sys.exit(result.returncode)
else:
    sys.exit("unexpected fixture command")
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "native Linux packaging")
class PackageReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="peerspan publication ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commands = self.root / "commands"
        self.commands.mkdir()
        self.output = self.root / "output"
        self.output.mkdir()
        self.control = self.root / "control"
        self.control.mkdir()
        machine = os.uname().machine
        architecture = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "aarch64": "arm64",
            "arm64": "arm64",
        }.get(machine)
        if architecture is None or not shutil.which("flock"):
            self.skipTest("requires a supported Linux architecture and flock")
        self.archive = self.output / (
            f"peerspan-publication-test-linux-{architecture}-go.tar.gz"
        )
        self.checksum = Path(str(self.archive) + ".sha256")
        self.env = dict(os.environ)
        self.env.pop("PEERSPAN_PACKAGE_OVERWRITE", None)
        self.env.update(
            PATH=str(self.commands) + os.pathsep + os.environ.get("PATH", ""),
            PEERSPAN_TEST_ARCHIVE=str(self.archive),
            PEERSPAN_TEST_CONTROL=str(self.control),
            PEERSPAN_TEST_ELF=shutil.which("true"),
            PEERSPAN_TEST_LN=shutil.which("ln"),
        )
        for command in ("node", "npm", "go"):
            self.shim(command)

    def shim(self, command):
        path = self.commands / command
        path.write_text(f"#!{sys.executable}\n" + SHIM)
        path.chmod(0o755)

    def start(self, **environment):
        return subprocess.Popen(
            [
                str(REPO / "scripts/package-release.sh"),
                "go",
                "publication-test",
                str(self.output),
            ],
            cwd=REPO,
            env=dict(self.env, **environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def finish(self, process):
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail("packaging did not finish")
        return process.returncode, stdout, stderr

    def matching_pair(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertEqual(self.checksum.read_text(), f"{digest}  {self.archive.name}\n")

    def test_concurrent_build_is_rejected_even_with_overwrite(self):
        first = self.start(PEERSPAN_TEST_HOLD="1")
        try:
            deadline = time.monotonic() + 10
            while not (self.control / "ready").exists():
                if first.poll() is not None or time.monotonic() >= deadline:
                    self.fail("first builder did not reach the fixture")
                time.sleep(0.02)
            for overwrite in ("", "1"):
                with self.subTest(overwrite=overwrite):
                    result, _, error = self.finish(
                        self.start(PEERSPAN_PACKAGE_OVERWRITE=overwrite)
                    )
                    self.assertNotEqual(result, 0)
                    self.assertIn("another packaging process", error)
        finally:
            (self.control / "release").touch()
            result, _, error = self.finish(first)
        self.assertEqual(result, 0, error)
        self.matching_pair()
        # The persistent lock file must not prevent subsequent explicit replacement.
        result, _, error = self.finish(self.start(PEERSPAN_PACKAGE_OVERWRITE="1"))
        self.assertEqual(result, 0, error)
        self.matching_pair()

    def test_outputs_created_during_build_are_preserved(self):
        for collision in ("archive", "checksum", "both", "symlink"):
            with self.subTest(collision=collision):
                (self.control / "ready").unlink(missing_ok=True)
                result, _, error = self.finish(
                    self.start(PEERSPAN_TEST_COLLISION=collision)
                )
                self.assertNotEqual(result, 0)
                self.assertIn("refusing to overwrite", error)
                if collision == "symlink":
                    self.assertTrue(self.archive.is_symlink())
                    self.assertEqual(os.readlink(self.archive), "missing-archive")
                elif collision in ("archive", "both"):
                    self.assertEqual(self.archive.read_bytes(), b"another publisher's archive")
                else:
                    self.assertFalse(self.archive.exists())
                if collision in ("checksum", "both"):
                    self.assertEqual(self.checksum.read_bytes(), b"another publisher's checksum")
                else:
                    self.assertFalse(self.checksum.exists())
                self.archive.unlink(missing_ok=True)
                self.checksum.unlink(missing_ok=True)

    def test_checksum_collision_rolls_back_only_our_archive(self):
        self.shim("ln")
        result, _, error = self.finish(self.start())
        self.assertNotEqual(result, 0)
        self.assertIn("checksum output appeared", error)
        self.assertFalse(self.archive.exists())
        self.assertEqual(
            self.checksum.read_bytes(), b"checksum created during publication"
        )
        self.assertEqual(
            [
                path.name
                for path in self.output.iterdir()
                if not path.name.endswith(".lock")
            ],
            [self.checksum.name],
        )

    def test_completed_outputs_require_explicit_overwrite(self):
        self.archive.write_bytes(b"old archive")
        self.checksum.write_bytes(b"old checksum")
        result, _, error = self.finish(self.start())
        self.assertNotEqual(result, 0)
        self.assertIn("package output already exists", error)
        self.assertEqual(self.archive.read_bytes(), b"old archive")
        self.assertEqual(self.checksum.read_bytes(), b"old checksum")
        result, _, error = self.finish(self.start(PEERSPAN_PACKAGE_OVERWRITE="1"))
        self.assertEqual(result, 0, error)
        self.matching_pair()


if __name__ == "__main__":
    unittest.main()
