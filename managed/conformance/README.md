# Managed contract conformance

Independent black-box Node 24 suite authored from `AGENTS.md` and
`docs/managed-contract.md`, without reading the managed implementation.
It launches the documented CLI and uses HTTP, an explicitly fake Peerspan
executable, and private throwaway Linux directories. It never reads the managed
database. Fixture names, instructions, results and binary are explicitly fake.

From this repository in Linux with Node 24:

```sh
node managed/conformance/acceptance.mjs
```

On the configured Windows editing machine:

```powershell
wsl.exe -d Ubuntu-24.04 -u matt -- bash -lc 'cd /mnt/c/Users/Owner/dev/peerspan-managed && node managed/conformance/acceptance.mjs'
```

Six concurrent cases cover authentication/schema/privacy, readiness/target
exclusion, crash/replay, real one-minute recurrence/caps, failure circuit and
read-only observation/process locks. The suite is bounded to 115 seconds; normal
duration is around 70 seconds. `KEEP_FAKE_MANAGED_FIXTURES=1` retains explicitly
fake temporary directories for diagnosing a failed run. Real Peerspan/model and
upstream transport compatibility require separate smoke checks.

`real-peerspan-smoke.py` is that separate compatibility smoke. It creates two
throwaway actual Peerspan hosts, a network and signed task access, verifies a
scripted adapter, and checks one managed task through actual transport and back
to its retained output. It calls no model and touches no existing daemon:

```sh
python3 managed/conformance/real-peerspan-smoke.py --bin /path/to/built/binaries
```
