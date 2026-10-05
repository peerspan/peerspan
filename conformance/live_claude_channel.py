#!/usr/bin/env python3
"""Explicit interactive experiment using authenticated Claude Code and model calls.

Creates only temporary host/config state and enables only the Capsule reply tool.
Existing developer sessions/MCP configs are never selected or reconfigured. Claude
may record trust/session state for this temporary test workspace. Requires Unix
PTYs and Linux /proc for the deterministic pause of this test's adapter child.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import signal
import struct
import subprocess
import tempfile
import termios
import threading
import time
import uuid

from agent_adapter import credential, sql
from peer_messaging import PeerHost


def wait_until(check, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError('live experiment timed out')


def adapter_pid(claude_pid, script):
    """Find only our spawned adapter beneath this test's Claude process."""
    pending = [claude_pid]
    while pending:
        parent = pending.pop()
        try:
            children = Path(f'/proc/{parent}/task/{parent}/children').read_text().split()
        except FileNotFoundError:
            continue
        for child in children:
            pid = int(child)
            try:
                args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            except FileNotFoundError:
                continue
            if str(script).encode() in args:
                return pid
            pending.append(pid)
    return None


def check(args):
    script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'
    with tempfile.TemporaryDirectory(prefix='capsule-live-channel-') as directory:
        root = Path(directory)
        sender = PeerHost(args.sender.resolve(), root / 'sender')
        receiver = PeerHost(args.receiver.resolve(), root / 'receiver')
        process = None
        stopped_adapter = None
        master = None
        console = bytearray()
        try:
            a, b = sender.start(), receiver.start()
            sender.configure(receiver, b)
            receiver.configure(sender, a)
            agent = receiver.cli('agent', 'register', '--name', 'live-claude', '--owner', 'test')
            session = receiver.cli('session', 'attach', '--agent', agent['id'], '--integration', 'claude-channel')
            secret = credential(receiver, session)
            secret_path = root / 'credential.json'
            secret_path.write_text(json.dumps(secret))
            secret_path.chmod(0o600)
            config = root / 'mcp.json'
            config.write_text(json.dumps({'mcpServers': {'capsule': {
                'command': str(args.node.resolve()), 'args': [str(script), '--socket', str(receiver.state / 'adapter.sock'),
                                                            '--credential-file', str(secret_path), '--poll-ms', '100']}}}))
            sid = str(uuid.uuid4())
            debug = root / 'claude-debug.log'
            command = [str(args.claude.resolve()), '--session-id', sid,
                       '--strict-mcp-config', '--mcp-config', str(config), '--setting-sources', '',
                       '--settings', '{"disableAllHooks":true}', '--tools', '',
                       '--allowedTools', 'mcp__capsule__reply', '--permission-mode', 'dontAsk',
                       '--disable-slash-commands', '--dangerously-load-development-channels', 'server:capsule',
                       '--debug-file', str(debug)]
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 100, 0, 0))
            environment = dict(os.environ, TERM='xterm-256color')
            def establish_terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            process = subprocess.Popen(command, cwd=root, stdin=slave, stdout=slave, stderr=slave,
                                       env=environment, preexec_fn=establish_terminal)
            os.close(slave)

            def read():
                while True:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        return
                    if not chunk:
                        return
                    console.extend(chunk)
                    if len(console) > 1048576:
                        del console[:-524288]

            reader = threading.Thread(target=read, daemon=True)
            reader.start()

            def running():
                if process.poll() is not None:
                    raise AssertionError('Claude exited before the experiment finished')

            def screen():
                running()
                text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', ' ', console.decode(errors='replace'))
                return re.sub(r'\s+', ' ', text)

            # These two prompts authorize our own temporary workspace and channel.
            # Do not change any user-wide permission setting or bypass tool approval.
            wait_until(lambda: 'Accessing' in screen() and 'Enter to confirm' in screen(), seconds=20)
            time.sleep(.5)
            os.write(master, b'\x1b[B\r')
            wait_until(lambda: 'Loading' in screen() and 'development' in screen() and 'channels' in screen(), seconds=20)
            os.write(master, b'\r')

            def debug_text():
                running()
                return debug.read_text() if debug.exists() else ''

            wait_until(lambda: 'Channel notifications registered' in debug_text(), seconds=30)
            protocol = re.search(r'"negotiatedProtocolVersion":"([^"]+)"', debug_text()).group(1)
            print('Interactive Claude session registered Capsule channel notifications.', flush=True)
            grant = receiver.grant(a, agent)
            offset = len(debug_text())
            first = sender.submit(b, agent, grant, content='Reply through the Capsule reply tool with exactly CAPSULE_LIVE_ONE.')
            rid1 = first['request']['request_id']
            wait_until(lambda: 'Stream started - received first chunk' in debug_text()[offset:], seconds=40)
            first_pending_when_second_sent = not sql(receiver, 'SELECT record FROM received_replies WHERE request_id = ?', (rid1,))
            assert first_pending_when_second_sent, 'first reply completed before the busy-session check'
            second = sender.submit(b, agent, grant, content='Reply through the Capsule reply tool with exactly CAPSULE_LIVE_TWO.')
            rid2 = second['request']['request_id']

            def responses():
                running()
                rows = sql(receiver, 'SELECT record FROM received_replies WHERE request_id IN (?, ?)', (rid1, rid2))
                return [json.loads(row[0]) for row in rows] if len(rows) == 2 else None

            replies = wait_until(responses)
            by_id = {r['request_id']: r for r in replies}
            assert by_id[rid1]['content'] == 'CAPSULE_LIVE_ONE', by_id[rid1]['content']
            assert by_id[rid2]['content'] == 'CAPSULE_LIVE_TWO', by_id[rid2]['content']
            assert all(r['session_id'] == session['id'] for r in replies)
            assert sender.cli('message', 'reply', '--peer', b['id'], rid1)['reply'] == by_id[rid1]
            assert sender.cli('message', 'reply', '--peer', b['id'], rid2)['reply'] == by_id[rid2]
            print('Two correlated replies returned; second message sent while the model was streaming.', flush=True)

            # Pause only this test's adapter to make revocation-before-handoff deterministic.
            stopped_adapter = wait_until(lambda: adapter_pid(process.pid, script), seconds=5)
            os.kill(stopped_adapter, signal.SIGSTOP)
            third = sender.submit(b, agent, grant, content='This queued message must be blocked after revocation.')
            rid3 = third['request']['request_id']
            assert not sql(receiver, 'SELECT id FROM deliveries WHERE request_id = ?', (rid3,))
            receiver.cli('grant', 'revoke', grant['id'])
            os.kill(stopped_adapter, signal.SIGCONT)
            stopped_adapter = None

            def blocked():
                running()
                rows = sql(receiver, 'SELECT record FROM deliveries WHERE request_id = ?', (rid3,))
                return json.loads(rows[0][0]) if rows else None

            assert wait_until(blocked, seconds=10)['state'] == 'blocked'
            assert not sql(receiver, 'SELECT record FROM received_replies WHERE request_id = ?', (rid3,))
            assert sender.cli('message', 'reply', '--peer', b['id'], rid1)['reply'] == by_id[rid1]
            print('Queued message blocked by receiver revocation.', flush=True)
            return {
                'checked_at': datetime.now(timezone.utc).isoformat(),
                'claude_version': subprocess.check_output([str(args.claude.resolve()), '--version'], text=True).strip(),
                'mcp_protocol': protocol,
                'sender': args.sender.name, 'receiver': args.receiver.name,
                'agent_integration': 'claude-channel', 'mode': 'interactive',
                'same_claude_process_and_session': True,
                'two_correlated_replies': True,
                'second_message_sent_while_model_streaming': True,
                'first_reply_pending_when_second_sent': first_pending_when_second_sent,
                'revocation_before_handoff_blocked': True,
                'permission_relay_enabled': False,
                'builtin_tools_enabled': False,
                'limitations': ['Ephemeral loopback hosts; cross-machine reachability not tested.',
                                'Model-driven adapter/host restart recovery not tested; deterministic conformance covers persistence and uncertain handoffs.',
                                'Noninteractive stream-json session connected to MCP but did not register/consume channel events on this installation.'],
            }
        except Exception:
            diagnostics = {'deliveries': sql(receiver, 'SELECT record FROM deliveries') if receiver.process else []}
            diagnostics['console_tail'] = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', ' ', console.decode(errors='replace'))[-1500:]
            debug = root / 'claude-debug.log'
            if debug.exists():
                diagnostics['channel_debug'] = [line for line in debug.read_text().splitlines()
                    if any(word in line.lower() for word in ['channel', 'capsule', 'protocolversion'])][-25:]
            print(json.dumps(diagnostics, indent=2), flush=True)
            raise
        finally:
            if stopped_adapter:
                os.kill(stopped_adapter, signal.SIGCONT)
            if process and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            if master is not None:
                os.close(master)
            sender.stop(); receiver.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sender', type=Path, required=True)
    parser.add_argument('--receiver', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--claude', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Live Claude integration passed; report:', args.output, flush=True)


if __name__ == '__main__':
    main()
