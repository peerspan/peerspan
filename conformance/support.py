"""Small helpers shared by conformance suites.

wait_for, decode_token and encode_token came from coordination.py, and sshsig
from coord_move.py, when those coordinator suites were deleted (DEC-OWN4).
"""
import base64
import hashlib
import json
import secrets
import struct
import subprocess
import time

NAMESPACE = b'peerspan-person-v1'


def wait_for(predicate, timeout=10, message='condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError(f'timed out waiting for {message}')


def decode_token(token):
    prefix, encoded = token.split('.', 1)
    return prefix, json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))


def encode_token(prefix, fields):
    data = json.dumps(fields, separators=(',', ':')).encode()
    return prefix + '.' + base64.urlsafe_b64encode(data).decode().rstrip('=')


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
    """The SSHSIG blob (namespace peerspan-person-v1, sha512) by key over the lines, built from the format."""
    message = '\n'.join(lines).encode()
    signed = b'SSHSIG' + _string(NAMESPACE) + _string(b'') + _string(b'sha512') + \
        _string(hashlib.sha512(message).digest())
    signature = sign_bytes(key, signed)
    public = _string(b'ssh-ed25519') + _string(key.public)
    blob = b'SSHSIG' + struct.pack('>I', 1) + _string(public) + _string(NAMESPACE) + _string(b'') + \
        _string(b'sha512') + _string(_string(b'ssh-ed25519') + _string(signature))
    return base64.b64encode(blob).decode()


def _retired(*_args, **_kwargs):
    raise SystemExit('this suite still uses the retired coordinator (DEC-OWN2); it runs again once ported '
                     'to a coordinator-free network')


# Names from the deleted coordinator suites. Suites waiting for their port still
# import them; using one stops the suite with the message above.
class Coordinator:
    def __init__(self, *args, **kwargs):
        _retired()


class CoordHost(Coordinator):
    pass


raw_relay = read_frame = _retired
INTERVAL = 1
