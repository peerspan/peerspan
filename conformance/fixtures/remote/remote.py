"""Fake remote MCP servers and fake OAuth authorization servers for conformance/capability_remote.py.

Written from docs/capabilities-contract.md ("Remote MCP servers and OAuth (slice 3)") and
docs/capabilities-slice3-remote-proposal.md, independently of the Go and Rust hosts. Only Python's standard library.

Each server is one ThreadingHTTPServer on 127.0.0.1 (loopback HTTP, which the contract allows in place of HTTPS),
started in a thread of the suite's own process, so the suite reads and changes its state directly. Every request is
recorded whole (method, path, query, headers, body) in `requests`, in arrival order, so the suite can check exactly
what each host sent, and to which origin.

- `McpServer`: one Streamable HTTP MCP endpoint (MCP 2025-11-25 transports): POST per JSON-RPC message, JSON or SSE
  replies, `MCP-Session-Id`, `MCP-Protocol-Version`, DELETE, and auth by nothing, by fixed headers, or by bearer
  tokens of an `AuthServer` with a 401 `WWW-Authenticate: Bearer` challenge. It also serves its RFC 9728 protected
  resource metadata, at the paths the suite chooses.
- `AuthServer`: an OAuth 2.1 authorization server: RFC 8414 and OpenID Connect metadata at the paths the suite
  chooses, RFC 7591 dynamic client registration, authorization code with PKCE S256 (auto-approved when the suite
  fetches the authorization URL), RFC 8707 `resource`, refresh with rotation (a reused refresh token is
  `invalid_grant`, as rotation implies), and RFC 7009 revocation. Anything it refuses is also appended to
  `violations` with the reason, so a check can say why.

Tools of the fake MCP server (all take an optional `text`):
  echo {text}                    returns text
  who {}                         the token's subject label and scope, or `none`, and the headers named in
                                 `reveal_headers` as digests (never values)
  sleep {seconds, text?}         answers after `seconds` (a cancellation is recorded, the answer still comes unless
                                 the client closed the connection)
  status {code, challenge?, location?}  answers the call with HTTP `code` (and the given WWW-Authenticate and
                                 Location values)
  drop {}                        reads the request, then closes the connection without an answer
  big {bytes}                    a text result of `bytes` copies of `b`
  ask {}                         an SSE answer holding a server-to-client request (`roots/list`) before the result;
                                 the result says whether the client answered it with error -32601
  lose_session {}                forgets every session and answers 404 (a lost session)
  garbage {}                     answers 200 text/plain that is not a JSON-RPC response
  write_note {text}              readOnlyHint false
Each execution of a tools/call (also the refused ones: status, drop, lose_session) is recorded in `executions`.
"""
import base64
import hashlib
import json
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

PROTOCOLS = ('2025-03-26', '2025-06-18', '2025-11-25')


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def s256(verifier):
    return b64url(hashlib.sha256(verifier.encode()).digest())


def digest(text):
    return 'sha256:' + hashlib.sha256(text.encode()).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def _serve(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        split = urlsplit(self.path)
        request = {'time': time.time(), 'method': self.command, 'path': split.path, 'query': split.query,
                   'headers': {k.lower(): v for k, v in self.headers.items()},
                   'body': body.decode('utf-8', errors='replace'), 'site': self.server.site.name}
        site = self.server.site
        with site.lock:
            request['index'] = len(site.requests)
            site.requests.append(request)
        try:
            site.handle(self, request)
        except (BrokenPipeError, ConnectionResetError):
            request['client_closed'] = True

    do_GET = do_POST = do_DELETE = do_PUT = _serve

    def setup(self):
        super().setup()
        with self.server.site.lock:
            self.server.site.connections.add(self.connection)

    def finish(self):
        try:
            super().finish()
        finally:
            with self.server.site.lock:
                self.server.site.connections.discard(self.connection)

    # helpers used by sites
    def reply(self, status, body=b'', content_type='application/json', headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        if body or status not in (204, 304):
            self.send_header('Content-Type', content_type)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.wfile.flush()

    def drop(self):
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass    # a client that closes its connection early is a case under test, not a fixture error


class Site:
    def __init__(self, name):
        self.name = name
        self.lock = threading.RLock()
        self.requests = []
        self.connections = set()
        self.httpd = QuietServer(('127.0.0.1', 0), Handler)
        self.httpd.daemon_threads = True
        self.httpd.site = self
        self.port = self.httpd.server_address[1]
        self.origin = f'http://127.0.0.1:{self.port}'
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop listening and close every open connection, so a client's next request cannot connect."""
        self.httpd.shutdown()
        self.httpd.server_close()
        with self.lock:
            connections = list(self.connections)
        for c in connections:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def mark(self):
        with self.lock:
            return len(self.requests)

    def since(self, mark=0, method=None, path=None):
        with self.lock:
            out = self.requests[mark:]
        return [r for r in out if (method is None or r['method'] == method) and (path is None or r['path'] == path)]

    def handle(self, handler, request):
        handler.reply(404, {'error': 'not_found'})


# --- the authorization server -----------------------------------------------------------------------------------

class AuthServer(Site):
    """An OAuth authorization server. `issuer_path` ('' or '/tenant') is appended to the origin for the issuer."""

    def __init__(self, name='as', issuer_path=''):
        super().__init__(name)
        self.issuer_path = issuer_path
        self.issuer = self.origin + issuer_path
        self.cfg = {
            'metadata': ('oauth',),          # documents served: 'oauth' (RFC 8414), 'oidc-insert' (OpenID Connect,
                                             # path inserted), 'oidc-append' (path appended); without an issuer
                                             # path both OIDC forms are /.well-known/openid-configuration
            'pkce': ['S256'],                # code_challenge_methods_supported; None leaves it out
            'dcr': True,                     # registration_endpoint advertised and served
            'dcr_secret': None,              # None, 'client_secret_post', or 'client_secret_basic'
            'dcr_status': None,              # refuse registration with this HTTP status
            'revocation': True,              # revocation_endpoint advertised
            'revoke_status': 200,
            'issuer_override': None,         # an `issuer` in the metadata other than the real one
            'scopes_supported': None,
            'access_ttl': 3600,              # expires_in; None leaves expires_in out
            'refresh': True,                 # issue refresh tokens
            'authorize': 'approve',          # or ('error', ERROR, DESCRIPTION)
            'subject': 'alice',              # who "approves" in the browser
            'grant_scope': None,             # the scope granted, when not the requested one
            'token_error': None,             # (ERROR, DESCRIPTION, status) for the next token requests
            'refresh_error': None,           # (ERROR, DESCRIPTION, status) for refresh requests only
            'refresh_delay': 0,              # seconds before answering a refresh
            'token_status_once': None,       # an HTTP status for the next token request only (network-like error)
            'auth_methods': ['none', 'client_secret_post', 'client_secret_basic'],
            'token_type': 'Bearer',
        }
        self.clients = {}      # client_id -> registration (and its secret)
        self.codes = {}        # code -> grant
        self.access = {}       # access token -> grant
        self.refresh = {}      # refresh token -> grant (with 'used')
        self.revoked = []      # tokens revoked through the endpoint
        self.violations = []   # (reason, request)
        self.preregistered = {}

    def add_client(self, client_id, redirect_uris=None, secret=None, method='none'):
        """A client registered with the provider by hand (the owner's --client-id)."""
        self.clients[client_id] = {'client_id': client_id, 'redirect_uris': redirect_uris, 'client_secret': secret,
                                   'token_endpoint_auth_method': method, 'manual': True}

    # metadata

    def metadata(self):
        o = self.origin
        m = {'issuer': self.cfg['issuer_override'] or self.issuer,
             'authorization_endpoint': o + '/authorize', 'token_endpoint': o + '/token',
             'response_types_supported': ['code'], 'grant_types_supported': ['authorization_code', 'refresh_token'],
             'token_endpoint_auth_methods_supported': self.cfg['auth_methods']}
        if self.cfg['pkce'] is not None:
            m['code_challenge_methods_supported'] = self.cfg['pkce']
        if self.cfg['dcr']:
            m['registration_endpoint'] = o + '/register'
        if self.cfg['revocation']:
            m['revocation_endpoint'] = o + '/revoke'
        if self.cfg['scopes_supported'] is not None:
            m['scopes_supported'] = self.cfg['scopes_supported']
        return m

    def metadata_paths(self):
        """The well-known paths this server answers, per MCP authorization (2025-11-25) discovery."""
        p = self.issuer_path
        kinds = self.cfg['metadata']
        paths = {}
        if 'oauth' in kinds:
            paths['/.well-known/oauth-authorization-server' + p] = 'oauth'
        if 'oidc-insert' in kinds:
            paths['/.well-known/openid-configuration' + p] = 'oidc-insert'
        if 'oidc-append' in kinds:
            paths[p + '/.well-known/openid-configuration'] = 'oidc-append'
        return paths

    def discovery_order(self):
        """Every well-known path in the order MCP authorization (2025-11-25) has clients try them."""
        p = self.issuer_path
        if p:
            return ['/.well-known/oauth-authorization-server' + p, '/.well-known/openid-configuration' + p,
                    p + '/.well-known/openid-configuration']
        return ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration']

    def violation(self, reason, request):
        with self.lock:
            self.violations.append((reason, request))

    def handle(self, h, r):
        if r['method'] == 'GET' and r['path'] in self.metadata_paths():
            return h.reply(200, self.metadata())
        if r['path'] == '/register' and r['method'] == 'POST' and self.cfg['dcr']:
            return self.register(h, r)
        if r['path'] == '/authorize' and r['method'] == 'GET':
            return self.authorize(h, r)
        if r['path'] == '/token' and r['method'] == 'POST':
            return self.token(h, r)
        if r['path'] == '/revoke' and r['method'] == 'POST' and self.cfg['revocation']:
            return self.revoke(h, r)
        h.reply(404, {'error': 'not_found'})

    def register(self, h, r):
        if self.cfg['dcr_status']:
            return h.reply(self.cfg['dcr_status'], {'error': 'invalid_client_metadata',
                                                    'error_description': 'fixture refuses registration'})
        try:
            body = json.loads(r['body'])
        except ValueError:
            self.violation('registration body is not JSON', r)
            return h.reply(400, {'error': 'invalid_client_metadata'})
        client_id = 'client_' + secrets.token_hex(8)
        reg = {'client_id': client_id, 'client_id_issued_at': int(time.time()), **body}
        method = self.cfg['dcr_secret']
        if method:
            reg['client_secret'] = 'secret_' + secrets.token_hex(12)
            reg['client_secret_expires_at'] = 0
            if method == 'unspecified':      # a secret, and no token_endpoint_auth_method in the answer
                reg.pop('token_endpoint_auth_method', None)
            else:
                reg['token_endpoint_auth_method'] = method
        reg['registration_access_token'] = 'rat_' + secrets.token_hex(12)
        with self.lock:
            self.clients[client_id] = dict(reg)
        h.reply(201, reg)

    def authorize(self, h, r):
        q = {k: v[0] for k, v in parse_qs(r['query'], keep_blank_values=True).items()}
        r['params'] = q
        client = self.clients.get(q.get('client_id'))
        problems = []
        if q.get('response_type') != 'code':
            problems.append('response_type is not code')
        if not client:
            problems.append('unknown client_id')
        elif client.get('redirect_uris') and q.get('redirect_uri') not in client['redirect_uris']:
            problems.append('redirect_uri not registered')
        if not q.get('code_challenge') or q.get('code_challenge_method') != 'S256':
            problems.append('no S256 code challenge')
        if not q.get('state'):
            problems.append('no state')
        if not q.get('resource'):
            problems.append('no resource')
        if problems:
            self.violation('authorize: ' + '; '.join(problems), r)
            return h.reply(400, {'error': 'invalid_request', 'error_description': '; '.join(problems)})
        target = q['redirect_uri']
        if self.cfg['authorize'] != 'approve':
            _, error, description = self.cfg['authorize']
            params = {'error': error, 'state': q['state']}
            if description:
                params['error_description'] = description
            return h.reply(302, b'', headers={'Location': target + '?' + urlencode(params)})
        code = 'code_' + secrets.token_hex(12)
        scope = self.cfg['grant_scope'] if self.cfg['grant_scope'] is not None else q.get('scope', '')
        with self.lock:
            self.codes[code] = {'client_id': q['client_id'], 'redirect_uri': target,
                                'challenge': q['code_challenge'], 'resource': q['resource'], 'scope': scope,
                                'subject': self.cfg['subject'], 'used': False}
        h.reply(302, b'', headers={'Location': target + '?' + urlencode({'code': code, 'state': q['state'],
                                                                        'iss': self.issuer})})

    def client_auth(self, r, form):
        """(client_id, problem) from client_secret_basic, client_secret_post, or a public client."""
        auth = r['headers'].get('authorization', '')
        if auth.lower().startswith('basic '):
            try:
                cid, _, secret = base64.b64decode(auth[6:]).decode().partition(':')
            except ValueError:
                return None, 'bad basic auth'
            from urllib.parse import unquote_plus
            cid, secret = unquote_plus(cid), unquote_plus(secret)
            client = self.clients.get(cid)
            if not client or client.get('client_secret') != secret:
                return cid, 'bad client secret (basic)'
            return cid, None
        cid = form.get('client_id')
        client = self.clients.get(cid)
        if not client:
            return cid, 'unknown client_id'
        if client.get('client_secret'):
            if form.get('client_secret') != client['client_secret']:
                return cid, 'missing or bad client_secret'
        return cid, None

    def issue(self, grant):
        access = 'at_' + secrets.token_hex(16)
        ttl = self.cfg['access_ttl']
        g = dict(grant, issued_at=time.time(), expires_at=(time.time() + ttl) if ttl is not None else None)
        body = {'access_token': access, 'token_type': self.cfg['token_type']}
        if ttl is not None:
            body['expires_in'] = ttl
        if g.get('scope'):
            body['scope'] = g['scope']
        with self.lock:
            self.access[access] = g
            if self.cfg['refresh']:
                rt = 'rt_' + secrets.token_hex(16)
                self.refresh[rt] = dict(g, used=False, access=access)
                body['refresh_token'] = rt
        return body

    def token(self, h, r):
        form = {k: v[0] for k, v in parse_qs(r['body'], keep_blank_values=True).items()}
        r['form'] = form
        once = self.cfg.get('token_status_once')
        if once:
            self.cfg['token_status_once'] = None
            return h.reply(once, {'error': 'temporarily_unavailable'})
        if self.cfg['token_error']:
            return self.error_reply(h, *self.cfg['token_error'])
        cid, problem = self.client_auth(r, form)
        if problem:
            self.violation('token: ' + problem, r)
            return h.reply(401, {'error': 'invalid_client', 'error_description': problem})
        grant_type = form.get('grant_type')
        if grant_type == 'authorization_code':
            with self.lock:
                grant = self.codes.get(form.get('code'))
                problems = []
                if not grant:
                    problems.append('unknown code')
                else:
                    if grant['used']:
                        problems.append('code reused')
                    grant['used'] = True
                    if grant['client_id'] != cid:
                        problems.append('client_id differs')
                    if form.get('redirect_uri') != grant['redirect_uri']:
                        problems.append('redirect_uri differs')
                    if not form.get('code_verifier') or s256(form['code_verifier']) != grant['challenge']:
                        problems.append('PKCE verifier does not match')
                    if form.get('resource') != grant['resource']:
                        problems.append('resource differs from the authorization request')
            if problems:
                self.violation('token: ' + '; '.join(problems), r)
                return h.reply(400, {'error': 'invalid_grant', 'error_description': '; '.join(problems)})
            return h.reply(200, self.issue(grant), headers={'Cache-Control': 'no-store'})
        if grant_type == 'refresh_token':
            if self.cfg['refresh_delay']:
                time.sleep(self.cfg['refresh_delay'])
            if self.cfg['refresh_error']:
                return self.error_reply(h, *self.cfg['refresh_error'])
            with self.lock:
                old = self.refresh.get(form.get('refresh_token'))
                problems = []
                if not old:
                    problems.append('unknown refresh token')
                elif old['used']:
                    problems.append('refresh token reused (rotated)')
                elif old.get('revoked'):
                    problems.append('refresh token revoked')
                elif old['client_id'] != cid:
                    problems.append('client_id differs')
                if old and not problems and form.get('resource') != old['resource']:
                    problems.append('resource differs')
                if old and not problems:
                    old['used'] = True
            if problems:
                self.violation('refresh: ' + '; '.join(problems), r)
                return h.reply(400, {'error': 'invalid_grant', 'error_description': '; '.join(problems)})
            grant = {k: old[k] for k in ('client_id', 'redirect_uri', 'resource', 'scope', 'subject')}
            return h.reply(200, self.issue(grant), headers={'Cache-Control': 'no-store'})
        self.violation(f'token: unsupported grant_type {grant_type}', r)
        h.reply(400, {'error': 'unsupported_grant_type'})

    @staticmethod
    def error_reply(h, error, description, status):
        """An OAuth error answer; without `error`, a body with no error string."""
        body = {}
        if error is not None:
            body['error'] = error
        if description is not None:
            body['error_description'] = description
        return h.reply(status, body)

    def revoke(self, h, r):
        form = {k: v[0] for k, v in parse_qs(r['body'], keep_blank_values=True).items()}
        r['form'] = form
        token = form.get('token')
        with self.lock:
            self.revoked.append(token)
            if token in self.refresh:
                self.refresh[token]['revoked'] = True
            if token in self.access:
                self.access[token]['revoked'] = True
        h.reply(self.cfg['revoke_status'], b'' if self.cfg['revoke_status'] == 200 else {'error': 'server_error'})

    # helpers for the suite

    def approve(self, authorization_url):
        """Fetch the authorization URL (as a browser would) and return the redirect it answers with, unfollowed."""
        import http.client
        u = urlsplit(authorization_url)
        connection = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        try:
            connection.request('GET', u.path + ('?' + u.query if u.query else ''))
            response = connection.getresponse()
            response.read()
            return response.status, response.getheader('Location')
        finally:
            connection.close()

    def token_valid(self, token, resource):
        g = self.access.get(token)
        if not g or g.get('revoked'):
            return None, 'unknown or revoked'
        if g['expires_at'] is not None and time.time() >= g['expires_at']:
            return None, 'expired'
        if g['resource'] != resource:
            return None, 'audience'
        return g, None

    def last_refresh_token(self):
        with self.lock:
            live = [t for t, g in self.refresh.items() if not g['used'] and not g.get('revoked')]
        return live[-1] if live else None

    def tokens(self):
        """Every token value this server issued (for secret scans)."""
        with self.lock:
            out = list(self.access) + list(self.refresh) + list(self.codes)
            for c in self.clients.values():
                for k in ('client_secret', 'registration_access_token'):
                    if c.get(k):
                        out.append(c[k])
        return out


# --- the MCP server ----------------------------------------------------------------------------------------------

def tool(name, description, properties=None, read_only=True):
    t = {'name': name, 'description': description,
         'inputSchema': {'type': 'object', 'properties': properties or {}}}
    t['annotations'] = {'readOnlyHint': read_only}
    return t


TOOLS = [
    tool('echo', 'Echo text', {'text': {'type': 'string'}}),
    tool('who', 'Who is calling', {'text': {'type': 'string'}}),
    tool('sleep', 'Sleep', {'seconds': {'type': 'number'}, 'text': {'type': 'string'}}),
    tool('status', 'Answer with an HTTP status', {'code': {'type': 'integer'}, 'challenge': {'type': 'string'},
                                                  'location': {'type': 'string'}, 'text': {'type': 'string'}}),
    tool('drop', 'Drop the connection', {'text': {'type': 'string'}}),
    tool('big', 'A big result', {'bytes': {'type': 'integer'}}),
    tool('ask', 'Ask the client something first', {'text': {'type': 'string'}}),
    tool('lose_session', 'Lose the session', {'text': {'type': 'string'}}),
    tool('garbage', 'Answer 200 with something that is not JSON-RPC', {'text': {'type': 'string'}}),
    tool('write_note', 'Write a note', {'text': {'type': 'string'}}, read_only=False),
]
RESOURCES = [{'uri': 'remote://docs/readme', 'name': 'readme', 'description': 'The remote readme',
              'mimeType': 'text/plain'}]


class McpServer(Site):
    """A Streamable HTTP MCP endpoint at `path`."""

    def __init__(self, name='mcp', path='/mcp'):
        super().__init__(name)
        self.path = path
        self.url = self.origin + path
        self.cfg = {
            'auth': 'none',              # 'none', 'headers', or 'oauth'
            'headers': {},               # for 'headers': required header name -> value
            'auth_server': None,         # for 'oauth': the AuthServer whose tokens are valid
            'resource': self.url,        # the audience the tokens must carry (the canonical URL)
            'challenge_metadata': True,  # resource_metadata in the 401 challenge (True: the path form URL)
            'challenge_scope': None,     # scope in the 401 challenge
            'prm_paths': ('path',),      # protected resource metadata served at: 'path', 'root', 'custom'
            'prm_scopes': None,          # scopes_supported in the protected resource metadata
            'prm_resource': None,        # `resource` in the metadata (default: the URL)
            'sessions': True,            # set MCP-Session-Id on initialize
            'reply': 'json',             # 'json' or 'sse'
            'sse_noise': False,          # with 'sse': an unrelated notification, a response to another request ID,
                                         # and a `ping` request before each response
            'protocol': None,            # the version answered to initialize (default: the client's, if known)
            'delete_status': 200,
            'init_status': None,         # an HTTP status for initialize (such as 500, or 405 for an old server)
            'redirect': None,            # answer every POST with 307 to this URL
            'tools': list(TOOLS),
            'scope_tools': {},           # tool -> scope the token must have, else 403 insufficient_scope
            'reveal_headers': (),        # header names `who` digests
            'hide_tools': (),
        }
        self.sessions = set()
        self.executions = []
        self.answers = []                # client answers to server-to-client requests (JSON-RPC responses)
        self.cancellations = []
        self.deletes = []
        self.pings = []                  # IDs of the ping requests sent on SSE streams

    def prm_url(self, form='path'):
        if form == 'path':
            return self.origin + '/.well-known/oauth-protected-resource' + self.path
        if form == 'root':
            return self.origin + '/.well-known/oauth-protected-resource'
        return self.origin + '/custom/resource-metadata'

    def prm(self):
        a = self.cfg['auth_server']
        m = {'resource': self.cfg['prm_resource'] or self.url, 'authorization_servers': [a.issuer] if a else [],
             'bearer_methods_supported': ['header']}
        if self.cfg['prm_scopes'] is not None:
            m['scopes_supported'] = self.cfg['prm_scopes']
        return m

    def challenge(self, error=None, scope=None):
        parts = []
        if error:
            parts.append(f'error="{error}"')
        m = self.cfg['challenge_metadata']
        if m:
            parts.append(f'resource_metadata="{m if isinstance(m, str) else self.prm_url("path")}"')
        s = scope if scope is not None else self.cfg['challenge_scope']
        if s:
            parts.append(f'scope="{s}"')
        return 'Bearer' + (' ' + ', '.join(parts) if parts else '')

    def handle(self, h, r):
        if r['method'] == 'GET':
            for form in self.cfg['prm_paths']:
                if r['path'] == urlsplit(self.prm_url(form)).path:
                    return h.reply(200, self.prm())
            if r['path'] == self.path:
                return h.reply(405, b'')      # no server-initiated stream
            return h.reply(404, {'error': 'not_found'})
        if r['path'] != self.path:
            return h.reply(404, {'error': 'not_found'})
        if self.cfg['redirect']:
            return h.reply(307, b'', headers={'Location': self.cfg['redirect']})
        if r['method'] == 'DELETE':
            with self.lock:
                self.deletes.append(r)
                self.sessions.discard(r['headers'].get('mcp-session-id'))
            return h.reply(self.cfg['delete_status'], b'')
        if r['method'] != 'POST':
            return h.reply(405, b'')
        try:
            r['message'] = json.loads(r['body'])
        except ValueError:
            r['message'] = None
        # auth
        r['grant'] = None
        mode = self.cfg['auth']
        if mode == 'headers':
            for name, value in self.cfg['headers'].items():
                if r['headers'].get(name.lower()) != value:
                    r['refused'] = 'headers'
                    return h.reply(401, {'error': 'unauthorized'}, headers={'WWW-Authenticate': 'Bearer'}
                                   if name.lower() == 'authorization' else None)
        elif mode == 'oauth':
            auth = r['headers'].get('authorization', '')
            grant, why = (None, 'no token')
            if auth.startswith('Bearer '):
                grant, why = self.cfg['auth_server'].token_valid(auth[7:], self.cfg['resource'])
            if not grant:
                r['refused'] = why
                return h.reply(401, {'error': 'unauthorized'},
                               headers={'WWW-Authenticate': self.challenge('invalid_token' if auth else None)})
            r['grant'] = grant
        message = r['message']
        if not isinstance(message, dict):
            return h.reply(400, {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}})
        method, mid, params = message.get('method'), message.get('id'), message.get('params') or {}
        if method is None:                  # a client's response to a server-to-client request
            with self.lock:
                self.answers.append(message)
            return h.reply(202, b'')
        sid = r['headers'].get('mcp-session-id')
        if method != 'initialize' and self.cfg['sessions'] and sid not in self.sessions:
            return h.reply(404 if sid else 400, {'jsonrpc': '2.0', 'id': mid,
                                                 'error': {'code': -32001, 'message': 'Session not found'}})
        if mid is None:                      # a notification
            if method == 'notifications/cancelled':
                with self.lock:
                    self.cancellations.append(params)
            return h.reply(202, b'')
        if method == 'initialize':
            if self.cfg['init_status']:
                return h.reply(self.cfg['init_status'], {'error': 'fixture'})
            requested = params.get('protocolVersion')
            version = self.cfg['protocol'] or (requested if requested in PROTOCOLS else '2025-06-18')
            headers = {}
            if self.cfg['sessions']:
                sid = 'sess_' + secrets.token_hex(8)
                with self.lock:
                    self.sessions.add(sid)
                headers['Mcp-Session-Id'] = sid
            result = {'protocolVersion': version,
                      'capabilities': {'tools': {'listChanged': False}, 'resources': {}},
                      'serverInfo': {'name': 'peerspan-conformance-remote', 'version': '1'}}
            return self.answer(h, mid, result, headers=headers)
        if method == 'ping':
            return self.answer(h, mid, {})
        if method == 'tools/list':
            tools = [t for t in self.cfg['tools'] if t['name'] not in self.cfg['hide_tools']]
            return self.answer(h, mid, {'tools': tools})
        if method == 'resources/list':
            return self.answer(h, mid, {'resources': RESOURCES})
        if method == 'resources/read':
            uri = params.get('uri')
            with self.lock:
                self.executions.append({'kind': 'read', 'uri': uri, 'request': r})
            return self.answer(h, mid, {'contents': [{'uri': uri, 'mimeType': 'text/plain',
                                                      'text': f'remote contents of {uri}'}]})
        if method == 'tools/call':
            return self.call(h, r, mid, params)
        return self.answer(h, mid, error={'code': -32601, 'message': f'Method not found: {method}'})

    def answer(self, h, mid, result=None, error=None, headers=None, before=()):
        message = {'jsonrpc': '2.0', 'id': mid}
        if error is not None:
            message['error'] = error
        else:
            message['result'] = result
        if self.cfg['reply'] != 'sse' and not before:
            return h.reply(200, message, headers=headers)
        events = list(before)
        if self.cfg['sse_noise']:
            ping_id = 'ping-' + secrets.token_hex(4)
            with self.lock:
                self.pings.append(ping_id)
            events[:0] = [{'jsonrpc': '2.0', 'method': 'notifications/message',
                           'params': {'level': 'info', 'data': 'fixture noise'}},
                          {'jsonrpc': '2.0', 'id': 987654321, 'result': {'content': [{'type': 'text',
                                                                                       'text': 'not yours'}]}},
                          {'jsonrpc': '2.0', 'id': ping_id, 'method': 'ping'}]
        h.send_response(200)
        h.send_header('Content-Type', 'text/event-stream')
        h.send_header('Cache-Control', 'no-cache')
        h.send_header('Connection', 'close')
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.end_headers()
        h.close_connection = True
        for event in events:
            if callable(event):
                event()
                continue
            h.wfile.write(f'event: message\ndata: {json.dumps(event)}\n\n'.encode())
            h.wfile.flush()
        h.wfile.write(f'id: {secrets.token_hex(4)}\nevent: message\ndata: {json.dumps(message)}\n\n'.encode())
        h.wfile.flush()

    def text(self, h, mid, text):
        return self.answer(h, mid, {'content': [{'type': 'text', 'text': text}], 'isError': False})

    def call(self, h, r, mid, params):
        name, args = params.get('name'), params.get('arguments') or {}
        with self.lock:
            self.executions.append({'kind': 'call', 'name': name, 'arguments': args, 'request': r, 'id': mid})
        need_scope = self.cfg['scope_tools'].get(name)
        if need_scope and r.get('grant') is not None and need_scope not in (r['grant'].get('scope') or '').split():
            return h.reply(403, {'error': 'insufficient_scope'},
                           headers={'WWW-Authenticate': self.challenge('insufficient_scope', need_scope)})
        if name == 'echo':
            return self.text(h, mid, str(args.get('text', '')))
        if name == 'write_note':
            return self.text(h, mid, 'noted: ' + str(args.get('text', '')))
        if name == 'who':
            g = r.get('grant')
            out = {'subject': g['subject'] if g else 'none', 'scope': g['scope'] if g else None,
                   'headers': {n: digest(r['headers'].get(n.lower(), '')) for n in self.cfg['reveal_headers']}}
            return self.text(h, mid, json.dumps(out, sort_keys=True))
        if name == 'sleep':
            time.sleep(float(args.get('seconds', 1)))
            return self.text(h, mid, str(args.get('text', 'slept')))
        if name == 'status':
            code = int(args.get('code', 500))
            headers = {'WWW-Authenticate': args['challenge']} if args.get('challenge') else {}
            if args.get('location'):
                headers['Location'] = args['location']
            return h.reply(code, {'error': 'fixture status'}, headers=headers)
        if name == 'drop':
            return h.drop()
        if name == 'garbage':
            return h.reply(200, 'this is not JSON-RPC', content_type='text/plain')
        if name == 'big':
            return self.text(h, mid, 'b' * int(args.get('bytes', 0)))
        if name == 'lose_session':
            with self.lock:
                self.sessions.clear()
            return h.reply(404, {'jsonrpc': '2.0', 'id': mid, 'error': {'code': -32001,
                                                                         'message': 'Session not found'}})
        if name == 'ask':
            ask_id = 'srv-' + secrets.token_hex(4)
            mark = len(self.answers)

            def wait():
                end = time.time() + 5
                while time.time() < end and not any(a.get('id') == ask_id for a in self.answers[mark:]):
                    time.sleep(0.05)
            request = {'jsonrpc': '2.0', 'id': ask_id, 'method': 'roots/list', 'params': {}}
            holder = {}

            def result_event():
                got = [a for a in self.answers[mark:] if a.get('id') == ask_id]
                holder['answered'] = got[0] if got else None
            # The SSE stream: the request, then (after waiting for the client's answer) the result.
            message_events = [request, wait, result_event]
            h.send_response(200)
            h.send_header('Content-Type', 'text/event-stream')
            h.send_header('Connection', 'close')
            h.end_headers()
            h.close_connection = True
            for e in message_events:
                if callable(e):
                    e()
                else:
                    h.wfile.write(f'event: message\ndata: {json.dumps(e)}\n\n'.encode())
                    h.wfile.flush()
            a = holder.get('answered')
            text = json.dumps({'answered': bool(a), 'code': (a or {}).get('error', {}).get('code')})
            final = {'jsonrpc': '2.0', 'id': mid, 'result': {'content': [{'type': 'text', 'text': text}],
                                                             'isError': False}}
            h.wfile.write(f'event: message\ndata: {json.dumps(final)}\n\n'.encode())
            h.wfile.flush()
            return None
        return self.answer(h, mid, error={'code': -32602, 'message': f'Unknown tool: {name}'})

    def calls(self, name=None, text=None, since=0):
        """tools/call executions, of requests from the request mark `since` on."""
        with self.lock:
            out = [e for e in self.executions if e['request']['index'] >= since]
        return [e for e in out if e['kind'] == 'call' and (name is None or e['name'] == name) and
                (text is None or (e['arguments'] or {}).get('text') == text)]


if __name__ == '__main__':
    # Manual use: start one authorization server and one MCP server needing its tokens, and print their URLs.
    a = AuthServer()
    m = McpServer()
    m.cfg.update(auth='oauth', auth_server=a)
    print(json.dumps({'issuer': a.issuer, 'mcp': m.url}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
