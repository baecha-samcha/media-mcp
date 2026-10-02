"""Single-owner OAuth policy using official MCP SDK protocol handlers.

No client-supplied URL is fetched. Registration allows only operator-configured
exact callbacks. SQLite survives restarts; raw codes/tokens are never stored.
"""
import asyncio
import base64
from collections import defaultdict, deque
import hashlib
import hmac
import ipaddress
from html import escape
import json
import logging
import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, unquote
from pydantic import AnyHttpUrl, TypeAdapter, ConfigDict
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import (OAuthAuthorizationServerProvider, AuthorizationCode, AuthorizationParams,
    AccessToken, RefreshToken, AuthorizeError, TokenError, RegistrationError, construct_redirect_uri)
from mcp.server.auth.routes import create_auth_routes, create_protected_resource_routes, build_metadata
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions, AuthSettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from .oauth_store import OAuthStore, digest

log = logging.getLogger(__name__)

SCOPES = ['media:read', 'offline_access']
TOKEN_PATTERN = re.compile(r'[A-Za-z0-9_-]{43}\Z')
# Reject duplicates without returning credentials; delayed reuse still revokes.
REFRESH_COLLISION_SECONDS = 5
CONSENT_RECEIPT_SECONDS = 300
STATE_PATTERN = re.compile(r'[\x21-\x7e]{1,1024}\Z')
CALLBACK = 'https://chatgpt.com/connector_platform_oauth_redirect'
URL_ADAPTER = TypeAdapter(AnyHttpUrl, config=ConfigDict(url_preserve_empty_path=True))


def owner_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return 'scrypt:' + salt.hex() + ':' + derived.hex()


def valid_owner_hash(value):
    return bool(re.fullmatch(r'scrypt:[0-9a-f]{32}:[0-9a-f]{64}', value))


def owner_matches(password, encoded):
    if not isinstance(password, str) or not 9 <= len(password) <= 1024:
        return False
    return hmac.compare_digest(owner_hash(password, bytes.fromhex(encoded.split(':')[1])), encoded)


def valid_redirect(value):
    try:
        p = urlsplit(value)
        port = p.port
    except (ValueError, TypeError):
        return False
    try:
        ipaddress.ip_address(p.hostname or '')
    except ValueError:
        pass
    else:
        return False
    return (p.scheme == 'https' and p.hostname and not p.username and not p.password
            # The authority also becomes a CSP host-source. Reject directive
            # delimiters/quotes here, in addition to the raw URL checks below.
            and re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?', p.netloc) is not None
            and port in (None, 443) and p.path.startswith('/') and p.path != '/'
            and not p.query and not p.fragment and not any(c in value for c in ('%', '\\', '*'))
            and all(33 <= ord(c) < 127 for c in value)
            and p.hostname not in ('localhost', '127.0.0.1', '::1'))


def error(code, status=400):
    headers = {'Cache-Control': 'no-store', 'Pragma': 'no-cache'}
    if status == 401:
        headers['WWW-Authenticate'] = 'Basic realm="media-mcp OAuth"'
    return JSONResponse({'error': code}, status_code=status, headers=headers)


def unique_object(pairs):
    """Reject duplicate JSON keys before the SDK independently parses DCR."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON member')
        result[key] = value
    return result


def safe_sdk_error(response):
    if response.status_code < 400:
        return response
    # SDK Pydantic errors can reflect input values (including credentials).
    return error(json.loads(response.body).get('error', 'invalid_request'), response.status_code)


class OwnerOAuth(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, settings):
        self.settings = settings
        self.issuer = settings.public_base_url.rstrip('/')
        self.resource = self.issuer + '/mcp'
        self.redirects = set(settings.oauth_redirect_uris.split(','))
        # Only startup-validated server configuration contributes CSP sources.
        # Paths/queries and client-provided redirect parameters never enter CSP.
        callback_origins = {urlsplit(uri)._replace(path='', query='', fragment='').geturl()
                            for uri in self.redirects}
        self.consent_form_sources = ' '.join(["'self'", self.issuer,
                                              *sorted(callback_origins - {self.issuer})])
        self.store = OAuthStore(settings.oauth_store_dir or settings.temp_dir + '/oauth-v1', settings.oauth_storage_key)
        self.rate = defaultdict(deque)
        self.cookie = '__Host-media-oauth' if self.issuer.startswith('https:') else 'media-oauth-local'
        self.registration = ClientRegistrationOptions(enabled=True, valid_scopes=SCOPES,
            default_scopes=SCOPES, client_secret_expiry_seconds=None if settings.oauth_persistent_grants else 31536000)
        self.revocation = RevocationOptions(enabled=True)

    def start(self):
        try:
            self.store.start(self.settings.owner_password_hash, self.issuer)
        except BaseException:
            self.store.close()
            raise

    def limit(self, name, maximum):
        now = time.monotonic()
        queue = self.rate[name]
        while queue and queue[0] <= now - 60:
            queue.popleft()
        if len(queue) >= maximum:
            return False
        queue.append(now)
        return True

    def has_room(self):
        self.store.cleanup()
        return self.store.count() < 4090

    async def get_client(self, client_id):
        if not isinstance(client_id, str) or len(client_id) > 128:
            return None
        data = self.store.get('client', client_id)
        if not data:
            return None
        client = OAuthClientInformationFull.model_validate(data)
        if any(str(uri) not in self.redirects for uri in client.redirect_uris):
            return None
        return client

    async def register_client(self, client_info):
        uris = [str(uri) for uri in client_info.redirect_uris]
        if not uris or len(uris) > 4 or any(u not in self.redirects or not valid_redirect(u) for u in uris):
            raise RegistrationError('invalid_redirect_uri', 'Callback is not on the owner allowlist')
        if (set(client_info.grant_types) - {'authorization_code', 'refresh_token'}
                or client_info.response_types != ['code']
                or client_info.token_endpoint_auth_method not in ('none', 'client_secret_post', 'client_secret_basic')):
            raise RegistrationError('invalid_client_metadata', 'Unsupported client policy')
        if not self.has_room() or self.store.count('client') >= 64:
            raise RegistrationError('invalid_client_metadata', 'Registration capacity reached')
        self.store.put('client', client_info.client_id, client_info.model_dump(mode='json'), 2**62 if self.settings.oauth_persistent_grants else time.time()+31536000)

    async def authorize(self, client, params):
        if (not params.state or not STATE_PATTERN.fullmatch(params.state)
                or not TOKEN_PATTERN.fullmatch(params.code_challenge)):
            raise AuthorizeError('invalid_request', 'Valid state and S256 challenge are required')
        if str(params.redirect_uri) not in self.redirects:
            raise AuthorizeError('invalid_request', 'Callback is not permitted')
        if params.resource != self.resource:
            raise AuthorizeError('invalid_target', 'Resource must match the MCP endpoint')
        if 'media:read' not in (params.scopes or []):
            raise AuthorizeError('invalid_scope', 'media:read is required')
        if not self.has_room() or self.store.count('pending') >= 64:
            raise AuthorizeError('temporarily_unavailable', 'Approval capacity reached')
        log.info('oauth authorize accepted offline_access_requested=%s', 'offline_access' in params.scopes)
        ticket = secrets.token_urlsafe(32)
        self.store.put('pending', digest(ticket), {'client_id': client.client_id,
            'params': params.model_dump(mode='json')}, time.time()+300)
        return self.issuer + '/oauth/consent?request_id=' + ticket

    def family_active(self, family):
        data = self.store.get('family', family)
        return data if data and not data['revoked'] else None

    def revoke_family(self, family, reason):
        data = self.store.get('family', family)
        if data:
            log.warning('oauth family_revoked reason=%s', reason)
            data['revoked'] = True
            self.store.put('family', family, data, data['expires_at'])

    async def load_authorization_code(self, client, authorization_code):
        data = self.store.get('code', digest(authorization_code))
        if not data or data['client_id'] != client.client_id:
            log.info('oauth authorization_code rejected reason=missing_expired_or_wrong_client')
            return None
        if data.get('used'):
            self.revoke_family(data['family'], 'authorization_code_reuse')
            return None
        return AuthorizationCode(code=authorization_code, **{k:v for k,v in data.items() if k not in ('used','family')})

    def issue(self, client_id, scopes, family, family_expires):
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(32), None
        persistent = family_expires == 2**62
        expiry = family_expires if persistent else min(now+self.settings.oauth_access_ttl, family_expires)
        common = {'client_id': client_id, 'scopes': scopes, 'resource': self.resource,
                  'subject': 'owner', 'family': family}
        generation = self.store.get('family',family).get('generation',0)
        self.store.put('access', digest(access), {**common, 'expires_at': None if persistent else expiry, 'generation':generation}, expiry)
        if 'offline_access' in scopes:
            refresh = secrets.token_urlsafe(32)
            self.store.put('refresh', digest(refresh), {**common, 'expires_at': family_expires, 'used': False}, family_expires)
        return OAuthToken(access_token=access, token_type='Bearer', expires_in=None if persistent else expiry-now,
                          refresh_token=refresh, scope=' '.join(scopes))

    async def exchange_authorization_code(self, client, authorization_code):
        failure = False
        with self.store.transaction():
            data = self.store.get('code', digest(authorization_code.code))
            if not data or data['client_id'] != client.client_id or data.get('used'):
                if data and data.get('family'):
                    self.revoke_family(data['family'], 'authorization_code_reuse')
                failure = True
            else:
                family = secrets.token_hex(32)
                expiry = 2**62 if self.settings.oauth_persistent_grants else int(time.time())+self.settings.oauth_refresh_ttl
                self.store.put('family', family, {'revoked': False, 'expires_at': expiry, 'generation': 0,
                    'refresh_issued': 'offline_access' in authorization_code.scopes}, expiry)
                data.update(used=True, family=family)
                self.store.put('code', digest(authorization_code.code), data, data['expires_at'])
                tokens = self.issue(client.client_id, authorization_code.scopes, family, expiry)
        if failure:
            raise TokenError('invalid_grant', 'Code is invalid or already used')
        log.info('oauth authorization_code exchanged refresh_issued=%s', tokens.refresh_token is not None)
        return tokens

    def reject_refresh_reuse(self, data):
        # Never return the successor or mint another token for a used credential.
        # A bounded collision interval prevents parallel requests from destroying
        # the winner. Legacy records without used_at retain strict revocation.
        age = time.time() - data.get('used_at', 0)
        if 0 <= age < REFRESH_COLLISION_SECONDS:
            log.warning('oauth refresh_rejected reason=rotation_collision')
        else:
            self.revoke_family(data['family'], 'refresh_reuse')

    async def load_refresh_token(self, client, refresh_token):
        data = self.store.get('refresh', digest(refresh_token))
        if not data or data['client_id'] != client.client_id:
            log.info('oauth refresh_rejected reason=missing_expired_or_wrong_client')
            return None
        if data['used']:
            self.reject_refresh_reuse(data)
            return None
        if not self.family_active(data['family']):
            log.info('oauth refresh_rejected reason=family_inactive')
            return None
        return RefreshToken(token=refresh_token, **{k:v for k,v in data.items() if k not in ('used','family')})

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        failure = False
        with self.store.transaction():
            data = self.store.get('refresh', digest(refresh_token.token))
            if (not data or data['client_id'] != client.client_id or data['used']
                    or not self.family_active(data['family'])):
                if data and data['client_id'] == client.client_id and data['used']:
                    self.reject_refresh_reuse(data)
                failure = True
            else:
                data['used'] = True
                data['used_at'] = time.time()
                self.store.put('refresh', digest(refresh_token.token), data, data['expires_at'])
                # Revoke previous access tokens from this generation via family epoch.
                family = self.store.get('family', data['family'])
                family['generation'] = family.get('generation', 0)+1
                self.store.put('family', data['family'], family, family['expires_at'])
                tokens = self.issue(client.client_id, scopes, data['family'], data['expires_at'])
        if failure:
            raise TokenError('invalid_grant', 'Refresh token is invalid or already used')
        log.info('oauth refresh_rotated reason=valid_refresh')
        return tokens

    async def load_access_token(self, token):
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        data = self.store.get('access', digest(token))
        if not data:
            return None
        family = self.family_active(data['family'])
        if not family or data.get('generation', 0) != family.get('generation', 0):
            return None
        if not await self.get_client(data['client_id']):
            return None
        return AccessToken(token=token, **{k:v for k,v in data.items() if k not in ('family','generation')},
                           claims={'iss': self.issuer})

    async def revoke_token(self, token):
        kind = 'access' if isinstance(token, AccessToken) else 'refresh'
        data = self.store.get(kind, digest(token.token))
        if data:
            self.revoke_family(data['family'], 'explicit_revocation')

    async def verify_token(self, token):
        # The API key is checked only as its exact value; OAuth never falls back
        # to treating malformed/expired tokens as another kind of credential.
        if hmac.compare_digest(token.encode(), self.settings.api_key.encode()):
            return AccessToken(token=token, client_id='legacy-api-key', scopes=['media:read'],
                               resource=self.resource, subject='owner', claims={'iss':self.issuer})
        return await self.load_access_token(token)

    def completed_consent(self, request, form):
        receipt = self.store.get('consent_receipt', digest(form.get('request_id', '')))
        if receipt is None:
            log.warning('consent_denied: pending')
            return error('access_denied', 403)
        if (receipt['decision'] != form.get('decision')
                or not hmac.compare_digest(receipt['browser'], digest(request.cookies.get(self.cookie, '')))
                or not hmac.compare_digest(receipt['csrf'], digest(form.get('csrf', '')))):
            log.warning('consent_denied: completed_binding')
            return error('access_denied', 403)
        log.warning('consent_duplicate: already_completed')
        # A receipt is only an acknowledgement, never another callback/code.
        return HTMLResponse('<!doctype html><title>Request already processed</title>'
            '<h1>Request already processed</h1><p>Return to ChatGPT to check the connection. '
            'If it did not finish, start a new connection there.</p>',
            headers={'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"})

    async def consent(self, request):
        if not self.limit('consent', 30):
            return error('temporarily_unavailable', 429)
        if request.method == 'GET':
            ticket = request.query_params.get('request_id', '')
            pending = self.store.get('pending', digest(ticket))
            if not pending:
                return error('invalid_request')
            browser, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            pending.update(browser=digest(browser), csrf=digest(csrf))
            # Reloading consent never extends the original authorization TTL.
            row = self.store.db.execute('SELECT expires FROM records WHERE kind=? AND key=?',('pending',digest(ticket))).fetchone()
            self.store.put('pending', digest(ticket), pending, row[0])
            client = await self.get_client(pending['client_id'])
            if not client:
                return error('invalid_client')
            params = pending['params']
            lifetime = ('Access and refresh grants do not expire automatically; they remain valid until revoked.'
                        if self.settings.oauth_persistent_grants else
                        f'Access tokens last up to {self.settings.oauth_access_ttl} seconds. '
                        f'If offline_access is approved, the refresh grant lasts up to {self.settings.oauth_refresh_ttl} seconds.')
            page = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Approve media-mcp access</title><h1>Approve media-mcp access</h1>
<p>Only approve a connection you just started. The client name below is unverified.</p>
<p>Client: {escape(client.client_name or 'Unnamed client')}</p><p>Client ID: {escape(client.client_id)}</p>
<p>Callback: {escape(str(params['redirect_uri']))}</p><p>Scopes: {escape(' '.join(params['scopes']))}</p>
<p>This grants access to extract and prepare Instagram/YouTube media.
{lifetime}</p>
<form method="post" action="/oauth/consent"><input type="hidden" name="request_id" value="{ticket}">
<input type="hidden" name="csrf" value="{csrf}"><label>Owner password <input type="password" name="password" required minlength="9" maxlength="1024" autocomplete="current-password"></label>
<button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></form></html>'''
            # Explicit issuer supports opaque-origin documents; configured
            # callback origins also permit browsers that check form redirects.
            response = HTMLResponse(page, headers={'Content-Security-Policy': f"default-src 'none'; form-action {self.consent_form_sources}; frame-ancestors 'none'; base-uri 'none'", 'X-Frame-Options':'DENY'})
            response.set_cookie(self.cookie,browser,max_age=300,secure=self.issuer.startswith('https:'),httponly=True,samesite='lax',path='/')
            return response
        # A browser form POST can serialize Origin as "null" (including under
        # no-referrer). This is not a trusted origin: only this consent handler
        # accepts it, subject to ALL ticket/browser-cookie/CSRF/password checks
        # below. Missing Origin and concrete foreign origins remain forbidden.
        # Fetch Metadata is not an authentication substitute or a requirement
        # for clients that omit it; the pending request binding is authoritative.
        if request.headers.get('origin') not in (self.issuer, 'null'):
            # Temporary diagnostics: fixed stage names only, never request data.
            log.warning('consent_denied: origin')
            return error('access_denied',403)
        if request.headers.get('content-type','').split(';')[0] != 'application/x-www-form-urlencoded':
            return error('invalid_request')
        form = await request.form()
        if len(form) != len(form.multi_items()) or not all(isinstance(v,str) for v in form.values()):
            return error('invalid_request')
        if form.get('decision') not in ('approve', 'deny'):
            return error('invalid_request')
        ticket = form.get('request_id','')
        pending = self.store.get('pending', digest(ticket))
        if not pending:
            return self.completed_consent(request, form)
        if not hmac.compare_digest(pending.get('browser',''),digest(request.cookies.get(self.cookie,''))):
            log.warning('consent_denied: browser_cookie')
            return error('access_denied',403)
        if not hmac.compare_digest(pending.get('csrf',''),digest(form.get('csrf',''))):
            log.warning('consent_denied: csrf')
            return error('access_denied',403)
        if not self.limit('owner_password',5):
            return error('temporarily_unavailable',429)
        if not await asyncio.to_thread(owner_matches,form.get('password',''),self.settings.owner_password_hash):
            log.warning('consent_denied: owner_password')
            return error('access_denied',403)
        if not await self.get_client(pending['client_id']):
            return error('invalid_client')
        # Recheck after the password worker await: approval is single-use too.
        with self.store.transaction():
            current = self.store.get('pending',digest(ticket))
            if not current:
                return self.completed_consent(request, form)
            if (current.get('csrf') != pending.get('csrf')
                    or current.get('browser') != pending.get('browser')):
                log.warning('consent_denied: changed_binding')
                return error('access_denied', 403)
            self.store.put('consent_receipt', digest(ticket),
                {'browser': current['browser'], 'csrf': current['csrf'], 'decision': form['decision']},
                time.time() + CONSENT_RECEIPT_SECONDS)
            self.store.delete('pending',digest(ticket))
            params = AuthorizationParams.model_validate(current['params'])
            if form.get('decision') == 'approve':
                code = secrets.token_urlsafe(32)
                auth = AuthorizationCode(code='',client_id=current['client_id'],scopes=params.scopes,
                    expires_at=time.time()+self.settings.oauth_code_ttl,code_challenge=params.code_challenge,
                    redirect_uri=params.redirect_uri,redirect_uri_provided_explicitly=True,resource=self.resource,subject='owner')
                value = auth.model_dump(mode='json');value.pop('code')
                self.store.put('code',digest(code),value,auth.expires_at)
                location = construct_redirect_uri(str(params.redirect_uri),code=code,state=params.state,iss=self.issuer)
            else:
                location = construct_redirect_uri(str(params.redirect_uri),error='access_denied',state=params.state,iss=self.issuer)
        # Temporary diagnostics, after COMMIT so rolled-back changes are never
        # reported as consumed/created. No request identifiers or secret values.
        if form.get('decision') == 'approve':
            log.warning('consent approval accepted')
            log.warning('consent approval: pending consumed')
            log.warning('consent approval: authorization code created')
            flow = 'approval'
        else:
            log.warning('consent denial accepted')
            log.warning('consent denial: pending consumed')
            flow = 'denial'
        response = RedirectResponse(location,status_code=303)
        # Keep the short-lived browser binding for duplicate acknowledgements.
        # The cookie alone cannot authorize anything; pending is already gone.
        # Inspect the generated header, never log Location itself or its query.
        # This confirms response construction, not browser/callback delivery.
        target = urlsplit(response.headers['location'])
        log.warning('consent %s: redirect response generated status=%d origin=%s://%s path=%s',
                    flow, response.status_code, target.scheme, target.netloc, target.path)
        return response

    def auth_settings(self):
        return AuthSettings(issuer_url=URL_ADAPTER.validate_python(self.issuer),
            resource_server_url=URL_ADAPTER.validate_python(self.resource),
            validate_token_resource=True, required_scopes=['media:read'])

    async def metadata(self, request):
        data = build_metadata(URL_ADAPTER.validate_python(self.issuer),None,self.registration,self.revocation).model_dump(mode='json',exclude_none=True)
        data.update(issuer=self.issuer, authorization_response_iss_parameter_supported=True,
                    token_endpoint_auth_methods_supported=['none','client_secret_post','client_secret_basic'],
                    revocation_endpoint_auth_methods_supported=['none','client_secret_post','client_secret_basic'])
        return JSONResponse(data)

    async def protocol(self, request):
        if request.url.path != '/token':
            return await self._protocol(request)
        request.state.oauth_grant = 'unknown'
        request.state.oauth_stage = 'request'
        status = 500
        try:
            response = await self._protocol(request)
            status = response.status_code
            return response
        finally:
            # Only server-selected enums and HTTP status; never exceptions/forms.
            log.info('oauth token grant=%s stage=%s outcome=%s status=%d',
                     request.state.oauth_grant, request.state.oauth_stage,
                     'success' if status == 200 else 'failure', status)

    async def _protocol(self, request):
        """Narrow policy checks around SDK endpoints, including SDK 2.2 gaps:
        exact raw callbacks, required state, RFC8707 on token exchange, Basic
        client ID without a form duplicate, and RFC9207 issuer on redirects.
        """
        path = request.url.path
        maximum = {'/register':10,'/authorize':60,'/token':120,'/revoke':60}[path]
        if not self.limit(path,maximum):
            return error('temporarily_unavailable',429)
        if path == '/register':
            try:
                if request.headers.get('content-type','').split(';')[0] != 'application/json':
                    return error('invalid_client_metadata')
                data = json.loads(await request.body(), object_pairs_hook=unique_object)
                uris = data['redirect_uris']
                if not isinstance(uris,list) or not uris or any(not isinstance(u,str) or u not in self.redirects for u in uris):
                    return error('invalid_redirect_uri')
            except (ValueError,KeyError,TypeError):
                return error('invalid_client_metadata')
            return safe_sdk_error(await self.registration_handler.handle(request))
        if request.method == 'GET':
            pairs = list(request.query_params.multi_items())
        else:
            if request.headers.get('content-type','').split(';')[0] != 'application/x-www-form-urlencoded':
                return error('invalid_request')
            pairs = list((await request.form()).multi_items())
        if len(dict(pairs)) != len(pairs) or not all(isinstance(v,str) for _,v in pairs):
            return error('invalid_request')
        params = dict(pairs)
        if path == '/token':
            request.state.oauth_grant = (params.get('grant_type')
                if params.get('grant_type') in ('authorization_code', 'refresh_token') else 'unsupported')
            request.state.oauth_stage = 'client_auth'
        if path == '/authorize':
            client = await self.get_client(params.get('client_id',''))
            if (not client or params.get('redirect_uri') not in [str(u) for u in client.redirect_uris]
                    or params.get('redirect_uri') not in self.redirects):
                return error('invalid_request')  # Never redirect an invalid raw callback.
            if (not STATE_PATTERN.fullmatch(params.get('state',''))
                    or params.get('code_challenge_method') != 'S256'
                    or not TOKEN_PATTERN.fullmatch(params.get('code_challenge',''))):
                location=construct_redirect_uri(params['redirect_uri'],error='invalid_request',state=params.get('state'),iss=self.issuer)
                return RedirectResponse(location,status_code=302)
            response = await AuthorizationHandler(self).handle(request)
            if response.status_code == 302:
                location = response.headers['location']
                if not location.startswith(self.issuer+'/oauth/consent?'):
                    values = dict(parse_qsl(urlsplit(location).query))
                    response.headers['location'] = construct_redirect_uri(params['redirect_uri'],
                        error=values.get('error', 'server_error'), state=params.get('state'), iss=self.issuer)
            return safe_sdk_error(response)
        # The SDK requires client_id in the form even with HTTP Basic. Normalize
        # the standard Basic-only request before passing it through SDK auth.
        header = request.headers.get('authorization','')
        if header.lower().startswith('basic '):
            try:
                identifier, _ = base64.b64decode(header[6:],validate=True).decode().split(':',1)
                identifier = unquote(identifier)
                if params.get('client_id',identifier) != identifier or 'client_secret' in params:
                    return error('invalid_client',401)
                params['client_id'] = identifier
            except (ValueError,UnicodeError):
                return error('invalid_client',401)
        # SDK ignores extraneous credentials for public/post clients; reject
        # ambiguous combinations rather than silently selecting one identity.
        client = await self.get_client(params.get('client_id',''))
        if header and (not header.lower().startswith('basic ') or not client
                       or client.token_endpoint_auth_method != 'client_secret_basic'):
            return error('invalid_client',401)
        if client and client.token_endpoint_auth_method == 'none' and params.get('client_secret'):
            return error('invalid_client',401)
        if path == '/token':
            if params.get('grant_type') not in ('authorization_code','refresh_token'):
                return error('unsupported_grant_type')
            request.state.oauth_stage = 'resource'
            if params.get('resource') != self.resource:
                return error('invalid_target')
            request.state.oauth_stage = 'grant_validation'
            if params['grant_type'] == 'authorization_code':
                request.state.oauth_stage = 'pkce'
                if not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}',params.get('code_verifier','')):
                    return error('invalid_grant')
                data = self.store.get('code',digest(params.get('code','')))
                if data:
                    hashed=base64.urlsafe_b64encode(hashlib.sha256(params['code_verifier'].encode()).digest()).decode().rstrip('=')
                    if not hmac.compare_digest(hashed,data['code_challenge']):
                        return error('invalid_grant')
                    request.state.oauth_stage = 'redirect_uri'
                    if params.get('redirect_uri') != data['redirect_uri']:
                        return error('invalid_grant')
            request.state.oauth_stage = 'capacity'
            if not self.has_room():
                return error('temporarily_unavailable',503)
        else:
            params.setdefault('client_secret','')  # SDK revocation field is required even for public clients.
        body = urlencode(params).encode()
        scope = dict(request.scope)
        scope['headers'] = [(k,v) for k,v in scope['headers'] if k != b'content-length'] + [(b'content-length',str(len(body)).encode())]
        if header.lower().startswith('basic '):
            scope['headers'] = [(k, b'Basic ' + v[6:] if k == b'authorization' else v)
                                for k,v in scope['headers']]
        async def receive():
            return {'type':'http.request','body':body,'more_body':False}
        normalized = Request(scope,receive)
        handler = TokenHandler(self,ClientAuthenticator(self)) if path == '/token' else RevocationHandler(self,ClientAuthenticator(self))
        if path == '/token':
            request.state.oauth_stage = 'sdk_exchange'
        response = await handler.handle(normalized)
        if path == '/token' and response.status_code >= 400:
            code = json.loads(response.body).get('error')
            reason = code if code in ('invalid_client', 'invalid_grant', 'invalid_scope',
                'invalid_request', 'unsupported_grant_type') else 'other'
            log.info('oauth token_rejected reason=%s', reason)
        return safe_sdk_error(response)

    def routes(self):
        from mcp.server.auth.handlers.register import RegistrationHandler
        self.registration_handler = RegistrationHandler(self,self.registration)
        # SDK-generated AS metadata/endpoint names remain the source of truth.
        routes = create_auth_routes(self,URL_ADAPTER.validate_python(self.issuer),
            client_registration_options=self.registration,revocation_options=self.revocation)
        for index, route in enumerate(routes):
            handler = self.metadata if route.path == '/.well-known/oauth-authorization-server' else self.protocol
            routes[index] = Route(route.path,handler,methods=['GET'] if handler == self.metadata else
                                  ['GET','POST'] if route.path == '/authorize' else ['POST'])
        prm = create_protected_resource_routes(URL_ADAPTER.validate_python(self.resource),
            [URL_ADAPTER.validate_python(self.issuer)],scopes_supported=SCOPES,resource_name='media-mcp')
        routes.extend(prm)
        routes.append(Route('/.well-known/oauth-protected-resource',prm[0].endpoint,methods=['GET','OPTIONS']))
        routes.append(Route('/oauth/consent',self.consent,methods=['GET','POST']))
        return routes
