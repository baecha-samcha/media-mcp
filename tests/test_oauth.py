"""Offline OAuth end-to-end tests against real SDK handlers and encrypted store."""
import asyncio
from unittest.mock import patch
import base64
from dataclasses import replace
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from media_mcp.api import create_app
from media_mcp.config import Settings
from media_mcp.oauth import CALLBACK, owner_hash
from media_mcp.oauth_store import digest
from media_mcp.service import MediaService
from test_server import fake_runner, KEY, URL

OWNER = 'owner-only-test-password-not-production'
HASH = owner_hash(OWNER)
BASE = 'https://media.example'
RESOURCE = BASE+'/mcp'
VERIFIER = 'v'*64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip('=')


class Form(HTMLParser):
    def __init__(self, text):
        super().__init__();self.fields={};self.feed(text)
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='input' and attrs.get('type')=='hidden':
            self.fields[attrs['name']]=attrs['value']


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.settings=Settings(api_key=KEY,public_base_url=BASE,temp_dir=self.temp.name,
            owner_password_hash=HASH,oauth_storage_key=Fernet.generate_key().decode())
        self.open_app()

    def open_app(self):
        self.app=create_app(self.settings,MediaService(self.settings,runner=fake_runner))
        self.http=TestClient(self.app,base_url=BASE,follow_redirects=False)
        self.http.__enter__();self.provider=self.app.state.oauth

    def tearDown(self):
        self.http.__exit__(None,None,None);self.temp.cleanup()

    def register(self, method='client_secret_post'):
        r=self.http.post('/register',json={'redirect_uris':[CALLBACK], 'client_name':'Test client',
            'token_endpoint_auth_method':method,'grant_types':['authorization_code','refresh_token'],
            'response_types':['code'],'scope':'media:read offline_access'})
        self.assertEqual(r.status_code,201,r.text)
        return r.json()

    def params(self, client, **changes):
        return {'client_id':client['client_id'],'redirect_uri':CALLBACK,'response_type':'code',
            'state':'state-for-this-browser-123','code_challenge':CHALLENGE,
            'code_challenge_method':'S256','scope':'media:read offline_access','resource':RESOURCE,**changes}

    def approval_form(self, client, **changes):
        r=self.http.get('/authorize',params=self.params(client,**changes))
        self.assertEqual(r.status_code,302,r.text)
        self.assertTrue(r.headers['location'].startswith(BASE+'/oauth/consent?'),r.headers['location'])
        page=self.http.get(r.headers['location'])
        self.assertEqual(page.status_code,200,page.text)
        self.assertIn("frame-ancestors 'none'",page.headers['content-security-policy'])
        self.assertEqual(page.headers['content-security-policy'],
            f"default-src 'none'; form-action 'self' {self.provider.issuer} https://chatgpt.com; frame-ancestors 'none'; base-uri 'none'")
        self.assertIn('Secure',page.headers['set-cookie'])
        self.assertIn('HttpOnly',page.headers['set-cookie'])
        self.assertIn('__Host-media-oauth=',page.headers['set-cookie'])
        self.assertIn('SameSite=lax',page.headers['set-cookie'])
        self.assertIn('Path=/',page.headers['set-cookie'])
        self.assertNotIn('Domain=',page.headers['set-cookie'])
        return Form(page.text).fields

    def authorize(self, client, **changes):
        form=self.approval_form(client,**changes)
        r=self.http.post('/oauth/consent',data={**form,'password':OWNER,'decision':'approve'},headers={'Origin':BASE})
        self.assertEqual(r.status_code,303,r.text)
        params=parse_qs(urlsplit(r.headers['location']).query)
        self.assertEqual(params['iss'],[BASE]);self.assertEqual(params['state'],['state-for-this-browser-123'])
        return params['code'][0]

    def exchange(self,client,code,**changes):
        params={'grant_type':'authorization_code','client_id':client['client_id'],
                'code':code,'redirect_uri':CALLBACK,'code_verifier':VERIFIER,'resource':RESOURCE}
        if client.get('client_secret'): params['client_secret']=client['client_secret']
        return self.http.post('/token',data={**params,**changes})

    def token(self,client=None):
        client=client or self.register()
        r=self.exchange(client,self.authorize(client))
        self.assertEqual(r.status_code,200,r.text)
        return client,r.json()

    def refresh(self,client,tokens,**changes):
        data={'grant_type':'refresh_token','client_id':client['client_id'],
              'refresh_token':tokens['refresh_token'],'resource':RESOURCE}
        if client.get('client_secret'): data['client_secret']=client['client_secret']
        return self.http.post('/token',data={**data,**changes})

    def mcp(self,token,method='tools/list',params=None):
        return self.http.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':method,'params':params or {}},
            headers={'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream'})

    def test_discovery_and_unauthenticated_challenge(self):
        r=self.http.post('/mcp',json={})
        self.assertEqual(r.status_code,401)
        self.assertIn('resource_metadata="'+BASE+'/.well-known/oauth-protected-resource/mcp"',r.headers['www-authenticate'])
        resource=self.http.get('/.well-known/oauth-protected-resource/mcp').json()
        self.assertEqual(resource['resource'],RESOURCE)
        self.assertEqual(resource['authorization_servers'],[BASE])
        self.assertEqual(self.http.get('/.well-known/oauth-protected-resource').json(),resource)
        metadata=self.http.get('/.well-known/oauth-authorization-server').json()
        self.assertEqual(metadata['issuer'],BASE)
        self.assertIn('offline_access',metadata['scopes_supported'])
        self.assertEqual(metadata['code_challenge_methods_supported'],['S256'])
        self.assertTrue(metadata['authorization_response_iss_parameter_supported'])
        self.assertEqual(metadata['registration_endpoint'],BASE+'/register')
        self.assertIn('refresh_token',metadata['grant_types_supported'])
        self.assertIn('none',metadata['token_endpoint_auth_methods_supported'])

    def test_existing_api_key_boundaries_and_capability_media(self):
        self.assertEqual(self.http.get('/health').status_code,200)
        for endpoint in ('/extract','/prepare'):
            self.assertEqual(self.http.post(endpoint,json={'url':URL}).status_code,401)
            r=self.http.post(endpoint,json={'url':URL},headers={'Authorization':'Bearer '+KEY})
            self.assertEqual(r.status_code,200,r.text)
            if endpoint=='/prepare': self.assertEqual(self.http.get(r.json()['media'][0]['url']).status_code,200)
        self.assertEqual(self.mcp(KEY).status_code,200)
        _,token=self.token()
        self.assertEqual(self.http.post('/extract',json={'url':URL},headers={'Authorization':'Bearer '+token['access_token']}).status_code,401)

    def test_owner_approval_required_and_csrf(self):
        client=self.register();form=self.approval_form(client)
        self.assertEqual(self.provider.store.count('code'),0)
        for data,headers in [({**form,'password':'wrong','decision':'approve'},{'Origin':BASE}),
                ({**form,'password':OWNER,'csrf':'wrong','decision':'approve'},{'Origin':BASE}),
                ({**form,'password':OWNER,'decision':'approve'},{}),
                ({**form,'password':OWNER,'decision':'approve'},{'Origin':'https://evil.test'})]:
            self.assertEqual(self.http.post('/oauth/consent',data=data,headers=headers).status_code,403)
        self.assertEqual(self.provider.store.count('code'),0)
        self.http.cookies.clear()
        self.assertEqual(self.http.post('/oauth/consent',data={**form,'password':OWNER,'decision':'approve'},headers={'Origin':BASE}).status_code,403)
        self.assertEqual(self.exchange(client,'not-approved').status_code,400)

    def test_oauth_origin_routing_and_flow(self):
        # Cross-origin OAuth requests must reach protocol validation, not the
        # legacy HTTP Origin gate. Consent still rejects concrete foreign origins.
        self.http.headers['Origin']='https://chatgpt.com'
        for path in ('/.well-known/oauth-authorization-server',
                     '/.well-known/oauth-protected-resource',
                     '/.well-known/oauth-protected-resource/mcp'):
            self.assertEqual(self.http.get(path).status_code,200,path)
        r=self.http.post('/register',json={'redirect_uris':['https://evil.test/cb']})
        self.assertEqual(r.json()['error'],'invalid_redirect_uri')
        client=self.register()
        r=self.http.get('/authorize',params=self.params(client,redirect_uri='https://evil.test/cb'))
        self.assertEqual(r.status_code,400)
        self.assertNotIn('location',r.headers)
        for changes in ({'state':''},{'code_challenge_method':'plain'}):
            r=self.http.get('/authorize',params=self.params(client,**changes))
            self.assertEqual(r.status_code,302)
            self.assertIn('error=',r.headers['location'])
        form=self.approval_form(client)
        data={**form,'password':OWNER,'decision':'approve'}
        for origin in ('https://chatgpt.com','https://evil.test','',
                       f'http://localhost:{self.settings.port}'):
            r=self.http.post('/oauth/consent',data=data,headers={'Origin':origin})
            self.assertEqual(r.status_code,403,r.text)
            self.assertEqual(r.json()['error'],'access_denied')
        r=self.http.post('/oauth/consent',data={**data,'csrf':'wrong'},headers={'Origin':BASE})
        self.assertEqual(r.json()['error'],'access_denied')
        self.assertEqual(self.provider.store.count('code'),0)
        r=self.http.post('/oauth/consent',data=data,headers={'Origin':BASE})
        self.assertEqual(r.status_code,303,r.text)
        code=parse_qs(urlsplit(r.headers['location']).query)['code'][0]
        self.assertEqual(self.exchange(client,code,code_verifier='x'*64).json()['error'],'invalid_grant')
        self.assertEqual(self.exchange(client,code,redirect_uri='https://evil.test/cb').status_code,400)
        r=self.exchange(client,code)
        self.assertEqual(r.status_code,200,r.text)
        tokens=r.json()
        r=self.refresh(client,tokens)
        self.assertEqual(r.status_code,200,r.text)
        r=self.http.post('/revoke',data={'client_id':client['client_id'],
            'client_secret':client['client_secret'],'token':r.json()['access_token']})
        self.assertEqual(r.status_code,200,r.text)

    def test_origin_policy_remains_scoped(self):
        for path in ('/extract','/prepare','/health','/media/unknown/token',
                     '/oauth/consent/extra','/token/extra','/mcp/extra'):
            for origin in ('https://chatgpt.com','null'):
                r=self.http.post(path,headers={'Origin':origin,'Authorization':'Bearer '+KEY})
                self.assertEqual(r.status_code,403,path)
                self.assertEqual(r.json()['error']['code'],'invalid_origin')
        for path in ('/register','/oauth/consent','/mcp'):
            self.assertEqual(self.http.post(path,headers={'Host':'evil.test'}).status_code,421)
            self.assertEqual(self.http.post(path,content=b'x'*16385).status_code,413)
        _,tokens=self.token()
        for token in (KEY,tokens['access_token']):
            for origin in (BASE,'https://chatgpt.com','https://evil.test','null'):
                r=self.http.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'},
                    headers={'Authorization':'Bearer '+token,'Origin':origin,
                             'Accept':'application/json, text/event-stream'})
                self.assertEqual(r.status_code,200 if origin == BASE else 403,r.text)
                if origin != BASE:
                    self.assertEqual(r.text,'Invalid Origin header')  # SDK, not Boundary.

    def test_null_origin_consent_flow_and_replay(self):
        client=self.register()
        # No Fetch Metadata is required. Even supplied metadata never replaces
        # the cookie/CSRF binding; browser privacy/redirect behavior can vary.
        for metadata in ({}, {'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate'},
                         {'Sec-Fetch-Site':'cross-site','Sec-Fetch-Mode':'navigate'}):
            with self.subTest(metadata=metadata):
                form=self.approval_form(client)
                cookies=dict(self.http.cookies)
                data={**form,'password':OWNER,'decision':'approve'}
                headers={'Origin':'null',**metadata}
                r=self.http.post('/oauth/consent',data=data,headers=headers)
                self.assertEqual(r.status_code,303,r.text)
                query=parse_qs(urlsplit(r.headers['location']).query)
                self.assertEqual(query['state'],['state-for-this-browser-123'])
                self.assertEqual(query['iss'],[BASE])
                self.assertEqual(self.exchange(client,query['code'][0],code_verifier='x'*64).status_code,400)
                r=self.exchange(client,query['code'][0])
                self.assertEqual(r.status_code,200,r.text)
                self.assertEqual(self.mcp(r.json()['access_token']).status_code,200)
                replay_headers={**headers,'Cookie':self.provider.cookie+'='+cookies[self.provider.cookie]}
                self.assertEqual(self.http.post('/oauth/consent',data=data,headers=replay_headers).status_code,200)

    def test_null_origin_requires_complete_pending_browser_binding(self):
        client=self.register();form=self.approval_form(client)
        data={**form,'password':OWNER,'decision':'approve'}
        headers={'Origin':'null','Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate'}
        cookies=dict(self.http.cookies)
        for origin in ('https://evil.test','https://chatgpt.com','', 'NULL'):
            r=self.http.post('/oauth/consent',data=data,headers={**headers,'Origin':origin})
            self.assertEqual(r.status_code,403,r.text)
        cases=[{**data,'csrf':'wrong'},{k:v for k,v in data.items() if k != 'csrf'},
               {**data,'request_id':'invalid'}, {k:v for k,v in data.items() if k != 'request_id'},
               {**data,'password':'wrong-password'}, {k:v for k,v in data.items() if k != 'password'}]
        for invalid in cases:
            r=self.http.post('/oauth/consent',data=invalid,headers=headers)
            self.assertEqual(r.status_code,403,r.text)
        for cookie in ('',self.provider.cookie+'=wrong'):
            r=self.http.post('/oauth/consent',data=data,headers={**headers,'Cookie':cookie})
            self.assertEqual(r.status_code,403,r.text)
        # An attacker's own valid form and cookie cannot be mixed with another
        # browser's pending request, even when every individual value is valid.
        other=self.approval_form(client)
        self.assertEqual(self.http.post('/oauth/consent',data=data,headers=headers).status_code,403)
        self.http.cookies.clear();self.http.cookies.update(cookies)
        self.assertEqual(self.http.post('/oauth/consent',data={**data,'csrf':other['csrf']},headers=headers).status_code,403)
        self.provider.store.db.execute("UPDATE records SET expires=? WHERE kind='pending'",(time.time()-1,))
        self.assertEqual(self.http.post('/oauth/consent',data=data,headers=headers).status_code,403)
        self.assertEqual(self.provider.store.count('code'),0)

    def test_consent_diagnostics_only_log_first_failed_stage(self):
        client=self.register();form=self.approval_form(client)
        data={**form,'password':OWNER,'decision':'approve'}
        headers={'Origin':'null','Authorization':'Bearer diagnostic-secret-sentinel'}
        cases=[
            ('origin',data,{**headers,'Origin':'https://evil.test'}),
            ('origin',data,{'Authorization':headers['Authorization']}),
            ('pending',{**data,'request_id':'invalid','csrf':'invalid'}, {**headers,'Cookie':''}),
            ('pending',{k:v for k,v in data.items() if k != 'request_id'},headers),
            ('browser_cookie',{**data,'csrf':'invalid'}, {**headers,'Cookie':''}),
            ('browser_cookie',data,{**headers,'Cookie':self.provider.cookie+'=invalid'}),
            ('csrf',{**data,'csrf':'invalid'},headers),
            ('csrf',{k:v for k,v in data.items() if k != 'csrf'},headers),
            ('owner_password',{**data,'password':'invalid-password'},headers),
        ]
        for stage,body,request_headers in cases:
            with self.subTest(stage=stage):
                with self.assertLogs('media_mcp.oauth',level='WARNING') as captured:
                    r=self.http.post('/oauth/consent',data=body,headers=request_headers)
                self.assertEqual(r.status_code,403)
                self.assertEqual(r.json(),{'error':'access_denied'})
                # Exact messages and empty arguments exclude all input values,
                # digests, credentials and exception details from diagnostic logs.
                self.assertEqual([record.getMessage() for record in captured.records],
                                 ['consent_denied: '+stage])
                self.assertTrue(all(not record.args and record.exc_info is None
                                    for record in captured.records))
        self.assertEqual(self.provider.store.count('code'),0)
        with self.assertLogs('media_mcp.oauth',level='WARNING') as captured:
            r=self.http.post('/oauth/consent',data=data,headers=headers)
        self.assertEqual(r.status_code,303,r.text)
        self.assertFalse(any('consent_denied:' in record.getMessage() for record in captured.records))

    def test_consent_redirect_diagnostics_and_single_use(self):
        client=self.register()
        for decision in ('approve','deny'):
            with self.subTest(decision=decision):
                form=self.approval_form(client)
                cookies=dict(self.http.cookies)
                data={**form,'password':OWNER,'decision':decision}
                before=self.provider.store.count('code')
                with self.assertLogs('media_mcp.oauth',level='WARNING') as captured:
                    r=self.http.post('/oauth/consent',data=data,headers={'Origin':'null'})
                self.assertEqual(r.status_code,303)
                location=urlsplit(r.headers['location'])
                self.assertEqual((location.scheme,location.netloc,location.path),
                                 ('https','chatgpt.com','/connector_platform_oauth_redirect'))
                self.assertEqual(location.fragment,'')
                query=parse_qs(location.query)
                self.assertEqual(query['state'],['state-for-this-browser-123'])
                self.assertEqual(query['iss'],[BASE])
                self.assertEqual(self.provider.store.count('pending'),0)
                self.assertEqual(self.provider.store.count('code'),before+(decision == 'approve'))
                self.assertEqual(r.headers['referrer-policy'],'no-referrer')
                self.assertIn('no-store',r.headers['cache-control'])
                flow='approval' if decision == 'approve' else 'denial'
                expected=['consent '+flow+' accepted','consent '+flow+': pending consumed']
                if decision == 'approve':
                    self.assertEqual(set(query),{'code','state','iss'})
                    expected.append('consent approval: authorization code created')
                else:
                    self.assertEqual(set(query),{'error','state','iss'})
                    self.assertEqual(query['error'],['access_denied'])
                expected.append('consent '+flow+': redirect response generated status=303 '
                                'origin=https://chatgpt.com path=/connector_platform_oauth_redirect')
                # An exact allowlist also excludes query values and digests.
                self.assertEqual([record.getMessage() for record in captured.records],expected)
                self.assertTrue(all(record.exc_info is None for record in captured.records))
                with self.assertLogs('media_mcp.oauth',level='WARNING') as replay:
                    second=self.http.post('/oauth/consent',data=data,headers={'Origin':'null',
                        'Cookie':self.provider.cookie+'='+cookies[self.provider.cookie]})
                self.assertEqual(second.status_code,200)
                self.assertNotIn('location',second.headers)
                self.assertEqual([record.getMessage() for record in replay.records],['consent_duplicate: already_completed'])
                if decision == 'approve':
                    self.assertEqual(self.exchange(client,query['code'][0]).status_code,200)

    def test_consent_csp_allows_only_configured_origins(self):
        client=self.register()
        r=self.http.get('/authorize',params=self.params(client))
        page=self.http.get(r.headers['location'],headers={'Origin':'https://evil.test'})
        self.assertEqual(page.status_code,200)
        policy=page.headers['content-security-policy']
        directives=dict((parts[0],parts[1:]) for directive in policy.split(';')
                        if (parts := directive.split()))
        self.assertEqual(directives,{'default-src':["'none'"],
            'form-action':["'self'",BASE,'https://chatgpt.com'],'frame-ancestors':["'none'"],'base-uri':["'none'"]})
        self.assertNotIn('*',policy)
        self.assertNotIn('https://evil.test',policy)
        self.assertNotIn('/connector_platform_oauth_redirect',policy)

    def test_consent_csp_uses_server_allowlist_not_client_metadata(self):
        self.http.__exit__(None,None,None)
        self.settings=replace(self.settings,oauth_redirect_uris=','.join([
            CALLBACK,'https://other.example/cb','https://other.example/second',BASE+'/callback']))
        self.open_app()
        client=self.register()  # This client registers only CALLBACK.
        r=self.http.get('/authorize',params=self.params(client))
        page=self.http.get(r.headers['location']+'&redirect_uri=https://evil.test/cb')
        self.assertEqual(page.status_code,200)
        self.assertEqual(page.headers['content-security-policy'],
            f"default-src 'none'; form-action 'self' {BASE} https://chatgpt.com https://other.example; "
            "frame-ancestors 'none'; base-uri 'none'")

    def test_callback_configuration_rejects_csp_injection(self):
        for uri in ('https://good.test;script-src/cb',"https://good.test'/cb",
                    'https://good.test https://evil.test/cb','https://*.test/cb',
                    'https://good.test\r\nX-Injected:yes/cb','https://good.test%3bscript-src/cb',
                    'https://good.test/cb?next=https://evil.test','https://good.test/cb#evil'):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                replace(self.settings,oauth_redirect_uris=uri)

    def test_issuer_rejects_csp_and_header_injection_at_configuration(self):
        for origin in ('https://media.example\r\nX-Injected: yes',
                       'https://media.exa\nmple','\thttps://media.example',
                       'https://media.example;script-src *',
                       'https://media.example;script-src',
                       'https://media.example https://evil.test',
                       'https://*.example',"https://media.example'",'https://media.example,',
                       'https://media.example%3Bscript-src', 'https://media.example\\evil',
                       'https://user@media.example','https://media.example/path',
                       'https://media.example?next=evil','https://media.example#evil'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                replace(self.settings,public_base_url=origin)
        for origin in (BASE,BASE+'/',BASE+':8443','https://media.baecha.xyz',
                       'http://localhost:8765','http://127.0.0.1:8765','http://[::1]:8765'):
            with self.subTest(origin=origin):
                self.assertEqual(replace(self.settings,public_base_url=origin).public_base_url,origin)

    def test_nine_character_password_consent(self):
        password='ninechars'
        self.http.__exit__(None,None,None)
        self.settings=replace(self.settings,owner_password_hash=owner_hash(password))
        self.open_app()
        client=self.register();form=self.approval_form(client)
        r=self.http.post('/oauth/consent',data={**form,'password':password,'decision':'approve'},
                         headers={'Origin':'null'})
        self.assertEqual(r.status_code,303,r.text)

    def test_invalid_state_and_pkce_requests(self):
        client=self.register()
        for changes in ({'state':''},{'state':'bad\nstate'},{'code_challenge_method':'plain'},
                        {'code_challenge_method':''},{'code_challenge':'bad'}, {'scope':'other'}):
            r=self.http.get('/authorize',params=self.params(client,**changes))
            self.assertEqual(r.status_code,302,r.text)
            query=parse_qs(urlsplit(r.headers['location']).query)
            self.assertIn('error',query);self.assertEqual(query['iss'],[BASE])
        params=self.params(client);params.pop('state')
        r=self.http.get('/authorize',params=params)
        self.assertIn('error=',r.headers['location'])
        self.assertEqual(self.provider.store.count('pending'),0)

    def test_redirect_registration_and_request_rejection(self):
        for uri in ('https://evil.test/callback','http://127.0.0.1/cb','https://chatgpt.com.evil.test/cb',
            CALLBACK+'?next=https://evil.test',CALLBACK+'#fragment',CALLBACK+'/',
            'https://chatgpt.com/connector/%2e%2e/oauth','file:///etc/passwd'):
            self.assertEqual(self.http.post('/register',json={'redirect_uris':[uri]}).status_code,400,uri)
        client=self.register()
        for uri in ('https://evil.test/callback',CALLBACK+'/',CALLBACK.replace('https:','HTTPS:'),CALLBACK+'?x=1'):
            r=self.http.get('/authorize',params=self.params(client,redirect_uri=uri))
            self.assertEqual(r.status_code,400,uri);self.assertNotIn('location',r.headers)
        self.assertEqual(self.http.post('/register',json={'redirect_uris':[CALLBACK],'token_endpoint_auth_method':'private_key_jwt'}).status_code,400)

    def test_code_exchange_single_use_and_verifier(self):
        client=self.register();code=self.authorize(client)
        self.assertEqual(self.exchange(client,code,code_verifier='x'*64).json()['error'],'invalid_grant')
        self.assertEqual(self.exchange(client,code,redirect_uri='https://evil.test/x').status_code,400)
        result=self.exchange(client,code);self.assertEqual(result.status_code,200,result.text)
        token=result.json();self.assertEqual(token['expires_in'],900);self.assertIn('refresh_token',token)
        self.assertEqual(self.mcp(token['access_token']).status_code,200)
        self.assertEqual(self.exchange(client,code).json()['error'],'invalid_grant')
        self.assertEqual(self.mcp(token['access_token']).status_code,401)

    def test_code_expiry(self):
        client=self.register();code=self.authorize(client)
        self.provider.store.db.execute("UPDATE records SET expires=? WHERE kind='code'",(time.time()-1,))
        self.assertEqual(self.exchange(client,code).json()['error'],'invalid_grant')

    def test_resource_and_client_binding(self):
        client=self.register();code=self.authorize(client)
        for target in ('','https://evil.test/mcp',BASE):
            self.assertEqual(self.exchange(client,code,resource=target).json()['error'],'invalid_target')
        other=self.register()
        self.assertEqual(self.exchange(other,code).status_code,400)
        self.assertEqual(self.exchange(client,code,client_secret='bad').status_code,401)
        self.assertEqual(self.exchange(client,code).status_code,200)
        self.assertEqual(self.mcp('revoked-or-invalid').status_code,401)

    def test_token_expiry(self):
        _,tokens=self.token()
        self.provider.store.db.execute("UPDATE records SET expires=? WHERE kind='access'",(time.time()-1,))
        self.assertEqual(self.mcp(tokens['access_token']).status_code,401)

    def test_refresh_rotation_and_reuse(self):
        client,old=self.token();r=self.refresh(client,old)
        self.assertEqual(r.status_code,200,r.text);new=r.json()
        self.assertNotEqual(new['refresh_token'],old['refresh_token'])
        self.assertEqual(self.mcp(new['access_token']).status_code,200)
        self.assertEqual(self.mcp(old['access_token']).status_code,401)
        self.assertEqual(self.refresh(client,old).json()['error'],'invalid_grant')
        self.assertEqual(self.mcp(new['access_token']).status_code,200)
        with patch('media_mcp.oauth.time.time',return_value=time.time()+6):
            self.assertEqual(self.refresh(client,old).json()['error'],'invalid_grant')
        self.assertEqual(self.mcp(new['access_token']).status_code,401)
        self.assertEqual(self.refresh(client,new).status_code,400)

    def test_refresh_scope_expiry_and_wrong_client(self):
        client,token=self.token()
        self.assertEqual(self.refresh(client,token,scope='media:write').json()['error'],'invalid_scope')
        other=self.register()
        self.assertEqual(self.refresh(other,token).status_code,400)
        self.assertEqual(self.mcp(token['access_token']).status_code,200)
        self.provider.store.db.execute("UPDATE records SET expires=? WHERE kind='refresh'",(time.time()-1,))
        self.assertEqual(self.refresh(client,token).status_code,400)

    def test_revocation(self):
        client,tokens=self.token()
        for value in ('unknown',tokens['refresh_token']):
            r=self.http.post('/revoke',data={'client_id':client['client_id'],'client_secret':client['client_secret'],
                'token':value,'token_type_hint':'refresh_token'})
            self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.mcp(tokens['access_token']).status_code,401)

    def test_public_client_and_basic_client(self):
        client,tokens=self.token(self.register('none'))
        self.assertEqual(self.mcp(tokens['access_token']).status_code,200)
        self.assertEqual(self.refresh(client,tokens).status_code,200)
        client=self.register('client_secret_basic');code=self.authorize(client)
        header=base64.b64encode((client['client_id']+':'+client['client_secret']).encode()).decode()
        r=self.http.post('/token',headers={'Authorization':'Basic '+header},data={'grant_type':'authorization_code',
            'code':code,'redirect_uri':CALLBACK,'code_verifier':VERIFIER,'resource':RESOURCE})
        self.assertEqual(r.status_code,200,r.text)

    def test_persistence_and_no_plain_credentials(self):
        client,tokens=self.token()
        db=Path(self.temp.name)/'oauth-v1/oauth.sqlite3'
        for secret in (OWNER,client['client_secret'],tokens['access_token'],tokens['refresh_token']):
            self.assertNotIn(secret.encode(),db.read_bytes())
        self.http.__exit__(None,None,None)
        self.open_app()
        self.assertEqual(self.mcp(tokens['access_token']).status_code,200)
        self.assertEqual(self.refresh(client,tokens).status_code,200)

    def test_no_refresh_without_offline_access(self):
        client=self.register();code=self.authorize(client,scope='media:read')
        r=self.exchange(client,code)
        self.assertEqual(r.status_code,200,r.text)
        self.assertFalse(r.json().get('refresh_token'))

    def test_rate_limit_and_duplicate_parameters(self):
        client=self.register();params=list(self.params(client).items())+[('state','second')]
        self.assertEqual(self.http.get('/authorize',params=params).status_code,400)
        self.provider.rate['/register'].extend([time.monotonic()]*10)
        self.assertEqual(self.http.post('/register',json={'redirect_uris':[CALLBACK]}).status_code,429)

    def test_oauth_mcp_tools_call(self):
        _,tokens=self.token()
        result=self.mcp(tokens['access_token'],'tools/call',{'name':'extract_media','arguments':{'url':URL}})
        self.assertEqual(result.status_code,200,result.text)
        self.assertIn('Example123',result.text)

    def test_denial_and_consent_single_use(self):
        client=self.register();form=self.approval_form(client)
        data={**form,'password':OWNER,'decision':'deny'}
        r=self.http.post('/oauth/consent',data=data,headers={'Origin':BASE})
        self.assertEqual(r.status_code,303)
        query=parse_qs(urlsplit(r.headers['location']).query)
        self.assertEqual(query['error'],['access_denied'])
        self.assertEqual(query['iss'],[BASE])
        self.assertNotIn('code',query)
        self.assertEqual(self.provider.store.count('code'),0)
        self.assertEqual(self.http.post('/oauth/consent',data={**data,'decision':'approve'},
            headers={'Origin':BASE}).status_code,403)

    def test_approval_expiry_and_replay(self):
        client=self.register();form=self.approval_form(client)
        headers={'Origin':BASE};data={**form,'password':OWNER,'decision':'approve'}
        self.provider.store.db.execute("UPDATE records SET expires=? WHERE kind='pending'",(time.time()-1,))
        self.assertEqual(self.http.post('/oauth/consent',data=data,headers=headers).status_code,403)
        form=self.approval_form(client);data={**form,'password':OWNER,'decision':'approve'}
        # Retain the cookie to prove the pending request itself is single-use.
        cookies=dict(self.http.cookies)
        self.assertEqual(self.http.post('/oauth/consent',data=data,headers=headers).status_code,303)
        self.http.cookies.update(cookies)
        self.assertEqual(self.http.post('/oauth/consent',data=data,headers=headers).status_code,200)
        self.assertEqual(self.provider.store.count('code'),1)

    def test_malformed_registration_and_sanitized_errors(self):
        for body in ('[]','null','{}','{"redirect_uris":null}',
                '{"redirect_uris":[],"redirect_uris":["'+CALLBACK+'"]}'):
            r=self.http.post('/register',content=body,headers={'Content-Type':'application/json'})
            self.assertEqual(r.status_code,400,r.text)
        r=self.http.post('/register',json={'redirect_uris':[CALLBACK],
            'token_endpoint_auth_method':'secret-value-must-not-be-reflected'})
        self.assertEqual(r.status_code,400)
        self.assertNotIn('secret-value',r.text)
        client=self.register()
        r=self.http.get('/authorize',params=self.params(client,response_type='secret-value-must-not-be-reflected'))
        self.assertNotIn('secret-value',r.headers['location'])
        self.assertIn('iss=',r.headers['location'])

    def test_ambiguous_client_authentication_rejected(self):
        client=self.register('none');code=self.authorize(client)
        self.assertEqual(self.exchange(client,code,client_secret='unexpected').status_code,401)
        r=self.http.post('/token',headers={'Authorization':'Basic !!!'},data={'client_id':client['client_id']})
        self.assertEqual(r.status_code,401)
        self.assertIn('Basic',r.headers['www-authenticate'])
        self.assertEqual(self.exchange(client,code).status_code,200)

    def test_owner_rotation_revokes_persisted_grants(self):
        from dataclasses import replace
        client,tokens=self.token()
        self.http.__exit__(None,None,None)
        self.settings=replace(self.settings,owner_password_hash=owner_hash(OWNER+'new'))
        self.open_app()
        self.assertEqual(self.mcp(tokens['access_token']).status_code,401)
        self.assertEqual(self.refresh(client,tokens).status_code,401)

    def test_removed_callback_disables_existing_client(self):
        client,tokens=self.token()
        self.provider.redirects=set()
        self.assertEqual(self.mcp(tokens['access_token']).status_code,401)
        self.assertEqual(self.refresh(client,tokens).status_code,401)

    def test_storage_key_mismatch_permissions_and_lock(self):
        from media_mcp.oauth_store import OAuthStore
        store=OAuthStore(self.provider.store.directory,self.settings.oauth_storage_key)
        with self.assertRaises(RuntimeError): store.start(HASH,BASE)
        self.assertIsNone(store.db)
        self.assertIsNone(store.lock)
        self.assertEqual(self.http.get('/health').status_code,200)

    def test_persistent_grant_survives_time_restart_and_can_be_revoked(self):
        self.http.__exit__(None,None,None)
        self.settings=replace(self.settings,oauth_persistent_grants=1)
        self.open_app()
        client,tokens=self.token()
        self.assertIsNone(tokens.get('expires_in'))
        self.assertEqual(client.get('client_secret_expires_at'),0)
        self.http.__exit__(None,None,None)
        self.open_app()
        with patch('time.time',return_value=time.time()+10*365*86400):
            self.provider.store.cleanup()
            self.assertEqual(self.mcp(tokens['access_token']).status_code,200)
            result=self.refresh(client,tokens)
            self.assertEqual(result.status_code,200,result.text)
            new=result.json()
            self.assertIsNone(new.get('expires_in'))
            self.assertEqual(self.mcp(tokens['access_token']).status_code,401)
            self.assertEqual(self.mcp(new['access_token']).status_code,200)
            self.assertEqual(self.http.post('/revoke',data={'client_id':client['client_id'],
                'client_secret':client['client_secret'],'token':new['access_token']}).status_code,200)
            self.assertEqual(self.mcp(new['access_token']).status_code,401)
            self.assertEqual(self.refresh(client,new).status_code,400)

    def test_persistent_setting_is_explicit_and_does_not_extend_existing_grants(self):
        for value in (-1,2):
            with self.assertRaises(ValueError):
                replace(self.settings,oauth_persistent_grants=value)
        client,tokens=self.token()
        old=self.provider.store.get('access',digest(tokens['access_token']))['expires_at']
        self.http.__exit__(None,None,None)
        self.settings=replace(self.settings,oauth_persistent_grants=1)
        self.open_app()
        with patch('time.time',return_value=old+1):
            self.assertEqual(self.mcp(tokens['access_token']).status_code,401)
            new=self.refresh(client,tokens).json()
            self.assertIsNotNone(new.get('expires_in'))

    def test_refresh_has_absolute_lifetime_and_revocation_client_binding(self):
        client,tokens=self.token();other=self.register()
        before=self.provider.store.get('refresh',digest(tokens['refresh_token']))['expires_at']
        new=self.refresh(client,tokens).json()
        after=self.provider.store.get('refresh',digest(new['refresh_token']))['expires_at']
        self.assertEqual(before,after)
        self.assertEqual(self.http.post('/revoke',data={'client_id':other['client_id'],
            'client_secret':other['client_secret'],'token':new['access_token']}).status_code,200)
        self.assertEqual(self.mcp(new['access_token']).status_code,200)
        self.assertEqual(self.http.post('/revoke',data={'client_id':client['client_id'],
            'client_secret':client['client_secret'],'token':new['access_token']}).status_code,200)
        self.assertEqual(self.refresh(client,new).status_code,400)

    def test_owner_rate_limit_and_html_escaping(self):
        client=self.register()
        stored=self.provider.store.get('client',client['client_id'])
        stored['client_name']='<script>alert(1)</script>'
        self.provider.store.put('client',client['client_id'],stored,time.time()+1000)
        result=self.http.get('/authorize',params=self.params(client))
        page=self.http.get(result.headers['location'])
        self.assertNotIn('<script>',page.text)
        self.assertIn('&lt;script&gt;',page.text)
        form=Form(page.text).fields
        for _ in range(5):
            self.assertEqual(self.http.post('/oauth/consent',data={**form,'password':OWNER+'wrong',
                'decision':'approve'},headers={'Origin':BASE}).status_code,403)
        self.assertEqual(self.http.post('/oauth/consent',data={**form,'password':OWNER,
            'decision':'approve'},headers={'Origin':BASE}).status_code,429)
        self.assertEqual(self.provider.store.count('code'),0)

    def test_discovery_selected_scope_full_lifecycle_after_three_days(self):
        # Model a client following the actual challenge, not a test hardcoding offline_access.
        challenge=self.http.post('/mcp',json={}).headers['www-authenticate']
        scope=challenge.split('scope="')[1].split('"')[0]
        self.assertEqual(set(scope.split()),{'media:read','offline_access'})
        prm=self.http.get('/.well-known/oauth-protected-resource/mcp').json()
        self.assertEqual(set(prm['scopes_supported']),set(scope.split()))
        client=self.register('none')
        code=self.authorize(client,scope=scope)
        result=self.exchange(client,code)
        self.assertEqual(result.status_code,200)
        tokens=result.json()
        self.assertTrue(tokens['refresh_token'])
        used=self.provider.store.get('code',digest(code))
        self.assertTrue(used['used'])
        self.assertEqual(self.mcp(tokens['access_token']).status_code,200)
        # Restart before the jump also verifies persistence of the complete grant.
        self.http.__exit__(None,None,None);self.open_app()
        with patch('media_mcp.oauth.time.time',return_value=time.time()+3*86400):
            self.assertEqual(self.mcp(tokens['access_token']).status_code,401)
            result=self.refresh(client,tokens)
            self.assertEqual(result.status_code,200,result.text)
            self.assertEqual(self.mcp(result.json()['access_token']).status_code,200)
        family=self.provider.store.get('family',used['family'])
        self.assertEqual(family['generation'],1)
        self.assertFalse(family['revoked'])

    def test_access_only_grant_reproduces_production_db_shape(self):
        client=self.register('none')
        tokens=self.exchange(client,self.authorize(client,scope='media:read')).json()
        self.assertIsNone(tokens.get('refresh_token'))
        with patch('media_mcp.oauth.time.time',return_value=time.time()+3*86400):
            self.provider.store.cleanup()
            self.assertEqual(self.mcp(tokens['access_token']).status_code,401)
            self.assertEqual(self.provider.store.count('refresh'),0)
            self.assertEqual(self.provider.store.count('code'),0)
            self.assertEqual(self.provider.store.count('access'),0)
            self.assertEqual(self.provider.store.count('family'),1)

    def test_duplicate_consent_requires_original_binding_and_expires(self):
        client=self.register();form=self.approval_form(client)
        data={**form,'password':OWNER,'decision':'approve'}
        approved=self.http.post('/oauth/consent',data=data,headers={'Origin':BASE})
        self.assertEqual(approved.status_code,303)
        for changes,headers in [({'csrf':'wrong'},{'Origin':BASE}),
                ({'decision':'deny'},{'Origin':BASE}),({}, {'Origin':BASE,'Cookie':''}),
                ({},{'Origin':'https://evil.test'})]:
            self.assertEqual(self.http.post('/oauth/consent',data={**data,**changes},headers=headers).status_code,403)
        duplicate=self.http.post('/oauth/consent',data=data,headers={'Origin':BASE})
        self.assertEqual(duplicate.status_code,200)
        self.assertNotIn('location',duplicate.headers)
        for secret in (form['request_id'],form['csrf'],OWNER):
            self.assertNotIn(secret,duplicate.text)
        self.assertEqual(self.provider.store.count('code'),1)
        self.provider.store.db.execute("UPDATE records SET expires=? WHERE kind='consent_receipt'",(time.time()-1,))
        self.assertEqual(self.http.post('/oauth/consent',data=data,headers={'Origin':BASE}).status_code,403)

    def test_concurrent_consent_post_issues_only_one_code(self):
        import httpx2
        client=self.register();form=self.approval_form(client)
        cookie=self.provider.cookie+'='+dict(self.http.cookies)[self.provider.cookie]
        async def run():
            entered=0
            both=asyncio.Event()
            async def password_check(*args):
                nonlocal entered
                entered+=1
                if entered==2: both.set()
                await both.wait()
                return True
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.app),base_url=BASE) as http:
                with patch('media_mcp.oauth.asyncio.to_thread',side_effect=password_check):
                    return await asyncio.wait_for(asyncio.gather(*[
                        http.post('/oauth/consent',data={**form,'password':OWNER,'decision':'approve'},
                                  headers={'Origin':BASE,'Cookie':cookie}) for _ in range(2)]),5)
        results=asyncio.run(run())
        self.assertEqual(sorted(r.status_code for r in results),[200,303])
        self.assertEqual(self.provider.store.count('code'),1)
        self.assertEqual(self.provider.store.count('pending'),0)

    def test_concurrent_refresh_keeps_winner_and_single_rotation(self):
        import httpx2
        client,tokens=self.token(self.register('none'))
        original=self.provider.load_refresh_token
        async def run():
            entered=0
            both=asyncio.Event()
            async def load(*args):
                nonlocal entered
                value=await original(*args)
                entered+=1
                if entered==2: both.set()
                await both.wait()
                return value
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.app),base_url=BASE) as http:
                with patch.object(self.provider,'load_refresh_token',side_effect=load):
                    return await asyncio.wait_for(asyncio.gather(*[
                        http.post('/token',data={'grant_type':'refresh_token','client_id':client['client_id'],
                            'refresh_token':tokens['refresh_token'],'resource':RESOURCE}) for _ in range(2)]),5)
        results=asyncio.run(run())
        self.assertEqual(sorted(r.status_code for r in results),[200,400])
        winner=next(r.json() for r in results if r.status_code==200)
        loser=next(r.json() for r in results if r.status_code==400)
        self.assertEqual(loser,{'error':'invalid_grant'})
        self.assertEqual(self.mcp(winner['access_token']).status_code,200)
        used=self.provider.store.get('refresh',digest(tokens['refresh_token']))
        self.assertTrue(used['used'])
        self.assertEqual(self.provider.store.get('family',used['family'])['generation'],1)
        self.assertEqual(self.provider.store.count('refresh'),2)
        self.assertEqual(self.refresh(client,winner).status_code,200)

    def test_rotation_collision_window_survives_restart_without_extending(self):
        client,tokens=self.token()
        new=self.refresh(client,tokens).json()
        used=self.provider.store.get('refresh',digest(tokens['refresh_token']))
        self.http.__exit__(None,None,None);self.open_app()
        with patch('media_mcp.oauth.time.time',return_value=used['used_at']+4):
            self.assertEqual(self.refresh(client,tokens).status_code,400)
            self.assertEqual(self.mcp(new['access_token']).status_code,200)
        with patch('media_mcp.oauth.time.time',return_value=used['used_at']+5):
            self.assertEqual(self.refresh(client,tokens).status_code,400)
            self.assertEqual(self.mcp(new['access_token']).status_code,401)

    def test_legacy_used_refresh_without_timestamp_still_revokes(self):
        client,tokens=self.token()
        new=self.refresh(client,tokens).json()
        old=self.provider.store.get('refresh',digest(tokens['refresh_token']))
        old.pop('used_at')
        self.provider.store.put('refresh',digest(tokens['refresh_token']),old,old['expires_at'])
        self.assertEqual(self.refresh(client,tokens).status_code,400)
        self.assertEqual(self.mcp(new['access_token']).status_code,401)

    def test_wrong_client_cannot_revoke_used_refresh_family(self):
        client,tokens=self.token()
        new=self.refresh(client,tokens).json()
        other=self.register()
        with patch('media_mcp.oauth.time.time',return_value=time.time()+6):
            self.assertEqual(self.refresh(other,tokens).status_code,400)
            self.assertEqual(self.mcp(new['access_token']).status_code,200)

    def test_completed_consent_persists_without_reissuing_code(self):
        client=self.register();form=self.approval_form(client)
        data={**form,'password':OWNER,'decision':'approve'}
        cookie=self.provider.cookie+'='+dict(self.http.cookies)[self.provider.cookie]
        first=self.http.post('/oauth/consent',data=data,headers={'Origin':BASE})
        code=parse_qs(urlsplit(first.headers['location']).query)['code'][0]
        self.http.__exit__(None,None,None);self.open_app()
        second=self.http.post('/oauth/consent',data=data,headers={'Origin':BASE,'Cookie':cookie})
        self.assertEqual(second.status_code,200)
        self.assertNotIn('location',second.headers)
        self.assertEqual(self.provider.store.count('code'),1)
        self.assertEqual(self.exchange(client,code).status_code,200)
        self.assertEqual(self.exchange(client,code).status_code,400)

    def test_token_diagnostics_do_not_log_credentials(self):
        client=self.register();code=self.authorize(client)
        with self.assertLogs('media_mcp.oauth',level='INFO') as captured:
            self.assertEqual(self.exchange(client,code,code_verifier='x'*64).status_code,400)
            self.assertEqual(self.exchange(client,code,resource='wrong').status_code,400)
            self.assertEqual(self.exchange(client,code,client_secret='wrong').status_code,401)
            tokens=self.exchange(client,code).json()
            self.assertEqual(self.refresh(client,tokens,scope='bad').status_code,400)
            new=self.refresh(client,tokens).json()
            self.assertEqual(self.refresh(client,tokens).status_code,400)
            with patch('media_mcp.oauth.time.time',return_value=time.time()+6):
                self.assertEqual(self.refresh(client,tokens).status_code,400)
        logs='\n'.join(r.getMessage() for r in captured.records)
        for value in (code,VERIFIER,client['client_id'],client['client_secret'],tokens['access_token'],
                      tokens['refresh_token'],new['access_token'],new['refresh_token']):
            self.assertNotIn(value,logs)
        for text in ('stage=pkce outcome=failure','stage=resource outcome=failure',
                     'grant=authorization_code stage=sdk_exchange outcome=success',
                     'grant=refresh_token stage=sdk_exchange outcome=success',
                     'reason=rotation_collision','reason=refresh_reuse'):
            self.assertIn(text,logs)
        self.assertTrue(all(r.exc_info is None for r in captured.records))


class OAuthSDKTests(unittest.IsolatedAsyncioTestCase):
    async def test_official_sdk_discovery_dcr_owner_pkce_mcp_and_refresh(self):
        import httpx2
        from mcp.client.auth import OAuthClientProvider
        from mcp.shared.auth import OAuthClientMetadata, AuthorizationCodeResult
        from mcp.client.streamable_http import streamable_http_client
        from mcp.client.session import ClientSession

        class Storage:
            tokens=None
            client=None
            async def get_tokens(self): return self.tokens
            async def set_tokens(self,tokens): self.tokens=tokens
            async def get_client_info(self): return self.client
            async def set_client_info(self,client): self.client=client

        with tempfile.TemporaryDirectory() as directory:
            settings=Settings(api_key=KEY,public_base_url=BASE,temp_dir=directory,
                owner_password_hash=HASH,oauth_storage_key=Fernet.generate_key().decode())
            app=create_app(settings,MediaService(settings,runner=fake_runner))
            store=Storage();callback={}
            async with app.router.lifespan_context(app):
                async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url=BASE) as browser:
                    async def redirect(url):
                        result=await browser.get(url)
                        page=await browser.get(result.headers['location'])
                        form=Form(page.text).fields
                        approved=await browser.post('/oauth/consent',data={**form,'password':OWNER,'decision':'approve'},headers={'Origin':BASE})
                        self.assertEqual(approved.status_code,303,approved.text)
                        callback.update({k:v[0] for k,v in parse_qs(urlsplit(approved.headers['location']).query).items()})
                    async def returned():
                        return AuthorizationCodeResult(**callback)
                    auth=OAuthClientProvider(RESOURCE,OAuthClientMetadata(redirect_uris=[CALLBACK],
                        token_endpoint_auth_method='client_secret_post',scope='media:read offline_access',
                        grant_types=['authorization_code','refresh_token']),store,redirect,returned)
                    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),auth=auth) as http:
                        async with streamable_http_client(RESOURCE,http_client=http) as (read,write):
                            async with ClientSession(read,write) as session:
                                await session.initialize()
                                tools=await session.list_tools()
                                self.assertEqual({t.name for t in tools.tools},{'extract_media','prepare_media','view_media'})
                                result=await session.call_tool('extract_media',{'url':URL})
                                self.assertFalse(result.is_error)
                                from mcp_types import ImageContent
                                image_result=await session.call_tool('prepare_media',{'url':URL})
                                self.assertFalse(image_result.is_error)
                                self.assertIsInstance(image_result.content[1],ImageContent)
                                self.assertIsNotNone(store.tokens.refresh_token)
                                old=store.tokens.refresh_token
                                auth.context.token_expiry_time=time.time()-1
                                await session.list_tools()
                                self.assertNotEqual(store.tokens.refresh_token,old)
