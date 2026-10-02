import asyncio
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from media_mcp.api import create_app
from media_mcp.config import Settings
from media_mcp.core import ExtractionError
from media_mcp.download import download_media, Redirects
from media_mcp.network import NetworkGuard, check_url, public_ip
from media_mcp.service import MediaService, ServiceError, run_worker
from media_mcp.worker import content_type

URL = 'https://www.instagram.com/p/Example123/'
JPEG = b'\xff\xd8\xff' + b'fixture bytes'
KEY = 'unit-test-key-' * 3


def source(count=1):
    return {'platform':'instagram','id':'Example123','url':URL,'type':'image' if count==1 else 'carousel',
            'author':{'username':'fixture'},'caption':'example','timestamp':None,
            'stats':{'likes':None,'comments':None},'extracted_at':1700000000,
            'media_urls_temporary':True,'media':[{'type':'image','url':'https://s.cdninstagram.com/example.jpg'} for _ in range(count)]}


async def fake_runner(operation, url, directory, settings, indices=None):
    data={'source':source()}
    if operation in ('prepare','prepare_inline','view'):
        (directory/'000.media').write_bytes(JPEG)
        data['files']=[{'name':'000.media','content_type':'image/jpeg'}]
    return data


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.settings=Settings(api_key=KEY,public_base_url='http://127.0.0.1:8765',temp_dir=self.temp.name)
        self.service=MediaService(self.settings,runner=fake_runner)
        self.app=create_app(self.settings,self.service)
        self.client=TestClient(self.app,base_url='http://127.0.0.1:8765')
        self.client.__enter__()
        self.auth={'Authorization':'Bearer '+KEY}

    def tearDown(self):
        self.client.__exit__(None,None,None)
        self.temp.cleanup()

    def prepare(self):
        r=self.client.post('/prepare',json={'url':URL},headers=self.auth)
        self.assertEqual(r.status_code,200,r.text)
        return r.json()

    def test_health_and_openapi(self):
        self.assertEqual(self.client.get('/health').json()['status'],'ok')
        schema=self.client.get('/openapi.json').json()
        self.assertIn('/prepare',schema['paths'])
        self.assertIn('HTTPBearer',schema['components']['securitySchemes'])
        self.assertEqual(self.client.get('/docs').status_code,200)

    def test_unauthorized_http_and_mcp(self):
        for path in ('/extract','/prepare','/mcp'):
            for headers in ({},{'Authorization':'Bearer wrong'}):
                self.assertEqual(self.client.post(path,json={'url':URL},headers=headers).status_code,401)

    def test_extract(self):
        r=self.client.post('/extract',json={'url':URL},headers=self.auth)
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json(),source())
        self.assertEqual(list(self.service.root.glob('job-*')),[])

    def test_invalid_source_and_ssrf(self):
        for url in ('https://instagram.com/p/','https://evil.test/p/x',
                'https://127.0.0.1/a','https://localhost/a','https://10.0.0.1/a',
                'https://[::1]/a','http://169.254.169.254/latest/meta-data',
                'file:///etc/passwd','ftp://instagram.com/p/x',
                'https://s.cdninstagram.com/image.jpg'):
            r=self.client.post('/extract',json={'url':url},headers=self.auth)
            self.assertEqual(r.status_code,400,url)
            self.assertEqual(r.json()['error']['code'],'unsupported_url')

    def test_prepare_get_head_and_cleanup(self):
        data=self.prepare()
        url=data['media'][0]['url']
        self.assertNotIn(self.temp.name,json.dumps(data))
        r=self.client.get(url)
        self.assertEqual(r.content,JPEG)
        self.assertEqual(r.headers['content-type'],'image/jpeg')
        self.assertEqual(int(r.headers['content-length']),len(JPEG))
        self.assertIn('no-store',r.headers['cache-control'])
        head=self.client.head(url)
        self.assertEqual(head.status_code,200)
        self.assertEqual(head.content,b'')
        self.assertEqual(head.headers['content-length'],str(len(JPEG)))
        self.assertEqual(self.service.streams,0)

    def test_expired(self):
        data=self.prepare();entry=self.service.sessions[data['session_id']]
        directory=entry['directory'];entry['expires_at']=time.time()-1
        self.assertEqual(self.client.get(data['media'][0]['url']).status_code,404)
        self.assertFalse(directory.exists())

    def test_nonexistent_and_path_traversal(self):
        for path in ('/media/'+'a'*64+'/'+'b'*64,'/media/%2e%2e/%2e%2e%2fetc%2fpasswd','/media/a/%252e%252e','/media/a/b'):
            r=self.client.get(path)
            self.assertIn(r.status_code,(401,404))
            self.assertNotIn('root:',r.text)

    def test_symlink_rejected(self):
        data=self.prepare();session=self.service.sessions[data['session_id']]
        path=next(iter(session['tokens'].values()))[0]
        path.unlink();path.symlink_to('/etc/passwd')
        self.assertEqual(self.client.get(data['media'][0]['url']).status_code,404)

    def test_limits_count_size_capacity(self):
        original=self.service.runner
        async def oversized(operation,url,directory,settings,indices=None):
            result=await original(operation,url,directory,settings)
            (directory/'000.media').write_bytes(b'x'*(settings.max_item_bytes+1))
            return result
        self.service.settings=replace(self.settings,max_item_bytes=16,max_total_bytes=32)
        self.service.runner=oversized
        self.assertEqual(self.client.post('/prepare',json={'url':URL},headers=self.auth).status_code,413)
        self.assertEqual(list(self.service.root.glob('job-*')),[])
        async def too_many(*args):
            return {'source':source(21),'files':[{}]*21}
        self.service.runner=too_many
        self.assertEqual(self.client.post('/prepare',json={'url':URL},headers=self.auth).status_code,413)
        self.service.runner=original
        self.service.settings=replace(self.settings,max_sessions=1)
        self.prepare()
        self.assertEqual(self.client.post('/prepare',json={'url':URL},headers=self.auth).status_code,507)

    def test_body_host_origin_validation(self):
        self.assertEqual(self.client.post('/extract',content=b'x'*16385,headers=self.auth).status_code,413)
        self.assertEqual(self.client.post('/extract',json={'url':URL,'extra':1},headers=self.auth).status_code,422)
        self.assertEqual(self.client.get('/health',headers={'Host':'evil.test'}).status_code,421)
        self.assertEqual(self.client.post('/extract',json={'url':URL},headers={**self.auth,'Origin':'https://evil.test'}).status_code,403)
        for path in ('/register','/token','/oauth/consent','/.well-known/oauth-authorization-server'):
            r=self.client.post(path,headers={**self.auth,'Origin':'https://chatgpt.com'})
            self.assertEqual(r.json()['error']['code'],'invalid_origin')
        r=self.client.post('/mcp',json={},headers={**self.auth,'Origin':'https://evil.test',
            'Accept':'application/json, text/event-stream'})
        self.assertEqual(r.status_code,403)
        self.assertEqual(r.text,'Invalid Origin header')

    def test_mcp_schema_and_invocation(self):
        headers={**self.auth,'Accept':'application/json, text/event-stream'}
        def rpc(method,params=None):
            r=self.client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':method,'params':params or {}})
            self.assertEqual(r.status_code,200,r.text)
            return r.json()
        init=rpc('initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'test','version':'1'}})
        self.assertIn('serverInfo',init['result'])
        tools=rpc('tools/list')['result']['tools']
        self.assertEqual({t['name'] for t in tools},{'extract_media','prepare_media','view_media'})
        self.assertTrue(all('url' in t['inputSchema']['properties'] for t in tools))
        result=rpc('tools/call',{'name':'extract_media','arguments':{'url':URL}})
        self.assertIn('Example123',json.dumps(result))
        result=rpc('tools/call',{'name':'prepare_media','arguments':{'url':URL}})
        self.assertIn('expires_at',json.dumps(result))
        result=rpc('tools/call',{'name':'extract_media','arguments':{'url':'file:///etc/passwd'}})
        self.assertIn('unsupported_url',json.dumps(result))
        self.assertTrue(result['result']['isError'])


class SecurityTests(unittest.TestCase):
    def test_invalid_configuration(self):
        with self.assertRaises(ValueError): Settings()
        with self.assertRaises(ValueError): Settings(api_key=KEY,public_base_url='http://evil.test')
        with self.assertRaises(ValueError): Settings(api_key=KEY,public_base_url='https://media.example',concurrency=0)

    def test_url_and_ips(self):
        for url in ('https://localhost/x','http://www.instagram.com/p/x',
                    'https://s.cdninstagram.com.evil.test/a','https://user:pass@www.youtube.com/a',
                    'https://youtube.com:444/a','file:///etc/passwd'):
            with self.assertRaises(OSError): check_url(url)
        for ip in ('127.0.0.1','10.0.0.1','172.16.0.1','192.168.0.1','169.254.169.254','::1','fc00::1','fe80::1','::ffff:127.0.0.1','224.0.0.1','0.0.0.0'):
            with self.assertRaises(OSError): public_ip(ip)
        self.assertEqual(check_url('https://s.cdninstagram.com/a',media_only=True),'s.cdninstagram.com')

    def test_dns_private_and_rebinding(self):
        guard=NetworkGuard()
        record=lambda ip: [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]
        guard.resolve=MagicMock(return_value=record('10.0.0.1'))
        with self.assertRaises(OSError): guard.getaddrinfo('www.instagram.com',443)
        guard.resolve=MagicMock(side_effect=[record('8.8.8.8'),record('127.0.0.1')])
        sock=MagicMock(family=socket.AF_INET)
        self.assertEqual(guard.destination(sock,('www.instagram.com',443)),('8.8.8.8',443))
        # Exact pinned numeric address is used; no second hostname resolution.
        self.assertEqual(guard.destination(sock,('8.8.8.8',443)),('8.8.8.8',443))
        self.assertEqual(guard.resolve.call_count,1)
        with self.assertRaises(OSError): guard.destination(sock,('127.0.0.1',443))

    def test_redirect_private(self):
        with self.assertRaises(ValueError):
            Redirects().redirect_request(None,None,302,'',{},'https://127.0.0.1/x')
        with patch('media_mcp.download.socket.getaddrinfo',return_value=[(2,1,6,'',('10.0.0.1',443))]):
            with self.assertRaises(ValueError):
                Redirects().redirect_request(None,None,302,'',{},'https://s.cdninstagram.com/x')

    def test_download_item_limit_and_types(self):
        r=MagicMock();r.__enter__.return_value=r;r.headers.get_content_type.return_value='image/jpeg'
        r.headers.get.return_value=None;r.read.side_effect=[b'12345']
        with patch('media_mcp.download.validate_url'),patch('media_mcp.download.build_opener') as opener:
            opener.return_value.open.return_value=r
            with self.assertRaises(ExtractionError):
                with download_media(source(),max_bytes=20,max_item_bytes=4): pass
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'x';p.write_bytes(JPEG)
            self.assertEqual(content_type(p,'image'),'image/jpeg')
            p.write_bytes(b'<html>not media</html>')
            with self.assertRaises(ExtractionError): content_type(p,'image')

    def test_stale_cleanup_and_owner_lock(self):
        with tempfile.TemporaryDirectory() as root:
            s=Settings(api_key=KEY,public_base_url='http://127.0.0.1:8765',temp_dir=root)
            store=MediaService(s);store.start()
            job=store.root/('job-'+'a'*64);job.mkdir();(job/'partial').write_bytes(b'x')
            unrelated=store.root/'keep';unrelated.write_text('keep')
            second=MediaService(s)
            with self.assertRaises(RuntimeError): second.start()
            asyncio.run(store.close())
            second.start();self.assertFalse(job.exists());self.assertTrue(unrelated.exists())
            asyncio.run(second.close())


class ViewMediaTests(unittest.TestCase):
    """view_media: inline ImageContent, no session, job directory removed."""
    def start(self,runner=fake_runner,**overrides):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.settings=Settings(api_key=KEY,public_base_url='http://127.0.0.1:8765',temp_dir=self.temp.name,**overrides)
        self.runner=AsyncMock(side_effect=runner)
        self.service=MediaService(self.settings,runner=self.runner)
        self.client=TestClient(create_app(self.settings,self.service),base_url='http://127.0.0.1:8765')
        self.client.__enter__();self.addCleanup(self.client.__exit__,None,None,None)

    def rpc(self,method,params=None):
        r=self.client.post('/mcp',headers={'Authorization':'Bearer '+KEY,'Accept':'application/json, text/event-stream'},
                           json={'jsonrpc':'2.0','id':1,'method':method,'params':params or {}})
        self.assertEqual(r.status_code,200,r.text)
        return r.json()['result']

    def view(self,url=URL):
        return self.rpc('tools/call',{'name':'view_media','arguments':{'url':url}})

    def assert_no_job_files(self):
        self.assertEqual(list(self.service.root.glob('job-*')),[])
        self.assertEqual(self.service.sessions,{})

    def test_tool_listed_with_single_url_input(self):
        self.start()
        tool={t['name']:t for t in self.rpc('tools/list')['tools']}['view_media']
        self.assertEqual(tool['inputSchema']['required'],['url'])
        self.assertEqual(set(tool['inputSchema']['properties']),{'url'})
        self.assertEqual(tool['inputSchema']['properties']['url']['type'],'string')

    def test_returns_text_and_exact_image_bytes(self):
        self.start()
        result=self.view()
        self.assertFalse(result['isError'])
        text,image=result['content']
        self.assertEqual(text['type'],'text')
        meta=json.loads(text['text'])
        self.assertEqual((meta['platform'],meta['id'],meta['type'],meta['author'],meta['caption']),
                         ('instagram','Example123','image',{'username':'fixture'},'example'))
        self.assertEqual(meta['media'],[{'index':0,'type':'image','content_type':'image/jpeg','bytes':len(JPEG)}])
        self.assertEqual(set(image),{'type','data','mimeType'})
        self.assertEqual((image['type'],image['mimeType']),('image','image/jpeg'))
        self.assertEqual(base64.b64decode(image['data'],validate=True),JPEG)
        self.assertEqual(result['structuredContent'],meta)
        self.assertEqual(self.runner.await_args.args[0],'view')
        self.assert_no_job_files()

    def test_inline_limit(self):
        self.start(inline_max_bytes=len(JPEG)-1)
        result=self.view()
        self.assertTrue(result['isError'])
        self.assertIn('limit_exceeded',result['content'][0]['text'])
        self.assert_no_job_files()

    def test_non_image_file_rejected_and_cleaned(self):
        async def video(operation,url,directory,settings,indices=None):
            data=await fake_runner(operation,url,directory,settings)
            data['files'][0]['content_type']='video/mp4';return data
        self.start(runner=video)
        result=self.view()
        self.assertTrue(result['isError']);self.assertIn('unsupported_media',result['content'][0]['text'])
        self.assert_no_job_files()

    def test_youtube_rejected_before_worker(self):
        self.start()
        result=self.view('https://www.youtube.com/watch?v=jNQXAC9IVRw')
        self.assertTrue(result['isError']);self.assertIn('unsupported_media',result['content'][0]['text'])
        self.runner.assert_not_awaited()

    def test_existing_tools_unchanged(self):
        self.start()
        extract=self.rpc('tools/call',{'name':'extract_media','arguments':{'url':URL}})
        self.assertEqual([c['type'] for c in extract['content']],['text'])
        self.assertNotIn('structuredContent',extract)
        prepared=json.loads(self.rpc('tools/call',{'name':'prepare_media','arguments':{'url':URL}})['content'][0]['text'])
        self.assertEqual(prepared['access'],'temporary_bearer_url')
        self.assertEqual(len(self.service.sessions),1)


class WorkerViewScopeTests(unittest.TestCase):
    def run_view(self,metadata):
        with tempfile.TemporaryDirectory() as root, patch('media_mcp.network.NetworkGuard.install'), \
                patch('media_mcp.worker.resource.setrlimit'), \
                patch('media_mcp.extractor.extract',return_value=metadata), \
                patch('media_mcp.download.download_media') as download:
            from media_mcp.worker import work
            with self.assertRaises(ServiceError) as ctx:
                work({'operation':'view','url':URL,'directory':root,'max_items':20,'max_item_bytes':1,
                      'max_total_bytes':1,'timeout':1,'memory_mb':512})
        self.assertEqual(ctx.exception.code,'unsupported_media')
        download.assert_not_called()

    def test_carousel_video_audio_and_youtube_not_downloaded(self):
        video=dict(source(),type='video',media=[{'type':'video','url':'https://s.cdninstagram.com/v.mp4'}])
        reel=dict(source(),type='reel',media=[{'type':'video','url':'https://s.cdninstagram.com/v.mp4'},
                                            {'type':'audio','url':'https://s.cdninstagram.com/a.m4a'}])
        youtube=dict(source(),platform='youtube',media=[{'type':'image','url':'https://i.ytimg.com/x.jpg'}])
        for metadata in (source(2),video,reel,youtube):
            with self.subTest(type=metadata['type'],platform=metadata['platform']):
                self.run_view(metadata)


class AsyncServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrency_cancellation_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            settings=Settings(api_key=KEY,public_base_url='http://127.0.0.1:8765',temp_dir=root)
            started=asyncio.Event()
            async def wait(*args):
                started.set();await asyncio.Event().wait()
            service=MediaService(settings,runner=wait);service.start()
            job=asyncio.create_task(service.execute('prepare',URL));await started.wait()
            with self.assertRaises(ServiceError) as ctx: await service.execute('extract',URL)
            self.assertEqual(ctx.exception.code,'busy')
            job.cancel()
            with self.assertRaises(asyncio.CancelledError): await job
            self.assertEqual(service.active,0);self.assertEqual(list(service.root.glob('job-*')),[])
            await service.close()

    async def test_view_worker_payload_uses_inline_limit(self):
        settings=Settings(api_key=KEY,public_base_url='http://127.0.0.1:8765',inline_max_bytes=1000,prepare_timeout=7)
        payloads={}
        async def capture(*args,**kwargs):
            process=MagicMock(pid=-1,returncode=0)
            async def communicate(data):
                payload=json.loads(data);payloads[payload['operation']]=payload
                return json.dumps({'source':source()}).encode(),b''
            process.communicate=communicate;process.wait=AsyncMock()
            return process
        with tempfile.TemporaryDirectory() as root,patch('media_mcp.service.asyncio.create_subprocess_exec',side_effect=capture), \
                patch('media_mcp.service.os.killpg'):
            for operation in ('view','prepare'):
                await run_worker(operation,URL,Path(root),settings)
        self.assertEqual((payloads['view']['max_item_bytes'],payloads['view']['max_total_bytes']),(1000,1000))
        self.assertEqual((payloads['prepare']['max_item_bytes'],payloads['prepare']['max_total_bytes']),
                         (settings.max_item_bytes,settings.max_total_bytes))
        self.assertEqual(payloads['view']['timeout'],7)

    async def test_real_process_timeout(self):
        import sys
        original=asyncio.create_subprocess_exec
        processes=[]
        async def sleeper(*args,**kwargs):
            p=await original(sys.executable,'-c','import time; time.sleep(60)',**kwargs)
            processes.append(p);return p
        settings=Settings(api_key=KEY,public_base_url='http://127.0.0.1:8765',extract_timeout=1)
        with tempfile.TemporaryDirectory() as root,patch('media_mcp.service.asyncio.create_subprocess_exec',side_effect=sleeper):
            with self.assertRaises(ServiceError) as ctx: await run_worker('extract',URL,Path(root),settings)
        self.assertEqual(ctx.exception.code,'timeout')
        self.assertIsNotNone(processes[0].returncode)


if __name__ == '__main__': unittest.main()

class PrepareNativeTests(unittest.TestCase):
    start = ViewMediaTests.start
    rpc = ViewMediaTests.rpc
    def prepare_native(self, indices=None):
        args={'url':URL}
        if indices is not None: args['indices']=indices
        return self.rpc('tools/call',{'name':'prepare_media','arguments':args})

    def carousel(self, bodies):
        async def runner(operation,url,directory,settings,indices=None):
            files=[]
            for index,body in enumerate(bodies):
                name=f'{index:03d}.media'
                if body is None:
                    files.append({'name':name,'error':'download_failed'})
                else:
                    (directory/name).write_bytes(body)
                    files.append({'name':name,'content_type':'image/jpeg'})
            return {'source':source(len(bodies)), 'files':files}
        return runner

    def test_single_image_sdk_type_and_url(self):
        from mcp_types import CallToolResult, ImageContent
        self.start()
        result=self.prepare_native()
        parsed=CallToolResult.model_validate(result)
        self.assertIsInstance(parsed.content[1],ImageContent)
        self.assertEqual(base64.b64decode(parsed.content[1].data),JPEG)
        meta=result['structuredContent']
        self.assertEqual(json.loads(result['content'][0]['text']),meta)
        self.assertEqual(self.client.get(meta['media'][0]['url']).content,JPEG)

    def test_carousel_selection_order_png_and_default_limit(self):
        png=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')
        self.start(runner=self.carousel([JPEG,png,JPEG,JPEG]))
        result=self.prepare_native([2,1])
        self.assertEqual([c['mimeType'] for c in result['content'][1:]],['image/png','image/jpeg'])
        self.assertEqual(base64.b64decode(result['content'][1]['data']),png)
        self.assertEqual(len(result['structuredContent']['media']),4)
        self.assertEqual(len(self.prepare_native()['content']),4)

    def test_invalid_indices(self):
        self.start()
        for indices in ([],[0],[-1],[1,1],[1,2,3,4],[2]):
            result=self.prepare_native(indices)
            self.assertTrue(result['isError'])
            self.assertIn('invalid_indices',result['content'][0]['text'])

    def test_partial_download_mime_empty_and_size(self):
        self.start(runner=self.carousel([None,b'unknown',JPEG]))
        result=self.prepare_native()
        self.assertEqual(len(result['content']),2)
        self.assertEqual(result['structuredContent']['media'][0]['error'],'download_failed')
        self.assertEqual(result['structuredContent']['media'][1]['inline_error'],'mime_detection_failed')
        self.service.runner=self.carousel([JPEG+b'x'*20,JPEG])
        self.service.settings=replace(self.settings,inline_max_bytes=len(JPEG))
        result=self.prepare_native()
        self.assertEqual(len(result['content']),2)
        self.assertEqual(result['structuredContent']['media'][0]['inline_error'],'limit_exceeded')

    def test_base64_failure_keeps_url(self):
        self.start()
        with patch('media_mcp.api.base64.b64encode',side_effect=ValueError):
            result=self.prepare_native()
        self.assertEqual(result['structuredContent']['media'][0]['inline_error'],'base64_failed')
        self.assertEqual(self.client.get(result['structuredContent']['media'][0]['url']).content,JPEG)

class WorkerPrepareNativeTests(unittest.TestCase):
    def test_download_failure_empty_mime_and_success_are_independent(self):
        from contextlib import contextmanager
        from media_mcp.worker import work
        calls=[]
        @contextmanager
        def download(metadata, **kwargs):
            index=len(calls);calls.append(kwargs)
            if index == 0: raise ExtractionError('download_failed')
            path=Path(kwargs['directory'])/f'fixture-{index}'
            path.write_bytes([b'',b'',b'unknown',JPEG][index])
            try: yield [str(path)]
            finally: path.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory() as root, patch('media_mcp.network.NetworkGuard.install'), \
                patch('media_mcp.worker.resource.setrlimit'), \
                patch('media_mcp.extractor.extract',return_value=source(4)), \
                patch('media_mcp.download.download_media',side_effect=download):
            result=work({'operation':'prepare_inline','url':URL,'directory':root,'max_items':20,
                         'max_item_bytes':1024,'max_total_bytes':4096,'timeout':10,'memory_mb':512})
            self.assertEqual([f.get('error') for f in result['files']],
                             ['download_failed','empty_file','mime_detection_failed',None])
            self.assertEqual((Path(root)/'003.media').read_bytes(),JPEG)
        self.assertEqual(len(calls),4)

    def test_real_downloader_empty_file_has_explicit_reason(self):
        from media_mcp.download import DownloadEmptyError
        response=MagicMock()
        response.__enter__.return_value=response
        response.headers.get_content_type.return_value='image/jpeg'
        response.headers.get.return_value=None
        response.read.return_value=b''
        with patch('media_mcp.download.validate_url'), patch('media_mcp.download.build_opener') as opener:
            opener.return_value.open.return_value=response
            with self.assertRaises(DownloadEmptyError) as caught:
                with download_media(source()): pass
        self.assertEqual(caught.exception.code,'download_failed')
        self.assertEqual(caught.exception.reason,'empty_file')
