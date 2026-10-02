import base64
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from media_mcp.config import Settings
from media_mcp.frames import extract_frames, jpeg_size
from media_mcp.service import run_worker
import test_server

REEL = 'https://www.instagram.com/reel/Example123/'


def video(path, duration=2, rate=10, static=False):
    # Brightness ramps with time so representative frames differ; static=True is one color.
    source = f'color=c=red:s=1600x900:r={rate}' if static else (
        f"color=c=black:s=1600x900:r={rate},geq=lum='255*T/{duration}':cb=128:cr=128")
    subprocess.run(['ffmpeg', '-v', 'error', '-nostdin', '-f', 'lavfi', '-i', source,
                    '-t', str(duration), '-c:v', 'mpeg4', '-threads', '1', '-y', str(path)], check=True)


class FrameTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'clip.mp4'
        video(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def frames(self, **kwargs):
        kwargs.setdefault('max_bytes', 5*1024*1024)
        kwargs.setdefault('max_items', 3)
        return extract_frames(self.path, 0, self.root, deadline=time.monotonic()+20, **kwargs)

    def test_real_extraction_dimensions_and_timestamps(self):
        frames = self.frames()
        self.assertEqual([f['timestamp_seconds'] for f in frames], [.2, 1, 1.8])
        self.assertEqual([f['frame_index'] for f in frames], [2, 10, 18])
        for frame in frames:
            self.assertNotIn('error', frame)
            self.assertTrue(frame['extracted'])
            self.assertEqual((frame['selection'], frame['source'], frame['content_type']),
                             ('default', 'instagram_reel', 'image/jpeg'))
            path = self.root / frame['name']
            self.assertTrue(path.read_bytes().startswith(b'\xff\xd8\xff'))
            self.assertEqual(frame['bytes'], path.stat().st_size)
            info = json.loads(subprocess.check_output(['ffprobe', '-v', 'error',
                '-show_entries', 'stream=width,height', '-of', 'json', str(path)]))
            stream = info['streams'][0]
            self.assertEqual((stream['width'], stream['height']), (1280, 720))
            self.assertEqual((frame['width'], frame['height']), (1280, 720))

    def test_single_frame_short_video(self):
        video(self.path, .1, 10)
        frames = self.frames()
        self.assertEqual([f['extracted'] for f in frames], [True, False, False])
        self.assertEqual([f.get('skipped') for f in frames[1:]], ['duplicate_frame']*2)
        self.assertEqual(sorted(p.name for p in self.root.glob('frame-*')), ['frame-000-0.jpg'])

    def test_near_duplicate_static_video(self):
        video(self.path, static=True)
        frames = self.frames()
        self.assertTrue(frames[0]['extracted'])
        self.assertEqual([(f['extracted'], f.get('skipped'), f.get('duplicate_of')) for f in frames[1:]],
                         [(False, 'near_duplicate', 0)]*2)
        self.assertEqual(sorted(p.name for p in self.root.glob('frame-*')), ['frame-000-0.jpg'])
        # Explicit selections are kept even when they look alike.
        frames = self.frames(timestamps=[.5, 1.5])
        self.assertTrue(all(f['extracted'] for f in frames))

    def test_timestamp_selection(self):
        frames = self.frames(timestamps=[1.5, .05, 1.52, 9])
        self.assertEqual([f['timestamp_seconds'] for f in frames], [1.5, .05, 1.52, 9])
        self.assertEqual([f['frame_index'] for f in frames], [15, 0, 15, 90])
        self.assertEqual({f['selection'] for f in frames}, {'timestamps'})
        self.assertEqual([f['extracted'] for f in frames], [True, True, False, False])
        self.assertEqual((frames[2]['skipped'], frames[2]['duplicate_of']), ('duplicate_frame', 0))
        self.assertEqual(frames[3]['error'], 'out_of_range')
        self.assertEqual((frames[0]['width'], frames[0]['height']), (1280, 720))

    def test_frame_index_selection(self):
        frames = self.frames(frame_indices=[19, 0, 20])
        self.assertEqual([f['timestamp_seconds'] for f in frames], [1.9, 0, 2])
        self.assertEqual({f['selection'] for f in frames}, {'frame_indices'})
        self.assertEqual([f['extracted'] for f in frames], [True, True, False])
        self.assertEqual(frames[2]['error'], 'out_of_range')

    def test_individual_frame_size_limit(self):
        frames = self.frames(max_frame_bytes=100)
        self.assertEqual({f['error'] for f in frames}, {'limit_exceeded'})
        self.assertEqual(list(self.root.glob('frame-*')), [])
        size = self.frames(max_items=1)[0]['bytes']
        frames = self.frames(max_frame_bytes=size + 1000)
        self.assertTrue(all(f['extracted'] and f['bytes'] <= size + 1000 for f in frames))

    def test_jpeg_size_parser(self):
        jpeg = b'\xff\xd8\xff\xe0\x00\x04ab\xff\xc0\x00\x11\x08\x02\xd0\x05\x00\x03'
        self.assertEqual(jpeg_size(jpeg + b'\x00'*20), (1280, 720))
        self.assertIsNone(jpeg_size(b'\xff\xd8not a jpeg at all'))
        self.assertIsNone(jpeg_size(b''))

    def test_corruption_and_timeout(self):
        self.path.write_bytes(b'broken')
        self.assertEqual(self.frames()[0]['error'], 'frame_probe_failed')
        frames = extract_frames(self.path, 0, self.root, deadline=0, max_bytes=1000, max_items=3)
        self.assertEqual(frames[0]['error'], 'timeout')

    def test_bounded_worker_real_ffmpeg_and_media_selection(self):
        import sys
        script = """
import contextlib, json, sys
from pathlib import Path
from unittest.mock import patch
from media_mcp.worker import work
payload = json.loads(sys.stdin.read())
metadata = {'platform':'instagram', 'type':'reel', 'media':[{'type':'video'}]}
@contextlib.contextmanager
def download(*args, **kwargs):
    yield [Path(payload['directory'])/'clip.mp4']
with patch('media_mcp.network.NetworkGuard.install'), patch('media_mcp.extractor.extract', return_value=metadata), patch('media_mcp.download.download_media', download):
    print(json.dumps(work(payload)))
"""
        payload = dict(operation='prepare_inline', url=REEL, directory=str(self.root),
            timeout=20, memory_mb=512, max_total_bytes=1024*1024*10,
            max_item_bytes=1024*1024*10, max_items=20,
            inline_max_bytes=5*1024*1024, inline_max_items=3, indices=[1])
        def run(payload):
            result = subprocess.run([sys.executable, '-c', script], input=json.dumps(payload),
                capture_output=True, text=True, timeout=25, check=True)
            return json.loads(result.stdout)
        data = run(payload)
        self.assertEqual(len(data['frames']), 3)
        self.assertTrue(all('error' not in f and f['extracted'] for f in data['frames']), data)
        self.assertTrue((self.root/'000.media').is_file())
        video(self.root/'clip.mp4')
        data = run(dict(payload, frame_timestamps=[1.5, 0.5], inline_frame_max_bytes=1024*1024))
        self.assertEqual([(f['timestamp_seconds'], f['frame_index'], f['extracted']) for f in data['frames']],
                         [(1.5, 15, True), (0.5, 5, True)], data)

    def test_limits_and_partial_failure(self):
        self.assertTrue(all(f['error']=='limit_exceeded' for f in self.frames(max_bytes=10)))
        frames = self.frames(max_items=1)
        self.assertNotIn('error', frames[0])
        self.assertEqual(frames[1]['error'], 'limit_exceeded')
        original = subprocess.run
        def fail_middle(args, **kwargs):
            if args[0]=='ffmpeg' and '-ss' in args and args[args.index('-ss')+1]=='0.975':  # frame 10 at 10 fps
                raise subprocess.CalledProcessError(1, args)
            return original(args, **kwargs)
        with patch('media_mcp.frames.subprocess.run', side_effect=fail_middle):
            frames = self.frames()
        self.assertEqual(frames[1]['error'], 'frame_extraction_failed')
        self.assertNotIn('error', frames[2])


class ReelNativeTests(unittest.TestCase):
    start = test_server.PrepareNativeTests.start
    rpc = test_server.PrepareNativeTests.rpc

    def test_real_frames_native_blocks_and_video_url(self):
        async def runner(operation, url, directory, settings, indices=None):
            path = directory / '000.media'
            video(directory/'clip.mp4')
            (directory/'clip.mp4').rename(path)
            metadata = test_server.source()
            metadata.update(url=REEL, type='reel', media=[{'type':'video'}])
            frames = extract_frames(path, 0, directory, deadline=time.monotonic()+20,
                max_bytes=settings.inline_max_bytes, max_items=settings.inline_max_items)
            return {'source':metadata, 'files':[{'name':'000.media','content_type':'video/mp4'}], 'frames':frames}
        self.start(runner=runner)
        result = self.rpc('tools/call', {'name':'prepare_media','arguments':{'url':REEL}})
        from mcp_types import CallToolResult, ImageContent
        parsed = CallToolResult.model_validate(result)
        self.assertEqual(len(parsed.content),4)
        metadata = result['structuredContent']
        for position, frame in enumerate(metadata['frames'], 1):
            self.assertEqual(frame['content_block_index'],position)
            self.assertIsInstance(parsed.content[position],ImageContent)
            self.assertEqual(len(base64.b64decode(parsed.content[position].data)),frame['bytes'])
        self.assertEqual(self.client.get(metadata['media'][0]['url']).status_code,200)
        self.assertEqual(metadata['inline_indices'],[0])
        async def official_client():
            import httpx2 as httpx
            from mcp.client.session import ClientSession
            from mcp.client.streamable_http import streamable_http_client
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.client.app),
                    headers={'Authorization':'Bearer '+test_server.KEY}) as http:
                async with streamable_http_client('http://127.0.0.1:8765/mcp', http_client=http) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        response = await session.call_tool('prepare_media', {'url':REEL, 'indices':[1]})
                        self.assertFalse(response.is_error)
                        self.assertEqual(len(response.content),4)
                        self.assertIsInstance(response.content[1],ImageContent)
                        text = json.loads(response.content[0].text)
                        download = await http.get(text['media'][0]['url'])
                        self.assertEqual(download.status_code,200)
        self.client.portal.call(official_client)


def fake_reel_runner(bodies, seen=None):
    """Reel prepare_inline runner with pre-made frame files (None = failed frame)."""
    async def runner(operation, url, directory, settings, indices=None, frames=None):
        if seen is not None:
            seen.append(frames)
        (directory/'000.media').write_bytes(b'\x00\x00\x00\x18ftypmp42video')
        metadata = test_server.source()
        metadata.update(url=REEL, type='reel', media=[{'type': 'video'}])
        records = []
        for ordinal, body in enumerate(bodies):
            record = {'index': 0, 'ordinal': ordinal, 'frame_index': ordinal, 'timestamp_seconds': ordinal/10,
                      'selection': 'default', 'name': f'frame-000-{ordinal}.jpg',
                      'source': 'instagram_reel', 'extracted': body is not None}
            if body is None:
                record['error'] = 'frame_extraction_failed'
            else:
                (directory/record['name']).write_bytes(body)
                record.update(bytes=len(body), content_type='image/jpeg', width=4, height=3)
            records.append(record)
        return {'source': metadata, 'files': [{'name': '000.media', 'content_type': 'video/mp4'}],
                'frames': records}
    return runner


class ReelServiceTests(unittest.TestCase):
    start = test_server.PrepareNativeTests.start
    rpc = test_server.PrepareNativeTests.rpc

    def call(self, **arguments):
        return self.rpc('tools/call', {'name': 'prepare_media', 'arguments': {'url': REEL, **arguments}})

    def test_frames_use_post_image_blocks_and_metadata(self):
        self.start(runner=fake_reel_runner([test_server.JPEG+b'0', test_server.JPEG+b'1']))
        result = self.call()
        self.assertFalse(result['isError'])
        blocks = result['content']
        self.assertEqual([b['type'] for b in blocks], ['text', 'image', 'image'])
        for position, block in enumerate(blocks[1:]):
            self.assertEqual(set(block), {'type', 'data', 'mimeType'})
            self.assertEqual(block['mimeType'], 'image/jpeg')
            self.assertEqual(base64.b64decode(block['data']), test_server.JPEG+str(position).encode())
        meta = result['structuredContent']
        self.assertEqual(json.loads(blocks[0]['text']), meta)
        frame = meta['frames'][0]
        self.assertEqual({k: frame[k] for k in ('index', 'frame_index', 'timestamp_seconds', 'width', 'height',
                          'content_type', 'extracted', 'source', 'inline_status', 'content_block_index')},
                         {'index': 0, 'frame_index': 0, 'timestamp_seconds': 0, 'width': 4, 'height': 3,
                          'content_type': 'image/jpeg', 'extracted': True, 'source': 'instagram_reel',
                          'inline_status': 'included', 'content_block_index': 1})
        self.assertEqual(meta['inline_indices'], [0])
        self.assertEqual(self.client.get(meta['media'][0]['url']).status_code, 200)
        self.assertEqual(list(list(self.service.sessions.values())[0]['directory'].glob('frame-*')), [])

    def test_partial_failure_keeps_successful_frames(self):
        self.start(runner=fake_reel_runner([test_server.JPEG, None, b'not an image', test_server.JPEG]))
        result = self.call()
        self.assertFalse(result['isError'])
        self.assertEqual(len(result['content']), 3)
        frames = result['structuredContent']['frames']
        self.assertEqual([f.get('error') for f in frames],
                         [None, 'frame_extraction_failed', 'mime_detection_failed', None])
        self.assertEqual([f.get('content_block_index') for f in frames], [1, None, None, 2])

    def test_total_count_and_per_frame_limits(self):
        jpeg = test_server.JPEG
        self.start(runner=fake_reel_runner([jpeg, jpeg, jpeg]), inline_max_bytes=2*len(jpeg))
        frames = self.call()['structuredContent']['frames']
        self.assertEqual([f.get('error') for f in frames], [None, None, 'limit_exceeded'])
        self.service.settings = replace(self.settings, inline_max_items=1)
        frames = self.call()['structuredContent']['frames']
        self.assertEqual([f.get('error') for f in frames], [None, 'limit_exceeded', 'limit_exceeded'])
        self.service.runner = fake_reel_runner([jpeg+b'x'*10, jpeg])
        self.service.settings = replace(self.settings, inline_frame_max_bytes=len(jpeg))
        result = self.call()
        self.assertFalse(result['isError'])
        self.assertEqual([f.get('error') for f in result['structuredContent']['frames']], ['limit_exceeded', None])
        self.assertEqual(len(result['content']), 2)

    def test_frame_selection_arguments_reach_runner(self):
        seen = []
        self.start(runner=fake_reel_runner([test_server.JPEG], seen))
        self.assertFalse(self.call(frame_timestamps=[1.5, 0])['isError'])
        self.assertFalse(self.call(frame_indices=[3], indices=[1])['isError'])
        self.call()
        self.assertEqual(seen, [{'frame_timestamps': [1.5, 0]}, {'frame_indices': [3]}, None])
        schema = {t['name']: t for t in self.rpc('tools/list')['tools']}['prepare_media']['inputSchema']
        self.assertEqual(schema['required'], ['url'])
        self.assertTrue({'indices', 'frame_timestamps', 'frame_indices'} <= set(schema['properties']))

    def test_invalid_frame_selection(self):
        self.start(runner=fake_reel_runner([test_server.JPEG]))
        for arguments in ({'frame_timestamps': []}, {'frame_timestamps': [-1]}, {'frame_timestamps': [1, 1]},
                          {'frame_timestamps': [0, 1, 2, 3]}, {'frame_indices': [-1]},
                          {'frame_timestamps': [1], 'frame_indices': [1]},
                          {'frame_timestamps': [1], 'url': test_server.URL}):
            with self.subTest(arguments=arguments):
                result = self.call(**arguments)
                self.assertTrue(result['isError'])
                self.assertIn('invalid_frames', result['content'][0]['text'])
        self.assertEqual(self.service.sessions, {})

    def test_post_images_unchanged(self):
        self.start()
        result = self.rpc('tools/call', {'name': 'prepare_media', 'arguments': {'url': test_server.URL}})
        meta = result['structuredContent']
        self.assertNotIn('frames', meta)
        self.assertEqual(meta['media'][0]['inline_status'], 'included')
        self.assertEqual(base64.b64decode(result['content'][1]['data']), test_server.JPEG)
        r = self.client.post('/prepare', json={'url': test_server.URL}, headers={'Authorization': 'Bearer '+test_server.KEY})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('frames', r.json())
        r = self.client.post('/prepare', json={'url': REEL, 'frame_timestamps': [1]},
                             headers={'Authorization': 'Bearer '+test_server.KEY})
        self.assertEqual(r.status_code, 422)


class ReelWorkerPayloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_payload_carries_frame_options_and_limits(self):
        from unittest.mock import AsyncMock, MagicMock
        settings = Settings(api_key=test_server.KEY, public_base_url='http://127.0.0.1:8765',
                            inline_frame_max_bytes=1234)
        payloads = []
        async def capture(*args, **kwargs):
            process = MagicMock(pid=-1, returncode=0)
            async def communicate(data):
                payloads.append(json.loads(data))
                return json.dumps({'source': test_server.source()}).encode(), b''
            process.communicate = communicate
            process.wait = AsyncMock()
            return process
        with tempfile.TemporaryDirectory() as root, \
                patch('media_mcp.service.asyncio.create_subprocess_exec', side_effect=capture), \
                patch('media_mcp.service.os.killpg'):
            await run_worker('prepare_inline', REEL, Path(root), settings, frames={'frame_indices': [4]})
            await run_worker('prepare_inline', REEL, Path(root), settings)
        self.assertEqual((payloads[0]['frame_indices'], payloads[0]['inline_frame_max_bytes']), ([4], 1234))
        self.assertNotIn('frame_indices', payloads[1])
        self.assertNotIn('frame_timestamps', payloads[1])
