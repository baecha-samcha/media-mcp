import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock
from media_mcp import extract, ExtractionError, download_media
from media_mcp.core import detect
from media_mcp.instagram import parse, Scripts, InstagramWeb

FIXTURES = Path(__file__).parent / 'fixtures'
TARGET = detect('https://www.instagram.com/p/DdEZgWTlGfB/')


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((FIXTURES / 'carousel.json').read_text())
        self.node = self.data['data']['xig_polaris_media']['if_not_gated_logged_out']

    def test_real_response_structure_18_images(self):
        out = parse(self.data, TARGET)
        self.assertEqual(out['type'], 'carousel')
        self.assertEqual(len(out['media']), 18)
        self.assertTrue(all(m['type'] == 'image' and m['url'] for m in out['media']))
        self.assertEqual(out['stats']['likes'], 0)
        self.assertEqual(out['id'], TARGET[2])

    def test_single_image(self):
        child = self.node.pop('carousel_media')[0]
        self.node.update(child, media_type=1)
        out = parse(self.data, TARGET)
        self.assertEqual(out['type'], 'image')
        self.assertEqual(len(out['media']), 1)

    def test_mixed_carousel(self):
        child = self.node['carousel_media'][1]
        child.update(media_type=2, video_versions=[{'url': 'https://s.cdninstagram.com/video.mp4', 'width':720,'height':1280}])
        out = parse(self.data, TARGET)
        self.assertEqual(out['media'][1]['type'], 'video')
        self.assertIn('thumbnail', out['media'][1])

    def test_partial_carousel_rejected(self):
        self.node['carousel_media_count'] = 19
        with self.assertRaises(ExtractionError): parse(self.data, TARGET)

    def test_missing_item_rejected(self):
        self.node['carousel_media'][3] = {}
        with self.assertRaises(ExtractionError): parse(self.data, TARGET)

    def test_wrong_post_rejected(self):
        self.node['code'] = 'other'
        with self.assertRaises(ExtractionError): parse(self.data, TARGET)

    def test_scripts_and_legacy(self):
        for content in [json.dumps(self.data), 'window._sharedData = ' + json.dumps(self.data) + ';']:
            parser = Scripts()
            parser.feed('<script>broken</script><script data-sjs>' + content + '</script>')
            self.assertEqual(len(parse(parser.documents, TARGET)['media']), 18)

    def test_legacy_graphql(self):
        data = {'shortcode': TARGET[2], 'owner': {'username':'example'},
                'edge_sidecar_to_children': {'edges': [{'node': {'is_video':False,'display_url':'https://s.cdninstagram.com/a.jpg','dimensions':{'width':1080}}}]}}
        self.assertEqual(parse(data,TARGET)['media'][0]['width'],1080)

    def test_invalid_urls(self):
        for url in ['https://instagram.com/p/', 'https://instagram.com.evil.test/p/abc/', 'https://instagram.com/accounts/login/', 'file:///p/abc', 'https://user:pass@instagram.com/p/abc/', 'https://instagram.com:8443/p/abc/']:
            with self.subTest(url=url), self.assertRaises(ExtractionError) as ctx:
                extract(url)
            self.assertEqual(ctx.exception.code,'unsupported_url')

    def test_routes(self):
        with patch('media_mcp.extractor.yt_extract', return_value={'ok':True}) as yt:
            self.assertEqual(extract('https://instagram.com/reel/abc/'),{'ok':True})
            yt.assert_called_once()
        with patch('media_mcp.extractor.yt_extract') as yt, patch.object(InstagramWeb,'extract',return_value={'ok':True}):
            extract(TARGET[3]);yt.assert_not_called()
        self.assertEqual(detect('https://youtu.be/dQw4w9WgXcQ')[0], 'youtube')
        self.assertEqual(detect('https://instagram.com/tv/abc/')[1], 'tv')

    def test_unknown_audio_and_separate_track(self):
        from media_mcp.extractor import yt_extract
        info = {'url':'https://s.cdninstagram.com/a.mp4', 'formats':[
            {'url':'https://s.cdninstagram.com/a.m4a', 'vcodec':'none', 'acodec':'aac'}]}
        with patch('yt_dlp.YoutubeDL') as client:
            client.return_value.__enter__.return_value.extract_info.return_value = info
            out = yt_extract(detect('https://instagram.com/reel/abc/'))
        self.assertIsNone(out['media'][0]['has_audio'])
        self.assertEqual(out['media'][1]['type'], 'audio')
        self.assertEqual(out['type'], 'reel')

    def test_public_then_authenticated(self):
        with patch.object(InstagramWeb,'extract',side_effect=[ExtractionError('login_required'), {'ok':True}]) as fn:
            self.assertEqual(extract(TARGET[3],cookiefile='/unused'),{'ok':True})
            self.assertEqual(fn.call_count,2)

    def test_block_no_retry(self):
        with patch.object(InstagramWeb,'request',side_effect=ExtractionError('rate_limited')) as fn:
            with self.assertRaises(ExtractionError) as ctx: InstagramWeb().extract(TARGET)
            self.assertEqual(ctx.exception.code,'rate_limited');self.assertEqual(fn.call_count,1)

    def test_download_rejects_local(self):
        with self.assertRaises(ExtractionError) as ctx:
            with download_media({'media':[{'url':'https://127.0.0.1/x'}]}): pass
        self.assertEqual(ctx.exception.code,'download_failed')

    def test_download_cleanup_and_limit(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers.get_content_type.return_value = 'image/jpeg'
        response.read.side_effect = [b'abc', b'']
        with patch('media_mcp.download.validate_url'), patch('media_mcp.download.build_opener') as opener:
            opener.return_value.open.return_value = response
            with download_media({'media':[{'url':'https://s.cdninstagram.com/a.jpg'}]}) as paths:
                path = Path(paths[0]);self.assertEqual(path.read_bytes(),b'abc')
            self.assertFalse(path.exists())
            response.read.side_effect = [b'abc']
            with self.assertRaises(ExtractionError):
                with download_media({'media':[{'url':'https://s.cdninstagram.com/a.jpg'}]},max_bytes=2): pass


@unittest.skipUnless(os.environ.get('MEDIA_MCP_LIVE') == '1', 'Opt-in live network tests')
class LiveTests(unittest.TestCase):
    def test_reel(self):
        out=extract('https://www.instagram.com/reel/DdQ90KiyERI/')
        self.assertEqual(out['type'],'reel');self.assertEqual(out['media'][0]['type'],'video')

    def test_carousel(self):
        out=extract(TARGET[3]);self.assertEqual(len(out['media']),18)
        self.assertTrue(all(m['url'].startswith('https://') for m in out['media']))


if __name__ == '__main__': unittest.main()
