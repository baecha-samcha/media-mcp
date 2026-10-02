"""Instagram-only response parsing. No dependency on yt-dlp internals."""
import json
import logging
import os
from html.parser import HTMLParser
from urllib.parse import urlencode
from .core import ExtractionError, result

log = logging.getLogger(__name__)


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.parts = []
        self.documents = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.active = True
            self.parts = []

    def handle_data(self, data):
        if self.active:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag != 'script' or not self.active:
            return
        self.active = False
        text = ''.join(self.parts).strip()
        # Legacy assignment is decoded as JSON, never evaluated as JavaScript.
        if text.startswith('window._sharedData') and '=' in text:
            text = text.split('=', 1)[1].strip().rstrip(';')
        try:
            self.documents.append(json.loads(text))
        except (ValueError, RecursionError):
            pass


def best(items):
    candidates = [i for i in (items or []) if isinstance(i, dict) and (i.get('url') or i.get('src'))]
    return max(candidates, key=lambda i: (i.get('width') or 0) * (i.get('height') or 0), default={})


def item(node):
    video = node.get('is_video') or node.get('media_type') == 2 or node.get('__typename') in ('GraphVideo', 'XDTGraphVideo')
    image = best(node.get('image_versions2', {}).get('candidates') or node.get('display_resources'))
    source = best(node.get('video_versions')) if video else image
    url = (source.get('url') or source.get('src') or node.get('video_url')) if video else (
        node.get('display_url') or source.get('url') or source.get('src'))
    if not isinstance(url, str) or not url.startswith('https://'):
        raise ExtractionError('extraction_failed')
    dimensions = node.get('dimensions') or {}
    out = {'type': 'video' if video else 'image', 'url': url}
    for key in ('width', 'height'):
        value = source.get(key) or node.get('original_' + key) or dimensions.get(key)
        if value:
            out[key] = value
    if video:
        thumbnail = node.get('display_url') or image.get('url') or image.get('src')
        if thumbnail:
            out['thumbnail'] = thumbnail
    return out


def parse(documents, target):
    """Find the exact post, never a recommendation or an unrelated nested image."""
    for node in walk(documents):
        if (node.get('shortcode') or node.get('code')) != target[2]:
            continue
        if not any(k in node for k in ('carousel_media', 'edge_sidecar_to_children', 'image_versions2', 'display_url', 'video_versions', 'video_url')):
            continue
        children = node.get('carousel_media')
        if children is None and 'edge_sidecar_to_children' in node:
            connection = node['edge_sidecar_to_children']
            if connection.get('page_info', {}).get('has_next_page'):
                raise ExtractionError('extraction_failed')
            children = [e['node'] for e in connection.get('edges', [])]
            expected = connection.get('count')
        else:
            expected = node.get('carousel_media_count')
        if children is not None:
            if not children or (expected is not None and len(children) != expected):
                raise ExtractionError('extraction_failed')
            media = [item(c) for c in children]
        else:
            if node.get('media_type') == 8 or 'Sidecar' in node.get('__typename', ''):
                raise ExtractionError('extraction_failed')
            media = [item(node)]
        caption = node.get('caption')
        if isinstance(caption, dict):
            caption = caption.get('text')
        if caption is None:
            edges = node.get('edge_media_to_caption', {}).get('edges', [])
            caption = edges[0]['node'].get('text') if edges else None
        return result(target, media, username=(node.get('owner') or node.get('user') or {}).get('username'),
            caption=caption, timestamp=node.get('taken_at_timestamp', node.get('taken_at')),
            likes=node.get('like_count', (node.get('edge_media_preview_like') or node.get('edge_liked_by') or {}).get('count')),
            comments=node.get('comment_count', (node.get('edge_media_to_parent_comment') or node.get('edge_media_to_comment') or {}).get('count')),
            media_id=str(node.get('pk') or node.get('id') or '') or None)
    raise ExtractionError('extraction_failed')


class InstagramWeb:
    def __init__(self, cookiefile=None, timeout=20):
        self.cookiefile = cookiefile
        self.timeout = timeout

    def request(self, url, data=None):
        # Reuse only yt-dlp's maintained HTTP transport and cookie support.
        # Its video extractor never processes post/carousel entries.
        from yt_dlp import YoutubeDL
        from yt_dlp.networking import Request
        from yt_dlp.networking.exceptions import HTTPError, RequestError
        try:
            with YoutubeDL({'quiet': True, 'no_warnings': True,
                    'cookiefile': self.cookiefile, 'socket_timeout': self.timeout}) as client:
                request = Request(url, data=urlencode(data).encode() if data else None)
                with client.urlopen(request) as response:
                    if '/accounts/login' in response.url:
                        raise ExtractionError('login_required')
                    raw = response.read(12 * 1024 * 1024 + 1)
                    if len(raw) > 12 * 1024 * 1024:
                        raise ExtractionError('extraction_failed')
                    return raw.decode('utf-8')
        except HTTPError as exc:
            raise ExtractionError({404: 'not_found', 410: 'not_found', 401: 'login_required',
                403: 'rate_limited', 429: 'rate_limited'}.get(exc.status, 'extraction_failed')) from None
        except (RequestError, OSError, UnicodeError):
            raise ExtractionError('extraction_failed') from None

    def extract(self, target):
        errors = []
        # Page JSON first, then a bounded public GraphQL fallback. IDs are isolated
        # and configurable because Instagram does not promise endpoint stability.
        routes = [(target[3].rstrip('/'), None), ('https://www.instagram.com/graphql/query', {
            'doc_id': os.environ.get('INSTAGRAM_GRAPHQL_DOC_ID', '8845758582119845'),
            'variables': json.dumps({'shortcode': target[2]})})]
        for url, data in routes:
            try:
                raw = self.request(url, data)
                if data:
                    documents = json.loads(raw)
                    message = str(documents.get('message', '')).lower()
                    if any(s in message for s in ('please wait', 'rate', 'feedback_required', 'challenge')):
                        raise ExtractionError('rate_limited')
                    if 'login_required' in message:
                        raise ExtractionError('login_required')
                else:
                    scripts = Scripts()
                    scripts.feed(raw)
                    documents = scripts.documents
                return parse(documents, target)
            except (ValueError, KeyError, TypeError, RecursionError):
                errors.append(ExtractionError('extraction_failed'))
            except ExtractionError as exc:
                errors.append(exc)
                log.info('Instagram route=%s failed code=%s', 'graphql' if data else 'page', exc.code)
                if exc.code == 'rate_limited':
                    break
        for code in ('rate_limited', 'login_required', 'not_found'):
            if any(e.code == code for e in errors):
                raise ExtractionError(code)
        raise ExtractionError('extraction_failed')
