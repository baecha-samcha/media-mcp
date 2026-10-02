"""Stable schema and errors shared by platform adapters."""
import re
import time
from urllib.parse import urlsplit, parse_qs


class ExtractionError(Exception):
    MESSAGES = {
        'unsupported_url': 'Unsupported or invalid media URL.',
        'login_required': 'This post requires login or a valid session.',
        'rate_limited': 'Instagram blocked or limited this request. Try again later.',
        'not_found': 'The post was not found or has been deleted.',
        'extraction_failed': 'Could not extract complete media from this post.',
        'download_failed': 'Could not download the media.',
    }

    def __init__(self, code):
        self.code = code
        super().__init__(self.MESSAGES[code])

    def as_dict(self):
        return {'error': {'code': self.code, 'message': str(self)}}


def detect(url):
    try:
        p = urlsplit(url)
        if p.scheme not in ('https', 'http') or p.username or p.password or p.port:
            raise ValueError()
        if p.hostname in ('instagram.com', 'www.instagram.com', 'm.instagram.com'):
            m = re.fullmatch(r'/(p|reel|tv)/([A-Za-z0-9_-]{1,64})/?', p.path)
            if m:
                kind, ident = m.groups()
                return 'instagram', kind, ident, f'https://www.instagram.com/{kind}/{ident}/'
        if p.hostname in ('youtube.com', 'www.youtube.com', 'm.youtube.com', 'youtu.be'):
            ident = p.path.strip('/') if p.hostname == 'youtu.be' else (
                parse_qs(p.query).get('v', [''])[0] if p.path == '/watch' else
                p.path.split('/')[-1] if p.path.startswith(('/shorts/', '/embed/')) else '')
            if re.fullmatch(r'[A-Za-z0-9_-]{11}', ident):
                return 'youtube', 'video', ident, f'https://www.youtube.com/watch?v={ident}'
    except (ValueError, TypeError):
        pass
    raise ExtractionError('unsupported_url')


def result(target, media, *, username=None, caption=None, timestamp=None, likes=None, comments=None, media_id=None):
    platform, kind, ident, url = target
    return dict(platform=platform, type=('carousel' if len(media) > 1 else
        'reel' if kind == 'reel' else media[0]['type']), id=ident, media_id=media_id,
        url=url, author={'username': username}, caption=caption, timestamp=timestamp,
        stats={'likes': likes, 'comments': comments}, media=media,
        extracted_at=int(time.time()), media_urls_temporary=True)
