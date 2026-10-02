import logging
import os
from .core import ExtractionError, detect, result
from .instagram import InstagramWeb

log = logging.getLogger(__name__)


class SafeLogger:
    # yt-dlp diagnostics can contain signed URLs, cookie paths and request data.
    def debug(self, message):
        pass

    def warning(self, message):
        log.debug('yt-dlp emitted a warning')

    def error(self, message):
        log.debug('yt-dlp emitted an extraction error')


def yt_extract(target, cookiefile=None):
    from yt_dlp import YoutubeDL
    from yt_dlp.utils import DownloadError
    options = {'quiet': True, 'no_warnings': True, 'logger': SafeLogger(),
        'skip_download': True, 'noplaylist': True, 'socket_timeout': 20,
        'retries': 0, 'extractor_retries': 0, 'format': 'best/bestvideo+bestaudio'}
    if cookiefile:
        options['cookiefile'] = cookiefile
    try:
        with YoutubeDL(options) as ydl:
            info = ydl.extract_info(target[3], download=False)
    except (DownloadError, OSError) as exc:
        text = str(exc).lower()
        code = 'extraction_failed'
        if any(s in text for s in ('429', 'rate-limit', 'rate limit', 'blocked', '403')):
            code = 'rate_limited'
        elif any(s in text for s in ('login', 'log in', 'private', 'sign in')):
            code = 'login_required'
        elif any(s in text for s in ('404', 'not found', 'deleted', 'removed')):
            code = 'not_found'
        log.info('yt-dlp platform=%s code=%s', target[0], code)
        raise ExtractionError(code) from None
    if not info or info.get('_type') == 'playlist':
        # Never return a partial video-only carousel.
        raise ExtractionError('extraction_failed')
    selected = list(info.get('requested_formats') or [info])
    audio_formats = [f for f in info.get('formats', []) if f.get('vcodec') == 'none' and f.get('url')]
    if audio_formats and not any(f.get('vcodec') == 'none' for f in selected):
        selected.append(audio_formats[-1])
    media = []
    for fmt in selected:
        if not fmt.get('url'):
            continue
        entry = {'type': 'audio' if fmt.get('vcodec') == 'none' else 'video', 'url': fmt['url']}
        for key in ('width', 'height', 'ext', 'protocol', 'acodec', 'vcodec'):
            if fmt.get(key) is not None:
                entry[key] = fmt[key]
        if info.get('thumbnail'):
            entry['thumbnail'] = info['thumbnail']
        if entry['type'] == 'video':
            entry['has_audio'] = None if fmt.get('acodec') is None else fmt['acodec'] != 'none'
        media.append(entry)
    if not media:
        raise ExtractionError('extraction_failed')
    out = result(target, media, username=info.get('channel') or info.get('uploader_id'),
        caption=info.get('description'), timestamp=info.get('timestamp'),
        likes=info.get('like_count'), comments=info.get('comment_count'), media_id=info.get('id'))
    out['type'] = 'reel' if target[1] == 'reel' else 'video'
    return out


def extract(url, *, cookiefile=None):
    target = detect(url)
    cookiefile = cookiefile or os.environ.get('MEDIA_MCP_COOKIE_FILE')
    if target[0] == 'youtube':
        return yt_extract(target, cookiefile)
    failures = []
    for cookies in ([None, cookiefile] if cookiefile else [None]):
        adapters = [InstagramWeb(cookies).extract]
        if target[1] in ('reel', 'tv'):
            adapters.insert(0, lambda t: yt_extract(t, cookies))
        for adapter in adapters:
            try:
                return adapter(target)
            except ExtractionError as exc:
                failures.append(exc)
                if exc.code == 'rate_limited':
                    # Do not hammer another endpoint/session after an explicit block.
                    raise
    for code in ('login_required', 'not_found'):
        if any(e.code == code for e in failures):
            raise ExtractionError(code)
    raise ExtractionError('extraction_failed')
