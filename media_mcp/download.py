"""Bounded temporary download context for an AI consumer; cleans up on exit."""
import ipaddress
import logging
import socket
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener
from .core import ExtractionError

log = logging.getLogger(__name__)


class DownloadEmptyError(ExtractionError):
    reason = 'empty_file'

    def __init__(self):
        super().__init__('download_failed')


class DownloadLimitError(ExtractionError):
    def __init__(self):
        super().__init__('download_failed')


def validate_url(url):
    p = urlsplit(url)
    if p.scheme != 'https' or p.username or p.password or p.port not in (None, 443):
        raise ValueError('Unsafe URL')
    # Only expected media CDNs; validate redirects as well.
    if not p.hostname or not any(p.hostname.endswith('.' + domain) for domain in
        ('cdninstagram.com', 'fbcdn.net', 'googlevideo.com', 'ytimg.com')):
        raise ValueError('Unexpected CDN')
    addresses = socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise ValueError('Non-public destination')


class Redirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@contextmanager
def download_media(metadata, *, max_bytes=256 * 1024 * 1024, directory=None,
                   max_item_bytes=None, max_items=20, timeout=90, content_types=None):
    """Stream into a cleanup context; optional per-file limits for the server.

    Server workers install network.NetworkGuard to additionally pin DNS results.
    content_types, when supplied, is populated alongside the returned paths.
    """
    if max_bytes <= 0:
        raise ValueError('max_bytes must be positive')
    max_item_bytes = max_item_bytes or max_bytes
    if not 0 < len(metadata.get('media', [])) <= max_items:
        raise ExtractionError('download_failed')
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix='media-mcp-', dir=directory) as temp:
        paths = []
        total = 0
        try:
            opener = build_opener(Redirects())
            for index, media in enumerate(metadata['media']):
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                validate_url(media['url'])
                if media.get('protocol', 'https') not in ('https', 'http'):
                    raise ValueError('Manifest formats need a separate streaming downloader')
                path = Path(temp) / f'{index:03d}.media'
                request = Request(media['url'], headers={'User-Agent': 'Mozilla/5.0'})
                with opener.open(request, timeout=min(15, max(1, deadline - time.monotonic()))) as response, path.open('wb') as output:
                    mime = response.headers.get_content_type()
                    if not mime.startswith(('image/', 'video/', 'audio/')) and mime != 'application/octet-stream':
                        raise ValueError('Unexpected content type')
                    item_bytes = 0
                    length = response.headers.get('Content-Length')
                    if isinstance(length, str) and (int(length) > max_item_bytes or int(length) > max_bytes - total):
                        raise DownloadLimitError()
                    while chunk := response.read(min(65536, max_bytes - total + 1, max_item_bytes - item_bytes + 1)):
                        if time.monotonic() >= deadline:
                            raise TimeoutError()
                        item_bytes += len(chunk)
                        if item_bytes > max_item_bytes:
                            raise DownloadLimitError()
                        total += len(chunk)
                        if total > max_bytes:
                            raise DownloadLimitError()
                        output.write(chunk)
                if not path.stat().st_size:
                    raise DownloadEmptyError()
                paths.append(str(path))
                if content_types is not None:
                    content_types.append(mime)
        except (DownloadLimitError, DownloadEmptyError):
            raise
        except Exception as exc:
            log.info('Media download failed exception=%s', type(exc).__name__)
            raise ExtractionError('download_failed') from None
        yield paths
