"""One bounded service shared by HTTP and MCP. Linux/Pi single-process owner."""
import asyncio
import fcntl
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import sys
import time
from .core import ExtractionError, detect

log = logging.getLogger(__name__)
ID = re.compile(r'[0-9a-f]{64}\Z')


class ServiceError(Exception):
    MESSAGES = {
        'busy': (429, 'The server is busy. Retry later.'),
        'capacity': (507, 'Temporary storage capacity is full. Retry after media expires.'),
        'limit_exceeded': (413, 'Media exceeds the configured resource limits.'),
        'timeout': (504, 'The operation exceeded its time limit.'),
        'media_not_found': (404, 'Media is missing or expired.'),
        'unsupported_media': (415, 'This operation supports only single-image Instagram posts.'),
        'internal_error': (500, 'The operation failed.'),
        'invalid_indices': (400, 'indices must be unique 1-based item numbers within the inline item limit.'),
        'invalid_frames': (400, 'Use either frame_timestamps or frame_indices with unique non-negative '
                                'values within the inline item limit, only for Instagram reels.'),
    }

    def __init__(self, code):
        self.code = code
        self.status, message = self.MESSAGES[code]
        super().__init__(message)

    def as_dict(self):
        return {'error': {'code': self.code, 'message': str(self)}}


class InlineSkip(Exception):
    """An image that stays URL-only; code goes to inline_error/error metadata."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def read_inline_image(path, budget):
    """Shared inline path for post images and reel frames: regular file, byte budget, signature MIME."""
    from .worker import sniff
    if budget <= 0:
        raise InlineSkip('limit_exceeded')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError()
            raw = stream.read(budget + 1)
    except OSError:
        raise InlineSkip('image_read_failed') from None
    if not raw:
        raise InlineSkip('empty_file')
    if len(raw) > budget:
        raise InlineSkip('limit_exceeded')
    try:
        mime = sniff(raw[:32], 'image')
    except ExtractionError:
        raise InlineSkip('mime_detection_failed') from None
    if not mime.startswith('image/'):
        raise InlineSkip('mime_detection_failed')
    return raw, mime


async def run_worker(operation, url, directory, settings, indices=None, frames=None):
    # Inline results stop the download itself at the inline limit.
    limit = settings.inline_max_bytes if operation == 'view' else settings.max_total_bytes
    payload = {'operation': operation, 'url': url, 'directory': str(directory),
        'max_items': settings.max_items, 'max_item_bytes': min(settings.max_item_bytes, limit),
        'max_total_bytes': min(settings.max_total_bytes, limit), 'timeout': settings.prepare_timeout,
        'memory_mb': settings.worker_memory_mb, 'indices': indices,
        'inline_max_items': settings.inline_max_items, 'inline_max_bytes': settings.inline_max_bytes,
        'inline_frame_max_bytes': settings.inline_frame_max_bytes, **(frames or {})}
    env = {k: v for k, v in os.environ.items() if k not in ('MEDIA_MCP_API_KEY', 'MEDIA_MCP_OWNER_PASSWORD_HASH', 'MEDIA_MCP_OAUTH_STORAGE_KEY') and not k.lower().endswith('_proxy')}
    process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'media_mcp.worker',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, env=env, start_new_session=True)
    timeout = settings.extract_timeout if operation == 'extract' else settings.prepare_timeout
    try:
        async with asyncio.timeout(timeout):
            stdout, _ = await process.communicate(json.dumps(payload).encode())
        if process.returncode != 0 or len(stdout) > 2 * 1024 * 1024:
            raise ServiceError('internal_error')
        result = json.loads(stdout)
        if 'error' in result:
            code = result['error']
            log.warning('Worker operation=%s code=%s exception=%s', operation, code, result.get('exception', '-'))
            if code in ExtractionError.MESSAGES:
                raise ExtractionError(code)
            raise ServiceError(code if code in ServiceError.MESSAGES else 'internal_error')
        return result
    except TimeoutError:
        raise ServiceError('timeout') from None
    finally:
        # Cancellation and timeout stop the work itself, not just the HTTP wait.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()


class MediaService:
    def __init__(self, settings, runner=run_worker):
        self.settings = settings
        self.runner = runner
        self.root = Path(settings.temp_dir) / 'sessions-v1'
        self.sessions = {}
        self.active = 0
        self.preparing = 0
        self.streams = 0
        self.lock = None
        self.jobs = set()

    def start(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or self.root.resolve() != self.root.absolute():
            raise ValueError('Temporary directory must not contain symlinks')
        info = self.root.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Session directory must be owned by this user with mode 700')
        fd = os.open(self.root / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, 'w')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            self.lock = None
            raise RuntimeError('Only one server worker may own this media store') from None
        # Exact app-owned names only; never sweep the configured parent directory.
        for child in self.root.iterdir():
            if child.name.startswith('job-') and ID.fullmatch(child.name[4:]):
                self._remove(child)

    def _remove(self, path):
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)

    def cleanup(self):
        for ident, session in list(self.sessions.items()):
            if session['expires_at'] <= time.time():
                self._remove(session['directory'])
                del self.sessions[ident]

    async def close(self):
        for task in list(self.jobs):
            task.cancel()
        if self.jobs:
            await asyncio.gather(*list(self.jobs), return_exceptions=True)
        for session in self.sessions.values():
            self._remove(session['directory'])
        self.sessions.clear()
        if self.lock:
            self.lock.close()
            self.lock = None

    async def execute(self, operation, url, indices=None, frames=None):
        if not isinstance(url, str) or len(url) > 2048:
            raise ExtractionError('unsupported_url')
        target = detect(url)
        canonical = target[3]
        if operation == 'view' and target[0] != 'instagram':
            raise ServiceError('unsupported_media')
        self.cleanup()
        if self.active >= self.settings.concurrency:
            raise ServiceError('busy')
        prepare = operation in ('prepare', 'prepare_inline')
        if indices is not None and (not indices or len(indices) > self.settings.inline_max_items
                or len(set(indices)) != len(indices) or any(type(i) is not int or i < 1 for i in indices)):
            raise ServiceError('invalid_indices')
        if frames is not None:
            # {'frame_timestamps': [...]} or {'frame_indices': [...]}, reels only.
            values = next(iter(frames.values()), None) if len(frames) == 1 else None
            kind = next(iter(frames)) if len(frames) == 1 else None
            number = (lambda v: type(v) is int) if kind == 'frame_indices' else (
                lambda v: type(v) in (int, float) and math.isfinite(v))
            if (operation != 'prepare_inline' or kind not in ('frame_timestamps', 'frame_indices')
                    or not values or len(values) > self.settings.inline_max_items
                    or not all(number(v) and v >= 0 for v in values) or len(set(values)) != len(values)
                    or target[:2] != ('instagram', 'reel')):
                raise ServiceError('invalid_frames')
        if prepare and len(self.sessions) + self.preparing >= self.settings.max_sessions:
            raise ServiceError('capacity')
        # All reservation mutations happen on one event loop before the first await.
        self.active += 1
        self.preparing += int(prepare)
        task = asyncio.current_task()
        self.jobs.add(task)
        directory = self.root / ('job-' + secrets.token_hex(32))
        retain = False
        try:
            directory.mkdir(mode=0o700)
            # Optional arguments are passed only when used so existing runners keep working.
            options = {k: v for k, v in (('indices', indices), ('frames', frames)) if v is not None}
            data = await self.runner(operation, canonical, directory, self.settings, **options)
            source = data['source']
            if indices is not None and any(i > len(source['media']) for i in indices):
                raise ServiceError('invalid_indices')
            if operation == 'view':
                # Read into memory; finally removes the job directory. No session/URL.
                return self._inline(directory, source, data['files'])
            if not prepare:
                return source
            files = data['files']
            if not 0 < len(files) <= self.settings.max_items or len(files) != len(source['media']):
                raise ServiceError('limit_exceeded')
            ident = secrets.token_hex(32)
            expires = int(time.time()) + self.settings.media_ttl
            entries, tokens = [], {}
            total = 0
            for index, artifact in enumerate(files):
                # Filename comes from our worker but validate it defensively anyway.
                name = artifact['name']
                if name != f'{index:03d}.media':
                    raise ServiceError('internal_error')
                if 'error' in artifact:
                    entries.append({'index': index, 'type': source['media'][index]['type'],
                                    'error': artifact['error']})
                    continue
                path = directory / name
                if path.is_symlink() or not path.is_file():
                    raise ServiceError('internal_error')
                size = path.stat().st_size
                total += size
                if not 0 < size <= self.settings.max_item_bytes or total > self.settings.max_total_bytes:
                    raise ServiceError('limit_exceeded')
                token = secrets.token_hex(32)
                tokens[token] = (path, artifact['content_type'], size)
                entry = {k: v for k, v in source['media'][index].items()
                         if k in ('type', 'width', 'height', 'has_audio')}
                entry.update(index=index, url=f'{self.settings.public_base_url.rstrip("/")}/media/{ident}/{token}',
                             content_type=artifact['content_type'], bytes=size)
                entries.append(entry)
            images = []
            if operation == 'prepare_inline':
                frames = data.get('frames', [])
                requested = [i - 1 for i in indices] if indices is not None else [
                    i for i, item in enumerate(source['media']) if item['type'] == 'image'][:self.settings.inline_max_items]
                used = 0
                for index in requested:
                    entry = entries[index]
                    if 'error' in entry:
                        continue
                    if entry['type'] != 'image':
                        if source['platform'] == 'instagram' and '/reel/' in canonical and entry['type'] == 'video':
                            continue
                        entry['inline_error'] = 'unsupported_media'
                        continue
                    try:
                        raw, mime = read_inline_image(directory / files[index]['name'],
                                                      self.settings.inline_max_bytes - used)
                    except InlineSkip as exc:
                        entry['inline_error'] = exc.code
                        continue
                    used += len(raw)
                    images.append({'index': index, 'data': raw, 'content_type': mime})
                for frame in frames:
                    # Worker records without the flag predate 'extracted'; treat them as successful.
                    if 'error' in frame or 'skipped' in frame or not frame.get('extracted', True):
                        continue
                    name = frame.get('name')
                    if name != f"frame-{frame['index']:03d}-{frame['ordinal']}.jpg":
                        raise ServiceError('internal_error')
                    path = directory / name
                    try:
                        if len(images) >= self.settings.inline_max_items:
                            raise InlineSkip('limit_exceeded')
                        raw, mime = read_inline_image(path, min(self.settings.inline_frame_max_bytes,
                                                                self.settings.inline_max_bytes - used))
                        if mime != 'image/jpeg':
                            raise InlineSkip('mime_detection_failed')
                    except InlineSkip as exc:
                        frame['error'] = exc.code
                        continue
                    finally:
                        path.unlink(missing_ok=True)
                    used += len(raw)
                    frame.update(bytes=len(raw), content_type=mime)
                    images.append({'index': frame['index'], 'data': raw,
                                   'content_type': mime, 'frame': frame})
                inline_indices = list(dict.fromkeys(item['index'] for item in images))
                for index, entry in enumerate(entries):
                    if entry['type'] == 'image' and index not in requested and 'error' not in entry:
                        entry['inline_status'] = 'not_selected'
            self.sessions[ident] = {'directory': directory, 'expires_at': expires, 'tokens': tokens}
            retain = True
            result = {'session_id': ident, 'source': source, 'media': entries,
                      'expires_at': expires, 'access': 'temporary_bearer_url'}
            if operation == 'prepare_inline':
                result['inline_indices'] = inline_indices
                result['inline_index_base'] = 0
                result['inline_max_items'] = self.settings.inline_max_items
                result['inline_max_bytes'] = self.settings.inline_max_bytes
                if frames:
                    result['frames'] = frames
            return (result, images) if operation == 'prepare_inline' else result
        except (ExtractionError, ServiceError):
            raise
        except Exception as exc:
            log.error('Service operation=%s exception=%s', operation, type(exc).__name__)
            raise ServiceError('internal_error') from None
        finally:
            if not retain:
                self._remove(directory)
            self.active -= 1
            self.preparing -= int(prepare)
            self.jobs.discard(task)

    def _inline(self, directory, source, files):
        if not 0 < len(files) <= self.settings.max_items or len(files) != len(source['media']):
            raise ServiceError('limit_exceeded')
        items, total = [], 0
        for index, artifact in enumerate(files):
            name, mime = artifact['name'], artifact['content_type']
            if name != f'{index:03d}.media':
                raise ServiceError('internal_error')
            if not mime.startswith('image/'):
                raise ServiceError('unsupported_media')
            fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ServiceError('internal_error')
                content = stream.read(self.settings.inline_max_bytes + 1)
            total += len(content)
            if not content or total > self.settings.inline_max_bytes:
                raise ServiceError('limit_exceeded')
            items.append({'index': index, 'type': source['media'][index]['type'],
                          'content_type': mime, 'bytes': len(content), 'data': content})
        return {'source': source, 'media': items}

    def open_media(self, ident, token):
        if not ID.fullmatch(ident) or not ID.fullmatch(token):
            raise ServiceError('media_not_found')
        self.cleanup()
        session = self.sessions.get(ident)
        artifact = session and session['tokens'].get(token)
        if not artifact:
            raise ServiceError('media_not_found')
        if self.streams >= self.settings.max_streams:
            raise ServiceError('busy')
        path, content_type, size = artifact
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise OSError()
        except OSError:
            raise ServiceError('media_not_found') from None
        self.streams += 1
        return os.fdopen(fd, 'rb'), content_type, size
