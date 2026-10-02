"""Short-lived, killable job process. No server imports or long-lived secrets."""
import contextlib
import json
import os
from pathlib import Path
import resource
import sys
from .core import ExtractionError


def content_type(path, kind):
    with open(path, 'rb') as stream:
        return sniff(stream.read(32), kind)


def sniff(header, kind):
    """MIME from a file signature; shared by downloads and inline image reads."""
    if header.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if header.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if header.startswith((b'GIF87a', b'GIF89a')):
        return 'image/gif'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'image/webp'
    if header[4:8] == b'ftyp':
        if header[8:12] in (b'avif', b'avis'):
            return 'image/avif'
        return 'audio/mp4' if kind == 'audio' else 'video/mp4'
    if header.startswith(b'\x1a\x45\xdf\xa3'):
        return 'audio/webm' if kind == 'audio' else 'video/webm'
    if header.startswith(b'OggS'):
        return 'audio/ogg' if kind == 'audio' else 'video/ogg'
    if header.startswith(b'ID3') or header[:2] in (b'\xff\xfb', b'\xff\xf3', b'\xff\xf2'):
        return 'audio/mpeg'
    raise ExtractionError('download_failed')


def work(payload):
    import time
    from .frames import extract_frames
    deadline = time.monotonic() + payload['timeout'] - min(2, payload['timeout'] / 10)
    from .network import NetworkGuard
    from .extractor import extract
    from .download import download_media
    from .service import ServiceError
    memory = payload['memory_mb'] * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_FSIZE, (payload['max_total_bytes'], payload['max_total_bytes']))
    NetworkGuard().install()
    metadata = extract(payload['url'])
    if payload['operation'] == 'extract':
        return {'source': metadata}
    if payload['operation'] == 'view' and not (metadata['platform'] == 'instagram' and
            len(metadata['media']) == 1 and metadata['media'][0]['type'] == 'image'):
        # Probe scope: never download reels, videos or carousels for inline results.
        raise ServiceError('unsupported_media')
    if not 0 < len(metadata['media']) <= payload['max_items']:
        raise ServiceError('limit_exceeded')
    directory = Path(payload['directory'])
    files = []
    reel = metadata['platform'] == 'instagram' and '/reel/' in payload['url']
    frames = []
    if payload['operation'] == 'prepare_inline' and (reel or any(item['type'] == 'image' for item in metadata['media'])):
        import time
        total = 0
        for index, item in enumerate(metadata['media']):
            name = f'{index:03d}.media'
            try:
                remaining = payload['max_total_bytes'] - total
                if remaining <= 0:
                    raise ServiceError('limit_exceeded')
                if time.monotonic() >= deadline:
                    raise ServiceError('timeout')
                with download_media(dict(metadata, media=[item]), max_bytes=remaining,
                        max_item_bytes=payload['max_item_bytes'], max_items=1,
                        timeout=max(0.001, deadline - time.monotonic()), directory=directory) as paths:
                    path = Path(paths[0])
                    size = path.stat().st_size
                    total += size
                    if not size:
                        files.append({'name': name, 'error': 'empty_file'})
                        continue
                    try:
                        mime = content_type(path, item['type'])
                    except ExtractionError:
                        files.append({'name': name, 'error': 'mime_detection_failed'})
                        continue
                    os.replace(path, directory / name)
                    files.append({'name': name, 'content_type': mime})
            except (ExtractionError, ServiceError) as exc:
                code = 'limit_exceeded' if type(exc).__name__ == 'DownloadLimitError' else getattr(exc, 'reason', getattr(exc, 'code', 'download_failed'))
                files.append({'name': name, 'error': code})
        if reel:
            selected = [i-1 for i in payload['indices']] if payload.get('indices') is not None else next(
                ([i] for i, item in enumerate(metadata['media']) if item['type'] == 'video'), [])
            used, count = 0, 0
            for index in selected:
                if index >= len(files) or metadata['media'][index]['type'] != 'video':
                    continue
                if 'error' in files[index]:
                    frames.append({'index': index, 'extracted': False, 'error': files[index]['error']})
                    continue
                extracted = extract_frames(directory / files[index]['name'], index, directory,
                    deadline=deadline, max_bytes=payload['inline_max_bytes']-used,
                    max_items=payload['inline_max_items']-count,
                    max_frame_bytes=payload.get('inline_frame_max_bytes'),
                    timestamps=payload.get('frame_timestamps'), frame_indices=payload.get('frame_indices'))
                frames.extend(extracted)
                used += sum(f.get('bytes', 0) for f in extracted if f['extracted'])
                count += sum(f['extracted'] for f in extracted)
        return {'source': metadata, 'files': files, 'frames': frames}
    with download_media(metadata, max_bytes=payload['max_total_bytes'],
            max_item_bytes=payload['max_item_bytes'], max_items=payload['max_items'],
            timeout=payload['timeout'], directory=directory) as paths:
        for index, path in enumerate(paths):
            mime = content_type(path, metadata['media'][index]['type'])
            name = f'{index:03d}.media'
            os.replace(path, directory / name)
            files.append({'name': name, 'content_type': mime})
    return {'source': metadata, 'files': files}


def main():
    payload = json.loads(sys.stdin.buffer.read(16384))
    try:
        # Third-party diagnostics can contain signed URLs or cookie paths.
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            output = work(payload)
        encoded = json.dumps(output)
        if len(encoded.encode()) > 2 * 1024 * 1024:
            encoded = json.dumps({'error': 'limit_exceeded'})
    except Exception as exc:
        code = 'limit_exceeded' if type(exc).__name__ == 'DownloadLimitError' else getattr(exc, 'code', 'internal_error')
        encoded = json.dumps({'error': code, 'exception': type(exc).__name__})
    sys.stdout.write(encoded)


if __name__ == '__main__':
    main()
