"""Bounded local-only representative JPEG extraction inside the job worker."""
import json
import math
from pathlib import Path
import subprocess
import time

DEFAULT_FRACTIONS = (0.1, 0.5, 0.9)
# Mean absolute difference (0-255) between 8x8 grayscale signatures below which
# consecutive default frames are treated as near-identical.
NEAR_DUPLICATE = 4
SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def jpeg_size(data):
    """(width, height) from the first JPEG SOF segment, or None."""
    i = 2
    while i + 9 <= len(data) and data[i] == 0xFF:
        marker = data[i+1]
        if marker == 0xFF:
            i += 1
            continue
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker in SOF_MARKERS:
            return int.from_bytes(data[i+7:i+9], 'big'), int.from_bytes(data[i+5:i+7], 'big')
        i += 2 + int.from_bytes(data[i+2:i+4], 'big')
    return None


def extract_frames(path, index, directory, *, deadline, max_bytes, max_items,
                   max_frame_bytes=None, timestamps=None, frame_indices=None):
    """Default: frames at 10%/50%/90% with near-duplicate skipping.

    timestamps (seconds) or frame_indices (0-based decoded frame numbers) select
    exact frames instead; those are only deduplicated when they hit the same frame.
    """
    max_frame_bytes = max_frame_bytes or max_bytes
    records = []
    common = ['-v', 'error', '-protocol_whitelist', 'file',
              '-format_whitelist', 'mov,matroska,webm', '-threads', '1']

    def run(args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(args, 0)
        return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=min(remaining, 15), check=True)

    try:
        probe = run(['ffprobe', *common, '-show_entries', 'format=duration:stream=avg_frame_rate',
                     '-select_streams', 'v:0', '-of', 'json', str(path)])
        info = json.loads(probe.stdout)
        duration = float(info['format']['duration'])
        numerator, denominator = info['streams'][0]['avg_frame_rate'].split('/')
        fps = float(numerator) / float(denominator)
        if not math.isfinite(duration) or duration <= 0 or not math.isfinite(fps) or fps <= 0:
            raise ValueError()
    except subprocess.TimeoutExpired:
        return [{'index': index, 'extracted': False, 'error': 'timeout'}]
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError, IndexError, ZeroDivisionError):
        return [{'index': index, 'extracted': False, 'error': 'frame_probe_failed'}]
    if frame_indices is not None:
        selection = 'frame_indices'
        requests = [(position / fps, position) for position in frame_indices]
    elif timestamps is not None:
        selection = 'timestamps'
        requests = [(timestamp, int(timestamp * fps)) for timestamp in timestamps]
    else:
        selection = 'default'
        requests = [(duration * f, int(duration * f * fps)) for f in DEFAULT_FRACTIONS]
    def signature_of(jpeg):
        # 8x8 grayscale thumbnail of the small JPEG; a separate single-output run
        # keeps ffmpeg's per-output threads within the worker memory limit.
        try:
            return run(['ffmpeg', '-nostdin', '-v', 'error', '-protocol_whitelist', 'file',
                        '-format_whitelist', 'image2,jpeg_pipe', '-threads', '1', '-i', str(jpeg),
                        '-vf', 'scale=8:8:flags=area,format=gray', '-filter_threads', '1',
                        '-frames:v', '1', '-f', 'rawvideo', 'pipe:1']).stdout
        except (OSError, subprocess.SubprocessError):
            return b''

    seen = {}
    used = count = 0
    previous = None
    for timestamp, position in requests:
        ordinal = len(records)
        name = f'frame-{index:03d}-{ordinal}.jpg'
        output = Path(directory) / name
        record = {'index': index, 'ordinal': ordinal, 'frame_index': position,
                  'timestamp_seconds': timestamp, 'selection': selection, 'name': name,
                  'source': 'instagram_reel', 'extracted': False}
        records.append(record)
        if position in seen:
            record.update(skipped='duplicate_frame', duplicate_of=seen[position])
            continue
        seen[position] = ordinal
        if timestamp >= duration:
            record['error'] = 'out_of_range'
            continue
        budget = min(max_frame_bytes, max_bytes - used)
        if count >= max_items or budget <= 0:
            record['error'] = 'limit_exceeded'
            continue
        try:
            # ffmpeg returns the first frame with pts >= -ss; seeking just before the
            # frame start selects frame_index itself (also the last frame of a clip).
            run(['ffmpeg', '-nostdin', *common, '-ss', str(max(0.0, (position - 0.25) / fps)), '-i', str(path),
                 '-an', '-sn', '-dn', '-frames:v', '1', '-filter_threads', '1',
                 '-vf', "scale=w='min(1280,iw)':h='min(1280,ih)':force_original_aspect_ratio=decrease",
                 '-c:v', 'mjpeg', '-threads', '1', '-q:v', '3', '-fs', str(budget+1),
                 '-y', str(output)])
            size = output.stat().st_size
            signature = signature_of(output) if selection == 'default' and 0 < size <= budget else b''
            if size <= 0:
                record['error'] = 'frame_extraction_failed'
            elif size > budget:
                record['error'] = 'limit_exceeded'
            elif (previous is not None and len(signature) == 64 and
                    sum(abs(a - b) for a, b in zip(signature, previous[1])) / 64 < NEAR_DUPLICATE):
                record.update(skipped='near_duplicate', duplicate_of=previous[0])
            else:
                with output.open('rb') as stream:
                    dimensions = jpeg_size(stream.read(65536))
                if dimensions:
                    record.update(width=dimensions[0], height=dimensions[1])
                used += size
                count += 1
                previous = (ordinal, signature) if len(signature) == 64 else None
                record.update(extracted=True, bytes=size, content_type='image/jpeg')
        except subprocess.TimeoutExpired:
            record['error'] = 'timeout'
        except (OSError, subprocess.CalledProcessError):
            record['error'] = 'frame_extraction_failed'
        if not record['extracted']:
            output.unlink(missing_ok=True)
    return records
