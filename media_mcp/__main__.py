import argparse
import json
import logging
from . import extract, download_media, ExtractionError


def main():
    parser = argparse.ArgumentParser(description='Extract normalized Instagram/YouTube media')
    parser.add_argument('url')
    parser.add_argument('--download-check', action='store_true', help='Download to temporary files and clean up')
    parser.add_argument('--max-bytes', type=int, default=256 * 1024 * 1024)
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    try:
        data = extract(args.url)
        if args.download_check:
            from pathlib import Path
            with download_media(data, max_bytes=args.max_bytes) as paths:
                data['download_check'] = {'items': len(paths), 'bytes': sum(Path(p).stat().st_size for p in paths)}
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    except ExtractionError as exc:
        print(json.dumps(exc.as_dict()))
        return 1
    except Exception as exc:
        logging.error('Unexpected extraction exception=%s', type(exc).__name__)
        print(json.dumps(ExtractionError('extraction_failed').as_dict()))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
