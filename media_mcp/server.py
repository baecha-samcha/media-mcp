"""Run with .venv/bin/python -m media_mcp.server (exactly one ASGI worker)."""
import logging
from .config import Settings


def main():
    import uvicorn
    from .api import create_app
    settings = Settings.from_env()
    logging.basicConfig(level=logging.INFO)
    # Access logs contain bearer media tokens; never enable them in production.
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port,
                workers=1, access_log=False, proxy_headers=False,
                limit_concurrency=32, timeout_keep_alive=5)


if __name__ == '__main__':
    main()
