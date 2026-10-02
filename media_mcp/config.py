"""Validated server configuration; no secret defaults."""
from dataclasses import dataclass, field, fields
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

VERSION = '0.3.0'


@dataclass(frozen=True)
class Settings:
    api_key: str = field(default='', repr=False)
    host: str = '127.0.0.1'
    port: int = 8765
    public_base_url: str = ''
    temp_dir: str = str(Path.home() / '.cache/media-mcp')
    media_ttl: int = 900
    max_item_bytes: int = 32 * 1024 * 1024
    max_total_bytes: int = 128 * 1024 * 1024
    # Raw bytes allowed inline in one MCP result (before base64).
    inline_max_bytes: int = 5 * 1024 * 1024
    inline_max_items: int = 3
    # Raw bytes allowed for one extracted reel frame (also bounded by the total).
    inline_frame_max_bytes: int = 2 * 1024 * 1024
    max_items: int = 20
    concurrency: int = 1
    max_sessions: int = 4
    extract_timeout: int = 45
    prepare_timeout: int = 90
    worker_memory_mb: int = 512
    cleanup_interval: int = 30
    max_streams: int = 4
    stream_timeout: int = 120

    owner_password_hash: str = field(default='', repr=False)
    oauth_storage_key: str = field(default='', repr=False)
    oauth_store_dir: str = ''
    oauth_redirect_uris: str = 'https://chatgpt.com/connector_platform_oauth_redirect'
    oauth_persistent_grants: int = 0
    oauth_access_ttl: int = 900
    oauth_refresh_ttl: int = 2592000
    oauth_code_ttl: int = 120

    @property
    def oauth_enabled(self):
        return bool(self.owner_password_hash)

    def __post_init__(self):
        if len(self.api_key.encode()) < 32 or not self.api_key.isascii() or any(c.isspace() for c in self.api_key):
            raise ValueError('MEDIA_MCP_API_KEY must contain at least 32 non-whitespace ASCII characters')
        if self.oauth_persistent_grants not in (0, 1):
            raise ValueError("MEDIA_MCP_OAUTH_PERSISTENT_GRANTS must be 0 or 1")
        for f in fields(self):
            if f.type is int and f.name != 'oauth_persistent_grants' and getattr(self, f.name) <= 0:
                raise ValueError(f'MEDIA_MCP_{f.name.upper()} must be positive')
        if self.port > 65535 or self.max_item_bytes > self.max_total_bytes:
            raise ValueError('Invalid port or byte limits')
        # Validate the raw origin before urlsplit can discard CR/LF/tab. This
        # value is also a CSP source: forbid whitespace, directive separators,
        # wildcards, escapes and encoded delimiters. IDNs must use ASCII punycode.
        if not re.fullmatch(r'https?://[A-Za-z0-9.\-:\[\]]+/?', self.public_base_url):
            raise ValueError('Set MEDIA_MCP_PUBLIC_BASE_URL to an absolute ASCII origin URL')
        p = urlsplit(self.public_base_url)
        if (p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password
                or p.path not in ('', '/') or p.query or p.fragment):
            raise ValueError('Set MEDIA_MCP_PUBLIC_BASE_URL to an absolute origin URL')
        if p.port is not None and not 1 <= p.port <= 65535:
            raise ValueError('Invalid public URL port')
        if p.scheme == 'http' and p.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('Public deployments require an HTTPS base URL')
        if not Path(self.temp_dir).is_absolute():
            raise ValueError('MEDIA_MCP_TEMP_DIR must be absolute')

        if self.owner_password_hash or self.oauth_storage_key:
            from .oauth import valid_owner_hash, valid_redirect
            from cryptography.fernet import Fernet
            if not valid_owner_hash(self.owner_password_hash):
                raise ValueError('Set a valid MEDIA_MCP_OWNER_PASSWORD_HASH')
            try:
                Fernet(self.oauth_storage_key.encode())
            except (ValueError, TypeError):
                raise ValueError('Set a valid MEDIA_MCP_OAUTH_STORAGE_KEY') from None
            if not all(valid_redirect(u) for u in self.oauth_redirect_uris.split(',')):
                raise ValueError('OAuth callbacks must be exact HTTPS URLs without query, fragment or wildcard')
            if self.oauth_code_ttl > 300 or self.oauth_access_ttl > 3600 or self.oauth_refresh_ttl > 7776000:
                raise ValueError('OAuth TTL maximum: code 300s, access 3600s, refresh 90 days')
            if self.oauth_store_dir and not Path(self.oauth_store_dir).is_absolute():
                raise ValueError('OAuth store path must be absolute')

    @classmethod
    def from_env(cls):
        values = {}
        for f in fields(cls):
            value = os.environ.get('MEDIA_MCP_' + f.name.upper())
            if value is not None:
                values[f.name] = int(value) if f.type is int else value
        values.setdefault('public_base_url', f"http://127.0.0.1:{values.get('port', 8765)}")
        return cls(**values)
