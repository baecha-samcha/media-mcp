"""Operator-run OAuth setup: append settings, never display/store raw passwords.

Does not start/restart services. Refuses existing OAuth settings. Run from repo:
  .venv/bin/python scripts/configure_oauth.py
"""
import argparse
import getpass
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.fernet import Fernet
from media_mcp.oauth import owner_hash


def append_settings(path, password):
    path = Path(path).absolute()
    repo = Path(__file__).resolve().parents[1]
    if path.resolve().is_relative_to(repo) or path.resolve() != path:
        raise ValueError('Use an external environment file, without symlinks')
    if not 9 <= len(password) <= 1024:
        raise ValueError('Owner password must be 9-1024 characters')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Existing environment file must be owned by you with mode 600')
        original = stream.read()
    text = original.decode()
    if re.search(r'^\s*(?:export\s+)?MEDIA_MCP_(?:OWNER_|OAUTH_)\w*\s*=', text, re.M):
        raise ValueError('OAuth settings already exist; no values were replaced')
    addition = ('\n# Single-owner OAuth; generated locally. Keep this file private.\n'
        'MEDIA_MCP_OWNER_PASSWORD_HASH=' + owner_hash(password) + '\n'
        'MEDIA_MCP_OAUTH_STORAGE_KEY=' + Fernet.generate_key().decode() + '\n'
        'MEDIA_MCP_OAUTH_REDIRECT_URIS=https://chatgpt.com/connector_platform_oauth_redirect\n'
        'MEDIA_MCP_OAUTH_ACCESS_TTL=900\n'
        'MEDIA_MCP_OAUTH_REFRESH_TTL=2592000\n'
        'MEDIA_MCP_OAUTH_CODE_TTL=120\n')
    # Backup is also outside the repo, private, and created exclusively.
    backup = path.with_name(path.name + '.before-oauth-' + secrets.token_hex(8))
    with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
        out.write(original)
        out.flush()
        os.fsync(out.fileno())
    temp_fd, temporary = tempfile.mkstemp(prefix='.oauth-env-', dir=path.parent)
    try:
        with os.fdopen(temp_fd, 'wb') as out:
            out.write(original + addition.encode())
            out.flush()
            os.fsync(out.fileno())
        if path.stat().st_ino != info.st_ino or path.read_bytes() != original:
            raise ValueError('Environment file changed during setup; refusing replacement')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, default=Path.home()/'.config/media-mcp/server.env')
    args = parser.parse_args()
    password = getpass.getpass('New owner password (9+ characters; save in your password manager): ')
    if password != getpass.getpass('Repeat owner password: '):
        raise SystemExit('Passwords do not match; no changes made')
    try:
        backup = append_settings(args.env_file, password)
    except (ValueError, OSError) as exc:
        # Do not print exception values that might contain file contents.
        raise SystemExit('Setup refused (' + type(exc).__name__ + '). Check file permissions and existing OAuth settings.') from None
    print('OAuth settings appended; existing settings preserved. Private backup: ' + str(backup))
    print('No service was restarted. See deployment/README.md for verification and restart.')


if __name__ == '__main__':
    main()
