"""Small encrypted OAuth store. Token/code lookup keys are SHA-256 digests."""
from contextlib import contextmanager
import hashlib
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from cryptography.fernet import Fernet


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class OAuthStore:
    def __init__(self, directory, key):
        self.directory = Path(directory)
        self.cipher = Fernet(key.encode())
        self.db = None
        self.lock = None

    def start(self, owner_hash, issuer):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.resolve() != self.directory.absolute():
            raise ValueError('OAuth directory may not contain symlinks')
        info = self.directory.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('OAuth directory must be owned by this user with mode 700')
        path = self.directory / 'oauth.sqlite3'
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            os.close(fd)
            raise ValueError('OAuth database must be a private regular file')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise RuntimeError('Only one process may own this OAuth store') from None
        self.lock = os.fdopen(fd, 'rb')
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute('PRAGMA secure_delete=ON')
        self.db.execute('PRAGMA max_page_count=8192')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('CREATE TABLE IF NOT EXISTS records(kind TEXT, key TEXT, data BLOB, expires REAL, PRIMARY KEY(kind,key))')
        try:
            previous = self.get('meta', 'config')
        except Exception:
            self.close()
            raise ValueError('OAuth storage key cannot decrypt existing database') from None
        fingerprint = {'owner': digest(owner_hash), 'issuer': issuer}
        with self.transaction():
            if previous and previous != fingerprint:
                self.db.execute('DELETE FROM records')  # Owner/issuer change revokes all grants.
            self.put('meta', 'config', fingerprint, 2**62)
        self.cleanup()

    def get(self, kind, key, *, expired=False):
        row = self.db.execute('SELECT data,expires FROM records WHERE kind=? AND key=?', (kind,key)).fetchone()
        if row is None or (not expired and row[1] <= time.time()):
            return None
        return json.loads(self.cipher.decrypt(row[0]))

    def put(self, kind, key, data, expires):
        encoded = self.cipher.encrypt(json.dumps(data, separators=(',', ':')).encode())
        self.db.execute('INSERT OR REPLACE INTO records VALUES (?,?,?,?)', (kind,key,encoded,expires))

    def delete(self, kind, key):
        self.db.execute('DELETE FROM records WHERE kind=? AND key=?', (kind,key))

    def count(self, kind=None):
        if kind:
            return self.db.execute('SELECT count(*) FROM records WHERE kind=?', (kind,)).fetchone()[0]
        return self.db.execute('SELECT count(*) FROM records').fetchone()[0]

    def cleanup(self):
        self.db.execute('DELETE FROM records WHERE expires<=?', (time.time(),))

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None
