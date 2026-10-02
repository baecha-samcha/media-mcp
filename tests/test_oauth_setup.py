"""Setup and persistence failures must preserve existing credentials/grants."""
import os
from pathlib import Path
import tempfile
import unittest
from cryptography.fernet import Fernet
from media_mcp.oauth import owner_hash, owner_matches, valid_redirect
from media_mcp.oauth_store import OAuthStore
from scripts.configure_oauth import append_settings


class SetupTests(unittest.TestCase):
    def test_owner_password_length_boundaries(self):
        for length in (8,9,15,16,1024,1025):
            with self.subTest(length=length):
                password='p'*length
                self.assertEqual(owner_matches(password,owner_hash(password)),9 <= length <= 1024)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'server.env';path.write_text('');path.chmod(0o600)
            with self.assertRaises(ValueError): append_settings(path,'p'*8)
            append_settings(path,'p'*9)

    def test_append_preserves_existing_env_and_refuses_reconfiguration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'server.env'
            original=b'# existing configuration\nMEDIA_MCP_API_KEY=existing-test-value\n'
            path.write_bytes(original);path.chmod(0o600)
            password='local-owner-password-for-tests'
            backup=append_settings(path,password)
            self.assertEqual(backup.read_bytes(),original)
            self.assertEqual(backup.stat().st_mode & 0o777,0o600)
            updated=path.read_bytes()
            self.assertTrue(updated.startswith(original))
            self.assertNotIn(password.encode(),updated)
            values=dict(line.split('=',1) for line in updated.decode().splitlines() if line.startswith('MEDIA_'))
            self.assertTrue(owner_matches(password,values['MEDIA_MCP_OWNER_PASSWORD_HASH']))
            Fernet(values['MEDIA_MCP_OAUTH_STORAGE_KEY'].encode())
            with self.assertRaises(ValueError): append_settings(path,password)
            self.assertEqual(path.read_bytes(),updated)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_setup_rejects_symlink_and_public_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'server.env';path.write_text('unchanged');path.chmod(0o644)
            with self.assertRaises(ValueError): append_settings(path,'a'*32)
            path.chmod(0o600)
            link=Path(directory)/'link.env';link.symlink_to(path)
            with self.assertRaises(ValueError): append_settings(link,'a'*32)
            self.assertEqual(path.read_text(),'unchanged')

    def test_store_wrong_key_fails_without_wiping_and_rejects_public_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Fernet.generate_key().decode();hashed=owner_hash('a'*32)
            store=OAuthStore(directory,key);store.start(hashed,'https://media.example');store.close()
            other=OAuthStore(directory,Fernet.generate_key().decode())
            with self.assertRaises(ValueError): other.start(hashed,'https://media.example')
            self.assertIsNone(other.db);self.assertIsNone(other.lock)
            store.start(hashed,'https://media.example')
            self.assertIsNotNone(store.get('meta','config'));store.close()
            (Path(directory)/'oauth.sqlite3').chmod(0o644)
            with self.assertRaises(ValueError): store.start(hashed,'https://media.example')

    def test_malformed_config_callback_returns_false(self):
        for uri in ('https://[oops/x','https://host.test:bad/x','https://127.0.0.1/x',
                    'https://host.test/*','https://host.test/x?next=evil'):
            self.assertFalse(valid_redirect(uri))


if __name__=='__main__': unittest.main()
