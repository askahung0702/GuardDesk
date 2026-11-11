import sys
import unittest
import urllib.error
from unittest.mock import patch

import test_system
from guarddesk.store import password_matches, validate_password
from guarddesk.server_setup import create
from guarddesk.server_config import load
from guarddesk.store import Store


class PasswordPolicyTest(unittest.TestCase):
    setUp = test_system.SystemTest.setUp
    tearDown = test_system.SystemTest.tearDown
    api = test_system.SystemTest.api

    def test_short_passwords_work_for_all_roles_and_preserve_exact_characters(self):
        for index, (role, password) in enumerate([('admin', '1'), ('auditor', 'abc'), ('support', '  x  ')]):
            username = 'short' + str(index)
            self.store.add_user(username, password, role)
            self.assertEqual(self.api('/api/login', {'username': username, 'password': password})['role'], role)
            with self.store.connect() as db:
                encoded = db.execute('SELECT password FROM users WHERE username=?', (username,)).fetchone()[0]
            self.assertNotEqual(encoded, password)
            self.assertTrue(password_matches(password, encoded))
        self.csrf = self.api('/api/login', {'username': 'admin', 'password': self.password})['csrf']
        self.api('/api/remote/account', {'username': 'short-helper', 'password': ' 7 '})
        self.assertEqual(self.api('/api/login', {'username': 'short-helper', 'password': ' 7 '})['role'], 'support')

    def test_blank_wrong_type_and_oversize_rejected_without_creating_accounts(self):
        for password in ('', '   ', None, 7, 'x' * 1025):
            with self.assertRaises(ValueError): validate_password(password)
            with self.assertRaises(ValueError): self.store.add_user('invalid', password)
            with self.assertRaises(urllib.error.HTTPError) as denied:
                self.api('/api/remote/account', {'username': 'invalid', 'password': password})
            self.assertEqual(denied.exception.code, 400)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM users WHERE username='invalid'").fetchone()[0], 0)

    def test_setup_and_add_user_cli_accept_one_character_password(self):
        result = create(self.root / 'new data', '192.0.2.10', 'mis', '1', exe=sys.executable)
        store = Store(load(result['config'])['db'])
        with store.connect() as db:
            self.assertTrue(password_matches('1', db.execute("SELECT password FROM users WHERE username='mis'").fetchone()[0]))
        from guarddesk.__main__ import main
        with patch('sys.argv', ['guarddesk', 'add-user', 'cli-mis', '--db', str(store.path)]), \
             patch('guarddesk.__main__.getpass.getpass', side_effect=['2', '2']), \
             patch('guarddesk.__main__.signal.signal'):
            main()
        with store.connect() as db:
            self.assertTrue(password_matches('2', db.execute("SELECT password FROM users WHERE username='cli-mis'").fetchone()[0]))


if __name__ == '__main__': unittest.main()
