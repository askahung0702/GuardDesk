from contextlib import contextmanager, ExitStack
import unittest
from unittest.mock import Mock, patch

from guarddesk import native_browser_identity as identity
from guarddesk.native_connector import VerifiedBrowserPeer, NativeAttachmentSession, ConnectorInbox
import test_native_connector as fixtures


@contextmanager
def verified_fixture(**changes):
    api = Mock()
    api.OpenProcess.return_value = 900
    image = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
    values = (100, 133000000000000000, 2, image)
    with ExitStack() as stack:
        stack.enter_context(patch.object(identity, '_windows', return_value=api))
        stack.enter_context(patch.object(identity, '_snapshot', return_value=changes.get('snapshot', values)))
        stack.enter_context(patch.object(identity, '_process_sid', return_value=changes.get('sid', 'S-1-5-21-100')))
        stack.enter_context(patch.object(identity, 'machine_browser_paths', return_value={image.lower(): 'Google LLC'}))
        stack.enter_context(patch.object(identity, 'protected_browser_image'))
        stack.enter_context(patch.object(identity, 'signed_publisher', return_value=changes.get('publisher', 'Google LLC')))
        yield api


class BrowserIdentityTest(unittest.TestCase):
    def test_verified_process_lifetime_lease_is_required(self):
        with verified_fixture() as api:
            with identity.verify_browser(100, session=2, sid='S-1-5-21-100') as lease:
                peer = VerifiedBrowserPeer(lease)
                self.assertTrue(lease.authenticated())
                self.assertEqual(peer.pid, 100)
                with patch.object(identity, '_snapshot', return_value=(100, 133000000000000001, 2, lease.identity.image)):
                    self.assertFalse(lease.alive())
                    with self.assertRaises(ValueError):
                        peer.validate()
            api.CloseHandle.assert_called_once_with(900)
            self.assertFalse(lease.authenticated())

    def test_wrong_user_session_publisher_image_and_exited_process_are_rejected(self):
        cases = [({'sid': 'S-1-5-21-999'}, 'process_scope_mismatch'),
                 ({'snapshot': (100, 12, 3, r'C:\Program Files\Google\Chrome\Application\chrome.exe')}, 'process_scope_mismatch'),
                 ({'publisher': 'Other Corporation'}, 'publisher_mismatch'),
                 ({'snapshot': (100, 12, 2, r'C:\Users\User\chrome.exe')}, 'image_not_supported')]
        for changes, code in cases:
            with self.subTest(code=code), verified_fixture(**changes) as api:
                with self.assertRaises(identity.IdentityError) as raised:
                    with identity.verify_browser(100, session=2, sid='S-1-5-21-100'):
                        self.fail('Untrusted identity admitted')
                self.assertEqual(raised.exception.code, code)
                api.CloseHandle.assert_called_once_with(900)
        with verified_fixture() as api, patch.object(identity, '_snapshot', side_effect=identity.IdentityError('browser_exited')):
            with self.assertRaises(identity.IdentityError):
                with identity.verify_browser(100, session=2, sid='S-1-5-21-100'):
                    self.fail('Exited process admitted')
            api.CloseHandle.assert_called_once_with(900)

    def test_lookalike_peer_and_unverified_lease_cannot_enable_production_adapter(self):
        forged = identity.BrowserLease(Mock(), 1,
            identity.BrowserIdentity(100, 12, 2, r'C:\Owned\chrome.exe', 'Google LLC'), 'S-1-5-21-100')
        with self.assertRaises(ValueError):
            VerifiedBrowserPeer(forged)
        request, _ = fixtures.request_envelope(fixtures.message())
        with self.assertRaises(ValueError):
            fixtures.attachment_details(request, Mock())
        for pid, session, sid in ((True, 2, 'S-1-5-21-100'), (100, 0, 'S-1-5-21-100'),
                                  (100, 2, 'S-1-untrusted')):
            with self.assertRaises(identity.IdentityError):
                with identity.verify_browser(pid, session=session, sid=sid):
                    self.fail('Malformed scope admitted')

    def test_authenticated_session_ack_precedes_metadata_and_expired_lease_is_rejected(self):
        with verified_fixture(), identity.verify_browser(100, session=2, sid='S-1-5-21-100') as lease:
            inbox = ConnectorInbox()
            session = NativeAttachmentSession(lease, inbox)
            order = []
            original = inbox.offer
            def offer(value):
                order.append('offer')
                self.assertEqual(value[0]['integration'], 'verified_native_connector')
                self.assertEqual(value[0]['process_publisher'], 'Google LLC')
                return original(value)
            with patch.object(inbox, 'offer', side_effect=offer), patch('builtins.open', side_effect=AssertionError('No content IO')):
                self.assertTrue(session.receive(fixtures.message(), lambda raw: order.append('allow')))
            self.assertEqual(order, ['allow', 'offer'])
            self.assertFalse(session.receive(fixtures.message(url='file:///invalid'), lambda raw: order.append('allow')))
            self.assertEqual(order[-1], 'allow')
            lease.close()
            self.assertFalse(session.receive(fixtures.message(), lambda raw: self.fail('Expired peer replied')))


if __name__ == '__main__':
    unittest.main()
