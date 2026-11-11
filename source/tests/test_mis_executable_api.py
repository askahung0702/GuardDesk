"""Dedicated one-file download keeps existing admin/CSRF/size lock boundary."""
import unittest
import urllib.error
from unittest.mock import patch
import test_mis_support as support


class ExecutableAPITest(unittest.TestCase):
    setUp=support.MISSupportTest.setUp
    tearDown=support.MISSupportTest.tearDown
    api=support.MISSupportTest.api
    def test_executable_download_requires_role_csrf_and_serialized_slot(self):
        path='/api/mis-support-executable'
        with self.assertRaises(urllib.error.HTTPError) as e:self.api(path,{},csrf=False)
        self.assertEqual(e.exception.code,403);e.exception.close()
        self.server.package_lock.acquire()
        try:
            with self.assertRaises(urllib.error.HTTPError) as e:self.api(path,{})
            self.assertEqual(e.exception.code,429);e.exception.close()
        finally:self.server.package_lock.release()
        self.csrf=self.api('/api/login',{'username':'helper','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as e:self.api(path,{})
        self.assertEqual(e.exception.code,403);e.exception.close()
        self.csrf=self.api('/api/login',{'username':'admin','password':self.password})['csrf']
        with patch('guarddesk.mis_onefile.executable',return_value=b'MZtest-public-executable') as builder:
            self.assertEqual(self.api(path,{}),b'MZtest-public-executable');self.assertEqual(builder.call_count,1)

if __name__=='__main__':unittest.main()
