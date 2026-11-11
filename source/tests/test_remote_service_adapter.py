import unittest
from tools.probe_remote_service_boundary import cases

class AdapterBoundaryTest(unittest.TestCase):
    def test_real_adapter_not_replaced_by_transaction_fixture(self):
        self.assertEqual(len(cases()),7)
