"""Owned fake transport regression executable; never a product installer."""
import sys
import unittest
import test_remote_broker_concurrency

if __name__ == '__main__':
    result=unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(test_remote_broker_concurrency))
    sys.exit(0 if result.wasSuccessful() else 1)
