# -*- coding: utf-8 -*-

import unittest


from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType


class TestException(unittest.TestCase):
    def test_str(self):
        with self.assertRaisesRegex(NetworkError, 'address of the target cannot be resolved'):
            raise NetworkError(NetworkErrorType.NO_ADDRESS)

        with self.assertRaisesRegex(SecurityError, 'target does not support secure communication'):
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
