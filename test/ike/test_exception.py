# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.ike.algorithm import Ikev2NotifyType

from cryptolyzer.ike.exception import IsakmpNotify


class TestIsakmpNotify(unittest.TestCase):
    def test_str_is_repr(self):
        exc = IsakmpNotify(Ikev2NotifyType.INVALID_SYNTAX)
        self.assertEqual(str(exc), repr(exc))
