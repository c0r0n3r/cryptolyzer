# SPDX-License-Identifier: MPL-2.0

import os

import unittest


SKIP_LIVE_SERVER = bool(os.environ.get('CRYPTOLYZER_TEST_SKIP_LIVE_SERVER'))
SKIP_LIVE_DNS = bool(os.environ.get('CRYPTOLYZER_TEST_SKIP_LIVE_DNS'))

live_server = unittest.skipIf(
    SKIP_LIVE_SERVER, 'live-server test skipped (CRYPTOLYZER_TEST_SKIP_LIVE_SERVER)'
)
live_dns = unittest.skipIf(
    SKIP_LIVE_DNS, 'live-DNS test skipped (CRYPTOLYZER_TEST_SKIP_LIVE_DNS)'
)
