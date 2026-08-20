# SPDX-License-Identifier: MPL-2.0

import os

import unittest


SKIP_LIVE_SERVER = bool(os.environ.get('CRYPTOLYZER_TEST_SKIP_LIVE_SERVER'))
SKIP_LIVE_DNS = bool(os.environ.get('CRYPTOLYZER_TEST_SKIP_LIVE_DNS'))


def _live(skip, reason):
    def decorator(test_method):
        test_method.live = True

        return unittest.skipIf(skip, reason)(test_method)

    return decorator


live_server = _live(
    SKIP_LIVE_SERVER, 'live-server test skipped (CRYPTOLYZER_TEST_SKIP_LIVE_SERVER)'
)
live_dns = _live(
    SKIP_LIVE_DNS, 'live-DNS test skipped (CRYPTOLYZER_TEST_SKIP_LIVE_DNS)'
)
