# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-
# pylint: disable=protected-access

import unittest
from unittest import mock

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.ike.analyzer import ProtocolHandlerIKEVersionIndependent
from cryptolyzer.ike.versions import AnalyzerVersions


class TestAnalyzer(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(KeyError):
            ProtocolHandlerBase.from_protocol('unsupportedprotocol')

    def test_protocol(self):
        self.assertEqual(ProtocolHandlerIKEVersionIndependent.get_protocol(), 'ike')


class TestAnalyzerThrottle(unittest.TestCase):
    """Tests for throttle functionality in AnalyzerBase._before_probe."""

    def test_throttle_delay_sleeps_between_probes(self):
        """When throttle_delay is set, sleep is called before 2nd and later probes, not before the first."""
        analyzer = AnalyzerVersions()
        analyzable = mock.Mock()
        analyzable.l4_socket_params = L4TransferSocketParams(throttle_delay=0.1)

        with mock.patch('cryptolyzer.common.analyzer.time.sleep') as mock_sleep:
            analyzer._before_probe(analyzable)
            mock_sleep.assert_not_called()

            analyzer._before_probe(analyzable)
            mock_sleep.assert_called_once_with(0.1)

            analyzer._before_probe(analyzable)
            self.assertEqual(mock_sleep.call_count, 2)

    def test_throttle_delay_zero_no_sleep(self):
        """When throttle_delay is 0, sleep is never called."""
        analyzer = AnalyzerVersions()
        analyzable = mock.Mock()
        analyzable.l4_socket_params = L4TransferSocketParams(throttle_delay=0.0)

        with mock.patch('cryptolyzer.common.analyzer.time.sleep') as mock_sleep:
            analyzer._before_probe(analyzable)
            analyzer._before_probe(analyzable)
            self.assertEqual(mock_sleep.call_count, 0)

    def test_reset_probe_throttle_clears_counter(self):
        """After _reset_probe_throttle, the next probe is treated as first (no sleep)."""
        analyzer = AnalyzerVersions()
        analyzable = mock.Mock()
        analyzable.l4_socket_params = L4TransferSocketParams(throttle_delay=0.1)

        with mock.patch('cryptolyzer.common.analyzer.time.sleep') as mock_sleep:
            analyzer._before_probe(analyzable)
            analyzer._before_probe(analyzable)
            self.assertEqual(mock_sleep.call_count, 1)

            analyzer._reset_probe_throttle()
            analyzer._before_probe(analyzable)
            self.assertEqual(mock_sleep.call_count, 1)  # still 1, no new sleep
