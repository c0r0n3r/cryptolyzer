# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from test.common.classes import TestMainBase

import test.ike.test_versions  # noqa: F401  pylint: disable=unused-import

import urllib3

from cryptodatahub.ike.version import IkeVersion

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ike.analyzer import (
    ProtocolHandlerIKEv1,
    ProtocolHandlerIKEv2,
    ProtocolHandlerIKEVersionIndependent,
)
from cryptolyzer.ike.server import L7ServerIke
from cryptolyzer.ike.versions import AnalyzerVersions

from cryptolyzer.__main__ import main

from .classes import create_ike_server


class TestMain(TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    def setUp(self):
        # Two analyses will be performed (expected + CLI), and each analysis
        # performs two handshakes (IKEv2 probe + IKEv1 probe).
        self.threaded_server = create_ike_server(
            L7ServerIke,
            timeout=5,
            max_handshake_count=4,
        )

        l4_transfer = self.threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None
        self.address = f'localhost:{l4_transfer.bind_port}'

    def tearDown(self):
        self.threaded_server.join(timeout=5)

    def test_versions(self):
        url = urllib3.util.parse_url('ipsec://' + self.address)
        expected = ProtocolHandlerIKEVersionIndependent().analyze(
            AnalyzerVersions(),
            url,
            socket_params=L4TransferSocketParams(timeout=5.0),
        ).as_json() + '\n'

        self.assertEqual(
            self._get_test_analyzer_result_json('ike', 'versions', self.address),
            expected,
        )


class TestProtocolHandlerVersion(TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return None

    def test_ikev1_protocol_version(self):
        self.assertEqual(ProtocolHandlerIKEv1.get_protocol_version(), IkeVersion.V1)

    def test_ikev2_protocol_version(self):
        self.assertEqual(ProtocolHandlerIKEv2.get_protocol_version(), IkeVersion.V2)
