# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev2DiffieHellmanGroup,
)
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ike.curves import AnalyzerCurves
from cryptolyzer.ike.server import IkeServerConfiguration

from .classes import get_ecdh_only_server_configuration, get_ffdh_only_server_configuration
from .test_dh import TestAnalyzerDHBase


class TestAnalyzerCurvesUnit(unittest.TestCase):
    def test_get_name(self):
        self.assertEqual(AnalyzerCurves.get_name(), 'curves')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerCurves.get_help(), str)


class TestAnalyzerCurves(TestAnalyzerDHBase):
    @classmethod
    def get_analyzer_class(cls):
        return AnalyzerCurves

    @classmethod
    def get_expected_groups_ikev1(cls):
        return (
            Ikev1DiffieHellmanGroup.ECP_256_BIT,
            Ikev1DiffieHellmanGroup.ECP_384_BIT,
        )

    @classmethod
    def get_expected_groups_ikev2(cls):
        return (
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
            Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT,
        )

    @classmethod
    def get_server_config(cls) -> IkeServerConfiguration:
        return get_ecdh_only_server_configuration()

    @classmethod
    def get_no_proposal_config(cls) -> IkeServerConfiguration:
        return get_ffdh_only_server_configuration()

    @classmethod
    def get_max_handshakes(cls):
        return None

    @classmethod
    def get_server_timeout(cls) -> float:
        return 2.0

    def _get_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            self, host, port, protocol_version, l4_socket_params=None, ip=None):
        if l4_socket_params is None:
            l4_socket_params = L4TransferSocketParams(timeout=2.0)
        return super()._get_result(host, port, protocol_version, l4_socket_params, ip)
