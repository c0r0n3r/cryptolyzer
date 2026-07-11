
import unittest
import unittest.mock

from test.common.classes import OFFLINE_CLIENT_L4_SOCKET_PARAMS

from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev2DiffieHellmanGroup,
)
from cryptodatahub.ike.version import IkeVersion
from cryptolyzer.common.result import AnalyzerTargetIke
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.curves import AnalyzerCurves
from cryptolyzer.ike.server import IkeServerConfiguration

from .classes import get_ecdh_only_server_configuration, get_ffdh_only_server_configuration
from .test_dh import TestAnalyzerDHBase


class TestAnalyzerCurvesUnit(unittest.TestCase):
    def test_get_name(self):
        self.assertEqual(AnalyzerCurves.get_name(), 'curves')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerCurves.get_help(), str)

    def test_analyze_result_target_is_analyzer_target_ike(self):
        analyzer = AnalyzerCurves()
        l7_client = L7ClientIPsecBase.from_scheme('ipsec', 'localhost', 500, OFFLINE_CLIENT_L4_SOCKET_PARAMS)
        with unittest.mock.patch.object(analyzer, '_analyze', return_value=([], None)):
            result = analyzer.analyze(l7_client, IkeVersion.V2)
        self.assertIsInstance(result.target, AnalyzerTargetIke)


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
        return 5000  # ECDH groups × algorithm subsets; IKEv1 enumerates many EC2N variants
