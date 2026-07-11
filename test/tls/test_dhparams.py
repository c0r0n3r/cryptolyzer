# SPDX-License-Identifier: MPL-2.0

from unittest import mock

from test.common.classes import OFFLINE_CLIENT_L4_SOCKET_PARAMS, OFFLINE_L4_SOCKET_PARAMS, TestMainBase
from test.common.markers import live_server

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionsBase, TlsNamedCurve
from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptodatahub.common.parameter import DHParameterNumbers

from cryptolyzer.common.dhparam import (
    DHParameter,
    DHPublicKey,
    DHPublicNumbers,
    DHParamWellKnown,
)

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.dhparams import AnalyzerDHParams
from cryptolyzer.tls.exception import TlsAlert, UnexpectedAlertError
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration

from cryptolyzer.__main__ import main

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsDHParams(TestTlsCases.TestTlsBase, TestMainBase):  # pylint: disable=too-many-public-methods
    @classmethod
    def _get_main_func(cls):
        return main

    @staticmethod
    def get_result(
            host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(TlsExtensionsBase, 'get_item_by_type', side_effect=KeyError)
    def test_error_missing_key_share_extension(self, _):
        threaded_server = self.create_server()
        result = self.get_result(
            'localhost', threaded_server.l7_server.l4_transfer.bind_port, TlsProtocolVersion(TlsVersion.TLS1_3)
        )
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    )
    def test_error_tls_alert_protocol_version(self, _):
        result = self.get_result('localhost', 0, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
    )
    def test_error_tls_alert_unexpected(self, _):
        with self.assertRaises(UnexpectedAlertError):
            self.get_result('localhost', 0, TlsProtocolVersion(TlsVersion.TLS1_2))

    @mock.patch.object(AnalyzerDHParams, '_get_server_messages')
    def test_error_missing_key_share_extension_in_server_hello(self, get_server_messages):
        server_hello = mock.Mock()
        server_hello.extensions.get_item_by_type.side_effect = KeyError
        get_server_messages.return_value = {TlsHandshakeType.SERVER_HELLO: server_hello}

        result = self.get_result('localhost', 0, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    @mock.patch.object(AnalyzerDHParams, '_get_public_key', side_effect=StopIteration)
    def test_error_no_respoinse_during_key_reuse_check(self, _):
        threaded_server = self.create_server()
        result = self.get_result(
            'localhost', threaded_server.l7_server.l4_transfer.bind_port, TlsProtocolVersion(TlsVersion.TLS1_3)
        )
        self.assertEqual(result.key_reuse, None)

    def test_tls_1_3_key_reuse(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_AES_128_GCM_SHA256],
            curves=[TlsNamedCurve.FFDHE2048, TlsNamedCurve.FFDHE3072, TlsNamedCurve.FFDHE4096],
        ))
        result = self.get_result(
            'localhost', threaded_server.l7_server.l4_transfer.bind_port, TlsProtocolVersion(TlsVersion.TLS1_3)
        )
        self.assertEqual(
            result.groups, [TlsNamedCurve.FFDHE2048, TlsNamedCurve.FFDHE3072, TlsNamedCurve.FFDHE4096]
        )
        self.assertIsNone(result.dhparam)
        self.assertFalse(result.key_reuse)

    @live_server
    @mock.patch.object(
        AnalyzerDHParams, '_get_public_key', side_effect=StopIteration
    )
    def test_error_key_reuse_undeterminable(self, _):
        result = self.get_result('lamar.edu', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [TlsNamedCurve.FFDHE2048, TlsNamedCurve.FFDHE3072, TlsNamedCurve.FFDHE4096])
        self.assertIsNone(result.dhparam)
        self.assertEqual(result.key_reuse, None)

        result = self.get_result('documentfreedom.org', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ])
        self.assertEqual(result.dhparam, None)
        self.assertEqual(result.key_reuse, None)

    @live_server
    @mock.patch.object(
        TlsExtensionsBase, 'get_item_by_type', side_effect=KeyError
    )
    def test_last_key_share_extension(self, _):
        result = self.get_result('lamar.edu', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [])
        self.assertIsNotNone(result.dhparam, None)

        result = self.get_result('gimp.org', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    def test_size(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA],
            dh_param=DHParameterNumbers((1 << 479) + 3, 2),
        ))

        def _mock_check_prime(self):
            self.prime = True
            self.safe_prime = True

        with mock.patch.object(DHParameter, '_check_prime', _mock_check_prime):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 480)
        self.assertEqual(result.dhparam.prime, True)
        self.assertEqual(result.dhparam.safe_prime, True)
        self.assertEqual(result.dhparam.well_known, None)
        self.assertFalse(result.key_reuse)
        self.assertEqual(
            self.get_log_lines(), [
                'Server offers 480-bit custom DH public parameter (TLS 1.2)',
            ]
        )

    def test_prime(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA],
            dh_param=DHParameterNumbers((1 << 2047) + 3, 2),
        ))

        def _mock_check_prime(self):
            self.prime = False
            self.safe_prime = False

        with mock.patch.object(DHParameter, '_check_prime', _mock_check_prime):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 2048)
        self.assertEqual(result.dhparam.prime, False)
        self.assertEqual(result.dhparam.safe_prime, False)
        self.assertEqual(result.dhparam.well_known, None)
        self.assertFalse(result.key_reuse)

    def test_safe_prime(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA],
            dh_param=DHParameterNumbers((1 << 2047) + 3, 2),
        ))

        def _mock_check_prime(self):
            self.prime = True
            self.safe_prime = False

        with mock.patch.object(DHParameter, '_check_prime', _mock_check_prime):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 2048)
        self.assertEqual(result.dhparam.prime, True)
        self.assertEqual(result.dhparam.safe_prime, False)
        self.assertEqual(result.dhparam.well_known, None)
        self.assertFalse(result.key_reuse)

    def test_well_known_prime(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA],
            dh_param=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam.key_size.value, 2048)
        self.assertEqual(result.dhparam.prime, True)
        self.assertEqual(result.dhparam.safe_prime, True)
        self.assertEqual(result.dhparam.well_known, DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP)
        self.assertFalse(result.key_reuse)

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, OFFLINE_L4_SOCKET_PARAMS),
        )
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)

    def test_no_dhe_support(self):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)
        self.assertEqual(result.key_reuse, None)
        self.assertFalse(self.log_stream.getvalue(), '')

    def test_tls_early_version(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA],
            dh_param=DHParameterNumbers((1 << 479) + 3, 2),
        ))
        result = self.get_result(
            'localhost', threaded_server.l7_server.l4_transfer.bind_port,
            TlsProtocolVersion(TlsVersion.TLS1),
        )
        self.assertEqual(result.groups, [])
        self.assertNotEqual(result.dhparam, None)
        self.assertFalse(result.key_reuse)

    @live_server
    def test_tls_1_2_rfc_7919_support(self):
        result = self.get_result('lamar.edu', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [TlsNamedCurve.FFDHE2048, TlsNamedCurve.FFDHE3072, TlsNamedCurve.FFDHE4096])
        self.assertEqual(result.dhparam, None)
        self.assertEqual(
            self.get_log_lines(), [
                'Server offers 2048-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
                'Server offers 3072-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
                'Server offers 4096-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
            ]
        )

    @live_server
    @mock.patch.object(
        AnalyzerDHParams, '_get_public_key_tls_1_x',
        return_value=DHPublicKey(
            DHPublicNumbers(
                0, DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.parameter_numbers
            ),
            4096
        )
    )
    def test_tls_1_x_key_reuse(self, _):
        result = self.get_result('lamar.edu', 443, TlsProtocolVersion(TlsVersion.TLS1_2))
        self.assertEqual(result.groups, [])
        self.assertEqual(
            result.dhparam.parameter_numbers,
            DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP.value.parameter_numbers,
        )
        self.assertTrue(result.key_reuse)
        log_lines = self.get_log_lines()
        self.assertEqual(
            log_lines, [
                'Server offers 4096-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
                'Server offers 4096-bit Finite Field Diffie-Hellman group (RFC 7919) (TLS 1.2)',
            ]
        )

    @live_server
    def test_tls_1_3(self):
        result = self.get_result('www.cloudflare.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [])
        self.assertEqual(result.dhparam, None)
        self.assertFalse(result.key_reuse)

        result = self.get_result('documentfreedom.org', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        self.assertEqual(result.groups, [
            TlsNamedCurve.FFDHE2048,
            TlsNamedCurve.FFDHE3072,
            TlsNamedCurve.FFDHE4096,
            TlsNamedCurve.FFDHE6144,
            TlsNamedCurve.FFDHE8192,
        ])
        self.assertEqual(result.dhparam, None)
        self.assertFalse(result.key_reuse)
        self.assertEqual(
            self.log_stream.getvalue(),
            'Server offers FFDHE public parameter with size 2048-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 3072-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 4096-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 6144-bit (TLS 1.3)\n'
            'Server offers FFDHE public parameter with size 8192-bit (TLS 1.3)\n'
        )

    def test_json(self):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result)
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result)

    def test_output(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            '127.0.0.1', 0,
            OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(
                cipher_suites=[TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
                dh_param=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
            )
        ))
        threaded_server.wait_for_server_listen()
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'dhparams', '127.0.0.1',
            threaded_server.l7_server.l4_transfer.bind_port, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
