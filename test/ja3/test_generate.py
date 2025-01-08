# -*- coding: utf-8 -*-

import time

from test.common.classes import TestThreadedServer, TestLoggerBase


from cryptodatahub.tls.algorithm import TlsECPointFormat
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import (
    TlsExtensionsClient,
    TlsExtensionECPointFormats,
    TlsExtensionEllipticCurves,
    TlsNamedCurve,
)
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello, TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ja3.generate import AnalyzerGenerate

from cryptolyzer.tls.client import L7ClientTls, TlsAlert
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration


class AnalyzerThread(TestThreadedServer):
    def __init__(self, configuration=None):
        self.l7_server = L7ServerTls('localhost', 0, configuration=configuration)
        super().__init__(self.l7_server)

        self.analyzer = AnalyzerGenerate()
        self.result = None

    def run(self):
        self.result = self.analyzer.analyze(self.l7_server)


class TestJA3Generate(TestLoggerBase):
    @staticmethod
    def get_result(hello_message):
        analyzer_thread = AnalyzerThread(TlsServerConfiguration(protocol_versions=[]))
        analyzer_thread.wait_for_server_listen()

        l7_client = L7ClientTls(
            analyzer_thread.l7_server.address,
            analyzer_thread.l7_server.l4_transfer.bind_port,
            ip=analyzer_thread.l7_server.ip
        )
        try:
            l7_client.do_tls_handshake(hello_message=hello_message)
        except TlsAlert as e:
            if e.description != TlsAlertDescription.PROTOCOL_VERSION:
                raise ValueError from e
        else:
            raise ValueError

        analyzer_thread.join()
        return analyzer_thread.result

    def test_error_no_connection(self):
        with self.assertRaisesRegex(NetworkError, 'connection to target cannot be established'):
            configuration = TlsServerConfiguration(protocol_versions=[])
            l7_server = L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.1), configuration=configuration)
            l7_server.init_connection()
            analyzer = AnalyzerGenerate()
            analyzer.analyze(l7_server)
            time.sleep(1)

    def test_tag_minimal(self):
        hello_message = TlsHandshakeClientHello([TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5])
        result = self.get_result(hello_message)
        self.assertEqual(result.target, '771,3,,,')
        self.assertEqual(
            self.log_stream.getvalue(),
            f'Client offers TLS client hello which JA3 tag is "{result.target}"\n'
        )

    def test_tag_one_element_lists(self):
        hello_message = TlsHandshakeClientHello(
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            cipher_suites=[TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5],
            extensions=TlsExtensionsClient([
                TlsExtensionECPointFormats([
                    TlsECPointFormat.UNCOMPRESSED,
                ]),
                TlsExtensionEllipticCurves([
                    TlsNamedCurve.SECT163K1,
                ]),
            ])
        )
        result = self.get_result(hello_message)
        self.assertEqual(result.target, '771,3,11-10,1,0')
        self.assertEqual(
            self.log_stream.getvalue(),
            f'Client offers TLS client hello which JA3 tag is "{result.target}"\n'
        )

    def test_tag_two_element_lists(self):
        hello_message = TlsHandshakeClientHello(
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            cipher_suites=[
                TlsCipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                TlsCipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA,
            ],
            extensions=TlsExtensionsClient([
                TlsExtensionECPointFormats([
                    TlsECPointFormat.ANSIX962_COMPRESSED_PRIME,
                    TlsECPointFormat.UNCOMPRESSED,
                ]),
                TlsExtensionEllipticCurves([
                    TlsNamedCurve.SECT163R2,
                    TlsNamedCurve.SECT163R1,
                ]),
            ])
        )
        result = self.get_result(hello_message)
        self.assertEqual(result.target, '771,13-12,11-10,3-2,1-0')
        self.assertEqual(
            self.log_stream.getvalue(),
            f'Client offers TLS client hello which JA3 tag is "{result.target}"\n'
        )
