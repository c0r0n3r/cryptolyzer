# -*- coding: utf-8 -*-

import unittest

from test.common.classes import TestThreaderServer

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import (
    TlsECPointFormat,
    TlsExtensionECPointFormats,
    TlsExtensionEllipticCurves,
    TlsNamedCurve,
)
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello, TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.ja3.generate import AnalyzerGenerate

from cryptolyzer.tls.client import L7ClientTls, TlsAlert
from cryptolyzer.tls.server import L7ServerTls


class AnalyzerThread(TestThreaderServer):
    def __init__(self):
        self.l7_server = L7ServerTls('localhost', 0)
        super(AnalyzerThread, self).__init__(self.l7_server)

        self.analyzer = AnalyzerGenerate()
        self.result = None

    def run(self):
        self.result = self.analyzer.analyze(self.l7_server)


class TestJA3Generate(unittest.TestCase):
    @staticmethod
    def get_result(hello_message):
        analyzer_thread = AnalyzerThread()
        analyzer_thread.wait_for_server_listen()

        l7_client = L7ClientTls(
            analyzer_thread.l7_server.address,
            analyzer_thread.l7_server.port,
            ip=analyzer_thread.l7_server.ip
        )
        try:
            l7_client.do_tls_handshake(hello_message=hello_message)
        except TlsAlert as e:
            if e.description != TlsAlertDescription.CLOSE_NOTIFY:
                raise ValueError
        else:
            raise ValueError

        analyzer_thread.join()
        return analyzer_thread.result

    def test_tag_minimal(self):
        hello_message = TlsHandshakeClientHello([TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5])
        result = self.get_result(hello_message)
        self.assertEqual(result.target, '771,3,,,')

    def test_tag_one_element_lists(self):
        hello_message = TlsHandshakeClientHello(
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            cipher_suites=[TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5],
            extensions=[
                TlsExtensionECPointFormats([TlsECPointFormat.UNCOMPRESSED]),
                TlsExtensionEllipticCurves([TlsNamedCurve.SECT163K1]),
            ]
        )
        result = self.get_result(hello_message)
        self.assertEqual(result.target, '771,3,11-10,1,0')

    def test_tag_two_element_lists(self):
        hello_message = TlsHandshakeClientHello(
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            cipher_suites=[
                TlsCipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                TlsCipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA,
            ],
            extensions=[
                TlsExtensionECPointFormats([TlsECPointFormat.ANSIX962_COMPRESSED_PRIME, TlsECPointFormat.UNCOMPRESSED]),
                TlsExtensionEllipticCurves([TlsNamedCurve.SECT163R2, TlsNamedCurve.SECT163R1]),
            ]
        )
        result = self.get_result(hello_message)
        self.assertEqual(result.target, '771,13-12,11-10,3-2,1-0')
