#!/usr/bin/env python
# -*- coding: utf-8 -*-

import attr

from cryptoparser.tls.extension import (
    TlsExtensionExtendedMasterSecret,
)
from cryptoparser.tls.subprotocol import TlsHandshakeType

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert


@attr.s  # pylint: disable=too-few-public-methods
class AnalyzerResultExtensions(AnalyzerResultTls):
    extended_master_secret_supported = attr.ib(validator=attr.validators.instance_of(bool))


class AnalyzerExtensions(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'extensions'

    @classmethod
    def get_help(cls):
        return 'Check which extensions supported by the server(s)'

    @staticmethod
    def _analyze_symmetric_extension(analyzable, protocol_version, client_extension):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([protocol_version, ], analyzable.address)
        client_hello.extensions.append(client_extension)

        try:
            server_messages = analyzable.do_tls_handshake(client_hello)
        except (TlsAlert, NetworkError):
            return False

        try:
            extensions = server_messages[TlsHandshakeType.SERVER_HELLO].extensions
            extensions.get_item_by_type(client_extension.extension_type)
        except KeyError:
            return False

        return True

    @staticmethod
    def _analyze_extended_master_secret(analyzable, protocol_version):
        return AnalyzerExtensions._analyze_symmetric_extension(
            analyzable, protocol_version, TlsExtensionExtendedMasterSecret()
        )

    def analyze(self, analyzable, protocol_version):
        extended_master_secret_supported = self._analyze_extended_master_secret(analyzable, protocol_version)

        return AnalyzerResultExtensions(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            extended_master_secret_supported,
        )
