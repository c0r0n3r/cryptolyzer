#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.extension import TlsExtensionType, TlsExtensionApplicationLayerProtocolNegotiation
from cryptoparser.tls.extension import TlsProtocolName, TlsProtocolNameList
from cryptoparser.tls.extension import TlsExtensionRenegotiationInfo, TlsExtensionSessionTicket
from cryptoparser.tls.extension import TlsExtensionGrease, TLS_EXTENSION_TYPES_GREASE
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsHandshakeServerHello

from cryptolyzer.common.analyzer import AnalyzerTlsBase, AnalyzerResultBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert


class AnalyzerResultExtensions(AnalyzerResultBase):  # pylint: disable=too-few-public-methods
    def __init__(self, application_layer_protocols, renegotiation_supported, session_ticket_supported, ignores_unknown_types):
        self.application_layer_protocols = application_layer_protocols
        self.renegotiation_supported = renegotiation_supported
        self.session_ticket_supported = session_ticket_supported
        self.ignores_unknown_types = ignores_unknown_types


class AnalyzerExtensions(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'extensions'

    @classmethod
    def get_help(cls):
        return 'Check which extensions supported by the server(s)'

    def _analyze_alpn(self, l7_client, protocol_version):
        supported_protocol_names = set()
        remaining_protocol_names = set(TlsProtocolName)
        client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host)

        while True:
            client_hello.extensions.append(TlsExtensionApplicationLayerProtocolNegotiation(remaining_protocol_names))
           
            try:
                server_messages = l7_client.do_tls_handshake(client_hello, client_hello.protocol_version)
                alpn_extensions = list(filter(
                    lambda extension: extension.extension_type == TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                    server_messages[TlsHandshakeType.SERVER_HELLO].extensions
                ))
            except (TlsAlert, NetworkError) as e:
                break
           
            if not alpn_extensions:
                break

            protocol_names = {protocol_name for protocol_name in alpn_extensions[0].protocol_names}
            already_known_protocol_names = supported_protocol_names & protocol_names
            supported_protocol_names.update(protocol_names)
            remaining_protocol_names.difference_update(protocol_names)

            if already_known_protocol_names:
                break

            del client_hello.extensions[-1]

        return supported_protocol_names

    def _analyze_symmetric_extension(self, l7_client, protocol_version, client_extension):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host)
        client_hello.extensions.append(client_extension)
        
        try:
            server_messages = l7_client.do_tls_handshake(client_hello, client_hello.protocol_version)
            renegotiation_info_extensions = list(filter(
                lambda server_extension: server_extension.extension_type == client_extension.extension_type,
                server_messages[TlsHandshakeType.SERVER_HELLO].extensions
            ))
        except (TlsAlert, NetworkError) as e:
            return False

        return len(renegotiation_info_extensions) == 1

    def _analyze_renegotiation(self, l7_client, protocol_version):
        return self._analyze_symmetric_extension(l7_client, protocol_version, TlsExtensionRenegotiationInfo())

    def _analyze_session_ticket(self, l7_client, protocol_version):
        return self._analyze_symmetric_extension(l7_client, protocol_version, TlsExtensionSessionTicket())

    def _analyze_unknown_types(self, l7_client, protocol_version):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host)
        for extension_type in TLS_EXTENSION_TYPES_GREASE:
            client_hello.extensions.append(TlsExtensionGrease(extension_type))

        try:
            l7_client.do_tls_handshake(client_hello, client_hello.protocol_version)
        except (TlsAlert, NetworkError) as e:
            return False

        return True

    def analyze(self, l7_client, protocol_version):
        supported_protocol_names = self._analyze_alpn(l7_client, protocol_version)
        renegotiation_supported = self._analyze_renegotiation(l7_client, protocol_version)
        session_ticket_supported = self._analyze_session_ticket(l7_client, protocol_version)
        ignores_unknown_types = self._analyze_unknown_types(l7_client, protocol_version)

        return AnalyzerResultExtensions(
            list(supported_protocol_names),
            renegotiation_supported,
            session_ticket_supported,
            ignores_unknown_types
        )
