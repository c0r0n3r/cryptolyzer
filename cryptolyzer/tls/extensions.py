#!/usr/bin/env python
# -*- coding: utf-8 -*-

import attr
import six

from cryptoparser.tls.algorithm import TlsProtocolName
from cryptoparser.tls.extension import (
    TlsExtensionApplicationLayerProtocolNegotiation,
    TlsExtensionEncryptThenMAC,
    TlsExtensionExtendedMasterSecret,
    TlsExtensionSessionTicket,
    TlsExtensionType,
)
from cryptoparser.tls.subprotocol import TlsHandshakeType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloBlockCipherModeCBC,
    TlsAlert,
)


@attr.s  # pylint: disable=too-few-public-methods
class AnalyzerResultExtensions(AnalyzerResultTls):
    application_layer_protocols = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(TlsProtocolName))
    )
    session_ticket_supported = attr.ib(validator=attr.validators.instance_of(bool))
    extended_master_secret_supported = attr.ib(validator=attr.validators.instance_of(bool))
    encrypt_then_mac_supported = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool)),
        metadata={'human_readable_name': 'Encrypt then MAC Supported'}
    )


class AnalyzerExtensions(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'extensions'

    @classmethod
    def get_help(cls):
        return 'Check which extensions supported by the server(s)'

    @classmethod
    def _analyze_alpn(cls, analyzable, protocol_version):
        supported_protocol_names = []
        remaining_protocol_names = set(TlsProtocolName)

        while remaining_protocol_names:
            client_hello = cls._get_client_hello(
                analyzable, protocol_version, TlsExtensionApplicationLayerProtocolNegotiation(remaining_protocol_names)
            )

            try:
                server_messages = analyzable.do_tls_handshake(client_hello)
                alpn_extensions = list(filter(
                    lambda extension:
                    extension.extension_type == TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                    server_messages[TlsHandshakeType.SERVER_HELLO].extensions
                ))
            except (TlsAlert, NetworkError):
                break

            if not alpn_extensions:
                break

            protocol_name = alpn_extensions[0].protocol_names[0]
            already_known_protocol_names = protocol_name in supported_protocol_names
            supported_protocol_names.append(protocol_name)

            if already_known_protocol_names:
                break

            remaining_protocol_names.remove(protocol_name)

        return supported_protocol_names

    @classmethod
    def _get_client_hello(cls, analyzable, protocol_version, extension=None):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([protocol_version, ], analyzable.address)

        if extension:
            client_hello.extensions.append(extension)

        return client_hello

    @classmethod
    def _get_server_messsages(cls, analyzable, client_hello):
        try:
            server_messages = analyzable.do_tls_handshake(
                client_hello, last_handshake_message_type=TlsHandshakeType.SERVER_HELLO
            )
        except (TlsAlert, NetworkError) as e:
            six.raise_from(KeyError, e)

        return server_messages

    @classmethod
    def _get_symmetric_extension(cls, analyzable, client_hello, extension_type):
        server_messages = cls._get_server_messsages(analyzable, client_hello)

        extensions = server_messages[TlsHandshakeType.SERVER_HELLO].extensions
        extension = extensions.get_item_by_type(extension_type)

        return extension

    @classmethod
    def _analyze_symmetric_extension(cls, analyzable, client_hello, extension_type):
        try:
            result = cls._get_symmetric_extension(analyzable, client_hello, extension_type) is not None
        except KeyError:
            return False

        return result

    @classmethod
    def _analyze_extended_master_secret(cls, analyzable, protocol_version):
        client_hello = cls._get_client_hello(analyzable, protocol_version, TlsExtensionExtendedMasterSecret())
        return cls._analyze_symmetric_extension(
            analyzable, client_hello, TlsExtensionType.EXTENDED_MASTER_SECRET,
        )

    @classmethod
    def _analyze_session_ticket(cls, analyzable, protocol_version):
        client_hello = cls._get_client_hello(analyzable, protocol_version, TlsExtensionSessionTicket())
        return AnalyzerExtensions._analyze_symmetric_extension(
            analyzable, client_hello, TlsExtensionType.SESSION_TICKET,
        )

    @classmethod
    def _analyze_encrypt_than_mac(cls, analyzable, protocol_version):
        if protocol_version < TlsProtocolVersionFinal(TlsVersion.TLS1_2):
            return None

        client_hello = TlsHandshakeClientHelloBlockCipherModeCBC(protocol_version, analyzable.address)
        client_hello.extensions.append(TlsExtensionEncryptThenMAC())
        try:
            server_messages = cls._get_server_messsages(analyzable, client_hello)
        except KeyError:
            return None

        try:
            extensions = server_messages[TlsHandshakeType.SERVER_HELLO].extensions
            extensions.get_item_by_type(TlsExtensionType.ENCRYPT_THEN_MAC)
        except KeyError:
            return False

        return True

    def analyze(self, analyzable, protocol_version):
        supported_protocol_names = self._analyze_alpn(analyzable, protocol_version)
        session_ticket_supported = self._analyze_session_ticket(analyzable, protocol_version)
        extended_master_secret_supported = self._analyze_extended_master_secret(analyzable, protocol_version)
        encrypt_then_mac_supported = self._analyze_encrypt_than_mac(analyzable, protocol_version)

        return AnalyzerResultExtensions(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            supported_protocol_names,
            session_ticket_supported,
            extended_master_secret_supported,
            encrypt_then_mac_supported,
        )
