#!/usr/bin/env python
# -*- coding: utf-8 -*-

import attr
import six

from cryptodatahub.tls.algorithm import TlsECPointFormat, TlsNextProtocolName, TlsProtocolName

from cryptoparser.tls.extension import (
    TlsExtensionApplicationLayerProtocolNegotiation,
    TlsExtensionEncryptThenMAC,
    TlsExtensionExtendedMasterSecret,
    TlsExtensionNextProtocolNegotiationClient,
    TlsExtensionRecordSizeLimit,
    TlsExtensionRenegotiationInfo,
    TlsExtensionSessionTicket,
    TlsExtensionType,
)
from cryptoparser.tls.subprotocol import (
    TlsCompressionMethodVector,
    TlsCompressionMethod,
    TlsHandshakeType,
    TlsSessionIdVector,
)
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloBlockCipherModeCBC,
    TlsHandshakeClientHelloKeyExchangeECDHx,
    TlsAlert,
    TlsAlertDescription,
)


@attr.s
class AnalyzerResultExtensions(AnalyzerResultTls):  # pylint: disable=too-many-instance-attributes
    next_protocols = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(TlsNextProtocolName))
    )
    application_layer_protocols = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(TlsProtocolName))
    )
    compression_methods = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsCompressionMethod))
    )
    clock_is_accurate = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)))
    renegotiation_supported = attr.ib(validator=attr.validators.instance_of(bool))
    session_cache_supported = attr.ib(validator=attr.validators.instance_of(bool))
    session_ticket_supported = attr.ib(validator=attr.validators.instance_of(bool))
    extended_master_secret_supported = attr.ib(validator=attr.validators.instance_of(bool))
    encrypt_then_mac_supported = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool)),
        metadata={'human_readable_name': 'Encrypt then MAC Supported'}
    )
    ec_point_formats = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsECPointFormat)),
        metadata={'human_readable_name': 'EC Point Formats'}
    )
    record_size_limit_handled = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)))
    record_size_limit_server = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(six.integer_types))
    )


class AnalyzerExtensions(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'extensions'

    @classmethod
    def get_help(cls):
        return 'Check which extensions supported by the server(s)'

    @classmethod
    def _analyze_npn(cls, analyzable, protocol_version):
        client_hello = cls._get_client_hello(analyzable, protocol_version, TlsExtensionNextProtocolNegotiationClient())
        try:
            extension = AnalyzerExtensions._get_symmetric_extension(
                analyzable, client_hello, TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION
            )
        except KeyError:
            return []

        protocol_names = list(extension.protocol_names)
        if protocol_names:
            LogSingleton().log(level=60, msg=six.u('Server offers next protocol(s) %s') % (
                ', '.join(['"{}"'.format(protocol_name.value.code) for protocol_name in protocol_names]),
            ))

        return protocol_names

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

            LogSingleton().log(level=60, msg=six.u('Server offers application layer protocol "%s"') % (
                protocol_name.value.code,
            ))

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
        extended_master_secret_supported = cls._analyze_symmetric_extension(
            analyzable, client_hello, TlsExtensionType.EXTENDED_MASTER_SECRET,
        )
        if extended_master_secret_supported:
            LogSingleton().log(level=60, msg=six.u('Server offers extended master secret'))
        else:
            LogSingleton().log(level=60, msg=six.u('Server does not offer extended master secret'))
        return extended_master_secret_supported

    @classmethod
    def _analyze_compression_methods(cls, analyzable, protocol_version):
        supported_compression_methods = set()
        client_hello = cls._get_client_hello(analyzable, protocol_version)

        for compression_method in TlsCompressionMethod:
            if compression_method == TlsCompressionMethod.NULL:
                offered_compression_methods = [TlsCompressionMethod.NULL, ]
            else:
                offered_compression_methods = [compression_method, TlsCompressionMethod.NULL, ]
            client_hello.compression_methods = TlsCompressionMethodVector(offered_compression_methods)

            try:
                server_messages = analyzable.do_tls_handshake(client_hello)
            except (TlsAlert, NetworkError):
                break

            supported_compression_method = server_messages[TlsHandshakeType.SERVER_HELLO].compression_method

            supported_compression_methods.add(supported_compression_method)

        if supported_compression_methods:
            LogSingleton().log(level=60, msg=six.u('Server offers compression method(s) %s') % (
                ', '.join([
                    '"{}"'.format(compression_method.name)
                    for compression_method in supported_compression_methods
                ]),
            ))

        return supported_compression_methods

    @classmethod
    def _analyze_clock_skew(cls, analyzable, protocol_version):
        client_hello = cls._get_client_hello(analyzable, protocol_version)
        try:
            server_messages = analyzable.do_tls_handshake(client_hello)
        except (TlsAlert, NetworkError):
            return None

        clock_skew = (
            int(client_hello.random.time.strftime('%s')) -
            int(server_messages[TlsHandshakeType.SERVER_HELLO].random.time.strftime('%s'))
        )
        clock_is_accurate = -15 < clock_skew < 15

        if clock_is_accurate:
            LogSingleton().log(level=60, msg=six.u('Server offers accurate clock'))
        else:
            LogSingleton().log(level=60, msg=six.u('Server does not offer accurate clock'))

        return clock_is_accurate

    @classmethod
    def _analyze_renegotiation(cls, analyzable, protocol_version):
        renegotiation_supported = None
        client_hello = cls._get_client_hello(analyzable, protocol_version)
        client_hello.empty_renegotiation_info_scsv = True
        if AnalyzerExtensions._analyze_symmetric_extension(
                analyzable, client_hello, TlsExtensionType.RENEGOTIATION_INFO):
            renegotiation_supported = True

        if renegotiation_supported is None:
            client_hello = cls._get_client_hello(analyzable, protocol_version, TlsExtensionRenegotiationInfo())
            renegotiation_supported = AnalyzerExtensions._analyze_symmetric_extension(
                analyzable, client_hello, TlsExtensionType.RENEGOTIATION_INFO
            )

        if renegotiation_supported:
            LogSingleton().log(level=60, msg=six.u('Server offers renegotiation'))
        else:
            LogSingleton().log(level=60, msg=six.u('Server does not offer renegotiation'))

        return renegotiation_supported

    @classmethod
    def _analyze_session_cache(cls, analyzable, protocol_version):
        session_cache_supported = None
        client_hello = cls._get_client_hello(analyzable, protocol_version)
        client_hello.session_id = TlsSessionIdVector(list(range(32)))
        try:
            server_messages = analyzable.do_tls_handshake(client_hello)
        except (TlsAlert, NetworkError):
            session_cache_supported = False

        if session_cache_supported is None:
            session_id = server_messages[TlsHandshakeType.SERVER_HELLO].session_id
            session_cache_supported = session_id != TlsSessionIdVector([])

        if session_cache_supported:
            LogSingleton().log(level=60, msg=six.u('Server offers session cache'))
        else:
            LogSingleton().log(level=60, msg=six.u('Server does not offer session cache'))

        return session_cache_supported

    @classmethod
    def _analyze_session_ticket(cls, analyzable, protocol_version):
        client_hello = cls._get_client_hello(analyzable, protocol_version, TlsExtensionSessionTicket())
        session_ticket_supported = AnalyzerExtensions._analyze_symmetric_extension(
            analyzable, client_hello, TlsExtensionType.SESSION_TICKET,
        )

        if session_ticket_supported:
            LogSingleton().log(level=60, msg=six.u('Server offers session ticket'))
        else:
            LogSingleton().log(level=60, msg=six.u('Server does not offer session ticket'))

        return session_ticket_supported

    @classmethod
    def _analyze_encrypt_than_mac(cls, analyzable, protocol_version):
        if protocol_version < TlsProtocolVersion(TlsVersion.TLS1_2):
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
            LogSingleton().log(level=60, msg=six.u('Server does not offer encrypt then MAC'))
            return False

        LogSingleton().log(level=60, msg=six.u('Server offers encrypt then MAC'))
        return True

    @classmethod
    def _analyze_ec_point_formats(cls, analyzable, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(protocol_version, analyzable.address)
        try:
            extension = AnalyzerExtensions._get_symmetric_extension(
                analyzable, client_hello, TlsExtensionType.EC_POINT_FORMATS
            )
            point_formats = extension.point_formats
        except KeyError:
            point_formats = [TlsECPointFormat.UNCOMPRESSED, ]

        LogSingleton().log(level=60, msg=six.u('Server offers point format(s) %s') % (
            ', '.join(['"{}"'.format(point_format.name) for point_format in point_formats]),
        ))

        return point_formats

    @classmethod
    def _analyze_record_size_limit(cls, analyzable, protocol_version):
        client_hello = cls._get_client_hello(analyzable, protocol_version, TlsExtensionRecordSizeLimit(1))

        handled = False
        try:
            server_messages = analyzable.do_tls_handshake(client_hello)
        except TlsAlert as e:
            if e.description == TlsAlertDescription.RECORD_OVERFLOW:
                handled = True
        except NetworkError:
            pass

        if not handled:
            LogSingleton().log(level=60, msg=six.u('Server does not handle record size limit'))
            return False, None

        LogSingleton().log(level=60, msg=six.u('Server handles record size limit'))

        client_hello = cls._get_client_hello(analyzable, protocol_version)
        try:
            server_messages = analyzable.do_tls_handshake(client_hello)
        except (TlsAlert, NetworkError):
            return True, None

        try:
            extensions = server_messages[TlsHandshakeType.SERVER_HELLO].extensions
            extension = extensions.get_item_by_type(TlsExtensionType.RECORD_SIZE_LIMIT)
        except KeyError:
            LogSingleton().log(level=60, msg=six.u('Server does not require record size limit'))
            return True, None

        LogSingleton().log(level=60, msg=six.u('Server requires record size limit %d' % (extension.record_size_limit)))

        return True, extension.record_size_limit

    def analyze(self, analyzable, protocol_version):
        supported_protocol_names = self._analyze_alpn(analyzable, protocol_version)
        supported_next_protocol_names = self._analyze_npn(analyzable, protocol_version)
        supported_compression_methods = self._analyze_compression_methods(analyzable, protocol_version)
        clock_is_accurate = self._analyze_clock_skew(analyzable, protocol_version)
        renegotiation_supported = self._analyze_renegotiation(analyzable, protocol_version)
        session_cache_supported = self._analyze_session_cache(analyzable, protocol_version)
        session_ticket_supported = self._analyze_session_ticket(analyzable, protocol_version)
        extended_master_secret_supported = self._analyze_extended_master_secret(analyzable, protocol_version)
        encrypt_then_mac_supported = self._analyze_encrypt_than_mac(analyzable, protocol_version)
        ec_point_formats = self._analyze_ec_point_formats(analyzable, protocol_version)
        record_size_limit_handled, record_size_limit_server = self._analyze_record_size_limit(
            analyzable, protocol_version
        )

        return AnalyzerResultExtensions(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            supported_next_protocol_names,
            supported_protocol_names,
            supported_compression_methods,
            clock_is_accurate,
            renegotiation_supported,
            session_cache_supported,
            session_ticket_supported,
            extended_master_secret_supported,
            encrypt_then_mac_supported,
            ec_point_formats,
            record_size_limit_handled,
            record_size_limit_server,
        )
