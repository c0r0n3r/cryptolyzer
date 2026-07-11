# SPDX-License-Identifier: MPL-2.0
# pylint: disable=too-many-lines

import abc
import attr


from cryptodatahub.common.algorithm import BlockCipher, KeyExchange
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.parameter import DHParameterNumbers, DHParamWellKnown
from cryptodatahub.tls.algorithm import (
    TlsNamedCurve,
    TlsNextProtocolName,
    TlsProtocolName,
    TlsSignatureAndHashAlgorithm,
)

from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.common.parse import ComposerBinary

from cryptoparser.common.x509 import SignedCertificateTimestampList

from cryptoparser.tls.extension import (
    TlsExtensionApplicationLayerProtocolNegotiation,
    TlsExtensionEncryptThenMAC,
    TlsExtensionExtendedMasterSecret,
    TlsExtensionKeyShareClientHelloRetry,
    TlsExtensionKeyShareServer,
    TlsExtensionNextProtocolNegotiationServer,
    TlsExtensionRenegotiationInfo,
    TlsExtensionSessionTicket,
    TlsExtensionSignedCertificateTimestampServer,
    TlsExtensionType,
    TlsExtensionSupportedVersionsServer,
    TlsNextProtocolNameList,
    TlsProtocolNameList,
)
from cryptoparser.tls.ldap import (
    LDAPResultCode,
    LDAPExtendedRequestStartTLS,
    LDAPExtendedResponseStartTLS,
)
from cryptoparser.tls.mysql import (
    MySQLCapability,
    MySQLHandshakeSslRequest,
    MySQLHandshakeV10,
    MySQLRecord,
    MySQLVersion,
)
from cryptoparser.tls.openvpn import (
    OpenVpnPacketHardResetServerV2,
    OpenVpnOpCode,
)
from cryptoparser.tls.postgresql import SslRequest, Sync
from cryptoparser.tls.rdp import (
    TPKT,
    COTPConnectionConfirm,
    COTPConnectionRequest,
    RDPProtocol,
    RDPNegotiationRequest,
    RDPNegotiationResponse,
)

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import (
    SslErrorMessage,
    SslErrorType,
    SslHandshakeServerHello,
    SslMessageBase,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsCertificate,
    TlsCertificates,
    TlsCipherSuite,
    TlsClientCertificateType,
    TlsContentType,
    TlsDistinguishedName,
    TlsECCurveType,
    TlsHandshakeCertificateRequest,
    TlsHandshakeServerCertificate,
    TlsHandshakeServerHelloDone,
    TlsHandshakeServerHello,
    TlsHandshakeServerKeyExchange,
    TlsHandshakeType,
    TlsSessionIdVector,
    TlsSubprotocolMessageParser,
)
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.__setup__ import __title__, __version__
from cryptolyzer.common.dhparam import (
    TlsDHParamVector,
    get_dh_ephemeral_key_forged,
    get_ecdh_ephemeral_key_forged,
    int_to_bytes,
)
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.common.application import L7ServerBase, L7ServerHandshakeBase, L7ServerConfigurationBase
from cryptolyzer.common.transfer import L4ServerTCP, L4ServerUDP
from cryptolyzer.common.utils import buffer_flush, buffer_is_plain_text

from cryptolyzer.tls.application import L7OpenVpnBase
from cryptolyzer.tls.client import key_share_entry_from_named_curve


@attr.s
class TlsServerConfiguration(L7ServerConfigurationBase):  # pylint: disable=too-many-instance-attributes
    min_protocol_version = attr.ib(
        default=TlsProtocolVersion(TlsVersion.TLS1),
        validator=attr.validators.instance_of(TlsProtocolVersion)
    )
    max_protocol_version = attr.ib(
        default=TlsProtocolVersion(TlsVersion.TLS1_3),
        validator=attr.validators.instance_of(TlsProtocolVersion)
    )
    cipher_suites = attr.ib(
        default=list(filter(lambda cipher_suite: cipher_suite.value.bulk_cipher == BlockCipher.RC2, TlsCipherSuite)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsCipherSuite))
    )
    fallback_to_ssl = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    close_on_error = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    certificates = attr.ib(
        default=[],
        validator=attr.validators.deep_iterable(attr.validators.instance_of(bytes))
    )
    certificate_authorities = attr.ib(
        default=None,
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(bytes))
        )
    )
    dh_param = attr.ib(
        default=None,
        validator=attr.validators.optional(
            attr.validators.or_(
                attr.validators.instance_of(DHParamWellKnown),
                attr.validators.instance_of(DHParameterNumbers)
            )
        )
    )
    curves = attr.ib(
        default=[],
        validator=attr.validators.deep_iterable(attr.validators.in_(TlsNamedCurve))
    )
    encrypt_then_mac_supported = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    extended_master_secret_supported = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    renegotiation_supported = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    session_cache_supported = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    session_ticket_supported = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    next_protocols = attr.ib(
        default=None,
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.in_(TlsNextProtocolName))
        )
    )
    application_layer_protocols = attr.ib(
        default=None,
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.in_(TlsProtocolName))
        )
    )
    signed_certificate_timestamps_supported = attr.ib(default=False, validator=attr.validators.instance_of(bool))

    def __attrs_post_init__(self):
        if self.min_protocol_version > self.max_protocol_version:
            raise ValueError(
                'min_protocol_version must not be greater than max_protocol_version'
            )

        if self.max_protocol_version >= TlsProtocolVersion(TlsVersion.TLS1):
            for cipher_suite in self.cipher_suites:
                if TlsProtocolVersion(cipher_suite.value.last_version) < self.min_protocol_version:
                    raise ValueError(
                        f'cipher suite {cipher_suite.value.iana_name} maximum version is below min_protocol_version'
                    )
                if TlsProtocolVersion(cipher_suite.value.initial_version) > self.max_protocol_version:
                    raise ValueError(
                        f'cipher suite {cipher_suite.value.iana_name} minimum version is above max_protocol_version'
                    )

        dh_cipher_suites = [
            cs for cs in self.cipher_suites
            if cs.value.key_exchange in (KeyExchange.DHE, KeyExchange.ADH)
        ]
        if self.dh_param is not None and not dh_cipher_suites:
            raise ValueError('dh_param is set but no DHE cipher suite is configured')

        ecdhe_cipher_suites = [
            cs for cs in self.cipher_suites
            if cs.value.key_exchange in (KeyExchange.ECDHE, KeyExchange.AECDH)
            or TlsProtocolVersion(cs.value.initial_version) > TlsProtocolVersion(TlsVersion.TLS1_2)
        ]
        if self.curves and not ecdhe_cipher_suites:
            raise ValueError('curves are set but no ECDHE cipher suite is configured')

        if self.certificate_authorities is not None and not self.certificates:
            raise ValueError('certificate_authorities is set but no certificate is configured')


@attr.s
class L7ServerTlsBase(L7ServerBase):
    def __attrs_post_init__(self):
        if self.configuration is None:
            self.configuration = TlsServerConfiguration()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _init_l7(self):
        pass

    def _deinit_l7(self):
        pass

    def _get_handshake_class(self):
        if self.configuration.fallback_to_ssl:
            try:
                self.receive(TlsRecord.HEADER_SIZE)
            except NotEnoughData as e:
                raise NetworkError(NetworkErrorType.NO_CONNECTION) from e

            try:
                TlsRecord.parse_header(self.buffer)
                handshake_class = TlsServerHandshake
            except InvalidValue:
                handshake_class = SslServerHandshake
        else:
            handshake_class = TlsServerHandshake

        return handshake_class

    def _do_handshake(self, last_handshake_message_type):
        try:
            self._init_l7()
        except (NotEnoughData, InvalidValue, NetworkError, SecurityError):
            self.l4_transfer.close_client()
            return {}

        try:
            handshake_class = self._get_handshake_class()
            handshake_object = handshake_class(self, self.configuration)
        except NetworkError:
            self.l4_transfer.close_client()
            return {}

        try:
            handshake_object.do_handshake(last_handshake_message_type)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self._deinit_l7()
            self.l4_transfer.close_client()

        return handshake_object.client_messages

    def do_handshake(self, last_handshake_message_type=TlsHandshakeType.CLIENT_HELLO):
        return self._do_handshakes(last_handshake_message_type)


class L7ServerStartTlsBase(L7ServerTlsBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()


@attr.s
class TlsServer(L7ServerHandshakeBase):
    @abc.abstractmethod
    def _parse_record(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _parse_message(self, record):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_handshake_message(self, message, last_handshake_message_type):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_non_handshake_message(self, message):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_invalid_message(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_plain_text_message(self):
        raise NotImplementedError()


class TlsServerHandshake(TlsServer):
    def _check_protocol_version(self, message):
        min_version = self.configuration.min_protocol_version
        max_version = self.configuration.max_protocol_version

        try:
            supported_versions = message.extensions.get_item_by_type(
                TlsExtensionType.SUPPORTED_VERSIONS
            ).supported_versions
            for version in supported_versions:
                if min_version <= version <= max_version:
                    return version
        except KeyError:
            client_version = message.protocol_version
            negotiated = min(client_version, max_version)
            if negotiated >= min_version:
                return negotiated

        self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.PROTOCOL_VERSION)
        raise StopIteration()

    def _prepare_server_hello(self, message, protocol_version):
        extensions = []
        if protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2):
            extensions.append(TlsExtensionSupportedVersionsServer(protocol_version))

        preferred_cipher_suite_list = self.configuration.cipher_suites
        selectable_cipher_suite_set = set(
            cs for cs in message.cipher_suites if isinstance(cs, TlsCipherSuite)
        )
        for cipher_suite in preferred_cipher_suite_list:
            if cipher_suite in selectable_cipher_suite_set:
                choosen_cipher_suite = cipher_suite
                break
        else:
            self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE)
            raise StopIteration()

        if protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2) and self.configuration.curves:
            selected_curve = self._get_ecdhe_curve(message)
            if selected_curve is None:
                self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE)
                raise StopIteration()

            if selected_curve in self._get_client_key_share_groups(message):
                extensions.append(TlsExtensionKeyShareServer(key_share_entry_from_named_curve(selected_curve)))
            else:
                extensions.append(TlsExtensionKeyShareClientHelloRetry(selected_curve))

        extensions.extend(self._get_configured_extensions())

        session_id = (
            TlsSessionIdVector(list(range(32)))
            if self.configuration.session_cache_supported
            else TlsSessionIdVector(())
        )

        wire_protocol_version = (
            TlsProtocolVersion(TlsVersion.TLS1_2)
            if protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2)
            else protocol_version
        )
        return TlsHandshakeServerHello(
            protocol_version=wire_protocol_version,
            cipher_suite=choosen_cipher_suite,
            random=message.random,
            session_id=session_id,
            extensions=extensions,
        )

    def _get_configured_extensions(self):
        extensions = []
        if self.configuration.encrypt_then_mac_supported:
            extensions.append(TlsExtensionEncryptThenMAC())
        if self.configuration.extended_master_secret_supported:
            extensions.append(TlsExtensionExtendedMasterSecret())
        if self.configuration.renegotiation_supported:
            extensions.append(TlsExtensionRenegotiationInfo())
        if self.configuration.session_ticket_supported:
            extensions.append(TlsExtensionSessionTicket())
        if self.configuration.next_protocols is not None:
            extensions.append(TlsExtensionNextProtocolNegotiationServer(
                TlsNextProtocolNameList(self.configuration.next_protocols)
            ))
        if self.configuration.application_layer_protocols is not None:
            extensions.append(TlsExtensionApplicationLayerProtocolNegotiation(
                TlsProtocolNameList(self.configuration.application_layer_protocols)
            ))
        if self.configuration.signed_certificate_timestamps_supported:
            extensions.append(TlsExtensionSignedCertificateTimestampServer(SignedCertificateTimestampList([])))

        return extensions

    def _get_ecdhe_curve(self, client_hello):
        try:
            client_supported_curves = client_hello.extensions.get_item_by_type(
                TlsExtensionType.SUPPORTED_GROUPS
            ).elliptic_curves
        except KeyError:
            return None

        for curve in self.configuration.curves:
            if curve in client_supported_curves:
                return curve

        return None

    @staticmethod
    def _get_client_key_share_groups(client_hello):
        try:
            key_share_entries = client_hello.extensions.get_item_by_type(
                TlsExtensionType.KEY_SHARE
            ).key_share_entries
        except KeyError:
            return []

        return [key_share_entry.group for key_share_entry in key_share_entries]

    @staticmethod
    def _compose_dh_param_bytes(dh_param):
        if isinstance(dh_param, DHParamWellKnown):
            parameter_numbers = dh_param.value.parameter_numbers
        else:
            parameter_numbers = dh_param
        p = parameter_numbers.p
        g = parameter_numbers.g

        p_byte_size = (p.bit_length() + 7) // 8
        p_bytes = int_to_bytes(p, p_byte_size)
        g_bytes = int_to_bytes(g, (g.bit_length() + 7) // 8)
        y = get_dh_ephemeral_key_forged(p)
        y_bytes = int_to_bytes(y, p_byte_size)

        return bytes(
            TlsDHParamVector(list(p_bytes)).compose() +
            TlsDHParamVector(list(g_bytes)).compose() +
            TlsDHParamVector(list(y_bytes)).compose()
        )

    @staticmethod
    def _compose_ecdh_param_bytes(named_curve):
        public_key = get_ecdh_ephemeral_key_forged(named_curve.value.named_group)

        composer = ComposerBinary()
        composer.compose_numeric(TlsECCurveType.NAMED_CURVE, 1)
        composer.compose_numeric_enum_coded(named_curve)
        composer.compose_numeric(len(public_key), 1)
        composer.compose_raw(public_key)

        return bytes(composer.composed_bytes)

    def _send_server_hello_messages(self, protocol_version, cipher_suite, client_hello):
        if self.configuration.certificates:
            certificate_chain = TlsCertificates(
                [TlsCertificate(cert_bytes) for cert_bytes in self.configuration.certificates]
            )
            self.l7_transfer.send(
                TlsRecord(TlsHandshakeServerCertificate(certificate_chain).compose()).compose()
            )

        if cipher_suite.value.key_exchange in (KeyExchange.DHE, KeyExchange.ADH):
            if self.configuration.dh_param is not None:
                param_bytes = self._compose_dh_param_bytes(self.configuration.dh_param)
                self.l7_transfer.send(
                    TlsRecord(TlsHandshakeServerKeyExchange(param_bytes).compose()).compose()
                )
        elif cipher_suite.value.key_exchange in (KeyExchange.ECDHE, KeyExchange.AECDH):
            if self.configuration.curves:
                named_curve = self._get_ecdhe_curve(client_hello)
                if named_curve is not None:
                    param_bytes = self._compose_ecdh_param_bytes(named_curve)
                    self.l7_transfer.send(
                        TlsRecord(TlsHandshakeServerKeyExchange(param_bytes).compose()).compose()
                    )

        if self.configuration.certificate_authorities is not None:
            if protocol_version < TlsProtocolVersion(TlsVersion.TLS1_2):
                supported_signature_algorithms = None
            else:
                supported_signature_algorithms = list(TlsSignatureAndHashAlgorithm)
            self.l7_transfer.send(TlsRecord(TlsHandshakeCertificateRequest(
                certificate_types=[
                    TlsClientCertificateType.RSA_SIGN,
                    TlsClientCertificateType.DSS_SIGN,
                    TlsClientCertificateType.ECDSA_SIGN,
                ],
                certificate_authorities=[
                    TlsDistinguishedName(certificate_authority)
                    for certificate_authority in self.configuration.certificate_authorities
                ],
                supported_signature_algorithms=supported_signature_algorithms,
            ).compose()).compose())

        self.l7_transfer.send(TlsRecord(TlsHandshakeServerHelloDone().compose()).compose())

    def _process_handshake_message(self, message, last_handshake_message_type):
        self._last_processed_message_type = message.get_handshake_type()
        self.client_messages[self._last_processed_message_type] = message

        if len(self.client_messages) == 1:
            if TlsHandshakeType.CLIENT_HELLO not in self.client_messages:
                self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE)
                raise StopIteration()

        if message.get_handshake_type() == TlsHandshakeType.CLIENT_HELLO:
            protocol_version = self._check_protocol_version(message)
            server_hello = self._prepare_server_hello(message, protocol_version)
            self.l7_transfer.send(TlsRecord(server_hello.compose()).compose())

            if (protocol_version <= TlsProtocolVersion(TlsVersion.TLS1_2) and
                    (self.configuration.certificates or
                     self.configuration.dh_param is not None or
                     self.configuration.curves)):
                self._send_server_hello_messages(protocol_version, server_hello.cipher_suite, message)

        if self._last_processed_message_type == last_handshake_message_type:
            try:
                self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)
            except (BrokenPipeError, ConnectionResetError):
                pass
            raise StopIteration()

    def _process_non_handshake_message(self, message):
        self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self.l7_transfer.buffer_is_plain_text:
            self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
            raise StopIteration()

    def _process_invalid_message(self):
        self._process_plain_text_message()

        self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
        raise StopIteration()

    def _handle_error(self, alert_level, alert_description):
        if self.configuration.close_on_error:
            self.l7_transfer.l4_transfer.close_client()
        else:
            self.l7_transfer.send(TlsRecord(
                TlsAlertMessage(alert_level, alert_description).compose(),
                content_type=TlsContentType.ALERT,
            ).compose())

    def _parse_record(self):
        record, parsed_length = TlsRecord.parse_immutable(self.l7_transfer.buffer)
        is_handshake = record.content_type == TlsContentType.HANDSHAKE

        return record, parsed_length, is_handshake

    def _parse_message(self, record):
        subprotocol_parser = TlsSubprotocolMessageParser(record.content_type)
        message, _ = subprotocol_parser.parse(record.fragment)

        return message


class SslServerHandshake(TlsServer):
    client_messages = attr.ib(
        init=False,
        default={},
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SslMessageBase))
    )

    def _process_handshake_message(self, message, last_handshake_message_type):
        self._last_processed_message_type = message.get_message_type()
        self.client_messages[self._last_processed_message_type] = message

        server_hello = SslHandshakeServerHello(
            certificate=b'fake certificate',
            cipher_kinds=message.cipher_kinds,
            connection_id=b'fake connection id',
        )
        self.l7_transfer.send(SslRecord(server_hello).compose())

        if self._last_processed_message_type == last_handshake_message_type:
            self._handle_error(SslErrorType.NO_CIPHER_ERROR)
            raise StopIteration()

    def _process_non_handshake_message(self, message):
        self._handle_error(SslErrorType.NO_CIPHER_ERROR)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self.l7_transfer.buffer_is_plain_text:
            self._handle_error(SslErrorType.NO_CIPHER_ERROR)
            raise StopIteration()

    def _process_invalid_message(self):
        self._process_plain_text_message()

        self._handle_error(SslErrorType.NO_CIPHER_ERROR)
        raise StopIteration()

    def _handle_error(self, error_type):
        self.l7_transfer.send(SslRecord(SslErrorMessage(error_type)).compose())

    def _parse_record(self):
        record, parsed_length = SslRecord.parse_immutable(self.l7_transfer.buffer)
        is_handshake = record.message.get_message_type() != SslMessageType.ERROR

        return record, parsed_length, is_handshake

    def _parse_message(self, record):
        return record.message


class L7ServerTls(L7ServerTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 4433


class L7ServerTlsRDP(L7ServerStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'rdp'

    @classmethod
    def get_default_port(cls):
        return 3389

    def _init_l7(self):
        self.receive(TPKT.HEADER_SIZE)
        try:
            TPKT.parse_exact_size(self.buffer)
        except NotEnoughData as e:
            self.receive(e.bytes_needed)

        tpkt = TPKT.parse_exact_size(self.buffer)
        cotp = COTPConnectionRequest.parse_exact_size(tpkt.message)
        neg_req = RDPNegotiationRequest.parse_exact_size(cotp.user_data)
        if RDPProtocol.SSL not in neg_req.protocol:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        self.flush_buffer()

        neg_resp = RDPNegotiationResponse([], [RDPProtocol.SSL, ])
        cotp = COTPConnectionConfirm(src_ref=cotp.src_ref, user_data=neg_resp.compose())
        tpkt = TPKT(version=3, message=cotp.compose())
        request_bytes = tpkt.compose()
        self.send(request_bytes)

    def _deinit_l7(self):
        pass


class L7ServerTlsLDAP(L7ServerStartTlsBase):
    _EXTENDED_RESPONSE_STARTLS_BYTES = LDAPExtendedResponseStartTLS(LDAPResultCode.SUCCESS).compose()

    @classmethod
    def get_scheme(cls):
        return 'ldap'

    @classmethod
    def get_default_port(cls):
        return 3389

    def _init_l7(self):
        self.receive(LDAPExtendedRequestStartTLS.HEADER_SIZE)
        try:
            LDAPExtendedRequestStartTLS.parse_exact_size(self.buffer)
        except NotEnoughData as e:
            self.receive(e.bytes_needed)

        LDAPExtendedRequestStartTLS.parse_exact_size(self.buffer)
        self.flush_buffer()

        self.send(self._EXTENDED_RESPONSE_STARTLS_BYTES)

    def _deinit_l7(self):
        pass


class L7ServerTlsPostgreSQL(L7ServerStartTlsBase):
    _SSL_REQUEST_BYTES = SslRequest().compose()
    _SYNC_BYTES = Sync().compose()

    @classmethod
    def get_scheme(cls):
        return 'postgresql'

    @classmethod
    def get_default_port(cls):
        return 5432

    def _init_l7(self):
        self.receive(len(self._SSL_REQUEST_BYTES))
        if self.buffer != self._SSL_REQUEST_BYTES:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        self.flush_buffer()

        self.send(self._SYNC_BYTES)

    def _deinit_l7(self):
        pass


class L7ServerTlsMySQL(L7ServerStartTlsBase):
    _SERVER_HANDSHAKE_RECORD_BYTES = MySQLRecord(0, MySQLHandshakeV10(
        protocol_version=MySQLVersion.MYSQL_10,
        server_version='1.2.3.4',
        connection_id=0x01020304,
        auth_plugin_data=b'12345678',
        capabilities=[MySQLCapability.CLIENT_SSL, ],
    ).compose()).compose()

    @classmethod
    def get_scheme(cls):
        return 'mysql'

    @classmethod
    def get_default_port(cls):
        return 3306

    def _init_l7(self):
        self.send(self._SERVER_HANDSHAKE_RECORD_BYTES)

        self.receive(MySQLRecord.HEADER_SIZE)
        try:
            MySQLRecord.parse_exact_size(self.buffer)
        except NotEnoughData as e:
            self.receive(e.bytes_needed)

        record, parsed_length = MySQLRecord.parse_immutable(self.buffer)
        self.flush_buffer(parsed_length)

        ssl_request = MySQLHandshakeSslRequest.parse_exact_size(record.packet_bytes)
        if not set([MySQLCapability.CLIENT_SSL, MySQLCapability.CLIENT_SECURE_CONNECTION]) & ssl_request.capabilities:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _deinit_l7(self):
        pass


@attr.s
class L7ServerStartTlsTextBase(L7ServerStartTlsBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_greeting(cls):
        raise NotImplementedError()

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return None

    @classmethod
    def _get_capabilities_response(cls):
        return None  # pragma: no cover

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'STARTTLS'

    @classmethod
    @abc.abstractmethod
    def _get_starttls_response(cls):
        raise NotImplementedError()

    @classmethod
    def _get_software_name(cls):
        return f'{__title__} {__version__}'.encode('ascii')

    def _init_l7(self):
        greeting = self._get_greeting()
        if greeting:
            self.send(greeting)

        self.l4_transfer.receive_line()
        capabilities_request_prefix = self._get_capabilities_request_prefix()
        if capabilities_request_prefix and self.buffer.startswith(capabilities_request_prefix):
            self.l4_transfer.flush_buffer()
            self.l4_transfer.send(self._get_capabilities_response())
            self.l4_transfer.receive_line()

        starttls_request_prefix = self._get_starttls_request_prefix()
        if not self.buffer.startswith(starttls_request_prefix):
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        self.flush_buffer()

        self.send(self._get_starttls_response())


class L7ServerTlsSieve(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'sieve'

    @classmethod
    def get_default_port(cls):
        return 4190

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'"STARTTLS"',
            b'OK "' + cls._get_software_name() + b'" ready,',
            b'',
        ])

    @classmethod
    def _get_starttls_response(cls):
        return b'OK "Begin TLS negotiation now."\r\n'


class L7ServerTlsFTP(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'ftp'

    @classmethod
    def get_default_port(cls):
        return 2121

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'FEAT'

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'211-Extensions supported:',
            b' AUTH TLS',
            b'211 End.',
            b'',
        ])

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'220 Welcome to ' + cls._get_software_name() + b'.',
            b'',
        ])

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'AUTH TLS'

    @classmethod
    def _get_starttls_response(cls):
        return b'234 AUTH TLS OK.\r\n'


class L7ServerTlsPOP3(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'pop3'

    @classmethod
    def get_default_port(cls):
        return 1110

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'+OK ' + cls._get_software_name() + b' ready.',
            b'',
        ])

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'CAPA'

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'+OK',
            b'CAPA',
            b'STLS',
            b'.',
            b'',
        ])

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'STLS'

    @classmethod
    def _get_starttls_response(cls):
        return b'+OK Begin TLS negotiation now.\r\n'


class L7ServerTlsIMAPBase(L7ServerStartTlsBase):
    """
    Minimal IMAP STARTTLS test server (RFC 3501 / RFC 2595).

    Implements:
    - initial untagged welcome message
    - CAPABILITY exchange during connection setup
    - tagged STARTTLS extension command

    After the STARTTLS negotiation response is sent, the base
    `L7ServerTlsBase` continues with the normal TLS handshake parsing
    over the same socket.
    """

    @classmethod
    def get_scheme(cls):
        return 'imap'

    @classmethod
    def get_default_port(cls):
        return 143

    @classmethod
    def _get_greeting(cls):
        return b'* OK IMAP4rev1 Service Ready\r\n'

    @classmethod
    @abc.abstractmethod
    def _is_capability_starttls(cls):
        raise NotImplementedError()

    @classmethod
    def _is_starttls_ok(cls):
        return True

    @classmethod
    def _get_capabilities(cls):
        capabilities = [
            b'IMAP4REV1',
            b'LITERAL+',
            b'SASL-IR',
            b'LOGIN-REFERRALS',
            b'ID',
            b'ENABLE',
            b'IDLE',
            b'LOGINDISABLED',
        ]
        if cls._is_capability_starttls():
            capabilities.append(b'STARTTLS')
        return b' '.join(capabilities)

    @classmethod
    def _get_starttls_response_type(cls):
        # {OK,NO,BAD} are IMAP tagged response types (RFC 3501).
        # Returning `NO` makes the client take the error path.
        return b'OK' if cls._is_starttls_ok() else b'NO'

    @staticmethod
    def _parse_imap_tag(line):
        # Tag is the first whitespace-separated token, e.g. b'A0001'.
        parts = line.split()
        return parts[0] if parts else b''

    def _init_l7(self):
        self.send(self._get_greeting())

        self.l4_transfer.receive_line()
        capability_cmd = bytes(self.buffer).strip()
        tag = self._parse_imap_tag(capability_cmd)
        self.flush_buffer()

        if b'CAPABILITY' not in capability_cmd.upper():
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        self.send(b'* CAPABILITY ' + self._get_capabilities() + b'\r\n')
        self.send(tag + b' OK CAPABILITY completed\r\n')

        self.l4_transfer.receive_line()
        starttls_cmd = bytes(self.buffer).strip()
        starttls_tag = self._parse_imap_tag(starttls_cmd)
        self.flush_buffer()

        if b'STARTTLS' not in starttls_cmd.upper():
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        self.send(
            starttls_tag
            + b' '
            + self._get_starttls_response_type()
            + b' STARTTLS completed\r\n'
        )


class L7ServerTlsIMAP(L7ServerTlsIMAPBase):
    @classmethod
    def _is_capability_starttls(cls):
        return True


class L7ServerTlsIMAPNoStartTLS(L7ServerTlsIMAPBase):
    @classmethod
    def _is_capability_starttls(cls):
        return False


class L7ServerTlsIMAPStartTLSBad(L7ServerTlsIMAPBase):
    @classmethod
    def _is_capability_starttls(cls):
        return True

    @classmethod
    def _is_starttls_ok(cls):
        return False


class L7ServerTlsIMAPInvalidGreeting(L7ServerTlsIMAP):
    @classmethod
    def _get_greeting(cls):
        return b'\xff\xff\xff\xff\r\n'


class L7ServerTlsIMAPEarlyClose(L7ServerTlsIMAP):
    def _init_l7(self):
        raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)


class L7ServerTlsXMPPBase(L7ServerStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'xmpp'

    @classmethod
    def get_default_port(cls):
        return 5222

    @classmethod
    @abc.abstractmethod
    def _is_starttls_feature(cls):
        raise NotImplementedError()

    @classmethod
    def _is_starttls_ok(cls):
        return True

    @classmethod
    def _get_features(cls):
        if cls._is_starttls_feature():
            return (
                b'<stream:features>'
                b'<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'
                b'</stream:features>'
            )
        return b'<stream:features></stream:features>'

    def _init_l7(self):
        self.l4_transfer.receive_until(b'>')
        self.flush_buffer()

        self.send(
            b'<stream:stream xmlns:stream="http://etherx.jabber.org/streams">'
            + self._get_features()
        )

        if not self._is_starttls_feature():
            return

        self.l4_transfer.receive_until(b'>')
        self.flush_buffer()

        if self._is_starttls_ok():
            self.send(b'<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')
        else:
            self.send(b'<failure xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')


class L7ServerTlsXMPP(L7ServerTlsXMPPBase):
    @classmethod
    def _is_starttls_feature(cls):
        return True


class L7ServerTlsXMPPNoStartTLS(L7ServerTlsXMPPBase):
    @classmethod
    def _is_starttls_feature(cls):
        return False


class L7ServerTlsXMPPStartTLSBad(L7ServerTlsXMPPBase):
    @classmethod
    def _is_starttls_feature(cls):
        return True

    @classmethod
    def _is_starttls_ok(cls):
        return False


class L7ServerStartTlsMailBase(L7ServerStartTlsTextBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'220 localhost ' + cls._get_software_name() + b' ready.',
            b'',
        ])

    @classmethod
    @abc.abstractmethod
    def _get_capabilities_request_prefix(cls):
        raise NotImplementedError()

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'250 localhost at your service',
            b'250 STARTTLS',
            b'',
        ])

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'STARTTLS'

    @classmethod
    def _get_starttls_response(cls):
        return b'220 Ready to start TLS\r\n'


class L7ServerTlsSMTP(L7ServerStartTlsMailBase):
    @classmethod
    def get_scheme(cls):
        return 'smtp'

    @classmethod
    def get_default_port(cls):
        return 5587

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'EHLO'


class L7ServerTlsLMTP(L7ServerStartTlsMailBase):
    @classmethod
    def get_scheme(cls):
        return 'lmtp'

    @classmethod
    def get_default_port(cls):
        return 2424

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'LHLO'


class L7ServerTlsNNTP(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'nntp'

    @classmethod
    def get_default_port(cls):
        return 1119

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'CAPABILITIES'

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'101 Capability list:',
            b'STARTTLS',
            b'.',
            b'',
        ])

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'200 ' + cls._get_software_name() + b' Welcome!',
            b'',
        ])

    @classmethod
    def _get_starttls_response(cls):
        return b'382 Continue with TLS negotiation\r\n'


@attr.s
class L7ServerStartTlsOpenVpnBase(L7ServerStartTlsBase, L7OpenVpnBase):
    session_id = attr.ib(
        init=False, default=0xff58585858585858,
        validator=attr.validators.instance_of(int)
    )
    client_packet_id = attr.ib(
        init=False, default=0x00000000,
        validator=attr.validators.instance_of(int)
    )
    remote_session_id = attr.ib(
        init=False, default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int))
    )
    _buffer = attr.ib(init=False)

    def __attrs_post_init__(self):
        super().__attrs_post_init__()

        self._buffer = bytearray()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _reset_session(self):
        packets = self._receive_packets(self.l4_transfer)
        packet_hard_reset_client = packets[0]

        if packet_hard_reset_client.get_op_code() != OpenVpnOpCode.HARD_RESET_CLIENT_V2:
            raise InvalidValue(
                packet_hard_reset_client.get_op_code(), type(self), 'op_code'
            )

        self.remote_session_id = packet_hard_reset_client.session_id
        packet_hard_reset_server = OpenVpnPacketHardResetServerV2(
            self.session_id,
            self.remote_session_id,
            [packet_hard_reset_client.packet_id],
            0
        )
        self._send_packet(self.l4_transfer, packet_hard_reset_server)

    def _init_l7(self):
        try:
            self._reset_session()
        except (InvalidValue, InvalidType, NotEnoughData) as e:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY) from e

    def send(self, sendable_bytes):
        return self._send_bytes(self.l4_transfer, sendable_bytes)

    def receive(self, receivable_byte_num):
        received_bytes = self._receive_packet_bytes(self.l4_transfer, receivable_byte_num)
        self._buffer += received_bytes
        return len(received_bytes)

    def flush_buffer(self, byte_num=None):
        self._buffer = buffer_flush(self._buffer, byte_num)

    @property
    def buffer_is_plain_text(self):
        return buffer_is_plain_text(self._buffer)

    @property
    def buffer(self):
        return self._buffer

    @classmethod
    def _is_tcp(cls):
        return issubclass(cls._get_transfer_class(), L4ServerTCP)


class L7ServerTlsOpenVpn(L7ServerStartTlsOpenVpnBase):
    @classmethod
    def get_scheme(cls):
        return 'openvpn'

    @classmethod
    def get_default_port(cls):
        return 1194

    @classmethod
    def _get_transfer_class(cls):
        return L4ServerUDP


class L7ServerTlsOpenVpnTcp(L7ServerStartTlsOpenVpnBase):
    @classmethod
    def get_scheme(cls):
        return 'openvpntcp'

    @classmethod
    def get_default_port(cls):
        return 443

    @classmethod
    def _get_transfer_class(cls):
        return L4ServerTCP
