# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc

import ftplib
import imaplib

import collections
import socket

import attr

import six

from cryptodatahub.common.algorithm import Authentication, BlockCipher, BlockCipherMode, KeyExchange, NamedGroupType
from cryptodatahub.common.exception import InvalidValue

from cryptodatahub.tls.algorithm import TlsSignatureAndHashAlgorithm, TlsECPointFormat

from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidType

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.ldap import (
    LDAPResultCode,
    LDAPExtendedRequestStartTLS,
    LDAPExtendedResponseStartTLS,
)
from cryptoparser.tls.mysql import MySQLCapability, MySQLHandshakeSslRequest, MySQLHandshakeV10, MySQLRecord
from cryptoparser.tls.postgresql import SslRequest, Sync
from cryptoparser.tls.rdp import (
    TPKT,
    COTPConnectionConfirm,
    COTPConnectionRequest,
    RDPProtocol,
    RDPNegotiationRequest,
    RDPNegotiationResponse,
)
from cryptoparser.tls.subprotocol import (
    TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM,
    SslHandshakeClientHello,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsContentType,
    TlsHandshakeClientHello,
    TlsHandshakeType,
    TlsSubprotocolMessageParser,
)
from cryptoparser.tls.extension import (
    TlsExtensionECPointFormats,
    TlsExtensionEllipticCurves,
    TlsExtensionKeyShareClient,
    TlsExtensionKeyShareReservedClient,
    TlsExtensionServerNameClient,
    TlsExtensionSignatureAlgorithms,
    TlsExtensionSignatureAlgorithmsCert,
    TlsExtensionSupportedVersionsClient,
    TlsExtensionsClient,
    TlsKeyShareEntry,
    TlsNamedCurve,
)
from cryptoparser.tls.openvpn import (
    OpenVpnPacketAckV1,
    OpenVpnPacketHardResetClientV2,
)

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.dhparam import (
    DHParamWellKnown,
    get_dh_ephemeral_key_forged,
    get_ecdh_ephemeral_key_forged,
    int_to_bytes,
)
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.common.transfer import L4ClientTCP, L4ClientUDP, L7TransferBase
from cryptolyzer.common.utils import buffer_flush, buffer_is_plain_text

from cryptolyzer.tls.application import L7OpenVpnBase
from cryptolyzer.tls.exception import TlsAlert


NAMED_CURVE_TO_RFC7919_WELL_KNOWN = {
    TlsNamedCurve.FFDHE2048: DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
    TlsNamedCurve.FFDHE3072: DHParamWellKnown.RFC7919_3072_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
    TlsNamedCurve.FFDHE4096: DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
    TlsNamedCurve.FFDHE6144: DHParamWellKnown.RFC7919_6144_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
    TlsNamedCurve.FFDHE8192: DHParamWellKnown.RFC7919_8192_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
}


RFC7919_WELL_KNOWN_TO_NAMED_CURVE = {
    DHParamWellKnown.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE2048,
    DHParamWellKnown.RFC7919_3072_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE3072,
    DHParamWellKnown.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE4096,
    DHParamWellKnown.RFC7919_6144_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE6144,
    DHParamWellKnown.RFC7919_8192_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE8192,
}


def key_share_entry_from_named_curve(named_curve):
    if named_curve.value.named_group is None:
        raise NotImplementedError(named_curve)

    if named_curve.value.named_group.value.group_type == NamedGroupType.ELLIPTIC_CURVE:
        return TlsKeyShareEntry(
            named_curve,
            get_ecdh_ephemeral_key_forged(named_curve.value.named_group)
        )

    if named_curve.value.named_group.value.group_type == NamedGroupType.FINITE_FIELD:
        well_known_dh_param = NAMED_CURVE_TO_RFC7919_WELL_KNOWN[named_curve]
        return TlsKeyShareEntry(
            named_curve,
            int_to_bytes(
                get_dh_ephemeral_key_forged(well_known_dh_param.value.parameter_numbers.p),
                well_known_dh_param.value.key_size // 8
            )
        )

    raise NotImplementedError()


class TlsHandshakeClientHelloSpecalization(TlsHandshakeClientHello):
    @classmethod
    def _get_signature_algorithms(cls, protocol_version_min, protocol_version_max, cipher_suites):
        if protocol_version_max > TlsProtocolVersion(TlsVersion.TLS1_2):
            authentications_not_exist_in_tls1_3 = [Authentication.ANONYMOUS, Authentication.DSS]
            signature_algorithms = [
                signature_algorithm
                for signature_algorithm in TlsSignatureAndHashAlgorithm
                if (signature_algorithm.value.signature_algorithm not in authentications_not_exist_in_tls1_3 and
                    signature_algorithm.value.hash_algorithm is not None)
            ]
        elif protocol_version_min >= TlsProtocolVersion(TlsVersion.TLS1_2):
            authentication_algorithms = set(
                cipher_suite.value.authentication
                for cipher_suite in cipher_suites
                if cipher_suite.value.authentication is not None
            )
            signature_algorithms = [
                signature_algorithm
                for signature_algorithm in TlsSignatureAndHashAlgorithm
                if signature_algorithm.value.signature_algorithm in authentication_algorithms
            ]
        else:
            signature_algorithms = []

        return signature_algorithms

    @classmethod
    def _get_tls1_3_extensions(cls, protocol_versions, signature_algorithms):
        extensions = [
            TlsExtensionKeyShareReservedClient([]),
            TlsExtensionKeyShareClient([]),
            TlsExtensionSupportedVersionsClient(protocol_versions),
        ]

        if signature_algorithms:
            extensions.append(TlsExtensionSignatureAlgorithmsCert(signature_algorithms))

        return extensions

    def __init__(
            self,
            hostname,
            protocol_versions,
            cipher_suites,
            named_curves,
            signature_algorithms,
            extensions
    ):  # pylint: disable=too-many-arguments
        protocol_version_min = min(protocol_versions)
        protocol_version_max = max(protocol_versions)
        is_tls1_3_supported = protocol_version_max > TlsProtocolVersion(TlsVersion.TLS1_2)

        if hostname is not None:
            extensions.append(TlsExtensionServerNameClient(hostname))
        if named_curves is None:
            named_curves = list(TlsNamedCurve)

        if signature_algorithms is None:
            signature_algorithms = self._get_signature_algorithms(
                protocol_version_min, protocol_version_max, cipher_suites
            )

        if is_tls1_3_supported:
            #  filter out non TLS 1.3 cipher suites
            cipher_suites = [
                cipher_suite
                for cipher_suite in cipher_suites
                if TlsProtocolVersion(cipher_suite.value.initial_version) > TlsProtocolVersion(TlsVersion.TLS1_2)
            ]

            extensions.extend(self._get_tls1_3_extensions(protocol_versions, signature_algorithms))
        elif len(protocol_versions) > 1:
            raise NotImplementedError(protocol_versions)

        if protocol_version_min >= TlsProtocolVersion(TlsVersion.TLS1):
            if named_curves:
                extensions.append(TlsExtensionEllipticCurves(named_curves))

                if not is_tls1_3_supported:
                    extensions.append(TlsExtensionECPointFormats(TlsECPointFormat))

        if signature_algorithms:
            extensions.append(TlsExtensionSignatureAlgorithms(signature_algorithms))

        if is_tls1_3_supported:
            protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        else:
            protocol_version = protocol_version_min

        super(TlsHandshakeClientHelloSpecalization, self).__init__(
            cipher_suites=cipher_suites,
            protocol_version=protocol_version,
            extensions=TlsExtensionsClient(extensions)
        )


class TlsHandshakeClientHelloAnyAlgorithm(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    def __init__(self, protocol_versions, hostname):
        super(TlsHandshakeClientHelloAnyAlgorithm, self).__init__(
            hostname=hostname,
            protocol_versions=protocol_versions,
            cipher_suites=list(TlsCipherSuite),
            named_curves=None,
            signature_algorithms=None,
            extensions=[]
        )


class TlsHandshakeClientHelloAuthenticationBase(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    # pylint: disable=too-many-ancestors
    def __init__(
            self,
            protocol_version,
            hostname,
            authentications,
            named_curves,
            signature_algorithms,
    ):  # pylint: disable=too-many-arguments
        _cipher_suites = [
            cipher_suite
            for cipher_suite in TlsCipherSuite
            if cipher_suite.value.authentication in authentications or
            TlsProtocolVersion(cipher_suite.value.initial_version) > TlsProtocolVersion(TlsVersion.TLS1_2)
        ]

        super(TlsHandshakeClientHelloAuthenticationBase, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=_cipher_suites,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


class TlsHandshakeClientHelloAuthenticationRSA(TlsHandshakeClientHelloAuthenticationBase):
    # pylint: disable=too-many-ancestors
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAuthenticationRSA, self).__init__(
            hostname=hostname,
            protocol_version=protocol_version,
            authentications=[Authentication.RSA, ],
            named_curves=None,
            signature_algorithms=None,
        )


class TlsHandshakeClientHelloAuthenticationDSS(TlsHandshakeClientHelloAuthenticationBase):
    # pylint: disable=too-many-ancestors
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAuthenticationDSS, self).__init__(
            protocol_version=protocol_version,
            hostname=hostname,
            authentications=[Authentication.DSS, ],
            named_curves=None,
            signature_algorithms=None,
        )


class TlsHandshakeClientHelloAuthenticationECDSA(TlsHandshakeClientHelloAuthenticationBase):
    # pylint: disable=too-many-ancestors
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAuthenticationECDSA, self).__init__(
            hostname=hostname,
            protocol_version=protocol_version,
            authentications=[Authentication.ECDSA, ],
            named_curves=None,
            signature_algorithms=None,
        )


class TlsHandshakeClientHelloAuthenticationGOST(TlsHandshakeClientHelloAuthenticationBase):
    # pylint: disable=too-many-ancestors
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAuthenticationGOST, self).__init__(
            protocol_version=protocol_version,
            hostname=hostname,
            authentications=[
                Authentication.GOST_R3410_94,
                Authentication.GOST_R3410_12_256,
                Authentication.GOST_R3410_12_512,
            ],
            named_curves=None,
            signature_algorithms=None,
        )


class TlsHandshakeClientHelloAuthenticationDeprecated(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    def __init__(self, protocol_version, hostname):
        _cipher_suites = [
            cipher_suite
            for cipher_suite in TlsCipherSuite
            if (cipher_suite.value.authentication and
                cipher_suite.value.authentication in [
                    Authentication.DSS,
                    Authentication.KRB5,
                    Authentication.PSK,
                    Authentication.SRP,
                    Authentication.ANONYMOUS,
                ])
        ]

        super(TlsHandshakeClientHelloAuthenticationDeprecated, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=_cipher_suites,
            named_curves=[],
            signature_algorithms=[],
            extensions=[]
        )


class TlsHandshakeClientHelloKeyExchangeDHE(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.key_exchange in [KeyExchange.DHE, KeyExchange.ADH] or
            TlsProtocolVersion(cipher_suite.value.initial_version) > TlsProtocolVersion(TlsVersion.TLS1_2))
    ]
    NAMED_CURVES = [
        named_curve
        for named_curve in TlsNamedCurve
        if (named_curve.value.named_group is not None
            and named_curve.value.named_group.value.group_type == NamedGroupType.FINITE_FIELD)
    ]

    def __init__(
            self,
            protocol_version,
            hostname,
            named_curves=None,
            signature_algorithms=None,
    ):
        if named_curves is None:
            named_curves = self.NAMED_CURVES

        super(TlsHandshakeClientHelloKeyExchangeDHE, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self.CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


class TlsHandshakeClientHelloKeyExchangeECDHx(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.key_exchange in [KeyExchange.ECDHE, KeyExchange.AECDH] or
            TlsProtocolVersion(cipher_suite.value.initial_version) > TlsProtocolVersion(TlsVersion.TLS1_2))
    ]
    NAMED_CURVES = [
        curve
        for curve, group in map(lambda curve: (curve, curve.value.named_group), TlsNamedCurve)
        if (group is not None and group.value.group_type in (NamedGroupType.ELLIPTIC_CURVE, NamedGroupType.HYBRID_PQS))
    ]

    def __init__(
            self,
            protocol_version,
            hostname,
            named_curves=None,
            signature_algorithms=None,
    ):

        if named_curves is None:
            named_curves = self.NAMED_CURVES

        super(TlsHandshakeClientHelloKeyExchangeECDHx, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self.CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


class TlsHandshakeClientHelloBlockCipherModeCBC(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.block_cipher_mode == BlockCipherMode.CBC
    ]

    def __init__(
            self,
            protocol_version,
            hostname,
            named_curves=None,
            signature_algorithms=None,
    ):

        super(TlsHandshakeClientHelloBlockCipherModeCBC, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self.CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


class TlsHandshakeClientHelloStreamCipherRC4(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.bulk_cipher in (
            BlockCipher.RC4_40,
            BlockCipher.RC4_56,
            BlockCipher.RC4_64,
            BlockCipher.RC4_128,
        )
    ]

    def __init__(
            self,
            protocol_version,
            hostname,
            named_curves=None,
            signature_algorithms=None,
    ):

        super(TlsHandshakeClientHelloStreamCipherRC4, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self.CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


class TlsHandshakeClientHelloBulkCipherBlockSize64(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.bulk_cipher and cipher_suite.value.bulk_cipher.value.block_size == 64
    ]

    def __init__(
            self,
            protocol_version,
            hostname,
            named_curves=None,
            signature_algorithms=None,
    ):

        super(TlsHandshakeClientHelloBulkCipherBlockSize64, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self.CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


class TlsHandshakeClientHelloBulkCipherNull(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.bulk_cipher is None
    ]

    def __init__(
            self,
            protocol_version,
            hostname,
            named_curves=None,
            signature_algorithms=None,
    ):

        super(TlsHandshakeClientHelloBulkCipherNull, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self.CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


class TlsHandshakeClientHelloKeyExchangeAnonymousDH(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.key_exchange == KeyExchange.ADH
    ]

    def __init__(
            self,
            protocol_version,
            hostname,
            named_curves=None,
            signature_algorithms=None,
    ):

        super(TlsHandshakeClientHelloKeyExchangeAnonymousDH, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self.CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=signature_algorithms,
            extensions=[]
        )


@attr.s
@six.add_metaclass(abc.ABCMeta)
class L7ClientTlsBase(L7TransferBase):
    l4_transfer = attr.ib(init=False, default=None)

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _init_connection(self):
        self.l4_transfer = L4ClientTCP(self.address, self.port, self.timeout, self.ip)
        self.l4_transfer.init_connection()

    def _do_handshake(
            self,
            l7_client,
            hello_message,
            record_version,
            last_handshake_message_type
    ):
        self.init_connection()

        try:
            l7_client.do_handshake(self, hello_message, record_version, last_handshake_message_type)
        finally:
            self._close_connection()

        return l7_client.server_messages

    def do_ssl_handshake(self, hello_message, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        return self._do_handshake(
            SslClientHandshake(),
            hello_message,
            TlsVersion.SSL2,
            last_handshake_message_type
        )

    def do_tls_handshake(
            self,
            hello_message,
            record_version=TlsProtocolVersion(TlsVersion.TLS1),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO
    ):
        return self._do_handshake(
            TlsClientHandshake(),
            hello_message,
            record_version,
            last_handshake_message_type
        )


@attr.s
class L7ClientStartTlsBase(L7ClientTlsBase):
    _l7_client = attr.ib(init=False, default=None)
    _tls_inititalized = attr.ib(init=False, default=False)

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def _init_l7(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _deinit_l7(self):
        raise NotImplementedError()

    def _init_connection(self):
        self.l4_transfer = L4ClientTCP(self.address, self.port, self.timeout, self.ip)

        try:
            self._init_l7()
        except NotEnoughData as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ == 'TimeoutError' or isinstance(e, socket.timeout):
                six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

            raise e

        self._tls_inititalized = True

    def _close_connection(self):
        if self._l7_client is not None and not self._tls_inititalized:
            self._deinit_l7()
        self.l4_transfer.close()


@attr.s
class L7ClientStartTlsTextBase(L7ClientStartTlsBase):
    greeting = attr.ib(
        init=False,
        default=[],
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(str))
    )

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @property
    def _encoding(self):
        return 'ascii'

    @property
    def _line_sep(self):
        return '\r\n'

    @property
    def _capabilities_command(self):
        return 'CAPABILITIES'

    @property
    def _starttls_command(self):
        return 'STARTTLS'

    @property
    @abc.abstractmethod
    def _starttls_ok_result(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _capabilities_ok_result(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _capabilities_terminator(self):
        raise NotImplementedError()

    def _update_capabilities(self, line, capabilities):
        key_and_value = line.split(' ', 1)
        key = key_and_value[0]
        if len(key_and_value) > 1:
            value = key_and_value[1]
        else:
            value = None

        if key == self._capabilities_terminator:
            raise StopIteration()

        capabilities.update(collections.OrderedDict([(key, value)]))

    def _get_capabilities(self):
        self.l4_transfer.send((self._capabilities_command + self._line_sep).encode(self._encoding))
        self.l4_transfer.receive_line()

        capabilities_ok_result = str(self._capabilities_ok_result).encode(self._encoding)
        if self.l4_transfer.buffer[:len(capabilities_ok_result)] != capabilities_ok_result:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        self.l4_transfer.flush_buffer()

        capabilities = collections.OrderedDict()
        while True:
            self.l4_transfer.receive_line()
            key_and_value = self.l4_transfer.buffer.decode('ascii').strip()
            self.l4_transfer.flush_buffer()

            try:
                self._update_capabilities(key_and_value, capabilities)
            except StopIteration:
                break

        return capabilities

    def _flush_line(self):
        self.l4_transfer.receive_line()
        line = self.l4_transfer.buffer.decode('ascii').strip()
        self.l4_transfer.flush_buffer()

        return line

    def _fill_greeting(self):
        self.greeting = [self._flush_line()]

    def _init_l7(self):
        try:
            self._l7_client = L7ClientTls(self.address, self.port, self.timeout)
            self._l7_client.init_connection()
            self.l4_transfer = self._l7_client.l4_transfer

            self._fill_greeting()

            capabilities = self._get_capabilities()
            if self._starttls_command in capabilities:
                self.l4_transfer.send((self._starttls_command + self._line_sep).encode(self._encoding))

                self.l4_transfer.receive_line()
                starttls_ok_result = str(self._starttls_ok_result).encode(self._encoding)
                if self.l4_transfer.buffer[:len(starttls_ok_result)] == starttls_ok_result:
                    self.l4_transfer.flush_buffer()
                else:
                    raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
            else:
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except UnicodeDecodeError as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)
        except NotEnoughData as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

    def _deinit_l7(self):
        pass


class L7ClientStartTlsMailBase(L7ClientStartTlsTextBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @property
    def _starttls_ok_result(self):
        return '220'

    @property
    def _capabilities_ok_result(self):
        return '250'

    @property
    def _capabilities_terminator(self):
        return None

    def _update_capabilities(self, line, capabilities):
        if len(line) < 4 or not line.startswith('250'):
            raise StopIteration()

        is_last_line = line[3] == ' '
        line = line[4:]

        super(L7ClientStartTlsMailBase, self)._update_capabilities(line, capabilities)

        if is_last_line:
            raise StopIteration()


class L7ClientTls(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 443


class L7ClientHTTPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'https'

    @classmethod
    def get_default_port(cls):
        return 443


class L7ClientDoH(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'doh'

    @classmethod
    def get_default_port(cls):
        return 443


class ClientLMTP(L7ClientStartTlsMailBase):
    @classmethod
    def get_scheme(cls):
        return 'lmtp'

    @classmethod
    def get_default_port(cls):
        return 24

    @property
    def _capabilities_command(self):
        return 'LHLO cryptolyzer'


class ClientMySQL(L7ClientStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'mysql'

    @classmethod
    def get_default_port(cls):
        return 3306

    def _init_l7(self):
        self._l7_client = L7ClientTls(self.address, self.port, self.timeout)
        self._l7_client.init_connection()
        self.l4_transfer = self._l7_client.l4_transfer

        self.l4_transfer.receive(MySQLRecord.HEADER_SIZE)
        try:
            MySQLRecord.parse_exact_size(self.l4_transfer.buffer)
        except NotEnoughData as e:
            self.l4_transfer.receive(e.bytes_needed)

        try:
            record, parsed_length = MySQLRecord.parse_immutable(self.l4_transfer.buffer)
            self.l4_transfer.flush_buffer(parsed_length)
            initial_handshake, _ = MySQLHandshakeV10.parse_immutable(record.packet_bytes)
        except (InvalidValue, InvalidType, NotEnoughData) as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

        capabilities = set()
        if MySQLCapability.CLIENT_SSL in initial_handshake.capabilities:
            capabilities.add(MySQLCapability.CLIENT_SSL)
        elif MySQLCapability.CLIENT_SECURE_CONNECTION in initial_handshake.capabilities:
            capabilities.add(MySQLCapability.CLIENT_SECURE_CONNECTION)
        else:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        if MySQLCapability.CLIENT_PROTOCOL_41 in initial_handshake.capabilities:
            capabilities.add(MySQLCapability.CLIENT_PROTOCOL_41)

        self.l4_transfer.send(MySQLRecord(
            packet_number=1, packet_bytes=MySQLHandshakeSslRequest(capabilities).compose()
        ).compose())

    def _deinit_l7(self):
        pass


class L7ClientPOP3S(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'pop3s'

    @classmethod
    def get_default_port(cls):
        return 995


class ClientPostgreSQL(L7ClientStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'postgresql'

    @classmethod
    def get_default_port(cls):
        return 5432

    def _init_l7(self):
        try:
            self._l7_client = L7ClientTls(self.address, self.port, self.timeout)
            self._l7_client.init_connection()
            self.l4_transfer = self._l7_client.l4_transfer

            self.l4_transfer.send(SslRequest().compose())

            self.l4_transfer.receive(Sync.MESSAGE_SIZE)
            Sync.parse_exact_size(self.l4_transfer.buffer)
            self.l4_transfer.flush_buffer(Sync.MESSAGE_SIZE)
        except (InvalidValue, InvalidType) as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

    def _deinit_l7(self):
        pass


@attr.s
class ClientPOP3(L7ClientStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'pop3'

    @classmethod
    def get_default_port(cls):
        return 110

    @property
    def _capabilities_command(self):
        return 'CAPA'

    @property
    def _starttls_command(self):
        return 'STLS'

    @property
    def _starttls_ok_result(self):
        return '+OK'

    @property
    def _capabilities_ok_result(self):
        return '+OK'

    @property
    def _capabilities_terminator(self):
        return '.'


class L7ClientSMTPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'smtps'

    @classmethod
    def get_default_port(cls):
        return 465


class ClientSMTP(L7ClientStartTlsMailBase):
    @classmethod
    def get_scheme(cls):
        return 'smtp'

    @classmethod
    def get_default_port(cls):
        return 587

    @classmethod
    def get_default_timeout(cls):
        # some servers delays initial response for 30 seconds
        return 35

    @property
    def _capabilities_command(self):
        return 'EHLO cryptolyzer'

    def _fill_greeting(self):
        greeting_line = self._flush_line()
        self.greeting = [greeting_line, ]

        while not greeting_line.startswith('220 '):
            greeting_line = self._flush_line()
            self.greeting.append(greeting_line)


class L7ClientIMAPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'imaps'

    @classmethod
    def get_default_port(cls):
        return 993


class IMAP4(imaplib.IMAP4, object):
    def __init__(self, host, port, timeout):
        self.timeout = timeout
        super(IMAP4, self).__init__(host, port)

    def open(self, *args, **kwargs):  # pylint: disable=arguments-differ,signature-differs,unused-argument
        self.host = args[0]
        self.port = args[1]
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.file = self.sock.makefile('rb')


class ClientIMAP(L7ClientStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'imap'

    @classmethod
    def get_default_port(cls):
        return 143

    @property
    def _capabilities(self):
        return self._l7_client.capabilities

    def _init_l7(self):
        try:
            self._l7_client = IMAP4(self.ip, self.port, self.timeout)
            self.l4_transfer.init_connection(self._l7_client.socket())

            if 'STARTTLS' not in self._capabilities:
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
            response, _ = self._l7_client.xatom('STARTTLS')
            if response != 'OK':
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except imaplib.IMAP4.error as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

    def _deinit_l7(self):
        try:
            self._l7_client.shutdown()
        except IMAP4.error:
            pass


class L7ClientFTPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'ftps'

    @classmethod
    def get_default_port(cls):
        return 990


class ClientFTP(L7ClientStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'ftp'

    @classmethod
    def get_default_port(cls):
        return 21

    def _init_l7(self):
        try:
            self._l7_client = ftplib.FTP()
            response = self._l7_client.connect(self.address, self.port, self.timeout)
            self.l4_transfer.init_connection(self._l7_client.sock)
            if not response.startswith('220'):
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

            response = self._l7_client.sendcmd('AUTH TLS')
            if not response.startswith('234'):
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except ftplib.all_errors as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

    def _deinit_l7(self):
        try:
            self._l7_client.quit()
        except ftplib.all_errors:
            pass


@attr.s
class ClientRDP(L7ClientStartTlsBase):
    _SUPPORTED_MODES = [RDPProtocol.SSL, RDPProtocol.HYBRID]

    @classmethod
    def get_scheme(cls):
        return 'rdp'

    @classmethod
    def get_default_port(cls):
        return 3389

    def _init_l7(self):
        try:
            self._l7_client = L7ClientTls(self.address, self.port, self.timeout)
            self._l7_client.init_connection()
            self.l4_transfer = self._l7_client.l4_transfer

            neg_req = RDPNegotiationRequest([], self._SUPPORTED_MODES)
            cotp = COTPConnectionRequest(src_ref=0, user_data=neg_req.compose())
            tpkt = TPKT(version=3, message=cotp.compose())
            request_bytes = tpkt.compose()
            self.l4_transfer.send(request_bytes)

            self.l4_transfer.receive(len(request_bytes))
            tpkt = TPKT.parse_exact_size(self.l4_transfer.buffer)
            cotp = COTPConnectionConfirm.parse_exact_size(tpkt.message)
            neg_rsp = RDPNegotiationResponse.parse_exact_size(cotp.user_data)
            self.l4_transfer.flush_buffer(len(request_bytes))
        except (InvalidValue, InvalidType) as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

        if not set(self._SUPPORTED_MODES) & set(neg_rsp.protocol):
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _deinit_l7(self):
        pass


@attr.s
class ClientXMPP(L7ClientStartTlsBase):
    _STREAM_OPEN = (
        '<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" '
        'xmlns:tls="http://www.ietf.org/rfc/rfc2595.txt" to="{}" xml:lang="en" version="1.0">'
    )
    _STARTTLS = b'<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'

    @classmethod
    def get_scheme(cls):
        return 'xmpp'

    @classmethod
    def get_default_port(cls):
        return 5222

    @staticmethod
    def _init_xmpp(l4_transfer, address):
        stream_open_message = ClientXMPP._STREAM_OPEN.format(address).encode("utf-8")
        l4_transfer.send(stream_open_message)

        l4_transfer.receive_until(b'<stream:')
        l4_transfer.receive_until(b'>')

        if b'stream:error' in l4_transfer.buffer:
            raise SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)

        if b'stream:features' not in l4_transfer.buffer:
            l4_transfer.receive_until(b'</stream:features>')

        if b'<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls">' not in l4_transfer.buffer.replace(b'\'', b'"'):
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        l4_transfer.flush_buffer()

        l4_transfer.send(ClientXMPP._STARTTLS)
        l4_transfer.receive_until(b'>')

        if b'stream:error' in l4_transfer.buffer:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        if l4_transfer.buffer.replace(b'\'', b'"') != b'<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>':
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        l4_transfer.flush_buffer()

    def _init_l7(self):
        self._l7_client = L7ClientTls(self.address, self.port, self.timeout)
        self._l7_client.init_connection()
        self.l4_transfer = self._l7_client.l4_transfer

        try:
            self._init_xmpp(self.l4_transfer, self.address)
        except NotEnoughData as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

    def _deinit_l7(self):
        pass


class L7ClientLDAPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'ldaps'

    @classmethod
    def get_default_port(cls):
        return 636


@attr.s
class ClientLDAP(L7ClientStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'ldap'

    @classmethod
    def get_default_port(cls):
        return 389

    def _init_l7(self):
        try:
            self._l7_client = L7ClientTls(self.address, self.port, self.timeout)
            self._l7_client.init_connection()
            self.l4_transfer = self._l7_client.l4_transfer

            request_bytes = LDAPExtendedRequestStartTLS().compose()
            self.l4_transfer.send(request_bytes)

            try:
                self.l4_transfer.receive(LDAPExtendedResponseStartTLS.HEADER_SIZE)
                LDAPExtendedResponseStartTLS.parse_immutable(self.l4_transfer.buffer)
            except NotEnoughData as e:
                header_size = LDAPExtendedResponseStartTLS.HEADER_SIZE
                header_not_received = header_size - len(self.l4_transfer.buffer) == e.bytes_needed
                if header_not_received:
                    self._close_connection()
                    raise e

                self.l4_transfer.receive(e.bytes_needed)

            ext_response, parsed_length = LDAPExtendedResponseStartTLS.parse_immutable(self.l4_transfer.buffer)
            self.l4_transfer.flush_buffer(parsed_length)
        except (InvalidValue, InvalidType) as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

        if ext_response.result_code != LDAPResultCode.SUCCESS:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _deinit_l7(self):
        pass


class L7ClientNNTPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'nntps'

    @classmethod
    def get_default_port(cls):
        return 563


class ClientNNTP(L7ClientStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'nntp'

    @classmethod
    def get_default_port(cls):
        return 119

    @property
    def _starttls_ok_result(self):
        return 382

    @property
    def _capabilities_ok_result(self):
        return 101

    @property
    def _capabilities_terminator(self):
        return '.'


class ClientSieve(L7ClientStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'sieve'

    @classmethod
    def get_default_port(cls):
        return 4190

    def _get_capabilities(self):
        capabilities = collections.OrderedDict()

        while True:
            self.l4_transfer.receive_line()
            key_and_value = self.l4_transfer.buffer.decode('ascii').strip().split(' ', 1)
            self.l4_transfer.flush_buffer()

            key = key_and_value[0].strip('"')
            if key == 'OK':
                break

            if len(key_and_value) > 1:
                value = key_and_value[1]
            else:
                value = None

            capabilities[key] = value

        return capabilities

    def _init_l7(self):
        try:
            self._l7_client = L7ClientTls(self.address, self.port, self.timeout)
            self._l7_client.init_connection()
            self.l4_transfer = self._l7_client.l4_transfer

            capabilities = self._get_capabilities()
            if 'STARTTLS' in capabilities:
                self.l4_transfer.send(b'STARTTLS\r\n')

                self.l4_transfer.receive_line()
                if self.l4_transfer.buffer[:2] == b'OK':
                    self.l4_transfer.flush_buffer()
                else:
                    raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
            else:
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except UnicodeDecodeError as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)
        except NotEnoughData as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

    def _deinit_l7(self):
        pass


class TlsClient(object):
    _last_processed_message_type = attr.ib(init=False, default=None)
    server_messages = attr.ib(init=False, default={})

    @classmethod
    def raise_response_error(cls, transfer):
        response_is_plain_text = transfer.buffer and transfer.buffer_is_plain_text
        transfer.flush_buffer()

        if response_is_plain_text:
            raise SecurityError(SecurityErrorType.PLAIN_TEXT_MESSAGE)

        raise SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)

    @abc.abstractmethod
    def do_handshake(self, transfer, hello_message, record_version, last_handshake_message_type):
        raise NotImplementedError()


class TlsClientHandshake(TlsClient):
    def _process_handshake_message(self, protocol_version, message, last_handshake_message_type):
        handshake_type = message.get_handshake_type()
        is_repeated_messages = handshake_type in self.server_messages
        self.server_messages[handshake_type] = message

        if is_repeated_messages:
            raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

        if (handshake_type == TlsHandshakeType.SERVER_HELLO and
                message.random != TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM and
                not message.protocol_version == protocol_version):
            raise TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)

        if last_handshake_message_type is None:
            if handshake_type == TlsHandshakeType.SERVER_HELLO_DONE:
                raise StopIteration()

            if (handshake_type == TlsHandshakeType.SERVER_HELLO and
                    message.cipher_suite.value.last_version == TlsVersion.TLS1_3):
                raise StopIteration()

        if handshake_type == last_handshake_message_type:
            raise StopIteration

    @classmethod
    def _process_non_handshake_message(cls, content_type, message, last_handshake_message_type):
        if content_type == TlsContentType.ALERT:
            if (message.level == TlsAlertLevel.FATAL or
                    message.description == TlsAlertDescription.CLOSE_NOTIFY):
                raise TlsAlert(message.description)
        elif last_handshake_message_type is None and content_type == TlsContentType.CHANGE_CIPHER_SPEC:
            raise StopIteration
        else:
            raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

    @classmethod
    def _process_invalid_message(cls, transfer):
        cls.raise_response_error(transfer)

    @classmethod
    def _send_hello(cls, transfer, hello_message, record_version):
        tls_record_bytes = TlsRecord(hello_message.compose(), record_version, TlsContentType.HANDSHAKE).compose()
        try:
            transfer.send(tls_record_bytes)
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ == 'TimeoutError' or isinstance(e, socket.timeout):
                six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

            raise e

    def do_handshake(
            self,
            transfer,
            hello_message,
            record_version=TlsProtocolVersion(TlsVersion.SSL3),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
    ):
        self.server_messages = {}
        transfer.flush_buffer()
        self._send_hello(transfer, hello_message, record_version)

        receivable_byte_num = 0
        message_buffer = bytearray()
        while True:
            try:
                record, parsed_length = TlsRecord.parse_immutable(transfer.buffer)
                message_buffer += record.fragment
                transfer.flush_buffer(parsed_length)

                subprotocol_parser = TlsSubprotocolMessageParser(record.content_type)

                while message_buffer:
                    try:
                        message, parsed_length = subprotocol_parser.parse(message_buffer)
                    except NotEnoughData:
                        # another record should be received
                        break

                    message_buffer = message_buffer[parsed_length:]

                    if record.content_type == TlsContentType.HANDSHAKE:
                        self._process_handshake_message(
                            hello_message.protocol_version, message, last_handshake_message_type
                        )
                    else:
                        self._process_non_handshake_message(record.content_type, message, last_handshake_message_type)

                # transfer buffer may contain another record or another record should be received
                continue
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except (InvalidType, InvalidValue):
                self._process_invalid_message(transfer)
            except StopIteration:
                return

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                if transfer.buffer:
                    six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

                six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)


@attr.s
class SslError(ValueError):
    error = attr.ib()


class SslHandshakeClientHelloAnyAlgorithm(SslHandshakeClientHello):
    def __init__(self):
        super(SslHandshakeClientHelloAnyAlgorithm, self).__init__(
            cipher_kinds=list(SslCipherKind)
        )


class SslClientHandshake(TlsClient):
    def do_handshake(
            self,
            transfer,
            hello_message=None,
            record_version=TlsVersion.SSL2,
            last_handshake_message_type=SslMessageType.SERVER_HELLO
    ):
        ssl_record = SslRecord(hello_message)
        transfer.send(ssl_record.compose())

        self.server_messages = {}
        while True:
            try:
                record = SslRecord.parse_exact_size(transfer.buffer)
                transfer.flush_buffer()
                if record.message.get_message_type() == SslMessageType.ERROR:
                    raise SslError(record.message.error_type)

                self._last_processed_message_type = record.message.get_message_type()
                self.server_messages[self._last_processed_message_type] = record.message
                if self._last_processed_message_type == last_handshake_message_type:
                    break

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except (InvalidType, InvalidValue, TooMuchData):
                self.raise_response_error(transfer)

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                if transfer.buffer:
                    try:
                        tls_record, parsed_length = TlsRecord.parse_immutable(transfer.buffer)
                        transfer.flush_buffer(parsed_length)
                    except (InvalidType, InvalidValue, NotEnoughData, TooMuchData):
                        self.raise_response_error(transfer)
                    else:
                        if tls_record.content_type == TlsContentType.ALERT:
                            message, _ = TlsAlertMessage.parse_immutable(tls_record.fragment)
                            if message.description in [
                                        TlsAlertDescription.PROTOCOL_VERSION,
                                        TlsAlertDescription.HANDSHAKE_FAILURE,
                                        TlsAlertDescription.CLOSE_NOTIFY,
                                        TlsAlertDescription.INTERNAL_ERROR,
                                    ]:
                                six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)

                        six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)
                else:
                    six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)


@attr.s
class ClientOpenVpnBase(L7ClientTlsBase, L7OpenVpnBase):
    SESSION_ID = 0xff58585858585858

    _buffer = attr.ib(init=False)

    def __attrs_post_init__(self):
        super(ClientOpenVpnBase, self).__attrs_post_init__()

        self._buffer = bytearray()

        if self.session_id is None:
            self.session_id = int(self.SESSION_ID)

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _reset_session(self):
        self.flush_buffer()
        self.client_packet_id = 0x00000000
        self.remote_session_id = None
        self.session_id += 1
        packet_client_hard_reset = OpenVpnPacketHardResetClientV2(
            self.session_id,
            self.client_packet_id
        )
        self._send_packet(self.l4_transfer, packet_client_hard_reset)

        packets = self._receive_packets(self.l4_transfer)
        packet_hard_reset_server = packets[0]

        if (packet_hard_reset_server.remote_session_id is not None and
                packet_hard_reset_server.remote_session_id != self.session_id):
            raise InvalidValue(
                packet_hard_reset_server.remote_session_id, type(self), 'session_id'
            )

        self.session_id = packet_hard_reset_server.remote_session_id
        self.remote_session_id = packet_hard_reset_server.session_id
        packet_ack_server_hard_reset = OpenVpnPacketAckV1(
            self.session_id,
            self.remote_session_id,
            [packet_hard_reset_server.packet_id, ]
        )
        self._send_packet(self.l4_transfer, packet_ack_server_hard_reset)

    def do_ssl_handshake(self, hello_message, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        return self._do_handshake(
            SslClientHandshake(),
            hello_message,
            TlsVersion.SSL2,
            last_handshake_message_type
        )

    def do_tls_handshake(
            self,
            hello_message,
            record_version=TlsProtocolVersion(TlsVersion.TLS1),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO
    ):
        return self._do_handshake(
            TlsClientOpenVpn(),
            hello_message,
            record_version,
            last_handshake_message_type
        )

    def _init_connection(self):
        if self._is_tcp():
            self.l4_transfer = L4ClientTCP(self.address, self.port, self.timeout, self.ip)
        else:
            self.l4_transfer = L4ClientUDP(self.address, self.port, self.timeout, self.ip)
        self.l4_transfer.init_connection()

        try:
            self._reset_session()
        except (InvalidValue, InvalidType, NotEnoughData) as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

    def send(self, sendable_bytes):
        return self._send_bytes(self.l4_transfer, sendable_bytes)

    def receive(self, receivable_byte_num):
        total_received_byte_num = 0
        while total_received_byte_num < receivable_byte_num:
            try:
                actual_received_bytes = self._receive_packet_bytes(self.l4_transfer, receivable_byte_num)
            except NotEnoughData as e:
                six.raise_from(NotEnoughData(receivable_byte_num - total_received_byte_num), e)
            self._buffer += actual_received_bytes
            total_received_byte_num += len(actual_received_bytes)

        return len(actual_received_bytes)

    def flush_buffer(self, byte_num=None):
        self._buffer = buffer_flush(self._buffer, byte_num)

    @property
    def buffer_is_plain_text(self):
        return buffer_is_plain_text(self._buffer)

    @property
    def buffer(self):
        return self._buffer

    @classmethod
    def get_default_timeout(cls):
        return 5


class ClientOpenVpn(ClientOpenVpnBase):
    @classmethod
    def get_scheme(cls):
        return 'openvpn'

    @classmethod
    def get_default_port(cls):
        return 1194

    @classmethod
    def get_default_timeout(cls):
        return 2

    @classmethod
    def _is_tcp(cls):
        return False


class ClientOpenVpnTcp(ClientOpenVpnBase):
    @classmethod
    def get_scheme(cls):
        return 'openvpntcp'

    @classmethod
    def get_default_port(cls):
        return 443

    @classmethod
    def _is_tcp(cls):
        return True


class TlsClientOpenVpn(TlsClientHandshake):
    pass
