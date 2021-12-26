# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc

import ftplib
import imaplib

import collections
import socket

import attr

import six

from cryptoparser.common.algorithm import Authentication, BlockCipherMode, KeyExchange, NamedGroupType
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidType, InvalidValue

from cryptoparser.tls.algorithm import TlsSignatureAndHashAlgorithm, TlsECPointFormat
from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.ldap import (
    LDAPResultCode,
    LDAPExtendedRequestStartTLS,
    LDAPExtendedResponseStartTLS,
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
    TlsExtensionServerName,
    TlsExtensionSignatureAlgorithms,
    TlsExtensionSignatureAlgorithmsCert,
    TlsExtensionSupportedVersionsClient,
    TlsExtensionsClient,
    TlsKeyShareEntry,
    TlsNamedCurve,
)

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslVersion

from cryptolyzer.common.dhparam import WellKnownDHParams, get_dh_ephemeral_key_forged, int_to_bytes
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.common.transfer import L4ClientTCP, L7TransferBase


class TlsHandshakeClientHelloSpecalization(TlsHandshakeClientHello):
    @classmethod
    def _get_signature_algorithms(cls, is_tls1_3_supported, cipher_suites):
        if is_tls1_3_supported:
            authentications_not_exist_in_tls1_3 = [Authentication.anon, Authentication.DSS]
            signature_algorithms = [
                signature_algorithm
                for signature_algorithm in TlsSignatureAndHashAlgorithm
                if (signature_algorithm.value.signature_algorithm not in authentications_not_exist_in_tls1_3 and
                    signature_algorithm.value.hash_algorithm is not None)
            ]
        else:
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

        return signature_algorithms

    @classmethod
    def _get_tls1_3_extensions(cls, protocol_versions, named_curves, signature_algorithms):
        key_share_entries = []
        for well_known_dh_param in WellKnownDHParams:
            if well_known_dh_param.value.source != 'RFC7919':
                continue

            named_curve = getattr(TlsNamedCurve, 'FFDHE{}'.format(well_known_dh_param.value.key_size))
            if named_curve not in named_curves:
                continue

            key_share_entries.append(TlsKeyShareEntry(
                named_curve,
                int_to_bytes(
                    get_dh_ephemeral_key_forged(well_known_dh_param.value.dh_param_numbers.p),
                    well_known_dh_param.value.key_size // 8
                )
            ))

        extensions = [
            TlsExtensionKeyShareReservedClient(key_share_entries),
            TlsExtensionKeyShareClient(key_share_entries),
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
        is_tls1_3_supported = max(protocol_versions) > TlsProtocolVersionFinal(TlsVersion.TLS1_2)

        if hostname is not None:
            extensions.append(TlsExtensionServerName(hostname))
        if named_curves is None:
            named_curves = list(TlsNamedCurve)

        if signature_algorithms is None:
            signature_algorithms = self._get_signature_algorithms(is_tls1_3_supported, cipher_suites)

        if is_tls1_3_supported:
            #  filter out non TLS 1.3 cipher suites
            cipher_suites = [
                cipher_suite
                for cipher_suite in cipher_suites
                if cipher_suite.value.min_version > TlsProtocolVersionFinal(TlsVersion.TLS1_2)
            ]

            extensions.extend(self._get_tls1_3_extensions(protocol_versions, named_curves, signature_algorithms))
        elif len(protocol_versions) > 1:
            raise NotImplementedError

        if protocol_version_min >= TlsProtocolVersionFinal(TlsVersion.TLS1_0):
            if named_curves:
                extensions.append(TlsExtensionEllipticCurves(named_curves))

                if not is_tls1_3_supported:
                    extensions.append(TlsExtensionECPointFormats(TlsECPointFormat))

        if signature_algorithms:
            extensions.append(TlsExtensionSignatureAlgorithms(signature_algorithms))

        if is_tls1_3_supported:
            protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_2)
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
            if cipher_suite.value.authentication in authentications
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


class TlsHandshakeClientHelloAuthenticationRarelyUsed(  # pylint: disable=too-many-ancestors
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
                    Authentication.anon,
                ])
        ]

        super(TlsHandshakeClientHelloAuthenticationRarelyUsed, self).__init__(
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
    _CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.key_exchange == KeyExchange.DHE or
            cipher_suite.value.min_version > TlsProtocolVersionFinal(TlsVersion.TLS1_2))
    ]
    _NAMED_CURVES = [
        named_curve
        for named_curve in TlsNamedCurve
        if (named_curve.value.named_group is not None
            and named_curve.value.named_group.value.group_type == NamedGroupType.DH_PARAM)
    ]

    def __init__(self, protocol_version, hostname, named_curves=None):
        if named_curves is None:
            named_curves = self._NAMED_CURVES

        super(TlsHandshakeClientHelloKeyExchangeDHE, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self._CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=None,
            extensions=[]
        )


class TlsHandshakeClientHelloKeyExchangeECDHx(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    _CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.key_exchange in [KeyExchange.ECDH, KeyExchange.ECDHE] or
            cipher_suite.value.min_version > TlsProtocolVersionFinal(TlsVersion.TLS1_2))
    ]
    _NAMED_CURVES = [
        named_curve
        for named_curve in TlsNamedCurve
        if (named_curve.value.named_group is not None
            and named_curve.value.named_group.value.group_type == NamedGroupType.ELLIPTIC_CURVE)
    ]

    def __init__(self, protocol_version, hostname, named_curves=None):
        if named_curves is None:
            named_curves = self._NAMED_CURVES

        super(TlsHandshakeClientHelloKeyExchangeECDHx, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self._CIPHER_SUITES,
            named_curves=named_curves,
            signature_algorithms=None,
            extensions=[]
        )


class TlsHandshakeClientHelloBlockCipherModeCBC(  # pylint: disable=too-many-ancestors
            TlsHandshakeClientHelloSpecalization
        ):
    _CIPHER_SUITES = [
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.block_cipher_mode == BlockCipherMode.CBC
    ]

    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloBlockCipherModeCBC, self).__init__(
            hostname=hostname,
            protocol_versions=[protocol_version, ],
            cipher_suites=self._CIPHER_SUITES,
            named_curves=None,
            signature_algorithms=None,
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
            SslVersion.SSL2,
            last_handshake_message_type
        )

    def do_tls_handshake(
            self,
            hello_message,
            record_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0),
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

            neg_req = RDPNegotiationRequest([], [RDPProtocol.SSL, ])
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

        if RDPProtocol.SSL not in neg_rsp.protocol:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _deinit_l7(self):
        pass


@attr.s
class ClientXMPP(L7ClientStartTlsBase):
    _STREAM_OPEN = (
        '<stream:stream xmlns=\'jabber:client\' xmlns:stream=\'http://etherx.jabber.org/streams\' '
        'xmlns:tls=\'http://www.ietf.org/rfc/rfc2595.txt\' to=\'{}\' xml:lang=\'en\' version=\'1.0\'>'
    )
    _STARTTLS = b'<starttls xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\'/>'

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

        if b'<starttls xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\'>' not in l4_transfer.buffer:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        l4_transfer.flush_buffer()

        l4_transfer.send(ClientXMPP._STARTTLS)
        l4_transfer.receive_until(b'>')

        if b'stream:error' in l4_transfer.buffer:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        if l4_transfer.buffer != b'<proceed xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\'/>':
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

        if handshake_type == last_handshake_message_type:
            raise StopIteration

    @classmethod
    def _process_non_handshake_message(cls, content_type, message):
        if content_type != TlsContentType.ALERT:
            raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

        if (message.level == TlsAlertLevel.FATAL or
                message.description == TlsAlertDescription.CLOSE_NOTIFY):
            raise TlsAlert(message.description)

    @classmethod
    def _process_invalid_message(cls, transfer):
        cls.raise_response_error(transfer)

    @classmethod
    def _send_hello(cls, transfer, hello_message, record_version):
        tls_record_bytes = TlsRecord(hello_message.compose(), record_version, TlsContentType.HANDSHAKE).compose()
        try:
            transfer.send(tls_record_bytes)
        except socket.timeout as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

    def do_handshake(
            self,
            transfer,
            hello_message,
            record_version=TlsProtocolVersionFinal(TlsVersion.SSL3),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
    ):
        self.server_messages = {}
        self._send_hello(transfer, hello_message, record_version)

        record_buffer = bytearray()
        while True:
            try:
                while True:
                    record, parsed_length = TlsRecord.parse_immutable(transfer.buffer)
                    record_buffer += record.fragment
                    transfer.flush_buffer(parsed_length)

                    if not transfer.buffer:
                        break

                subprotocol_parser = TlsSubprotocolMessageParser(record.content_type)

                while record_buffer:
                    message, parsed_length = subprotocol_parser.parse(record_buffer)
                    record_buffer = record_buffer[parsed_length:]

                    if record.content_type == TlsContentType.HANDSHAKE:
                        self._process_handshake_message(
                            hello_message.protocol_version, message, last_handshake_message_type
                        )
                    else:
                        self._process_non_handshake_message(record.content_type, message)

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except (InvalidType, InvalidValue):
                self._process_invalid_message(transfer)
            except StopIteration:
                return

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                if transfer.buffer or record_buffer:
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
            record_version=SslVersion.SSL2,
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
