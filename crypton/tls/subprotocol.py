#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import cryptography.hazmat.backends
import cryptography.x509
import datetime
import enum
import random
import time

from typing import Tuple, List

from crypton.common.base import Opaque, Vector, VectorParamNumeric, VectorParamParsable, VectorParsable
from crypton.common.exception import NotEnoughData, InvalidValue
from crypton.common.parse import ParsableBase, Parser, Composer

from crypton.tls.extension import TlsExtensions, TlsNamedCurve
from crypton.tls.version import TlsVersion, TlsProtocolVersionBase, TlsProtocolVersionFinal, TlsProtocolVersionDraft, SslVersion
from crypton.tls.ciphersuite import TlsCipherSuiteFactory


class TlsContentType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18


class TlsSubprotocolMessageBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def get_content_type(cls):
        raise NotImplementedError()


class TlsAlertLevel(enum.IntEnum):
    WARNING = 0x01
    FATAL = 0x02


class TlsAlertDescription(enum.IntEnum):
    CLOSE_NOTIFY = 0x00
    UNEXPECTED_MESSAGE = 0x0a
    BAD_RECORD_MAC = 0x14
    RECORD_OVERFLOW = 0x16
    HANDSHAKE_FAILURE = 0x28
    BAD_CERTIFICATE = 0x2a
    UNSUPPORTED_CERTIFICATE = 0x2b
    CERTIFICATE_REVOKED = 0x2c
    CERTIFICATE_EXPIRED = 0x2d
    CERTIFICATE_UNKNOWN = 0x2e
    ILLEGAL_PARAMETER = 0x2f
    UNKNOWN_CA = 0x30
    ACCESS_DENIED = 0x30
    DECODE_ERROR = 0x32
    DECRYPT_ERROR = 0x33
    PROTOCOL_VERSION = 0x46
    INSUFFICIENT_SECURITY = 0x47
    INTERNAL_ERROR = 0x50
    INAPPROPRIATE_FALLBACK = 0x56
    USER_CANCELED = 0x5a
    MISSING_EXTENSION = 0x6d
    UNSUPPORTED_EXTENSION = 0x6e
    CERTIFICATE_UNOBTAINABLE = 0x6f
    UNRECOGNIZED_NAME = 0x70
    BAD_CERTIFICATE_STATUS_RESPONSE = 0x71
    BAD_CERTIFICATE_HASH_VALUE = 0x72
    UNKNOWN_PSK_IDENTITY = 0x73
    CERTIFICATE_REQUIRED = 0x74
    NO_APPLICATION_PROTOCOL = 0x78


class TlsAlertMessage(TlsSubprotocolMessageBase):
    __SIZE = 2

    def __init__(self, level, description):
        self.level = level
        self.description = description

    @classmethod
    def get_content_type(cls):
        return TlsContentType.ALERT

    @classmethod
    def _parse(cls, parsable_bytes):
        if len(parsable_bytes) < cls.__SIZE:
            raise NotEnoughData(cls.__SIZE)

        parser = Parser(parsable_bytes)

        parser.parse_numeric('level', 1)
        parser.parse_numeric('description', 1)

        return TlsAlertMessage(parser['level'], parser['description']), parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.level, 1)
        composer.compose_numeric(self.description, 1)

        return composer.composed_bytes

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, value):
        try:
            # pylint: disable=attribute-defined-outside-init
            self._level = TlsAlertLevel(value)
        except ValueError:
            raise InvalidValue(value, TlsAlertLevel)

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        try:
            # pylint: disable=attribute-defined-outside-init
            self._description = TlsAlertDescription(value)
        except ValueError:
            raise InvalidValue(value, TlsAlertDescription)

    def __eq__(self, other):
        return self.level == other.level and self.description == other.description


class TlsChangeCipherSpecType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x01


class TlsChangeCipherSpecMessage(TlsSubprotocolMessageBase):
    def __init__(self, change_cipher_spec_type=TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC):
        super(TlsChangeCipherSpecMessage, self).__init__()

        self._change_cipher_spec_type = change_cipher_spec_type

    @classmethod
    def get_content_type(cls):
        return TlsContentType.CHANGE_CIPHER_SPEC

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('change_cipher_spec_type', 1, TlsChangeCipherSpecType)

        return TlsChangeCipherSpecMessage(parser['change_cipher_spec_type']), parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self._change_cipher_spec_type, 1)

        return composer.composed_bytes

    def __eq__(self, other):
        return self._change_cipher_spec_type == other._change_cipher_spec_type


class TlsApplicationDataMessage(TlsSubprotocolMessageBase):
    def __init__(self, data):
        super(TlsApplicationDataMessage, self).__init__()

        self.data = data

    @classmethod
    def get_content_type(cls):
        return TlsContentType.APPLICATION_DATA

    @classmethod
    def _parse(cls, parsable_bytes):
        return TlsApplicationDataMessage(parsable_bytes), len(parsable_bytes)

    def compose(self):
        return self.data

    def __eq__(self, other):
        return self.data == other.data


class TlsHandshakeType(enum.IntEnum):
    HELLO_REQUEST = 0x00
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    HELLO_VERIFY_REQUEST = 0x03
    NEW_SESSION_TICKET = 0x04
    HELLO_RETRY_REQUEST = 0x06
    CERTIFICATE = 0x0b
    SERVER_KEY_EXCHANGE = 0x0c
    CERTIFICATE_REQUEST = 0x0d
    SERVER_HELLO_DONE = 0x0e
    CERTIFICATE_VERIFY = 0x0f
    CLIENT_KEY_EXCHANGE = 0x10
    FINISHED = 0x14
    CLIENT_CERTIFICATE_URL = 0x15
    CERTIFICATE_STATUS = 0x16
    SUPPLEMENTAL_DATA = 0x17


class TlsHandshakeMessage(TlsSubprotocolMessageBase):
    """The payload of a handshake record.
    """
    _HEADER_SIZE = 4

    @classmethod
    def get_content_type(cls):
        return TlsContentType.HANDSHAKE

    @classmethod
    def _parse_handshake_header(cls, parsable_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeMessage, int]
        if len(parsable_bytes) < cls._HEADER_SIZE:
            raise NotEnoughData(cls._HEADER_SIZE)

        parser = Parser(parsable_bytes)

        try:
            parser.parse_numeric('handshake_type', 1, TlsHandshakeType)
        except InvalidValue as e:
            raise e
        else:
            if parser['handshake_type'] != cls.get_handshake_type():
                raise InvalidValue(parser['handshake_type'], TlsHandshakeMessage, 'handshake type')

        parser.parse_numeric('handshake_length', 3)

        try:
            parser.parse_bytes('payload', parser['handshake_length'])
        except NotEnoughData as e:
            raise NotEnoughData(e.bytes_needed + cls._HEADER_SIZE)

        return parser

    def _compose_header(self, payload_length):
        composer = Composer()

        composer.compose_numeric(self.get_handshake_type(), 1)
        composer.compose_numeric(payload_length, 3)

        return composer.composed_bytes

    """
    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        try:
            parser.parse_numeric('handshake_type', 1, TlsHandshakeType)
        except InvalidValue as e:
            raise UnknownType('{} is not a valid TlsHandshakeType'.format(e.value))

        for handshake_class in utils.get_leaf_classes(TlsHandshakeMessage):
            if handshake_class.get_handshake_type() == parser['handshake_type']:
                return handshake_class.parse_exact_bytes(parsable_bytes)
        else:
            raise UnknownType('{} is not a valid TlsHandshakeType'.format(parser['handshake_type']))

    def compose(self):
        pass
    """

    @classmethod
    def _parse_extensions(cls, parser):
        parser.parse_parsable('extensions', TlsExtensions)

        return parser

    def _compose_extensions(self):
        extension_bytes = bytearray()

        for extension in self.extensions:
            extension_bytes += extension.compose()

        payload_composer = Composer()
        payload_composer.compose_numeric(len(extension_bytes), 2)

        return payload_composer.composed_bytes + extension_bytes


class TlsHandshakeHelloRandomBytes(Opaque):
    @classmethod
    def get_byte_num(cls):
        return 28


class TlsHandshakeHelloRandom(ParsableBase):
    def __init__(
        self,
        time=datetime.datetime.now(),
        random=bytearray.fromhex('{:28x}'.format(random.getrandbits(224)).zfill(56))
    ):
        self.time = time
        self.random = random

    @property
    def random(self):
        return bytearray(self._random)

    @random.setter
    def random(self, value):

        self._random = value

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        self._time = value

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('time', 4, datetime.datetime.utcfromtimestamp)
        parser.parse_parsable('random', TlsHandshakeHelloRandomBytes)

        return TlsHandshakeHelloRandom(time, parser['random']), parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(int(time.mktime(self._time.timetuple())), 4)
        composer.compose_bytes(self._random)

        return composer.composed_bytes


class TlsHandshakeHello(TlsHandshakeMessage):
    def __init__(self, protocol_version, random, session_id):
        super(TlsHandshakeHello, self).__init__()

        self.protocol_version = protocol_version
        self.random = random
        self.session_id = session_id

    @classmethod
    def _parse_hello_header(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_parsable('protocol_version', TlsProtocolVersionBase)
        parser.parse_parsable('random', TlsHandshakeHelloRandom)
        protocol_version = parser['protocol_version']
        if not (type(protocol_version) == TlsProtocolVersionDraft and protocol_version.minor < 22):
            parser.parse_parsable('session_id', TlsSessionIdVector)

        return parser

    def _compose_header(self, payload_length):
        composer = Composer()

        handshake_header_bytes = super(TlsHandshakeHello, self)._compose_header(
            payload_length + composer.composed_byte_num
        )

        return handshake_header_bytes + composer.composed_bytes


class TlsCipherSuiteVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsCipherSuiteFactory,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 16 - 2
        )


class TlsCompressionMethod(enum.IntEnum):
    NULL = 0


class TlsCompressionMethodVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=1, max_byte_num=2 ** 8 - 1)


class TlsSessionIdVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=0, max_byte_num=32)


class TlsHandshakeClientHello(TlsHandshakeHello):
    def __init__(
        self,
        cipher_suites,
        protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
        random=TlsHandshakeHelloRandom(),
        session_id=TlsSessionIdVector([]),
        compression_methods=TlsCompressionMethodVector([TlsCompressionMethod.NULL, ]),
        extensions=[],
    ):
        super(TlsHandshakeClientHello, self).__init__(protocol_version, random, session_id)

        self.cipher_suites = TlsCipherSuiteVector(cipher_suites)
        self.compression_methods = compression_methods
        self.extensions = extensions

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.CLIENT_HELLO

    @classmethod
    def _parse(cls, parsable_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeClientHello, int]

        handshake_header_parser = cls._parse_handshake_header(parsable_bytes)

        payload_parser = cls._parse_hello_header(parsable_bytes)

        cipher_suites = TlsVector._parse(remaining_bytes, int, elem_size=2, max_elem_num=2 ** 16 - 2)
        remaining_bytes = remaining_bytes[cipher_suites.size:]

        compression_methods = TlsVector._parse(remaining_bytes, int, elem_size=1, max_elem_num=2 ** 8 - 1)
        remaining_bytes = remaining_bytes[compression_methods.size:]

        extensions, len_consumed_for_extensions = cls._parse_extensions(payload_parser)
        remaining_bytes = remaining_bytes[len_consumed_for_extensions:]

        return TlsHandshakeClientHello(
            handshake_header_parser['protocol_version'],
            handshake_header_parser['random'],
            handshake_header_parser['session_id'],
            cipher_suites,
            compression_methods,
            extensions),
        len(parsable_bytes) - len(remaining_bytes)

    def compose(self):
        payload_composer = Composer()

        payload_composer.compose_parsable(self.protocol_version)
        payload_composer.compose_parsable(self.random)
        payload_composer.compose_parsable(self.session_id)
        payload_composer.compose_parsable(self.cipher_suites)
        payload_composer.compose_parsable(self.compression_methods)

        extension_bytes = self._compose_extensions()

        header_bytes = self._compose_header(payload_composer.composed_byte_num + len(extension_bytes))

        return header_bytes + payload_composer.composed_bytes + extension_bytes


class TlsHandshakeServerHello(TlsHandshakeHello):
    def __init__(
        self,
        protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
        random=TlsHandshakeHelloRandom(),
        session_id=TlsSessionIdVector([random.randint(0, 255) for i in range(32)]),
        compression_method=TlsCompressionMethod.NULL,
        cipher_suite=None,
        extensions=[],
    ):
        super(TlsHandshakeServerHello, self).__init__(protocol_version, random, session_id)

        self.cipher_suite = cipher_suite
        self.compression_method = compression_method
        self.extensions = extensions

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_HELLO

    @classmethod
    def _parse(cls, parsable_bytes):
        handshake_header_parser = cls._parse_handshake_header(parsable_bytes)

        parser = cls._parse_hello_header(handshake_header_parser['payload'])

        parser.parse_parsable('cipher_suite', TlsCipherSuiteFactory)

        protocol_version = parser['protocol_version']
        if not (type(protocol_version) == TlsProtocolVersionDraft and protocol_version.minor < 22):
            parser.parse_numeric('compression_method', 1)

        if parser.parsed_byte_num < handshake_header_parser['handshake_length']:
            cls._parse_extensions(parser)

        return TlsHandshakeServerHello(
            protocol_version=parser['protocol_version'],
            random=parser['random'],
            session_id=parser['session_id'] if hasattr(parser, 'session_id') else [],
            compression_method=parser['compression_method'] if hasattr(parser, 'compression_method') else TlsCompressionMethod.NULL,
            cipher_suite=parser['cipher_suite'],
            extensions=parser['extensions'] if hasattr(parser, 'extensions') else [],
        ), handshake_header_parser.parsed_byte_num

    def compose(self):
        # type: () -> bytes

        payload_composer = Composer()

        payload_composer.compose_parsable(self.cipher_suite)
        payload_composer.compose_parsable(self.compression_method)

        # FIXME parsable_bytes += self._compose_extensions()

        header_bytes = self._compose_header(payload_composer.composed_byte_num)

        return header_bytes + payload_composer.composed_bytes

import base64
class TlsCertificate(ParsableBase):
    def __init__(self, certificate):
        self._certificate = certificate

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('certificate_length', 3)
        #print('certificate_length', parser['certificate_length'])
        #print(parser.unparsed_byte_num)
        parser.parse_bytes('certificate', parser['certificate_length'])
        #print(len(parser['certificate']))
        #print('-----BEGIN CERTIFICATE-----')
        #x=base64.b64encode(parser['certificate'])
        #for i in range(0, len(x), 64):
        #    print(x[i:i+64])
        #print('-----END CERTIFICATE-----')

        try:
            certificate = cryptography.x509.load_der_x509_certificate(
                bytes(parser['certificate']),
                cryptography.hazmat.backends.default_backend()
            )
        except ValueError as e:
            print(e)
            raise InvalidValue(parser['certificate'], TlsCertificate, 'certificate')

        return TlsCertificate(certificate), parser.parsed_byte_num

    def compose(self):
        return bytearray(self._certificate.tbs_certificate_bytes)


class TlsCertificates(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsCertificate,
            fallback_class=None,
            min_byte_num=1, max_byte_num=2 ** 24 - 1
        )


class TlsHandshakeCertificate(TlsHandshakeMessage):
    def __init__(self, certificate_chain):
        super(TlsHandshakeCertificate, self).__init__()

        self.certificate_chain = certificate_chain

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.CERTIFICATE

    @classmethod
    def _parse(cls, parsable_bytes):
        handshake_header_parser = cls._parse_handshake_header(parsable_bytes)

        parser = Parser(handshake_header_parser['payload'])

        parser.parse_parsable('certificates', TlsCertificates)

        return TlsHandshakeCertificate(
            parser['certificates']
        ), handshake_header_parser.parsed_byte_num

    def compose(self):
        body_composer = Composer()
        body_composer.compose_parsable(self.certificate_chain)

        header_composer = Composer()
        header_composer.compose_numeric(body_composer.composed_byte_num)

        return header_composer.composed_bytes + body_composer.composed_bytes


class TlsHandshakeServerHelloDone(TlsHandshakeMessage):
    def __init__(self):
        super(TlsHandshakeServerHelloDone, self).__init__()

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_HELLO_DONE

    @classmethod
    def _parse(cls, parsable_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeServerHelloDone, int]

        handshake_header_parser = cls._parse_handshake_header(parsable_bytes)

        if handshake_header_parser['handshake_length'] != 0:
            raise InvalidValue()

        return TlsHandshakeServerHelloDone(), handshake_header_parser.parsed_byte_num

    def compose(self):
        # type: () -> bytes

        return bytearray()


class TlsDHParamVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=1, max_byte_num=2 ** 16 - 1)


class TlsECCurveType(enum.IntEnum):
    EXPLICIT_PRIME = 1
    EXPLICIT_CHAR2 = 2
    NAMED_CURVE = 3


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh


class TlsHandshakeServerKeyExchange(TlsHandshakeMessage):
    def __init__(self, param_bytes):
        super(TlsHandshakeServerKeyExchange, self).__init__()

        self.param_bytes = param_bytes
        self.dh_public_key = None

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_KEY_EXCHANGE

    @classmethod
    def _parse(cls, parsable_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeServerKeyExchange, int]

        handshake_header_parser = cls._parse_handshake_header(parsable_bytes)

        return TlsHandshakeServerKeyExchange(handshake_header_parser['payload']), handshake_header_parser.parsed_byte_num

    def compose(self):
        # type: () -> bytes

        return self.dh_params

    def parse_dh_params(self):
        parser = Parser(self.param_bytes)

        parser.parse_parsable('p', TlsDHParamVector)
        parser.parse_parsable('g', TlsDHParamVector)
        parser.parse_parsable('y', TlsDHParamVector)
        
        p = long(''.join(map('{:02x}'.format, parser['p'])), 16)
        g = long(''.join(map('{:02x}'.format, parser['g'])), 16)
        y = long(''.join(map('{:02x}'.format, parser['y'])), 16)

        parameter_numbers = dh.DHParameterNumbers(p, g)
        public_numbers = dh.DHPublicNumbers(y, parameter_numbers)

        self.dh_public_key = public_numbers.public_key(default_backend())

    def parse_ecdh_params(self):
        parser = Parser(self.param_bytes)

        parser.parse_numeric('curve_type', 1, TlsECCurveType)

        if parser['curve_type'] == TlsECCurveType.NAMED_CURVE:
            parser.parse_numeric('curve_type', 2, TlsNamedCurve)


class SslMessageBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def get_message_type(cls):
        return NotImplementedError()


class SslMessageType(enum.IntEnum):
    ERROR = 0x00
    CLIENT_HELLO = 0x01
    CLIENT_MASTER_KEY = 0x02
    CLIENT_FINISHED = 0x03
    SERVER_HELLO = 0x04
    SERVER_VERIFY = 0x05
    SERVER_FINISHED = 0x06
    REQUEST_CERTIFICATE = 0x07
    CLIENT_CERTIFICATE = 0x08


class SslCipherKind(enum.IntEnum):
    RC4_128_WITH_MD5 = 0x010080
    RC4_128_EXPORT40_WITH_MD5 = 0x020080
    RC2_128_CBC_WITH_MD5 = 0x030080
    RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080
    IDEA_128_CBC_WITH_MD5 = 0x050080
    DES_64_CBC_WITH_MD5 = 0x060040
    DES_192_EDE3_CBC_WITH_MD5 = 0x0700C0


class SslCertificateType(enum.IntEnum):
    X509_CERTIFICATE = 0x01


class SslAuthenticationType(enum.IntEnum):
    MD5_WITH_RSA_ENCRYPTION = 0x01


class SslErrorType(enum.IntEnum):
    NO_CIPHER_ERROR = 0x0001
    NO_CERTIFICATE_ERROR = 0x0002
    BAD_CERTIFICATE_ERROR = 0x0003
    UNSUPPORTED_CERTIFICATE_TYPE_ERROR  = 0x0004


class SslSessionIdVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=0, max_byte_num=16)


class SslHandshakeClientHello(SslMessageBase):
    def __init__(
        self,
        cipher_kinds,
        session_id=SslSessionIdVector([]),
        challenge=bytearray.fromhex('{:16x}'.format(random.getrandbits(128)).zfill(32)),
    ):
        self.cipher_kinds = cipher_kinds
        self.session_id = session_id
        self.challenge = challenge

    @classmethod
    def get_message_type(cls):
        return SslMessageType.CLIENT_HELLO

    def _parse(self, parsable_bytes):
        raise NotImplementedError()

    def compose(self):
        composer = Composer()

        composer.compose_numeric(SslVersion.SSL2, 2)

        composer.compose_numeric(len(self.cipher_kinds) * 3, 2)
        composer.compose_numeric(0, 2)
        composer.compose_numeric(len(self.challenge), 2)

        composer.compose_numeric_array(self.cipher_kinds, 3)
        composer.compose_bytes(self.challenge)

        return composer.composed_bytes


class SslCertificateType(enum.IntEnum):
    X509_CERTIFICATE = 0x01


class SslHandshakeServerHello(SslMessageBase):
    def __init__(
        self,
        certificate,
        cipher_kinds,
        connection_id=SslSessionIdVector([]),
    ):
        self.cipher_kinds = cipher_kinds
        self.certificate = certificate
        self.connection_id = connection_id

    @classmethod
    def get_message_type(cls):
        return SslMessageType.SERVER_HELLO

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('session_id_hit', 1)
        parser.parse_numeric('certificate_type', 1, SslCertificateType)
        parser.parse_numeric('version', 2, SslVersion)
        parser.parse_numeric('certificate_length', 2)
        parser.parse_numeric('cipher_kinds_length', 2)
        parser.parse_numeric('connection_id_length', 2)
        parser.parse_bytes('certificate', parser['certificate_length'])
        parser.parse_numeric_array('cipher_kinds', parser['cipher_kinds_length'] / 3, 3, SslCipherKind)
        parser.parse_bytes('connection_id', parser['connection_id_length'])

        try:
            certificate = cryptography.x509.load_der_x509_certificate(
                bytes(parser['certificate']),
                cryptography.hazmat.backends.default_backend()
            )
        except ValueError:
            raise InvalidValue(value=parser['certificate'])

        return SslHandshakeServerHello(
            certificate=certificate,
            cipher_kinds=parser['cipher_kinds'],
            connection_id=parser['connection_id'],
        ), parser.parsed_byte_num

    def compose(self):
        raise NotImplementedError()


class TlsHandshakeHelloRetryRequest(TlsHandshakeHello):
    def __init__(self, selected_group, protocol_version):
        super(TlsHandshakeHelloRetryRequest, self).__init__()

        self.protocol_version = protocol_version
        self.selected_group = TlsNamedCurve(selected_group)

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.HELLO_RETRY_REQUEST

    @classmethod
    def _parse(cls, parsable_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeHelloRetryRequest, int]

        handshake_header_parser = cls._parse_handshake_header(parsable_bytes)

        parser = cls._parse_hello_header(handshake_header_parser['payload'])

        parser = Parser(handshake_header_parser['payload'])
        parser.parse_parsable('protocol_version', TlsProtocolVersionBase)
        parser.parse_numeric('selected_group', 2, TlsNamedCurve)

        return TlsHandshakeHelloRetryRequest(
            parser['selected_group'],
            parser['protocol_version']
        ), handshake_header_parser.parsed_byte_num

    def compose(self):
        # type: () -> bytes
        payload_composer = Composer()

        payload_composer.compose_parsable(self.protocol_version)
        payload_composer.compose_numeric(self.selected_group, 2)

        extension_bytes = self._compose_extensions()

        header_bytes = self._compose_header(payload_composer.composed_byte_num + len(extension_bytes))

        return extension_bytes
