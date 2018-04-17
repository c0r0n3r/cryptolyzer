#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum
import collections

from crypton.common.base import Vector, VectorParsable, VectorParsableDerived, VectorParamNumeric, VectorParamParsable
from crypton.common.algorithm import Authentication, MAC
from crypton.common.base import TwoByteEnumComposer, TwoByteEnumParsable
from crypton.common.exception import NotEnoughData, InvalidValue
from crypton.common.parse import ParsableBase, Parser, Composer
from crypton.tls.version import TlsProtocolVersionBase


class TlsExtensionType(enum.IntEnum):
    SERVER_NAME = 0x0000                             # [RFC6066]
    MAX_FRAGMENT_LENGTH = 0x0001                     # [RFC6066]
    CLIENT_CERTIFICATE_URL = 0x0002                  # [RFC6066]
    TRUSTED_CA_KEYS = 0x0003                         # [RFC6066]
    TRUNCATED_HMAC = 0x0004                          # [RFC6066]
    STATUS_REQUEST = 0x0005                          # [RFC6066]
    USER_MAPPING = 0x0006                            # [RFC4681]
    CLIENT_AUTHZ = 0x0007                            # [RFC5878]
    SERVER_AUTHZ = 0x0008                            # [RFC5878]
    CERT_TYPE = 0x0009                               # [RFC6091]
    SUPPORTED_GROUPS = 0x000a                        # [RFC-IETF-TLS-RFC]
    EC_POINT_FORMATS = 0x000b                        # [RFC-IETF-TLS-RFC]
    SRP = 0x000c                                     # [RFC5054]
    SIGNATURE_ALGORITHMS = 0x000d                    # [RFC5246]
    USE_SRTP = 0x000e                                # [RFC5764]
    HEARTBEAT = 0x000f                               # [RFC6520]
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x0010  # [RFC7301]
    STATUS_REQUEST_V = 0x0011                        # [RFC6961]
    SIGNED_CERTIFICATE_TIMESTAMP = 0x0012            # [RFC6962]
    CLIENT_CERTIFICATE_TYPE = 0x0013                 # [RFC7250]
    SERVER_CERTIFICATE_TYPE = 0x0014                 # [RFC7250]
    PADDING = 0x0015                                 # [RFC7685]
    ENCRYPT_THEN_MAC = 0x0016                        # [RFC7366]
    EXTENDED_MASTER_SECRET = 0x0017                  # [RFC7627]
    TOKEN_BINDING = 0x0018                           # [DRAFT-IETF-TOKBIND-NEGOTIATION]
    CACHED_INFO = 0x0019                             # [RFC7924]
    SESSION_TICKET = 0x0023                          # [RFC4507]
    KEY_SHARE_RESERVED = 0x0028                      # [DRAFT-IETF-TLS-TLS13-12]
    PRE_SHARED_KEY = 0x0029                          # [DRAFT-IETF-TLS-TLS13-20]
    EARLY_DATA = 0x002a                              # [DRAFT-IETF-TLS-TLS13-20]
    SUPPORTED_VERSIONS = 0x002b                      # [DRAFT-IETF-TLS-TLS13-20]
    COOKIE = 0x002c                                  # [DRAFT-IETF-TLS-TLS13-20]
    PSK_KEY_EXCHANGE_MODES = 0x002d                  # [DRAFT-IETF-TLS-TLS13-20]
    CERTIFICATE_AUTHORITIES = 0x002f                 # [DRAFT-IETF-TLS-TLS13-20]
    OID_FILTERS = 0x0030                             # [DRAFT-IETF-TLS-TLS13-20]
    POST_HANDSHAKE_AUTH = 0x0030                     # [DRAFT-IETF-TLS-TLS13-20]
    KEY_SHARE = 0x0033                               # [DRAFT-IETF-TLS-TLS13-20]
    RENEGOTIATION_INFO = 0Xff01                      # [RFC5746]


class TlsExtensions(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsExtensionParsed,
            fallback_class=TlsExtensionUnparsed,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


class TlsExtensionBase(ParsableBase):
    def __init__(self, extension_type):
        self.extension_type = extension_type

    @classmethod
    def _parse_header(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('extension_type', 2, TlsExtensionType)
        parser.parse_numeric('extension_length', 2)

        if parser.unparsed_byte_num < parser['extension_length']:
            raise NotEnoughData(parser['extension_length'] + parser.parsed_byte_num)

        return parser

    def _compose_header(self, payload_length):
        header_composer = Composer()

        header_composer.compose_numeric(self.extension_type, 2)
        header_composer.compose_numeric(payload_length, 2)

        return header_composer.composed_bytes


class TlsExtensionUnparsed(TlsExtensionBase):
    def __init__(self, extension_type, extension_data):
        super(TlsExtensionUnparsed, self).__init__(extension_type)

        self._extension_data = extension_data

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionUnparsed, cls)._parse_header(parsable_bytes)

        parser.parse_bytes('extension_data', parser['extension_length'])

        return TlsExtensionUnparsed(parser['extension_type'], parser['extension_data']), parser.parsed_byte_num

    def compose(self):
        payload_composer = Composer()
        payload_composer.compose_bytes(self._extension_data)

        header_bytes = self._compose_header(payload_composer.composed_byte_num)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionParsed(TlsExtensionBase):
    def __init__(self):
        super(TlsExtensionParsed, self).__init__(self.get_extension_type())

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable_bytes):
        parser = super(TlsExtensionParsed, cls)._parse_header(parsable_bytes)

        if parser['extension_type'] != cls.get_extension_type():
            raise InvalidValue(parser['extension_type'], TlsExtensionParsed, 'extension type')

        return parser


class TlsServerNameType(enum.IntEnum):
    HOST_NAME = 0x00


class TlsServerName(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 16 - 1,
        )


class TlsExtensionServerName(TlsExtensionParsed):
    def __init__(self, host_name, name_type=TlsServerNameType.HOST_NAME):
        super(TlsExtensionServerName, self).__init__()

        self.host_name = host_name
        self.name_type = name_type

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SERVER_NAME

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionServerName, cls)._parse_header(parsable_bytes)

        if parser['extension_length'] > 0:
            parser.parse_numeric('server_name_list_length', 2)
            parser.parse_numeric('server_name_type', 1, TlsServerNameType)
            parser.parse_parsable('server_name', TlsServerName)
           
            return TlsExtensionServerName(bytearray(parser['server_name']).decode('idna')), parser.parsed_byte_num
        else:
            return TlsExtensionServerName(bytearray().decode('idna')), parser.parsed_byte_num


    def compose(self):
        composer = Composer()

        if self.host_name:
            idna_encoded_host_name = self.host_name.encode('idna')

            composer.compose_numeric(3 + len(idna_encoded_host_name), 2)
            composer.compose_numeric(self.name_type, 1)
           
            composer.compose_numeric(len(idna_encoded_host_name), 2)
            composer.compose_bytes(idna_encoded_host_name)

        header_bytes = self._compose_header(composer.composed_byte_num)

        return header_bytes + composer.composed_bytes


class TlsECPointFormat(enum.IntEnum):
    UNCOMPRESSED  = 0X0
    ANSIX962_COMPRESSED_PRIME  = 0X1
    ANSIX962_COMPRESSED_CHAR2  = 0X2


class TlsECPointFormatVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 8 - 1,
            numeric_class=TlsECPointFormat
        )


class TlsExtensionECPointFormats(TlsExtensionParsed):
    def __init__(self, point_formats):
        super(TlsExtensionECPointFormats, self).__init__()

        self.point_formats = TlsECPointFormatVector(point_formats)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.EC_POINT_FORMATS

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionECPointFormats, cls)._parse_header(parsable_bytes)

        parser.parse_parsable('point_formats', TlsECPointFormatVector)

        return TlsExtensionECPointFormats(parser['point_formats']), parser.parsed_byte_num

    def compose(self):
        payload_composer = Composer()

        payload_composer.compose_parsable(self.point_formats)

        header_bytes = self._compose_header(payload_composer.composed_byte_num)

        return header_bytes + payload_composer.composed_bytes


class TlsNamedCurve(enum.IntEnum):
    SECT163K1 = 0x0001
    SECT163R1 = 0x0002
    SECT163R2 = 0x0003
    SECT193R1 = 0x0004
    SECT193R2 = 0x0005
    SECT233K1 = 0x0006
    SECT233R1 = 0x0007
    SECT239K1 = 0x0008
    SECT283K1 = 0x0009
    SECT283R1 = 0x000a
    SECT409K1 = 0x000b
    SECT409R1 = 0x000c
    SECT571K1 = 0x000d
    SECT571R1 = 0x000e
    SECP160K1 = 0x000f
    SECP160R1 = 0x0010
    SECP160R2 = 0x0011
    SECP192K1 = 0x0012
    SECP192R1 = 0x0013
    SECP224K1 = 0x0014
    SECP224R1 = 0x0015
    SECP256K1 = 0x0016
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019

    BRAINPOOLP256R1 = 0x001a
    BRAINPOOLP384R1 = 0x001b
    BRAINPOOLP512R1 = 0x001c
    X25519 = 0x001d
    X448 = 0x001e

    FFDHE2048 = 0x0100
    FFDHE3072 = 0x0101
    FFDHE4096 = 0x0102
    FFDHE6144 = 0x0103
    FFDHE8192 = 0x0104

    ARBITRARY_EXPLICIT_PRIME_CURVES = 0xff01
    ARBITRARY_EXPLICIT_CHAR2_CURVES = 0xff02


class TlsEllipticCurveVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=2,
            min_byte_num=1,
            max_byte_num=2 ** 16 - 1,
            numeric_class=TlsNamedCurve
        )

class TlsExtensionEllipticCurves(TlsExtensionParsed):
    def __init__(self, elliptic_curves):
        super(TlsExtensionEllipticCurves, self).__init__()

        self.elliptic_curves = TlsEllipticCurveVector(elliptic_curves)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SUPPORTED_GROUPS

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionEllipticCurves, cls)._parse_header(parsable_bytes)

        parser.parse_parsable('elliptic_curves', TlsEllipticCurveVector)

        return TlsExtensionEllipticCurves(parser['elliptic_curves']), parser.parsed_byte_num

    def compose(self):
        payload_composer = Composer()

        payload_composer.compose_parsable(self.elliptic_curves)

        header_bytes = self._compose_header(payload_composer.composed_byte_num)

        return header_bytes + payload_composer.composed_bytes


class TlsSupportedVersionVector(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsProtocolVersionBase,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 8 - 2
        )


class TlsExtensionSupportedVersions(TlsExtensionParsed):
    def __init__(self, supported_versions):
        super(TlsExtensionSupportedVersions, self).__init__()

        self.supported_versions = TlsSupportedVersionVector(supported_versions)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SUPPORTED_VERSIONS

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionSupportedVersions, cls)._parse_header(parsable_bytes)

        # it possible only when the extension is part of the server hello message
        if parser['extension_length'] == 2:
            parser.parse_parsable('supported_version', TlsProtocolVersionBase)
            return TlsExtensionSupportedVersions([parser['supported_version'], ]), parser.parsed_byte_num
        else:
            parser.parse_parsable('supported_versions', TlsSupportedVersionVector)
            return TlsExtensionSupportedVersions(parser['supported_versions']), parser.parsed_byte_num

    def compose(self):
        payload_composer = Composer()

        payload_composer.compose_parsable(self.supported_versions)

        header_bytes = self._compose_header(payload_composer.composed_byte_num)

        return header_bytes + payload_composer.composed_bytes


class TlsSignatureAndHashAlgorithm(ParsableBase):
    def __init__(self, hash_algorithm, signature_algorithm):
        self = hash_algorithm = hash_algorithm
        self.signature_algorithm = signature_algorithm

    def _parse(self, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('hash_algorithm', 1)
        parser.parse_numeric('signature_algorithm', 1)

        return TlsSignatureAndHashAlgorithm(
            parser['signature_algorithm'],
            parser['hash_algorithm']),
        parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.hash_algorithm, 1)
        composer.compose_numeric(self.signature_algorithm, 1)

        return composer.composed_bytes


class TlsSignatureAndHashAlgorithmFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsSignatureAndHashAlgorithm


HashAndSignatureAlgorithmParam = collections.namedtuple('HashAndSignatureAlgorithmParam', ['code', 'hash_algorithm', 'signature_algorithm'])


class TlsSignatureAndHashAlgorithm(TwoByteEnumComposer, enum.Enum):
    ANONYMOUS_NONE = HashAndSignatureAlgorithmParam(
        code=0x0000,
        signature_algorithm=Authentication.anon,
        hash_algorithm=None,
    )
    ANONYMOUS_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0100,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.MD5
    )
    ANONYMOUS_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0200,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA
    )
    ANONYMOUS_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0300,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA224
    )
    ANONYMOUS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0400,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA256
    )
    ANONYMOUS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0500,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA384
    )
    ANONYMOUS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0006,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA512
    )
    RSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0001,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=None,
    )
    RSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0101,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.MD5
    )
    RSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0201,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA
    )
    RSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0301,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA224
    )
    RSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0401,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA256
    )
    RSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0501,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA384
    )
    RSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0601,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA512
    )
    DSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0002,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=None,
    )
    DSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0102,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.MD5
    )
    DSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0202,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA
    )
    DSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0302,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA224
    )
    DSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0402,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA256
    )
    DSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0502,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA384
    )
    DSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0602,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA512
    )
    ECDSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0003,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=None,
    )
    ECDSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0103,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.MD5
    )
    ECDSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0203,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA
    )
    ECDSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0303,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA224
    )
    ECDSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0403,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA256
    )
    ECDSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0503,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA384
    )
    ECDSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0603,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA512
    )

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    RSA_PSS_RSAE_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0804,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA256
    )
    RSA_PSS_RSAE_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0805,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA384
    )
    RSA_PSS_RSAE_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0806,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA512
    )

    RSA_PSS_PSS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0809,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA256
    )
    RSA_PSS_PSS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x080a,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA384
    )
    RSA_PSS_PSS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x080b,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA512
    )


class TlsSignatureAndHashAlgorithmVector(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsSignatureAndHashAlgorithm,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 16 - 2
        )


class TlsExtensionSignatureAlgorithms(TlsExtensionParsed):
    def __init__(self, hash_and_signature_algorithms):
        super(TlsExtensionSignatureAlgorithms, self).__init__()

        self.hash_and_signature_algorithms = TlsSignatureAndHashAlgorithmVector(hash_and_signature_algorithms)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SIGNATURE_ALGORITHMS

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionSignatureAlgorithms, cls)._parse_header(parsable_bytes)

        parser.parse_parsable('hash_and_signature_algorithms', TlsSignatureAndHashAlgorithmVector)

        return TlsExtensionSignatureAlgorithms(parser['hash_and_signature_algorithms']), parser.parsed_byte_num

    def compose(self):
        payload_composer = Composer()

        payload_composer.compose_parsable(self.hash_and_signature_algorithms)

        header_bytes = self._compose_header(payload_composer.composed_byte_num)

        return header_bytes + payload_composer.composed_bytes


class TlsKeyExchangeVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=1, max_byte_num=2 ** 16 - 1)


class TlsKeyShareEntry(ParsableBase):
    def __init__(self, group, key_exchange):
        self.group = TlsNamedCurve(group)
        self.key_exchange = TlsKeyExchangeVector(key_exchange)

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('group', 2, TlsNamedCurve)
        parser.parse_parsable('key_exchange', TlsKeyExchangeVector)

        return TlsKeyShareEntry(parser['group'], parser['key_exchange']), parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.group, 2)
        composer.compose_parsable(self.key_exchange)

        return composer.composed_bytes


class TlsKeyShareEntryVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsKeyShareEntry,
            fallback_class=None,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


class TlsExtensionKeyShare(TlsExtensionParsed):
    def __init__(self, key_share_entries):
        super(TlsExtensionKeyShare, self).__init__()

        self.key_share_entries = TlsKeyShareEntryVector(key_share_entries)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.KEY_SHARE

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionKeyShare, cls)._parse_header(parsable_bytes)

        parser.parse_parsable('key_share_entries', TlsKeyShareEntryVector)

        return TlsExtensionKeyShare(parser['key_share_entries']), parser.parsed_byte_num

    def compose(self):
        payload_composer = Composer()

        payload_composer.compose_parsable(self.key_share_entries)

        header_bytes = self._compose_header(payload_composer.composed_byte_num)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionKeyShareReserved(TlsExtensionKeyShare):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.KEY_SHARE_RESERVED
